from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import wx

import SignSeal
from SignSeal import SignSealError
from SignSeal.config import Config
from SignSeal.io_utils import KeyFormat
from SignSeal.key_encoding import get_alphanumeric_key
from SignSeal.key_generation import generate_key_material
from SignSeal.key_specs import KEY_SPECS, KEY_SPECS_BY_NAME
from SignSeal.models import ProcessMode

_F: str = Config.FILE_EXT
_V: str = Config.VAULT_EXT
from SignSeal.gui.dialogs import (
    APP_SECURITY_NOTICE,
    AboutDialog,
    FingerprintDialog,
    KeySelectionDialog,
)
from SignSeal.gui.main_frame import MainFrame
from SignSeal.gui.vault_dialogs import (
    WELCOME_SECURITY_NOTICE,
    CreateVaultDialog,
    WelcomeDialog,
    ask_new_vault,
)
from SignSeal.gui.main import main


@pytest.fixture(scope="session", autouse=True)
def wx_app():
    app = wx.GetApp()
    if not app:
        app = wx.App()
    yield app


@pytest.fixture
def temp_vault(tmp_path):
    vault_path = tmp_path / f"test_gui{_V}"
    return SignSeal("password12345", vault_path)


class MockEvent:
    pass


class ImmediateThread:
    def __init__(self, target, daemon=None):
        self._target = target
        self.daemon = daemon

    def start(self):
        self._target()


def _find_static_labels(window: wx.Window) -> list[str]:
    labels: list[str] = []
    for child in window.GetChildren():
        if isinstance(child, wx.StaticText):
            labels.append(child.GetLabel())
        labels.extend(_find_static_labels(child))
    return labels


def test_welcome_dialog_open(monkeypatch, temp_vault):
    monkeypatch.setattr(
        "SignSeal.gui.vault_dialogs.ask_open_vault", lambda p: temp_vault
    )

    dialog = WelcomeDialog()
    # Simulate closing via 'Open Vault'
    dialog.on_open(None)
    assert dialog.ss == temp_vault
    dialog.Destroy()


def test_welcome_dialog_does_not_repeat_window_title() -> None:
    dialog = WelcomeDialog()
    normalized_labels = {
        " ".join(label.split()) for label in _find_static_labels(dialog)
    }

    assert dialog.GetTitle() == "SignSeal"
    assert "SignSeal" not in _find_static_labels(dialog)
    assert " ".join(WELCOME_SECURITY_NOTICE.split()) in normalized_labels

    dialog.Destroy()


def test_about_dialog_shows_requested_metadata() -> None:
    dialog = AboutDialog(None)
    labels = _find_static_labels(dialog)
    normalized_labels = {" ".join(label.split()) for label in labels}

    assert dialog.GetTitle() == "About SignSeal"
    assert "SignSeal" in labels
    assert "Version: v0.1.0" in labels
    assert "Created: 2026-03-23" in labels
    assert "Created by: Chi Kim" in labels
    assert "License: MIT" in labels
    assert " ".join(APP_SECURITY_NOTICE.split()) in normalized_labels
    assert dialog.FindWindowById(wx.ID_OK, dialog).GetLabel() == "Close"

    dialog.Destroy()


def test_main_frame_vault_menu_includes_about_item(temp_vault) -> None:
    frame = MainFrame(temp_vault)
    vault_menu = frame.GetMenuBar().GetMenu(0)
    labels = [
        vault_menu.FindItemByPosition(index).GetItemLabelText()
        for index in range(vault_menu.GetMenuItemCount())
        if not vault_menu.FindItemByPosition(index).IsSeparator()
    ]

    assert "About..." in labels

    frame.Destroy()


def test_main_frame_about_opens_dialog(monkeypatch, temp_vault) -> None:
    frame = MainFrame(temp_vault)
    calls: list[object] = []

    class MockAboutDialog:
        def __init__(self, parent):
            calls.append(parent)

        def ShowModal(self):
            calls.append("shown")
            return wx.ID_OK

        def Destroy(self):
            calls.append("destroyed")

    monkeypatch.setattr("SignSeal.gui.main_frame.AboutDialog", MockAboutDialog)

    frame.on_about(None)

    assert calls == [frame, "shown", "destroyed"]

    frame.Destroy()


def test_ask_new_vault_appends_locked_extension_after_user_suffix(
    monkeypatch, tmp_path
):
    created: dict[str, object] = {}
    form_calls: list[object] = []
    save_calls: list[dict[str, object]] = []

    class MockCreateVaultDialog:
        def __init__(self, parent=None):
            form_calls.append(parent)
            self.entry_name = "new-vault.db"
            self.password = "password12345"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

    class MockDirDialog:
        def __init__(self, parent, message, defaultPath="", style=0):
            save_calls.append(
                {
                    "parent": parent,
                    "message": message,
                    "defaultPath": defaultPath,
                    "style": style,
                }
            )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetPath(self):
            return str(tmp_path)

    def mock_vault(password, vault_path, overwrite=False):
        created["password"] = password
        created["vault_path"] = vault_path
        created["overwrite"] = overwrite
        return created

    monkeypatch.setattr(
        "SignSeal.gui.vault_dialogs.CreateVaultDialog",
        MockCreateVaultDialog,
    )
    monkeypatch.setattr(wx, "DirDialog", MockDirDialog)
    monkeypatch.setattr("SignSeal.gui.vault_dialogs.SignSeal", mock_vault)

    result = ask_new_vault()

    assert result is created
    assert form_calls == [None]
    assert save_calls == [
        {
            "parent": None,
            "message": "Choose Vault Folder",
            "defaultPath": "",
            "style": wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST,
        }
    ]
    assert created["password"] == "password12345"
    assert created["vault_path"] == tmp_path / f"new-vault.db{_V}"
    assert created["overwrite"] is True


def test_main_frame_empty_vault_state(temp_vault):
    frame = MainFrame(temp_vault)
    assert frame.GetTitle() == f"SignSeal - {temp_vault.vault_path}"
    # Vault is empty, so welcome panel should be shown
    assert frame.welcome_panel.IsShown()
    assert not frame.splitter.IsShown()
    assert "SignSeal" not in _find_static_labels(frame.welcome_panel)
    frame.Destroy()


def test_main_frame_switch_vault_updates_views_and_closes_previous(tmp_path):
    old_ss = SignSeal("password12345", tmp_path / f"old{_V}")
    new_ss = SignSeal("password12345", tmp_path / f"new{_V}")
    new_ss.vault.set_entry("Alice", note="fresh vault")

    frame = MainFrame(old_ss)
    frame.switch_vault(new_ss)

    assert frame.ss is new_ss
    assert frame.panel_keys.ss is new_ss
    assert frame.panel_process.ss is new_ss
    assert frame.GetTitle() == f"SignSeal - {new_ss.vault_path}"
    assert frame.splitter.IsShown()
    assert not frame.welcome_panel.IsShown()
    with pytest.raises(SignSealError, match="vault is closed"):
        old_ss.list()

    frame.Destroy()


def test_main_frame_change_password_success(monkeypatch, temp_vault, tmp_path):
    frame = MainFrame(temp_vault)
    notices: list[tuple[str, str]] = []

    class MockPasswordDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetValue(self):
            return "password12345"

    monkeypatch.setattr(wx, "PasswordEntryDialog", MockPasswordDialog)
    monkeypatch.setattr(
        "SignSeal.gui.main_frame.prompt_new_password",
        lambda *args, **kwargs: "new-password-12345",
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, caption, *args, **kwargs: notices.append((message, caption))
        or wx.OK,
    )

    frame.on_change_password(None)

    frame.Destroy()

    with pytest.raises(SignSealError):
        SignSeal("password12345", tmp_path / f"test_gui{_V}")
    reopened = SignSeal("new-password-12345", tmp_path / f"test_gui{_V}")
    assert notices == [("Success.", "Info")]
    reopened.close()


def test_main_frame_change_password_rejects_incorrect_current_password(
    monkeypatch, temp_vault
):
    frame = MainFrame(temp_vault)
    notices: list[tuple[str, str]] = []
    prompted: list[bool] = []

    class MockPasswordDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetValue(self):
            return "wrong-password"

    monkeypatch.setattr(wx, "PasswordEntryDialog", MockPasswordDialog)
    monkeypatch.setattr(
        "SignSeal.gui.main_frame.prompt_new_password",
        lambda *args, **kwargs: prompted.append(True),
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, caption, *args, **kwargs: notices.append((message, caption))
        or wx.OK,
    )

    frame.on_change_password(None)

    assert prompted == []
    assert notices == [("Incorrect password.", "Error")]

    frame.Destroy()


def test_key_panel_generate_and_rename(monkeypatch, temp_vault):
    frame = MainFrame(temp_vault)

    class MockGenerateDialog:
        def __init__(self, *args, **kwargs):
            self.entry_name = "Alice"
            self.password = "alice-password-123"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

    monkeypatch.setattr(
        "SignSeal.gui.key_panel.CreateVaultDialog",
        MockGenerateDialog,
    )

    # 1. Generate Key
    frame.panel_keys.on_generate(None)

    assert "Alice" in temp_vault.list()

    # Now vault is not empty
    frame._check_empty_vault()
    assert not frame.welcome_panel.IsShown()
    assert frame.splitter.IsShown()

    # 2. Rename Key
    class MockRenameDialog:
        def __init__(self, *args, **kwargs):
            self.value = "Bob"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetValue(self):
            return self.value

    monkeypatch.setattr(wx, "TextEntryDialog", MockRenameDialog)

    # We must mock _get_selected_name directly since wx UI interactions without real events can be flaky
    monkeypatch.setattr(frame.panel_keys, "_get_selected_name", lambda: "Alice")

    frame.panel_keys.on_rename(None)

    assert "Bob" in temp_vault.list()
    assert "Alice" not in temp_vault.list()

    frame.Destroy()


def test_process_panel_encrypt_decrypt(monkeypatch, tmp_path):
    vault_path = tmp_path / f"test_process{_V}"
    ss = SignSeal("password12345", vault_path)

    pub_e, priv_d, pub_v, priv_s = generate_key_material(
        "alice-password-123", security="low"
    )
    ss.vault.set_entry("Alice", pub_e, priv_d, pub_v, priv_s)

    frame = MainFrame(ss)

    data_file = tmp_path / "secret.txt"
    data_file.write_text("gui secret info")

    # Set UI states via proper methods
    frame.panel_process.set_input_path(str(data_file))

    # Force selections instead of SetStringSelection which requires the string to be populated in the choice
    monkeypatch.setattr(
        frame.panel_process.combo_recipient, "GetStringSelection", lambda: "Alice"
    )
    monkeypatch.setattr(
        frame.panel_process.combo_sender, "GetStringSelection", lambda: "Alice"
    )
    frame.panel_process.password.SetValue("alice-password-123")

    errors = []

    def mock_msgbox(message, *args, **kwargs):
        if "Error" in args or kwargs.get("caption") == "Error":
            errors.append(message)
        return wx.OK

    monkeypatch.setattr(wx, "MessageBox", mock_msgbox)

    def mock_status(msg):
        pass  # Ignore status callback for errors, we have it from msgbox

    frame.panel_process.status_callback = mock_status

    import time

    class MockEvent:
        pass

    # Run Encrypt
    frame.panel_process.on_action(MockEvent())

    ciphertext = tmp_path / f"secret.txt{_F}"
    for _ in range(50):
        if ciphertext.exists() or errors:
            break
        time.sleep(0.1)

    if errors:
        raise Exception(f"Encryption failed, errors: {errors}")
    assert ciphertext.exists()

    # Run Decrypt
    data_file.unlink()  # Delete original

    frame.panel_process.set_input_path(str(ciphertext))
    frame.panel_process.password.SetValue("alice-password-123")

    frame.panel_process.on_action(MockEvent())

    for _ in range(50):
        if data_file.exists() or errors:
            break
        time.sleep(0.1)

    if errors:
        raise Exception(f"Decryption failed, errors: {errors}")

    assert data_file.exists()
    assert data_file.read_text() == "gui secret info"

    frame.Destroy()


def test_key_panel_remove(monkeypatch, temp_vault):
    pub_e, priv_d, pub_v, priv_s = generate_key_material(
        "alice-password-123", security="low"
    )
    temp_vault.vault.set_entry("Alice", pub_e, priv_d, pub_v, priv_s)

    frame = MainFrame(temp_vault)

    # Mock _get_selected_name on the instance directly
    frame.panel_keys._get_selected_name = MagicMock(return_value="Alice")

    # Mock KeySelectionDialog
    class MockKeySelectionDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def get_selections(self):
            return {
                "encrypt_key": True,
                "decrypt_key": True,
                "verify_key": True,
                "sign_key": True,
            }

    monkeypatch.setattr(
        "SignSeal.gui.key_panel.KeySelectionDialog", MockKeySelectionDialog
    )
    # Mock MessageBox confirmation
    monkeypatch.setattr(wx, "MessageBox", lambda *args, **kwargs: wx.YES)

    # Trigger on_remove. Using a mock for event to ensure it triggers the MessageBox path
    frame.panel_keys.on_remove(MockEvent())

    assert "Alice" not in temp_vault.list()

    frame.Destroy()


def test_key_panel_import_overwrite_cancel_preserves_existing_key(
    monkeypatch, tmp_path
):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    old_encrypt, _, _, _ = generate_key_material("old-password-123", security="low")
    ss.vault.set_entry("Alice", encrypt_key=old_encrypt)
    frame = MainFrame(ss)

    source_dir = tmp_path / "import_keys"
    source_dir.mkdir()
    new_encrypt, _, _, _ = generate_key_material("new-password-123", security="low")
    (source_dir / KEY_SPECS_BY_NAME["encrypt"].filename).write_bytes(
        KeyFormat.pack(KeyFormat.ENCRYPT, new_encrypt)
    )

    monkeypatch.setattr(wx, "MessageBox", lambda *args, **kwargs: wx.NO)

    frame.panel_keys.on_import(
        MockEvent(),
        import_path=source_dir,
        name="Alice",
        selections={"encrypt_key": True},
    )

    assert ss.vault.get_entry("Alice").key_bytes("encrypt_key") == old_encrypt

    frame.Destroy()


def test_key_panel_export_overwrite_cancel_preserves_existing_file(
    monkeypatch, tmp_path
):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    ss.vault.set_entry("Alice", encrypt_key=public_encrypt)
    frame = MainFrame(ss)
    frame.panel_keys._get_selected_name = MagicMock(return_value="Alice")

    export_root = tmp_path / "exports"
    target_file = export_root / "Alice" / KEY_SPECS_BY_NAME["encrypt"].filename
    target_file.parent.mkdir(parents=True)
    target_file.write_bytes(b"sentinel")

    monkeypatch.setattr(wx, "MessageBox", lambda *args, **kwargs: wx.NO)

    frame.panel_keys.on_export(
        MockEvent(),
        target_dir=export_root,
        selections={"encrypt_key": True},
    )

    assert target_file.read_bytes() == b"sentinel"

    frame.Destroy()


def test_key_panel_manual_add_overwrite_cancel_preserves_existing_key(
    monkeypatch, tmp_path
):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    old_encrypt, _, _, _ = generate_key_material("old-password-123", security="low")
    new_encrypt, _, _, _ = generate_key_material("new-password-123", security="low")
    ss.vault.set_entry("Alice", encrypt_key=old_encrypt)
    frame = MainFrame(ss)
    frame.panel_keys._get_selected_name = MagicMock(return_value="Alice")
    paper_key = get_alphanumeric_key(new_encrypt, expected_type="encrypt")

    class MockTextDialog:
        def __init__(self, *args, **kwargs):
            self.value = paper_key

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

        def GetValue(self):
            return self.value

    monkeypatch.setattr(wx, "TextEntryDialog", MockTextDialog)
    monkeypatch.setattr(wx, "MessageBox", lambda *args, **kwargs: wx.NO)

    frame.panel_keys.on_add_manual(MockEvent())

    assert ss.vault.get_entry("Alice").key_bytes("encrypt_key") == old_encrypt

    frame.Destroy()


def test_process_panel_signed_decrypt_warning_cancel_skips_run(monkeypatch, tmp_path):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    _, private_decrypt, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    ss.vault.set_entry("Alice", decrypt_key=private_decrypt)
    frame = MainFrame(ss)
    statuses: list[str] = []
    run_called: list[bool] = []
    warnings: list[str] = []

    frame.panel_process.selected_path = str(tmp_path / f"ciphertext{_F}")
    frame.panel_process.mode = ProcessMode.DECRYPT
    frame.panel_process.status_callback = statuses.append
    frame.panel_process.password.SetValue("entry-password-123")

    monkeypatch.setattr(
        frame.panel_process.combo_recipient, "GetStringSelection", lambda: "Alice"
    )
    monkeypatch.setattr(
        frame.panel_process.combo_sender,
        "GetStringSelection",
        lambda: frame.panel_process._NO_SENDER_LABEL,
    )
    monkeypatch.setattr(
        frame.panel_process.workflow,
        "unverified_decrypt_warning",
        lambda *args, **kwargs: "warning text",
    )
    monkeypatch.setattr(
        frame.panel_process.ss,
        "decrypt",
        lambda *args, **kwargs: run_called.append(True),
    )
    monkeypatch.setattr(
        "SignSeal.gui.process_panel.threading.Thread",
        ImmediateThread,
    )
    monkeypatch.setattr(
        "SignSeal.gui.process_panel.wx.CallAfter",
        lambda fn, *args, **kwargs: fn(*args, **kwargs),
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, *args, **kwargs: warnings.append(message) or wx.NO,
    )

    frame.panel_process.on_action(MockEvent())

    assert run_called == []
    assert statuses == ["Cancelled"]
    assert warnings == ["warning text"]
    assert frame.panel_process.btn_action.IsEnabled()

    frame.Destroy()


def test_process_panel_existing_output_cancel_skips_run(monkeypatch, tmp_path):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    ss.vault.set_entry("Alice", encrypt_key=public_encrypt)
    frame = MainFrame(ss)
    prompts: list[str] = []
    run_called: list[bool] = []

    input_path = tmp_path / "message.txt"
    input_path.write_text("hello", encoding="utf-8")
    output_path = tmp_path / f"message.txt{_F}"
    output_path.write_bytes(b"existing")

    frame.panel_process.selected_path = str(input_path)
    frame.panel_process.mode = ProcessMode.ENCRYPT

    monkeypatch.setattr(
        frame.panel_process.combo_recipient, "GetStringSelection", lambda: "Alice"
    )
    monkeypatch.setattr(
        frame.panel_process.combo_sender,
        "GetStringSelection",
        lambda: frame.panel_process._NO_SENDER_LABEL,
    )
    monkeypatch.setattr(
        frame.panel_process.workflow,
        "output_path",
        lambda *args, **kwargs: output_path,
    )
    monkeypatch.setattr(
        frame.panel_process.ss,
        "encrypt",
        lambda *args, **kwargs: run_called.append(True),
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, *args, **kwargs: prompts.append(message) or wx.NO,
    )

    frame.panel_process.on_action(MockEvent())

    assert run_called == []
    assert prompts and "Replace it?" in prompts[0]

    frame.Destroy()


def test_process_panel_error_shows_message_and_resets_state(monkeypatch, tmp_path):
    ss = SignSeal("password12345", tmp_path / f"vault{_V}")
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    ss.vault.set_entry("Alice", encrypt_key=public_encrypt)
    frame = MainFrame(ss)
    statuses: list[str] = []
    messages: list[str] = []

    input_path = tmp_path / "message.txt"
    input_path.write_text("hello", encoding="utf-8")
    frame.panel_process.selected_path = str(input_path)
    frame.panel_process.mode = ProcessMode.ENCRYPT
    frame.panel_process.status_callback = statuses.append
    frame.panel_process.password.SetValue("should-clear")

    monkeypatch.setattr(
        frame.panel_process.combo_recipient, "GetStringSelection", lambda: "Alice"
    )
    monkeypatch.setattr(
        frame.panel_process.combo_sender,
        "GetStringSelection",
        lambda: frame.panel_process._NO_SENDER_LABEL,
    )
    monkeypatch.setattr(
        frame.panel_process.ss,
        "encrypt",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        "SignSeal.gui.process_panel.threading.Thread",
        ImmediateThread,
    )
    monkeypatch.setattr(
        "SignSeal.gui.process_panel.wx.CallAfter",
        lambda fn, *args, **kwargs: fn(*args, **kwargs),
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, *args, **kwargs: messages.append(message) or wx.OK,
    )

    frame.panel_process.on_action(MockEvent(), replace=True)

    assert statuses == ["Encrypting...", "Error"]
    assert messages == ["boom"]
    assert frame.panel_process.password.GetValue() == ""
    assert frame.panel_process.btn_action.IsEnabled()

    frame.Destroy()


def test_key_selection_dialog_uses_key_specs() -> None:
    key_states = {
        "encrypt_key": True,
        "decrypt_key": False,
        "verify_key": True,
        "sign_key": False,
    }
    dialog = KeySelectionDialog(None, "Select", key_states)

    assert list(dialog.checks) == [spec.field_name for spec in KEY_SPECS]
    assert [dialog.checks[spec.field_name].GetLabel() for spec in KEY_SPECS] == [
        spec.label for spec in KEY_SPECS
    ]
    assert dialog.checks["encrypt_key"].IsEnabled()
    assert not dialog.checks["decrypt_key"].IsEnabled()

    dialog.Destroy()


def test_key_selection_dialog_uses_contextual_confirm_label() -> None:
    dialog = KeySelectionDialog(
        None,
        "Export Keys",
        {"encrypt_key": True},
        confirm_label="Export",
    )

    assert dialog.FindWindowById(wx.ID_OK, dialog).GetLabel() == "Export"
    assert dialog.FindWindowById(wx.ID_CANCEL, dialog).GetLabel() == "Cancel"

    dialog.Destroy()


def test_create_vault_dialog_uses_custom_confirm_label() -> None:
    dialog = CreateVaultDialog(title="Generate Keys", create_label="Generate")

    assert dialog.FindWindowById(wx.ID_OK, dialog).GetLabel() == "Generate"
    assert dialog.FindWindowById(wx.ID_CANCEL, dialog).GetLabel() == "Cancel"

    dialog.Destroy()


def test_key_panel_export_uses_export_confirm_label(monkeypatch, temp_vault) -> None:
    frame = MainFrame(temp_vault)
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    temp_vault.vault.set_entry("Alice", encrypt_key=public_encrypt)
    frame.panel_keys.refresh_lists()
    frame.panel_keys._get_selected_name = MagicMock(return_value="Alice")
    captured: dict[str, object] = {}

    class MockKeySelectionDialog:
        def __init__(self, *args, **kwargs):
            captured["confirm_label"] = kwargs.get("confirm_label")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_CANCEL

        def get_selections(self):
            return {}

    monkeypatch.setattr(
        "SignSeal.gui.key_panel.KeySelectionDialog",
        MockKeySelectionDialog,
    )

    frame.panel_keys.on_export(MockEvent())

    assert captured == {"confirm_label": "Export"}

    frame.Destroy()


def test_key_panel_remove_uses_remove_confirm_label(monkeypatch, temp_vault) -> None:
    frame = MainFrame(temp_vault)
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123", security="low"
    )
    temp_vault.vault.set_entry("Alice", encrypt_key=public_encrypt)
    frame.panel_keys.refresh_lists()
    frame.panel_keys._get_selected_name = MagicMock(return_value="Alice")
    captured: dict[str, object] = {}

    class MockKeySelectionDialog:
        def __init__(self, *args, **kwargs):
            captured["confirm_label"] = kwargs.get("confirm_label")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_CANCEL

        def get_selections(self):
            return {}

    monkeypatch.setattr(
        "SignSeal.gui.key_panel.KeySelectionDialog",
        MockKeySelectionDialog,
    )

    frame.panel_keys.on_remove(MockEvent())

    assert captured == {"confirm_label": "Remove"}

    frame.Destroy()


def test_ask_new_vault_uses_contextual_dialog_labels(monkeypatch, tmp_path) -> None:
    label_calls: list[tuple[str, str | None, str | None]] = []

    class MockCreateVaultDialog:
        def __init__(self, parent=None):
            self.entry_name = "new-vault"
            self.password = "password12345"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_OK

    class MockDirDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ShowModal(self):
            return wx.ID_CANCEL

        def GetPath(self):
            return str(tmp_path)

    monkeypatch.setattr(
        "SignSeal.gui.vault_dialogs.CreateVaultDialog",
        MockCreateVaultDialog,
    )
    monkeypatch.setattr(wx, "DirDialog", MockDirDialog)
    monkeypatch.setattr(
        "SignSeal.gui.vault_dialogs.set_dialog_button_labels",
        lambda dialog, *, affirmative=None, cancel=None: label_calls.append(
            (type(dialog).__name__, affirmative, cancel)
        ),
    )

    assert ask_new_vault() is None
    assert label_calls == [("MockDirDialog", "Choose", "Cancel")]


def test_fingerprint_dialog_copy_warns_and_schedules_clear(monkeypatch) -> None:
    dialog = FingerprintDialog(None, "Fingerprints", "SECRET")
    messages: list[tuple[str, str]] = []
    scheduled: list[bool] = []

    monkeypatch.setattr(
        dialog, "_write_clipboard_text", lambda value: value == "SECRET"
    )
    monkeypatch.setattr(
        dialog,
        "_schedule_clipboard_clear",
        lambda: scheduled.append(True),
    )
    monkeypatch.setattr(
        wx,
        "MessageBox",
        lambda message, caption, *args, **kwargs: messages.append((message, caption))
        or wx.OK,
    )

    dialog.on_copy(object())

    assert scheduled == [True]
    assert messages
    assert "cleared after" in messages[0][0]

    dialog.Destroy()


def test_fingerprint_dialog_clears_only_matching_clipboard(monkeypatch) -> None:
    dialog = FingerprintDialog(None, "Paper Keys", "SECRET")
    cleared: list[bool] = []

    monkeypatch.setattr(dialog, "_read_clipboard_text", lambda: "SECRET")
    monkeypatch.setattr(
        dialog,
        "_clear_clipboard_text",
        lambda: cleared.append(True) or True,
    )
    dialog.clear_clipboard_if_unchanged()

    monkeypatch.setattr(dialog, "_read_clipboard_text", lambda: "OTHER")
    dialog.clear_clipboard_if_unchanged()

    assert cleared == [True]

    dialog.Destroy()
