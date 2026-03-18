from __future__ import annotations

from pathlib import Path

import wx

from ..api import SignSeal
from ..config import Config
from ..exceptions import SignSealError
from ..io_utils import append_extension
from ..passwords import request_new_password, validate_new_password

from .dialogs import WARNING_COLOR, set_dialog_button_labels
from .ui_utils import get_svg_bitmap

WELCOME_SECURITY_NOTICE = (
    "This software has not undergone formal security auditing. Use at your own risk."
)


def _ask_password(
    parent,
    title: str,
    prompt: str,
    *,
    confirm_label: str = "Continue",
) -> str | None:
    with wx.PasswordEntryDialog(parent, prompt, title) as dialog:
        set_dialog_button_labels(dialog, affirmative=confirm_label, cancel="Cancel")
        if dialog.ShowModal() != wx.ID_OK:
            return None
        return dialog.GetValue()


def prompt_new_password(
    parent, title: str, first_prompt: str, confirm_prompt: str
) -> str | None:
    return request_new_password(
        first_prompt,
        confirm_prompt,
        lambda prompt: _ask_password(
            parent,
            title,
            prompt,
            confirm_label="Continue",
        ),
        lambda message: wx.MessageBox(message, "Error"),
    )

class CreateVaultDialog(wx.Dialog):
    def __init__(
        self,
        parent=None,
        *,
        title: str = "Create New Vault",
        name_label: str = "Vault name:",
        default_name: str = "vault",
        create_label: str = "Create",
    ):
        super().__init__(parent, title=title, size=(420, 260))
        self.entry_name: str | None = None
        self.password: str | None = None

        sizer = wx.BoxSizer(wx.VERTICAL)
        form = wx.FlexGridSizer(3, 2, 10, 10)
        form.AddGrowableCol(1, 1)

        form.Add(wx.StaticText(self, label=name_label), 0, wx.ALIGN_CENTER_VERTICAL)
        self.name_ctrl = wx.TextCtrl(self, value=default_name)
        form.Add(self.name_ctrl, 1, wx.EXPAND)

        form.Add(wx.StaticText(self, label="Password:"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.password_ctrl = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        form.Add(self.password_ctrl, 1, wx.EXPAND)

        form.Add(
            wx.StaticText(self, label="Confirm password:"),
            0,
            wx.ALIGN_CENTER_VERTICAL,
        )
        self.confirm_ctrl = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        form.Add(self.confirm_ctrl, 1, wx.EXPAND)

        sizer.Add(form, 1, wx.EXPAND | wx.ALL, 15)
        password_hint = wx.StaticText(
            self,
            label=f"Password must be at least {Config.MIN_PASSWORD_LEN} characters.",
        )
        sizer.Add(password_hint, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)
        sizer.Add(self.CreateButtonSizer(wx.OK | wx.CANCEL), 0, wx.EXPAND | wx.ALL, 15)
        self.SetSizerAndFit(sizer)
        set_dialog_button_labels(self, affirmative=create_label, cancel="Cancel")

        ok_button = self.FindWindowById(wx.ID_OK, self)
        if ok_button is not None:
            ok_button.Bind(wx.EVT_BUTTON, self.on_submit)

    def on_submit(self, _event) -> None:
        entry_name = self.name_ctrl.GetValue().strip()
        if not entry_name:
            wx.MessageBox("Name cannot be empty.", "Error")
            return
        try:
            password = validate_new_password(
                self.password_ctrl.GetValue(),
                self.confirm_ctrl.GetValue(),
            )
        except SignSealError as exc:
            wx.MessageBox(str(exc), "Error")
            return

        self.entry_name = entry_name
        self.password = password
        self.EndModal(wx.ID_OK)


def _confirm_overwrite(parent, vault_path: Path) -> bool:
    if not vault_path.exists():
        return True
    return (
        wx.MessageBox(
            f"'{vault_path.name}' already exists. Replace it?",
            "Confirm Overwrite",
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
            parent,
        )
        == wx.YES
    )


def _ask_new_vault_save_path(parent, vault_name: str) -> Path | None:
    with wx.DirDialog(
        parent,
        "Choose Vault Folder",
        "",
        style=wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST,
    ) as dir_dialog:
        set_dialog_button_labels(dir_dialog, affirmative="Choose", cancel="Cancel")
        if dir_dialog.ShowModal() != wx.ID_OK:
            return None
        base_path = Path(dir_dialog.GetPath()) / vault_name

    resolved_path = append_extension(base_path, Config.VAULT_EXT)
    if not _confirm_overwrite(parent, resolved_path):
        return None
    return resolved_path


def ask_new_vault(parent=None):
    with CreateVaultDialog(parent) as dialog:
        if dialog.ShowModal() != wx.ID_OK:
            return None
        vault_name = dialog.entry_name
        password = dialog.password

    if vault_name is None or password is None:
        return None

    vault_path = _ask_new_vault_save_path(parent, vault_name)
    if vault_path is None:
        return None

    try:
        return SignSeal(password, vault_path, overwrite=True)
    except SignSealError as exc:
        wx.MessageBox(str(exc), "Error")
        return None


def ask_open_vault(parent=None):
    with wx.FileDialog(
        parent,
        "Open Vault",
        "",
        "",
        f"Vault files (*{Config.VAULT_EXT})|*{Config.VAULT_EXT}",
        wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
    ) as file_dialog:
        set_dialog_button_labels(file_dialog, affirmative="Open", cancel="Cancel")
        if file_dialog.ShowModal() != wx.ID_OK:
            return None
        vault_path = Path(file_dialog.GetPath())

    password = _ask_password(
        parent,
        "Login",
        "Vault password:",
        confirm_label="Unlock",
    )
    if password is None:
        return None

    try:
        return SignSeal(password, vault_path)
    except SignSealError as exc:
        wx.MessageBox(str(exc), "Error")
        return None


class WelcomeDialog(wx.Dialog):
    def __init__(self):
        super().__init__(None, title="SignSeal", size=(380, 300))
        self.ss = None

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.AddSpacer(25)

        open_button = wx.Button(self, label="Open Existing Vault", size=(220, 40))
        open_button.SetBitmap(get_svg_bitmap("folder.svg", (20, 20)))
        open_button.Bind(wx.EVT_BUTTON, self.on_open)
        sizer.Add(open_button, 0, wx.ALL | wx.ALIGN_CENTER, 10)

        new_button = wx.Button(self, label="Create New Vault", size=(220, 40))
        new_button.SetBitmap(get_svg_bitmap("add.svg", (16, 16)))
        new_button.Bind(wx.EVT_BUTTON, self.on_new)
        sizer.Add(new_button, 0, wx.ALL | wx.ALIGN_CENTER, 10)

        notice = wx.StaticText(
            self,
            label=WELCOME_SECURITY_NOTICE,
            style=wx.ALIGN_CENTER,
        )
        notice.SetForegroundColour(WARNING_COLOR)
        notice.Wrap(320)
        sizer.Add(notice, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM | wx.ALIGN_CENTER, 15)

        self.SetSizer(sizer)

    def on_open(self, _event) -> None:
        self.ss = ask_open_vault(self)
        if self.ss and self.IsModal():
            self.EndModal(wx.ID_OK)

    def on_new(self, _event) -> None:
        self.ss = ask_new_vault(self)
        if self.ss and self.IsModal():
            self.EndModal(wx.ID_OK)
