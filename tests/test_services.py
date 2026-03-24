from __future__ import annotations

from pathlib import Path

import SignSeal
from SignSeal.config import Config
from SignSeal.exceptions import SignSealError
from SignSeal.app_services import KeyWorkflowService, ProcessWorkflowService
from SignSeal.models import ProcessMode
from SignSeal.io_utils import KeyFormat
from SignSeal.key_generation import generate_key_material
from SignSeal.key_specs import KEY_SPECS_BY_NAME
from SignSeal.vault import Vault

_F: str = Config.FILE_EXT
_V: str = Config.VAULT_EXT
_K: str = Config.KEY_EXT


def test_key_workflow_service_export_import_and_remove(tmp_path: Path) -> None:
    source_vault = Vault("vault-password-123", vault_path=tmp_path / f"source{_V}")
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "entry-password-123",
            security="low",
        )
    )
    source_vault.set_entry(
        "alice",
        encrypt_key=public_encrypt,
        decrypt_key=private_decrypt,
        verify_key=public_verify,
        sign_key=private_sign,
        source="generated",
        created_at="now",
    )

    workflow = KeyWorkflowService()
    selections = {
        "encrypt_key": True,
        "decrypt_key": True,
        "verify_key": True,
        "sign_key": True,
    }

    export_summary = workflow.export_keys(
        source_vault.get_entry("alice"),
        "alice",
        tmp_path,
        selections,
        private_passwords={
            "decrypt_key": "entry-password-123",
            "sign_key": "entry-password-123",
        },
    )
    assert export_summary.target_dir.exists()
    assert len(export_summary.exported_paths) == 4

    target_vault = Vault("vault-password-456", vault_path=tmp_path / f"target{_V}")
    import_summary = workflow.import_keys(
        target_vault,
        "bob",
        export_summary.target_dir,
        selections,
    )
    assert import_summary.key_count == 4

    remove_summary = workflow.remove_plan(target_vault.get_entry("bob"), selections)
    assert remove_summary.removed_entry is True
    workflow.apply_remove(target_vault, "bob", selections, removed_entry=True)
    assert target_vault.get_entry("bob") is None


def test_process_workflow_service_mode_and_password_rules() -> None:
    workflow = ProcessWorkflowService()

    assert workflow.mode_for_path("document.txt") == ProcessMode.ENCRYPT
    assert workflow.mode_for_path(f"document.txt{_F}") == ProcessMode.DECRYPT
    assert workflow.mode_for_path(f"document.txt{_F.upper()}") == ProcessMode.ENCRYPT
    assert workflow.output_path("document.txt", ProcessMode.ENCRYPT) == Path(
        f"document.txt{_F}"
    )
    assert workflow.output_path(
        "document.txt", ProcessMode.ENCRYPT, out="custom.enc"
    ) == Path(f"custom.enc{_F}")
    assert workflow.output_path(
        "document.txt", ProcessMode.ENCRYPT, out=f"custom.enc{_F}"
    ) == Path(f"custom.enc{_F}")
    assert workflow.output_path(f"document.txt{_F}", ProcessMode.DECRYPT) == Path(
        "document.txt"
    )
    assert (
        workflow.output_path(f"document.txt{_F.upper()}", ProcessMode.DECRYPT) is None
    )
    assert workflow.password_required(ProcessMode.ENCRYPT, None) is False
    assert workflow.password_required(ProcessMode.DECRYPT, None) is True


def test_key_workflow_service_show_entry_text_and_overwrite_labels(
    tmp_path: Path,
) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / f"vault{_V}")
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "entry-password-123",
            security="low",
        )
    )
    vault.set_entry(
        "alice",
        encrypt_key=public_encrypt,
        decrypt_key=private_decrypt,
        verify_key=public_verify,
        sign_key=private_sign,
        source="generated",
        created_at="now",
        note="trusted contact",
    )

    workflow = KeyWorkflowService()
    rendered = workflow.show_entry_text(
        "alice",
        vault.get_entry("alice"),
        include_paper_keys=True,
        private_passwords={
            "decrypt_key": "entry-password-123",
            "sign_key": "entry-password-123",
        },
    )
    overwrite = workflow.overwrite_labels(
        vault.get_entry("alice"),
        {"encrypt_key": True, "verify_key": True},
    )

    assert "trusted contact" in rendered
    assert "Full Bundle" in rendered
    assert overwrite == ["Encrypt (Public)", "Verify (Public)"]


def test_key_workflow_service_rejects_noncanonical_directory_filenames(
    tmp_path: Path,
) -> None:
    noncanonical_dir = tmp_path / "noncanonical_keys"
    noncanonical_dir.mkdir()
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123",
        security="low",
    )
    noncanonical_file = noncanonical_dir / f"encrypt{_K}"
    noncanonical_file.write_bytes(
        KeyFormat.pack(KEY_SPECS_BY_NAME["encrypt"].format_code, public_encrypt)
    )

    workflow = KeyWorkflowService()

    try:
        workflow.available_import_selections(noncanonical_dir)
    except SignSealError as exc:
        assert str(exc) == f"no keys found in: {noncanonical_dir}"
    else:
        raise AssertionError("only canonical key filenames should be imported")


def test_process_workflow_service_detects_unverified_signed_ciphertext(
    tmp_path: Path,
) -> None:
    plaintext_path = tmp_path / "message.txt"
    plaintext_path.write_text("signed payload", encoding="utf-8")
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "entry-password-123",
            security="low",
        )
    )

    ciphertext = SignSeal().encrypt(
        plaintext_path.read_bytes(),
        recipient_key=public_encrypt,
        sender_key=private_sign,
        sender_passphrase="entry-password-123",
    )
    ciphertext_path = tmp_path / f"message.txt{_F}"
    ciphertext_path.write_bytes(ciphertext)

    workflow = ProcessWorkflowService()

    assert workflow.unverified_decrypt_warning(
        str(ciphertext_path),
        ProcessMode.DECRYPT,
        None,
    )
    assert (
        workflow.unverified_decrypt_warning(
            str(ciphertext_path),
            ProcessMode.DECRYPT,
            "alice",
        )
        is None
    )
