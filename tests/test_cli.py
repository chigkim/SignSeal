from __future__ import annotations

import builtins
from pathlib import Path
import pytest

import SignSeal
from SignSeal import SignSealError
from SignSeal.app_services import KeyWorkflowService
from SignSeal.config import Config
from SignSeal.io_utils import KeyFormat
from SignSeal.key_generation import generate_key_material
from SignSeal.key_specs import KEY_SPECS_BY_NAME

from SignSeal.cli.main import CLIContext, main

_F: str = Config.FILE_EXT
_V: str = Config.VAULT_EXT


def test_cli_init_generate_list_and_show(patch_prompts, capsys, tmp_path: Path) -> None:
    vault_path = tmp_path / f"vault{_V}"

    patch_prompts(["vault-password-123", "vault-password-123"])
    main(["init", "-v", str(vault_path)])

    patch_prompts(["entry-password-123", "entry-password-123", "vault-password-123"])
    main(["generate", "alice", "--security", "low", "-v", str(vault_path)])

    patch_prompts(["vault-password-123"])
    main(["list", "-v", str(vault_path)])
    list_output = capsys.readouterr().out

    patch_prompts(
        [
            "vault-password-123",
            "entry-password-123",
        ]
    )
    main(["show", "alice", "--paper", "-v", str(vault_path)])
    show_output = capsys.readouterr().out

    assert "alice" in list_output
    assert "generated" in list_output
    assert "Full Bundle" in show_output
    assert "Encrypt (Public)" in show_output


def test_cli_import_cancelled_when_overwrite_rejected(
    monkeypatch,
    patch_prompts,
    capsys,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / f"vault{_V}"
    export_root = tmp_path / "exports"

    patch_prompts(["vault-password-123", "vault-password-123"])
    main(["init", "-v", str(vault_path)])

    patch_prompts(["entry-password-123", "entry-password-123", "vault-password-123"])
    main(["generate", "alice", "--security", "low", "-v", str(vault_path)])

    workflow = KeyWorkflowService()
    vault = SignSeal("vault-password-123", vault_path).vault
    workflow.export_all_keys(
        vault,
        "alice",
        export_root,
        private_passwords={
            "decrypt_key": "entry-password-123",
            "sign_key": "entry-password-123",
        },
    )

    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    patch_prompts(["vault-password-123"])
    main(["import", "alice", str(export_root / "alice"), "-v", str(vault_path)])
    output = capsys.readouterr().out

    assert "Import cancelled" in output


def test_cli_standalone_generate_to_path(tmp_path: Path, patch_prompts) -> None:
    keys_dir = tmp_path / "my_keys"

    # Standalone generate doesn't use vault, just prompts for password
    patch_prompts(["paper-password-123", "paper-password-123"])
    main(["generate", str(keys_dir)])

    assert (keys_dir / KEY_SPECS_BY_NAME["encrypt"].filename).exists()
    assert (keys_dir / KEY_SPECS_BY_NAME["decrypt"].filename).exists()
    assert (keys_dir / KEY_SPECS_BY_NAME["verify"].filename).exists()
    assert (keys_dir / KEY_SPECS_BY_NAME["sign"].filename).exists()


def test_cli_vault_requirement_enforcement(monkeypatch) -> None:
    # Try to list without -v
    with pytest.raises(SystemExit):
        main(["list"])


def test_cli_rejects_outdated_command_aliases() -> None:
    for alias in ("gen", "enc", "dec", "ver", "imp", "exp"):
        with pytest.raises(SystemExit):
            main([alias])


def test_cli_encrypt_decrypt_roundtrip_vault(
    tmp_path: Path, patch_prompts, capsys
) -> None:
    vault_path = tmp_path / f"secure{_V}"
    data_file = tmp_path / "secret.txt"
    data_file.write_text("top secret info")

    vpass = "vault-password-123"
    apass = "alice-password-123"

    # 1. Init vault: asks for new password twice
    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault_path)], context=CLIContext())

    # 2. Generate key:
    # handle_generate calls prompt_new_password(apass, apass)
    # THEN context.get_vault() calls getpass(vpass)
    patch_prompts([apass, apass, vpass])
    main(
        ["generate", "alice", "--security", "low", "-v", str(vault_path)],
        context=CLIContext(),
    )

    # 3. Encrypt:
    # 1. resolve_vault_for_refs calls get_vault() -> asks for vpass
    # 2. handle_encrypt calls prompt_password(prompt) -> asks for apass
    patch_prompts([vpass, apass])
    main(
        [
            "encrypt",
            str(data_file),
            "-r",
            "alice",
            "-s",
            "alice",
            "-v",
            str(vault_path),
        ],
        context=CLIContext(),
    )

    ciphertext = tmp_path / f"secret.txt{_F}"
    assert ciphertext.exists()
    data_file.unlink()  # delete original

    # 4. Decrypt:
    # 1. resolve_vault_for_refs calls get_vault() -> asks for vpass
    # 2. handle_decrypt calls prompt_password(prompt) -> asks for apass
    patch_prompts([vpass, apass])
    main(
        [
            "decrypt",
            str(ciphertext),
            "-r",
            "alice",
            "-s",
            "alice",
            "-v",
            str(vault_path),
        ],
        context=CLIContext(),
    )

    assert data_file.read_text() == "top secret info"


def test_cli_encrypt_decrypt_optional_signing(
    tmp_path: Path, patch_prompts, capsys
) -> None:
    vault_path = tmp_path / f"secure_no_sign{_V}"
    data_file = tmp_path / "secret_unsigned.txt"
    data_file.write_text("not signed info")

    vpass = "vault-password-123"
    apass = "alice-password-123"

    # 1. Init vault
    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault_path)], context=CLIContext())

    # 2. Generate key
    patch_prompts([apass, apass, vpass])
    main(
        ["generate", "alice", "--security", "low", "-v", str(vault_path)],
        context=CLIContext(),
    )

    # 3. Encrypt WITHOUT sender:
    # 1. resolve_vault_for_refs calls get_vault() -> asks for vpass
    patch_prompts([vpass])
    main(
        [
            "encrypt",
            str(data_file),
            "-r",
            "alice",
            "-v",
            str(vault_path),
        ],
        context=CLIContext(),
    )

    ciphertext = tmp_path / f"secret_unsigned.txt{_F}"
    assert ciphertext.exists()
    data_file.unlink()

    # 4. Decrypt WITHOUT sender:
    # 1. resolve_vault_for_refs calls get_vault() -> asks for vpass
    # 2. handle_decrypt calls prompt_password(prompt) -> asks for apass
    patch_prompts([vpass, apass])
    main(
        [
            "decrypt",
            str(ciphertext),
            "-r",
            "alice",
            "-v",
            str(vault_path),
        ],
        context=CLIContext(),
    )

    assert data_file.read_text() == "not signed info"


def test_cli_password_change(tmp_path: Path, patch_prompts) -> None:
    vault_path = tmp_path / f"v{_V}"
    pass1 = "password-number-one"
    pass2 = "password-number-two"
    patch_prompts([pass1, pass1])
    main(["init", "-v", str(vault_path)])

    # Change password: asks for old, then new twice
    patch_prompts([pass1, pass2, pass2])
    main(["password", "-v", str(vault_path)])

    # Verify we can open with new password
    patch_prompts([pass2])
    main(["list", "-v", str(vault_path)])


def test_cli_appends_locked_extensions_for_vault_and_encrypt_output(
    tmp_path: Path,
    patch_prompts,
) -> None:
    vault_base = tmp_path / "secure.db"
    data_file = tmp_path / "secret.txt"
    data_file.write_text("top secret info", encoding="utf-8")
    output_base = tmp_path / "secret.enc"

    vpass = "vault-password-123"
    apass = "alice-password-123"

    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault_base)])
    assert (tmp_path / f"secure.db{_V}").exists()

    patch_prompts([apass, apass, vpass])
    main(["generate", "alice", "--security", "low", "-v", str(vault_base)])

    patch_prompts([vpass])
    main(
        [
            "encrypt",
            str(data_file),
            "-r",
            "alice",
            "-o",
            str(output_base),
            "-v",
            str(vault_base),
        ]
    )

    assert Path(f"{output_base}{_F}").exists()


def test_cli_decrypt_cancelled_when_signed_ciphertext_unverified(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    message_path = tmp_path / "message.txt"
    message_path.write_text("signed payload", encoding="utf-8")

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    SignSeal().generate(
        "entry-password-123",
        output_dir=key_dir,
        force=True,
        security="low",
    )

    SignSeal().encrypt(
        message_path,
        recipient_key=key_dir / KEY_SPECS_BY_NAME["encrypt"].filename,
        sender_key=key_dir / KEY_SPECS_BY_NAME["sign"].filename,
        sender_passphrase="entry-password-123",
    )
    message_path.unlink()

    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    main(
        [
            "decrypt",
            str(tmp_path / f"message.txt{_F}"),
            "-r",
            str(key_dir / KEY_SPECS_BY_NAME["decrypt"].filename),
        ]
    )
    output = capsys.readouterr().out

    assert "Decrypt cancelled" in output
    assert not message_path.exists()


def test_cli_verify_detached_invalid_signature_exits(
    tmp_path: Path,
    capsys,
) -> None:
    message_path = tmp_path / "message.txt"
    message_path.write_text("signed payload", encoding="utf-8")

    _, _, public_verify, private_sign = generate_key_material(
        "signing-password-123",
        security="low",
    )
    signature_path = tmp_path / "message.txt.sig"
    signature_path.write_bytes(
        SignSeal().sign(
            message_path,
            sender_key=private_sign,
            sender_passphrase="signing-password-123",
        )
    )

    tampered_signature = bytearray(signature_path.read_bytes())
    tampered_signature[-1] ^= 0x01
    signature_path.write_bytes(bytes(tampered_signature))

    public_verify_path = tmp_path / KEY_SPECS_BY_NAME["verify"].filename
    public_verify_path.write_bytes(KeyFormat.pack(KeyFormat.VERIFY, public_verify))

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "verify",
                str(message_path),
                "-s",
                str(public_verify_path),
                "--signature",
                str(signature_path),
            ]
        )

    assert exc_info.value.code == 1
    assert "signature verification failed" in capsys.readouterr().err
