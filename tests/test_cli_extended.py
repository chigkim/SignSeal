from __future__ import annotations

from pathlib import Path
import pytest

from SignSeal.config import Config
from SignSeal.key_encoding import get_alphanumeric_bundle
from SignSeal.key_generation import generate_key_material
from SignSeal.key_specs import KEY_SPECS_BY_NAME
from SignSeal.cli.main import CLIContext, main

_V: str = Config.VAULT_EXT


def test_cli_rename_remove_roundtrip(tmp_path: Path, patch_prompts) -> None:
    vault_path = tmp_path / f"test{_V}"
    vpass = "vault-password-123"
    apass = "alice-password-123"

    # 1. Init
    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault_path)], context=CLIContext())

    # 2. Generate Alice
    patch_prompts([apass, apass, vpass])
    main(["generate", "Alice", "-v", str(vault_path)], context=CLIContext())

    # 3. Rename Alice -> Bob
    patch_prompts([vpass])
    main(["rename", "Alice", "Bob", "-v", str(vault_path)], context=CLIContext())

    # Verify Rename
    patch_prompts([vpass])
    ctx = CLIContext()
    ctx.vault_path = vault_path
    entries = ctx.get_client().list()
    assert "Bob" in entries
    assert "Alice" not in entries
    ctx.close()

    # 4. Remove Bob
    patch_prompts([vpass])
    main(["remove", "Bob", "-v", str(vault_path)], context=CLIContext())

    # Verify Remove
    patch_prompts([vpass])
    ctx = CLIContext()
    ctx.vault_path = vault_path
    entries = ctx.get_client().list()
    assert "Bob" not in entries
    ctx.close()


def test_cli_export_import_add_roundtrip(tmp_path: Path, patch_prompts) -> None:
    vault_path = tmp_path / f"v1{_V}"
    vault2_path = tmp_path / f"v2{_V}"
    vpass = "vault-password-123"
    apass = "alice-password-123"
    export_dir = tmp_path / "exports"

    # Setup V1 with Alice
    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault_path)], context=CLIContext())
    patch_prompts([apass, apass, vpass])
    main(["generate", "Alice", "-v", str(vault_path)], context=CLIContext())

    # Export Alice
    patch_prompts([vpass])
    main(
        ["export", "Alice", str(export_dir), "-v", str(vault_path)],
        context=CLIContext(),
    )
    assert (export_dir / "Alice").exists()

    # Import into V2
    patch_prompts([vpass, vpass])
    main(["init", "-v", str(vault2_path)], context=CLIContext())
    patch_prompts([vpass])
    main(
        ["import", "AliceClone", str(export_dir / "Alice"), "-v", str(vault2_path)],
        context=CLIContext(),
    )

    # Verify Import
    patch_prompts([vpass])
    ctx = CLIContext()
    ctx.vault_path = vault2_path
    entries = ctx.get_client().list()
    assert "AliceClone" in entries
    ctx.close()
    # Capture output to get paper key
    # (Actually we can just generate it manually for 'add' test)
    pub_e, priv_d, pub_v, priv_s = generate_key_material(apass, security="low")
    bundle = get_alphanumeric_bundle(
        {"encrypt": pub_e, "decrypt": priv_d, "verify": pub_v, "sign": priv_s}
    )

    # Add via paper key
    patch_prompts([vpass])
    main(["add", "PaperAlice", bundle, "-v", str(vault2_path)], context=CLIContext())

    patch_prompts([vpass])
    ctx = CLIContext()
    ctx.vault_path = vault2_path
    entries = ctx.get_client().list()
    assert "PaperAlice" in entries
    ctx.close()


def test_cli_sign_verify_standalone(tmp_path: Path, patch_prompts, capsys) -> None:
    data_file = tmp_path / "test.txt"
    data_file.write_text("hello")
    apass = "alice-password-123"

    # 1. Generate standalone keys
    patch_prompts([apass, apass])
    main(["generate", str(tmp_path)])

    priv_s = tmp_path / KEY_SPECS_BY_NAME["sign"].filename
    pub_v = tmp_path / KEY_SPECS_BY_NAME["verify"].filename

    # 2. Sign
    patch_prompts([apass])
    main(["sign", str(data_file), "-s", str(priv_s)])

    sig_file = tmp_path / "test.txt.sig"
    assert sig_file.exists()

    # 3. Verify
    main(["verify", str(data_file), "-s", str(pub_v), "--signature", str(sig_file)])
    out = capsys.readouterr().out
    assert "Verified" in out or "fingerprint" in out


def test_cli_fingerprint(tmp_path: Path, patch_prompts, capsys) -> None:
    apass = "alice-password-123"

    # 1. Generate keys
    patch_prompts([apass, apass])
    main(["generate", str(tmp_path)], context=CLIContext())

    # 2. Check fingerprint
    pub_e = tmp_path / KEY_SPECS_BY_NAME["encrypt"].filename
    main(["fingerprint", str(pub_e)])
    out = capsys.readouterr().out
    assert ":" in out  # fingerprint format
