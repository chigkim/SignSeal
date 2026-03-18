from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from SignSeal import SignSealError
from SignSeal.config import Config
from SignSeal.key_generation import generate_key_material
from SignSeal.vault import Vault


def test_vault_persists_entries_and_password_changes(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    vault = Vault("vault-password-123", vault_path=vault_path)
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
        created_at="2026-03-19 12:00",
    )
    vault.update_note("alice", "primary key set")

    reopened = Vault("vault-password-123", vault_path=vault_path)
    entry = reopened.get_entry("alice")

    assert entry is not None
    assert entry.source == "generated"
    assert entry.note == "primary key set"

    reopened.rename_entry("alice", "bob")
    reopened.clear_keys("bob", verify_key=True)
    reopened.change_vault_password("vault-password-456")

    with pytest.raises(SignSealError):
        Vault("vault-password-123", vault_path=vault_path)

    changed = Vault("vault-password-456", vault_path=vault_path)
    changed_entry = changed.get_entry("bob")
    assert changed_entry is not None
    assert changed_entry.verify_key is None
    assert changed_entry.note == "primary key set"

    changed.remove_entry("bob")
    assert changed.get_entry("bob") is None


def test_vault_init_overwrite(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"

    # Create first vault
    vault1 = Vault("password12345678", vault_path=vault_path)
    vault1.set_entry("alice", note="original")
    vault1.save()

    # Create second vault over the first one
    # Without overwrite=True, it would load the old one
    vault2 = Vault("password45678901", vault_path=vault_path, overwrite=True)

    # Should be empty
    assert len(vault2.entries()) == 0
    assert vault2.get_entry("alice") is None


def test_vault_appends_locked_extension_after_user_suffix(tmp_path: Path) -> None:
    vault = Vault("password12345678", vault_path=tmp_path / "vault.db")

    assert vault.vault_path == tmp_path / f"vault.db{Config.VAULT_EXT}"
    assert vault.vault_path.exists()


def test_vault_batch_update_saves_once(tmp_path: Path, monkeypatch) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / "vault")
    encrypt_key, decrypt_key, verify_key, sign_key = generate_key_material(
        "entry-password-123",
        security="low",
    )
    save_calls: list[dict[str, object]] = []
    original_save = vault.store.save

    def record_save(data):
        save_calls.append(data)
        original_save(data)

    monkeypatch.setattr(vault.store, "save", record_save)

    with vault.batch_update():
        vault.set_entry(
            "alice",
            encrypt_key=encrypt_key,
            decrypt_key=decrypt_key,
            verify_key=verify_key,
            sign_key=sign_key,
            source="generated",
            created_at="2026-03-19 12:00",
        )
        vault.update_note("alice", "batched")

    assert len(save_calls) == 1
    assert vault.get_entry("alice").note == "batched"


def test_vault_close_is_explicit_and_context_managed(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"

    with Vault("vault-password-123", vault_path=vault_path) as vault:
        vault.set_entry("alice", note="live")
        assert vault.get_entry("alice") is not None

    with pytest.raises(SignSealError, match="vault is closed"):
        vault.entries()


def test_vault_zeroes_removed_key_buffers(tmp_path: Path) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / "vault")
    public_encrypt, _, _, _ = generate_key_material(
        "entry-password-123",
        security="low",
    )
    vault.set_entry("alice", encrypt_key=public_encrypt)

    entry = vault.get_entry("alice")
    assert entry is not None
    previous_buffer = entry.encrypt_key

    vault.clear_keys("alice", encrypt_key=True)

    assert previous_buffer is not None
    assert previous_buffer == bytearray(len(public_encrypt))
    assert vault.get_entry("alice").encrypt_key is None


def test_vault_discards_unknown_entry_fields_on_save(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    vault = Vault("vault-password-123", vault_path=vault_path)
    vault.save()

    prefix_format = Config.PROTECTED_BLOB_PREFIX_FMT
    prefix_len = struct.calcsize(prefix_format)
    blob = vault.vault_path.read_bytes()
    _, _, _, _, _, nonce = struct.unpack(prefix_format, blob[:prefix_len])
    aad = Config.VAULT_AAD_PREFIX + blob[:prefix_len]
    plaintext = vault.store._derived_key

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    decoded = json.loads(
        AESGCM(bytes(plaintext)).decrypt(nonce, blob[prefix_len:], aad).decode("utf-8")
    )
    decoded["entries"]["alice"] = {
        "encrypt_key": None,
        "decrypt_key": None,
        "verify_key": None,
        "sign_key": None,
        "source": "generated",
        "created_at": "2026-03-19 12:00",
        "note": "",
        "legacy_field": "stale",
    }
    vault.store.save(decoded)

    reopened = Vault("vault-password-123", vault_path=vault_path)
    reopened.save()

    rewritten_blob = reopened.vault_path.read_bytes()
    _, _, _, _, _, rewritten_nonce = struct.unpack(
        prefix_format, rewritten_blob[:prefix_len]
    )
    rewritten_aad = Config.VAULT_AAD_PREFIX + rewritten_blob[:prefix_len]
    rewritten = json.loads(
        AESGCM(bytes(reopened.store._derived_key))
        .decrypt(
            rewritten_nonce,
            rewritten_blob[prefix_len:],
            rewritten_aad,
        )
        .decode("utf-8")
    )

    assert "legacy_field" not in rewritten["entries"]["alice"]


def test_vault_set_entry_rejects_nonbytes_key_data(tmp_path: Path) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / "vault")

    with pytest.raises(TypeError, match="encrypt_key must be bytes-like or None"):
        vault.set_entry("alice", encrypt_key="not-bytes")


def test_vault_rename_missing_or_same_name_is_noop(tmp_path: Path) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / "vault")
    vault.set_entry("alice", note="primary")

    vault.rename_entry("missing", "bob")
    vault.rename_entry("alice", "alice")
    vault.rename_entry("alice", "")

    entries = vault.entries()
    assert list(entries) == ["alice"]
    assert entries["alice"].note == "primary"


def test_vault_rename_rejects_overwriting_existing_entry(tmp_path: Path) -> None:
    vault = Vault("vault-password-123", vault_path=tmp_path / "vault")
    vault.set_entry("alice", note="primary")
    vault.set_entry("bob", note="secondary")

    with pytest.raises(SignSealError, match="entry 'bob' already exists"):
        vault.rename_entry("alice", "bob")

    assert set(vault.entries()) == {"alice", "bob"}
