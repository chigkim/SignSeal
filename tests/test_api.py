from __future__ import annotations

from pathlib import Path

import pytest

import SignSeal
from SignSeal.config import Config
from SignSeal.exceptions import SignSealError
from SignSeal.io_utils import KeyFormat
from SignSeal.key_encoding import get_alphanumeric_bundle, unpack_alphanumeric_key
from SignSeal.key_generation import generate_key_material
from SignSeal.key_resolution import resolve_key
from SignSeal.key_specs import KEY_SPECS_BY_NAME
from SignSeal.models import ProcessMode

_F: str = Config.FILE_EXT
_V: str = Config.VAULT_EXT


def test_signed_encrypt_decrypt_roundtrip_bytes() -> None:
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "entry-password-123",
            security="low",
        )
    )
    plaintext = b"hello SignSeal"
    ss = SignSeal()

    ciphertext = ss.encrypt(
        plaintext,
        recipient_key=public_encrypt,
        sender_key=private_sign,
        sender_passphrase="entry-password-123",
    )

    restored = ss.decrypt(
        ciphertext,
        recipient_key=private_decrypt,
        recipient_passphrase="entry-password-123",
        sender_key=public_verify,
    )

    assert restored == plaintext
    assert ss.verify(ciphertext, sender_key=public_verify)


def test_detached_sign_and_verify(tmp_path: Path) -> None:
    payload_path = tmp_path / "message.txt"
    payload_path.write_text("signed payload", encoding="utf-8")

    _, _, public_verify, private_sign = generate_key_material(
        "signing-password-123",
        security="low",
    )
    ss = SignSeal()

    signature = ss.sign(
        payload_path,
        sender_key=private_sign,
        sender_passphrase="signing-password-123",
    )

    fingerprint = ss.verify_detached(
        payload_path,
        signature,
        sender_key=public_verify,
    )

    assert isinstance(fingerprint, str)
    assert fingerprint


def test_alphanumeric_bundle_roundtrip() -> None:
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "paper-password-123",
            security="low",
        )
    )
    bundle = get_alphanumeric_bundle(
        {
            "encrypt": public_encrypt,
            "decrypt": private_decrypt,
            "verify": public_verify,
            "sign": private_sign,
        }
    )
    restored = unpack_alphanumeric_key(bundle)

    assert restored["encrypt"] == public_encrypt
    assert restored["decrypt"] == private_decrypt
    assert restored["verify"] == public_verify
    assert restored["sign"] == private_sign


def test_directory_encryption_roundtrip(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "file1.txt").write_text("content 1")
    (source_dir / "sub").mkdir()
    (source_dir / "sub" / "file2.txt").write_text("content 2")

    encrypted_base = tmp_path / "archive"
    encrypted_path = Path(f"{encrypted_base}{_F}")
    restored_dir = tmp_path / "restored"

    pub_e, priv_d, pub_v, priv_s = generate_key_material("pass12345678", security="low")
    ss = SignSeal()

    ss.encrypt(
        source_dir,
        recipient_key=pub_e,
        sender_key=priv_s,
        sender_passphrase="pass12345678",
        out=encrypted_base,
    )

    ss.decrypt(
        encrypted_path,
        recipient_key=priv_d,
        recipient_passphrase="pass12345678",
        sender_key=pub_v,
        out=restored_dir,
    )

    assert (restored_dir / "file1.txt").read_text() == "content 1"
    assert (restored_dir / "sub" / "file2.txt").read_text() == "content 2"


def test_encrypt_decrypt_roundtrip_with_explicit_outputs(tmp_path: Path) -> None:
    plaintext_path = tmp_path / "message.txt"
    plaintext_path.write_text("process workflow", encoding="utf-8")

    public_encrypt, private_decrypt, _, _ = generate_key_material(
        "entry-password-123",
        security="low",
    )
    ciphertext_base = tmp_path / "custom-output.enc"
    ciphertext_path = Path(f"{ciphertext_base}{_F}")
    restored_path = tmp_path / "restored.txt"
    ss = SignSeal()

    encrypted_output = ss.encrypt(
        plaintext_path,
        recipient_key=public_encrypt,
        out=ciphertext_base,
        compress=False,
    )
    decrypted_output = ss.decrypt(
        ciphertext_path,
        recipient_key=private_decrypt,
        recipient_passphrase="entry-password-123",
        out=restored_path,
    )

    assert encrypted_output is None
    assert decrypted_output is None
    assert ciphertext_path.exists()
    assert restored_path.exists()
    assert restored_path.read_text(encoding="utf-8") == "process workflow"


def test_compressed_directory_encryption_roundtrip(tmp_path: Path) -> None:
    source_dir = tmp_path / "source_compressed"
    source_dir.mkdir()
    (source_dir / "nested").mkdir()
    (source_dir / "nested" / "alpha.txt").write_text("alpha")
    (source_dir / "beta.txt").write_text("beta")

    encrypted_path = tmp_path / f"archive-compressed{_F}"
    restored_dir = tmp_path / "restored_compressed"

    pub_e, priv_d, pub_v, priv_s = generate_key_material("pass12345678", security="low")
    ss = SignSeal()

    ss.encrypt(
        source_dir,
        recipient_key=pub_e,
        sender_key=priv_s,
        sender_passphrase="pass12345678",
        out=encrypted_path,
        compress=True,
    )

    ss.decrypt(
        encrypted_path,
        recipient_key=priv_d,
        recipient_passphrase="pass12345678",
        sender_key=pub_v,
        out=restored_dir,
    )

    assert (restored_dir / "nested" / "alpha.txt").read_text() == "alpha"
    assert (restored_dir / "beta.txt").read_text() == "beta"


def test_optional_signing_and_verification() -> None:
    pub_e, priv_d, _, _ = generate_key_material("pass12345678", security="low")
    ss = SignSeal()

    ciphertext = ss.encrypt(b"unsigned data", recipient_key=pub_e)
    assert ciphertext

    restored = ss.decrypt(
        ciphertext,
        recipient_key=priv_d,
        recipient_passphrase="pass12345678",
        sender_key=None,
    )
    assert restored == b"unsigned data"


def test_signed_file_verification_is_optional_on_decrypt() -> None:
    pub_e, priv_d, _, priv_s = generate_key_material("pass12345678", security="low")
    ss = SignSeal()

    ciphertext = ss.encrypt(
        b"signed data",
        recipient_key=pub_e,
        sender_key=priv_s,
        sender_passphrase="pass12345678",
    )

    restored = ss.decrypt(
        ciphertext,
        recipient_key=priv_d,
        recipient_passphrase="pass12345678",
        sender_key=None,
    )
    assert restored == b"signed data"


def test_signseal_facade_vault_integration(tmp_path: Path) -> None:
    vault_path = tmp_path / f"test{_V}"
    ss = SignSeal("vault-pass-123456", vault_path)

    ss.generate("entry-pass-123456", name="alice", security="low")

    plaintext = b"secret message"
    ciphertext = ss.encrypt(
        plaintext,
        recipient_key="alice",
        sender_key="alice",
        sender_passphrase="entry-pass-123456",
    )

    restored = ss.decrypt(
        ciphertext,
        recipient_key="alice",
        recipient_passphrase="entry-pass-123456",
        sender_key="alice",
    )

    assert restored == plaintext


def test_signseal_facade_generate_standalone_files(tmp_path: Path) -> None:
    ss = SignSeal()
    key_dir = tmp_path / "keys"

    ss.generate(
        "entry-pass-123456",
        output_dir=key_dir,
        force=True,
        security="low",
    )

    encrypt_key = key_dir / KEY_SPECS_BY_NAME["encrypt"].filename
    decrypt_key = key_dir / KEY_SPECS_BY_NAME["decrypt"].filename
    verify_key = key_dir / KEY_SPECS_BY_NAME["verify"].filename
    sign_key = key_dir / KEY_SPECS_BY_NAME["sign"].filename

    plaintext = b"secret message"
    ciphertext = ss.encrypt(
        plaintext,
        recipient_key=encrypt_key,
        sender_key=sign_key,
        sender_passphrase="entry-pass-123456",
    )

    restored = ss.decrypt(
        ciphertext,
        recipient_key=decrypt_key,
        recipient_passphrase="entry-pass-123456",
        sender_key=verify_key,
    )

    assert restored == plaintext


def test_signseal_facade_generate_standalone_output_dir(tmp_path: Path) -> None:
    ss = SignSeal()
    key_dir = tmp_path / "keys_dir"

    ss.generate(
        "entry-pass-123456",
        output_dir=key_dir,
        security="low",
    )

    assert key_dir.exists()
    for key_name in ("encrypt", "decrypt", "verify", "sign"):
        assert (key_dir / KEY_SPECS_BY_NAME[key_name].filename).exists()


def test_signseal_generate_rejects_mixed_vault_and_file_targets(tmp_path: Path) -> None:
    ss = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")

    with pytest.raises(SignSealError, match="name cannot be combined with output_dir"):
        ss.generate(
            "entry-pass-123456",
            name="alice",
            output_dir=tmp_path / "keys",
        )


def test_signseal_facade_vault_management_commands(tmp_path: Path) -> None:
    ss = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")
    ss.generate("alice-pass-123456", name="alice", security="low")

    private_passwords = {
        "decrypt_key": "alice-pass-123456",
        "sign_key": "alice-pass-123456",
    }
    export_summary = ss.export(
        "alice",
        tmp_path / "exports",
        private_passwords=private_passwords,
    )
    assert export_summary.target_dir.exists()
    assert len(export_summary.exported_paths) == 4

    import_summary = ss.import_keys("bob", export_summary.target_dir)
    assert import_summary.key_count == 4

    ss.note("bob", "trusted contact")
    shown = ss.show("bob", paper=True, private_passwords=private_passwords)
    assert "trusted contact" in shown
    assert "Full Bundle" in shown

    entry_fingerprint = ss.fingerprint("bob")
    file_fingerprint = ss.fingerprint(
        export_summary.target_dir / KEY_SPECS_BY_NAME["encrypt"].filename
    )
    assert "Entry: bob" in entry_fingerprint
    assert ":" in file_fingerprint

    bundle = ss.paper_keys("alice", private_passwords=private_passwords).splitlines()[
        -1
    ]
    add_summary = ss.add("carol", bundle)
    assert add_summary.key_count == 4

    remove_summary = ss.remove_keys("carol", sign_key=True)
    assert remove_summary.removed_entry is False
    assert "carol" in ss.list()

    remove_summary = ss.remove_keys(
        "carol",
        {
            "encrypt_key": True,
            "decrypt_key": True,
            "verify_key": True,
        },
    )
    assert remove_summary.removed_entry is True
    assert "carol" not in ss.list()

    with pytest.raises(SignSealError, match="not both"):
        ss.remove_keys("bob", {"sign_key": True}, sign_key=True)


def test_signseal_list_returns_public_entry_summaries(tmp_path: Path) -> None:
    ss = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")
    ss.generate("alice-pass-123456", name="alice", security="low")
    ss.note("alice", "trusted contact")

    entry = ss.list()["alice"]

    assert entry.note == "trusted contact"
    assert entry.has_key("encrypt_key") is True
    assert entry.has_key("decrypt_key") is True
    assert not hasattr(entry, "key_bytes")


def test_signseal_export_allows_public_only_disclosure_without_private_passwords(
    tmp_path: Path,
) -> None:
    ss = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")
    ss.generate("alice-pass-123456", name="alice", security="low")

    export_summary = ss.export(
        "alice",
        tmp_path / "exports",
        selections={"encrypt_key": True, "verify_key": True},
    )

    assert {path.name for path in export_summary.exported_paths} == {
        KEY_SPECS_BY_NAME["encrypt"].filename,
        KEY_SPECS_BY_NAME["verify"].filename,
    }

    shown = ss.paper_keys(
        "alice",
        selections={"encrypt_key": True, "verify_key": True},
    )
    assert "Encrypt (Public)" in shown
    assert "Verify (Public)" in shown
    assert "Decrypt (Private)" not in shown
    assert "Sign (Private)" not in shown


def test_signseal_private_export_and_paper_keys_require_private_passwords(
    tmp_path: Path,
) -> None:
    ss = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")
    ss.generate("alice-pass-123456", name="alice", security="low")

    with pytest.raises(
        SignSealError,
        match="Decrypt \\(Private\\) password is required",
    ):
        ss.export(
            "alice",
            tmp_path / "exports",
            selections={"decrypt_key": True},
        )

    with pytest.raises(
        SignSealError,
        match="Decrypt \\(Private\\) password is required",
    ):
        ss.paper_keys("alice")


def test_invalid_password_raises_error() -> None:
    _, priv_d, _, _ = generate_key_material("correct-pass-123", security="low")
    pub_e, _, pub_v, priv_s = generate_key_material("sender-pass-123", security="low")
    ss = SignSeal()
    ciphertext = ss.encrypt(
        b"data",
        recipient_key=pub_e,
        sender_key=priv_s,
        sender_passphrase="sender-pass-123",
    )

    with pytest.raises(SignSealError, match="password incorrect"):
        ss.decrypt(
            ciphertext,
            recipient_key=priv_d,
            recipient_passphrase="wrong-pass",
            sender_key=pub_v,
        )


def test_detached_verify_rejects_tampered_signature(tmp_path: Path) -> None:
    payload_path = tmp_path / "message.txt"
    payload_path.write_text("signed payload", encoding="utf-8")

    _, _, public_verify, private_sign = generate_key_material(
        "signing-password-123",
        security="low",
    )
    ss = SignSeal()

    signature = bytearray(
        ss.sign(
            payload_path,
            sender_key=private_sign,
            sender_passphrase="signing-password-123",
        )
    )
    signature[-1] ^= 0x01

    with pytest.raises(SignSealError, match="signature verification failed"):
        ss.verify_detached(
            payload_path,
            bytes(signature),
            sender_key=public_verify,
        )


def test_decrypt_rejects_tampered_ciphertext() -> None:
    public_encrypt, private_decrypt, _, _ = generate_key_material(
        "entry-password-123",
        security="low",
    )
    ss = SignSeal()
    ciphertext = bytearray(
        ss.encrypt(
            b"tamper me",
            recipient_key=public_encrypt,
        )
    )
    ciphertext[-65] ^= 0x01

    with pytest.raises(
        SignSealError, match="authentication failed -- corrupt or tampered file"
    ):
        ss.decrypt(
            bytes(ciphertext),
            recipient_key=private_decrypt,
            recipient_passphrase="entry-password-123",
        )


def test_decrypt_requires_explicit_output_for_non_encrypted_input(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "not-encrypted.bin"
    source_path.write_bytes(b"plain")

    _, private_decrypt, _, _ = generate_key_material(
        "entry-password-123",
        security="low",
    )
    ss = SignSeal()

    with pytest.raises(SignSealError, match="extension mismatch"):
        ss.decrypt(
            source_path,
            recipient_key=private_decrypt,
            recipient_passphrase="entry-password-123",
        )


def test_resolve_key_uses_vault_names_and_path_objects_deterministically(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / f"vault{_V}"
    ss = SignSeal("vault-pass-123456", vault_path)
    public_encrypt, private_decrypt, public_verify, private_sign = (
        generate_key_material(
            "entry-pass-123456",
            security="low",
        )
    )
    ss.vault.set_entry(
        "alice",
        encrypt_key=public_encrypt,
        decrypt_key=private_decrypt,
        verify_key=public_verify,
        sign_key=private_sign,
    )

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    SignSeal().generate(
        "file-pass-123456",
        output_dir=key_dir,
        force=True,
        security="low",
    )

    enc_filename = KEY_SPECS_BY_NAME["encrypt"].filename
    assert resolve_key("alice", "encrypt", vault=ss.vault) == public_encrypt
    assert (
        resolve_key(key_dir / enc_filename, "encrypt", vault=ss.vault) != public_encrypt
    )

    with pytest.raises(SignSealError, match=f"entry '{enc_filename}' not found"):
        resolve_key(enc_filename, "encrypt", vault=ss.vault)


def test_signseal_add_accepts_string_paths_like_cli_and_gui(tmp_path: Path) -> None:
    vault = SignSeal("vault-pass-123456", tmp_path / f"vault{_V}")
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    SignSeal().generate(
        "file-pass-123456",
        output_dir=key_dir,
        force=True,
        security="low",
    )

    summary = vault.add("alice", str(key_dir))

    assert summary.key_count == 4
    assert "alice" in vault.list()


def test_key_format_unpack_rejects_noncurrent_version() -> None:
    bad_version = bytes([Config.FORMAT_VERSION + 1])
    payload = KeyFormat.MAGIC + bad_version + KeyFormat.ENCRYPT + b"payload"

    with pytest.raises(SignSealError, match="unsupported key format version"):
        KeyFormat.unpack(payload)
