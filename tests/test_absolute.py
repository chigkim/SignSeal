from __future__ import annotations

import struct
import shutil
from pathlib import Path

import SignSeal
from SignSeal.config import Config
from SignSeal.io_utils import KeyFormat
from SignSeal.key_specs import KEY_SPECS, KEY_SPECS_BY_NAME
from SignSeal.randgen import generate_random_file

_F: str = Config.FILE_EXT
_V: str = Config.VAULT_EXT
_ASSETS_DIR = Path(__file__).parent / "assets"
_GOLDEN_VAULT_PATH = _ASSETS_DIR / "golden.ssvv0"
_GOLDEN_ENCRYPTED_PATH = _ASSETS_DIR / "golden.docx.ssfv0"
_GOLDEN_PASSWORD = "test12345678"
_GOLDEN_ENTRY_NAME = "test"


# ── Binary format contracts ──────────────────────────────────────────────────
# These pin the exact byte layout of every file type.  If an LLM changes
# struct formats, field order, magic bytes, or header sizes while keeping
# FORMAT_VERSION the same, these will break.


def _assert_key_file_format(path: Path, expected_type_code: bytes) -> None:
    """Verify key file binary layout: SSK + version(1) + type(1) + raw_key."""
    data = path.read_bytes()
    assert data[:3] == b"SSK", f"key magic mismatch: {data[:3]!r}"
    assert data[3:4] == Config._VERSION_BYTE, f"key version byte mismatch"
    assert (
        data[4:5] == expected_type_code
    ), f"key type code mismatch: expected {expected_type_code!r}, got {data[4:5]!r}"
    assert len(data) > 5, "key file has no key payload"


def _assert_encrypted_file_format(path: Path) -> None:
    """Verify encrypted file header layout: SS(2) + version(1) + salt(32) + eph_pub(56) + sign_fp(32) = 123 bytes."""
    data = path.read_bytes()
    # Magic
    assert data[:2] == b"SS", f"encrypted magic mismatch: {data[:2]!r}"
    # Version byte
    assert data[2] == Config.FORMAT_VERSION, f"encrypted version byte mismatch"
    # Header struct must be parseable
    header_len = struct.calcsize(">2sB32s56s32s")
    assert header_len == 123, f"header struct size changed: {header_len}"
    assert len(data) >= header_len, "encrypted file shorter than header"
    magic, version, salt, eph_pub, sign_fp = struct.unpack(
        ">2sB32s56s32s", data[:header_len]
    )
    assert magic == b"SS"
    assert version == Config.FORMAT_VERSION
    assert len(salt) == 32
    assert len(eph_pub) == 56  # X448 public key
    assert len(sign_fp) == 32  # SHA-256 fingerprint or zeroes
    # After header: nonce(12) + ciphertext + GCM tag(16) + signature(64)
    post_header = len(data) - header_len
    min_post_header = 12 + 16 + 64  # nonce + tag + signature
    assert (
        post_header >= min_post_header
    ), f"post-header too short: {post_header} < {min_post_header}"


def _assert_vault_file_format(path: Path) -> None:
    """Verify vault file prefix layout: version(1) + salt(32) + iters(4) + mem(4) + lanes(1) + nonce(12) = 54 bytes."""
    data = path.read_bytes()
    prefix_fmt = ">B32sIIB12s"
    prefix_len = struct.calcsize(prefix_fmt)
    assert prefix_len == 54, f"vault prefix struct size changed: {prefix_len}"
    assert len(data) >= prefix_len, "vault file shorter than prefix"
    version, salt, iters, mem, lanes, nonce = struct.unpack(
        prefix_fmt, data[:prefix_len]
    )
    assert version == Config.FORMAT_VERSION, f"vault version byte mismatch"
    assert len(salt) == 32
    assert iters >= 2, f"argon2 iterations too low: {iters}"
    assert mem >= 65536, f"argon2 memory too low: {mem}"
    assert lanes >= 1, f"argon2 lanes too low: {lanes}"
    assert len(nonce) == 12
    # After prefix: GCM ciphertext (encrypted JSON + 16-byte tag)
    assert len(data) > prefix_len + 16, "vault has no encrypted payload"


def _cleanup_tmp_contents(tmp_path: Path) -> None:
    for child in tmp_path.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def test_golden_vault_decrypt_and_roundtrip(tmp_path: Path) -> None:
    decrypted_path = tmp_path / "golden.docx"
    roundtrip_cipher_path = tmp_path / f"golden-roundtrip{_F}"
    roundtrip_decrypted_path = tmp_path / "golden-roundtrip.docx"

    try:
        assert _GOLDEN_VAULT_PATH.exists()
        assert _GOLDEN_ENCRYPTED_PATH.exists()

        with SignSeal.SignSeal(_GOLDEN_PASSWORD, _GOLDEN_VAULT_PATH) as ss:
            assert _GOLDEN_ENTRY_NAME in ss.list()

            ss.decrypt(
                _GOLDEN_ENCRYPTED_PATH,
                recipient_key=_GOLDEN_ENTRY_NAME,
                recipient_passphrase=_GOLDEN_PASSWORD,
                out=decrypted_path,
            )
            original_bytes = decrypted_path.read_bytes()

            ss.encrypt(
                decrypted_path,
                recipient_key=_GOLDEN_ENTRY_NAME,
                out=roundtrip_cipher_path,
                compress=False,
            )
            ss.decrypt(
                roundtrip_cipher_path,
                recipient_key=_GOLDEN_ENTRY_NAME,
                recipient_passphrase=_GOLDEN_PASSWORD,
                out=roundtrip_decrypted_path,
            )

        assert decrypted_path.exists()
        assert roundtrip_cipher_path.exists()
        assert roundtrip_decrypted_path.exists()
        assert roundtrip_decrypted_path.read_bytes() == original_bytes
    finally:
        _cleanup_tmp_contents(tmp_path)


def test_robust_key_workflow_end_to_end(tmp_path: Path) -> None:
    existing_entry_name = "test1"
    shared_password = "test12345678"
    test2_password = "test2-password-123"
    vault_path = tmp_path / f"vault{_V}"
    payload_path = tmp_path / "payload.bin"
    exports_root = tmp_path / "exports"
    standalone_root = tmp_path / "standalone"
    signed_cipher_path = tmp_path / f"payload-file-keys{_F}"
    signed_restored_path = tmp_path / "payload-file-keys.bin"
    unsigned_cipher_path = tmp_path / f"payload-file-keys-unsigned{_F}"
    unsigned_restored_path = tmp_path / "payload-file-keys-unsigned.bin"
    cross_to_test1_cipher_path = tmp_path / f"payload-to-test1-from-test2{_F}"
    cross_to_test1_restored_path = tmp_path / "payload-to-test1-from-test2.bin"
    cross_to_test2_cipher_path = tmp_path / f"payload-to-test2-from-test1{_F}"
    cross_to_test2_restored_path = tmp_path / "payload-to-test2-from-test1.bin"
    selections = {spec.field_name: True for spec in KEY_SPECS}
    ss: SignSeal | None = None

    try:
        ss = SignSeal(shared_password, vault_path)
        ss.generate(shared_password, name=existing_entry_name, security="low")
        assert vault_path.exists()

        # ── Pin vault file binary layout ──
        _assert_vault_file_format(vault_path)

        assert existing_entry_name in ss.list()

        export_summary = ss.export(
            existing_entry_name,
            exports_root,
            selections=selections,
            private_passwords={
                "decrypt_key": shared_password,
                "sign_key": shared_password,
            },
        )
        assert export_summary.target_dir.exists()
        assert {path.name for path in export_summary.exported_paths} == {
            spec.filename for spec in KEY_SPECS
        }
        for path in export_summary.exported_paths:
            assert path.exists()

        # ── Pin key file binary layout ──
        _type_codes = {
            "encrypt": KeyFormat.ENCRYPT,
            "decrypt": KeyFormat.DECRYPT,
            "verify": KeyFormat.VERIFY,
            "sign": KeyFormat.SIGN,
        }
        for spec in KEY_SPECS:
            _assert_key_file_format(
                export_summary.target_dir / spec.filename,
                _type_codes[spec.name],
            )

        generate_random_file(str(payload_path), value=1, unit="mb", chunk_size=128)
        original_payload = payload_path.read_bytes()

        ss.encrypt(
            payload_path,
            recipient_key=export_summary.target_dir
            / KEY_SPECS_BY_NAME["encrypt"].filename,
            sender_key=export_summary.target_dir / KEY_SPECS_BY_NAME["sign"].filename,
            sender_passphrase=shared_password,
            out=signed_cipher_path,
            compress=False,
        )

        # ── Pin encrypted file binary layout (signed) ──
        _assert_encrypted_file_format(signed_cipher_path)

        ss.decrypt(
            signed_cipher_path,
            recipient_key=export_summary.target_dir
            / KEY_SPECS_BY_NAME["decrypt"].filename,
            recipient_passphrase=shared_password,
            sender_key=export_summary.target_dir / KEY_SPECS_BY_NAME["verify"].filename,
            out=signed_restored_path,
        )
        assert signed_restored_path.read_bytes() == original_payload

        ss.encrypt(
            payload_path,
            recipient_key=export_summary.target_dir
            / KEY_SPECS_BY_NAME["encrypt"].filename,
            out=unsigned_cipher_path,
            compress=False,
        )

        # ── Pin encrypted file binary layout (unsigned) ──
        _assert_encrypted_file_format(unsigned_cipher_path)

        ss.decrypt(
            unsigned_cipher_path,
            recipient_key=export_summary.target_dir
            / KEY_SPECS_BY_NAME["decrypt"].filename,
            recipient_passphrase=shared_password,
            out=unsigned_restored_path,
        )
        assert unsigned_restored_path.read_bytes() == original_payload

        standalone_root.mkdir()
        ss.generate(
            test2_password,
            output_dir=standalone_root,
            force=True,
            security="low",
        )
        ss.import_keys("test2", standalone_root)
        imported_entry = ss.list().get("test2")
        assert imported_entry is not None

        ss.encrypt(
            payload_path,
            recipient_key=existing_entry_name,
            sender_key="test2",
            sender_passphrase=test2_password,
            out=cross_to_test1_cipher_path,
            compress=False,
        )
        ss.decrypt(
            cross_to_test1_cipher_path,
            recipient_key=existing_entry_name,
            recipient_passphrase=shared_password,
            sender_key="test2",
            out=cross_to_test1_restored_path,
        )
        assert cross_to_test1_restored_path.read_bytes() == original_payload

        ss.encrypt(
            payload_path,
            recipient_key="test2",
            sender_key=existing_entry_name,
            sender_passphrase=shared_password,
            out=cross_to_test2_cipher_path,
            compress=False,
        )
        ss.decrypt(
            cross_to_test2_cipher_path,
            recipient_key="test2",
            recipient_passphrase=test2_password,
            sender_key=existing_entry_name,
            out=cross_to_test2_restored_path,
        )
        assert cross_to_test2_restored_path.read_bytes() == original_payload
    finally:
        if ss is not None:
            if "test2" in ss.list():
                ss.remove("test2")
            ss.close()
        _cleanup_tmp_contents(tmp_path)
