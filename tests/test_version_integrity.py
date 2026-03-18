"""Verifies that every version-bearing constant derives from Config.FORMAT_VERSION.

If any constant is hardcoded or a second version source is introduced,
these tests will fail — catching accidental or LLM-introduced version drift.
"""

from __future__ import annotations

from SignSeal.config import Config
from SignSeal.io_utils import KeyFormat

V = Config.FORMAT_VERSION
TAG = f"v{V}".encode()
BYTE = bytes([V])


# -- Config derived constants --------------------------------------------------


def test_version_tag_derives_from_format_version() -> None:
    assert Config._VERSION_TAG == TAG


def test_version_byte_derives_from_format_version() -> None:
    assert Config._VERSION_BYTE == BYTE


def test_hkdf_info_contains_version_tag() -> None:
    assert Config.HKDF_INFO == b"SignSealX448-HKDF-" + TAG


def test_signature_context_contains_version_tag() -> None:
    assert Config.SIGNATURE_CONTEXT == b"SignSeal-Ed25519-SHA512-" + TAG


def test_decrypt_key_aad_contains_version_tag() -> None:
    assert Config.DECRYPT_KEY_AAD_PREFIX == b"SignSeal-PrivateKey-" + TAG


def test_sign_key_aad_contains_version_tag() -> None:
    assert Config.SIGN_KEY_AAD_PREFIX == b"SignSeal-SigningKey-" + TAG


def test_vault_aad_contains_version_tag() -> None:
    assert Config.VAULT_AAD_PREFIX == b"SignSeal-Vault-" + TAG


def test_dir_magic_contains_version_tag() -> None:
    assert Config.DIR_MAGIC == b"SS-DIR-" + TAG + b"\x00"


def test_zstd_magic_contains_version_tag() -> None:
    assert Config.ZSTD_MAGIC == b"SS-ZSTD-" + TAG + b"\x00"


# -- File extensions -----------------------------------------------------------


def test_file_ext_derives_from_format_version() -> None:
    assert Config.FILE_EXT == f".ssfv{V}"


def test_key_ext_derives_from_format_version() -> None:
    assert Config.KEY_EXT == f".sskv{V}"


def test_vault_ext_derives_from_format_version() -> None:
    assert Config.VAULT_EXT == f".ssvv{V}"


# -- KeyFormat -----------------------------------------------------------------


def test_keyformat_version_derives_from_config() -> None:
    assert KeyFormat.VERSION == BYTE


# -- Key spec filenames --------------------------------------------------------


def test_key_spec_filenames_use_key_ext() -> None:
    from SignSeal.key_specs import KEY_SPECS

    for spec in KEY_SPECS:
        assert spec.filename.endswith(
            Config.KEY_EXT
        ), f"{spec.name} filename '{spec.filename}' does not end with '{Config.KEY_EXT}'"
