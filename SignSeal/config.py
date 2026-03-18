from __future__ import annotations

import struct
from typing import Final


class Config:
    FORMAT_VERSION: Final[int] = 0
    _VERSION_TAG: Final[bytes] = f"v{FORMAT_VERSION}".encode()
    _VERSION_BYTE: Final[bytes] = bytes([FORMAT_VERSION])

    KEY_LEN: Final[int] = 32
    HKDF_LEN: Final[int] = 32
    HKDF_INFO: Final[bytes] = b"SignSealX448-HKDF-" + _VERSION_TAG
    SIGNATURE_CONTEXT: Final[bytes] = b"SignSeal-Ed25519-SHA512-" + _VERSION_TAG
    PROTECTED_BLOB_PREFIX_FMT: Final[str] = ">B32sIIB12s"
    PROTECTED_BLOB_PREFIX_LEN: Final[int] = struct.calcsize(PROTECTED_BLOB_PREFIX_FMT)
    DECRYPT_KEY_AAD_PREFIX: Final[bytes] = b"SignSeal-PrivateKey-" + _VERSION_TAG
    SIGN_KEY_AAD_PREFIX: Final[bytes] = b"SignSeal-SigningKey-" + _VERSION_TAG
    VAULT_AAD_PREFIX: Final[bytes] = b"SignSeal-Vault-" + _VERSION_TAG
    ARGON2_PROFILES: Final[dict[str, tuple[int, int, int]]] = {
        #                  (iterations, memory_cost, lanes)
        "low": (3, 65536, 4),  #  64 MiB - constrained devices
        "medium": (4, 262144, 4),  # 256 MiB - balanced default
        "high": (8, 524288, 4),  # 512 MiB - maximum hardening
    }
    ARGON2_DEFAULT_PROFILE: Final[str] = "medium"
    ARGON2_DKLEN: Final[int] = 32
    ARGON2_MIN_ITERATIONS: Final[int] = 2
    ARGON2_MIN_MEMORY: Final[int] = 65536
    ARGON2_MIN_LANES: Final[int] = 1
    ARGON2_MAX_ITERATIONS: Final[int] = 20
    ARGON2_MAX_MEMORY: Final[int] = 4 * 1024 * 1024  # 4 GiB in KiB
    ARGON2_MAX_LANES: Final[int] = 16
    SALT_LEN: Final[int] = 32
    NONCE_LEN: Final[int] = 12
    GCM_TAG_LEN: Final[int] = 16
    SIGNATURE_LEN: Final[int] = 64
    FINGERPRINT_LEN: Final[int] = 32
    MAGIC: Final[bytes] = b"SS"

    HEADER_FMT: Final[str] = ">2sB32s56s32s"
    HEADER_LEN: Final[int] = struct.calcsize(HEADER_FMT)
    MAX_FILE_SIZE: Final[int] = 100 * 1024 * 1024 * 1024
    MAX_KEY_SIZE: Final[int] = 1024 * 1024
    MAX_VAULT_SIZE: Final[int] = 10 * 1024 * 1024
    READ_CHUNK_SIZE: Final[int] = 1024 * 1024
    MIN_PASSWORD_LEN: Final[int] = 12
    DIR_MAGIC: Final[bytes] = b"SS-DIR-" + _VERSION_TAG + b"\x00"
    ZSTD_MAGIC: Final[bytes] = b"SS-ZSTD-" + _VERSION_TAG + b"\x00"
    FILE_EXT: Final[str] = f".ssfv{FORMAT_VERSION}"
    KEY_EXT: Final[str] = f".sskv{FORMAT_VERSION}"
    VAULT_EXT: Final[str] = f".ssvv{FORMAT_VERSION}"
    MIN_CIPHERTEXT_SIZE: Final[int] = (
        HEADER_LEN + NONCE_LEN + GCM_TAG_LEN + SIGNATURE_LEN
    )
    MAX_DECOMPRESSED_SIZE: Final[int] = MAX_FILE_SIZE
    MAX_ARCHIVE_ENTRIES: Final[int] = 10000
    MAX_ARCHIVE_TOTAL_SIZE: Final[int] = MAX_FILE_SIZE
    MAX_ARCHIVE_MEMBER_SIZE: Final[int] = MAX_FILE_SIZE
    CLIPBOARD_CLEAR_MS: Final[int] = 45_000
