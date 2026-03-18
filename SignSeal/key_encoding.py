from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x448

from .config import Config
from .engine import CryptoEngine
from .exceptions import SignSealError
from .io_utils import FileIO, KeyFormat
from .key_specs import KEY_SPECS_BY_NAME


def fingerprint_key(key: str | os.PathLike[str] | bytes) -> str:
    key_bytes = (
        FileIO.read_key_file(Path(key))
        if isinstance(key, (str, os.PathLike))
        else bytes(key)
    )
    if len(key_bytes) > Config.MAX_KEY_SIZE:
        raise SignSealError("key too large")
    try:
        public_key = serialization.load_pem_public_key(key_bytes)
    except Exception:
        raise SignSealError("invalid key content for fingerprint")
    if not isinstance(public_key, (x448.X448PublicKey, ed25519.Ed25519PublicKey)):
        raise SignSealError("unsupported key type for fingerprint")
    return CryptoEngine.format_fingerprint(
        CryptoEngine.key_fingerprint_bytes(public_key)
    )


def get_alphanumeric_key(
    key: str | os.PathLike[str] | bytes,
    expected_type: str | None = None,
) -> str:
    data = (
        FileIO.read_key_file(Path(key), expected_type=expected_type)
        if isinstance(
            key,
            (str, os.PathLike),
        )
        else bytes(key)
    )
    key_type, raw = _unpack_key_blob(data, expected_type)
    return KeyFormat.pack_alphanumeric(
        _type_to_format_code(key_type), _public_key_pem_to_raw(key_type, raw)
    )


def get_alphanumeric_bundle(keys: dict[str, bytes]) -> str:
    raw_keys: dict[str, bytes] = {}
    for key_type, data in keys.items():
        if data is None:
            continue
        unpacked_type, raw = _unpack_key_blob(data, key_type)
        raw_keys[unpacked_type] = _public_key_pem_to_raw(unpacked_type, raw)
    return KeyFormat.pack_bundle_alphanumeric(raw_keys)


def unpack_alphanumeric_key(key_str: str) -> dict[str, bytes]:
    unpacked = KeyFormat.unpack_alphanumeric(key_str)
    return {
        key_type: _public_key_raw_to_pem(key_type, raw)
        for key_type, raw in unpacked.items()
    }


def _unpack_key_blob(data: bytes, expected_type: str | None) -> tuple[str, bytes]:
    try:
        return KeyFormat.unpack(data)
    except SignSealError:
        if not expected_type:
            raise SignSealError("cannot determine key type for alphanumeric packing")
        return expected_type, data


def _public_key_pem_to_raw(key_type: str, raw: bytes) -> bytes:
    if b"-----BEGIN PUBLIC KEY-----" not in raw:
        return raw
    public_key = serialization.load_pem_public_key(raw)
    if key_type == "encrypt" and isinstance(public_key, x448.X448PublicKey):
        return public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    if key_type == "verify" and isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    return raw


def _public_key_raw_to_pem(key_type: str, raw: bytes) -> bytes:
    if b"-----BEGIN PUBLIC KEY-----" in raw:
        return raw
    if key_type == "encrypt" and len(raw) == 56:
        public_key = x448.X448PublicKey.from_public_bytes(raw)
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    if key_type == "verify" and len(raw) == 32:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return raw


def _type_to_format_code(key_type: str) -> bytes:
    spec = KEY_SPECS_BY_NAME.get(key_type)
    if spec is None:
        raise SignSealError(
            f"unsupported key type for alphanumeric packing: {key_type}"
        )
    return spec.format_code
