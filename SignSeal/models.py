from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ProcessMode(StrEnum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"


@dataclass(slots=True)
class VaultEntry:
    encrypt_key: bytearray | None = None
    decrypt_key: bytearray | None = None
    verify_key: bytearray | None = None
    sign_key: bytearray | None = None
    source: str = "unknown"
    created_at: str = "unknown"
    note: str = ""

    def __post_init__(self) -> None:
        self.encrypt_key = _decode_key(self.encrypt_key)
        self.decrypt_key = _decode_key(self.decrypt_key)
        self.verify_key = _decode_key(self.verify_key)
        self.sign_key = _decode_key(self.sign_key)

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> "VaultEntry":
        if data is None:
            return cls()
        return cls(
            encrypt_key=data.get("encrypt_key"),
            decrypt_key=data.get("decrypt_key"),
            verify_key=data.get("verify_key"),
            sign_key=data.get("sign_key"),
            source=data.get("source") or "unknown",
            created_at=data.get("created_at") or "unknown",
            note=data.get("note") or "",
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "encrypt_key": _encode_key(self.encrypt_key),
            "decrypt_key": _encode_key(self.decrypt_key),
            "verify_key": _encode_key(self.verify_key),
            "sign_key": _encode_key(self.sign_key),
            "source": self.source,
            "created_at": self.created_at,
            "note": self.note,
        }

    def has_key(self, field_name: str) -> bool:
        return bool(getattr(self, field_name))

    def set_key_bytes(self, field_name: str, value: bytes | None) -> None:
        if value is not None and not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{field_name} must be bytes-like or None")
        existing = getattr(self, field_name)
        if existing is not None:
            _zero_buffer(existing)
        setattr(self, field_name, _decode_key(value))

    def key_bytes(self, field_name: str) -> bytes | None:
        value = getattr(self, field_name)
        return bytes(value) if value is not None else None

    def clear_sensitive_keys(self, *field_names: str) -> None:
        names = field_names or (
            "encrypt_key",
            "decrypt_key",
            "verify_key",
            "sign_key",
        )
        for field_name in names:
            value = getattr(self, field_name)
            if value is not None:
                _zero_buffer(value)
                setattr(self, field_name, None)


def _encode_key(value: bytes | bytearray | None) -> str | None:
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def _decode_key(value: Any) -> bytearray | None:
    if value in (None, ""):
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytearray(value)
    if isinstance(value, str):
        return bytearray(base64.b64decode(value))
    raise TypeError(f"unsupported key value type: {type(value)!r}")


def _zero_buffer(value: bytearray) -> None:
    if value:
        ctypes.memset((ctypes.c_char * len(value)).from_buffer(value), 0, len(value))


def entries_as_records(entries: dict[str, VaultEntry]) -> dict[str, dict[str, Any]]:
    return {name: entry.to_record() for name, entry in entries.items()}
