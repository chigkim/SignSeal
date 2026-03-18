from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .io_utils import KeyFormat

_K: str = Config.KEY_EXT


@dataclass(frozen=True)
class KeySpec:
    name: str
    field_name: str
    label: str
    filename: str
    format_code: bytes
    capability: str
    mode: int
    is_private: bool


KEY_SPECS: tuple[KeySpec, ...] = (
    KeySpec(
        name="encrypt",
        field_name="encrypt_key",
        label="Encrypt (Public)",
        filename=f"public_encrypt{_K}",
        format_code=KeyFormat.ENCRYPT,
        capability="E",
        mode=0o644,
        is_private=False,
    ),
    KeySpec(
        name="decrypt",
        field_name="decrypt_key",
        label="Decrypt (Private)",
        filename=f"private_decrypt{_K}",
        format_code=KeyFormat.DECRYPT,
        capability="D",
        mode=0o600,
        is_private=True,
    ),
    KeySpec(
        name="verify",
        field_name="verify_key",
        label="Verify (Public)",
        filename=f"public_verify{_K}",
        format_code=KeyFormat.VERIFY,
        capability="V",
        mode=0o644,
        is_private=False,
    ),
    KeySpec(
        name="sign",
        field_name="sign_key",
        label="Sign (Private)",
        filename=f"private_sign{_K}",
        format_code=KeyFormat.SIGN,
        capability="S",
        mode=0o600,
        is_private=True,
    ),
)

KEY_SPECS_BY_NAME = {spec.name: spec for spec in KEY_SPECS}


def capability_string(entry) -> str:
    return "".join(
        spec.capability if entry.has_key(spec.field_name) else "." for spec in KEY_SPECS
    )


def entry_key_states(entry) -> dict[str, bool]:
    return {spec.field_name: entry.has_key(spec.field_name) for spec in KEY_SPECS}


def sanitize_entry_name(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in " _-").strip()
    return cleaned.replace(" ", "_") or "entry"
