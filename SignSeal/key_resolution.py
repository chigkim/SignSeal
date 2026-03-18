from __future__ import annotations

from pathlib import Path

from .exceptions import SignSealError
from .io_utils import FileIO
from .key_specs import KEY_SPECS_BY_NAME
from .models import VaultEntry
from .vault import Vault


def resolve_key(
    key_input: str | Path | bytes | None,
    expected_type: str,
    vault: Vault | None = None,
) -> bytes | None:
    if key_input is None:
        return None

    if isinstance(key_input, bytes):
        return key_input

    if isinstance(key_input, str) and vault is not None:
        return _key_from_vault_entry(vault, key_input, expected_type)
    return FileIO.read_key_file(
        FileIO.coerce_path(key_input),
        expected_type=expected_type,
    )


def _key_from_vault_entry(vault: Vault, name: str, expected_type: str) -> bytes:
    entry = vault.get_entry(name)
    if entry is None:
        raise SignSealError(f"entry '{name}' not found in vault")
    return _decode_entry_key(entry, expected_type, name)


def _decode_entry_key(
    entry: VaultEntry,
    expected_type: str,
    name: str,
) -> bytes:
    key_field = KEY_SPECS_BY_NAME[expected_type].field_name
    key_data = entry.key_bytes(key_field)
    if not key_data:
        raise SignSealError(f"entry '{name}' does not contain a {expected_type} key")
    return key_data
