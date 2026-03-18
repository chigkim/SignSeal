from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from .exceptions import SignSealError
from .key_specs import KEY_SPECS
from .models import VaultEntry, entries_as_records
from .passwords import validate_password_strength
from .vault_store import VaultStore


class Vault:
    def __init__(
        self,
        password: str,
        vault_path: str | Path,
        overwrite: bool = False,
    ) -> None:
        self.store = VaultStore(vault_path=vault_path)
        self.vault_path = self.store.vault_path
        self._batch_depth = 0
        self._dirty = False
        self._closed = False
        try:
            if overwrite or not self.vault_path.exists():
                validate_password_strength(password)
                raw_data = self.store.create(password, {"entries": {}})
            else:
                raw_data = self.store.load(password)
        except Exception:
            self.store.close()
            raise

        self._entries = {
            name: VaultEntry.from_mapping(entry_data)
            for name, entry_data in raw_data.get("entries", {}).items()
        }

    def __enter__(self) -> "Vault":
        self._require_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        for entry in self._entries.values():
            entry.clear_sensitive_keys()
        self._entries.clear()
        self._dirty = False
        self.store.close()
        self._closed = True

    def entries(self) -> dict[str, VaultEntry]:
        self._require_open()
        return dict(self._entries)

    def get_entry(self, name: str) -> VaultEntry | None:
        self._require_open()
        normalized_name = self._normalize_entry_name(name, allow_empty=True)
        if normalized_name is None:
            return None
        return self._entries.get(normalized_name)

    def verify_password(self, password: str) -> bool:
        self._require_open()
        return self.store.verify_password(password)

    def save(self) -> None:
        self._require_open()
        self.store.save({"entries": entries_as_records(self._entries)})
        self._dirty = False

    @contextmanager
    def batch_update(self):
        self._require_open()
        self._batch_depth += 1
        try:
            yield self
        finally:
            self._batch_depth -= 1
            if self._batch_depth == 0 and self._dirty:
                self.save()

    def set_entry(
        self,
        name: str,
        encrypt_key: bytes | None = None,
        decrypt_key: bytes | None = None,
        verify_key: bytes | None = None,
        sign_key: bytes | None = None,
        source: str | None = None,
        created_at: str | None = None,
        note: str | None = None,
    ) -> None:
        self._require_open()
        normalized_name = self._normalize_entry_name(name)
        entry = self._ensure_entry(normalized_name)
        key_values = {
            "encrypt_key": encrypt_key,
            "decrypt_key": decrypt_key,
            "verify_key": verify_key,
            "sign_key": sign_key,
        }
        for spec in KEY_SPECS:
            value = key_values[spec.field_name]
            if value is not None:
                entry.set_key_bytes(spec.field_name, value)
        if source is not None:
            entry.source = source
        if created_at is not None:
            entry.created_at = created_at
        if note is not None:
            entry.note = note
        self._mark_dirty()

    def update_note(self, name: str, note: str) -> None:
        self._require_open()
        normalized_name = self._normalize_entry_name(name, allow_empty=True)
        if normalized_name is None:
            return
        entry = self._entries.get(normalized_name)
        if entry is None:
            return
        entry.note = note
        self._mark_dirty()

    def remove_entry(self, name: str) -> None:
        self._require_open()
        normalized_name = self._normalize_entry_name(name, allow_empty=True)
        if normalized_name is None:
            return
        entry = self._entries.pop(normalized_name, None)
        if entry is not None:
            entry.clear_sensitive_keys()
            self._mark_dirty()

    def clear_keys(
        self,
        name: str,
        encrypt_key: bool = False,
        decrypt_key: bool = False,
        verify_key: bool = False,
        sign_key: bool = False,
    ) -> None:
        self._require_open()
        normalized_name = self._normalize_entry_name(name, allow_empty=True)
        if normalized_name is None:
            return
        entry = self._entries.get(normalized_name)
        if entry is None:
            return
        key_flags = {
            "encrypt_key": encrypt_key,
            "decrypt_key": decrypt_key,
            "verify_key": verify_key,
            "sign_key": sign_key,
        }
        for spec in KEY_SPECS:
            if key_flags[spec.field_name]:
                entry.clear_sensitive_keys(spec.field_name)
        self._mark_dirty()

    def rename_entry(self, old_name: str, new_name: str) -> None:
        self._require_open()
        normalized_old = self._normalize_entry_name(old_name, allow_empty=True)
        normalized_new = self._normalize_entry_name(new_name, allow_empty=True)
        if (
            normalized_old is None
            or normalized_new is None
            or normalized_old == normalized_new
            or normalized_old not in self._entries
        ):
            return
        if normalized_new in self._entries:
            raise SignSealError(f"entry '{normalized_new}' already exists")
        self._entries[normalized_new] = self._entries.pop(normalized_old)
        self._mark_dirty()

    def change_vault_password(self, new_password: str) -> None:
        self._require_open()
        validate_password_strength(new_password)
        self.store.change_password(
            {"entries": entries_as_records(self._entries)},
            new_password,
        )

    def _ensure_entry(self, name: str) -> VaultEntry:
        return self._entries.setdefault(name, VaultEntry())

    def _normalize_entry_name(
        self,
        name: str,
        *,
        allow_empty: bool = False,
    ) -> str | None:
        normalized = name.strip()
        if normalized:
            return normalized
        if allow_empty:
            return None
        raise SignSealError("entry name must not be empty")

    def _mark_dirty(self) -> None:
        self._dirty = True
        if self._batch_depth == 0:
            self.save()

    def _require_open(self) -> None:
        if self._closed:
            raise SignSealError("vault is closed")
