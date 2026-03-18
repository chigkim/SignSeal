from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import Config
from .engine import CryptoEngine
from .exceptions import SignSealError
from .io_utils import FileIO
from .key_encoding import (
    get_alphanumeric_bundle,
    get_alphanumeric_key,
)
from .key_generation import generate_key_material
from .key_specs import (
    KEY_SPECS,
    KEY_SPECS_BY_NAME,
    capability_string,
    entry_key_states,
    sanitize_entry_name,
)
from .key_workflows import (
    discover_keys,
    current_timestamp,
    entry_key_bytes,
    entry_fields_for_keys,
    existing_export_filenames,
    export_entry_keys,
    format_entry_fingerprints,
    format_entry_paper_keys,
    selected_entry_key_labels,
)
from .models import ProcessMode, VaultEntry
from .operations import resolve_process_output


class VaultLike(Protocol):
    def entries(self) -> dict[str, VaultEntry]: ...

    def get_entry(self, name: str) -> VaultEntry | None: ...

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
    ) -> None: ...

    def remove_entry(self, name: str) -> None: ...

    def clear_keys(
        self,
        name: str,
        encrypt_key: bool = False,
        decrypt_key: bool = False,
        verify_key: bool = False,
        sign_key: bool = False,
    ) -> None: ...


@dataclass(frozen=True)
class ImportSummary:
    imported_labels: list[str]
    replaced_labels: list[str]
    key_count: int


@dataclass(frozen=True)
class RemoveSummary:
    removed_entry: bool
    labels: list[str]


@dataclass(frozen=True)
class ExportSummary:
    target_dir: Path
    existing_files: list[str]
    exported_paths: list[Path]


@dataclass(frozen=True)
class EntrySummary:
    name: str
    capabilities: str
    source: str
    created_at: str

    def format_label(self) -> str:
        return (
            f"{self.name:<20} [{self.capabilities:<4}] "
            f"{self.source.capitalize():<12} {self.created_at}"
        )


class KeyWorkflowService:
    def normalize_key_selections(
        self,
        selections: dict[str, bool] | None = None,
    ) -> dict[str, bool]:
        selected = selections or {}
        return {
            spec.field_name: bool(selected.get(spec.field_name)) for spec in KEY_SPECS
        }

    def selections_for_keys(self, keys: dict[str, bytes]) -> dict[str, bool]:
        return self.normalize_key_selections(
            {KEY_SPECS_BY_NAME[name].field_name: True for name in keys}
        )

    def describe_entry(
        self,
        name: str,
        entry: VaultEntry,
    ) -> EntrySummary:
        return EntrySummary(
            name=name,
            capabilities=capability_string(entry),
            source=entry.source,
            created_at=entry.created_at,
        )

    def describe_entries(self, entries: dict[str, VaultEntry]) -> list[EntrySummary]:
        return [self.describe_entry(name, entry) for name, entry in entries.items()]

    def generate_entry(
        self,
        vault: VaultLike,
        name: str,
        password: str,
        security: str = Config.ARGON2_DEFAULT_PROFILE,
    ) -> None:
        encrypt_key, decrypt_key, verify_key, sign_key = generate_key_material(
            password,
            security=security,
        )
        vault.set_entry(
            name,
            encrypt_key=encrypt_key,
            decrypt_key=decrypt_key,
            verify_key=verify_key,
            sign_key=sign_key,
            source="generated",
            created_at=current_timestamp(),
        )

    def import_keys(
        self,
        vault: VaultLike,
        name: str,
        source: str | Path,
        selections: dict[str, bool],
        source_label: str = "imported",
    ) -> ImportSummary:
        keys = discover_keys(source)
        normalized_selections = self.normalize_key_selections(selections)
        available_fields = entry_fields_for_keys(keys)
        chosen_fields = {
            field_name: raw
            for field_name, raw in available_fields.items()
            if normalized_selections[field_name]
        }
        existing = vault.get_entry(name) or VaultEntry()
        replaced_labels = selected_entry_key_labels(
            existing,
            self.normalize_key_selections({field: True for field in chosen_fields}),
        )
        vault.set_entry(
            name,
            **chosen_fields,
            source=source_label,
            created_at=current_timestamp(),
        )
        imported_labels = [
            spec.label
            for spec in KEY_SPECS
            if spec.field_name in chosen_fields and spec.label not in replaced_labels
        ]
        return ImportSummary(
            imported_labels=imported_labels,
            replaced_labels=replaced_labels,
            key_count=len(chosen_fields),
        )

    def import_all_keys(
        self,
        vault: VaultLike,
        name: str,
        source: str | Path,
        source_label: str = "imported",
    ) -> ImportSummary:
        return self.import_keys(
            vault,
            name,
            source,
            self.available_import_selections(source),
            source_label=source_label,
        )

    def remove_plan(
        self,
        entry: VaultEntry,
        selections: dict[str, bool],
    ) -> RemoveSummary:
        normalized_selections = self.normalize_key_selections(selections)
        states = entry_key_states(entry)
        available_selected = {
            field_name: selected
            for field_name, selected in normalized_selections.items()
            if states.get(field_name)
        }
        if not available_selected:
            return RemoveSummary(removed_entry=False, labels=[])

        remove_entry = all(
            available_selected.get(field_name)
            for field_name, available in states.items()
            if available
        )
        labels = selected_entry_key_labels(entry, available_selected)
        return RemoveSummary(removed_entry=remove_entry, labels=labels)

    def apply_remove(
        self,
        vault: VaultLike,
        name: str,
        selections: dict[str, bool],
        removed_entry: bool,
    ) -> None:
        if removed_entry:
            vault.remove_entry(name)
            return
        vault.clear_keys(name, **self.normalize_key_selections(selections))

    def export_preview(
        self,
        entry: VaultEntry,
        name: str,
        base_dir: Path,
        selections: dict[str, bool],
    ) -> ExportSummary:
        target_dir = base_dir / sanitize_entry_name(name)
        normalized_selections = self.normalize_key_selections(selections)
        return ExportSummary(
            target_dir=target_dir,
            existing_files=existing_export_filenames(
                entry,
                target_dir,
                normalized_selections,
            ),
            exported_paths=[],
        )

    def export_keys(
        self,
        entry: VaultEntry,
        name: str,
        base_dir: Path,
        selections: dict[str, bool],
    ) -> ExportSummary:
        target_dir = base_dir / sanitize_entry_name(name)
        normalized_selections = self.normalize_key_selections(selections)
        return ExportSummary(
            target_dir=target_dir,
            existing_files=[],
            exported_paths=export_entry_keys(
                entry,
                target_dir,
                normalized_selections,
            ),
        )

    def export_all_keys(
        self,
        vault: VaultLike,
        name: str,
        base_dir: Path,
    ) -> ExportSummary:
        entry = self.require_entry(vault, name)
        return self.export_keys(entry, name, base_dir, entry_key_states(entry))

    def fingerprint_text(
        self,
        name: str,
        entry: VaultEntry,
    ) -> str:
        return format_entry_fingerprints(name, entry)

    def paper_keys_text(
        self,
        name: str,
        entry: VaultEntry,
    ) -> str:
        return format_entry_paper_keys(name, entry)

    def show_entry_text(
        self,
        name: str,
        entry: VaultEntry,
        include_paper_keys: bool = False,
    ) -> str:
        lines = [
            f"[Entry: {name}]",
            f"  Source:     {entry.source}",
            f"  Created At: {entry.created_at}",
        ]
        if entry.note:
            lines.append(f"  Note:       {entry.note}")
        lines.append("")
        lines.append("  Keys:")

        found_keys = entry_key_bytes(entry)
        for spec in KEY_SPECS:
            raw = found_keys.get(spec.name)
            if raw is None:
                lines.append(f"    {spec.label:<16}: [Missing]")
                continue
            if include_paper_keys:
                lines.append(
                    f"    {spec.label:<16}: "
                    f"{get_alphanumeric_key(raw, expected_type=spec.name)}"
                )
            else:
                lines.append(f"    {spec.label:<16}: [Available]")

        if include_paper_keys and len(found_keys) > 1:
            lines.append("")
            lines.append("  Full Bundle (all above keys at once):")
            lines.append(f"    {get_alphanumeric_bundle(found_keys)}")
        return "\n".join(lines)

    def available_import_selections(self, source: str | Path) -> dict[str, bool]:
        return self.selections_for_keys(discover_keys(source))

    def overwrite_labels(
        self,
        entry: VaultEntry | None,
        selections: dict[str, bool],
    ) -> list[str]:
        if entry is None:
            return []
        return selected_entry_key_labels(
            entry,
            self.normalize_key_selections(selections),
        )

    def require_entry(self, vault: VaultLike, name: str) -> VaultEntry:
        entry = vault.get_entry(name)
        if entry is None:
            raise SignSealError(f"Entry '{name}' not found.")
        return entry


class ProcessWorkflowService:
    def mode_for_path(self, path: str | Path) -> ProcessMode:
        return (
            ProcessMode.DECRYPT
            if str(path).endswith(Config.FILE_EXT)
            else ProcessMode.ENCRYPT
        )

    def output_path(
        self, path: str | Path, mode: ProcessMode, out: str | Path | None = None
    ) -> Path | None:
        return resolve_process_output(path, mode, out=out)

    def recipient_names(
        self,
        entries: dict[str, VaultEntry],
        mode: ProcessMode,
    ) -> list[str]:
        required_field = "encrypt_key" if mode == ProcessMode.ENCRYPT else "decrypt_key"
        return [
            name for name, entry in entries.items() if entry.has_key(required_field)
        ]

    def sender_names(
        self,
        entries: dict[str, VaultEntry],
        mode: ProcessMode,
    ) -> list[str]:
        required_field = "sign_key" if mode == ProcessMode.ENCRYPT else "verify_key"
        return [
            name for name, entry in entries.items() if entry.has_key(required_field)
        ]

    def password_required(self, mode: ProcessMode, sender_name: str | None) -> bool:
        return mode == ProcessMode.DECRYPT or sender_name is not None

    def ciphertext_is_signed(self, path: str | Path) -> bool:
        try:
            with FileIO.open_regular(Path(path)) as (fh, file_size):
                return CryptoEngine.ciphertext_is_signed(fh, file_size)
        except (OSError, SignSealError):
            return False

    def unverified_decrypt_warning(
        self,
        path: str | Path,
        mode: ProcessMode,
        sender_name: str | Path | None,
    ) -> str | None:
        if mode != ProcessMode.DECRYPT or sender_name is not None:
            return None
        if not self.ciphertext_is_signed(path):
            return None
        return (
            "This file is signed, but no sender was selected to verify it.\n\n"
            "Decrypt anyway as unverified?"
        )
