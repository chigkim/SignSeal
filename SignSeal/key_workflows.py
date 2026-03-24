from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .config import Config
from .exceptions import SignSealError
from .io_utils import FileIO, KeyFormat
from .key_encoding import (
    fingerprint_key,
    get_alphanumeric_bundle,
    get_alphanumeric_key,
    unpack_alphanumeric_key,
)
from .key_specs import KEY_SPECS, KEY_SPECS_BY_NAME
from .models import VaultEntry


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def entry_key_bytes(entry: VaultEntry) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for spec in KEY_SPECS:
        raw = entry.key_bytes(spec.field_name)
        if raw is not None:
            result[spec.name] = raw
    return result


def discover_keys(source: str | Path) -> dict[str, bytes]:
    source_path = Path(source)
    if source_path.is_dir():
        return _discover_keys_from_directory(source_path)
    if source_path.is_file():
        return _discover_keys_from_file(source_path)
    if isinstance(source, Path):
        raise SignSealError(f"no keys found in: {source}")
    return _discover_keys_from_text(source)


def _discover_keys_from_directory(directory: Path) -> dict[str, bytes]:
    results: dict[str, bytes] = {}
    for spec in KEY_SPECS:
        candidate = directory / spec.filename
        if candidate.exists():
            results[spec.name] = FileIO.read_key_file(
                candidate, expected_type=spec.name
            )

    if not results:
        raise SignSealError(f"no keys found in: {directory}")
    return results


def _discover_keys_from_file(path: Path) -> dict[str, bytes]:
    try:
        with FileIO.open_regular(path, max_size=Config.MAX_KEY_SIZE) as (fh, _):
            data = fh.read()
    except (OSError, SignSealError) as exc:
        raise SignSealError(f"failed to read key from file: {exc}")

    results = _decode_packed_or_paper_keys(data)
    if not results:
        raise SignSealError(f"no keys found in: {path}")
    return results


def _discover_keys_from_text(source: str) -> dict[str, bytes]:
    try:
        results = unpack_alphanumeric_key(source)
    except SignSealError:
        raise
    except Exception as exc:
        raise SignSealError(
            f"could not interpret source as path or alphanumeric key: {exc}"
        )
    if not results:
        raise SignSealError(f"no keys found in: {source}")
    return results


def _decode_packed_or_paper_keys(data: bytes) -> dict[str, bytes]:
    try:
        key_type, raw = KeyFormat.unpack(data)
    except SignSealError:
        pass
    else:
        if key_type in KEY_SPECS_BY_NAME:
            return {key_type: raw}

    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return {}
    if not text:
        return {}

    try:
        return unpack_alphanumeric_key(text)
    except (SignSealError, ValueError, UnicodeDecodeError):
        return {}


def export_entry_keys(
    entry: VaultEntry,
    target_dir: Path,
    selected_fields: dict[str, bool] | None = None,
) -> list[Path]:
    FileIO.secure_mkdir(target_dir)
    exported: list[Path] = []
    for spec in KEY_SPECS:
        if selected_fields is not None and not selected_fields.get(spec.field_name):
            continue
        raw = entry.key_bytes(spec.field_name)
        if raw is None:
            continue
        output_path = target_dir / spec.filename
        FileIO.atomic_write(
            output_path,
            KeyFormat.pack(spec.format_code, raw),
            mode=spec.mode,
        )
        exported.append(output_path)
    return exported


def existing_export_filenames(
    entry: VaultEntry,
    target_dir: Path,
    selected_fields: dict[str, bool] | None = None,
) -> list[str]:
    existing: list[str] = []
    for spec in KEY_SPECS:
        if selected_fields is not None and not selected_fields.get(spec.field_name):
            continue
        if not entry.has_key(spec.field_name):
            continue
        if (target_dir / spec.filename).exists():
            existing.append(spec.filename)
    return existing


def format_entry_fingerprints(
    name: str,
    entry: VaultEntry,
) -> str:
    lines = [f"Entry: {name}", ""]
    added = False
    for key_name in ("encrypt", "verify"):
        spec = KEY_SPECS_BY_NAME[key_name]
        raw = entry.key_bytes(spec.field_name)
        if raw is None:
            continue
        lines.append(f"{spec.label}:")
        lines.append(fingerprint_key(raw))
        lines.append("")
        added = True
    if not added:
        lines.append("(No encrypt or verify keys in this entry to fingerprint)")
    return "\n".join(lines).rstrip()


def format_entry_paper_keys(
    name: str,
    entry: VaultEntry,
    selected_fields: dict[str, bool] | None = None,
) -> str:
    lines = [f"Paper Keys for: {name}", "=" * 30, ""]
    entry_keys = entry_key_bytes(entry)
    found_keys: dict[str, bytes] = {}
    for spec in KEY_SPECS:
        if selected_fields is not None and not selected_fields.get(spec.field_name):
            continue
        raw = entry_keys.get(spec.name)
        if raw is None:
            continue
        found_keys[spec.name] = raw
        lines.append(f"{spec.label}:")
        lines.append(get_alphanumeric_key(raw, expected_type=spec.name))
        lines.append("")

    if not found_keys:
        lines.append("(No keys found in this entry)")
    elif len(found_keys) > 1:
        lines.append("-" * 30)
        lines.append("Full Bundle (all above keys at once):")
        lines.append(get_alphanumeric_bundle(found_keys))
    return "\n".join(lines)


def selected_entry_key_labels(
    entry: VaultEntry,
    selected_fields: dict[str, bool],
) -> list[str]:
    return [
        spec.label
        for spec in KEY_SPECS
        if selected_fields.get(spec.field_name) and entry.has_key(spec.field_name)
    ]


def entry_fields_for_keys(keys: dict[str, bytes]) -> dict[str, bytes]:
    return {KEY_SPECS_BY_NAME[name].field_name: raw for name, raw in keys.items()}
