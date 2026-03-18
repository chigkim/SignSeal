from __future__ import annotations

import os
from pathlib import Path

from .app_services import KeyWorkflowService
from .config import Config
from .exceptions import SignSealError
from .key_encoding import fingerprint_key
from .models import VaultEntry
from .operations import (
    decrypt as _decrypt,
    encrypt as _encrypt,
    generate as _generate,
    sign as _sign,
    verify as _verify,
    verify_detached as _verify_detached,
)
from .vault import Vault


class SignSeal:
    """Unified facade for standalone key files and vault-backed operations."""

    def __init__(
        self,
        password: str | None = None,
        vault_path: str | Path | None = None,
        *,
        overwrite: bool = False,
    ) -> None:
        if (password is None) != (vault_path is None):
            raise SignSealError(
                "password and vault_path must be provided together for vault operations"
            )

        self._key_workflow = KeyWorkflowService()
        self.vault = (
            None
            if password is None
            else Vault(password, vault_path=str(vault_path), overwrite=overwrite)
        )

    def __enter__(self) -> "SignSeal":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def vault_path(self) -> Path | None:
        if self.vault is None:
            return None
        return self.vault.vault_path

    def uses_vault(self) -> bool:
        return self.vault is not None

    def close(self) -> None:
        if self.vault is not None:
            self.vault.close()

    def _require_vault(self) -> Vault:
        if self.vault is None:
            raise SignSealError(
                "vault operation requires SignSeal(password, vault_path)"
            )
        return self.vault

    def generate(
        self,
        passphrase: str,
        name: str | None = None,
        output_dir: str | Path | None = None,
        force: bool = False,
        security: str = Config.ARGON2_DEFAULT_PROFILE,
    ) -> None:
        if name is not None:
            if output_dir is not None:
                raise SignSealError(
                    "name cannot be combined with output_dir in SignSeal.generate"
                )
            self._key_workflow.generate_entry(
                self._require_vault(),
                name,
                passphrase,
                security=security,
            )
            return

        _generate(
            passphrase,
            output_dir=output_dir,
            force=force,
            security=security,
        )

    def encrypt(
        self,
        data: str | Path | bytes,
        recipient_key: str | Path | bytes | None = None,
        out: str | Path | None = None,
        replace: bool = False,
        compress: bool = False,
        sender_key: str | Path | bytes | None = None,
        sender_passphrase: str = "",
    ) -> bytes | None:
        return _encrypt(
            data,
            recipient_key=recipient_key,
            out=out,
            replace=replace,
            compress=compress,
            sender_key=sender_key,
            sender_passphrase=sender_passphrase,
            vault=self.vault,
        )

    def decrypt(
        self,
        data: str | Path | bytes,
        recipient_key: str | Path | bytes | None = None,
        recipient_passphrase: str = "",
        out: str | Path | None = None,
        replace: bool = False,
        sender_key: str | Path | bytes | None = None,
    ) -> bytes | None:
        return _decrypt(
            data,
            recipient_key=recipient_key,
            recipient_passphrase=recipient_passphrase,
            out=out,
            replace=replace,
            sender_key=sender_key,
            vault=self.vault,
        )

    def sign(
        self,
        data: str | Path | bytes,
        sender_key: str | Path | bytes | None = None,
        sender_passphrase: str = "",
        out: str | Path | None = None,
        replace: bool = False,
    ) -> bytes | None:
        return _sign(
            data,
            sender_key=sender_key,
            sender_passphrase=sender_passphrase,
            out=out,
            replace=replace,
            vault=self.vault,
        )

    def verify(
        self,
        data: str | Path | bytes,
        sender_key: str | Path | bytes | None = None,
    ) -> str:
        return _verify(data, sender_key=sender_key, vault=self.vault)

    def verify_detached(
        self,
        data: str | Path | bytes,
        signature: str | Path | bytes,
        sender_key: str | Path | bytes | None = None,
    ) -> str:
        return _verify_detached(
            data,
            signature,
            sender_key=sender_key,
            vault=self.vault,
        )

    def list(self) -> dict[str, VaultEntry]:
        return self._require_vault().entries()

    def import_keys(
        self,
        name: str,
        source: str | Path,
        selections: dict[str, bool] | None = None,
        source_label: str = "imported",
    ):
        vault = self._require_vault()
        if selections is None:
            return self._key_workflow.import_all_keys(
                vault,
                name,
                source,
                source_label=source_label,
            )
        return self._key_workflow.import_keys(
            vault,
            name,
            source,
            selections,
            source_label=source_label,
        )

    def export(
        self,
        name: str,
        base_dir: str | Path,
        selections: dict[str, bool] | None = None,
    ):
        vault = self._require_vault()
        base_path = Path(base_dir)
        if selections is None:
            return self._key_workflow.export_all_keys(vault, name, base_path)
        entry = self._key_workflow.require_entry(vault, name)
        return self._key_workflow.export_keys(entry, name, base_path, selections)

    def show(self, name: str, paper: bool = False) -> str:
        vault = self._require_vault()
        entry = self._key_workflow.require_entry(vault, name)
        return self._key_workflow.show_entry_text(
            name,
            entry,
            include_paper_keys=paper,
        )

    def add(self, name: str, source: str | Path):
        return self._key_workflow.import_all_keys(
            self._require_vault(),
            name,
            source,
            source_label="manual",
        )

    def fingerprint(self, target: str | os.PathLike[str] | bytes) -> str:
        if isinstance(target, str) and self.vault is not None:
            entry = self.vault.get_entry(target)
            if entry is not None:
                return self._key_workflow.fingerprint_text(target, entry)
        return fingerprint_key(target)

    def paper_keys(self, name: str) -> str:
        vault = self._require_vault()
        entry = self._key_workflow.require_entry(vault, name)
        return self._key_workflow.paper_keys_text(name, entry)

    def note(self, name: str, note: str) -> None:
        self._require_vault().update_note(name, note)

    def remove_keys(
        self,
        name: str,
        selections: dict[str, bool] | None = None,
        *,
        encrypt_key: bool = False,
        decrypt_key: bool = False,
        verify_key: bool = False,
        sign_key: bool = False,
    ):
        explicit_flags = {
            "encrypt_key": encrypt_key,
            "decrypt_key": decrypt_key,
            "verify_key": verify_key,
            "sign_key": sign_key,
        }
        if selections is not None and any(explicit_flags.values()):
            raise SignSealError(
                "remove_keys accepts either selections or individual key flags, not both"
            )
        final_selections = selections or explicit_flags
        vault = self._require_vault()
        entry = self._key_workflow.require_entry(vault, name)
        summary = self._key_workflow.remove_plan(entry, final_selections)
        self._key_workflow.apply_remove(
            vault,
            name,
            final_selections,
            summary.removed_entry,
        )
        return summary

    def remove(self, name: str) -> None:
        self._require_vault().remove_entry(name)

    def rename(self, old_name: str, new_name: str) -> None:
        self._require_vault().rename_entry(old_name, new_name)

    def password(self, new_password: str) -> None:
        self._require_vault().change_vault_password(new_password)

    def verify_password(self, password: str) -> bool:
        return self._require_vault().verify_password(password)
