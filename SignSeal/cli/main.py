from __future__ import annotations

import argparse
import getpass
import sys
from dataclasses import dataclass
from pathlib import Path

from ..api import SignSeal
from ..app_services import KeyWorkflowService, ProcessWorkflowService
from ..config import Config
from ..exceptions import SignSealError
from ..io_utils import append_extension
from ..key_specs import KEY_SPECS, KEY_SPECS_BY_NAME, entry_key_states
from ..models import ProcessMode, VaultEntry

from .prompts import confirm_action, prompt_new_password, prompt_password


@dataclass(slots=True)
class CLIContext:
    vault_path: Path | None = None
    client: SignSeal | None = None

    def resolved_vault_path(self) -> Path | None:
        if self.vault_path is None:
            return None
        return append_extension(self.vault_path, Config.VAULT_EXT)

    def get_client(self, create: bool = False, overwrite: bool = False) -> SignSeal:
        if self.client is not None and not overwrite:
            return self.client
        if overwrite and self.client is not None:
            self.client.close()
            self.client = None

        if self.vault_path is None:
            raise SystemExit("[!] No vault specified. Use -v/--vault.")

        resolved = self.resolved_vault_path()
        if not resolved.exists() and not create:
            raise SystemExit(
                f"[!] Vault '{resolved}' does not exist. Use 'cli init -v {self.vault_path}' to create it."
            )

        if overwrite or (not resolved.exists() and create):
            password = prompt_new_password("Create vault password: ")
        else:
            password = getpass.getpass(f"Vault password [{resolved}]: ")

        try:
            self.client = SignSeal(password, self.vault_path, overwrite=overwrite)
            return self.client
        except SignSealError as exc:
            raise SystemExit(f"[!] {exc}")

    def get_standalone_client(self) -> SignSeal:
        return SignSeal()

    def close(self) -> None:
        if self.client is None:
            return
        self.client.close()
        self.client = None

    def uses_vault(self) -> bool:
        return self.vault_path is not None

    def key_ref(self, value: str | None) -> str | Path | None:
        if value is None:
            return None
        if self.uses_vault():
            return value
        return Path(value)

    def command_client(self, *refs: str | None) -> SignSeal:
        if self.uses_vault() and any(ref for ref in refs):
            return self.get_client()
        return self.get_standalone_client()


def build_parser() -> argparse.ArgumentParser:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("-v", "--vault", help="path to the vault database")

    parser = argparse.ArgumentParser(prog="cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen_sp = sub.add_parser(
        "generate",
        help="generate new keys (in vault if name provided, otherwise to disk)",
        parents=[parent_parser],
    )
    gen_sp.add_argument(
        "name_or_path",
        nargs="?",
        help="vault entry name when used with --vault, otherwise output directory",
    )
    gen_sp.add_argument("--force", action="store_true")
    gen_sp.add_argument(
        "--security",
        choices=["low", "medium", "high"],
        default="medium",
        help="Argon2id strength: low (64 MiB), medium (256 MiB, default), high (512 MiB)",
    )

    enc_sp = sub.add_parser("encrypt", parents=[parent_parser])
    enc_sp.add_argument("file", type=Path)
    enc_sp.add_argument(
        "-r",
        "--recipient",
        help=f"recipient entry name with --vault, otherwise {KEY_SPECS_BY_NAME['encrypt'].filename} path",
    )
    enc_sp.add_argument(
        "-s",
        "--sender",
        help=f"sender entry name with --vault, otherwise {KEY_SPECS_BY_NAME['sign'].filename} path",
    )
    enc_sp.add_argument("-o", "--out", type=Path)
    enc_sp.add_argument(
        "--replace", action="store_true", help="overwrite existing output file"
    )
    enc_sp.add_argument(
        "-z",
        "--compress",
        action="store_true",
        help="compress with zstd before encrypting",
    )

    dec_sp = sub.add_parser("decrypt", parents=[parent_parser])
    dec_sp.add_argument("file", type=Path)
    dec_sp.add_argument(
        "-r",
        "--recipient",
        help=f"recipient entry name with --vault, otherwise {KEY_SPECS_BY_NAME['decrypt'].filename} path",
    )
    dec_sp.add_argument(
        "-s",
        "--sender",
        help=f"sender entry name with --vault, otherwise {KEY_SPECS_BY_NAME['verify'].filename} path",
    )
    dec_sp.add_argument("-o", "--out", type=Path)
    dec_sp.add_argument(
        "--replace",
        action="store_true",
        help="overwrite existing output file or folder",
    )

    sign_sp = sub.add_parser("sign", parents=[parent_parser])
    sign_sp.add_argument("file", type=Path)
    sign_sp.add_argument(
        "-s",
        "--sender",
        help=f"sender entry name with --vault, otherwise {KEY_SPECS_BY_NAME['sign'].filename} path",
    )
    sign_sp.add_argument("-o", "--out", type=Path)
    sign_sp.add_argument(
        "--replace", action="store_true", help="overwrite existing output file"
    )

    ver_sp = sub.add_parser("verify", parents=[parent_parser])
    ver_sp.add_argument("file", type=Path)
    ver_sp.add_argument(
        "-s",
        "--sender",
        help=f"sender entry name with --vault, otherwise {KEY_SPECS_BY_NAME['verify'].filename} path",
    )
    ver_sp.add_argument(
        "--signature", type=Path, help="detached signature file to verify against"
    )

    fp_sp = sub.add_parser("fingerprint", parents=[parent_parser])
    fp_sp.add_argument("key", type=Path)

    init_sp = sub.add_parser(
        "init",
        help="initialize a new vault database",
        parents=[parent_parser],
    )
    init_sp.add_argument(
        "--replace", action="store_true", help="overwrite existing vault file"
    )
    sub.add_parser(
        "list",
        help="list entries in the vault",
        parents=[parent_parser],
    )

    remove_sp = sub.add_parser(
        "remove",
        help="remove an entry from the vault",
        parents=[parent_parser],
    )
    remove_sp.add_argument("name")

    import_sp = sub.add_parser(
        "import",
        help="import keys from a folder, file, or paper string",
        parents=[parent_parser],
    )
    import_sp.add_argument("name")
    import_sp.add_argument("path")

    export_sp = sub.add_parser(
        "export",
        help="export keys to a folder",
        parents=[parent_parser],
    )
    export_sp.add_argument("name")
    export_sp.add_argument("path", type=Path)

    rename_sp = sub.add_parser(
        "rename",
        help="rename a vault entry",
        parents=[parent_parser],
    )
    rename_sp.add_argument("old_name")
    rename_sp.add_argument("new_name")

    show_sp = sub.add_parser(
        "show",
        help="show details and paper keys for an entry",
        parents=[parent_parser],
    )
    show_sp.add_argument("name")
    show_sp.add_argument(
        "--paper", action="store_true", help="show keys in alphanumeric (paper) format"
    )

    add_sp = sub.add_parser(
        "add",
        help="add keys from paper string or files",
        parents=[parent_parser],
    )
    add_sp.add_argument("name")
    add_sp.add_argument("source")

    sub.add_parser(
        "password",
        help="change vault master password",
        parents=[parent_parser],
    )
    return parser


def print_entries(entries: dict[str, VaultEntry]) -> None:
    key_service = KeyWorkflowService()
    print("\n[Vault Entries]")
    if not entries:
        print("  (None)")
        return
    print(f"  {'Name':<25} {'Caps':<10} {'Source':<12} {'Created At'}")
    print(f"  {'-'*25} {'-'*10} {'-'*12} {'-'*20}")
    for summary in key_service.describe_entries(entries):
        print(f"  - {summary.format_label()}")


def _prompt_key_password(
    client: SignSeal,
    *,
    key_name: str | None,
    key_label: str,
) -> str:
    prompt = (
        f"Password for {key_label} '{key_name}': "
        if client.uses_vault() and key_name is not None
        else f"{key_label.capitalize()} password: "
    )
    return prompt_password(prompt)


def handle_init(args, context: CLIContext) -> None:
    resolved = context.resolved_vault_path()
    if resolved and resolved.exists() and not args.replace:
        raise SystemExit(
            f"[!] Vault '{resolved}' already exists. Use 'init --replace' to overwrite."
        )
    context.get_client(create=True, overwrite=args.replace)
    print("[*] Vault initialized.")


def handle_list(args, context: CLIContext) -> None:
    print_entries(context.get_client().list())


def handle_remove(args, context: CLIContext) -> None:
    context.get_client().remove(args.name)
    print(f"[*] Entry '{args.name}' removed from vault.")


def handle_rename(args, context: CLIContext) -> None:
    context.get_client().rename(args.old_name, args.new_name)
    print(f"[*] Entry '{args.old_name}' renamed to '{args.new_name}'.")


def handle_password(args, context: CLIContext) -> None:
    client = context.get_client()
    new_password = prompt_new_password("Enter new vault password: ")
    client.password(new_password)
    print("[*] Vault password changed successfully.")


def _handle_import_or_add(
    context: CLIContext,
    name: str,
    source: str | Path,
    source_label: str,
    cancel_msg: str,
    success_verb: str,
) -> None:
    key_service = KeyWorkflowService()
    client = context.get_client()
    entries = client.list()
    selections = key_service.available_import_selections(source)
    replaced_labels = key_service.overwrite_labels(entries.get(name), selections)
    if replaced_labels and not confirm_action(
        f"Overwrite existing keys in '{name}'? {', '.join(replaced_labels)}"
    ):
        print(f"[*] {cancel_msg}")
        return

    summary = client.import_keys(
        name,
        source,
        selections=selections,
        source_label=source_label,
    )
    print(f"[*] {summary.key_count} key(s) {success_verb} entry '{name}'.")


def handle_import(args, context: CLIContext) -> None:
    _handle_import_or_add(
        context,
        args.name,
        args.path,
        source_label="imported",
        cancel_msg="Import cancelled.",
        success_verb="imported into",
    )


def handle_export(args, context: CLIContext) -> None:
    key_service = KeyWorkflowService()
    client = context.get_client()
    entries = client.list()
    entry = entries.get(args.name)
    if entry is None:
        raise SignSealError(f"Entry '{args.name}' not found.")
    selections = entry_key_states(entry)
    preview = key_service.export_preview(entry, args.name, args.path, selections)
    if preview.existing_files and not confirm_action(
        f"Overwrite existing files in '{preview.target_dir}'? {', '.join(preview.existing_files)}"
    ):
        print("[*] Export cancelled.")
        return

    summary = client.export(args.name, args.path, selections=selections)
    if summary.exported_paths:
        print(
            f"[*] Exported {len(summary.exported_paths)} keys to {args.path}: "
            + ", ".join(path.name for path in summary.exported_paths)
        )
        return
    print(f"[!] Entry '{args.name}' has no keys to export.")


def handle_show(args, context: CLIContext) -> None:
    print(context.get_client().show(args.name, paper=args.paper))


def handle_add(args, context: CLIContext) -> None:
    _handle_import_or_add(
        context,
        args.name,
        args.source,
        source_label="manual",
        cancel_msg="Add cancelled.",
        success_verb="added to",
    )


def handle_generate(args, context: CLIContext) -> None:
    if args.name_or_path and context.vault_path:
        name = args.name_or_path
        password = prompt_new_password(f"Master password for new entry '{name}': ")
        context.get_client().generate(password, name=name, security=args.security)
        print(f"[*] Keys for '{name}' generated and added to vault.")
        return

    target_dir = Path(args.name_or_path) if args.name_or_path else Path.cwd()
    password = prompt_new_password("Password: ")

    client = context.get_standalone_client()
    client.generate(
        password,
        output_dir=target_dir,
        force=args.force,
        security=args.security,
    )

    print(f"[*] Standalone keys generated in: {target_dir}")
    print("[*] Encrypt key fingerprint:", client.fingerprint(target_dir / KEY_SPECS_BY_NAME["encrypt"].filename))
    print("[*] Verify key fingerprint:", client.fingerprint(target_dir / KEY_SPECS_BY_NAME["verify"].filename))


def handle_encrypt(args, context: CLIContext) -> None:
    workflow = ProcessWorkflowService()
    recipient_ref = context.key_ref(args.recipient)
    sender_ref = context.key_ref(args.sender)
    client = context.command_client(args.recipient, args.sender)
    sender_password = ""
    if workflow.password_required(ProcessMode.ENCRYPT, args.sender):
        sender_password = _prompt_key_password(
            client,
            key_name=args.sender,
            key_label="sign key",
        )

    output_path = workflow.output_path(args.file, ProcessMode.ENCRYPT, out=args.out)
    client.encrypt(
        args.file,
        recipient_key=recipient_ref,
        out=args.out,
        replace=args.replace,
        sender_key=sender_ref,
        sender_passphrase=sender_password,
        compress=args.compress,
    )
    print(f"[*] Encrypted {'and signed ' if args.sender else ''}-> {output_path}")


def handle_decrypt(args, context: CLIContext) -> None:
    workflow = ProcessWorkflowService()
    recipient_ref = context.key_ref(args.recipient)
    sender_ref = context.key_ref(args.sender)
    client = context.command_client(args.recipient, args.sender)
    warning = workflow.unverified_decrypt_warning(
        str(args.file), ProcessMode.DECRYPT, args.sender
    )
    if warning and not confirm_action(warning):
        print("[*] Decrypt cancelled.")
        return

    recipient_passphrase = _prompt_key_password(
        client,
        key_name=args.recipient,
        key_label="decrypt key",
    )
    output_path = args.out or workflow.output_path(args.file, ProcessMode.DECRYPT)
    client.decrypt(
        args.file,
        recipient_key=recipient_ref,
        out=args.out,
        replace=args.replace,
        sender_key=sender_ref,
        recipient_passphrase=recipient_passphrase,
    )
    print(f"[*] Decrypted -> {output_path}")


def handle_sign(args, context: CLIContext) -> None:
    sender_ref = context.key_ref(args.sender)
    client = context.command_client(args.sender)
    sender_passphrase = _prompt_key_password(
        client,
        key_name=args.sender,
        key_label="sign key",
    )
    output_path = args.out or Path(f"{args.file}.sig")
    client.sign(
        args.file,
        sender_key=sender_ref,
        sender_passphrase=sender_passphrase,
        out=output_path,
        replace=args.replace,
    )
    print(f"[*] Signature created -> {output_path}")


def handle_verify(args, context: CLIContext) -> None:
    sender_ref = context.key_ref(args.sender)
    client = context.command_client(args.sender)
    if args.signature:
        signer_fp = client.verify_detached(
            args.file,
            args.signature,
            sender_key=sender_ref,
        )
    else:
        signer_fp = client.verify(args.file, sender_key=sender_ref)
    print(f"[*] Signature verified for sender fingerprint: {signer_fp}")


def handle_fingerprint(args, context: CLIContext) -> None:
    print(context.get_standalone_client().fingerprint(args.key))


COMMAND_HANDLERS = {
    "init": handle_init,
    "list": handle_list,
    "remove": handle_remove,
    "rename": handle_rename,
    "password": handle_password,
    "import": handle_import,
    "export": handle_export,
    "show": handle_show,
    "add": handle_add,
    "generate": handle_generate,
    "encrypt": handle_encrypt,
    "decrypt": handle_decrypt,
    "sign": handle_sign,
    "verify": handle_verify,
    "fingerprint": handle_fingerprint,
}


def main(argv: list[str] | None = None, context: CLIContext | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    context = context or CLIContext()
    if args.vault:
        context.vault_path = Path(args.vault)

    try:
        COMMAND_HANDLERS[args.cmd](args, context)
    except KeyboardInterrupt:
        print("\n[!] Cancelled.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except SignSealError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        context.close()
