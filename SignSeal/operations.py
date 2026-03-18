from __future__ import annotations

import io
import os
import shutil
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import zstandard as _zstd
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x448

from .config import Config
from .engine import CryptoEngine
from .exceptions import SignSealError
from .io_utils import FileIO, KeyFormat, append_extension, validate_extension
from .key_generation import generate_key_material
from .key_resolution import resolve_key
from .key_specs import KEY_SPECS, KEY_SPECS_BY_NAME
from .models import ProcessMode
from .payload import PayloadManager, PlaintextProcessor
from .vault import Vault


@contextmanager
def open_input(
    data: str | Path | bytes,
    max_size: int | None = None,
):
    if max_size is None:
        max_size = Config.MAX_FILE_SIZE
    if isinstance(data, (str, Path)):
        path = Path(data)
        with FileIO.open_regular(path, max_size=max_size) as (fh, size):
            yield fh, size, path
        return

    data_bytes = bytes(data)
    if len(data_bytes) > max_size:
        raise SignSealError("input exceeds size limit")
    yield io.BytesIO(data_bytes), len(data_bytes), None


def hash_input(data: str | Path | bytes) -> bytes:
    with open_input(data) as (fh, size, _):
        return CryptoEngine.stream_sha512(fh, size)


def read_small_binary(data: str | Path | bytes, max_size: int | None = None) -> bytes:
    if max_size is None:
        max_size = Config.MAX_FILE_SIZE
    if isinstance(data, (str, Path)):
        with FileIO.open_regular(Path(data), max_size=max_size) as (fh, _):
            return fh.read()
    data_bytes = bytes(data)
    if len(data_bytes) > max_size:
        raise SignSealError("input exceeds size limit")
    return data_bytes


def infer_encrypt_output(path: Path) -> Path:
    return Path(f"{path}{Config.FILE_EXT}")


def infer_decrypt_output(path: Path) -> Path:
    path_str = str(path)
    ext = Config.FILE_EXT
    if not path_str.endswith(ext):
        raise SignSealError(f"cannot infer output name for '{path}' -- use out=")
    return Path(path_str[: -len(ext)])


def resolve_process_output(
    path: str | Path,
    mode: ProcessMode,
    out: str | Path | None = None,
) -> Path | None:
    input_path = FileIO.coerce_path(path)
    if mode == ProcessMode.ENCRYPT:
        if out is not None:
            return append_extension(out, Config.FILE_EXT)
        return infer_encrypt_output(input_path)
    if out is not None:
        return FileIO.coerce_path(out)
    try:
        return infer_decrypt_output(input_path)
    except SignSealError:
        return None


def _require_key_bytes(
    key_input: str | Path | bytes | None,
    expected_type: str,
    missing_message: str,
    vault: Vault | None,
) -> bytes:
    resolved = resolve_key(key_input, expected_type, vault)
    if resolved is None:
        raise SignSealError(missing_message)
    return resolved


def _load_encrypt_key(
    recipient_key: str | Path | bytes | None,
    vault: Vault | None,
) -> x448.X448PublicKey:
    return CryptoEngine.load_encrypt_key(
        _require_key_bytes(
            recipient_key,
            "encrypt",
            "recipient encrypt key is required",
            vault,
        )
    )


def _load_decrypt_key(
    recipient_key: str | Path | bytes | None,
    recipient_passphrase: str,
    vault: Vault | None,
) -> x448.X448PrivateKey:
    return CryptoEngine.load_decrypt_key(
        _require_key_bytes(
            recipient_key,
            "decrypt",
            "recipient decrypt key is required",
            vault,
        ),
        recipient_passphrase,
    )


def _load_optional_sign_key(
    sender_key: str | Path | bytes | None,
    sender_passphrase: str,
    vault: Vault | None,
) -> ed25519.Ed25519PrivateKey | None:
    resolved = resolve_key(sender_key, "sign", vault)
    if resolved is None:
        return None
    return CryptoEngine.load_sign_key(resolved, sender_passphrase)


def _load_required_sign_key(
    sender_key: str | Path | bytes | None,
    sender_passphrase: str,
    vault: Vault | None,
) -> ed25519.Ed25519PrivateKey:
    resolved = _require_key_bytes(
        sender_key,
        "sign",
        "sender sign key is required for signing",
        vault,
    )
    return CryptoEngine.load_sign_key(resolved, sender_passphrase)


def _load_required_verify_key(
    sender_key: str | Path | bytes | None,
    missing_message: str,
    vault: Vault | None,
) -> ed25519.Ed25519PublicKey:
    resolved = _require_key_bytes(
        sender_key,
        "verify",
        missing_message,
        vault,
    )
    return CryptoEngine.load_verify_key(resolved)


def _load_optional_verify_key(
    sender_key: str | Path | bytes | None,
    vault: Vault | None,
) -> ed25519.Ed25519PublicKey | None:
    resolved = resolve_key(sender_key, "verify", vault)
    if resolved is None:
        return None
    return CryptoEngine.load_verify_key(resolved)


def generate(
    passphrase: str,
    output_dir: str | os.PathLike[str] | None = None,
    force: bool = False,
    security: str = Config.ARGON2_DEFAULT_PROFILE,
) -> None:
    base = FileIO.coerce_path(output_dir or Path.cwd())
    if not base.exists() and output_dir:
        base.mkdir(parents=True)

    path_map = {spec.name: base / spec.filename for spec in KEY_SPECS}

    for path in path_map.values():
        if not path.parent.exists():
            path.parent.mkdir(parents=True)
        FileIO.check_output(path, None, force)

    encrypt_raw, decrypt_raw, verify_raw, sign_raw = generate_key_material(
        passphrase,
        security=security,
    )
    generated = {
        "encrypt": encrypt_raw,
        "decrypt": decrypt_raw,
        "verify": verify_raw,
        "sign": sign_raw,
    }
    for spec in KEY_SPECS:
        FileIO.atomic_write(
            path_map[spec.name],
            KeyFormat.pack(spec.format_code, generated[spec.name]),
            mode=spec.mode,
        )


def _encrypt_stream(
    out_fh: BinaryIO,
    encrypt_key: x448.X448PublicKey,
    compress: bool,
    sign_key: ed25519.Ed25519PrivateKey | None = None,
    write_payload: Callable[[BinaryIO], None] = lambda _fh: None,
) -> None:
    with CryptoEngine.encrypt_writer(
        out_fh,
        encrypt_key,
        sign_key=sign_key,
    ) as encrypted_fh:
        if compress:
            encrypted_fh.write(Config.ZSTD_MAGIC)
            with _zstd.ZstdCompressor().stream_writer(encrypted_fh) as zstd_fh:
                write_payload(zstd_fh)
            return
        write_payload(encrypted_fh)


def _encrypt_directory(
    input_path: Path,
    output_fh: BinaryIO,
    encrypt_key: x448.X448PublicKey,
    compress: bool,
    sign_key: ed25519.Ed25519PrivateKey | None,
) -> None:
    _encrypt_stream(
        output_fh,
        encrypt_key,
        compress,
        sign_key,
        lambda plaintext_fh: PayloadManager.write_directory(input_path, plaintext_fh),
    )


def _encrypt_data_to_stream(
    data: str | Path | bytes,
    output_fh: BinaryIO,
    encrypt_key: x448.X448PublicKey,
    compress: bool,
    sign_key: ed25519.Ed25519PrivateKey | None,
) -> None:
    input_path = Path(data) if isinstance(data, (str, Path)) else None
    if input_path is not None and input_path.is_dir():
        _encrypt_directory(input_path, output_fh, encrypt_key, compress, sign_key)
        return

    with open_input(data) as (input_fh, _, _):
        _encrypt_stream(
            output_fh,
            encrypt_key,
            compress,
            sign_key,
            lambda plaintext_fh: shutil.copyfileobj(
                input_fh,
                plaintext_fh,
                length=Config.READ_CHUNK_SIZE,
            ),
        )


def encrypt(
    data: str | Path | bytes,
    recipient_key: str | Path | bytes | None = None,
    out: str | Path | None = None,
    replace: bool = False,
    compress: bool = False,
    sender_key: str | Path | bytes | None = None,
    sender_passphrase: str = "",
    vault: Vault | None = None,
) -> bytes | None:
    encrypt_key = _load_encrypt_key(recipient_key, vault)
    sign_key_obj = _load_optional_sign_key(sender_key, sender_passphrase, vault)

    input_path = Path(data) if isinstance(data, (str, Path)) else None

    if out is not None:
        out = append_extension(out, Config.FILE_EXT)
    elif input_path is not None:
        out = infer_encrypt_output(input_path)

    def run(output_fh: BinaryIO) -> None:
        _encrypt_data_to_stream(
            data,
            output_fh,
            encrypt_key,
            compress,
            sign_key_obj,
        )

    if out is not None:
        output_path = FileIO.coerce_path(out)
        FileIO.check_output(output_path, input_path, replace, hint="--replace")
        with FileIO.atomic_writer(output_path) as output_fh:
            run(output_fh)
        return None

    output_buffer = io.BytesIO()
    run(output_buffer)
    return output_buffer.getvalue()


def verify(
    data: str | Path | bytes,
    sender_key: str | Path | bytes | None = None,
    vault: Vault | None = None,
) -> str:
    input_path = Path(data) if isinstance(data, (str, Path)) else None
    if input_path is not None:
        validate_extension(input_path, Config.FILE_EXT, "encrypted file")
    verify_key = _load_required_verify_key(
        sender_key,
        "sender verify key is required for explicit verification",
        vault,
    )
    with open_input(data) as (input_fh, file_size, _):
        return CryptoEngine.verify_signed_stream(input_fh, verify_key, file_size)


def sign(
    data: str | Path | bytes,
    sender_key: str | Path | bytes | None = None,
    sender_passphrase: str = "",
    out: str | Path | None = None,
    replace: bool = False,
    vault: Vault | None = None,
) -> bytes | None:
    sign_key_obj = _load_required_sign_key(
        sender_key,
        sender_passphrase,
        vault,
    )
    digest = hash_input(data)
    signature = sign_key_obj.sign(Config.SIGNATURE_CONTEXT + digest)

    if out is not None:
        output_path = FileIO.coerce_path(out)
        FileIO.check_output(output_path, None, replace, hint="--replace")
        FileIO.atomic_write(output_path, signature, mode=0o644)
        return None
    return signature


def verify_detached(
    data: str | Path | bytes,
    signature: str | Path | bytes,
    sender_key: str | Path | bytes | None = None,
    vault: Vault | None = None,
) -> str:
    verify_key = _load_required_verify_key(
        sender_key,
        "sender verify key is required for explicit detached verification",
        vault,
    )
    digest = hash_input(data)
    signature_bytes = read_small_binary(signature, Config.MAX_KEY_SIZE)

    if len(signature_bytes) != Config.SIGNATURE_LEN:
        raise SignSealError("invalid signature length")

    try:
        verify_key.verify(signature_bytes, Config.SIGNATURE_CONTEXT + digest)
    except InvalidSignature:
        raise SignSealError("signature verification failed")

    return CryptoEngine.format_fingerprint(
        CryptoEngine.key_fingerprint_bytes(verify_key)
    )


def _decrypt_verified_stream(
    input_fh: BinaryIO,
    file_size: int,
    decrypt_key: x448.X448PrivateKey,
    out: Path | None,
    verify_key: ed25519.Ed25519PublicKey | None,
) -> bytes | None:
    processor = PlaintextProcessor(out)
    try:
        CryptoEngine.decrypt_and_verify_stream(
            input_fh,
            processor,
            decrypt_key,
            file_size,
            verify_key=verify_key,
        )
        return processor.close()
    except Exception:
        processor.abort()
        raise


def decrypt(
    data: str | Path | bytes,
    recipient_key: str | Path | bytes | None = None,
    recipient_passphrase: str = "",
    out: str | Path | None = None,
    replace: bool = False,
    sender_key: str | Path | bytes | None = None,
    vault: Vault | None = None,
) -> bytes | None:
    decrypt_key = _load_decrypt_key(
        recipient_key,
        recipient_passphrase,
        vault,
    )
    verify_key = _load_optional_verify_key(sender_key, vault)

    input_path = Path(data) if isinstance(data, (str, Path)) else None

    if input_path is not None:
        validate_extension(input_path, Config.FILE_EXT, "encrypted file")

    if out is None and input_path is not None:
        out = infer_decrypt_output(input_path)

    output_path = FileIO.coerce_path(out) if out is not None else None
    if output_path is not None:
        FileIO.check_output(output_path, input_path, replace, hint="--replace")

    with open_input(data) as (cipher_fh, file_size, _):
        result = _decrypt_verified_stream(
            cipher_fh,
            file_size,
            decrypt_key,
            output_path,
            verify_key,
        )

    return result
