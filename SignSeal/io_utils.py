from __future__ import annotations
import base64
import os
import stat
import tempfile
import struct
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from .config import Config
from .exceptions import SignSealError


class CountingWriter:
    def __init__(self, out_fh: BinaryIO, limit: int, label: str) -> None:
        self._out_fh = out_fh
        self._limit = limit
        self._label = label
        self._written = 0

    def write(self, data: bytes) -> int:
        new_total = self._written + len(data)
        if new_total > self._limit:
            raise SignSealError(f"{self._label} exceeds size limit")
        self._written = new_total
        return self._out_fh.write(data)

    def flush(self) -> None:
        if hasattr(self._out_fh, "flush"):
            self._out_fh.flush()

    def close(self) -> None:
        if hasattr(self._out_fh, "close"):
            self._out_fh.close()


class KeyFormat:
    MAGIC = b"SSK"
    MAGIC_BUNDLE = b"SSB"
    VERSION = Config._VERSION_BYTE

    # Types
    ENCRYPT = b"E"  # Encrypt key
    DECRYPT = b"D"  # Decrypt key
    SIGN = b"S"  # Sign key
    VERIFY = b"V"  # Verify key

    @staticmethod
    def pack(key_type: bytes, raw_key: bytes) -> bytes:
        return KeyFormat.MAGIC + KeyFormat.VERSION + key_type + raw_key

    TYPE_MAP: dict[bytes, str] = {
        ENCRYPT: "encrypt",
        DECRYPT: "decrypt",
        SIGN: "sign",
        VERIFY: "verify",
    }

    @staticmethod
    def unpack(data: bytes) -> tuple[str, bytes]:
        """Returns (type_str, raw_key)"""
        if len(data) < 5 or data[:3] != KeyFormat.MAGIC:
            raise SignSealError("invalid key format")
        if data[3:4] != KeyFormat.VERSION:
            raise SignSealError("unsupported key format version")

        key_type = data[4:5]
        raw_key = data[5:]

        if key_type not in KeyFormat.TYPE_MAP:
            raise SignSealError("unsupported key type")
        return KeyFormat.TYPE_MAP[key_type], raw_key

    @staticmethod
    def pack_alphanumeric(key_type: bytes, raw_key: bytes) -> str:
        """Packs a key into a Base32 string with hyphens for manual typing."""
        packed = KeyFormat.pack(key_type, raw_key)
        # Use Base32 (no padding, uppercase)
        b32 = base64.b32encode(packed).decode("ascii").rstrip("=")
        # Group by 4 for readability
        return "-".join(b32[i : i + 4] for i in range(0, len(b32), 4))

    @staticmethod
    def pack_bundle_alphanumeric(keys: dict[str, bytes]) -> str:
        """Packs multiple keys into a single Base32 string."""
        type_map = {
            "encrypt": KeyFormat.ENCRYPT,
            "decrypt": KeyFormat.DECRYPT,
            "sign": KeyFormat.SIGN,
            "verify": KeyFormat.VERIFY,
        }
        packed = KeyFormat.MAGIC_BUNDLE + KeyFormat.VERSION
        for ktype, raw in keys.items():
            tcode = type_map.get(ktype)
            if not tcode:
                continue
            packed += tcode + struct.pack(">H", len(raw)) + raw

        b32 = base64.b32encode(packed).decode("ascii").rstrip("=")
        return "-".join(b32[i : i + 4] for i in range(0, len(b32), 4))

    @staticmethod
    def unpack_alphanumeric(data: str) -> dict[str, bytes]:
        """Unpacks a key or bundle from a Base32 string. Returns {type_str: raw_key}."""
        clean = (
            data.replace("-", "")
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "")
            .upper()
        )
        # Add back padding
        padding = len(clean) % 8
        if padding:
            clean += "=" * (8 - padding)
        try:
            packed = base64.b32decode(clean)
            if packed.startswith(KeyFormat.MAGIC):
                t, r = KeyFormat.unpack(packed)
                return {t: r}
            elif packed.startswith(KeyFormat.MAGIC_BUNDLE):
                if packed[3:4] != KeyFormat.VERSION:
                    raise SignSealError("unsupported bundle version")
                results = {}
                offset = 4
                while offset < len(packed):
                    tcode = packed[offset : offset + 1]
                    if offset + 3 > len(packed):
                        raise SignSealError("invalid alphanumeric key format")
                    klen = struct.unpack(">H", packed[offset + 1 : offset + 3])[0]
                    if offset + 3 + klen > len(packed):
                        raise SignSealError("invalid alphanumeric key format")
                    raw = packed[offset + 3 : offset + 3 + klen]
                    if tcode not in KeyFormat.TYPE_MAP:
                        raise SignSealError("unsupported key type")
                    results[KeyFormat.TYPE_MAP[tcode]] = raw
                    offset += 3 + klen
                return results
            else:
                raise SignSealError("invalid alphanumeric key format")
        except Exception as e:
            if isinstance(e, SignSealError):
                raise
            raise SignSealError(f"invalid alphanumeric key format: {e}")


def validate_extension(path: Path, expected_ext: str, label: str) -> None:
    if path.suffix != expected_ext:
        raise SignSealError(
            f"{label} extension mismatch: expected '{expected_ext}', got '{path.suffix or '(none)'}'"
        )


class FileIO:
    @staticmethod
    def _set_owner_only_acl(path: str) -> None:
        """Set Windows ACL to owner-only. No-op on non-Windows. Raises SignSealError on failure."""
        if os.name != "nt":
            return
        try:
            user = os.getlogin()
        except OSError:
            user = os.environ.get("USERNAME", "")
        if not user:
            raise SignSealError(
                f"failed to resolve Windows user for permissions on {path}"
            )
        result = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            raise SignSealError(
                f"failed to set permissions on {path}: {result.stderr.decode().strip()}"
            )

    @staticmethod
    def coerce_path(value: str | os.PathLike[str], name: str = "path") -> Path:
        if isinstance(value, (str, os.PathLike)):
            return Path(value)
        raise TypeError(f"{name} must be a file path")

    @staticmethod
    def reject_symlink(path: Path, role: str) -> None:
        """Refuses paths where the leaf or any ancestor is a symlink or Windows junction."""
        curr = path.absolute()
        while True:
            try:
                # Use lstat to check for symlink without following it
                st = os.lstat(curr)
                if stat.S_ISLNK(st.st_mode):
                    raise SignSealError(f"refusing symlink in {role} path: {curr}")

                # Windows junction/reparse point check
                if os.name == "nt" and (
                    st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    # We reject reparse points that act as name surrogates (symlinks, junctions).
                    # IO_REPARSE_TAG_MOUNT_POINT (0xA0000003) is used for junctions.
                    # IO_REPARSE_TAG_SYMLINK (0xA000000C) is used for symlinks.
                    if hasattr(st, "st_reparse_tag"):
                        if st.st_reparse_tag in (
                            stat.IO_REPARSE_TAG_MOUNT_POINT,
                            stat.IO_REPARSE_TAG_SYMLINK,
                        ):
                            raise SignSealError(
                                f"refusing reparse point (junction/symlink) in {role} path: {curr}"
                            )
            except FileNotFoundError:
                pass  # path component does not exist yet
            except OSError as exc:
                raise SignSealError(
                    f"cannot verify {role} path component {curr}: {exc}"
                ) from exc
            parent = curr.parent
            if parent == curr:
                break
            curr = parent

    @staticmethod
    def _same_file(st_a: os.stat_result, st_b: os.stat_result) -> bool:
        return st_a.st_ino == st_b.st_ino and st_a.st_dev == st_b.st_dev

    @staticmethod
    def check_output(
        out_path: Path, in_path: Path | None, allow: bool, hint: str = "--force"
    ) -> None:
        FileIO.reject_symlink(out_path, role="output")
        # Use lstat for comparison to avoid following symlinks during check
        if in_path:
            try:
                if out_path.exists() and os.path.samefile(out_path, in_path):
                    raise SignSealError("output path must differ from input path")
            except OSError:
                pass
        if out_path.exists() and not allow:
            raise SignSealError(f"{out_path} already exists -- use {hint} to overwrite")

    @staticmethod
    @contextmanager
    def open_regular(
        path: Path, max_size: int | None = None
    ) -> Iterator[tuple[BinaryIO, int]]:
        if max_size is None:
            max_size = Config.MAX_FILE_SIZE
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SignSealError(f"not a regular file: {path}")

            # TOCTOU mitigation: check path after opening
            FileIO.reject_symlink(path, role="input")
            st_check = os.lstat(path)
            if not FileIO._same_file(st, st_check):
                raise SignSealError(f"file changed during open: {path}")

            if st.st_size > max_size:
                raise SignSealError(f"file {path} exceeds size limit")
            with os.fdopen(fd, "rb", closefd=True) as fh:
                fd = -1
                yield fh, st.st_size
        finally:
            if fd != -1:
                os.close(fd)

    @staticmethod
    @contextmanager
    def atomic_writer(path: Path, mode: int = 0o600) -> Iterator[BinaryIO]:
        path = path.absolute()
        FileIO.reject_symlink(path, role="output")

        parent = path.parent
        if not parent.is_dir():
            raise SignSealError(f"output directory does not exist: {parent}")

        fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp_sc_")
        fh = None
        try:
            if mode == 0o600:
                try:
                    FileIO._set_owner_only_acl(str(tmp))
                except SignSealError:
                    raise
                except Exception as e:
                    raise SignSealError(f"failed to set permissions on {tmp}: {e}")

            fh = os.fdopen(fd, "wb")
            fd = -1
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
            fh.close()
            fh = None

            if os.name != "nt":
                os.chmod(tmp, mode)

            # Re-verify path before commit
            FileIO.reject_symlink(path, role="output")
            os.replace(tmp, path)
            if os.name != "nt":
                dir_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            if fh is not None:
                try:
                    fh.close()
                except Exception:
                    pass
            if fd != -1:
                try:
                    os.close(fd)
                except Exception:
                    pass
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

    @staticmethod
    def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
        with FileIO.atomic_writer(path, mode) as fh:
            fh.write(data)

    @staticmethod
    def secure_mkdir(path: Path, mode: int = 0o700) -> None:
        """Creates a directory with restrictive permissions."""
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        if os.name == "nt":
            FileIO._set_owner_only_acl(str(path))
        else:
            os.chmod(path, mode)

    @staticmethod
    def read_key_file(path: Path, expected_type: str | None = None) -> bytes:
        """Reads a key file and optionally verifies its type. Returns raw bytes."""
        validate_extension(path, Config.KEY_EXT, "key file")
        with FileIO.open_regular(path, max_size=Config.MAX_KEY_SIZE) as (fh, _):
            data = fh.read()

        ktype, raw_key = KeyFormat.unpack(data)

        if expected_type and ktype != expected_type:
            raise SignSealError(
                f"expected {expected_type} key, but found {ktype} key in {path}"
            )

        return raw_key


def append_extension(path: str | os.PathLike[str], extension: str) -> Path:
    normalized = FileIO.coerce_path(path)
    path_str = str(normalized)
    if path_str.endswith(extension):
        return normalized
    return Path(f"{path_str}{extension}")
