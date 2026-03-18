from __future__ import annotations
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path
from typing import BinaryIO

import zstandard as _zstd

from .config import Config
from .exceptions import SignSealError
from .io_utils import FileIO, CountingWriter


class PayloadManager:
    @staticmethod
    def write_directory(source_dir: Path, out_fh: BinaryIO) -> None:
        source_dir = source_dir.resolve()
        FileIO.reject_symlink(source_dir, "input directory")
        out_fh.write(Config.DIR_MAGIC)
        with tarfile.open(
            fileobj=out_fh, mode="w|", format=tarfile.PAX_FORMAT
        ) as archive:
            for root, dirs, files in os.walk(source_dir):
                for name in sorted(dirs + files):
                    path = Path(root) / name
                    st = path.lstat()
                    if stat.S_ISLNK(st.st_mode):
                        raise SignSealError(f"refusing symlink in tree: {path}")
                    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                        raise SignSealError(f"refusing special file in tree: {path}")
                    archive.add(
                        path,
                        arcname=path.relative_to(source_dir).as_posix(),
                        recursive=False,
                    )

    @staticmethod
    def unpack_directory_stream(in_fh: BinaryIO, out_dir: Path) -> None:
        FileIO.reject_symlink(out_dir, "output directory")
        if out_dir.exists():
            if not out_dir.is_dir():
                raise SignSealError(f"output directory is not a directory: {out_dir}")
        else:
            FileIO.secure_mkdir(out_dir)
        root_dir = out_dir.resolve()
        entries = 0
        total_size = 0
        with tarfile.open(fileobj=in_fh, mode="r|*") as archive:
            for member in archive:
                entries += 1
                if entries > Config.MAX_ARCHIVE_ENTRIES:
                    raise SignSealError("archive contains too many entries")
                if not (member.isfile() or member.isdir()):
                    raise SignSealError(
                        f"refusing non-regular archive member: {member.name}"
                    )
                rel = Path(member.name)
                if rel.is_absolute() or ".." in rel.parts:
                    raise SignSealError("unsafe archive path")

                # Check target and its parents for symlinks to prevent TOCTOU/redirection
                target = (out_dir / rel).resolve()
                if root_dir not in target.parents and target != root_dir:
                    raise SignSealError("unsafe archive escape")

                # Verify no part of the path is a symlink
                curr = target
                while curr != root_dir and curr != curr.parent:
                    if curr.is_symlink():
                        raise SignSealError(
                            f"refusing symlink in extraction path: {curr}"
                        )
                    curr = curr.parent
                if member.isdir():
                    FileIO.secure_mkdir(target)
                else:
                    if member.size > Config.MAX_ARCHIVE_MEMBER_SIZE:
                        raise SignSealError(f"archive member too large: {member.name}")
                    total_size += member.size
                    if total_size > Config.MAX_ARCHIVE_TOTAL_SIZE:
                        raise SignSealError("archive exceeds total size limit")
                    FileIO.secure_mkdir(target.parent)
                    src = archive.extractfile(member)
                    if src is None:
                        raise SignSealError(
                            f"cannot extract archive member: {member.name}"
                        )
                    with src, FileIO.atomic_writer(target) as dst:
                        remaining = member.size
                        while remaining > 0:
                            chunk = src.read(min(Config.READ_CHUNK_SIZE, remaining))
                            if not chunk:
                                raise SignSealError(
                                    f"truncated archive member: {member.name}"
                                )
                            dst.write(chunk)
                            remaining -= len(chunk)
                    if os.name != "nt":
                        os.chmod(target, 0o600)


class _FileOutput:
    def __init__(self, out_path: Path) -> None:
        self._cm = FileIO.atomic_writer(out_path)
        self._fh = self._cm.__enter__()
        self._closed = False

    def write(self, data: bytes) -> int:
        return self._fh.write(data)

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        if not self._closed:
            self._cm.__exit__(None, None, None)
            self._closed = True

    def abort(self) -> None:
        if not self._closed:
            self._cm.__exit__(SignSealError, SignSealError("aborted"), None)
            self._closed = True


class _DirectoryOutput:
    def __init__(self, out_path: Path) -> None:
        self._out_path = out_path.absolute()
        parent = self._out_path.parent
        if not parent.is_dir():
            raise SignSealError(f"output directory does not exist: {parent}")
        self._temp_dir = Path(tempfile.mkdtemp(dir=parent, prefix=".tmp_sc_dir_"))
        archive_fd, archive_path = tempfile.mkstemp(dir=parent, prefix=".tmp_sc_tar_")
        self._archive_path = Path(archive_path)
        self._archive_fh = os.fdopen(archive_fd, "wb")
        self._archive_closed = False
        if os.name == "nt":
            FileIO._set_owner_only_acl(str(self._temp_dir))
            FileIO._set_owner_only_acl(str(self._archive_path))
        else:
            os.chmod(self._temp_dir, 0o700)
        self._closed = False

    def write(self, data: bytes) -> int:
        return self._archive_fh.write(data)

    def flush(self) -> None:
        self._archive_fh.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._close_archive_writer()
        with FileIO.open_regular(self._archive_path) as (archive_fh, _):
            PayloadManager.unpack_directory_stream(archive_fh, self._temp_dir)
        self._delete_temp_archive()
        FileIO.reject_symlink(self._out_path, role="output directory")
        self._temp_dir.replace(self._out_path)
        self._closed = True

    def abort(self) -> None:
        if self._closed:
            return
        try:
            self._close_archive_writer()
        except Exception:
            pass
        self._delete_temp_archive()
        self._cleanup_temp_dir()
        self._closed = True

    def _close_archive_writer(self) -> None:
        if self._archive_closed:
            return
        self._archive_fh.flush()
        os.fsync(self._archive_fh.fileno())
        self._archive_fh.close()
        self._archive_closed = True

    def _delete_temp_archive(self) -> None:
        self._archive_path.unlink(missing_ok=True)

    def _cleanup_temp_dir(self) -> None:
        if not self._temp_dir.exists():
            return
        try:
            import shutil

            shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass


class _PayloadOutputRouter:
    def __init__(self, out: Path | None) -> None:
        self._out = out
        self._buffer = bytearray()
        self._sink: BinaryIO | io.BytesIO | None = None
        self._captured_data: bytes | None = None

    def write(self, data: bytes) -> int:
        if not data:
            return 0
        if self._sink is None:
            self._buffer.extend(data)
            self._initialize_if_ready(force=False)
        else:
            self._sink.write(data)
        return len(data)

    def flush(self) -> None:
        if self._sink is not None:
            self._sink.flush()

    def close(self) -> bytes | None:
        if self._sink is None:
            self._initialize_if_ready(force=True)
        if isinstance(self._sink, io.BytesIO):
            if not self._sink.closed:
                self._captured_data = self._sink.getvalue()
                self._sink.close()
            return self._captured_data
        if self._sink is not None and hasattr(self._sink, "close"):
            if not (hasattr(self._sink, "closed") and self._sink.closed):
                self._sink.close()
        return None

    def abort(self) -> None:
        if self._sink is None:
            self._buffer.clear()
            return
        if hasattr(self._sink, "abort"):
            self._sink.abort()
            return
        if hasattr(self._sink, "close"):
            self._sink.close()

    def _initialize_if_ready(self, force: bool) -> None:
        if self._sink is not None:
            return
        if not force and len(self._buffer) < len(Config.DIR_MAGIC):
            return
        buf = bytes(self._buffer)
        if buf.startswith(Config.DIR_MAGIC):
            payload = buf[len(Config.DIR_MAGIC) :]
            self._sink = (
                io.BytesIO() if self._out is None else _DirectoryOutput(self._out)
            )
        else:
            payload = buf
            if self._out is None:
                self._sink = io.BytesIO()
            else:
                self._sink = _FileOutput(self._out)
        self._buffer.clear()
        self._sink.write(payload)


class PlaintextProcessor:
    def __init__(self, out: Path | None) -> None:
        self._buffer = bytearray()
        self._sink: _PayloadOutputRouter | BinaryIO | None = None
        self._payload_router: _PayloadOutputRouter | None = None
        self._compressed = False
        self._out = out

    def write(self, data: bytes) -> int:
        if not data:
            return 0
        if self._sink is None:
            self._buffer.extend(data)
            self._initialize_if_ready(force=False)
        else:
            self._sink.write(data)
        return len(data)

    def flush(self) -> None:
        if self._sink is not None:
            self._sink.flush()

    def close(self) -> bytes | None:
        if self._sink is None:
            self._initialize_if_ready(force=True)
        if self._sink is None:
            return None
        self._sink.flush()
        if self._compressed:
            self._sink.close()
            return (
                self._payload_router.close()
                if self._payload_router is not None
                else None
            )
        return (
            self._payload_router.close() if self._payload_router is not None else None
        )

    def abort(self) -> None:
        if self._payload_router is not None:
            self._payload_router.abort()

    def _initialize_if_ready(self, force: bool) -> None:
        if self._sink is not None:
            return
        if not force and len(self._buffer) < len(Config.ZSTD_MAGIC):
            return
        buf = bytes(self._buffer)
        payload_router = _PayloadOutputRouter(self._out)
        self._payload_router = payload_router
        if buf.startswith(Config.ZSTD_MAGIC):
            bounded_router = CountingWriter(
                payload_router, Config.MAX_DECOMPRESSED_SIZE, "decompressed payload"
            )
            self._sink = _zstd.ZstdDecompressor().stream_writer(bounded_router)
            self._compressed = True
            payload = buf[len(Config.ZSTD_MAGIC) :]
        else:
            self._sink = payload_router
            payload = buf
        self._buffer.clear()
        if payload:
            self._sink.write(payload)
