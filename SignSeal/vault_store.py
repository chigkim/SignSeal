from __future__ import annotations

import hmac
import json
import os
import struct
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config
from .engine import CryptoEngine
from .exceptions import SignSealError
from .io_utils import FileIO, append_extension
from .passwords import normalize_password_buffer


class VaultStore:
    def __init__(self, vault_path: str | Path) -> None:
        self.vault_path = append_extension(vault_path, Config.VAULT_EXT)
        self._derived_key = bytearray()
        self._salt: bytes | None = None
        self._iters: int | None = None
        self._mem: int | None = None
        self._lanes: int | None = None
        self._closed = False

    def __enter__(self) -> "VaultStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        CryptoEngine.secure_zero(self._derived_key)
        self._derived_key = bytearray()
        self._salt = None
        self._iters = None
        self._mem = None
        self._lanes = None
        self._closed = True

    def create(
        self, password: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self._ensure_open()
        self._salt = os.urandom(Config.SALT_LEN)
        self._iters, self._mem, self._lanes = Config.ARGON2_PROFILES[
            Config.ARGON2_DEFAULT_PROFILE
        ]
        self._derive_key(password)
        payload = data or {"entries": {}}
        self.save(payload)
        return payload

    def load(self, password: str) -> dict[str, Any]:
        try:
            self._ensure_open()
            with FileIO.open_regular(
                self.vault_path,
                max_size=Config.MAX_VAULT_SIZE,
            ) as (fh, _):
                blob = fh.read()

            prefix_len = struct.calcsize(Config.PROTECTED_BLOB_PREFIX_FMT)
            if len(blob) < prefix_len or blob[0] != Config.FORMAT_VERSION:
                raise SignSealError("invalid vault format")

            try:
                _, salt, iters, mem, lanes, nonce = struct.unpack(
                    Config.PROTECTED_BLOB_PREFIX_FMT,
                    blob[:prefix_len],
                )
            except struct.error:
                raise SignSealError("invalid vault format")
            CryptoEngine.validate_argon2(iters, mem, lanes)

            self._salt = salt
            self._iters = iters
            self._mem = mem
            self._lanes = lanes
            self._derive_key(password)

            aad = Config.VAULT_AAD_PREFIX + blob[:prefix_len]
            plaintext = bytearray()
            try:
                plaintext = bytearray(
                    AESGCM(bytes(self._derived_key)).decrypt(
                        nonce,
                        blob[prefix_len:],
                        aad,
                    )
                )
                return self._decode_payload(plaintext)
            finally:
                CryptoEngine.secure_zero(plaintext)
        except SignSealError:
            self.close()
            raise
        except InvalidTag:
            self.close()
            raise SignSealError(
                "could not open vault - incorrect password or corrupted file"
            )
        except OSError as exc:
            self.close()
            raise SignSealError(f"could not open vault: {exc}")

    def save(self, data: dict[str, Any]) -> None:
        self._ensure_open()
        params_block = self._pack_prefix()
        aad = Config.VAULT_AAD_PREFIX + params_block
        plaintext = bytearray()
        try:
            plaintext = self._encode_payload(data)
            ciphertext = AESGCM(bytes(self._derived_key)).encrypt(
                params_block[-Config.NONCE_LEN :],
                bytes(plaintext),
                aad,
            )
            FileIO.atomic_write(self.vault_path, params_block + ciphertext)
        finally:
            CryptoEngine.secure_zero(plaintext)

    def verify_password(self, password: str) -> bool:
        self._ensure_open()
        if (
            self._salt is None
            or self._iters is None
            or self._mem is None
            or self._lanes is None
        ):
            raise SignSealError("vault is not loaded")
        pw_bytes = normalize_password_buffer(password)
        candidate = bytearray()
        try:
            candidate = bytearray(
                CryptoEngine.derive_argon2(
                    bytes(pw_bytes),
                    self._salt,
                    self._iters,
                    self._mem,
                    self._lanes,
                )
            )
            return hmac.compare_digest(bytes(candidate), bytes(self._derived_key))
        finally:
            CryptoEngine.secure_zero(pw_bytes)
            CryptoEngine.secure_zero(candidate)

    def change_password(self, current_data: dict[str, Any], new_password: str) -> None:
        self._ensure_open()
        old_key = self._derived_key
        old_salt = self._salt
        old_iters = self._iters
        old_mem = self._mem
        old_lanes = self._lanes

        self._salt = os.urandom(Config.SALT_LEN)
        self._iters, self._mem, self._lanes = Config.ARGON2_PROFILES[
            Config.ARGON2_DEFAULT_PROFILE
        ]
        try:
            self._derive_key(new_password)
            self.save(current_data)
            CryptoEngine.secure_zero(old_key)
        except Exception:
            if self._derived_key is not old_key:
                CryptoEngine.secure_zero(self._derived_key)
            self._derived_key = old_key
            self._salt = old_salt
            self._iters = old_iters
            self._mem = old_mem
            self._lanes = old_lanes
            raise

    def _derive_key(self, password: str) -> None:
        pw_bytes = normalize_password_buffer(password)
        old_key = self._derived_key
        try:
            self._derived_key = bytearray(
                CryptoEngine.derive_argon2(
                    bytes(pw_bytes),
                    self._salt,
                    self._iters,
                    self._mem,
                    self._lanes,
                )
            )
        finally:
            CryptoEngine.secure_zero(pw_bytes)
            if old_key is not self._derived_key:
                CryptoEngine.secure_zero(old_key)

    def _pack_prefix(self) -> bytes:
        nonce = os.urandom(Config.NONCE_LEN)
        return struct.pack(
            Config.PROTECTED_BLOB_PREFIX_FMT,
            Config.FORMAT_VERSION,
            self._salt,
            self._iters,
            self._mem,
            self._lanes,
            nonce,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise SignSealError("vault store is closed")

    @staticmethod
    def _decode_payload(payload: bytearray) -> dict[str, Any]:
        try:
            return json.loads(payload.decode("utf-8"))
        except (JSONDecodeError, UnicodeDecodeError):
            raise SignSealError("vault payload is corrupted")

    @staticmethod
    def _encode_payload(data: dict[str, Any]) -> bytearray:
        encoded = bytearray()
        encoder = json.JSONEncoder(separators=(",", ":"), ensure_ascii=True)
        for chunk in encoder.iterencode(data):
            encoded.extend(chunk.encode("utf-8"))
        return encoded
