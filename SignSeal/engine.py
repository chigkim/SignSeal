from __future__ import annotations
import ctypes
import hmac
import secrets
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from typing import BinaryIO, Final, Iterator

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x448
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .config import Config
from .exceptions import SignSealError
from .passwords import normalize_password_buffer


@dataclass(slots=True)
class _DecryptContext:
    version: int
    header: bytes
    nonce: bytes
    sign_fingerprint: bytes | None
    body_len: int
    decryptor: object
    shared: bytearray
    sym_key: bytearray


class _HashingWriter:
    def __init__(self, out_fh: BinaryIO, hasher) -> None:
        self._out_fh = out_fh
        self._hasher = hasher

    def write(self, data: bytes) -> int:
        if data:
            self._hasher.update(data)
        return self._out_fh.write(data)

    def flush(self) -> None:
        if hasattr(self._out_fh, "flush"):
            self._out_fh.flush()


class _EncryptSink:
    def __init__(self, encryptor, out_fh: BinaryIO) -> None:
        self._encryptor = encryptor
        self._out_fh = out_fh
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise SignSealError("encryptor is closed")
        if data:
            self._out_fh.write(self._encryptor.update(data))
        return len(data)

    def flush(self) -> None:
        if hasattr(self._out_fh, "flush"):
            self._out_fh.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._out_fh.write(self._encryptor.finalize())
        self._out_fh.write(self._encryptor.tag)
        self._closed = True


class CryptoEngine:
    _ZERO_56: Final[bytes] = b"\x00" * 56
    _ZERO_FINGERPRINT: Final[bytes] = b"\x00" * 32
    _ZERO_SIGNATURE: Final[bytes] = b"\x00" * 64

    @staticmethod
    def secure_zero(buf: bytearray) -> None:
        if buf:
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))

    @staticmethod
    def validate_argon2(iterations: int, memory: int, lanes: int) -> None:
        if not (
            Config.ARGON2_MIN_ITERATIONS <= iterations <= Config.ARGON2_MAX_ITERATIONS
            and Config.ARGON2_MIN_MEMORY <= memory <= Config.ARGON2_MAX_MEMORY
            and Config.ARGON2_MIN_LANES <= lanes <= Config.ARGON2_MAX_LANES
        ):
            raise SignSealError("KDF parameters outside security bounds")

    @staticmethod
    def derive_symmetric_key(
        shared_secret: bytes,
        salt: bytes,
        eph_pub_bytes: bytes,
        encrypt_key_bytes: bytes,
    ) -> bytearray:
        info = Config.HKDF_INFO + eph_pub_bytes + encrypt_key_bytes
        key = HKDF(
            algorithm=hashes.SHA512(),
            length=Config.HKDF_LEN,
            salt=salt,
            info=info,
        ).derive(shared_secret)
        return bytearray(key)

    @staticmethod
    def derive_argon2(
        password: bytes, salt: bytes, iters: int, mem: int, lanes: int
    ) -> bytes:
        return Argon2id(
            salt=salt,
            length=Config.ARGON2_DKLEN,
            iterations=iters,
            lanes=lanes,
            memory_cost=mem,
        ).derive(password)

    @staticmethod
    def key_fingerprint_bytes(
        public_key: x448.X448PublicKey | ed25519.Ed25519PublicKey,
    ) -> bytes:
        spki = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(spki)
        return digest.finalize()

    @staticmethod
    def format_fingerprint(fingerprint: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in fingerprint)

    @staticmethod
    def load_encrypt_key(pem: bytes) -> x448.X448PublicKey:
        if len(pem) > Config.MAX_KEY_SIZE:
            raise SignSealError("key too large")
        try:
            pub = serialization.load_pem_public_key(pem)
            if not isinstance(pub, x448.X448PublicKey):
                raise ValueError()
            return pub
        except (TypeError, ValueError, UnsupportedAlgorithm):
            raise SignSealError("invalid encrypt key (E)")

    @staticmethod
    def load_verify_key(pem: bytes) -> ed25519.Ed25519PublicKey:
        if len(pem) > Config.MAX_KEY_SIZE:
            raise SignSealError("key too large")
        try:
            pub = serialization.load_pem_public_key(pem)
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                raise ValueError()
            return pub
        except (TypeError, ValueError, UnsupportedAlgorithm):
            raise SignSealError("invalid verify key (V)")

    @staticmethod
    def _load_wrapped_private_key(
        blob: bytes, password: str, aad_prefix: bytes, key_type, error_message: str
    ):
        prefix_fmt = Config.PROTECTED_BLOB_PREFIX_FMT
        prefix_len = Config.PROTECTED_BLOB_PREFIX_LEN
        if len(blob) < prefix_len or blob[0] != Config.FORMAT_VERSION:
            raise SignSealError("invalid private key format")
        _, salt, iters, mem, lanes, nonce = struct.unpack(prefix_fmt, blob[:prefix_len])
        CryptoEngine.validate_argon2(iters, mem, lanes)

        pw_bytes = normalize_password_buffer(password)
        key = bytearray()
        plaintext = bytearray()
        try:
            key = bytearray(
                CryptoEngine.derive_argon2(bytes(pw_bytes), salt, iters, mem, lanes)
            )
            aad = aad_prefix + blob[:prefix_len]
            plaintext = bytearray(
                AESGCM(bytes(key)).decrypt(nonce, blob[prefix_len:], aad)
            )
            priv = serialization.load_der_private_key(bytes(plaintext), password=None)
            if not isinstance(priv, key_type):
                raise ValueError()
            return priv
        except InvalidTag:
            raise SignSealError(error_message)
        except (TypeError, ValueError, UnsupportedAlgorithm):
            raise SignSealError(error_message)
        finally:
            CryptoEngine.secure_zero(pw_bytes)
            CryptoEngine.secure_zero(key)
            CryptoEngine.secure_zero(plaintext)

    @staticmethod
    def load_decrypt_key(blob: bytes, password: str) -> x448.X448PrivateKey:
        return CryptoEngine._load_wrapped_private_key(
            blob,
            password,
            Config.DECRYPT_KEY_AAD_PREFIX,
            x448.X448PrivateKey,
            "password incorrect or decrypt key corrupted",
        )

    @staticmethod
    def load_sign_key(blob: bytes, password: str) -> ed25519.Ed25519PrivateKey:
        return CryptoEngine._load_wrapped_private_key(
            blob,
            password,
            Config.SIGN_KEY_AAD_PREFIX,
            ed25519.Ed25519PrivateKey,
            "password incorrect or sign key corrupted",
        )

    @staticmethod
    def wrap_private_key(
        private_key, password: str, security: str, aad_prefix: bytes
    ) -> bytes:
        if security not in Config.ARGON2_PROFILES:
            raise SignSealError(
                f"unknown security profile: {security} (choose from: {', '.join(Config.ARGON2_PROFILES)})"
            )
        salt = secrets.token_bytes(Config.SALT_LEN)
        nonce = secrets.token_bytes(Config.NONCE_LEN)
        iters, mem, lanes = Config.ARGON2_PROFILES[security]
        params_block = struct.pack(
            Config.PROTECTED_BLOB_PREFIX_FMT,
            Config.FORMAT_VERSION,
            salt,
            iters,
            mem,
            lanes,
            nonce,
        )

        pw_bytes = normalize_password_buffer(password)
        key = bytearray()
        plaintext = bytearray()
        try:
            key = bytearray(
                CryptoEngine.derive_argon2(bytes(pw_bytes), salt, iters, mem, lanes)
            )
            aad = aad_prefix + params_block
            plaintext = bytearray(
                private_key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            return params_block + AESGCM(bytes(key)).encrypt(
                nonce,
                bytes(plaintext),
                aad,
            )
        finally:
            CryptoEngine.secure_zero(pw_bytes)
            CryptoEngine.secure_zero(key)
            CryptoEngine.secure_zero(plaintext)

    @staticmethod
    def read_header(
        in_fh: BinaryIO, file_size: int
    ) -> tuple[int, bytes, bytes, bytes, bytes | None]:
        prefix = in_fh.read(3)
        if len(prefix) != 3:
            raise SignSealError("truncated header")
        magic, version = prefix[:2], prefix[2]
        if magic != Config.MAGIC:
            raise SignSealError("unsupported format")
        if version == Config.FORMAT_VERSION:
            if file_size < Config.MIN_CIPHERTEXT_SIZE:
                raise SignSealError("ciphertext too short")
            rest = in_fh.read(Config.HEADER_LEN - len(prefix))
            if len(rest) != Config.HEADER_LEN - len(prefix):
                raise SignSealError("truncated header")
            header = prefix + rest
            _, _, salt, eph_pub_bytes, sign_fingerprint = struct.unpack(
                Config.HEADER_FMT, header
            )
            return version, header, salt, eph_pub_bytes, sign_fingerprint
        raise SignSealError(f"unsupported format version: {version}")

    @staticmethod
    def signer_fingerprint_from_header(
        sign_fingerprint: bytes | None,
    ) -> bytes | None:
        if (
            sign_fingerprint is None
            or sign_fingerprint == CryptoEngine._ZERO_FINGERPRINT
        ):
            return None
        return sign_fingerprint

    @staticmethod
    def ciphertext_signer_fingerprint(in_fh: BinaryIO, file_size: int) -> bytes | None:
        _, _, _, _, sign_fingerprint = CryptoEngine.read_header(in_fh, file_size)
        return CryptoEngine.signer_fingerprint_from_header(sign_fingerprint)

    @staticmethod
    def ciphertext_is_signed(in_fh: BinaryIO, file_size: int) -> bool:
        return CryptoEngine.ciphertext_signer_fingerprint(in_fh, file_size) is not None

    @staticmethod
    def stream_sha512(in_fh: BinaryIO, size: int) -> bytes:
        digest = hashes.Hash(hashes.SHA512())
        remaining = size
        while remaining > 0:
            chunk = in_fh.read(min(Config.READ_CHUNK_SIZE, remaining))
            if not chunk:
                raise SignSealError("unexpected end of ciphertext")
            remaining -= len(chunk)
            digest.update(chunk)
        return digest.finalize()

    @staticmethod
    def _prepare_decrypt_context(
        in_fh: BinaryIO, decrypt_key: x448.X448PrivateKey, file_size: int
    ) -> _DecryptContext:
        version, header, salt, eph_pub_bytes, sign_fingerprint = (
            CryptoEngine.read_header(in_fh, file_size)
        )
        nonce = in_fh.read(Config.NONCE_LEN)
        if len(nonce) != Config.NONCE_LEN:
            raise SignSealError("truncated nonce")

        eph_pub = x448.X448PublicKey.from_public_bytes(eph_pub_bytes)
        encrypt_key_bytes = decrypt_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        shared = bytearray(decrypt_key.exchange(eph_pub))
        sym_key = bytearray()
        try:
            if hmac.compare_digest(bytes(shared), CryptoEngine._ZERO_56):
                raise SignSealError("invalid shared secret")

            sym_key = CryptoEngine.derive_symmetric_key(
                bytes(shared), salt, eph_pub_bytes, encrypt_key_bytes
            )

            body_len = (
                file_size
                - len(header)
                - Config.NONCE_LEN
                - Config.GCM_TAG_LEN
                - Config.SIGNATURE_LEN
            )
            decryptor = Cipher(
                algorithms.AES(bytes(sym_key)), modes.GCM(nonce)
            ).decryptor()
            decryptor.authenticate_additional_data(header + nonce)
            return _DecryptContext(
                version=version,
                header=header,
                nonce=nonce,
                sign_fingerprint=sign_fingerprint,
                body_len=body_len,
                decryptor=decryptor,
                shared=shared,
                sym_key=sym_key,
            )
        except Exception:
            CryptoEngine.secure_zero(shared)
            CryptoEngine.secure_zero(sym_key)
            raise

    @staticmethod
    @contextmanager
    def encrypt_writer(
        out_fh: BinaryIO,
        encrypt_key: x448.X448PublicKey,
        sign_key: ed25519.Ed25519PrivateKey | None = None,
    ) -> Iterator[BinaryIO]:
        eph_priv = x448.X448PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        encrypt_key_bytes = encrypt_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        salt = secrets.token_bytes(Config.SALT_LEN)

        shared = bytearray(eph_priv.exchange(encrypt_key))
        sym_key = bytearray()
        sign_hasher = None
        signed_out = out_fh
        try:
            if hmac.compare_digest(bytes(shared), CryptoEngine._ZERO_56):
                raise SignSealError("invalid shared secret")

            sym_key = CryptoEngine.derive_symmetric_key(
                bytes(shared),
                salt,
                eph_pub_bytes,
                encrypt_key_bytes,
            )
            nonce = secrets.token_bytes(Config.NONCE_LEN)
            if sign_key is not None:
                sign_fingerprint = CryptoEngine.key_fingerprint_bytes(
                    sign_key.public_key()
                )
            else:
                sign_fingerprint = CryptoEngine._ZERO_FINGERPRINT

            header = struct.pack(
                Config.HEADER_FMT,
                Config.MAGIC,
                Config.FORMAT_VERSION,
                salt,
                eph_pub_bytes,
                sign_fingerprint,
            )
            sign_hasher = hashes.Hash(hashes.SHA512())
            signed_out = _HashingWriter(out_fh, sign_hasher)

            signed_out.write(header)
            signed_out.write(nonce)

            encryptor = Cipher(
                algorithms.AES(bytes(sym_key)), modes.GCM(nonce)
            ).encryptor()
            encryptor.authenticate_additional_data(header + nonce)
            sink = _EncryptSink(encryptor, signed_out)
            try:
                yield sink
                sink.close()
                if sign_key is not None:
                    signature_message = (
                        Config.SIGNATURE_CONTEXT + sign_hasher.finalize()
                    )
                    out_fh.write(sign_key.sign(signature_message))
                else:
                    out_fh.write(CryptoEngine._ZERO_SIGNATURE)
            finally:
                sink.close()
        finally:
            CryptoEngine.secure_zero(shared)
            CryptoEngine.secure_zero(sym_key)
            del eph_priv

    @staticmethod
    def decrypt_and_verify_stream(
        in_fh: BinaryIO,
        out_fh: BinaryIO,
        decrypt_key: x448.X448PrivateKey,
        file_size: int,
        verify_key: ed25519.Ed25519PublicKey | None = None,
    ) -> str | None:
        ctx = CryptoEngine._prepare_decrypt_context(in_fh, decrypt_key, file_size)
        sign_hasher = None
        expected_fingerprint = None
        try:
            if verify_key is not None:
                if (
                    not ctx.sign_fingerprint
                    or ctx.sign_fingerprint == CryptoEngine._ZERO_FINGERPRINT
                ):
                    raise SignSealError("ciphertext is not sender-signed")

                expected_fingerprint = CryptoEngine.key_fingerprint_bytes(verify_key)
                if not hmac.compare_digest(expected_fingerprint, ctx.sign_fingerprint):
                    raise SignSealError(
                        "verify key does not match ciphertext sign fingerprint"
                    )

            sign_hasher = hashes.Hash(hashes.SHA512())
            sign_hasher.update(ctx.header)
            sign_hasher.update(ctx.nonce)

            remaining = ctx.body_len
            while remaining > 0:
                chunk = in_fh.read(min(Config.READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise SignSealError("unexpected end of ciphertext")
                remaining -= len(chunk)
                sign_hasher.update(chunk)
                plaintext = ctx.decryptor.update(chunk)
                if plaintext:
                    out_fh.write(plaintext)

            tag = in_fh.read(Config.GCM_TAG_LEN)
            if len(tag) != Config.GCM_TAG_LEN:
                raise SignSealError("truncated authentication tag")
            sign_hasher.update(tag)
            try:
                final_plaintext = ctx.decryptor.finalize_with_tag(tag)
            except InvalidTag:
                raise SignSealError("authentication failed -- corrupt or tampered file")
            if final_plaintext:
                out_fh.write(final_plaintext)

            signature = in_fh.read(Config.SIGNATURE_LEN)
            if len(signature) != Config.SIGNATURE_LEN:
                raise SignSealError("truncated sender signature")

            if verify_key is not None:
                try:
                    verify_key.verify(
                        signature,
                        Config.SIGNATURE_CONTEXT + sign_hasher.finalize(),
                    )
                except InvalidSignature:
                    raise SignSealError("signature verification failed")
                return CryptoEngine.format_fingerprint(expected_fingerprint)

            if (
                ctx.sign_fingerprint
                and ctx.sign_fingerprint != CryptoEngine._ZERO_FINGERPRINT
            ):
                return CryptoEngine.format_fingerprint(ctx.sign_fingerprint)

            return None
        finally:
            CryptoEngine.secure_zero(ctx.shared)
            CryptoEngine.secure_zero(ctx.sym_key)

    @staticmethod
    def verify_signed_stream(
        in_fh: BinaryIO, verify_key: ed25519.Ed25519PublicKey, file_size: int
    ) -> str:
        version, _, _, _, sign_fingerprint = CryptoEngine.read_header(in_fh, file_size)
        if CryptoEngine.signer_fingerprint_from_header(sign_fingerprint) is None:
            raise SignSealError("ciphertext is not sender-signed")
        expected_fingerprint = CryptoEngine.key_fingerprint_bytes(verify_key)
        if not hmac.compare_digest(expected_fingerprint, sign_fingerprint):
            raise SignSealError("verify key does not match ciphertext sign fingerprint")
        in_fh.seek(0)
        digest = CryptoEngine.stream_sha512(in_fh, file_size - Config.SIGNATURE_LEN)
        signature = in_fh.read(Config.SIGNATURE_LEN)
        if len(signature) != Config.SIGNATURE_LEN:
            raise SignSealError("truncated sender signature")
        try:
            verify_key.verify(signature, Config.SIGNATURE_CONTEXT + digest)
        except InvalidSignature:
            raise SignSealError("signature verification failed")
        return CryptoEngine.format_fingerprint(expected_fingerprint)
