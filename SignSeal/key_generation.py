from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x448

from .config import Config
from .engine import CryptoEngine
from .exceptions import SignSealError
from .passwords import validate_password_strength


def generate_key_material(
    passphrase: str,
    security: str = Config.ARGON2_DEFAULT_PROFILE,
) -> tuple[bytes, bytes, bytes, bytes]:
    normalized = validate_password_strength(passphrase)

    encrypt_private = x448.X448PrivateKey.generate()
    sign_private = ed25519.Ed25519PrivateKey.generate()

    encrypt_public = encrypt_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    decrypt_private = CryptoEngine.wrap_private_key(
        encrypt_private,
        normalized,
        security,
        Config.DECRYPT_KEY_AAD_PREFIX,
    )
    verify_public = sign_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sign_private_wrapped = CryptoEngine.wrap_private_key(
        sign_private,
        normalized,
        security,
        Config.SIGN_KEY_AAD_PREFIX,
    )
    return encrypt_public, decrypt_private, verify_public, sign_private_wrapped
