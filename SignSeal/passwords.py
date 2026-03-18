from __future__ import annotations

import hmac
import unicodedata
from collections.abc import Callable

from .config import Config
from .exceptions import SignSealError

PromptCallback = Callable[[str], str | None]
ErrorCallback = Callable[[str], None]


def normalize_password(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def normalize_password_bytes(password: str) -> bytes:
    return normalize_password(password).encode("utf-8")


def normalize_password_buffer(password: str) -> bytearray:
    return bytearray(normalize_password_bytes(password))


def passwords_match(left: str, right: str) -> bool:
    left_normalized = normalize_password_bytes(left)
    right_normalized = normalize_password_bytes(right)
    return hmac.compare_digest(left_normalized, right_normalized)


def validate_password_strength(password: str) -> str:
    normalized = normalize_password(password)
    if len(normalized) < Config.MIN_PASSWORD_LEN:
        raise SignSealError(
            f"password must be at least {Config.MIN_PASSWORD_LEN} characters"
        )
    return normalized


def validate_new_password(password: str, confirmation: str) -> str:
    normalized = validate_password_strength(password)
    if not passwords_match(normalized, confirmation):
        raise SignSealError("passwords do not match")
    return normalized


def request_password(
    prompt: str,
    ask: PromptCallback,
    on_error: ErrorCallback,
) -> str | None:
    while True:
        password = ask(prompt)
        if password is None:
            return None
        try:
            return validate_password_strength(password)
        except SignSealError as exc:
            on_error(str(exc))


def request_new_password(
    first_prompt: str,
    confirm_prompt: str,
    ask: PromptCallback,
    on_error: ErrorCallback,
) -> str | None:
    while True:
        password = ask(first_prompt)
        if password is None:
            return None
        confirmation = ask(confirm_prompt)
        if confirmation is None:
            return None
        try:
            return validate_new_password(password, confirmation)
        except SignSealError as exc:
            on_error(str(exc))
