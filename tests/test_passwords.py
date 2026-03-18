from __future__ import annotations

from SignSeal.passwords import request_new_password, request_password


def test_request_password_retries_until_valid() -> None:
    prompts: list[str] = []
    errors: list[str] = []
    responses = iter(["short", "long-enough-password"])

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    password = request_password("Password: ", ask, errors.append)

    assert password == "long-enough-password"
    assert prompts == ["Password: ", "Password: "]
    assert errors == ["password must be at least 12 characters"]


def test_request_new_password_retries_until_match() -> None:
    prompts: list[str] = []
    errors: list[str] = []
    responses = iter(
        [
            "long-enough-password",
            "wrong-confirmation",
            "long-enough-password",
            "long-enough-password",
        ]
    )

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    password = request_new_password(
        "Password: ",
        "Confirm: ",
        ask,
        errors.append,
    )

    assert password == "long-enough-password"
    assert prompts == ["Password: ", "Confirm: ", "Password: ", "Confirm: "]
    assert errors == ["passwords do not match"]
