from __future__ import annotations

import getpass

from ..passwords import request_new_password, request_password


def _ask_hidden(prompt: str) -> str:
    return getpass.getpass(prompt)


def _show_error(message: str) -> None:
    print(message)


def prompt_password(prompt: str) -> str:
    password = request_password(prompt, _ask_hidden, _show_error)
    if password is None:
        raise KeyboardInterrupt
    return password


def prompt_new_password(
    prompt: str,
    confirm_prompt: str = "Confirm password: ",
) -> str:
    password = request_new_password(prompt, confirm_prompt, _ask_hidden, _show_error)
    if password is None:
        raise KeyboardInterrupt
    return password


def confirm_action(message: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    response = input(f"{message} {suffix} ").strip().lower()
    if not response:
        return default
    return response in {"y", "yes"}
