from __future__ import annotations

import getpass

import pytest


@pytest.fixture
def patch_prompts(monkeypatch):
    def _patch(responses: list[str]) -> None:
        values = iter(responses)
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(values))

    return _patch
