from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

from .api import SignSeal as _SignSeal
from .config import Config
from .exceptions import SignSealError

SignSeal = _SignSeal

__all__ = ["SignSeal", "Config", "SignSealError"]


class _CallableModule(ModuleType):
    def __call__(
        self,
        password: str | None = None,
        vault_path: str | Path | None = None,
        *,
        overwrite: bool = False,
    ) -> _SignSeal:
        return _SignSeal(password=password, vault_path=vault_path, overwrite=overwrite)


sys.modules[__name__].__class__ = _CallableModule
