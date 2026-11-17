"""The check catalogue."""

from __future__ import annotations

from . import filesystem, lifecycle, network, optional, quota, secrets, snapshot
from .base import Check, CheckContext, CheckFailed, Evidence, SkipCheck

_MODULES = (lifecycle, filesystem, snapshot, network, secrets, quota, optional)

ALL_CHECKS: list[Check] = [check for module in _MODULES for check in module.CHECKS]
CHECKS_BY_ID: dict[str, Check] = {check.id: check for check in ALL_CHECKS}
CATEGORIES: list[str] = list(dict.fromkeys(check.category for check in ALL_CHECKS))

__all__ = [
    "ALL_CHECKS",
    "CATEGORIES",
    "CHECKS_BY_ID",
    "Check",
    "CheckContext",
    "CheckFailed",
    "Evidence",
    "SkipCheck",
]
