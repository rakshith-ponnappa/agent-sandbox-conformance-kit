"""Vendor-neutral interfaces that every sandbox adapter implements.

Required surface (the two Protocols below) is deliberately small. Adapters may
also offer these optional extensions; checks that need them are skipped when
they are missing or raise :class:`UnsupportedFeature`:

* ``SandboxProvider.list_active() -> list[str]`` - ids of live sandboxes created
  by this provider instance (used for leftover detection).
* ``Sandbox.logs() -> str`` - whatever the platform exposes as sandbox logs.
* ``Sandbox.run_pty(cmd, timeout=None) -> tuple[int, str]`` - run with a PTY.
"""

from __future__ import annotations

from typing import Mapping, Protocol, Sequence, runtime_checkable

NETWORK_MODES = ("deny-all", "allowlist", "open")


class SandboxError(Exception):
    """Base class for adapter errors."""


class UnsupportedFeature(SandboxError):
    """Raised for a capability the provider does not offer. Checks report SKIP."""


class QuotaExceeded(SandboxError):
    """Raised when the provider refuses to create more sandboxes."""


def validate_mode(mode: str) -> str:
    if mode not in NETWORK_MODES:
        raise ValueError(f"unknown network mode {mode!r}; expected one of {NETWORK_MODES}")
    return mode


@runtime_checkable
class Sandbox(Protocol):
    id: str

    def run(self, cmd: str, timeout: float | None = None) -> tuple[int, str, str]:
        """Run ``cmd`` through a POSIX shell; return (exit code, stdout, stderr)."""

    def write_file(self, path: str, data: bytes) -> None: ...

    def read_file(self, path: str) -> bytes:
        """Return file bytes; raise FileNotFoundError when the path is absent."""

    def snapshot(self) -> str:
        """Capture filesystem state and return an opaque snapshot id."""

    def restore(self, snapshot_id: str) -> None: ...

    def set_network_policy(self, mode: str, allow: Sequence[str] | None = None) -> None:
        """Switch egress policy: ``deny-all``, ``allowlist`` (with ``allow``) or ``open``."""

    def kill(self) -> None:
        """Destroy the sandbox. Must be idempotent."""


@runtime_checkable
class SandboxProvider(Protocol):
    name: str

    def create(
        self,
        template: str | None = None,
        network_policy: str = "deny-all",
        env: Mapping[str, str] | None = None,
        timeout: float = 300.0,
    ) -> Sandbox: ...
