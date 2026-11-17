"""Check model and the per-check execution context."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

MAX_EVIDENCE_CHARS = 2000


class SkipCheck(Exception):
    """Raised by a check when it cannot reach a verdict (unsupported or inconclusive)."""


class CheckFailed(AssertionError):
    """Raised by a check when the sandbox violates the expected property."""


@dataclass(frozen=True)
class Check:
    id: str
    category: str
    description: str
    fn: Callable[["CheckContext"], None]


@dataclass
class Evidence:
    command: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    note: str = ""


class Registry(Protocol):
    def add(self, sandbox: Any) -> None: ...
    def discard(self, sandbox: Any) -> None: ...


def truncate(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated {len(text) - limit} chars]"


class CheckContext:
    """Handed to every check. Tracks sandboxes for teardown and records evidence."""

    def __init__(
        self,
        provider: Any,
        *,
        options: Mapping[str, Any] | None = None,
        registry: Registry | None = None,
    ) -> None:
        self.provider = provider
        self.options = dict(options or {})
        self.evidence: list[Evidence] = []
        self._registry = registry
        self._sandboxes: list[Any] = []
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def secret(self, value: str) -> str:
        """Register a value that must be redacted from all evidence."""
        self._secrets.add(value)
        return value

    def redact(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "[REDACTED]")
        return text

    def create(self, **kwargs: Any) -> Any:
        sandbox = self.provider.create(**kwargs)
        with self._lock:
            self._sandboxes.append(sandbox)
        if self._registry is not None:
            self._registry.add(sandbox)
        self.note(f"created sandbox {sandbox.id} (network_policy={kwargs.get('network_policy', 'deny-all')})")
        return sandbox

    def run(self, sandbox: Any, cmd: str, timeout: float | None = None, *, label: str | None = None):
        code, out, err = sandbox.run(cmd, timeout=timeout)
        self.record(label or cmd, code, out, err)
        return code, out, err

    def record(self, command: str, exit_code: int | None, stdout: str = "", stderr: str = "") -> None:
        self.evidence.append(
            Evidence(
                command=self.redact(command),
                exit_code=exit_code,
                stdout=truncate(self.redact(stdout)),
                stderr=truncate(self.redact(stderr)),
            )
        )

    def note(self, text: str) -> None:
        self.evidence.append(Evidence(command="", exit_code=None, note=truncate(self.redact(text))))

    def require(self, condition: object, message: str) -> None:
        if not condition:
            raise CheckFailed(self.redact(message))

    def skip(self, reason: str) -> None:
        raise SkipCheck(reason)

    def cleanup(self) -> list[str]:
        """Kill every sandbox created through this context. Returns teardown errors."""
        with self._lock:
            sandboxes = list(reversed(self._sandboxes))
            self._sandboxes.clear()
        errors: list[str] = []
        for sandbox in sandboxes:
            try:
                sandbox.kill()
            except Exception as exc:  # keep going; leftovers stay registered for atexit
                errors.append(f"{getattr(sandbox, 'id', '?')}: {type(exc).__name__}: {exc}")
            else:
                if self._registry is not None:
                    self._registry.discard(sandbox)
        return errors
