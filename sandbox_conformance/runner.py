"""Execute checks with guaranteed teardown and render reports."""

from __future__ import annotations

import atexit
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from .checks import ALL_CHECKS, CATEGORIES
from .checks.base import Check, CheckContext, Evidence, SkipCheck
from .provider import UnsupportedFeature


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

    def __str__(self) -> str:
        return self.value


ICONS = {Status.PASS: "✅", Status.FAIL: "❌", Status.SKIP: "⏭️", Status.ERROR: "⚠️"}


@dataclass
class CheckResult:
    id: str
    category: str
    description: str
    status: Status
    message: str = ""
    duration_s: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class Report:
    provider: str
    started_at: str
    finished_at: str = ""
    results: list[CheckResult] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in Status}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def ok(self) -> bool:
        return not any(r.status in (Status.FAIL, Status.ERROR) for r in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary(),
            "results": [result.to_dict() for result in self.results],
        }


class LiveRegistry:
    """Every sandbox not yet torn down. Drained at interpreter exit as a last resort."""

    def __init__(self) -> None:
        self._items: dict[int, Any] = {}
        self._lock = threading.Lock()

    def add(self, sandbox: Any) -> None:
        with self._lock:
            self._items[id(sandbox)] = sandbox

    def discard(self, sandbox: Any) -> None:
        with self._lock:
            self._items.pop(id(sandbox), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def drain(self) -> int:
        with self._lock:
            items = list(self._items.values())
        killed = 0
        for sandbox in items:
            try:
                sandbox.kill()
            except Exception:
                continue
            self.discard(sandbox)
            killed += 1
        return killed


LIVE = LiveRegistry()
_ATEXIT_REGISTERED = False


def _ensure_atexit() -> None:
    global _ATEXIT_REGISTERED
    if not _ATEXIT_REGISTERED:
        atexit.register(LIVE.drain)
        _ATEXIT_REGISTERED = True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def select_checks(
    categories: Iterable[str] | None = None,
    catalogue: Sequence[Check] = ALL_CHECKS,
) -> list[Check]:
    if not categories:
        return list(catalogue)
    wanted = list(dict.fromkeys(categories))
    known = {check.category for check in catalogue}
    unknown = [c for c in wanted if c not in known]
    if unknown:
        raise ValueError(f"unknown categories {unknown}; known: {sorted(known)}")
    return [check for check in catalogue if check.category in wanted]


def run_one(
    provider: Any,
    check: Check,
    *,
    options: Mapping[str, Any] | None = None,
    registry: LiveRegistry | None = None,
) -> CheckResult:
    registry = LIVE if registry is None else registry
    ctx = CheckContext(provider, options=options, registry=registry)
    status, message = Status.PASS, ""
    started = time.monotonic()
    try:
        try:
            check.fn(ctx)
        except (SkipCheck, UnsupportedFeature) as exc:
            status, message = Status.SKIP, str(exc) or type(exc).__name__
        except AssertionError as exc:
            status, message = Status.FAIL, str(exc) or "assertion failed"
        except Exception as exc:
            status, message = Status.ERROR, ctx.redact(f"{type(exc).__name__}: {exc}")
    finally:
        cleanup_errors = ctx.cleanup()
    if cleanup_errors:
        ctx.note("teardown errors: " + "; ".join(cleanup_errors))
        if status in (Status.PASS, Status.SKIP):
            status = Status.ERROR
        message = "; ".join(filter(None, [message, "cleanup failed: " + "; ".join(cleanup_errors)]))
    return CheckResult(
        id=check.id,
        category=check.category,
        description=check.description,
        status=status,
        message=message,
        duration_s=round(time.monotonic() - started, 3),
        evidence=ctx.evidence,
    )


def run_checks(
    provider: Any,
    checks: Sequence[Check] | None = None,
    *,
    categories: Iterable[str] | None = None,
    options: Mapping[str, Any] | None = None,
    registry: LiveRegistry | None = None,
    on_result: Callable[[CheckResult], None] | None = None,
) -> Report:
    _ensure_atexit()
    selected = list(checks) if checks is not None else select_checks(categories)
    report = Report(provider=getattr(provider, "name", type(provider).__name__), started_at=_now())
    try:
        for check in selected:
            result = run_one(provider, check, options=options, registry=registry)
            report.results.append(result)
            if on_result:
                on_result(result)
    finally:
        report.finished_at = _now()
    return report


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def render_markdown(report: Report, *, include_evidence: bool = True) -> str:
    order = [c for c in CATEGORIES if any(r.category == c for r in report.results)]
    order += [c for c in dict.fromkeys(r.category for r in report.results) if c not in order]
    statuses = list(Status)
    lines = [
        f"# Sandbox conformance report: `{report.provider}`",
        "",
        f"Started {report.started_at} · finished {report.finished_at}",
        "",
        "## Matrix",
        "",
        "| Category | " + " | ".join(s.value for s in statuses) + " |",
        "|---|" + "---|" * len(statuses),
    ]
    for category in order:
        counts = [sum(1 for r in report.results if r.category == category and r.status == s) for s in statuses]
        lines.append(f"| {category} | " + " | ".join(str(n) for n in counts) + " |")
    totals = report.summary()
    lines.append("| **total** | " + " | ".join(f"**{totals[s.value]}**" for s in statuses) + " |")
    lines += ["", "## Results", "", "| Check | Category | Status | Details |", "|---|---|---|---|"]
    for r in report.results:
        lines.append(f"| `{r.id}` | {r.category} | {ICONS[r.status]} {r.status.value} | {_cell(r.message or r.description)} |")
    if include_evidence:
        lines += ["", "## Evidence", ""]
        for r in report.results:
            if not r.evidence:
                continue
            lines += [f"<details><summary><code>{r.id}</code> — {r.status.value}</summary>", "", "```text"]
            for ev in r.evidence:
                if ev.note:
                    lines.append(f"# {ev.note}")
                    continue
                lines.append(f"$ {ev.command}  (exit {ev.exit_code})")
                for stream in (ev.stdout, ev.stderr):
                    if stream:
                        lines.append(stream.rstrip("\n").replace("```", "'''"))
            lines += ["```", "", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
