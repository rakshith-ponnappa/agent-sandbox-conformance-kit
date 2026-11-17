from __future__ import annotations

from .base import Check, CheckContext


def create_run(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    code, out, _ = ctx.run(sandbox, "echo conformance-ok")
    ctx.require(code == 0 and "conformance-ok" in out, f"echo returned code={code} stdout={out!r}")
    code, _, _ = ctx.run(sandbox, "exit 3")
    ctx.require(code == 3, f"exit code not propagated: expected 3, got {code}")


def kill_stops_execution(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    ctx.run(sandbox, "echo alive")
    sandbox.kill()
    ctx.note(f"killed sandbox {sandbox.id}")
    try:
        code, out, _ = ctx.run(sandbox, "echo still-alive")
    except Exception as exc:
        ctx.note(f"run() after kill() raised {type(exc).__name__}: {exc}")
        return
    ctx.require(not (code == 0 and "still-alive" in out), "sandbox still executes commands after kill()")


def no_leftovers(ctx: CheckContext) -> None:
    list_active = getattr(ctx.provider, "list_active", None)
    if list_active is None:
        ctx.skip("provider does not implement list_active()")
    before = set(list_active())
    sandboxes = [ctx.create() for _ in range(2)]
    for sandbox in sandboxes:
        sandbox.kill()
    leftovers = sorted(set(list_active()) - before)
    ctx.note(f"active before={len(before)} leftovers after kill={leftovers}")
    ctx.require(not leftovers, f"sandboxes still active after kill(): {leftovers}")


CHECKS = [
    Check("lifecycle.create-run", "lifecycle", "Create a sandbox, run a command, exit codes propagate", create_run),
    Check("lifecycle.kill", "lifecycle", "kill() stops command execution", kill_stops_execution),
    Check("lifecycle.no-leftovers", "lifecycle", "Teardown leaves no running sandboxes behind", no_leftovers),
]
