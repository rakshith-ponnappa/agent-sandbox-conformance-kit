from __future__ import annotations

from .base import Check, CheckContext
from .probes import GIT_CLONE_PROBE


def pty(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    run_pty = getattr(sandbox, "run_pty", None)
    if run_pty is None:
        ctx.skip("sandbox does not implement run_pty()")
    command = "test -t 1 && echo TTY || echo NOTTY"
    code, out = run_pty(command)
    ctx.record(f"[pty] {command}", code, out)
    ctx.require(code == 0 and "NOTTY" not in out and "TTY" in out, "stdout is not a terminal under run_pty()")


def git_clone(ctx: CheckContext) -> None:
    sandbox = ctx.create()
    code, out, _ = ctx.run(sandbox, GIT_CLONE_PROBE, label="git init + git clone (local, no network)")
    if code == 127:
        ctx.skip("git is not available in the sandbox template")
    ctx.require(code == 0 and "CLONED" in out, f"git clone failed with exit code {code}")


CHECKS = [
    Check("optional.pty", "optional", "Commands can run attached to a PTY", pty),
    Check("optional.git-clone", "optional", "git is available and can clone a repository", git_clone),
]
