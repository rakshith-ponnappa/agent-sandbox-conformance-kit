from __future__ import annotations

import uuid

from .base import Check, CheckContext
from .probes import PS_PROBE

SECRET_VAR = "CONFORMANCE_SECRET"


def _sandbox_with_secret(ctx: CheckContext):
    token = ctx.secret(f"scc-canary-{uuid.uuid4().hex}")
    sandbox = ctx.create(env={SECRET_VAR: token})
    code, _, _ = ctx.run(sandbox, f'test -n "${SECRET_VAR}"')
    ctx.require(code == 0, f"env passed to create() is not visible inside the sandbox (${SECRET_VAR} empty)")
    return sandbox, token


def env_not_in_ps(ctx: CheckContext) -> None:
    sandbox, token = _sandbox_with_secret(ctx)
    code, out, _ = ctx.run(sandbox, PS_PROBE, label="ps auxww (or /proc/*/cmdline)")
    if code != 0 and not out:
        ctx.skip("neither ps nor /proc is available in the sandbox")
    ctx.require(token not in out, "env secret visible in process listing (passed as a command-line argument?)")


def env_not_in_logs(ctx: CheckContext) -> None:
    sandbox, token = _sandbox_with_secret(ctx)
    ctx.run(sandbox, "echo log-probe")
    logs = getattr(sandbox, "logs", None)
    if logs is None:
        ctx.skip("sandbox does not expose logs()")
    text = logs()
    ctx.record("sandbox.logs()", None, text)
    ctx.require(token not in text, "env secret appears in sandbox logs")


CHECKS = [
    Check("secrets.env-not-in-ps", "secrets", "Env secrets are absent from `ps` output inside the sandbox", env_not_in_ps),
    Check("secrets.env-not-in-logs", "secrets", "Env secrets are absent from sandbox logs", env_not_in_logs),
]
