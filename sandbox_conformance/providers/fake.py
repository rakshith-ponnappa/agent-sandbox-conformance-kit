"""In-memory fake provider with configurable (mis)behaviour.

The fake understands a tiny shell subset (``echo``, ``exit``, ``cat``, ``test``,
``mkdir``, ``true``, ``false``) plus the probe commands emitted by
``sandbox_conformance.checks.probes``, which carry a trailing ``# probe:<kind>``
marker. Flip fields on :class:`FakeBehaviour` to simulate a non-conformant
sandbox and confirm the matching check fails.
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
import re
import shlex
import threading
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..provider import QuotaExceeded, SandboxError, UnsupportedFeature, validate_mode

METADATA_IP = "169.254.169.254"
_PROBE = re.compile(r"#\s*probe:(?P<kind>[\w-]+)(?P<args>[^\n]*)$")


@dataclass
class FakeBehaviour:
    egress_leaks_under_deny: bool = False
    dns_resolves_under_deny: bool = False
    allowlist_supported: bool = True
    allowlist_ignored: bool = False
    metadata_reachable: bool = False
    env_in_ps: bool = False
    env_in_logs: bool = False
    binary_safe: bool = True
    snapshot_supported: bool = True
    snapshot_restores: bool = True
    leak_on_kill: bool = False
    kill_raises: bool = False
    max_concurrent: int | None = None
    logs_supported: bool = True
    pty_supported: bool = False
    git_available: bool = False


PROFILES: dict[str, FakeBehaviour] = {
    "conformant": FakeBehaviour(),
    "full": FakeBehaviour(pty_supported=True, git_available=True),
    "leaky": FakeBehaviour(
        metadata_reachable=True,
        dns_resolves_under_deny=True,
        env_in_ps=True,
        leak_on_kill=True,
    ),
}


class FakeSandbox:
    def __init__(
        self,
        provider: "FakeProvider",
        sandbox_id: str,
        template: str,
        network_policy: str,
        env: Mapping[str, str],
        timeout: float,
    ) -> None:
        self.id = sandbox_id
        self.template = template
        self.mode = network_policy
        self.allow: list[str] = []
        self.env = dict(env)
        self.timeout = timeout
        self.files: dict[str, bytes] = {}
        self.killed = False
        self._provider = provider
        self._snapshots: dict[str, dict[str, bytes]] = {}
        self._snap_ids = itertools.count(1)
        self._log = [f"boot template={template} policy={network_policy}"]
        if provider.behaviour.env_in_logs:
            self._log.append("env " + " ".join(f"{k}={v}" for k, v in self.env.items()))

    @property
    def behaviour(self) -> FakeBehaviour:
        return self._provider.behaviour

    def _alive(self) -> None:
        if self.killed:
            raise SandboxError(f"sandbox {self.id} has been killed")

    def run(self, cmd: str, timeout: float | None = None) -> tuple[int, str, str]:
        self._alive()
        self._provider.commands.append((self.id, cmd))
        code, out, err = self._interpret(cmd)
        self._log.append(f"exec exit={code}")
        return code, out, err

    def run_pty(self, cmd: str, timeout: float | None = None) -> tuple[int, str]:
        self._alive()
        if not self.behaviour.pty_supported:
            raise UnsupportedFeature("fake sandbox configured without PTY support")
        return 0, "TTY\r\n"

    def write_file(self, path: str, data: bytes) -> None:
        self._alive()
        if not self.behaviour.binary_safe:
            data = data.decode("utf-8", "replace").encode("utf-8")
        self.files[path] = bytes(data)

    def read_file(self, path: str) -> bytes:
        self._alive()
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def snapshot(self) -> str:
        self._alive()
        if not self.behaviour.snapshot_supported:
            raise UnsupportedFeature("fake sandbox configured without snapshots")
        snap_id = f"{self.id}-snap-{next(self._snap_ids)}"
        self._snapshots[snap_id] = copy.deepcopy(self.files)
        return snap_id

    def restore(self, snapshot_id: str) -> None:
        self._alive()
        if snapshot_id not in self._snapshots:
            raise SandboxError(f"unknown snapshot {snapshot_id}")
        if self.behaviour.snapshot_restores:
            self.files = copy.deepcopy(self._snapshots[snapshot_id])

    def set_network_policy(self, mode: str, allow: Sequence[str] | None = None) -> None:
        self._alive()
        validate_mode(mode)
        if mode == "allowlist" and not self.behaviour.allowlist_supported:
            raise UnsupportedFeature("fake sandbox configured without allowlists")
        self.mode = mode
        self.allow = list(allow or [])

    def logs(self) -> str:
        if not self.behaviour.logs_supported:
            raise UnsupportedFeature("fake sandbox configured without logs")
        return "\n".join(self._log) + "\n"

    def kill(self) -> None:
        if self.killed:
            return
        if self.behaviour.kill_raises:
            raise SandboxError("simulated teardown failure")
        self.killed = True
        if not self.behaviour.leak_on_kill:
            self._provider._forget(self.id)

    # --- tiny shell -------------------------------------------------------

    def _interpret(self, cmd: str) -> tuple[int, str, str]:
        match = _PROBE.search(cmd)
        if match:
            return self._probe(match["kind"], match["args"].split())
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return 2, "", "fake: unable to parse command\n"
        if not argv:
            return 0, "", ""
        prog, args = argv[0], argv[1:]
        if prog == "echo":
            return 0, " ".join(args) + "\n", ""
        if prog == "true" or prog == "mkdir":
            return 0, "", ""
        if prog == "false":
            return 1, "", ""
        if prog == "exit":
            return (int(args[0]) if args else 0), "", ""
        if prog == "cat":
            out = b""
            for path in args:
                if path not in self.files:
                    return 1, "", f"cat: {path}: No such file or directory\n"
                out += self.files[path]
            return 0, out.decode("utf-8", "replace"), ""
        if prog == "test" and len(args) == 2:
            flag, value = args
            if flag == "-e":
                return (0 if value in self.files else 1), "", ""
            if flag == "-n":
                if value.startswith("$"):
                    value = self.env.get(value[1:], "")
                return (0 if value else 1), "", ""
        return 127, "", f"fake: {prog}: command not found\n"

    def _egress_allowed(self, host: str) -> bool:
        if self.mode == "deny-all":
            return self.behaviour.egress_leaks_under_deny
        if host == METADATA_IP:
            return self.behaviour.metadata_reachable
        if self.mode == "allowlist":
            return self.behaviour.allowlist_ignored or host in self.allow
        return True

    def _probe(self, kind: str, args: list[str]) -> tuple[int, str, str]:
        if kind == "tcp":
            ok = self._egress_allowed(args[0])
            return 0, ("CONNECTED" if ok else "BLOCKED:TimeoutError") + "\n", ""
        if kind == "dns":
            ok = self._egress_allowed(args[0]) or (
                self.mode == "deny-all" and self.behaviour.dns_resolves_under_deny
            )
            return 0, ("RESOLVED" if ok else "UNRESOLVED:gaierror") + "\n", ""
        if kind == "ps":
            lines = ["PID COMMAND", f"1 sleep {int(self.timeout)}", "42 sh -c ps"]
            if self.behaviour.env_in_ps:
                lines.append("7 agent " + " ".join(f"--{k}={v}" for k, v in self.env.items()))
            return 0, "\n".join(lines) + "\n", ""
        if kind == "git-clone":
            if not self.behaviour.git_available:
                return 127, "", "fake: git: command not found\n"
            return 0, "CLONED\n", ""
        return 127, "", f"fake: unknown probe {kind}\n"


class FakeProvider:
    name = "fake"

    def __init__(
        self,
        behaviour: FakeBehaviour | None = None,
        *,
        profile: str | None = None,
        **overrides: object,
    ) -> None:
        if behaviour is None:
            behaviour = copy.deepcopy(PROFILES[profile or "conformant"])
        self.behaviour = dataclasses.replace(behaviour, **overrides) if overrides else behaviour
        self.created: list[FakeSandbox] = []
        self.commands: list[tuple[str, str]] = []
        self._live: dict[str, FakeSandbox] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def create(
        self,
        template: str | None = None,
        network_policy: str = "deny-all",
        env: Mapping[str, str] | None = None,
        timeout: float = 300.0,
    ) -> FakeSandbox:
        validate_mode(network_policy)
        if network_policy == "allowlist" and not self.behaviour.allowlist_supported:
            raise UnsupportedFeature("fake provider configured without allowlists")
        with self._lock:
            limit = self.behaviour.max_concurrent
            if limit is not None and len(self._live) >= limit:
                raise QuotaExceeded(f"concurrency limit of {limit} sandboxes reached")
            sandbox = FakeSandbox(
                self, f"fake-{next(self._ids)}", template or "default", network_policy, env or {}, timeout
            )
            self._live[sandbox.id] = sandbox
            self.created.append(sandbox)
        return sandbox

    def list_active(self) -> list[str]:
        with self._lock:
            return sorted(self._live)

    def _forget(self, sandbox_id: str) -> None:
        with self._lock:
            self._live.pop(sandbox_id, None)
