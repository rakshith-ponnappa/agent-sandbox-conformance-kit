"""Reference adapter that drives a local Docker engine through the ``docker`` CLI.

Mapping:
    create            -> docker run -d --network none|bridge ... sleep <timeout>
    run               -> docker exec <id> sh -c <cmd>
    write/read_file   -> docker cp (tar stream over stdin/stdout, binary safe)
    snapshot/restore  -> docker commit / docker run from the committed image
    kill              -> docker rm -f (+ docker rmi for snapshot images)

Plain Docker has no hostname allowlist, so ``allowlist`` raises
UnsupportedFeature (put an egress proxy in front of it to add one).
Secret env values are never placed on the docker command line: we pass
``-e NAME`` and hand the value to the docker CLI through its own environment.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import time
import uuid
from typing import Callable, Mapping, Sequence

from ..provider import SandboxError, UnsupportedFeature, validate_mode

Executor = Callable[..., tuple[int, bytes, bytes]]
LABEL = "sandbox-conformance"
DEFAULT_IMAGE = "python:3.12-slim"


def subprocess_executor(
    argv: Sequence[str],
    input: bytes | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> tuple[int, bytes, bytes]:
    try:
        proc = subprocess.run(
            list(argv), input=input, capture_output=True, env=dict(env) if env else None, timeout=timeout
        )
    except FileNotFoundError as exc:
        raise SandboxError(f"{argv[0]!r} not found - is the Docker CLI installed?") from exc
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or b"", (exc.stderr or b"") + b"\n[timed out]\n"
    return proc.returncode, proc.stdout, proc.stderr


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


class DockerSandbox:
    def __init__(
        self,
        provider: "LocalDockerProvider",
        image: str,
        network_policy: str,
        env: Mapping[str, str],
        timeout: float,
    ) -> None:
        self.id = ""
        self.image = image
        self.mode = network_policy
        self.env = dict(env)
        self.timeout = timeout
        self.killed = False
        self._p = provider
        self._images: list[str] = []

    def _docker(self, *args: str, **kwargs: object) -> tuple[int, bytes, bytes]:
        return self._p.docker(*args, **kwargs)

    def _start(self, image: str) -> None:
        argv = [
            "run", "-d", "--rm",
            "--label", f"{LABEL}=1",
            "--label", f"{LABEL}.session={self._p.session}",
            "--network", "none" if self.mode == "deny-all" else "bridge",
            "--pids-limit", "256",
            "--memory", "512m",
            "--security-opt", "no-new-privileges",
        ]
        for name in self.env:
            argv += ["-e", name]
        argv += [image, "sleep", str(int(self.timeout))]
        code, out, err = self._docker(*argv, env={**os.environ, **self.env})
        if code != 0:
            raise SandboxError(f"docker run failed: {_text(err).strip()}")
        self.id = _text(out).strip()

    def run(self, cmd: str, timeout: float | None = None) -> tuple[int, str, str]:
        code, out, err = self._docker("exec", self.id, "sh", "-c", cmd, timeout=timeout or self.timeout)
        return code, _text(out), _text(err)

    def run_pty(self, cmd: str, timeout: float | None = None) -> tuple[int, str]:
        code, out, err = self._docker("exec", "-t", self.id, "sh", "-c", cmd, timeout=timeout or self.timeout)
        return code, _text(out + err)

    def write_file(self, path: str, data: bytes) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size = len(data)
            info.mode = 0o644
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
        code, _, err = self._docker("cp", "-", f"{self.id}:/", input=buf.getvalue())
        if code != 0:
            raise SandboxError(f"docker cp (write {path}) failed: {_text(err).strip()}")

    def read_file(self, path: str) -> bytes:
        code, out, err = self._docker("cp", f"{self.id}:{path}", "-")
        if code != 0:
            message = _text(err).strip()
            if "could not find" in message.lower() or "no such" in message.lower():
                raise FileNotFoundError(path)
            raise SandboxError(f"docker cp (read {path}) failed: {message}")
        with tarfile.open(fileobj=io.BytesIO(out)) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    handle = tar.extractfile(member)
                    return handle.read() if handle else b""
        raise FileNotFoundError(path)

    def snapshot(self) -> str:
        code, out, err = self._docker("commit", "--change", f"LABEL {LABEL}.snapshot=1", self.id)
        if code != 0:
            raise SandboxError(f"docker commit failed: {_text(err).strip()}")
        image = _text(out).strip()
        self._images.append(image)
        return image

    def restore(self, snapshot_id: str) -> None:
        if snapshot_id not in self._images:
            raise SandboxError(f"unknown snapshot {snapshot_id}")
        self._docker("rm", "-f", self.id)
        self._start(snapshot_id)

    def _networks(self) -> list[str]:
        code, out, _ = self._docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", self.id)
        if code != 0:
            return []
        return sorted(json.loads(_text(out) or "{}") or {})

    def set_network_policy(self, mode: str, allow: Sequence[str] | None = None) -> None:
        validate_mode(mode)
        if mode == "allowlist":
            raise UnsupportedFeature("plain Docker has no egress allowlist; front it with an egress proxy")
        current = self._networks()
        if mode == "deny-all":
            for net in current:
                if net != "none":
                    self._docker("network", "disconnect", "-f", net, self.id)
        else:
            if "none" in current:
                self._docker("network", "disconnect", "none", self.id)
            if "bridge" not in current:
                code, _, err = self._docker("network", "connect", "bridge", self.id)
                if code != 0:
                    raise SandboxError(f"docker network connect failed: {_text(err).strip()}")
        self.mode = mode

    def logs(self) -> str:
        code, out, err = self._docker("logs", self.id)
        if code != 0:
            raise SandboxError(f"docker logs failed: {_text(err).strip()}")
        return _text(out + err)

    def kill(self) -> None:
        errors: list[str] = []
        if self.id:
            code, _, err = self._docker("rm", "-f", self.id)
            if code != 0 and b"no such container" not in err.lower():
                errors.append(_text(err).strip())
        while self._images:
            self._docker("rmi", "-f", self._images.pop())
        self.killed = True
        if errors:
            raise SandboxError("; ".join(errors))


class LocalDockerProvider:
    name = "local-docker"

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        docker_bin: str = "docker",
        executor: Executor | None = None,
    ) -> None:
        self.image = image
        self.docker_bin = docker_bin
        self.session = uuid.uuid4().hex[:12]
        self._exec = executor or subprocess_executor

    def docker(
        self,
        *args: str,
        input: bytes | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = 120.0,
    ) -> tuple[int, bytes, bytes]:
        return self._exec([self.docker_bin, *args], input=input, env=env, timeout=timeout)

    def create(
        self,
        template: str | None = None,
        network_policy: str = "deny-all",
        env: Mapping[str, str] | None = None,
        timeout: float = 300.0,
    ) -> DockerSandbox:
        validate_mode(network_policy)
        if network_policy == "allowlist":
            raise UnsupportedFeature("plain Docker has no egress allowlist; front it with an egress proxy")
        sandbox = DockerSandbox(self, template or self.image, network_policy, env or {}, timeout)
        sandbox._start(sandbox.image)
        return sandbox

    def list_active(self) -> list[str]:
        code, out, _ = self.docker(
            "ps", "-aq", "--no-trunc", "--filter", f"label={LABEL}.session={self.session}"
        )
        if code != 0:
            return []
        return sorted(line for line in _text(out).split() if line)
