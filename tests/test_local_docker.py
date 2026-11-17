"""Command construction for the docker adapter, without a docker engine."""

from __future__ import annotations

import pytest

from sandbox_conformance.provider import UnsupportedFeature
from sandbox_conformance.providers import LocalDockerProvider


class FakeDockerCLI:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict | None]] = []
        self.archive = b""

    def __call__(self, argv, input=None, env=None, timeout=None):
        self.calls.append((list(argv), env))
        if argv[1] == "run":
            return 0, b"c0ffee\n", b""
        if argv[1:3] == ["cp", "-"]:
            self.archive = input
            return 0, b"", b""
        if argv[1] == "cp":
            return 0, self.archive, b""
        return 0, b"", b""


def test_create_uses_network_none_and_keeps_secret_values_off_argv():
    cli = FakeDockerCLI()
    sandbox = LocalDockerProvider(executor=cli).create(env={"API_TOKEN": "value-not-on-argv"})
    argv, env = cli.calls[0]
    assert argv[:3] == ["docker", "run", "-d"]
    assert argv[argv.index("--network") + 1] == "none"
    assert "value-not-on-argv" not in " ".join(argv)
    assert argv[argv.index("-e") + 1] == "API_TOKEN"
    assert env["API_TOKEN"] == "value-not-on-argv"

    sandbox.run("echo hi")
    assert cli.calls[-1][0] == ["docker", "exec", "c0ffee", "sh", "-c", "echo hi"]
    sandbox.kill()
    assert cli.calls[-1][0] == ["docker", "rm", "-f", "c0ffee"]


def test_open_policy_uses_bridge_and_allowlist_is_unsupported():
    cli = FakeDockerCLI()
    provider = LocalDockerProvider(executor=cli)
    provider.create(network_policy="open")
    argv = cli.calls[0][0]
    assert argv[argv.index("--network") + 1] == "bridge"
    with pytest.raises(UnsupportedFeature):
        provider.create(network_policy="allowlist")


def test_file_transfer_is_binary_safe_tar_over_docker_cp():
    cli = FakeDockerCLI()
    sandbox = LocalDockerProvider(executor=cli).create()
    payload = bytes(range(256)) * 4
    sandbox.write_file("/sandbox-conformance/blob.bin", payload)
    assert cli.calls[-1][0] == ["docker", "cp", "-", "c0ffee:/"]
    assert sandbox.read_file("/sandbox-conformance/blob.bin") == payload
    assert cli.calls[-1][0] == ["docker", "cp", "c0ffee:/sandbox-conformance/blob.bin", "-"]
