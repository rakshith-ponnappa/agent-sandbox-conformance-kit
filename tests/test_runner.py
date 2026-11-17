from __future__ import annotations

import pytest

from sandbox_conformance import runner
from sandbox_conformance.checks import CHECKS_BY_ID, Check
from sandbox_conformance.providers import FakeProvider
from sandbox_conformance.runner import LiveRegistry, Status, run_checks, run_one


def _check(fn, check_id: str = "custom.probe") -> Check:
    return Check(check_id, "custom", "test-only check", fn)


def test_conformant_fake_passes_all_mandatory_checks_and_skips_optional():
    report = run_checks(FakeProvider(), registry=LiveRegistry())
    problems = [(r.id, r.status, r.message) for r in report.results if r.category != "optional" and r.status != Status.PASS]
    assert problems == []
    by_id = {r.id: r for r in report.results}
    assert by_id["optional.pty"].status == Status.SKIP
    assert by_id["optional.git-clone"].status == Status.SKIP
    assert report.ok


def test_full_profile_runs_optional_checks():
    report = run_checks(FakeProvider(profile="full"), categories=["optional"], registry=LiveRegistry())
    assert [r.status for r in report.results] == [Status.PASS, Status.PASS]


@pytest.mark.parametrize(
    ("override", "check_id"),
    [
        ({"egress_leaks_under_deny": True}, "network.deny-all-egress"),
        ({"allowlist_ignored": True}, "network.allowlist"),
        ({"metadata_reachable": True}, "network.metadata-unreachable"),
        ({"dns_resolves_under_deny": True}, "network.dns-under-deny"),
        ({"env_in_ps": True}, "secrets.env-not-in-ps"),
        ({"env_in_logs": True}, "secrets.env-not-in-logs"),
        ({"binary_safe": False}, "filesystem.binary-roundtrip"),
        ({"snapshot_restores": False}, "snapshot.restore-integrity"),
        ({"leak_on_kill": True}, "lifecycle.no-leftovers"),
    ],
)
def test_misbehaving_fake_fails_matching_check(override, check_id):
    result = run_one(FakeProvider(**override), CHECKS_BY_ID[check_id], registry=LiveRegistry())
    assert result.status == Status.FAIL, result.message


def test_leaked_secret_is_redacted_from_evidence():
    result = run_one(FakeProvider(env_in_ps=True), CHECKS_BY_ID["secrets.env-not-in-ps"], registry=LiveRegistry())
    assert result.status == Status.FAIL
    dumped = repr(result.evidence) + result.message
    assert "[REDACTED]" in dumped
    assert "scc-canary-" not in dumped


def test_unsupported_features_are_skipped():
    provider = FakeProvider(snapshot_supported=False, allowlist_supported=False, logs_supported=False)
    report = run_checks(provider, categories=["snapshot", "network", "secrets"], registry=LiveRegistry())
    by_id = {r.id: r.status for r in report.results}
    assert by_id["snapshot.restore-integrity"] == Status.SKIP
    assert by_id["network.allowlist"] == Status.SKIP
    assert by_id["secrets.env-not-in-logs"] == Status.SKIP
    assert by_id["network.deny-all-egress"] == Status.PASS
    assert report.ok


def test_inconclusive_probe_skips_instead_of_passing():
    provider = FakeProvider()
    original = provider.create

    def create_without_python(**kwargs):
        sandbox = original(**kwargs)
        sandbox.run = lambda cmd, timeout=None: (127, "", "sh: python3: not found\n")
        return sandbox

    provider.create = create_without_python
    result = run_one(provider, CHECKS_BY_ID["network.deny-all-egress"], registry=LiveRegistry())
    assert result.status == Status.SKIP


def test_unexpected_exception_is_error():
    def broken(ctx):
        raise RuntimeError("adapter exploded")

    result = run_one(FakeProvider(), _check(broken), registry=LiveRegistry())
    assert result.status == Status.ERROR
    assert "adapter exploded" in result.message


def test_quota_check_tolerates_clean_refusals_and_tears_everything_down():
    provider = FakeProvider(max_concurrent=2)
    result = run_one(provider, CHECKS_BY_ID["quota.parallel-teardown"], options={"parallel": 5}, registry=LiveRegistry())
    assert result.status == Status.PASS, result.message
    assert provider.list_active() == []
    assert sum("QuotaExceeded" in ev.note for ev in result.evidence) == 3


# --- guaranteed cleanup -----------------------------------------------------


def test_sandboxes_killed_when_check_raises():
    provider, registry = FakeProvider(), LiveRegistry()

    def boom(ctx):
        ctx.create()
        ctx.create(network_policy="open")
        raise RuntimeError("boom")

    result = run_one(provider, _check(boom), registry=registry)
    assert result.status == Status.ERROR
    assert provider.list_active() == []
    assert len(provider.created) == 2 and all(sb.killed for sb in provider.created)
    assert len(registry) == 0


def test_sandboxes_killed_when_check_fails():
    provider = FakeProvider()

    def failing(ctx):
        ctx.create()
        ctx.require(False, "nope")

    result = run_one(provider, _check(failing), registry=LiveRegistry())
    assert result.status == Status.FAIL and result.message == "nope"
    assert provider.list_active() == []


def test_cleanup_runs_on_keyboard_interrupt():
    provider, registry = FakeProvider(), LiveRegistry()

    def interrupted(ctx):
        ctx.create()
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_one(provider, _check(interrupted), registry=registry)
    assert provider.list_active() == []
    assert len(registry) == 0


def test_failed_teardown_is_reported_and_retried_by_registry():
    provider, registry = FakeProvider(kill_raises=True), LiveRegistry()
    result = run_one(provider, _check(lambda ctx: ctx.create()), registry=registry)
    assert result.status == Status.ERROR
    assert "cleanup failed" in result.message
    assert len(registry) == 1

    provider.behaviour.kill_raises = False
    assert registry.drain() == 1
    assert provider.list_active() == []


def test_atexit_drain_is_registered(monkeypatch):
    registered = []
    monkeypatch.setattr(runner.atexit, "register", registered.append)
    monkeypatch.setattr(runner, "_ATEXIT_REGISTERED", False)
    run_checks(FakeProvider(), [_check(lambda ctx: None)], registry=LiveRegistry())
    assert registered == [runner.LIVE.drain]
