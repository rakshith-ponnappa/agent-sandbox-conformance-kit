from __future__ import annotations

import json

from sandbox_conformance.checks.base import CheckContext, Evidence
from sandbox_conformance.providers import FakeProvider
from sandbox_conformance.runner import CheckResult, LiveRegistry, Report, Status, render_json, render_markdown


def _report() -> Report:
    return Report(
        provider="fake",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        results=[
            CheckResult("lifecycle.create-run", "lifecycle", "create", Status.PASS),
            CheckResult(
                "network.metadata-unreachable",
                "network",
                "metadata",
                Status.FAIL,
                message="reachable | via\nbridge",
                evidence=[Evidence("tcp-probe 169.254.169.254:80", 0, stdout="CONNECTED\n")],
            ),
            CheckResult("network.allowlist", "network", "allowlist", Status.SKIP, message="unsupported"),
            CheckResult("quota.parallel-teardown", "quota", "quota", Status.ERROR, message="boom"),
        ],
    )


def test_markdown_matrix_counts_per_category():
    md = render_markdown(_report())
    assert "| Category | PASS | FAIL | SKIP | ERROR |" in md
    assert "| lifecycle | 1 | 0 | 0 | 0 |" in md
    assert "| network | 0 | 1 | 1 | 0 |" in md
    assert "| quota | 0 | 0 | 0 | 1 |" in md
    assert "| **total** | **1** | **1** | **1** | **1** |" in md
    assert md.index("| lifecycle |") < md.index("| network |") < md.index("| quota |")


def test_markdown_escapes_cells_and_includes_evidence():
    md = render_markdown(_report())
    assert "reachable \\| via<br>bridge" in md
    assert "$ tcp-probe 169.254.169.254:80  (exit 0)" in md
    assert "CONNECTED" in md
    assert "Evidence" not in render_markdown(_report(), include_evidence=False)


def test_json_report_round_trips():
    data = json.loads(render_json(_report()))
    assert data["provider"] == "fake"
    assert data["summary"] == {"PASS": 1, "FAIL": 1, "SKIP": 1, "ERROR": 1}
    assert [r["status"] for r in data["results"]] == ["PASS", "FAIL", "SKIP", "ERROR"]
    assert data["results"][1]["evidence"][0] == {
        "command": "tcp-probe 169.254.169.254:80",
        "exit_code": 0,
        "stdout": "CONNECTED\n",
        "stderr": "",
        "note": "",
    }


def test_evidence_output_is_truncated():
    ctx = CheckContext(FakeProvider(), registry=LiveRegistry())
    sandbox = ctx.create()
    ctx.run(sandbox, "echo " + "x" * 5000)
    ctx.cleanup()
    stdout = ctx.evidence[-1].stdout
    assert len(stdout) < 2100
    assert stdout.endswith("[truncated 3001 chars]")
