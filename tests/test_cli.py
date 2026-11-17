from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sandbox_conformance.__main__ import main
from sandbox_conformance.checks import ALL_CHECKS

ROOT = Path(__file__).resolve().parents[1]


def test_list_prints_full_catalogue(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    for check in ALL_CHECKS:
        assert check.id in out
        assert check.description in out


def test_list_via_python_dash_m():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "sandbox_conformance", "list"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    assert "network.metadata-unreachable" in proc.stdout


def test_run_writes_json_and_markdown(tmp_path, capsys):
    json_path, md_path = tmp_path / "out.json", tmp_path / "out.md"
    code = main(["run", "--provider", "fake", "--only", "network,secrets", "--json", str(json_path), "--md", str(md_path)])
    assert code == 0
    data = json.loads(json_path.read_text())
    assert {r["category"] for r in data["results"]} == {"network", "secrets"}
    assert "| network | 4 | 0 | 0 | 0 |" in md_path.read_text()
    assert "PASS" in capsys.readouterr().out


def test_run_exits_nonzero_on_failures():
    assert main(["run", "--provider", "fake", "--fake-profile", "leaky", "--only", "network"]) == 1


def test_unknown_category_is_rejected():
    with pytest.raises(SystemExit):
        main(["run", "--provider", "fake", "--only", "nonexistent"])
