"""Checks that need PowerShell 7: PSScriptAnalyzer, the Pester suite, fixture freshness, and the real scripts as processes.

They skip when no ``pwsh`` is available. ``scripts/fetch_pwsh.sh`` puts a pinned PowerShell and
the two modules under ``tools/`` (ignored by git), which is where these tests look first; set
``WF_PWSH`` and ``WF_PSMODULES`` to use another copy. PowerShell 7 is only the test host: the
collectors target Windows PowerShell 5.1, and nothing here proves behaviour on Windows.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import verify_bundle
import wf_schema
from conftest import REPO_ROOT

COLLECTOR_DIR = REPO_ROOT / "collectors" / "windows"
TESTS_DIR = COLLECTOR_DIR / "tests"
FIXTURES = REPO_ROOT / "fixtures" / "collector-bundles"


def find_pwsh() -> str | None:
    candidates = [os.environ.get("WF_PWSH"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh"), shutil.which("pwsh")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


PWSH = find_pwsh()
MODULES = os.environ.get("WF_PSMODULES") or str(REPO_ROOT / "tools" / "psmodules")
pytestmark = pytest.mark.skipif(PWSH is None, reason="no pwsh; run scripts/fetch_pwsh.sh or set WF_PWSH")


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, NO_COLOR="1")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)


def test_script_analyzer_and_pester_suite_pass():
    args = ["-File", str(TESTS_DIR / "Invoke-Checks.ps1")]
    if Path(MODULES).is_dir():
        args += ["-ModulePath", MODULES]
    result = run(args)
    if result.returncode == 3:
        pytest.skip("Pester 5 or PSScriptAnalyzer is not installed; run scripts/fetch_pwsh.sh")
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr[-3000:]
    assert "PSScriptAnalyzer: 0 findings" in result.stderr
    assert "Failed: 0" in result.stdout


def normalised(path: Path):
    """JSON compares by value, everything else by bytes."""
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return path.read_bytes()


def test_committed_fixture_bundles_match_a_fresh_run(tmp_path):
    result = run(["-File", str(TESTS_DIR / "New-FixtureBundles.ps1")], cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == "", "the generator keeps collector output off its own stdout"
    fresh = tmp_path / "fixtures" / "collector-bundles"
    committed_files = sorted(p.relative_to(FIXTURES).as_posix() for p in FIXTURES.rglob("*") if p.is_file())
    fresh_files = sorted(p.relative_to(fresh).as_posix() for p in fresh.rglob("*") if p.is_file())
    assert fresh_files == committed_files, "regenerate with collectors/windows/tests/New-FixtureBundles.ps1"
    stale = [f for f in committed_files if normalised(FIXTURES / f) != normalised(fresh / f)]
    assert not stale, f"stale fixtures, regenerate with collectors/windows/tests/New-FixtureBundles.ps1: {stale}"


@pytest.mark.parametrize("collector", sorted(p.stem for p in COLLECTOR_DIR.glob("*.ps1") if p.name != "_common.ps1"))
def test_collector_without_an_output_directory_prints_one_failed_line(collector):
    result = run(["-File", str(COLLECTOR_DIR / f"{collector}.ps1")])
    assert result.returncode == 1
    assert result.stdout.count("\n") == 1
    assert json.loads(result.stdout) == {"collector": collector, "status": "failed", "bundle": "", "artifacts": 0}
    assert "-OutputDirectory is required" in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="on Windows the real adapters would read the machine")
@pytest.mark.parametrize("collector", ["bugcheck-history", "reliability-records"])
def test_real_adapters_fail_closed_off_windows(collector, tmp_path):
    """Run the unmodified script as a process where no Windows API exists.

    Every source fails, and the collector must still honour the seam: one JSON line, exit 1, a
    schema valid manifest that records the failure as a status, and no export that could be
    read as an empty result.
    """
    out = tmp_path / "bundle dir"
    result = run(["-File", str(COLLECTOR_DIR / f"{collector}.ps1"), "-OutputDirectory", str(out)])
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout.count("\n") == 1
    summary = json.loads(result.stdout)
    assert summary["collector"] == collector and summary["status"] == "failed" and summary["bundle"] == str(out)
    verified = verify_bundle.verify(out)
    assert verified["ok"], verified["checks"]
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(manifest, "manifest.schema.json") == []
    assert summary["artifacts"] == sum(len(c["artifacts"]) for c in manifest["collectors"])
    for source in manifest["collectors"]:
        assert source["status"] in ("not_collected", "capture_failed", "unsupported") and source["status_reason"]
        assert [a for a in source["artifacts"] if a["role"] == "primary"] == []
    # The inventory of what ran is real here: both script files are hashed.
    tools = {t["name"]: t for t in manifest["tools"]}
    assert tools[f"collector:{collector}"]["sha256"] == wf_schema.sha256_of(COLLECTOR_DIR / f"{collector}.ps1")
    assert tools["collector-helper:_common.ps1"]["sha256"] == wf_schema.sha256_of(COLLECTOR_DIR / "_common.ps1")
    # Nothing was written next to the bundle.
    assert [p.name for p in tmp_path.iterdir()] == ["bundle dir"]
