"""Checks on the change scripts that need PowerShell 7: PSScriptAnalyzer, the Pester suite, and the real entry scripts as processes.

They skip when no ``pwsh`` is available; ``scripts/fetch_pwsh.sh`` puts one and the two modules
under ``tools/``. PowerShell 7 off Windows is only the test host: the change scripts target
Windows PowerShell 5.1, and nothing here proves behaviour on Windows or touches a real registry
or adapter.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT

CHANGES_DIR = REPO_ROOT / "changes" / "windows"
TESTS_DIR = CHANGES_DIR / "tests"
ENTRY_SCRIPTS = sorted(p for p in CHANGES_DIR.glob("*.ps1") if not p.name.startswith("_"))
# Arguments each entry script needs besides the verb, so it fails only on what the test checks.
EXTRA_ARGS = {"gpu-affinity-1a.ps1": ["-StutterGuardDataDirectory", "{tmp}"]}
# kbd-crash-dump.ps1 keeps the reverse exit codes (1 refused, 2 failed after a change began; see
# AGENTS.md); tests/test_change_kbd_crash_dump.py and its Pester suite check its refusals instead.
STEP_EXIT_CODE_SCRIPTS = [p for p in ENTRY_SCRIPTS if p.name != "kbd-crash-dump.ps1"]


def extra_args(script: Path, tmp_path: Path) -> list[str]:
    return [a.replace("{tmp}", str(tmp_path)) for a in EXTRA_ARGS.get(script.name, [])]


def find_pwsh() -> str | None:
    for candidate in (os.environ.get("WF_PWSH"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh"), shutil.which("pwsh")):
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


@pytest.mark.parametrize("script", STEP_EXIT_CODE_SCRIPTS, ids=lambda p: p.name)
def test_two_verbs_are_refused_by_the_real_script(script, tmp_path):
    result = run(["-File", str(script), "-Apply", "-Undo", *extra_args(script, tmp_path), "-EvidenceRoot", str(tmp_path / "ev")])
    assert result.returncode == 2
    assert "name one verb" in result.stdout
    assert not (tmp_path / "ev").exists()


@pytest.mark.parametrize("script", STEP_EXIT_CODE_SCRIPTS, ids=lambda p: p.name)
def test_plan_off_windows_stops_without_writing(script, tmp_path):
    """Off Windows the adapters cannot run; Plan must stop with exit 2 and change nothing."""
    result = run(["-File", str(script), *extra_args(script, tmp_path), "-EvidenceRoot", str(tmp_path / "ev")])
    assert result.returncode == 2, result.stdout + result.stderr
    assert "STOPPED" in result.stdout
    assert not (tmp_path / "ev").exists()
