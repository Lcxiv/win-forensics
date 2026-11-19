"""The change area: scripts that change the gaming PC live apart from everything that reads it.

changes/windows/ holds one self contained script per change, run only by the captain at the PC.
Nothing the dispatcher, the scenario runner or a collector does may call one, so no file under
collectors/ or remote-access/ names the area. The Pester suite under changes/windows/tests runs
every verb against synthetic backends; it skips without pwsh, like tests/test_collectors_pwsh.py.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT

CHANGES = REPO_ROOT / "changes" / "windows"
# Everything that reads the PC or runs on it: the collectors (with their tests, fixtures and
# README and the scenario runner), the SSH front door, and the Mac side scripts.
READERS = [REPO_ROOT / "collectors", REPO_ROOT / "remote-access", REPO_ROOT / "scripts"]
# Anything that would let a reader find or start a change script: the folder name in either
# separator style, and the script's own name.
REFERENCE = re.compile(r"changes[\\/]|session-bracket-task", re.IGNORECASE)


def reader_files() -> list[Path]:
    out: list[Path] = []
    for root in READERS:
        out += [p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts
                and p.suffix in (".ps1", ".psm1", ".psd1", ".cmd", ".sh", ".py", ".json", ".jsonl", ".md", ".txt", ".csv", ".xml")]
    return out


def test_readers_never_reference_the_change_area():
    offenders = []
    for path in reader_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), start=1):
            if REFERENCE.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not offenders, offenders


def test_the_reference_guard_catches_both_spellings():
    for line in ("& (Join-Path $root 'changes\\windows\\x.ps1')", "source changes/windows/x.ps1", "session-bracket-task.ps1 -Apply"):
        assert REFERENCE.search(line), line
    assert not REFERENCE.search("records the changes in the manifest")


@pytest.mark.parametrize("path", sorted(CHANGES.rglob("*.ps1")), ids=lambda p: p.name)
def test_change_scripts_are_plain_ascii(path):
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    offenders = [i for i, b in enumerate(data) if b > 126 or (b < 32 and b not in (9, 10))]
    assert not offenders, f"{path.name}: byte offsets {offenders[:5]}"


@pytest.mark.parametrize("path", sorted(CHANGES.glob("*.ps1")), ids=lambda p: p.name)
def test_each_change_script_has_the_four_verbs_and_a_readme_entry(path):
    text = path.read_text(encoding="ascii")
    for verb in ("Plan", "Apply", "Undo", "Readback"):
        assert re.search(rf"\[switch\]\${verb}\b", text), verb
    assert "Read-Host" not in text and "Get-Credential" not in text, "a change script never prompts"
    assert "if ($MyInvocation.InvocationName -ne '.')" in text, "the tests dot source the script without running it"
    readme = (CHANGES / "README.md").read_text(encoding="utf-8")
    assert f"`{path.name}`" in readme, path.name
    assert (CHANGES / "tests" / "SessionBracketTask.Tests.ps1").is_file()


def test_the_logon_task_runs_only_the_read_only_baseline():
    text = (CHANGES / "session-bracket-task.ps1").read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "collectors\\windows\\session-bracket.ps1" in code and "-Phase baseline -ToEvidenceFolder" in code
    assert "-LogonType Interactive -RunLevel Limited" in code
    assert "Highest" not in code and "-Password" not in code and "S4U" not in code
    # Exactly one task: one Register- and one Unregister- call, both with the fixed name.
    assert code.count("Register-ScheduledTask ") == 1 and code.count("Unregister-ScheduledTask ") == 1


def find_pwsh() -> str | None:
    for candidate in (os.environ.get("WF_PWSH"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh"), shutil.which("pwsh")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


@pytest.mark.skipif(find_pwsh() is None, reason="no pwsh; run scripts/fetch_pwsh.sh or set WF_PWSH")
def test_change_script_analyzer_and_pester_suite_pass():
    modules = os.environ.get("WF_PSMODULES") or str(REPO_ROOT / "tools" / "psmodules")
    result = subprocess.run([find_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(CHANGES / "tests" / "Invoke-Checks.ps1"), "-ModulePath", modules],
                            env=dict(os.environ, NO_COLOR="1"), capture_output=True, text=True, timeout=900)
    if result.returncode == 3:
        pytest.skip("Pester 5 and PSScriptAnalyzer are not installed: " + result.stderr.strip())
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    assert "PSScriptAnalyzer: 0 findings" in result.stderr
    assert "Failed: 0" in result.stdout
