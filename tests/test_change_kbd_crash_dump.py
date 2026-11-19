"""Checks specific to ``changes/windows/kbd-crash-dump.ps1``.

The area rules (no reference from unattended code, ASCII, the forbidden command list) are in
``tests/test_changes_area.py``, and ``tests/test_changes_pwsh.py`` runs the analyzer and the whole
Pester suite. What the script writes is checked on its behaviour by ``KbdCrashDump.Tests.ps1``
against the synthetic registry (every write and export any test makes is recorded). This file keeps
the safety guards that hold even for code no test reaches, the operator page's required sections,
and the unmodified script run as a process off Windows, where every adapter fails and it must refuse
without writing anything.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from test_changes_area import code_lines

CHANGE_DIR = REPO_ROOT / "changes" / "windows"
SCRIPT = CHANGE_DIR / "kbd-crash-dump.ps1"
DOC = REPO_ROOT / "docs" / "changes" / "kbd-crash-dump.md"
LEARN_KBD = "https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard"

# The functions allowed to hold a registry write primitive: the three write adapters and the one
# that opens an existing parent key for them.
WRITERS = {"Set-KcdRegistryDword", "Remove-KcdRegistryValue", "Remove-KcdRegistryKey", "Open-KcdParentForWrite"}
REG_RUNNER = "Invoke-KcdRegExport"
WRITE_PRIMITIVE = re.compile(
    r"\.SetValue\(|\.DeleteValue\(|OpenSubKey\([^)]*,\s*(\$true|\[[^\]]*RegistryKeyPermissionCheck\]|\[[^\]]*RegistryRights\])"
    r"|CreateSubKey|DeleteSubKey|DeleteSubKeyTree|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|New-Item\s+[^\n]*HK"
    r"|\breg(\.exe)?['\"]?\s+(add|delete|import|copy|restore|load|unload)\b",
    re.IGNORECASE,
)
REG_EXE = re.compile(r"reg\.exe", re.IGNORECASE)
CALL_OPERATOR = re.compile(r"&\s*(\$\w+|'[^']*'|\"[^\"]*\")\s+'?([^\s')]+)")


def function_bodies(code: str) -> dict[str, str]:
    """Every function, including the indented adapters inside the guarded block, by name."""
    bodies: dict[str, str] = {}
    for header in re.finditer(r"^([ \t]*)function ([A-Za-z0-9\-]+) \{", code, re.MULTILINE):
        close = re.compile(r"^" + re.escape(header.group(1)) + r"\}[ \t]*$", re.MULTILINE).search(code, header.end())
        bodies[header.group(2)] = code[header.start():close.end() if close else len(code)]
    return bodies


def outermost(bodies: dict[str, str]) -> dict[str, str]:
    """The bodies with any nested function bodies removed, so a primitive is charged to the innermost function."""
    out = {}
    for name, body in bodies.items():
        own = body
        for other, inner in bodies.items():
            if other != name and inner in own and inner != own:
                own = own.replace(inner, "")
        out[name] = own
    return out


def write_offenders(code: str) -> list[str]:
    bodies = function_bodies(code)
    offenders = [name for name, body in outermost(bodies).items() if name not in WRITERS and WRITE_PRIMITIVE.search(body)]
    rest = code
    for body in bodies.values():
        rest = rest.replace(body, "")
    if WRITE_PRIMITIVE.search(rest):
        offenders.append("<top level>")
    return offenders


def reg_offenders(code: str) -> list[str]:
    offenders = []
    for name, body in outermost(function_bodies(code)).items():
        if name != REG_RUNNER and REG_EXE.search(body):
            offenders.append(name)
        if name == REG_RUNNER:
            offenders += [f"{name}: {verb}" for _, verb in CALL_OPERATOR.findall(body) if verb.lower() != "export"]
    return offenders


def test_registry_writes_happen_only_in_the_write_adapters():
    code = code_lines(SCRIPT)
    assert write_offenders(code) == []
    bodies = function_bodies(code)
    assert WRITERS <= set(bodies), WRITERS - set(bodies)


def test_reg_exe_only_ever_exports():
    code = code_lines(SCRIPT)
    assert reg_offenders(code) == []
    assert CALL_OPERATOR.findall(function_bodies(code)[REG_RUNNER]) != []


def test_the_guards_catch_what_they_are_for():
    planted = (
        "function Invoke-KcdApply {\n    $k.SetValue('x', 1)\n}\n"
        "if ($true) {\n    function Get-KcdRegistryKey {\n        $b.OpenSubKey('p', $true)\n    }\n"
        "    function Invoke-KcdRegExport {\n        & $reg 'import' $File\n    }\n}\n"
        "function Show-KcdState {\n    reg.exe query x\n}\n"
    )
    assert sorted(write_offenders(planted)) == ["Get-KcdRegistryKey", "Invoke-KcdApply"]
    assert sorted(reg_offenders(planted)) == ["Invoke-KcdRegExport: import", "Show-KcdState"]


def test_the_operator_page_covers_the_brief():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("Hold down the right CTRL key, and press SCROLL LOCK twice", "MANUALLY_INITIATED_CRASH", "Dump1Keys",
                   "Dump2Key", "-AlternateKeys", "## What you should see", "## After the reboot", "## What it cannot do",
                   "high interrupt request level", "Whether a GPU hang freeze responds is unverified",
                   "crashes the PC on purpose", "## Follow-up: a deliberate test crash", "take effect", LEARN_KBD,
                   "BugcheckCode` 226"):
        assert needle in text, needle
    readme = (CHANGE_DIR / "README.md").read_text(encoding="utf-8")
    assert "## Facts to verify on the PC" in readme
    assert re.findall(r"^\| (K\d+) \|", readme, re.MULTILINE) == [f"K{i}" for i in range(1, 12)]


# ---------------------------------------------------------------------------
# The unmodified script as a process (needs pwsh)
# ---------------------------------------------------------------------------

def find_pwsh() -> str | None:
    for candidate in (os.environ.get("WF_PWSH"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh"), shutil.which("pwsh")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


PWSH = find_pwsh()


@pytest.mark.skipif(PWSH is None, reason="no pwsh; run scripts/fetch_pwsh.sh or set WF_PWSH")
@pytest.mark.skipif(sys.platform == "win32", reason="on Windows the real adapters would read the machine")
@pytest.mark.parametrize("verb", ["-Plan", "-Apply", "-Undo", "-Readback"])
def test_real_adapters_fail_closed_off_windows(verb, tmp_path):
    """Every read fails where no Windows API exists, and the script must refuse without writing."""
    root = tmp_path / "evidence root"
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), verb, "-EvidenceRoot", str(root)],
                            env=dict(os.environ, NO_COLOR="1"), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=600)
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stderr == ""
    if verb in ("-Plan", "-Apply"):
        assert "FAIL" in result.stdout and "REFUSED" in result.stdout
    if verb == "-Undo":
        assert "REFUSED: no apply folder" in result.stdout
    if verb == "-Readback":
        assert "RESULT: FAIL" in result.stdout
    assert not root.exists(), "nothing may be saved when the preconditions fail"
    assert list(tmp_path.iterdir()) == []
