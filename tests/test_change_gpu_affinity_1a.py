"""Static checks specific to step 1a, ``changes/windows/gpu-affinity-1a.ps1``.

The script writes exactly two registry values of one key. These checks pin where a write can
happen at all: only the two adapters at the bottom of its library open a key for writing, they
set or delete one value and never create or remove a key, and reg.exe is only ever asked to
export.
"""
from __future__ import annotations

import re

from conftest import REPO_ROOT
from test_changes_area import code_lines, function_bodies

CHANGES_DIR = REPO_ROOT / "changes" / "windows"
LIB = CHANGES_DIR / "_gpu-affinity-1a-lib.ps1"
JOURNAL = CHANGES_DIR / "_stutter-guard-journal.ps1"
ENTRY = CHANGES_DIR / "gpu-affinity-1a.ps1"
WRITERS = {"Set-Wf1aRegistryValue", "Remove-Wf1aRegistryValue"}
PINNED = "8c783a478f4b511c273b3235bf745b5d64550f49"


def test_only_the_two_adapters_write():
    bodies = function_bodies(code_lines(LIB))
    for name, body in bodies.items():
        writes = re.findall(r"\.SetValue\(|\.DeleteValue\(|OpenSubKey\([^)]*\$true\)", body)
        if name in WRITERS:
            assert writes, f"{name} should hold its write"
        else:
            assert not writes, f"{name} writes: {writes}"
    assert "DeleteValue(" in bodies["Remove-Wf1aRegistryValue"]
    assert "SetValue(" in bodies["Set-Wf1aRegistryValue"]
    for path in (JOURNAL, ENTRY):
        assert not re.search(r"\.SetValue\(|\.DeleteValue\(|OpenSubKey\(", code_lines(path)), path.name


def test_writes_reach_only_the_affinity_policy_key():
    bodies = function_bodies(code_lines(LIB))
    callers = [name for name, body in bodies.items() if name not in WRITERS and re.search(r"Set-Wf1aRegistryValue|Remove-Wf1aRegistryValue", body)]
    assert callers == ["Set-Wf1aValueTo"]
    assert "-SubKey $Keys.Affinity" in bodies["Set-Wf1aValueTo"]
    assert "Get-Wf1aChangedValueNames { return @('DevicePolicy', 'AssignmentSetOverride') }" in code_lines(LIB)


def test_reg_exe_only_exports():
    bodies = function_bodies(code_lines(LIB))
    users = [name for name, body in bodies.items() if "reg.exe" in body or "$reg " in body]
    assert users == ["Export-Wf1aRegistryKey"]
    assert "& $reg export $Key $File /y" in bodies["Export-Wf1aRegistryKey"]


def test_journal_reader_cites_the_pinned_source_and_loads_nothing():
    text = JOURNAL.read_text(encoding="ascii")
    assert text.count(PINNED) >= 5
    code = code_lines(JOURNAL)
    for token in ("Import-", "Invoke-", "Start-", "& $", ". $", "Get-Content"):
        assert token not in code, token


def test_operator_page_exists_and_is_linked():
    page = REPO_ROOT / "docs" / "changes" / "step-1a-gpu-affinity.md"
    assert page.is_file()
    assert "docs/changes/step-1a-gpu-affinity.md" in (CHANGES_DIR / "README.md").read_text(encoding="utf-8")
    text = page.read_text(encoding="utf-8")
    for section in ("## When to run", "## The sequence", "## Play log", "## Advance criteria", "## Follow-up"):
        assert section in text, section
