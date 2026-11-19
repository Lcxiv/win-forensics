"""Static checks specific to step 1a, ``changes/windows/gpu-affinity-1a.ps1``.

What the script writes is checked on its behaviour, by the Pester suite against the synthetic
backend (every registry write and reg.exe call any test makes is recorded and checked). This file
keeps one safety guard that holds even for code no test reaches: a registry write primitive
appears only inside the two named write adapters, and reg.exe is only ever run with ``export``.
"""
from __future__ import annotations

import re

from conftest import REPO_ROOT
from test_changes_area import CHANGE_SCRIPTS, code_lines, function_bodies

CHANGES_DIR = REPO_ROOT / "changes" / "windows"
LIB = CHANGES_DIR / "_gpu-affinity-1a-lib.ps1"
JOURNAL = CHANGES_DIR / "_stutter-guard-journal.ps1"
WRITERS = {"Set-Wf1aRegistryValue", "Remove-Wf1aRegistryValue"}
# The functions that may run reg.exe, and only with ``export``: step 1a's, and the network
# tuning library's, which this guard covers too since it walks every change script.
REG_RUNNERS = {"Export-Wf1aRegistryKey", "Export-WfNtRegistryKey"}
NT_LIB = CHANGES_DIR / "_network-tuning-lib.ps1"

WRITE_PRIMITIVE = re.compile(
    r"\.SetValue\(|\.DeleteValue\(|\.DeleteValueAsync\(|OpenSubKey\([^)]*,\s*(\$true|\[[^\]]*RegistryKeyPermissionCheck\]|\[[^\]]*RegistryRights\])"
    r"|CreateSubKey|DeleteSubKey|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Rename-ItemProperty|New-Item\s+[^\n]*HK"
    r"|\breg(\.exe)?['\"]?\s+(add|delete|import|copy|restore|load|unload)\b",
    re.IGNORECASE,
)
REG_EXE = re.compile(r"Get-Wf1aRegExe|['\"]([^'\"\s]*\\)?reg\.exe['\"]|(^|[;&|{(])\s*reg(\.exe)?\s", re.IGNORECASE | re.MULTILINE)
CALL_OPERATOR = re.compile(r"&\s*(\$\w+|'[^']*'|\"[^\"]*\")\s+([^\s)]+)")


def write_offenders(code: str) -> list[str]:
    """Functions other than the two write adapters that hold a registry write primitive, and any
    primitive outside every function."""
    bodies = function_bodies(code)
    offenders = [name for name, body in bodies.items() if name not in WRITERS and WRITE_PRIMITIVE.search(body)]
    rest = code
    for body in bodies.values():
        rest = rest.replace(body, "")
    if WRITE_PRIMITIVE.search(rest):
        offenders.append("<top level>")
    return offenders


def reg_offenders(code: str) -> list[str]:
    """Places that run reg.exe with anything but ``export``: a function other than the runner (or
    the one that names the path) that mentions reg.exe, or a call in the runner whose verb is not
    ``export``."""
    offenders = []
    bodies = function_bodies(code)
    for name, body in bodies.items():
        if name == "Get-Wf1aRegExe":
            continue
        if name not in REG_RUNNERS and REG_EXE.search(body):
            offenders.append(name)
        if name in REG_RUNNERS:
            offenders += [f"{name}: {verb}" for _, verb in CALL_OPERATOR.findall(body) if verb.lower() != "export"]
    rest = code
    for body in bodies.values():
        rest = rest.replace(body, "")
    if REG_EXE.search(rest):
        offenders.append("<top level>")
    return offenders


def test_only_the_two_write_adapters_hold_a_registry_write():
    for path in CHANGE_SCRIPTS:
        assert not write_offenders(code_lines(path)), path.name
    assert WRITERS <= set(function_bodies(code_lines(LIB))), "the guard names adapters the library no longer has"


def test_reg_exe_is_only_run_to_export():
    for path in CHANGE_SCRIPTS:
        assert not reg_offenders(code_lines(path)), path.name
    assert "Export-Wf1aRegistryKey" in function_bodies(code_lines(LIB))
    assert "Export-WfNtRegistryKey" in function_bodies(code_lines(NT_LIB))


def test_the_write_guard_catches_writes_outside_the_adapters():
    for line in (
        "$key.SetValue('x', 1)", "$key.DeleteValue('x', $false)", "$base.OpenSubKey($p, $true)",
        "$base.OpenSubKey($p, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)", "$base.CreateSubKey($p)",
        "Set-ItemProperty -Path HKLM:\\x -Name y -Value 1", "New-ItemProperty -Path x", "Remove-ItemProperty -Path x",
        "& reg add HKLM\\x /v y /d 1", "& 'reg.exe' delete HKLM\\x", "reg import x.reg",
    ):
        code = "function Get-Wf1aOther {\n    " + line + "\n}\n"
        assert write_offenders(code) == ["Get-Wf1aOther"], line
        assert write_offenders(line + "\n") == ["<top level>"], line
    inside = "function Set-Wf1aRegistryValue {\n    $key = $base.OpenSubKey($p, $true)\n    $key.SetValue('x', 1)\n}\n"
    assert write_offenders(inside) == []
    assert write_offenders("function Get-Wf1aX {\n    $key = $base.OpenSubKey($p, $false)\n}\n") == []


def test_the_reg_guard_catches_other_verbs():
    runner = "function Export-Wf1aRegistryKey {\n    $reg = Get-Wf1aRegExe\n    $null = & $reg %s $Key $File /y 2>&1\n}\n"
    assert reg_offenders(runner % "export") == []
    for verb in ("add", "delete", "import", "$Verb"):
        assert reg_offenders(runner % verb) == [f"Export-Wf1aRegistryKey: {verb}"], verb
    assert reg_offenders("function Get-Wf1aOther {\n    $reg = Get-Wf1aRegExe\n}\n") == ["Get-Wf1aOther"]
    assert reg_offenders("& 'C:\\Windows\\System32\\reg.exe' query x\n") == ["<top level>"]
    assert reg_offenders("function Get-Wf1aOther {\n    reg query HKLM\\x\n}\n") == ["Get-Wf1aOther"]
    assert reg_offenders("function Get-Wf1aOther {\n    $r = 'the reg.exe export header'\n}\n") == []


def test_journal_reader_loads_nothing():
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
