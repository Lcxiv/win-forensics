"""Static checks on the change tooling area, ``changes/windows/``, that need no PowerShell.

Change scripts are the only code in this repository that writes to the PC, so the area is kept
apart from everything that runs unattended: no collector, no part of the scenario runner and no
part of the SSH front door may refer to it, and every change script follows the shared rules in
``changes/windows/README.md`` (one self contained script per change, Plan by default, nothing that
prompts, installs, downloads, schedules or restarts).
"""
from __future__ import annotations

import re

import pytest

from conftest import REPO_ROOT

CHANGES_DIR = REPO_ROOT / "changes" / "windows"
CHANGE_FILES = sorted(p for p in CHANGES_DIR.rglob("*") if p.is_file())
CHANGE_SCRIPTS = sorted(p for p in CHANGES_DIR.glob("*.ps1"))
ENTRY_SCRIPTS = [p for p in CHANGE_SCRIPTS if not p.name.startswith("_")]

# Anything that would let unattended code reach a change script: the directory in either slash
# form, or the name of any script in it.
REFERENCE = re.compile(r"changes[/\\]|" + "|".join(re.escape(p.stem) for p in CHANGE_SCRIPTS), re.IGNORECASE)
UNATTENDED_ROOTS = [REPO_ROOT / "collectors", REPO_ROOT / "remote-access"]

# Never in a change script: prompts and credentials, code from text, native interop, the network,
# installs, scheduled tasks, services, restarts, other processes, whole key imports, and the
# PowerShell registry setters (writes go through the two audited .NET adapters instead).
FORBIDDEN = [
    "Read-Host", "Get-Credential", "ConvertTo-SecureString", "Invoke-Expression", "Invoke-Command", "EncodedCommand",
    "Add-Type", "DllImport", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "Net.Http", "Start-BitsTransfer",
    "Install-", "Uninstall-", "Register-ScheduledTask", "Set-ScheduledTask", "Enable-ScheduledTask", "Disable-ScheduledTask",
    "schtasks", "New-Service", "Set-Service", "Start-Service", "Stop-Service", "Restart-Service", "sc.exe", "Start-Process",
    "Stop-Process", "Restart-Computer", "Stop-Computer", "shutdown", "Set-ExecutionPolicy", "regedit", "reg import",
    "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "CreateSubKey", "DeleteSubKey", "ConvertTo-Json",
    "$script:", "$global:",
]


def code_lines(path):
    """The script without comment lines, so a rule can be named in a comment that explains it."""
    return "\n".join(line for line in path.read_text(encoding="ascii").splitlines() if not line.lstrip().startswith("#"))


def function_bodies(code: str) -> dict[str, str]:
    bodies: dict[str, str] = {}
    for header in re.finditer(r"^function ([A-Za-z0-9\-]+) \{", code, re.MULTILINE):
        close = re.compile(r"^\}[ \t]*$", re.MULTILINE).search(code, header.end())
        bodies[header.group(1)] = code[header.start():close.end() if close else len(code)]
    return bodies


def test_the_area_exists_with_its_readme():
    assert ENTRY_SCRIPTS, "no change script found"
    assert (CHANGES_DIR / "README.md").is_file()


def test_unattended_code_never_refers_to_the_change_area():
    offenders = []
    for root in UNATTENDED_ROOTS:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".ps1", ".psd1", ".psm1", ".sh", ".py", ".cmd", ".md", ".json", ".txt"}:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if REFERENCE.search(line):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert not offenders, offenders


def test_the_reference_guard_catches_both_slash_forms_and_script_names():
    assert REFERENCE.search(r"& .\changes\windows\x.ps1")
    assert REFERENCE.search("changes/windows/x.ps1")
    for script in CHANGE_SCRIPTS:
        assert REFERENCE.search("run " + script.name)
    assert not REFERENCE.search("no changes are made")


@pytest.mark.parametrize("path", CHANGE_FILES, ids=lambda p: str(p.relative_to(CHANGES_DIR)))
def test_files_are_plain_ascii(path):
    path.read_bytes().decode("ascii")


@pytest.mark.parametrize("path", CHANGE_SCRIPTS, ids=lambda p: p.name)
def test_change_scripts_avoid_forbidden_commands(path):
    code = code_lines(path)
    found = [token for token in FORBIDDEN if token.lower() in code.lower()]
    assert not found, found


@pytest.mark.parametrize("path", ENTRY_SCRIPTS, ids=lambda p: p.name)
def test_entry_scripts_default_to_plan_and_take_explicit_verbs(path):
    code = code_lines(path)
    for verb in ("Plan", "Apply", "Undo", "Readback"):
        assert re.search(rf"\[switch\]\${verb}\s*,", code), verb
        assert not re.search(rf"\[switch\]\${verb}\s*=", code), f"{verb} must not default to on"


@pytest.mark.parametrize("path", ENTRY_SCRIPTS, ids=lambda p: p.name)
def test_every_change_script_is_documented(path):
    readme = (CHANGES_DIR / "README.md").read_text(encoding="utf-8")
    assert f"`{path.name}`" in readme


def test_verification_items_are_numbered_once():
    readme = (CHANGES_DIR / "README.md").read_text(encoding="utf-8")
    ids = re.findall(r"^(\d+[a-z]?\.\d+)\. ", readme, re.MULTILINE)
    assert ids, "the README has no verification list"
    assert len(ids) == len(set(ids)), ids
