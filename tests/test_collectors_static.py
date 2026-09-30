"""Static checks on the collector scripts that need no PowerShell: the seam, read only posture, citations."""
from __future__ import annotations

import re

import pytest

from conftest import REPO_ROOT

COLLECTOR_DIR = REPO_ROOT / "collectors" / "windows"
COLLECTOR_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
HELPER = "_common.ps1"
SHIPPED = sorted(COLLECTOR_DIR.glob("*.ps1"))
COLLECTORS = [p for p in SHIPPED if p.name != HELPER]
EXPECTED_COLLECTORS = ["application-errors", "bugcheck-history", "driver-inventory", "reliability-records", "tdr-events", "whea-errors"]

# Commands that change the machine, reach the network, prompt, handle credentials, or run text
# as code. A read only collector has no use for any of them.
FORBIDDEN = [
    "Clear-EventLog", "Remove-EventLog", "Limit-EventLog", "New-EventLog", "Write-EventLog", "clear-log", "wevtutil cl",
    " sl ", "set-log", "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "Set-Service", "Start-Service",
    "Stop-Service", "Restart-Service", "Stop-Process", "Start-Process", "Restart-Computer", "Stop-Computer",
    "Register-ScheduledTask", "schtasks", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "Start-BitsTransfer",
    "Invoke-Expression", "Invoke-Command", "EncodedCommand", "Add-Type", "DllImport", "Read-Host", "Get-Credential",
    "ConvertTo-SecureString", "Set-ExecutionPolicy", "Enable-", "Disable-", "Install-", "Uninstall-", "Set-Content",
    "Out-File", "Add-Content", "Remove-CimInstance", "Set-CimInstance", "Invoke-CimMethod", "Invoke-WmiMethod",
]


def test_the_collector_set_is_the_documented_one():
    assert [p.stem for p in COLLECTORS] == EXPECTED_COLLECTORS


def test_names_follow_the_seam_and_the_helper_cannot_be_dispatched():
    for path in COLLECTORS:
        assert COLLECTOR_NAME.match(path.stem), path.name
    assert (COLLECTOR_DIR / HELPER).is_file()
    assert not COLLECTOR_NAME.match(HELPER.removesuffix(".ps1")), "the dispatcher must never map a verb to the helper"
    assert [p.name for p in COLLECTOR_DIR.iterdir() if p.is_file() and p.suffix != ".ps1"] == ["README.md"], \
        "the setup script installs *.ps1 from this directory; everything a collector needs at run time is a .ps1 file here"


@pytest.mark.parametrize("path", sorted(COLLECTOR_DIR.rglob("*.ps1")), ids=lambda p: p.name)
def test_scripts_are_plain_ascii(path):
    # Windows PowerShell 5.1 reads a script without a byte order mark in the ANSI code page, so a
    # non ASCII character would be read differently on the PC than here.
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    offenders = [i for i, b in enumerate(data) if b > 126 or (b < 32 and b not in (9, 10))]
    assert not offenders, f"{path.name}: byte offsets {offenders[:5]}"


@pytest.mark.parametrize("path", COLLECTORS, ids=lambda p: p.stem)
def test_collector_follows_the_interface(path):
    text = path.read_text(encoding="ascii")
    assert f"$collectorName = '{path.stem}'" in text
    assert "[string]$OutputDirectory" in text
    assert "Mandatory" not in text.split("param(")[1].split(")\n\nSet-StrictMode")[0].replace("not marked Mandatory", "").replace("a missing Mandatory", ""), \
        "a Mandatory parameter would prompt in an interactive session"
    assert "Set-StrictMode -Version 2.0" in text and "$ErrorActionPreference = 'Stop'" in text
    assert "Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'" in text and ". $common" in text
    assert text.count("Invoke-WfCollectorScript") == 1 and text.rstrip().endswith("exit $exitCode")
    assert '"status":"failed"' in text, "the collector prints a failed summary even when the helper is missing"
    assert "https://learn.microsoft.com/" in text, "every collector cites the documentation for what it reads"
    assert "Event Log Readers" in text or "Authenticated Users" in text, "every collector states why a standard account may read its source"
    for stream in ("Write-Host", "Write-Output", "Write-Verbose", "Write-Warning", "Write-Information"):
        assert stream not in text, f"{stream} would put text other than the summary on an output stream"


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_scripts_are_read_only(path):
    text = path.read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for token in FORBIDDEN:
        assert token.lower() not in code.lower(), f"{path.name} uses {token.strip()}"
    # The only deletions are of the collector's own export inside the output directory.
    removals = [line.strip() for line in code.splitlines() if "Remove-Item" in line]
    assert all("-LiteralPath $evtxPath" in r or "-LiteralPath $recordsPath" in r for r in removals), removals
    # The only process started is wevtutil, with the export verb and nothing else.
    if path.name == HELPER:
        assert code.count("System.Diagnostics.ProcessStartInfo") == 1
        assert "'epl \"{0}\" \"{1}\" /sq:true /ow:true'" in code
    else:
        assert "ProcessStartInfo" not in code


def test_helper_writes_json_without_convertto_json():
    # ConvertTo-Json has a default depth of 2, and in Windows PowerShell it writes a psobject
    # wrapped array as an object with value and Count members (PowerShell/PowerShell issues 3153
    # and 5579). Neither can be tested off Windows, so the helper has its own writer and must
    # not fall back to the cmdlet.
    text = (COLLECTOR_DIR / HELPER).read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "ConvertTo-Json" not in code and "ConvertFrom-Json" not in code
    assert "$script:" not in code and "$global:" not in code


def test_readme_covers_every_collector_and_the_elevated_list():
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    for path in COLLECTORS:
        assert f"`{path.stem}`" in readme, path.stem
    for heading in ("## Interface", "## Collectors", "## Needs elevation", "## Facts to verify on the PC", "## Testing"):
        assert heading in readme, heading
    for term in ("Minidump", "MEMORY.DMP", "Security", "Get-StorageReliabilityCounter", "chkdsk", "sfc"):
        assert term in readme, term
