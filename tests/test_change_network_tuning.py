"""Static checks specific to ``changes/windows/network-tuning.ps1``.

The script changes advanced properties of one network adapter and nothing else. These checks pin
where a change can happen at all: exactly one adapter at the bottom of its library writes, it
passes ``-NoRestart``, nothing restarts, disables or resets an adapter, no TCP/IP stack, QoS,
power or registry writer appears, and reg.exe is only asked to export. They also hold the
settings table to the research document and keep the two documents in place.
"""
from __future__ import annotations

import re

from conftest import REPO_ROOT
from test_changes_area import code_lines, function_bodies

CHANGES_DIR = REPO_ROOT / "changes" / "windows"
LIB = CHANGES_DIR / "_network-tuning-lib.ps1"
ENTRY = CHANGES_DIR / "network-tuning.ps1"
RESEARCH = REPO_ROOT / "docs" / "changes" / "network-tuning-research.md"
OPERATOR = REPO_ROOT / "docs" / "changes" / "network-tuning.md"
WRITER = "Set-WfNtAdvancedProperty"

# Commands that would change the adapter, the TCP/IP stack, QoS, power or the registry by another
# path, or restart something. None may appear in the code of the script or its library.
NEVER = [
    "Restart-NetAdapter", "Disable-NetAdapter", "Enable-NetAdapter", "Reset-NetAdapterAdvancedProperty",
    "New-NetAdapterAdvancedProperty", "Remove-NetAdapterAdvancedProperty", "Set-NetAdapterPowerManagement",
    "Enable-NetAdapterPowerManagement", "Disable-NetAdapterPowerManagement", "Set-NetAdapterRss", "Set-NetAdapterLso",
    "Set-NetAdapterChecksumOffload", "Set-NetAdapterRsc", "Set-NetTCPSetting", "Set-NetOffloadGlobalSetting",
    "Set-NetIPInterface", "Set-NetQosPolicy", "New-NetQosPolicy", "Set-DnsClientServerAddress", "Disable-NetAdapterBinding",
    "Enable-NetAdapterBinding", "netsh", "powercfg", "pnputil", "Disable-PnpDevice", "Enable-PnpDevice", ".SetValue(",
    ".DeleteValue(", "OpenSubKey(", "Set-CimInstance", "Invoke-CimMethod", "Set-WmiInstance", "Invoke-WmiMethod",
]


def test_only_the_one_adapter_writes_and_never_restarts():
    bodies = function_bodies(code_lines(LIB))
    writers = [name for name, body in bodies.items() if "Set-NetAdapterAdvancedProperty" in body]
    assert writers == [WRITER]
    body = bodies[WRITER]
    assert "-NoRestart" in body
    assert body.count("Set-NetAdapterAdvancedProperty") == 1
    assert "Set-NetAdapterAdvancedProperty" not in code_lines(ENTRY)


def test_the_writer_is_called_only_by_apply_and_undo():
    bodies = function_bodies(code_lines(LIB))
    callers = sorted(name for name, body in bodies.items() if name != WRITER and WRITER in body)
    assert callers == ["Invoke-WfNtApply", "Invoke-WfNtUndo"]


def test_nothing_else_changes_the_machine():
    for path in (LIB, ENTRY):
        code = code_lines(path)
        found = [token for token in NEVER if token.lower() in code.lower()]
        assert not found, (path.name, found)


def test_reg_exe_only_exports():
    bodies = function_bodies(code_lines(LIB))
    users = [name for name, body in bodies.items() if "reg.exe" in body or "$reg " in body]
    assert users == ["Export-WfNtRegistryKey"]
    assert "& $reg export $Key $File /y" in bodies["Export-WfNtRegistryKey"]


def test_settings_table_matches_the_research_verdicts():
    body = function_bodies(code_lines(LIB))["Get-WfNtSettings"]
    entries = re.findall(r"Name\s+=\s+'([a-z0-9-]+)'.*?Default\s+=\s+\$(true|false)\s+Verdict\s+=\s+'([a-z-]+)'", body, re.S)
    assert [(n, d, v) for n, d, v in entries] == [
        ("idle-restriction", "true", "include"),
        ("green-ethernet", "false", "measure-first"),
        ("power-saving-mode", "false", "measure-first"),
        ("gigabit-lite", "false", "measure-first"),
        ("ltr-obff", "false", "measure-first"),
        ("flow-control", "false", "measure-first"),
    ]
    research = RESEARCH.read_text(encoding="utf-8")
    assert re.search(r"\| `\*IdleRestriction`[^\n]*\| \*\*include\*\* \|", research)
    for name, default, verdict in entries:
        assert f"`{name}`" in research, name
        if verdict == "measure-first":
            assert re.search(rf"\*\*measure first, opt in\*\*:[^\n|]*`{name}`", research), name


def test_research_covers_every_topic_in_the_brief():
    text = RESEARCH.read_text(encoding="utf-8")
    for topic in ("autotuning", "RSS", "RSC", "ECN", "timestamps", "initial RTO", "congestion provider", "TcpAckFrequency",
                  "TCPNoDelay", "TcpDelAckTicks", "NetworkThrottlingIndex", "SystemResponsiveness", "NonBestEffortLimit",
                  "DSCP", "MTU", "DNS", "IPv6", "Interrupt Moderation", "Flow Control", "EEE", "Green Ethernet",
                  "Receive Buffers", "LSO", "checksum offload", "Stutter Guard", "FoxOS", "TCP Optimizer"):
        assert topic.lower() in text.lower(), topic
    for section in ("## Verdicts", "## Current against proposed", "## Overlaps with other steps", "## Stutter Guard",
                    "## Sources"):
        assert section in text, section


def test_operator_page_exists_and_is_linked():
    assert OPERATOR.is_file()
    readme = (CHANGES_DIR / "README.md").read_text(encoding="utf-8")
    assert "docs/changes/network-tuning.md" in readme
    assert "docs/changes/network-tuning-research.md" in readme
    text = OPERATOR.read_text(encoding="utf-8")
    for section in ("## What it changes", "## When to run", "## The sequence", "## Experiments", "## What to record", "## Undo"):
        assert section in text, section
    assert "-Only" in text and "cannot" in text
    assert "Allow the computer to turn off this device to save power" in text and "Record the before value" in text


def test_documents_copy_no_address():
    pattern = re.compile(r"\b([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b|\b\d{1,3}(\.\d{1,3}){3}\b")
    for path in (RESEARCH, OPERATOR, CHANGES_DIR / "README.md", LIB, ENTRY):
        hits = [m.group(0) for m in pattern.finditer(path.read_text(encoding="utf-8"))]
        allowed = {"1125.31.50.603"}
        assert not [h for h in hits if h not in allowed], (path.name, hits)
