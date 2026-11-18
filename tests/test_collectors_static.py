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
EXPECTED_COLLECTORS = ["application-errors", "bugcheck-history", "driver-inventory", "presentmon-frames", "reliability-records", "rf-survey", "tdr-events", "whea-errors"]

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


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_scripts_are_read_only(path):
    text = path.read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for token in FORBIDDEN:
        assert token.lower() not in code.lower(), f"{path.name} uses {token.strip()}"
    # The only deletions are of the collector's own exports inside the output directory: a failed or
    # over-cap .evtx, and a primary export that must not be left behind ($Path is the primary passed to
    # Remove-WfPrimaryUnlessKept; the others are the primaries of the event, WMI, netsh, file and device
    # sources, and the recording, CSV and wpr temp folder of presentmon-frames).
    removals = [line.strip() for line in code.splitlines() if "Remove-Item" in line]
    own = ("-LiteralPath $evtxPath", "-LiteralPath $recordsPath", "-LiteralPath $eventsPath", "-LiteralPath $outputPath",
           "-LiteralPath $summaryPath", "-LiteralPath $devicesPath", "-LiteralPath $Path -Force",
           "-LiteralPath $etlPath -Force", "-LiteralPath $wprTempPath -Recurse -Force")
    assert all(any(marker in r for marker in own) for r in removals), removals
    # The only process the helper builds itself is wevtutil, with the export verb and nothing else; the
    # netsh queries rf-survey runs and the PresentMon runs of presentmon-frames go through the helper's
    # one runner and are checked on what the runs record (test_collector_bundles and the Pester suite).
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
    for term in ("Minidump", "MEMORY.DMP", "Security", "Get-StorageReliabilityCounter", "chkdsk", "sfc", "wlanreport"):
        assert term in readme, term


def test_rf_survey_sources_are_documented_with_their_privacy_rule():
    """Every rf-survey source id appears in the README, as does the pseudonym rule and the method document."""
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    script = (COLLECTOR_DIR / "rf-survey.ps1").read_text(encoding="ascii")
    ids = re.findall(r"Id\s*=\s*'([a-z_]+)'", script)
    assert len(ids) == 10 and len(set(ids)) == 10
    for source_id in ids:
        assert f"`{source_id}`" in readme, source_id
    for term in ("ssid-", "mac-", "docs/rf-survey.md", "location", "Get-PnpDeviceProperty", "MSFT_NetAdapter"):
        assert term in readme, term


# ---------------------------------------------------------------- presentmon-frames

PRESENTMON = COLLECTOR_DIR / "presentmon-frames.ps1"
# Every PresentMon option the collector may pass, each documented in the pinned version's console README
# (collectors/windows/README.md cites them). PresentMon only ever reads a file: every option of its realtime
# mode (a session, a timer, a process id, elevation, a hotkey) is deliberately absent.
PRESENTMON_ALLOWED_OPTIONS = {"--etl_file", "--output_file", "--no_console_stats", "--qpc_time", "--process_name"}
PRESENTMON_LIVE_OPTIONS = ("--timed", "--session_name", "--terminate_after_timed", "--terminate_existing_session", "--stop_existing_session",
                           "--process_id", "--restart_as_admin", "--hotkey", "--output_stdout", "--multi_csv", "--delay", "--terminate_on_proc_exit")
# The wpr verbs the collector may use: one recording started, read, saved and cancelled. Everything that
# changes a machine setting or configures a boot trace is deliberately absent.
WPR_ALLOWED = {"-start", "-filemode", "-recordtempto", "-status", "-stop", "-skipPdbGen", "-cancel", "-details"}
WPR_FORBIDDEN = ("-disablepagingexecutive", "-heaptracingconfig", "-boottrace", "-addboot", "-stopboot", "-setprofint", "-resetprofint",
                 "-snapshotconfig", "-enableperiodicsnapshot", "-marker", "-markerflush", "-flush", "-merge", "-purgecache", "-capturestateondemand")


def presentmon_code() -> str:
    text = PRESENTMON.read_text(encoding="ascii")
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def presentmon_pin() -> dict:
    code = presentmon_code()
    out = {}
    for name, pattern in (("version", r"Get-WfPresentMonPinnedVersion \{ return '([0-9.]+)' \}"),
                          ("file_name", r"Get-WfPresentMonPinnedFileName \{ return '([A-Za-z0-9.-]+\.exe)' \}"),
                          ("sha256", r"Get-WfPresentMonPinnedSha256 \{ return '([0-9a-f]{64})' \}"),
                          ("length", r"Get-WfPresentMonPinnedLength \{ return \[int64\]([0-9]+) \}"),
                          ("release_url", r"Get-WfPresentMonReleaseUrl \{ return '(https://[^']+)' \}"),
                          ("asset_url", r"Get-WfPresentMonAssetUrl \{ return '(https://[^']+)' \}"),
                          ("docs_url", r"Get-WfPresentMonDocumentationUrl \{ return '(https://[^']+)' \}")):
        m = re.search(pattern, code)
        assert m, name
        out[name] = m.group(1)
    return out


def test_presentmon_pin_is_one_release_and_is_repeated_in_the_docs_and_the_fixtures():
    pin = presentmon_pin()
    assert pin["file_name"] == f"PresentMon-{pin['version']}-x64.exe"
    assert pin["release_url"] == f"https://github.com/GameTechDev/PresentMon/releases/tag/v{pin['version']}"
    assert pin["asset_url"] == f"https://github.com/GameTechDev/PresentMon/releases/download/v{pin['version']}/{pin['file_name']}"
    assert pin["docs_url"] == f"https://github.com/GameTechDev/PresentMon/blob/v{pin['version']}/README-ConsoleApplication.md"
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    for value in (pin["sha256"], pin["file_name"], pin["release_url"], pin["docs_url"], pin["length"]):
        assert value in readme, value
    scenarios = (COLLECTOR_DIR / "tests" / "SyntheticScenarios.ps1").read_text(encoding="ascii")
    assert f"return '{pin['sha256']}'" in scenarios, "the synthetic binary must report the collector's own pin"
    assert f"[int64]$Length = {pin['length']}" in scenarios


def test_presentmon_only_ever_reads_a_recording_and_wpr_only_records_one():
    code = presentmon_code()
    used = set(re.findall(r"'(--[a-z_]+)'", code))
    assert used == PRESENTMON_ALLOWED_OPTIONS, used ^ PRESENTMON_ALLOWED_OPTIONS
    for forbidden in PRESENTMON_LIVE_OPTIONS:
        assert forbidden not in code, forbidden
    # The offline read is built in this order and always with the file and QPC time stamps.
    assert re.search(r"\$decodeArguments\.Add\('--etl_file'\).*?\$decodeArguments\.Add\('--output_file'\).*?\$decodeArguments\.Add\('--no_console_stats'\)\s*"
                     r"\$decodeArguments\.Add\('--qpc_time'\)", code, re.S)
    # wpr: the four verbs and their switches, nothing that changes a setting.
    wpr_tokens = set(re.findall(r"(?<![\w-])(-[A-Za-z]+)(?=[\s\"'])", "\n".join(line for line in code.splitlines() if "wpr" in line.lower() or "-start" in line or "-stop" in line or "-status" in line or "-cancel" in line)))
    assert WPR_ALLOWED <= wpr_tokens, WPR_ALLOWED - wpr_tokens
    for forbidden in WPR_FORBIDDEN:
        assert forbidden not in code, forbidden
    # Session control stays in the collector: the helper knows no PresentMon or wpr option.
    helper = (COLLECTOR_DIR / HELPER).read_text(encoding="ascii")
    helper_code = "\n".join(line for line in helper.splitlines() if not line.lstrip().startswith("#"))
    for token in ("--etl_file", "--qpc_time", "-recordtempto", "-filemode", "profile.wprp"):
        assert token not in helper_code, token
    # The collector never downloads: no URL is fetched, the release URL is only printed in a reason.
    assert "Invoke-WebRequest" not in code and "DownloadFile" not in code
    # The profile never enables the DxgKrnl Performance keyword PresentMon avoids: it appears only in the
    # provider table's explanation, never as a keyword value.
    assert "keywords = '0x4000000000000000'" not in code and 'Value="0x4000000000000000"' not in code
    assert "0x4000000000000000) is removed as PresentMon does" in code


def test_presentmon_documents_elevation_and_the_anti_cheat_position():
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("### The presentmon-frames source"):]
    for term in ("Performance Log Users", "S-1-5-32-559", "<unknown>", "Easy Anti-Cheat", "not documented", "ETW",
                 "--qpc_time", "CPUStartQPC", "--etl_file", "OpenProcess", "PROCESS_QUERY_LIMITED_INFORMATION", "SeDebugPrivilege",
                 "wpr -cancel", "Events Lost", "events_lost", "Flash Injector", "Anticheat Mitigation", "MaximumFileSize",
                 "one at a time", "OutputThread.cpp", "ReadAndExecute", "collect-presentmon-frames"):
        assert term in section, term
    assert "live PresentMon" in section.lower() or "realtime" in section.lower()
