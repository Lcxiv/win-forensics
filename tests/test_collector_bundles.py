"""The synthetic collector bundles follow the bundle contract, and the event log decoder reads them.

The bundles under fixtures/collector-bundles are written by the real collector scripts against
the synthetic backend (collectors/windows/tests/New-FixtureBundles.ps1). Nothing in them comes
from a real machine. tests/test_collectors_pwsh.py checks that they match a fresh run.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

import decode_eventlog
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = sorted(p.name for p in BUNDLES.iterdir() if p.is_dir())
COLLECTOR_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
OBSERVED = ("observed", "observed_zero")

# The only netsh queries a collector may run: the four read only listings. "wlan show wlanreport"
# writes a file outside the bundle and "connect", "disconnect", "refresh" and "reportissues" act on
# the machine, so an allowlist, not a denylist, decides.
ALLOWED_NETSH = re.compile(r"^wlan show (interfaces|drivers|networks mode=bssid|profiles)$")
# The only powercfg verbs a collector may run: the five listings. Everything else on the powercfg
# page changes a setting, a scheme, or writes a report file outside the bundle.
ALLOWED_POWERCFG = re.compile(r"^/(list|getactivescheme|aliases|query|qh)$")
# The configuration snapshot's two questions without a documented read only path.
UNAVAILABLE = {"power_mode", "timer_resolution"}
# The only wpr verbs the live capture collector may use: read the status, enumerate the profile file,
# start the one session it owns, stop it, cancel it. No boot trace, no marker, no configuration change.
ALLOWED_WPR_VERBS = {"-status", "-profiles", "-start", "-stop", "-cancel"}
# The only xperf action: the DPC and ISR report of the trace in the bundle, with -tle only after a loss.
ALLOWED_XPERF = re.compile(r"^-i <bundle>/private/trace\.etl -a dpcisr( -tle)?$")
# The only tracerpt action: the summary of the trace in the private folder, written into the bundle, never prompting.
ALLOWED_TRACERPT = re.compile(r"^<bundle>/private/trace\.etl -summary <bundle>/raw/wpr_trace/tracerpt-summary\.txt -y$")
# Collectors whose cases run elevated (the live capture needs it) and carry a QPC trace.
LIVE_CAPTURE = {"dpcisr-trace"}

# What each committed case is there to show: summary status and the status of every source.
EXPECTED = {
    "application-errors": ("ok", {"application_error_events": "observed"}),
    "bugcheck-history": ("ok", {"system_restart_events": "observed"}),
    "bugcheck-history-access-denied": ("failed", {"system_restart_events": "not_collected"}),
    "clock-calibration": ("ok", {"clock_calibration": "observed", "operator_marks": "observed"}),
    "clock-calibration-clock-step": ("ok", {"clock_calibration": "observed", "operator_marks": "observed"}),
    "clock-calibration-missed-slot": ("ok", {"clock_calibration": "observed", "operator_marks": "observed_zero"}),
    "clock-calibration-read-failed": ("ok", {"clock_calibration": "observed", "operator_marks": "observed_zero"}),
    "driver-inventory": ("ok", {"pnp_signed_drivers": "observed", "system_drivers": "observed"}),
    "reliability-records": ("ok", {"reliability_records": "observed", "reliability_stability_metrics": "observed"}),
    "rf-survey": ("ok", {"net_adapters": "observed", "default_routes": "observed", "wlan_interfaces": "observed", "wlan_drivers": "observed",
                         "wlan_networks": "observed", "wlan_profiles": "observed", "wlan_report": "observed",
                         "wlan_autoconfig_events": "observed", "usb_device_tree": "observed", "bluetooth_devices": "observed"}),
    "rf-survey-clean": ("partial", {"net_adapters": "observed", "default_routes": "observed", "wlan_interfaces": "observed", "wlan_drivers": "observed",
                                    "wlan_networks": "observed", "wlan_profiles": "observed", "wlan_report": "not_collected",
                                    "wlan_autoconfig_events": "observed_zero", "usb_device_tree": "observed", "bluetooth_devices": "observed"}),
    "rf-survey-connected": ("partial", {"net_adapters": "observed", "default_routes": "observed", "wlan_interfaces": "observed", "wlan_drivers": "observed",
                                        "wlan_networks": "observed", "wlan_profiles": "observed", "wlan_report": "not_collected",
                                        "wlan_autoconfig_events": "observed_zero", "usb_device_tree": "observed", "bluetooth_devices": "observed"}),
    "rf-survey-no-wifi": ("partial", {"net_adapters": "observed", "default_routes": "observed", "wlan_interfaces": "capture_failed",
                                      "wlan_drivers": "capture_failed", "wlan_networks": "capture_failed", "wlan_profiles": "capture_failed",
                                      "wlan_report": "not_collected", "wlan_autoconfig_events": "unsupported", "usb_device_tree": "observed",
                                      "bluetooth_devices": "observed_zero"}),
    "rf-survey-non-english": ("partial", {"net_adapters": "observed", "default_routes": "observed", "wlan_interfaces": "observed", "wlan_drivers": "observed",
                                          "wlan_networks": "observed", "wlan_profiles": "observed", "wlan_report": "not_collected",
                                          "wlan_autoconfig_events": "observed_zero", "usb_device_tree": "observed", "bluetooth_devices": "observed"}),
    "tdr-events-partial": ("partial", {"system_display_events": "capture_failed", "system_bugcheck_events": "observed_zero"}),
    "whea-errors-quiet": ("ok", {"system_whea_events": "observed_zero"}),
    "config-snapshot": ("partial", {"interrupt_policy": "observed", "graphics_tdr": "observed", "processors": "observed", "cpu_caches": "observed",
                                    "logical_processor_map": "observed", "power_active_scheme": "observed", "power_schemes": "observed",
                                    "power_aliases": "observed", "power_settings": "observed", "power_settings_hidden": "observed",
                                    "power_mode": "not_collected", "timer_resolution": "not_collected", "processes": "observed",
                                    "timer_helper_process": "observed", "process_lasso_install": "observed", "process_lasso_config": "observed",
                                    "process_lasso_log": "observed", "stutter_guard_install": "observed", "stutter_guard_journal": "observed"}),
    "config-snapshot-clean": ("partial", {"interrupt_policy": "observed", "graphics_tdr": "observed", "processors": "observed", "cpu_caches": "observed",
                                          "logical_processor_map": "observed", "power_active_scheme": "observed", "power_schemes": "observed",
                                          "power_aliases": "observed", "power_settings": "observed", "power_settings_hidden": "capture_failed",
                                          "power_mode": "not_collected", "timer_resolution": "not_collected", "processes": "observed",
                                          "timer_helper_process": "observed_zero", "process_lasso_install": "observed_zero", "process_lasso_config": "not_collected",
                                          "process_lasso_log": "not_collected", "stutter_guard_install": "observed_zero", "stutter_guard_journal": "not_collected"}),
    "config-snapshot-denied": ("failed", {"interrupt_policy": "not_collected", "graphics_tdr": "not_collected", "processors": "not_collected", "cpu_caches": "not_collected",
                                          "logical_processor_map": "not_collected", "power_active_scheme": "not_collected", "power_schemes": "not_collected",
                                          "power_aliases": "not_collected", "power_settings": "not_collected", "power_settings_hidden": "not_collected",
                                          "power_mode": "not_collected", "timer_resolution": "not_collected", "processes": "not_collected",
                                          "timer_helper_process": "not_collected", "process_lasso_install": "not_collected", "process_lasso_config": "not_collected",
                                          "process_lasso_log": "not_collected", "stutter_guard_install": "not_collected", "stutter_guard_journal": "not_collected"}),
    "dpcisr-trace": ("ok", {"wpr_trace": "observed", "dpcisr_report": "observed"}),
    "dpcisr-trace-no-xperf": ("partial", {"wpr_trace": "observed", "dpcisr_report": "not_collected"}),
    "dpcisr-trace-events-lost": ("failed", {"wpr_trace": "capture_failed", "dpcisr_report": "capture_failed"}),
    "dpcisr-trace-not-elevated": ("failed", {"wpr_trace": "not_collected", "dpcisr_report": "not_collected"}),
}


def load_manifest(case: str) -> dict:
    return json.loads((BUNDLES / case / "manifest.json").read_text(encoding="utf-8"))


def load_summary(case: str) -> dict:
    text = (BUNDLES / case / "logs" / "summary.json").read_text(encoding="utf-8")
    assert text.endswith("\n") and text.count("\n") == 1, "the summary is exactly one line"
    return json.loads(text)


def summary_status(statuses: list[str]) -> str:
    good = [s for s in statuses if s in OBSERVED]
    if statuses and len(good) == len(statuses):
        return "ok"
    return "partial" if good else "failed"


def test_every_expected_case_is_committed():
    assert CASES == sorted(EXPECTED)


@pytest.mark.parametrize("case", CASES)
def test_container_integrity(case):
    result = verify_bundle.verify(BUNDLES / case)
    assert result["ok"], result["checks"]
    assert {c["name"] for c in result["checks"]} == {"manifest_schema", "artifacts_listed_once", "artifacts_match_manifest",
                                                      "no_unlisted_raw_file", "status_has_artifact_or_reason"}


@pytest.mark.parametrize("case", CASES)
def test_layout_is_capture_only(case):
    bundle = BUNDLES / case
    top = {p.name for p in bundle.iterdir()}
    assert top == {"manifest.json", "raw", "logs"}, "a collector writes no evidence, verdict, validation, or decoded table"
    assert {p.name for p in (bundle / "logs").iterdir()} == {"collector.log", "summary.json"}
    manifest = load_manifest(case)
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            assert artifact["path"].startswith(f"raw/{collector['id']}/"), "one raw subdirectory per collector id"


@pytest.mark.parametrize("case", CASES)
def test_manifest_identifies_the_collector(case):
    manifest = load_manifest(case)
    summary = load_summary(case)
    name = summary["collector"]
    assert COLLECTOR_NAME.match(name) and (REPO_ROOT / "collectors" / "windows" / f"{name}.ps1").is_file()
    scenario = name.replace("-", "_")
    assert manifest["scenario"]["id"] == scenario
    assert manifest["capture"]["orchestrator"] == f"wf-collector:{name}"
    start = manifest["capture"]["start_utc"]
    compact = start[:19].replace("-", "").replace(":", "") + "Z"
    assert manifest["bundle_id"] == f"{compact}_{scenario}_{manifest['machine']['machine_id'][:8]}"
    if name in LIVE_CAPTURE:
        # The kernel trace needs an elevated account (the not-elevated case shows the refusal), its
        # timestamps are QPC and the calibration pairs come from the clock collector, a separate piece.
        assert manifest["capture"]["elevated"] is (case != "dpcisr-trace-not-elevated")
        assert manifest["calibration"]["status"] == "not_collected" and manifest["calibration"]["pairs"] == []
        assert manifest["scenario"]["requested_duration_s"] == 10
    elif name == "clock-calibration":
        assert manifest["capture"]["elevated"] is False, "the clock collector runs as a standard account"
        clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
        assert manifest["calibration"]["status"] == clock["status"], "the calibration section carries the clock source's own status"
        assert manifest["calibration"]["qpc_frequency_hz"] == manifest["machine"]["cpu"]["qpc_frequency_hz"]
        assert manifest["calibration"]["time_adjustment"] == {"start": None, "stop": None}, "GetSystemTimeAdjustment is not reachable without compiling code"
        assert manifest["scenario"]["requested_duration_s"] == clock["requested"]["options"]["duration_seconds"]
        if clock["status"] == "observed":
            assert len(manifest["calibration"]["pairs"]) == clock["enabled"]["options"]["pairs_taken"] >= 2
            assert manifest["calibration"]["expected_pairs"] == len(manifest["calibration"]["pairs"]) + manifest["calibration"]["missing_pairs"]
        else:
            assert manifest["calibration"]["pairs"] == [] and manifest["calibration"]["missing_pairs"] == manifest["calibration"]["expected_pairs"]
    else:
        assert manifest["capture"]["elevated"] is False, "the history collectors run as a standard account"
        assert manifest["calibration"]["status"] == "not_applicable" and manifest["calibration"]["pairs"] == []
        assert manifest["scenario"]["marks"] == []
    assert manifest["machine"]["hostname"] == "SYNTHETIC-PC", "fixtures never carry a real host name"
    tool_names = [t["name"] for t in manifest["tools"]]
    base = ["powershell", "wevtutil", f"collector:{name}", "collector-helper:_common.ps1"]
    extra = [t for t in tool_names[len(base):]]
    assert tool_names[:len(base)] == base
    ran_xperf = any(c["id"] == "dpcisr_report" and c["status"] in OBSERVED + ("capture_failed",) and c["exit_code"] is not None for c in manifest["collectors"])
    ran_tracerpt = any(c["id"] == "wpr_trace" and c["enabled"]["options"] and c["enabled"]["options"].get("trace_sha256") for c in manifest["collectors"])
    assert extra == ([] if name not in LIVE_CAPTURE else ["wpr"] + (["tracerpt"] if ran_tracerpt else []) + (["xperf"] if ran_xperf else [])), extra
    for tool in manifest["tools"]:
        if tool["name"] == "xperf":
            assert re.fullmatch(r"[0-9a-f]{64}", tool["sha256"]) and tool["version"], "the pinned tool is recorded with hash and version"


@pytest.mark.parametrize("case", CASES)
def test_summary_line_follows_the_seam(case):
    manifest = load_manifest(case)
    summary = load_summary(case)
    assert list(summary) == ["collector", "status", "bundle", "artifacts"]
    assert summary["bundle"] == f"fixtures/collector-bundles/{case}"
    statuses = [c["status"] for c in manifest["collectors"]]
    assert summary["status"] == summary_status(statuses) == EXPECTED[case][0]
    assert summary["artifacts"] == sum(len(c["artifacts"]) for c in manifest["collectors"])
    assert manifest["capture"]["incomplete"] is (summary["status"] != "ok")


@pytest.mark.parametrize("case", CASES)
def test_status_and_evidence_stay_separate(case):
    manifest = load_manifest(case)
    assert {c["id"]: c["status"] for c in manifest["collectors"]} == EXPECTED[case][1]
    for collector in manifest["collectors"]:
        primary = [a for a in collector["artifacts"] if a["role"] == "primary"]
        if collector["status"] in OBSERVED:
            assert collector["status_reason"] is None and len(primary) == 1
            assert collector["preflight"]["ok"] is True
            if collector["kind"] == "clock":
                # The clock calibration exception (timestamps.md section 3, measurement-status.md section 2): two or more
                # pairs are observed even when pairs are missing; the expectation is the full count and says so.
                assert collector["expectation"]["met"] is (manifest["calibration"]["missing_pairs"] == 0)
            else:
                assert collector["expectation"]["met"] is True
            assert collector["raw_time_range"] is not None, "an observation states the range it covers"
        else:
            assert collector["status_reason"]
        if collector["status"] in ("not_collected", "unsupported"):
            assert primary == [], "a source that was not read leaves no export, not an empty one"
            assert collector["raw_time_range"] is None
        if collector["status"] not in OBSERVED:
            # Only a capped export may survive a failed source, and it says so. The trace rule is the
            # same idea stated for a kernel trace: a saved trace (or the report made from it) is kept
            # when every event in it is real, with a status reason that names the loss, the cap or the
            # unconfirmed stop, so a decoder can never read it as a clean absence.
            if collector["kind"] in ("wpr", "xperf"):
                assert primary == [] or any(word in collector["status_reason"] for word in ("lost", "cap", "confirm", "unknown")), collector["id"]
            else:
                assert primary == [] or "cap" in collector["status_reason"], collector["id"]
        if collector["kind"] == "eventlog":
            options = collector["requested"]["options"]
            # rf-survey shares the dispatcher's budget across ten sources and defaults to 80 seconds per source.
            assert options["timeout_seconds"] == (80 if case.startswith("rf-survey") else 300)
            assert options["window_end_utc"] > options["window_start_utc"]
            query = (BUNDLES / case / "raw" / collector["id"] / "query.xml").read_text(encoding="utf-8")
            # The interval is fixed, not relative to now, and it is written as two @SystemTime comparisons:
            # the gaming PC rejected timediff(@SystemTime, <FILETIME>) at the first read (collectors/windows/README.md, item 35).
            assert "timediff" not in query, "the numeric timediff form fails on the PC at the first read"
            for select in ET.fromstring(query).iter("Select"):
                bound = re.search(r"TimeCreated\[@SystemTime >= '([^']+)' and @SystemTime <= '([^']+)'\]", select.text)
                assert bound, select.text
                for literal, recorded in zip(bound.groups(), (options["window_start_utc"], options["window_end_utc"])):
                    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", literal), literal
                    assert literal[:-1] + "0000Z" == recorded, (literal, recorded)
            if collector["raw_time_range"] is not None:
                assert collector["raw_time_range"]["end"] == options["window_end_utc"]
        elif collector["command"][0] == "Get-CimInstance" and "Win32_PnPEntity" not in collector["command"]:
            assert "-OperationTimeoutSec" in collector["command"] and "-Property" in collector["command"]
            if collector["requested"]["options"]["time_property"]:
                assert "-Filter" in collector["command"] and collector["requested"]["options"]["filter"].startswith("TimeGenerated >= '")
        elif collector["command"][0].endswith("netsh.exe"):
            assert ALLOWED_NETSH.fullmatch(" ".join(collector["command"][1:])), collector["command"]
            options = collector["requested"]["options"]
            assert options["protection"]["mac_pseudonym"].startswith("mac-") and options["protection"]["ssid_pseudonym"].startswith("ssid-")
            if collector["status"] in OBSERVED:
                assert collector["enabled"]["options"]["exit_code"] == 0
        elif collector["command"][0].endswith("powercfg.exe"):
            assert ALLOWED_POWERCFG.fullmatch(" ".join(collector["command"][1:])), collector["command"]
            assert collector["kind"] == "powercfg"
            if collector["status"] in OBSERVED:
                assert collector["enabled"]["options"]["exit_code"] == 0 and collector["enabled"]["options"]["records"] > 0
        elif collector["command"][0] == "System.IO.File.ReadAllBytes":
            assert collector["requested"]["options"]["path_documented"] is False
            mode = collector["requested"]["options"]["mode"]
            if mode == "summary":
                # The text of the WLAN report and of the vendor log never leaves the machine.
                assert collector["requested"]["options"]["protection"] is None
                if collector["status"] in OBSERVED:
                    assert primary[0]["path"].endswith("-summary.json") and collector["enabled"]["options"]["content_kept"] is False
            else:
                assert mode == "copy" and collector["requested"]["options"]["protection"]["user_pseudonym"].startswith("user-")
                if collector["status"] in OBSERVED:
                    assert collector["enabled"]["options"]["source_sha256"] and collector["enabled"]["options"]["content_kept"] is True
        elif collector["command"][0] == "System.IO.Directory.GetFiles":
            assert collector["requested"]["options"]["mode"] == "listing" and collector["requested"]["options"]["recursive"] is False
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/listing.json") and collector["enabled"]["options"]["content_kept"] is False
        elif "SetupDiOpenDevRegKey" in collector["command"]:
            # The device key API path: global scope, the hardware key, read access, the two fixed relative subkeys.
            assert collector["command"][5:9] == ["SetupDiOpenDevRegKey", "DICS_FLAG_GLOBAL", "DIREG_DEV", "KEY_READ"]
            assert collector["command"][10] == "Interrupt Management\\Affinity Policy;Interrupt Management\\MessageSignaledInterruptProperties"
            assert collector["requested"]["options"]["mode"] == "devices" and collector["requested"]["options"]["instance_prefixes"] == ["PCI\\"]
            assert collector["requested"]["options"]["resolver"]["access"] == "KEY_READ (0x20019)"
            assert "CurrentControlSet\\\\Enum" not in json.dumps(collector["requested"]["options"]), "no physical Enum path is named"
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/keys.json")
        elif "Microsoft.Win32.RegistryKey.GetValue" in collector["command"]:
            assert collector["requested"]["options"]["read_only"].startswith("keys are opened for reading")
            assert collector["requested"]["options"]["mode"] == "keys"
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/keys.json")
        elif collector["command"][0] == "kernel32.dll!GetLogicalProcessorInformationEx":
            assert collector["command"] == ["kernel32.dll!GetLogicalProcessorInformationEx", "RelationAll"]
            assert collector["requested"]["options"]["read_only"].startswith("a query")
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/topology.json") and collector["enabled"]["options"]["cores"] > 0
        elif collector["command"] == ["none"]:
            assert collector["id"] in UNAVAILABLE and collector["status"] == "not_collected"
            assert collector["preflight"]["ok"] is False and collector["requested"]["options"]["documented_paths"]
            assert primary == [] and collector["expectation"]["met"] is False
        elif collector["kind"] == "wpr":
            assert collector["command"][0].endswith("\\wpr.exe") and collector["command"][1] == "-start"
            assert collector["command"][2:6] == ["<bundle>/raw/wpr_trace/dpcisr-trace.wprp!WfDpcIsrTrace.Verbose", "-filemode", "-recordtempto", "<bundle>/private/temp"], "file mode, the recording under the private folder, no absolute path recorded"
            assert collector["command"][6] == "-instancename" and re.fullmatch(r"WfDpcIsrTrace-\d{8}T\d{6}Z", collector["command"][7]), "the session is scoped to the collector's own instance"
            session = json.loads((BUNDLES / case / "raw" / collector["id"] / "session.json").read_text(encoding="utf-8"))
            wpr_runs = [run for run in session["runs"] if run["tool"] == "wpr.exe"]
            verbs = ["-" + run["verb"] for run in wpr_runs]
            assert set(verbs) <= ALLOWED_WPR_VERBS, verbs
            assert verbs.count("-start") <= 1 and verbs.count("-stop") <= 1
            if "-start" in verbs:
                assert verbs[-1] == "-status", "every started session ends with a status check that confirms the stop"
                for run in wpr_runs[2:]:
                    assert run["arguments"].endswith(f"-instancename {session['instance_name']}"), run
            for run in session["runs"]:
                if run["tool"] == "tracerpt.exe":
                    assert ALLOWED_TRACERPT.fullmatch(run["arguments"]), run["arguments"]
            assert collector["buffers"] == {"size_kb": 1024, "count": 64, "mode": "file"}
            assert collector["requested"]["keywords"] == ["Interrupt", "DPC", "Loader"], "DPC and interrupt attribution only: no process, thread or scheduling events"
            assert session["trace_kept_in_bundle"] is False and not any(a["path"].endswith(".etl") for a in collector["artifacts"]), "the kernel trace never leaves the machine"
            if collector["status"] in OBSERVED:
                assert collector["events_lost"] == 0 and collector["buffers_lost"] == 0
                assert collector["enabled"]["keywords"] == collector["requested"]["keywords"]
                assert collector["enabled"]["options"]["session_confirmed_stopped"] is True
                assert primary[0]["path"].endswith("/tracerpt-summary.txt")
            if collector["status_reason"] and "lost" in collector["status_reason"] and "events" in collector["status_reason"]:
                assert (collector["events_lost"] or 0) + (collector["buffers_lost"] or 0) > 0
        elif collector["kind"] == "xperf":
            if collector["preflight"]["ok"]:
                assert collector["command"][0].endswith("\\xperf.exe")
                arguments = " ".join(collector["command"][1:])
                assert ALLOWED_XPERF.fullmatch(arguments), arguments
                assert ("-tle" in collector["command"]) is (collector["status"] == "capture_failed"), "tolerate lost events only after a loss, and then the report inherits the failure"
            else:
                assert primary == []
        elif collector["kind"] == "clock":
            assert collector["command"] == ["Stopwatch.GetTimestamp", "DateTime.UtcNow.ToFileTimeUtc", "Stopwatch.GetTimestamp"], "the contract's read order"
            options = collector["requested"]["options"]
            assert options["interval_seconds"] == 5 and 10 <= options["duration_seconds"] <= 840
            assert options["timeout_seconds"] == options["duration_seconds"] + 60
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/samples.jsonl")
                assert collector["enabled"]["options"]["qpc_high_resolution"] is True
                assert collector["enabled"]["options"]["pairs_taken"] >= 2
                assert collector["enabled"]["options"]["stop_pair_taken"] is (manifest["calibration"]["missing_pairs"] == 0 or case == "clock-calibration-missed-slot")
            else:
                assert "fewer than two" in collector["status_reason"] or "not kept" in collector["status_reason"]
        elif collector["id"] == "operator_marks":
            assert collector["command"][0] == "clock-calibration.ps1" and "-Mark" in collector["command"]
            if collector["status"] in OBSERVED:
                assert primary[0]["path"].endswith("/marks.jsonl") and collector["enabled"]["options"]["closed"] is True
        else:
            assert "Win32_PnPEntity" in collector["command"] and "Get-PnpDeviceProperty" in collector["command"]
        config = [a for a in collector["artifacts"] if a["role"] == "config"]
        assert len(config) == 1 and collector["config_hash"] == {"algorithm": "sha256", "value": config[0]["sha256"]}


def test_the_netsh_allowlist_rejects_both_report_spellings_and_every_action():
    for forbidden in ("wlan wlanreport", "wlan show wlanreport", "wlan connect x", "wlan disconnect", "wlan refresh hostednetwork", "wlan reportissues", "wlan show networks"):
        assert not ALLOWED_NETSH.fullmatch(forbidden), forbidden
    for allowed in ("wlan show interfaces", "wlan show drivers", "wlan show networks mode=bssid", "wlan show profiles"):
        assert ALLOWED_NETSH.fullmatch(allowed), allowed


def test_the_powercfg_allowlist_rejects_every_verb_that_writes_or_reports():
    for forbidden in ("/setactive x", "/setacvalueindex a b c 1", "/change monitor-timeout-ac 5", "/energy", "/requests", "/import x", "/export x y",
                      "/hibernate off", "/delete x", "/overlaysetactive x", "/query x", "/q", "/l", "/L"):
        assert not ALLOWED_POWERCFG.fullmatch(forbidden), forbidden
    for allowed in ("/list", "/getactivescheme", "/aliases", "/query", "/qh"):
        assert ALLOWED_POWERCFG.fullmatch(allowed), allowed


@pytest.mark.parametrize("case", CASES)
def test_observed_zero_is_an_empty_export_inside_a_covered_range(case):
    bundle = BUNDLES / case
    for collector in load_manifest(case)["collectors"]:
        primary = [a for a in collector["artifacts"] if a["role"] == "primary"]
        if not primary:
            continue
        text = (bundle / primary[0]["path"]).read_text(encoding="utf-8")
        if primary[0]["path"].endswith("-summary.json"):
            # The file source's summary: one object about the file, never its text, never empty.
            summary = json.loads(text)
            assert summary["content_kept"] is False and summary["bytes"] > 0 and len(summary["sha256"]) == 64
            assert collector["status"] == "observed"
        elif primary[0]["path"].endswith("/listing.json"):
            # The directory source: an array of files; the folder's own facts are in result.json, and a folder that does not
            # exist is a zero with exists false there.
            files = json.loads(text)
            report = json.loads((bundle / "raw" / collector["id"] / "result.json").read_text(encoding="utf-8"))
            assert isinstance(files, list) and report["exists"] in (True, False) and report["parent_exists"] is True
            if collector["status"] == "observed_zero":
                assert files == []
            if collector["status"] == "observed":
                assert files and report["exists"] is True
        elif collector["requested"]["options"].get("mode") == "copy":
            # A copied text file: never empty, and the hash of the original is next to it.
            assert text.strip() and collector["status"] == "observed"
            report = json.loads((bundle / "raw" / collector["id"] / "result.json").read_text(encoding="utf-8"))
            assert len(report["source_sha256"]) == 64 and report["copied"] is True
        elif primary[0]["path"].endswith(".json"):
            records = json.loads(text)
            assert isinstance(records, list)
            if collector["status"] == "observed_zero":
                assert records == []
            if collector["status"] == "observed":
                assert records
        elif primary[0]["path"].endswith("/tracerpt-summary.txt"):
            assert "Lost" in text, "the summary carries the final loss figures"
        elif primary[0]["path"].endswith("/dpcisr.txt"):
            assert "DPC Info" in text and "Interrupt Info" in text
        elif primary[0]["path"].endswith(".jsonl"):
            # JSON lines (the clock collector): one object per line, zero lines for observed_zero.
            lines = [json.loads(line) for line in text.splitlines() if line.strip()]
            assert all(isinstance(line, dict) for line in lines)
            if collector["status"] == "observed_zero":
                assert lines == [] and text == ""
            if collector["status"] == "observed":
                assert lines
        else:
            # A netsh output: text, kept whole, never empty.
            assert text.strip(), "a text primary is never empty"
            assert collector["enabled"]["options"]["records"] == 0 if collector["status"] == "observed_zero" else True
        if collector["status"] in OBSERVED:
            requested = collector["requested"]["options"].get("window_start_utc")
            covered = collector["raw_time_range"]["start"]
            if requested is not None:
                assert covered >= requested, "the covered range never starts before the requested window"
                assert collector["enabled"]["options"]["window_start_utc"] == covered


def test_a_short_log_narrows_the_covered_range():
    manifest = load_manifest("application-errors")
    source = manifest["collectors"][0]
    state = json.loads((BUNDLES / "application-errors" / "raw" / source["id"] / "channel_state.json").read_text(encoding="utf-8"))
    assert source["raw_time_range"]["start"] == state["state"]["oldest_record_time_utc"]
    assert source["raw_time_range"]["start"] > source["requested"]["options"]["window_start_utc"]
    assert any("only holds records from" in note for note in manifest["notes"])


def test_an_unreadable_channel_is_a_status_and_never_an_absence():
    manifest = load_manifest("bugcheck-history-access-denied")
    source = manifest["collectors"][0]
    assert source["status"] == "not_collected" and "unauthorized" in source["status_reason"]
    assert source["preflight"]["ok"] is False
    assert {a["role"] for a in source["artifacts"]} == {"config", "report"}
    assert not (BUNDLES / "bugcheck-history-access-denied" / "raw" / source["id"] / "events.json").exists()


def test_the_undocumented_display_provider_never_yields_a_quiet_window():
    manifest = load_manifest("tdr-events-partial")
    display = next(c for c in manifest["collectors"] if c["id"] == "system_display_events")
    assert display["status"] == "capture_failed" and display["required"] is False
    assert "verification step" in display["status_reason"]
    assert display["expectation"]["met"] is False
    assert sorted(a["role"] for a in display["artifacts"]) == ["config", "report"], "no empty events.json is left behind"
    assert not (BUNDLES / "tdr-events-partial" / "raw" / "system_display_events" / "events.json").exists()


def dmtf(iso: str) -> str:
    return iso[:4] + iso[5:7] + iso[8:10] + iso[11:13] + iso[14:16] + iso[17:19] + "." + iso[20:26] + "+000"


def test_reliability_window_is_pushed_into_the_filter_with_a_coverage_probe():
    manifest = load_manifest("reliability-records")
    records = next(c for c in manifest["collectors"] if c["id"] == "reliability_records")
    options = records["requested"]["options"]
    assert options["filter"] == f"TimeGenerated >= '{dmtf(options['window_start_utc'])}' AND TimeGenerated <= '{dmtf(options['window_end_utc'])}'"
    assert options["coverage_probe_filter"] == f"TimeGenerated < '{dmtf(options['window_start_utc'])}'"
    assert records["enabled"]["options"]["coverage_probe"] is True
    assert "coverage probe found 1 record" in records["expectation"]["detail"]
    assert records["raw_time_range"]["start"] == options["window_start_utc"]
    query = json.loads((BUNDLES / "reliability-records" / "raw" / "reliability_records" / "query.json").read_text(encoding="utf-8"))
    assert query["properties"] == ["ComputerName", "EventIdentifier", "InsertionStrings", "Logfile", "Message", "ProductName",
                                   "RecordNumber", "SourceName", "TimeGenerated", "User"]


# ---------------------------------------------------------------- decoding

EVENT_CASES = [c for c in CASES if any(col["kind"] == "eventlog" for col in load_manifest(c)["collectors"])]


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str) -> Path:
        dst = tmp_path / case
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


@pytest.mark.parametrize("case", EVENT_CASES)
def test_event_exports_decode_into_eventlog_events(case, bundle_copy):
    bundle = bundle_copy(case)
    manifest = load_manifest(case)
    result = decode_eventlog.decode(bundle, decoded_at="2026-09-03T00:00:00Z")
    readable = [c for c in manifest["collectors"] if c["kind"] == "eventlog" and c["status"] in OBSERVED]
    if not readable:
        assert result["status"] == "not_collected" and result["rows"] == 0
        assert not (bundle / "decoded").exists(), "an absent input is not decoded into an empty table"
        return
    rows = wf_schema.read_jsonl(bundle / "decoded" / "eventlog_events.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/eventlog_events.schema.json") == []
    meta = json.loads((bundle / "decoded" / "eventlog_events.meta.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["row_count"] == len(rows) == result["rows"]
    listed = {a["path"]: a for c in manifest["collectors"] for a in c["artifacts"]}
    assert [s["path"] for s in meta["source_files"]] == [a["path"] for c in readable for a in c["artifacts"] if a["role"] == "primary"]
    for src in meta["source_files"]:
        assert listed[src["path"]]["sha256"] == src["sha256"]
    raw = {s["path"]: json.loads((bundle / s["path"]).read_text(encoding="utf-8")) for s in meta["source_files"]}
    assert len(rows) == sum(len(v) for v in raw.values())
    assert meta["status"] == ("observed" if rows else "observed_zero")
    for row in rows:
        prov = row["provenance"]
        index, record = re.fullmatch(r"index:(\d+);record:(\d+)", prov["row_id_or_offset"]).groups()
        element = raw[prov["source_file"]][int(index)]
        assert element["record_id"] == int(record) == row["record_id"]
        assert element["time_created_utc"] == row["time_created_utc"]
        assert f"<EventRecordID>{record}</EventRecordID>" in element["xml"], "the raw element keeps the full event XML"
        assert "xml" not in row
    # The decoded table is part of the container: the bundle still verifies with it present.
    assert verify_bundle.verify(bundle)["ok"]


def test_decoder_refuses_an_export_whose_xml_disagrees(bundle_copy):
    bundle = bundle_copy("bugcheck-history")
    path = bundle / "raw" / "system_restart_events" / "events.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    events[0]["record_id"] += 1
    path.write_text(json.dumps(events), encoding="utf-8")
    result = decode_eventlog.decode(bundle, sources=["raw/system_restart_events/events.json"], decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "decode_failed" and "its XML says" in result["reason"]
    assert wf_schema.read_jsonl(bundle / "decoded" / "eventlog_events.jsonl") == []


def test_decoder_refuses_inputs_it_cannot_vouch_for(bundle_copy):
    bundle = bundle_copy("tdr-events-partial")
    good = "raw/system_bugcheck_events/events.json"
    assert decode_eventlog.decode(bundle, sources=[good], decoded_at="2026-09-03T00:00:00Z")["status"] == "observed_zero"
    shutil.rmtree(bundle / "decoded")
    (bundle / "raw" / "system_bugcheck_events" / "unlisted.json").write_text("[]", encoding="utf-8")
    cases = {
        "raw/system_bugcheck_events/missing.json": "not listed",
        "raw/../raw/system_bugcheck_events/events.json": "not a normalised path",
        "../outside.json": "not a normalised path",
        "/etc/passwd": "not a bundle relative path",
        "raw/system_bugcheck_events/channel_state.json": "not listed",
        "raw/system_display_events/events.json": "not listed",
        "raw/system_bugcheck_events/unlisted.json": "not listed",
    }
    for source, reason in cases.items():
        result = decode_eventlog.decode(bundle, sources=[source], decoded_at="2026-09-03T00:00:00Z")
        assert result["status"] == "decode_failed" and reason in result["reason"], (source, result)
        assert not (bundle / "decoded").exists(), source
    # A listed primary that the bundle lacks fails too, whether named explicitly or found through the manifest.
    (bundle / good).unlink()
    for sources in ([good], None):
        result = decode_eventlog.decode(bundle, sources=sources, decoded_at="2026-09-03T00:00:00Z")
        assert result["status"] == "decode_failed" and "missing from the bundle" in result["reason"]
        assert not (bundle / "decoded").exists()
    nowhere = bundle / "nowhere"
    assert decode_eventlog.decode(nowhere, decoded_at="2026-09-03T00:00:00Z")["status"] == "decode_failed"
    assert not nowhere.exists()


def test_decoder_orders_the_native_range_by_parsed_time(bundle_copy):
    bundle = bundle_copy("bugcheck-history")
    path = bundle / "raw" / "system_restart_events" / "events.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    # As text "...00Z" sorts after "...00.5Z"; as time it is earlier.
    events[0]["time_created_utc"] = "2026-02-17T00:00:00Z"
    events[1]["time_created_utc"] = "2026-02-17T00:00:00.5Z"
    events[2]["time_created_utc"] = "2026-02-17T00:00:00.4999999Z"
    events[3]["time_created_utc"] = "2026-02-17T00:00:00.5000001Z"
    path.write_text(json.dumps(events), encoding="utf-8")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["collectors"][0]["artifacts"]:
        if artifact["path"].endswith("events.json"):
            artifact["bytes"], artifact["sha256"] = path.stat().st_size, wf_schema.sha256_of(path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_eventlog.decode(bundle, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "observed", result
    meta = json.loads((bundle / "decoded" / "eventlog_events.meta.json").read_text(encoding="utf-8"))
    assert meta["native_time_range"]["start"] == "2026-02-17T00:00:00Z"
    assert meta["native_time_range"]["end"] == "2026-02-17T00:00:00.5000001Z"
    events[0]["time_created_utc"] = "17/02/2026 00:00"
    path.write_text(json.dumps(events), encoding="utf-8")
    for artifact in manifest["collectors"][0]["artifacts"]:
        if artifact["path"].endswith("events.json"):
            artifact["bytes"], artifact["sha256"] = path.stat().st_size, wf_schema.sha256_of(path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_eventlog.decode(bundle, sources=["raw/system_restart_events/events.json"], decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "decode_failed" and "not ISO 8601 UTC" in result["reason"]


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_eventlog.main(["--bundle", str(bundle_copy("bugcheck-history")), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    assert "4 rows from 1 exports, status observed" in capsys.readouterr().out
    assert decode_eventlog.main(["--bundle", str(bundle_copy("bugcheck-history-access-denied"))]) == 2


# ---------------------------------------------------------------- verification

def test_verify_bundle_catches_a_changed_artifact_and_an_unlisted_file(bundle_copy):
    bundle = bundle_copy("bugcheck-history")
    assert verify_bundle.main([str(bundle)]) == 0
    events = bundle / "raw" / "system_restart_events" / "events.json"
    events.write_text(events.read_text(encoding="utf-8").replace("6008", "6009"), encoding="utf-8")
    (bundle / "raw" / "system_restart_events" / "extra.txt").write_text("not in the manifest", encoding="utf-8")
    result = verify_bundle.verify(bundle)
    failed = {c["name"] for c in result["checks"] if not c["ok"]}
    assert failed == {"artifacts_match_manifest", "no_unlisted_raw_file"}
    assert verify_bundle.main([str(bundle)]) == 1


def test_verify_bundle_rejects_a_missing_or_invalid_manifest(tmp_path, bundle_copy):
    assert verify_bundle.verify(tmp_path)["ok"] is False
    bundle = bundle_copy("whea-errors-quiet")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["collectors"][0]["status"] = "quiet"
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_bundle.verify(bundle)
    assert result["ok"] is False and result["checks"][0]["name"] == "manifest_schema"


# ---------------------------------------------------------------- WMI exports

def test_driver_rows_fit_the_config_snapshot_table():
    """The driver export is shaped so a later decoder can emit config_snapshot rows of category driver."""
    manifest = load_manifest("driver-inventory")
    source = next(c for c in manifest["collectors"] if c["id"] == "pnp_signed_drivers")
    path = next(a["path"] for a in source["artifacts"] if a["role"] == "primary")
    records = json.loads((BUNDLES / "driver-inventory" / path).read_text(encoding="utf-8"))
    rows = []
    for index, record in enumerate(records):
        if record["DriverVersion"] is None:
            continue
        rows.append({
            "category": "driver", "key": "driver_version", "value_text": record["DriverVersion"],
            "source_command": " ".join(source["command"]), "captured_at_utc": source["raw_time_range"]["start"],
            "device_instance_id": record["DeviceID"], "device_name": record["DeviceName"],
            "provenance": {"source_file": path, "row_id_or_offset": f"index:{index}", "decoded_table": "config_snapshot",
                           "decoder_version": "0.0.0", "schema_version": wf_schema.table_schema_version("config_snapshot")},
        })
    assert len(rows) == 2
    assert wf_schema.validate_rows(rows, "decoded/config_snapshot.schema.json") == []
    assert manifest["machine"]["drivers"] == [
        {"name": r["DeviceName"], "version": r["DriverVersion"], "provider": r["DriverProviderName"], "class": r["DeviceClass"]}
        for r in records if r["DeviceName"]
    ]


def test_reliability_export_keeps_wmi_names_and_utc_times():
    records = json.loads((BUNDLES / "reliability-records" / "raw" / "reliability_records" / "records.json").read_text(encoding="utf-8"))
    iso = re.compile(wf_schema.schema("common.schema.json")["$defs"]["iso_utc"]["pattern"])
    assert [r["RecordNumber"] for r in records] == [4800, 5120], "only records inside the window, oldest first"
    for record in records:
        assert set(record) == {"ComputerName", "EventIdentifier", "InsertionStrings", "Logfile", "Message", "ProductName",
                               "RecordNumber", "SourceName", "TimeGenerated", "User"}
        assert iso.match(record["TimeGenerated"]) and isinstance(record["InsertionStrings"], list)
