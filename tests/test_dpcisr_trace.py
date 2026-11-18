"""The live DPC and interrupt capture: its synthetic bundles, the trace loss table, and the per CPU report.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a clean session with a pinned
xperf whose report puts the invented graphics driver on CPU 6; the same session without an xperf; a
session whose saved trace lost events (shown by the final tracerpt summary, not by the live status);
and the account the front door uses today, which is not elevated. Nothing here comes from a real
machine: the recorder, the trace bytes, the summary and the report are all synthetic, and no trace
file is ever part of a bundle.
"""
from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
import pytest

import decode_dpcisr
import decode_tracestats
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
COLLECTOR = REPO_ROOT / "collectors" / "windows" / "dpcisr-trace.ps1"
CASES = ["dpcisr-trace", "dpcisr-trace-no-xperf", "dpcisr-trace-events-lost", "dpcisr-trace-not-elevated"]
KEYWORDS = ["Interrupt", "DPC", "Loader"]
REPORT = "raw/dpcisr_report/dpcisr.txt"
STATUS = "raw/wpr_trace/status.txt"
SUMMARY = "raw/wpr_trace/tracerpt-summary.txt"
AT = "2026-09-03T00:00:00Z"


def manifest(case: str) -> dict:
    return json.loads((BUNDLES / case / "manifest.json").read_text(encoding="utf-8"))


def source(case: str, source_id: str) -> dict:
    return next(c for c in manifest(case)["collectors"] if c["id"] == source_id)


def session(case: str) -> dict:
    return json.loads((BUNDLES / case / "raw/wpr_trace/session.json").read_text(encoding="utf-8"))


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str) -> Path:
        dst = tmp_path / case
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


# ---------------------------------------------------------------- the profile and the privacy rule

@pytest.mark.parametrize("case", CASES)
def test_the_profile_is_the_committed_one_and_hashed_as_the_config(case):
    """The profile WPR ran is in the bundle byte for byte, well formed, with the three keywords and no stacks."""
    bundle = BUNDLES / case
    trace = source(case, "wpr_trace")
    config = [a for a in trace["artifacts"] if a["role"] == "config"]
    assert [a["path"] for a in config] == ["raw/wpr_trace/dpcisr-trace.wprp"]
    assert trace["config_hash"] == {"algorithm": "sha256", "value": config[0]["sha256"]}
    root = ET.parse(bundle / config[0]["path"]).getroot()
    assert root.tag == "WindowsPerformanceRecorder" and root.get("Version") == "1.0" and root.get("Author")
    profiles = root.find("Profiles")
    collector = profiles.find("SystemCollector")
    assert collector.get("Name") == "NT Kernel Logger"
    assert collector.find("BufferSize").get("Value") == "1024" and collector.find("Buffers").get("Value") == "64"
    provider = profiles.find("SystemProvider")
    assert [k.get("Value") for k in provider.find("Keywords")] == KEYWORDS
    assert provider.find("Stacks") is None, "no stack walking: nothing here needs it and it multiplies the volume"
    for forbidden in ("ProcessThread", "CSwitch", "ReadyThread", "SampledProfile"):
        assert forbidden not in [k.get("Value") for k in provider.find("Keywords")], "process, thread and scheduling events carry command lines and user ids"
    defined = profiles.findall("Profile")
    assert [p.get("LoggingMode") for p in defined] == ["File", "Memory"], "a .wprp defines both logging modes"
    assert {p.get("Name") for p in defined} == {"WfDpcIsrTrace"}
    for profile in defined:
        assert profile.get("Id") == f"WfDpcIsrTrace.{profile.get('DetailLevel')}.{profile.get('LoggingMode')}"
        assert profile.find("Collectors/SystemCollectorId").get("Value") == collector.get("Id")
        assert profile.find("Collectors/SystemCollectorId/SystemProviderId").get("Value") == provider.get("Id")
    assert trace["requested"]["keywords"] == KEYWORDS
    assert trace["requested"]["providers"] == ["NT Kernel Logger"]


@pytest.mark.parametrize("case", CASES)
def test_no_trace_and_no_private_folder_ever_reaches_a_bundle(case):
    bundle = BUNDLES / case
    assert sorted(p.name for p in bundle.iterdir()) == ["logs", "manifest.json", "raw"]
    assert not list(bundle.rglob("*.etl")) and not (bundle / "private").exists()
    trace = source(case, "wpr_trace")
    assert not any(a["path"].endswith(".etl") for a in trace["artifacts"])
    assert trace["requested"]["options"]["trace_kept_in_bundle"] is False
    assert trace["requested"]["options"]["trace_path"] == "<bundle>/private/trace.etl"
    s = session(case)
    assert s["trace_kept_in_bundle"] is False and "never leaves the machine" in s["trace_removed_reason"]
    log = (bundle / "logs" / "collector.log").read_text(encoding="utf-8")
    if s["trace_bytes"]:
        assert "private directory removed" in log and len(s["trace_sha256"]) == 64
        assert trace["enabled"]["options"]["trace_sha256"] == s["trace_sha256"]


# ---------------------------------------------------------------- status and loss

def test_a_clean_session_is_observed_with_zero_final_loss_verified_from_the_tools():
    trace = source("dpcisr-trace", "wpr_trace")
    assert trace["status"] == "observed" and trace["events_lost"] == 0 and trace["buffers_lost"] == 0
    assert trace["enabled"]["keywords"] == KEYWORDS and trace["enabled"]["providers"] == ["NT Kernel Logger"]
    assert "tracerpt" in trace["enabled"]["verified_by"] and "-instancename" in trace["enabled"]["verified_by"]
    options = trace["enabled"]["options"]
    assert options["session_confirmed_stopped"] is True and options["session_state_final"] == "idle"
    assert options["final_events_lost"] == 0 and options["final_buffers_lost"] == 0
    assert re.fullmatch(r"WfDpcIsrTrace-\d{8}T\d{6}Z", options["instance_name"])
    assert 10 <= options["recording_seconds"] < 13, "the requested ten seconds bound the recording"
    assert trace["raw_time_range"] == {"start": options["session_started_utc"], "end": options["session_stop_issued_utc"], "domain": "system_time", "unit": "iso_utc"}
    assert trace["expectation"]["met"] is True
    assert [a["path"] for a in trace["artifacts"] if a["role"] == "primary"] == [SUMMARY]
    status = (BUNDLES / "dpcisr-trace" / STATUS).read_text(encoding="utf-8")
    assert re.search(r"^Events Lost\s+: 0$", status, re.M) and re.search(r"^Dropped event\s+: 0$", status, re.M)
    summary = (BUNDLES / "dpcisr-trace" / SUMMARY).read_text(encoding="utf-8")
    assert re.search(r"Events\s+Lost\s+0$", summary, re.M) and re.search(r"Buffers Lost\s+0$", summary, re.M)
    s = session("dpcisr-trace")
    assert [(r["tool"], r["verb"]) for r in s["runs"]] == [("wpr.exe", "status"), ("wpr.exe", "profiles"), ("wpr.exe", "start"), ("wpr.exe", "status"), ("wpr.exe", "stop"), ("wpr.exe", "status"), ("tracerpt.exe", None)]
    for run in s["runs"][2:6]:
        assert run["arguments"].endswith(f"-instancename {s['instance_name']}"), "every call on the session names the collector's own instance, last"
    assert s["runs"][0]["arguments"] == "-status", "the preflight looks at the default instance"
    assert s["events_lost_bound"] == 0 and s["buffers_lost_bound"] == 0 and s["stopped_early_at_cap"] is False
    assert s["worst_case_seconds"] == 10 + 2 * 120 + 5 * 30
    assert s["settings_verified"] is True


def test_a_lossy_trace_is_failed_by_the_final_figures_even_when_the_live_status_showed_none():
    trace = source("dpcisr-trace-events-lost", "wpr_trace")
    assert trace["status"] == "capture_failed" and trace["events_lost"] == 544 and trace["buffers_lost"] == 0
    assert "lost 544 events and 0 buffers" in trace["status_reason"] and "never the whole window" in trace["status_reason"]
    assert trace["enabled"]["options"]["events_lost_after_start"] == 0, "the live snapshot said nothing was lost"
    assert [a["path"] for a in trace["artifacts"] if a["role"] == "primary"] == [SUMMARY], "the summary that shows the loss is kept"
    report = source("dpcisr-trace-events-lost", "dpcisr_report")
    assert report["status"] == "capture_failed" and "-tle" in report["command"] and "with -tle" in report["status_reason"]
    assert report["raw_time_range"] == trace["raw_time_range"]
    assert any("lower bound" in note for note in manifest("dpcisr-trace-events-lost")["notes"])


def test_the_front_door_account_cannot_start_a_kernel_trace_and_nothing_runs():
    trace = source("dpcisr-trace-not-elevated", "wpr_trace")
    assert trace["status"] == "not_collected" and "not elevated" in trace["status_reason"]
    assert trace["preflight"]["ok"] is False
    assert [c["name"] for c in trace["preflight"]["checks"]] == ["tool_present", "tracerpt_present", "account_elevated"], "no wpr call before the account check"
    assert trace["artifacts"] and all(a["role"] in ("config", "report") for a in trace["artifacts"])
    assert trace["events_lost"] is None and trace["buffers_lost"] is None and trace["raw_time_range"] is None
    assert session("dpcisr-trace-not-elevated")["runs"] == []
    report = source("dpcisr-trace-not-elevated", "dpcisr_report")
    assert report["status"] == "not_collected" and "no trace" in report["status_reason"]


def test_without_an_xperf_the_report_says_the_trace_cannot_leave_the_machine():
    report = source("dpcisr-trace-no-xperf", "dpcisr_report")
    assert report["status"] == "not_collected" and "-XperfPath was not given" in report["status_reason"]
    assert "never leaves" in report["status_reason"]
    assert [c["name"] for c in report["preflight"]["checks"]] == ["trace_present", "tool_named"]
    assert source("dpcisr-trace-no-xperf", "wpr_trace")["status"] == "observed"
    assert "xperf" not in [t["name"] for t in manifest("dpcisr-trace-no-xperf")["tools"]]


def test_the_pinned_tool_is_recorded_with_its_hash_before_and_after_the_run():
    report = source("dpcisr-trace", "dpcisr_report")
    config = json.loads((BUNDLES / "dpcisr-trace" / "raw/dpcisr_report/command.json").read_text(encoding="utf-8"))
    result = json.loads((BUNDLES / "dpcisr-trace" / "raw/dpcisr_report/result.json").read_text(encoding="utf-8"))
    tool = next(t for t in manifest("dpcisr-trace")["tools"] if t["name"] == "xperf")
    assert config["pinned_builds"][0]["sha256"] == tool["sha256"] == report["enabled"]["options"]["tool_sha256"] == result["tool_sha256_after_run"]
    assert config["pinned_builds"][0]["version"] == tool["version"] == report["enabled"]["options"]["tool_version"]
    assert config["trace"] == "<bundle>/private/trace.etl" and config["trace_events_lost"] == 0 and config["trace_buffers_lost"] == 0
    assert config["trace_sha256"] == source("dpcisr-trace", "wpr_trace")["enabled"]["options"]["trace_sha256"]
    assert "pinned" in config["tool_source"] and "not inbox" in config["tool_source"]
    assert report["raw_time_range"] == source("dpcisr-trace", "wpr_trace")["raw_time_range"], "the report's range is the trace's window, not the xperf run"


# ---------------------------------------------------------------- tracestats

@pytest.mark.parametrize("case", CASES)
def test_the_statistics_decode_into_tracestats_and_agree_with_the_manifest(case, bundle_copy):
    bundle = bundle_copy(case)
    trace = source(case, "wpr_trace")
    result = decode_tracestats.decode(bundle, decoded_at=AT)
    paths = {a["path"] for a in trace["artifacts"]}
    if not ({STATUS, SUMMARY} & paths):
        assert result["status"] == "not_collected" and not (bundle / "decoded").exists()
        return
    assert result["status"] == "observed", result
    rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/tracestats.schema.json") == []
    meta = json.loads((bundle / "decoded" / "tracestats.meta.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["time_domain"] == "system_time" and meta["row_count"] == len(rows) == result["rows"]
    assert [s["path"] for s in meta["source_files"]] == sorted({STATUS, SUMMARY} & paths)
    for src in meta["source_files"]:
        assert src["sha256"] == next(a["sha256"] for a in trace["artifacts"] if a["path"] == src["path"])
    assert decode_tracestats.events_lost_of(rows) == trace["events_lost"], "the contract: the table's final events lost equals the manifest's"
    assert decode_tracestats.buffers_lost_of(rows) == trace["buffers_lost"]
    assert all(c["ok"] for c in meta["checks"]), meta["checks"]
    sections = {r["section"] for r in rows if r["normalized_key"] == "events_lost"}
    assert sections == {"recording", "NT Kernel Logger", "summary"}, "the live snapshot and the final figure are both rows, told apart by section"
    buffer = next(r for r in rows if r["normalized_key"] == "buffer_size_kb")
    assert buffer["value_number"] == 1024 and buffer["key"] == "Buffer Size (KB)"
    assert [r["value_text"] for r in rows if r["key"] == "System Keywords"] == KEYWORDS
    for row in rows:
        lines = (bundle / row["provenance"]["source_file"]).read_text(encoding="utf-8").splitlines()
        line = lines[int(row["provenance"]["row_id_or_offset"].removeprefix("line:")) - 1]
        assert row["value_text"] in line
    assert verify_bundle.verify(bundle)["ok"]


def test_tracestats_never_turns_an_unreadable_loss_into_zero(bundle_copy):
    bundle = bundle_copy("dpcisr-trace")
    summary = bundle / SUMMARY
    text = summary.read_text(encoding="utf-8")
    for bad in ("n/a", "1,234", ""):
        broken = re.sub(r"^(Total Events\s+Lost\s+)\d+$", lambda m: m.group(1) + bad, text, flags=re.M)
        assert broken != text
        summary.write_text(broken, encoding="utf-8")
        shutil.rmtree(bundle / "decoded", ignore_errors=True)
        result = decode_tracestats.decode(bundle, decoded_at=AT)
        rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
        assert decode_tracestats.events_lost_of(rows) is None, bad
        assert result["status"] == "decode_failed", bad
        meta = json.loads((bundle / "decoded" / "tracestats.meta.json").read_text(encoding="utf-8"))
        assert not next(c for c in meta["checks"] if c["name"] == "wpr_trace_final_events_lost_present")["ok"]
    # A summary without the buffers line fails the same way.
    summary.write_text("\n".join(l for l in text.splitlines() if "Buffers Lost" not in l) + "\n", encoding="utf-8")
    shutil.rmtree(bundle / "decoded")
    result = decode_tracestats.decode(bundle, decoded_at=AT)
    rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
    assert decode_tracestats.buffers_lost_of(rows) is None and result["status"] == "decode_failed"


def test_tracestats_refuses_a_disagreement_and_inputs_it_cannot_vouch_for(bundle_copy):
    bundle = bundle_copy("dpcisr-trace-events-lost")
    good = decode_tracestats.decode(bundle, decoded_at=AT)
    assert good["status"] == "observed"
    rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
    assert decode_tracestats.events_lost_of(rows) == 544
    shutil.rmtree(bundle / "decoded")
    path = bundle / "manifest.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    next(c for c in tampered["collectors"] if c["id"] == "wpr_trace")["events_lost"] = 0
    path.write_text(json.dumps(tampered), encoding="utf-8")
    result = decode_tracestats.decode(bundle, decoded_at=AT)
    assert result["status"] == "decode_failed"
    meta = json.loads((bundle / "decoded" / "tracestats.meta.json").read_text(encoding="utf-8"))
    assert not next(c for c in meta["checks"] if c["name"] == "wpr_trace_events_lost_matches_manifest")["ok"]
    shutil.rmtree(bundle / "decoded")
    for bad, reason in {"raw/wpr_trace/session.json": "not listed", "raw/../raw/wpr_trace/status.txt": "not a normalised",
                        "/etc/passwd": "not a bundle relative path", "raw/dpcisr_report/dpcisr.txt": "not listed"}.items():
        result = decode_tracestats.decode(bundle, sources=[bad], decoded_at=AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (bad, result)
        assert not (bundle / "decoded").exists()
    # The status text alone has no final figure: the table cannot satisfy the contract from it.
    result = decode_tracestats.decode(bundle, sources=[STATUS], decoded_at=AT)
    assert result["status"] == "decode_failed"
    assert decode_tracestats.decode(bundle_copy("dpcisr-trace-not-elevated"), decoded_at=AT)["status"] == "not_collected"


def test_tracestats_cli(bundle_copy, capsys):
    assert decode_tracestats.main(["--bundle", str(bundle_copy("dpcisr-trace")), "--decoded-at", AT]) == 0
    out = capsys.readouterr().out
    assert out.startswith("tracestats: ") and "status observed" in out
    assert decode_tracestats.main(["--bundle", str(bundle_copy("dpcisr-trace-not-elevated"))]) == 2


# ---------------------------------------------------------------- the per CPU report

@pytest.mark.parametrize("case", ["dpcisr-trace", "dpcisr-trace-events-lost"])
def test_the_report_decodes_per_cpu_and_per_module(case, bundle_copy):
    bundle = bundle_copy(case)
    result = decode_dpcisr.decode(bundle, REPORT, decoded_at=AT)
    assert result["status"] == "observed", result
    rows = wf_schema.read_jsonl(bundle / "decoded" / "dpcisr_module_cpu.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/dpcisr_module_cpu.schema.json") == []
    df = pd.DataFrame(rows)
    assert sorted(df["cpu"].unique()) == list(range(16)), "every CPU number survives into the table"
    for kind, group in df.groupby("kind"):
        assert len(group) == group["module"].nunique() * 16, f"{kind}: one row per module per CPU, zeros included"
    gfx = df[(df["kind"] == "dpc") & (df["module"] == "synthgfx.sys")].set_index("cpu")["usec"]
    assert gfx[6] > 0 and (gfx.drop(6) == 0).all(), "the invented GPU driver's DPC time sits on one CPU, and the table shows which"
    kernel = df[(df["kind"] == "isr") & (df["module"] == "ntoskrnl.exe")]
    assert (kernel["usec"] > 0).all(), "a module spread over every CPU keeps one row per CPU"
    intervals = wf_schema.read_jsonl(bundle / "decoded" / "dpcisr_interval.jsonl")
    assert wf_schema.validate_rows(intervals, "decoded/dpcisr_interval.schema.json") == []
    idf = pd.DataFrame(intervals)
    assert idf["cpu"].nunique() == 16 and idf["interval_end_ms"].max() == 10000
    meta = json.loads((bundle / "decoded" / "dpcisr_module_cpu.meta.json").read_text(encoding="utf-8"))
    status_check = next(c for c in meta["checks"] if c["name"] == "collector_status")
    collector = source(case, "dpcisr_report")
    assert status_check["ok"] is (collector["status"] == "observed")
    assert collector["status"] in status_check["detail"]
    if collector["status"] == "capture_failed":
        assert "lost 544 events" in status_check["detail"], "the loss travels with the decoded table through its sidecar"
    assert meta["status"] == "observed", "the decoder's own status says it emitted rows; the collector's status is the manifest's"
    assert verify_bundle.verify(bundle)["ok"]


def test_the_report_decoder_refuses_a_source_the_manifest_does_not_vouch_for(bundle_copy):
    bundle = bundle_copy("dpcisr-trace")
    (bundle / "raw" / "dpcisr_report" / "unlisted.txt").write_bytes((bundle / REPORT).read_bytes())
    for bad, reason in {"raw/dpcisr_report/unlisted.txt": "not listed", "raw/dpcisr_report/result.json": "not listed",
                        "raw/wpr_trace/tracerpt-summary.txt": "not listed", "raw/../raw/dpcisr_report/dpcisr.txt": "not a normalised",
                        "/etc/passwd": "not a bundle relative path"}.items():
        result = decode_dpcisr.decode(bundle, bad, decoded_at=AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (bad, result)
        assert not (bundle / "decoded").exists(), bad
    assert decode_dpcisr.decode(bundle_copy("dpcisr-trace-no-xperf"), REPORT, decoded_at=AT)["status"] == "decode_failed"


def test_nothing_in_the_fixtures_comes_from_a_real_machine():
    for case in CASES:
        bundle = BUNDLES / case
        if (bundle / REPORT).exists():
            text = (bundle / REPORT).read_text(encoding="utf-8")
            assert {m for m in re.findall(r" ([A-Za-z0-9_.]+\.(?:sys|exe))\s*$", text, re.M)} == {"synthgfx.sys", "synthnic.sys", "synthusb.sys", "synthaudio.sys", "ntoskrnl.exe"}
        assert manifest(case)["machine"]["hostname"] == "SYNTHETIC-PC"
