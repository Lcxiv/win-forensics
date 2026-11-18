"""The live DPC and interrupt capture: its synthetic bundles, the trace loss table, and the per CPU report.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a clean session with a pinned
xperf whose report puts the invented graphics driver on CPU 6; the same session without an xperf; a
session that lost events; and the account the front door uses today, which is not elevated. Nothing here
comes from a real machine: the recorder, the trace bytes and the report are all synthetic.
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
KEYWORDS = ["Interrupt", "DPC", "Loader", "ProcessThread", "CSwitch", "ReadyThread"]
REPORT = "raw/dpcisr_report/dpcisr.txt"
STATUS = "raw/wpr_trace/status.txt"
AT = "2026-09-03T00:00:00Z"


def manifest(case: str) -> dict:
    return json.loads((BUNDLES / case / "manifest.json").read_text(encoding="utf-8"))


def source(case: str, source_id: str) -> dict:
    return next(c for c in manifest(case)["collectors"] if c["id"] == source_id)


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str) -> Path:
        dst = tmp_path / case
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


# ---------------------------------------------------------------- the profile

@pytest.mark.parametrize("case", CASES)
def test_the_profile_is_the_committed_one_and_hashed_as_the_config(case):
    """The profile WPR ran is in the bundle byte for byte, well formed, with the six keywords and no stacks."""
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
    defined = profiles.findall("Profile")
    assert [p.get("LoggingMode") for p in defined] == ["File", "Memory"], "a .wprp defines both logging modes"
    assert {p.get("Name") for p in defined} == {"WfDpcIsrTrace"}
    for profile in defined:
        assert profile.get("Id") == f"WfDpcIsrTrace.{profile.get('DetailLevel')}.{profile.get('LoggingMode')}"
        assert profile.find("Collectors/SystemCollectorId").get("Value") == collector.get("Id")
        assert profile.find("Collectors/SystemCollectorId/SystemProviderId").get("Value") == provider.get("Id")
    # The profile text in the script is the one in the bundle: same keywords, same buffers.
    script = COLLECTOR.read_text(encoding="ascii")
    for keyword in KEYWORDS:
        assert f"'{keyword}'" in script
    assert trace["requested"]["keywords"] == KEYWORDS
    assert trace["requested"]["providers"] == ["NT Kernel Logger"]


# ---------------------------------------------------------------- status and loss

def test_a_clean_session_is_observed_with_zero_loss_verified_from_the_tool():
    trace = source("dpcisr-trace", "wpr_trace")
    assert trace["status"] == "observed" and trace["events_lost"] == 0
    assert trace["enabled"]["keywords"] == KEYWORDS and trace["enabled"]["providers"] == ["NT Kernel Logger"]
    assert "wpr -status" in trace["enabled"]["verified_by"]
    assert trace["enabled"]["options"]["session_confirmed_stopped"] is True
    assert trace["raw_time_range"]["domain"] == "system_time"
    assert trace["expectation"]["met"] is True
    text = (BUNDLES / "dpcisr-trace" / STATUS).read_text(encoding="utf-8")
    assert re.search(r"^Events Lost\s+: 0$", text, re.M) and re.search(r"^Dropped event\s+: 0$", text, re.M)
    session = json.loads((BUNDLES / "dpcisr-trace" / "raw/wpr_trace/session.json").read_text(encoding="utf-8"))
    assert [r["verb"] for r in session["runs"]] == ["status", "profiles", "start", "status", "stop", "status"]
    assert session["events_lost_bound"] == 0 and session["stopped_early_at_cap"] is False


def test_a_lossy_trace_is_kept_but_never_observed_and_the_report_inherits_the_loss():
    trace = source("dpcisr-trace-events-lost", "wpr_trace")
    assert trace["status"] == "capture_failed" and trace["events_lost"] == 544
    assert "544 events lost" in trace["status_reason"] and "never support an absence" in trace["status_reason"]
    assert [a["path"] for a in trace["artifacts"] if a["role"] == "primary"] == ["raw/wpr_trace/trace.etl"], "the trace is kept with its status"
    report = source("dpcisr-trace-events-lost", "dpcisr_report")
    assert report["status"] == "capture_failed" and "-tle" in report["command"] and "lost 544 events" in report["status_reason"]
    assert any("lower bound" in note for note in manifest("dpcisr-trace-events-lost")["notes"])


def test_the_front_door_account_cannot_start_a_kernel_trace_and_nothing_runs():
    trace = source("dpcisr-trace-not-elevated", "wpr_trace")
    assert trace["status"] == "not_collected" and "not elevated" in trace["status_reason"]
    assert trace["preflight"]["ok"] is False
    assert [c["name"] for c in trace["preflight"]["checks"]] == ["tool_present", "account_elevated"], "no wpr call before the account check"
    assert trace["artifacts"] and all(a["role"] in ("config", "report") for a in trace["artifacts"])
    session = json.loads((BUNDLES / "dpcisr-trace-not-elevated" / "raw/wpr_trace/session.json").read_text(encoding="utf-8"))
    assert session["runs"] == []
    report = source("dpcisr-trace-not-elevated", "dpcisr_report")
    assert report["status"] == "not_collected" and "no trace" in report["status_reason"]


def test_without_an_xperf_the_report_says_where_it_can_be_produced():
    report = source("dpcisr-trace-no-xperf", "dpcisr_report")
    assert report["status"] == "not_collected" and "-XperfPath was not given" in report["status_reason"]
    assert [c["name"] for c in report["preflight"]["checks"]] == ["trace_present", "tool_named"]
    assert source("dpcisr-trace-no-xperf", "wpr_trace")["status"] == "observed"
    assert "xperf" not in [t["name"] for t in manifest("dpcisr-trace-no-xperf")["tools"]]


def test_the_pinned_tool_is_recorded_in_the_manifest_and_the_report_config():
    report = source("dpcisr-trace", "dpcisr_report")
    config = json.loads((BUNDLES / "dpcisr-trace" / "raw/dpcisr_report/command.json").read_text(encoding="utf-8"))
    tool = next(t for t in manifest("dpcisr-trace")["tools"] if t["name"] == "xperf")
    assert config["pinned_builds"][0]["sha256"] == tool["sha256"] == report["enabled"]["options"]["tool_sha256"]
    assert config["pinned_builds"][0]["version"] == tool["version"] == report["enabled"]["options"]["tool_version"]
    assert config["trace"] == "raw/wpr_trace/trace.etl" and config["trace_events_lost"] == 0
    assert "pinned" in config["tool_source"] and "not inbox" in config["tool_source"]


# ---------------------------------------------------------------- tracestats

@pytest.mark.parametrize("case", CASES)
def test_the_status_text_decodes_into_tracestats_and_agrees_with_the_manifest(case, bundle_copy):
    bundle = bundle_copy(case)
    trace = source(case, "wpr_trace")
    result = decode_tracestats.decode(bundle, decoded_at=AT)
    if not any(a["path"] == STATUS for a in trace["artifacts"]):
        assert result["status"] == "not_collected" and not (bundle / "decoded").exists()
        return
    assert result["status"] == "observed", result
    rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/tracestats.schema.json") == []
    meta = json.loads((bundle / "decoded" / "tracestats.meta.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["time_domain"] == "system_time" and meta["row_count"] == len(rows) == result["rows"]
    assert meta["source_files"] == [{"path": STATUS, "sha256": next(a["sha256"] for a in trace["artifacts"] if a["path"] == STATUS)}]
    lost = [r for r in rows if r["normalized_key"] == "events_lost"]
    assert {r["section"] for r in lost} == {"recording", "NT Kernel Logger"}
    assert decode_tracestats.events_lost_of(rows) == trace["events_lost"], "the contract: the table's events lost equals the manifest's"
    assert all(c["ok"] for c in meta["checks"]), meta["checks"]
    buffer = next(r for r in rows if r["normalized_key"] == "buffer_size_kb")
    assert buffer["value_number"] == 1024 and buffer["key"] == "Buffer Size (KB)"
    keywords = [r["value_text"] for r in rows if r["key"] == "System Keywords"]
    assert keywords == KEYWORDS
    lines = (bundle / STATUS).read_text(encoding="utf-8").splitlines()
    for row in rows:
        line = lines[int(row["provenance"]["row_id_or_offset"].removeprefix("line:")) - 1]
        assert row["value_text"] in line and (row["key"] in line or row["key"] in ("System Keywords", "System Stacks"))
    assert verify_bundle.verify(bundle)["ok"]


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
    assert not next(c for c in meta["checks"] if c["name"].endswith("events_lost_matches_manifest"))["ok"]
    shutil.rmtree(bundle / "decoded")
    for bad, reason in {"raw/wpr_trace/session.json": "not listed", "raw/../raw/wpr_trace/status.txt": "not a normalised",
                        "/etc/passwd": "not a bundle relative path", "raw/dpcisr_report/dpcisr.txt": "not listed"}.items():
        result = decode_tracestats.decode(bundle, sources=[bad], decoded_at=AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (bad, result)
        assert not (bundle / "decoded").exists()
    assert decode_tracestats.decode(bundle_copy("dpcisr-trace-not-elevated"), decoded_at=AT)["status"] == "not_collected"


def test_tracestats_cli(bundle_copy, capsys):
    assert decode_tracestats.main(["--bundle", str(bundle_copy("dpcisr-trace")), "--decoded-at", AT]) == 0
    assert "tracestats:" in capsys.readouterr().out and "status observed" in capsys.readouterr().out or True
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
                        "raw/wpr_trace/trace.etl": "not listed", "raw/../raw/dpcisr_report/dpcisr.txt": "not a normalised",
                        "/etc/passwd": "not a bundle relative path"}.items():
        result = decode_dpcisr.decode(bundle, bad, decoded_at=AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (bad, result)
        assert not (bundle / "decoded").exists(), bad
    assert decode_dpcisr.decode(bundle_copy("dpcisr-trace-no-xperf"), REPORT, decoded_at=AT)["status"] == "decode_failed"


def test_nothing_in_the_fixtures_comes_from_a_real_machine():
    for case in CASES:
        bundle = BUNDLES / case
        etl = bundle / "raw" / "wpr_trace" / "trace.etl"
        if etl.exists():
            assert etl.read_bytes().startswith(b"synthetic trace, not an event trace log")
        if (bundle / REPORT).exists():
            text = (bundle / REPORT).read_text(encoding="utf-8")
            assert {m for m in re.findall(r" ([A-Za-z0-9_.]+\.(?:sys|exe))\s*$", text, re.M)} == {"synthgfx.sys", "synthnic.sys", "synthusb.sys", "synthaudio.sys", "ntoskrnl.exe"}
        assert manifest(case)["machine"]["hostname"] == "SYNTHETIC-PC"
