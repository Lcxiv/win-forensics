"""The disk activity capture: its synthetic bundles, the aggregate made on the PC, and the diskio_activity table.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a clean ten second session whose
invented dump names a game, a launcher, the system and a helper with an unreadable image name; a session
whose saved trace lost events (no aggregate is made); the account the front door uses today, which is not
elevated; and a dump that does not render the disk events' response time (the aggregate fails, the trace
does not). Nothing here comes from a real machine, and no trace or dump is ever part of a bundle.
"""
from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import decode_diskio
import decode_tracestats
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = ["diskio-trace", "diskio-trace-events-lost", "diskio-trace-not-elevated", "diskio-trace-dump-unrendered"]
KEYWORDS = ["DiskIO", "Filename", "HardFaults", "ProcessThread"]
AGGREGATE = "raw/diskio_aggregate/aggregate.jsonl"
RESULT = "raw/diskio_aggregate/result.json"
AT = "2026-09-03T00:00:00Z"
# Everything the invented trace held that must stay on the PC: the owner's folder name, a command line
# argument, a hardware address, a user id, file names and directories below the readable level.
SECRETS = ("SyntheticOwner", "secret-token", "02-00-5E-10-20-30", "S-1-5-21-", "cache01", "world.pak", "slot1.sav",
           "index.dat", "ShaderCache", "Saved Games", "Synthetic-Operational", "Manifests", "Pipeline", "Paks")


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


# ---------------------------------------------------------------- the profile and the privacy rule

@pytest.mark.parametrize("case", CASES)
def test_the_profile_asks_for_the_four_keywords_and_nothing_else(case):
    trace = source(case, "wpr_trace")
    config = [a for a in trace["artifacts"] if a["role"] == "config"]
    assert [a["path"] for a in config] == ["raw/wpr_trace/diskio-trace.wprp"]
    assert trace["config_hash"] == {"algorithm": "sha256", "value": config[0]["sha256"]}
    root = ET.parse(BUNDLES / case / config[0]["path"]).getroot()
    assert root.tag == "WindowsPerformanceRecorder" and root.get("Version") == "1.0" and root.get("Author")
    profiles = root.find("Profiles")
    collector = profiles.find("SystemCollector")
    assert collector.get("Name") == "NT Kernel Logger"
    provider = profiles.find("SystemProvider")
    assert [k.get("Value") for k in provider.find("Keywords")] == KEYWORDS
    assert provider.find("Stacks") is None, "no stack walking"
    assert "FileIO" not in [k.get("Value") for k in provider.find("Keywords")], "file I/O events wait for a pilot that measures their volume"
    defined = profiles.findall("Profile")
    assert [p.get("LoggingMode") for p in defined] == ["File", "Memory"]
    assert [p.get("Id") for p in defined] == ["WfDiskIoTrace.Verbose.File", "WfDiskIoTrace.Verbose.Memory"]
    assert trace["requested"]["keywords"] == KEYWORDS
    assert trace["requested"]["options"]["concurrent_kernel_session_check"] == "not_checked"
    assert "run alone" in trace["requested"]["options"]["run_alone"] or "alone" in trace["requested"]["options"]["run_alone"]


@pytest.mark.parametrize("case", CASES)
def test_no_trace_no_dump_and_nothing_private_reaches_a_bundle(case):
    bundle = BUNDLES / case
    assert sorted(p.name for p in bundle.iterdir()) == ["logs", "manifest.json", "raw"]
    assert not list(bundle.rglob("*.etl")) and not list(bundle.rglob("*.xml")) and not (bundle / "private").exists()
    text = "\n".join(p.read_text(encoding="utf-8") for p in bundle.rglob("*") if p.is_file())
    for secret in SECRETS:
        assert secret not in text, secret
    result = json.loads((bundle / RESULT).read_text(encoding="utf-8"))
    assert result["recording_and_dump_removed"] is True
    rules = json.loads((bundle / "raw/diskio_aggregate/command.json").read_text(encoding="utf-8"))
    assert rules["recording_kept"] is False and rules["pseudonyms"]["readable_levels_below_root"] == 1
    assert "never written" in rules["pseudonyms"]["other_components"], "the salt never leaves the PC"


def test_every_directory_keeps_fixed_roots_and_one_level_and_pseudonymises_the_rest():
    rows = [json.loads(line) for line in (BUNDLES / "diskio-trace" / AGGREGATE).read_text(encoding="utf-8").splitlines()]
    roots = (r"\\Windows", r"\\Program Files", r"\\Program Files \(x86\)", r"\\ProgramData", r"\\\$Extend",
             r"\\Users\\<profile>\\AppData\\(Local|LocalLow|Roaming)", r"\\Users\\<profile>\\(Desktop|Documents|Downloads)")
    shape = re.compile(r"^(\\|\\Users\\<profile>|(" + "|".join(roots) + r")(\\[^\\]+)?(\\dir-[0-9a-f]{12})*|\\Users\\<profile>(\\dir-[0-9a-f]{12})+|(\\dir-[0-9a-f]{12})+)$")
    named = [r for r in rows if r["path_class"] == "named"]
    assert named
    for row in named:
        assert shape.fullmatch(row["directory"]), row["directory"]
    assert all(r["directory"] is None for r in rows if r["path_class"] != "named")
    assert {r["extension"] for r in rows} == {".pak", ".bin", ".sav", ".evtx", ".dat", None}
    rules = json.loads((BUNDLES / "diskio-trace" / "raw/diskio_aggregate/command.json").read_text(encoding="utf-8"))["pseudonyms"]
    kept = {"." + name for name in rules["kept_extensions"]}
    assert kept and all(r["extension"] in kept | {"other", None} for r in rows), "an extension outside the bundle's own stated list is never kept"


# ---------------------------------------------------------------- status

def test_a_clean_session_is_observed_and_its_aggregate_agrees_with_its_record():
    trace = source("diskio-trace", "wpr_trace")
    aggregate = source("diskio-trace", "diskio_aggregate")
    assert trace["status"] == aggregate["status"] == "observed"
    assert trace["events_lost"] == 0 and trace["buffers_lost"] == 0
    assert trace["enabled"]["keywords"] == KEYWORDS
    assert trace["enabled"]["options"]["clock_type"] == "qpc" and trace["enabled"]["options"]["session_confirmed_stopped"] is True
    assert aggregate["raw_time_range"] == trace["raw_time_range"], "the aggregate covers exactly the trace"
    result = json.loads((BUNDLES / "diskio-trace" / RESULT).read_text(encoding="utf-8"))
    assert result["trace_sha256"] == trace["enabled"]["options"]["trace_sha256"]
    assert result["dump_events"] == result["trace_events_processed"]
    assert result["counts"]["malformed"] == 0 and result["counts"]["disk_read"] + result["counts"]["disk_write"] > 0
    assert aggregate["enabled"]["options"]["rows"] == result["rows"] == len((BUNDLES / "diskio-trace" / AGGREGATE).read_text(encoding="utf-8").splitlines())


def test_a_lossy_trace_makes_no_aggregate():
    trace = source("diskio-trace-events-lost", "wpr_trace")
    aggregate = source("diskio-trace-events-lost", "diskio_aggregate")
    assert trace["status"] == "capture_failed" and trace["events_lost"] == 544
    assert aggregate["status"] == "not_collected" and "capture_failed" in aggregate["status_reason"]
    assert not (BUNDLES / "diskio-trace-events-lost" / AGGREGATE).exists()
    result = json.loads((BUNDLES / "diskio-trace-events-lost" / RESULT).read_text(encoding="utf-8"))
    assert result["dump_bytes"] is None and result["dump_events"] is None, "the dump of a lossy trace is never read"
    assert result["recording_and_dump_removed"] is True


def test_the_front_door_account_cannot_start_a_kernel_trace_and_nothing_runs():
    trace = source("diskio-trace-not-elevated", "wpr_trace")
    assert trace["status"] == "not_collected" and "not elevated" in trace["status_reason"]
    session = json.loads((BUNDLES / "diskio-trace-not-elevated" / "raw/wpr_trace/session.json").read_text(encoding="utf-8"))
    assert session["runs"] == []
    assert manifest("diskio-trace-not-elevated")["capture"]["elevated"] is False


def test_a_dump_that_does_not_render_the_fields_fails_the_aggregate_not_the_trace():
    trace = source("diskio-trace-dump-unrendered", "wpr_trace")
    aggregate = source("diskio-trace-dump-unrendered", "diskio_aggregate")
    assert trace["status"] == "observed"
    assert aggregate["status"] == "capture_failed" and "could not be read" in aggregate["status_reason"]
    assert not (BUNDLES / "diskio-trace-dump-unrendered" / AGGREGATE).exists()


# ---------------------------------------------------------------- the decoders

def test_the_aggregate_decodes_into_diskio_activity(bundle_copy):
    bundle = bundle_copy("diskio-trace")
    result = decode_diskio.decode(bundle, decoded_at=AT)
    assert result["status"] == "observed", result
    rows = wf_schema.read_jsonl(bundle / "decoded" / "diskio_activity.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/diskio_activity.schema.json") == []
    meta = json.loads((bundle / "decoded" / "diskio_activity.meta.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["time_domain"] == "etw_qpc_relative" and meta["native_time_range"] == {"start": 0, "end": 3, "domain": "etw_qpc_relative", "unit": "s"}
    assert [s["path"] for s in meta["source_files"]] == [AGGREGATE, RESULT]
    assert all(c["ok"] for c in meta["checks"]), meta["checks"]
    raw = (bundle / AGGREGATE).read_text(encoding="utf-8").splitlines()
    for row in rows:
        number = int(row["provenance"]["row_id_or_offset"].removeprefix("line:"))
        line = json.loads(raw[number - 1])
        assert line["operations"] == row["operations"] and line["directory"] == row["directory"]
    reads = [r for r in rows if r["operation"] == "read" and r["extension"] == ".pak" and r["process_image"] == "SyntheticGame.exe"]
    assert reads[0]["paging_operations"] == 2 and reads[0]["paging_bytes"] == 196608, "IrpFlags 0x60043 carries IRP_PAGING_IO (0x2)"
    writes = [r for r in rows if r["operation"] == "write" and r["extension"] == ".bin" and r["process_image"] == "SyntheticGame.exe"]
    assert writes[0]["paging_operations"] == 0, "IrpFlags 0x60a01 does not"
    faults = [r for r in rows if r["operation"] == "hard_fault"]
    assert faults and all(r["paging_operations"] is None and r["response_time_p95_us"] is None for r in faults)
    assert verify_bundle.verify(bundle)["ok"]


def test_the_trace_statistics_decode_into_tracestats_like_any_wpr_source(bundle_copy):
    for case in ("diskio-trace", "diskio-trace-events-lost"):
        bundle = bundle_copy(case)
        result = decode_tracestats.decode(bundle, decoded_at=AT)
        assert result["status"] == "observed", result
        rows = wf_schema.read_jsonl(bundle / "decoded" / "tracestats.jsonl")
        assert decode_tracestats.events_lost_of(rows) == source(case, "wpr_trace")["events_lost"]
        assert [r["value_text"] for r in rows if r["key"] == "System Keywords"] == KEYWORDS


@pytest.mark.parametrize("case", ["diskio-trace-events-lost", "diskio-trace-not-elevated", "diskio-trace-dump-unrendered"])
def test_nothing_to_decode_is_not_collected_and_writes_nothing(case, bundle_copy):
    bundle = bundle_copy(case)
    assert decode_diskio.decode(bundle, decoded_at=AT)["status"] == "not_collected"
    assert not (bundle / "decoded").exists()


def tamper(bundle: Path, path: str, change) -> None:
    target = bundle / path
    data = json.loads(target.read_text(encoding="utf-8"))
    change(data)
    target.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize("change, reason", [
    (lambda m: next(c for c in m["collectors"] if c["id"] == "wpr_trace").update(events_lost=1), "events_lost"),
    (lambda m: next(c for c in m["collectors"] if c["id"] == "wpr_trace")["enabled"]["options"].update(session_confirmed_stopped=False), "not confirmed"),
    (lambda m: next(c for c in m["collectors"] if c["id"] == "wpr_trace")["enabled"]["options"].update(trace_sha256="0" * 64), "trace_sha256"),
    (lambda m: next(c for c in m["collectors"] if c["id"] == "diskio_aggregate")["enabled"]["options"].update(rows=1), "rows"),
])
def test_the_decoder_refuses_a_manifest_that_disagrees(change, reason, bundle_copy):
    bundle = bundle_copy("diskio-trace")
    tamper(bundle, "manifest.json", change)
    result = decode_diskio.decode(bundle, decoded_at=AT)
    assert result["status"] == "decode_failed" and reason in result["reason"], result
    assert wf_schema.read_jsonl(bundle / "decoded" / "diskio_activity.jsonl") == []


@pytest.mark.parametrize("change, reason", [
    (lambda r: r.update(recording_and_dump_removed=False), "removed"),
    (lambda r: r.update(dump_events=r["dump_events"] - 1), "processed"),
    (lambda r: r["counts"].update(malformed=1), "not whole"),
    (lambda r: r["trace_header"].update(clock_type="system_time"), "performance counter"),
    (lambda r: r["totals"].update(read_bytes=1), "add up"),
])
def test_the_decoder_refuses_a_result_record_it_cannot_vouch_for(change, reason, bundle_copy):
    bundle = bundle_copy("diskio-trace")
    tamper(bundle, RESULT, change)
    result = decode_diskio.decode(bundle, decoded_at=AT)
    assert result["status"] == "decode_failed" and reason in result["reason"], result


def test_the_decoder_refuses_rows_that_do_not_add_up_and_sources_it_cannot_vouch_for(bundle_copy):
    bundle = bundle_copy("diskio-trace")
    lines = (bundle / AGGREGATE).read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["irp_flags_operations"] = {"0x60043": row["operations"] + 1}
    (bundle / AGGREGATE).write_text("\n".join([lines[0], json.dumps(row)] + lines[2:]) + "\n", encoding="utf-8")
    result = decode_diskio.decode(bundle, decoded_at=AT)
    assert result["status"] == "decode_failed" and "do not add up" in result["reason"]
    row["irp_flags_operations"] = {"0x60043": row["operations"]}
    row["file_name"] = "x"
    (bundle / AGGREGATE).write_text("\n".join([lines[0], json.dumps(row)] + lines[2:]) + "\n", encoding="utf-8")
    assert "unknown ['file_name']" in decode_diskio.decode(bundle, decoded_at=AT)["reason"]
    clean = bundle_copy("diskio-trace-dump-unrendered")
    for bad, reason in {"raw/wpr_trace/session.json": "not listed", "raw/../raw/diskio_aggregate/result.json": "not a normalised",
                        "/etc/passwd": "not a bundle relative path"}.items():
        result = decode_diskio.decode(clean, sources=[bad], decoded_at=AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (bad, result)


def test_the_cli(bundle_copy, capsys):
    assert decode_diskio.main(["--bundle", str(bundle_copy("diskio-trace")), "--decoded-at", AT]) == 0
    assert "status observed" in capsys.readouterr().out
    assert decode_diskio.main(["--bundle", str(bundle_copy("diskio-trace-not-elevated"))]) == 2


def test_nothing_in_the_fixtures_comes_from_a_real_machine():
    for case in CASES:
        assert manifest(case)["machine"]["hostname"] == "SYNTHETIC-PC"
    images = {json.loads(line)["process_image"] for line in (BUNDLES / "diskio-trace" / AGGREGATE).read_text(encoding="utf-8").splitlines()}
    assert {i for i in images if i and not i.startswith("image-")} == {"SyntheticGame.exe", "SyntheticLauncher.exe", "System"}
