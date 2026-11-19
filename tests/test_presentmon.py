"""The PresentMon decoder turns the synthetic frame captures into presentmon_frames rows with provenance.

The inputs are the ``presentmon-frames*`` bundles under fixtures/collector-bundles, written by the
real collector against the synthetic backend: an invented CSV in the header PresentMon 2.6.0 prints
for its default options with --qpc_time, and the collector's record of an invented recording whose
first buffer follows the layout of PresentMon's own regression recordings. The one file here that
is not invented is fixtures/presentmon/gold-test_case_0.first-buffer.etl, the first 4096 bytes of
the vendor's Tests/Gold/test_case_0.etl at tag v2.6.0 (MIT licence), which settles that layout.
Nothing here comes from the captain's machine.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import decode_presentmon
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
GOLD = REPO_ROOT / "fixtures" / "presentmon" / "gold-test_case_0.first-buffer.etl"
# SHA-256 of the vendor file this is cut from (Tests/Gold/test_case_0.etl at v2.6.0) and of the cut itself.
GOLD_SHA256 = "d7d2463ec3f97c59db6815fb936a73ecbdaae5b782ec81e597b1946b97a4a8fc"
HAPPY = "presentmon-frames"
CSV_SOURCE = "raw/presentmon_frames/frames.csv"
RECORD_SOURCE = "raw/presentmon_frames/recording.json"
DECODED_AT = "2026-09-03T00:00:00Z"
FAILED_CASES = ("presentmon-frames-no-frames", "presentmon-frames-no-binary", "presentmon-frames-access-denied",
                "presentmon-frames-lost-events", "presentmon-frames-overflow")
# The header PresentMon 2.6.0 writes for the console application's default options with --qpc_time
# (CsvOutput.cpp WriteCsvHeader<FrameMetrics>, lines 531 to 667 at tag v2.6.0).
HEADER_2_6_0 = ("Application,ProcessID,SwapChainAddress,PresentRuntime,SyncInterval,PresentFlags,AllowsTearing,PresentMode,TimeInQPC,"
                "MsBetweenSimulationStart,MsBetweenPresents,MsBetweenDisplayChange,MsInPresentAPI,MsRenderPresentLatency,MsUntilDisplayed,"
                "CPUStartQPC,MsBetweenAppStart,MsCPUBusy,MsCPUWait,MsGPULatency,MsGPUTime,MsGPUBusy,MsGPUWait,MsAnimationError,AnimationTime,"
                "MsFlipDelay,MsAllInputToPhotonLatency,MsClickToPhotonLatency").split(",")


@pytest.fixture()
def bundle_copy(tmp_path):
    copies = [0]

    def make(case: str) -> Path:
        copies[0] += 1
        dst = tmp_path / f"{copies[0]}-{case}"
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


def relist(bundle: Path, path: str) -> None:
    """Refresh the manifest's size and hash of one artifact after a test rewrote it."""
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = bundle / path
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            if artifact["path"] == path:
                artifact["bytes"], artifact["sha256"] = target.stat().st_size, wf_schema.sha256_of(target)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def rewrite_csv(bundle: Path, header: list[str], records: list[list[str]]) -> None:
    with (bundle / CSV_SOURCE).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\r\n")
        writer.writerow(header)
        writer.writerows(records)
    relist(bundle, CSV_SOURCE)


def read_csv(bundle: Path) -> tuple[list[str], list[list[str]]]:
    with (bundle / CSV_SOURCE).open("r", encoding="utf-8-sig", newline="") as fh:
        records = list(csv.reader(fh))
    return records[0], records[1:]


def rows_and_meta(bundle: Path):
    rows = wf_schema.read_jsonl(bundle / "decoded" / "presentmon_frames.jsonl")
    meta = json.loads((bundle / "decoded" / "presentmon_frames.meta.json").read_text(encoding="utf-8"))
    return rows, meta


def patch_recording(bundle: Path, **changes) -> None:
    """Edit the collector's recording record (and the manifest's copy of the clock when asked) the way a test needs."""
    path = bundle / RECORD_SOURCE
    record = json.loads(path.read_text(encoding="utf-8"))
    manifest_clock = changes.pop("manifest_clock", None)
    header = changes.pop("header", None) or {}
    record["header"].update(header)
    record.update(changes)
    path.write_text(json.dumps(record), encoding="utf-8")
    relist(bundle, RECORD_SOURCE)
    if manifest_clock is not None:
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["collectors"][0]["enabled"]["options"]["clock_type"] = manifest_clock
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


# ---------------------------------------------------------------- the committed captures

def test_the_capture_decodes_into_validated_rows_in_the_recording_clock(bundle_copy):
    bundle = bundle_copy(HAPPY)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result == {"status": "observed", "reason": None, "rows": 10, "sources": 2}
    rows, meta = rows_and_meta(bundle)
    assert wf_schema.validate_rows(rows, "decoded/presentmon_frames.schema.json") == []
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["row_count"] == len(rows) == 10
    assert meta["time_domain"] == "etw_qpc", "the recording's header says the events were stamped with the performance counter"
    assert meta["tool"] == {"name": decode_presentmon.TOOL_NAME, "version": "2.6.0"}, "the version the collector verified"
    qpc = [r["cpu_start_qpc"] for r in rows]
    assert meta["native_time_range"] == {"start": min(qpc), "end": max(qpc), "domain": "etw_qpc", "unit": "qpc_ticks"}
    assert all(isinstance(r["cpu_start_qpc"], int) and isinstance(r["time_in_qpc"], int) for r in rows)
    assert all("cpu_start_time_s" not in r for r in rows)
    assert {r["application"] for r in rows} == {"SyntheticGame.exe", "<unknown>"}
    assert sum(r["application"] == "<unknown>" for r in rows) == 2
    assert all(c["ok"] for c in meta["checks"]), meta["checks"]
    names = [c["name"] for c in meta["checks"]]
    assert names == [f"recording:{RECORD_SOURCE}", f"header_mapped:{CSV_SOURCE}", f"rows_read:{CSV_SOURCE}",
                     f"qpc_increases_per_swap_chain:{CSV_SOURCE}", "processes", "rows_validate"]
    assert "clock qpc, PerfFreq 10000000 Hz" in meta["checks"][0]["detail"] and "deleted on the PC" in meta["checks"][0]["detail"]
    assert "28 of 28 columns mapped" in meta["checks"][1]["detail"]
    assert "2 frames of <unknown> processes" in meta["checks"][2]["detail"]
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    listed = {a["path"]: a for c in manifest["collectors"] for a in c["artifacts"]}
    assert meta["source_files"] == [{"path": CSV_SOURCE, "sha256": listed[CSV_SOURCE]["sha256"]}, {"path": RECORD_SOURCE, "sha256": listed[RECORD_SOURCE]["sha256"]}]
    assert not any(p.endswith("trace.etl") for p in listed) and not (bundle / "raw" / "presentmon_frames" / "trace.etl").exists(), "the recording never leaves the PC"
    # The decoded table is part of the container: the bundle still verifies with it present.
    assert verify_bundle.verify(bundle)["ok"]


def test_every_row_points_at_its_csv_row_and_keeps_na_as_null(bundle_copy):
    bundle = bundle_copy(HAPPY)
    decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    rows, _ = rows_and_meta(bundle)
    header, records = read_csv(bundle)
    assert header == HEADER_2_6_0
    inverse = {v: k for k, v in decode_presentmon.COLUMN_MAP.items()}
    for row in rows:
        prov = row["provenance"]
        assert prov["source_file"] == CSV_SOURCE and prov["decoded_table"] == "presentmon_frames"
        assert prov["decoder_version"] == decode_presentmon.DECODER_VERSION
        assert prov["schema_version"] == wf_schema.table_schema_version("presentmon_frames") == "0.2.0"
        n = int(re.fullmatch(r"row:(\d+)", prov["row_id_or_offset"]).group(1))
        record = dict(zip(header, records[n - 1]))
        assert record["Application"] == row["application"] and int(record["ProcessID"]) == row["process_id"]
        assert int(record["CPUStartQPC"]) == row["cpu_start_qpc"] and int(record["TimeInQPC"]) == row["time_in_qpc"]
        for column, value in row.items():
            if column in ("provenance", "raw_columns"):
                continue
            if inverse[column] not in record:
                assert value is None, column
                continue
            cell = record[inverse[column]].strip()
            if value is None:
                assert cell == "NA", (column, cell)
            elif isinstance(value, str):
                assert cell == value
            else:
                assert float(cell) == value, (column, cell, value)
        assert "raw_columns" not in row, "every column of the 2.6.0 default header is mapped"
    # The writer's NA rules are present in the fixture: a zero MsBetweenDisplayChange, no input for most frames.
    assert any(r["ms_between_display_change"] is None for r in rows)
    assert all(r["ms_click_to_photon_latency"] is None or r["ms_click_to_photon_latency"] > 0 for r in rows)
    assert all(r["ms_between_simulation_start"] is None for r in rows)


def test_failed_captures_are_not_decoded_and_nothing_is_a_quiet_window(bundle_copy):
    for case in FAILED_CASES:
        bundle = bundle_copy(case)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "not_collected" and result["rows"] == 0, case
        assert not (bundle / "decoded").exists(), "an absent or failed capture is not decoded into an empty table"
        assert not (bundle / CSV_SOURCE).exists(), f"{case}: a failed capture leaves no CSV that could be read as frames"
        # Naming the record of a failed capture does not help: it is not an input.
        result = decode_presentmon.decode(bundle, sources=[RECORD_SOURCE], decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and "not listed" in result["reason"], case
    no_frames = json.loads((BUNDLES / "presentmon-frames-no-frames" / "manifest.json").read_text(encoding="utf-8"))["collectors"][0]
    assert no_frames["status"] == "capture_failed" and "not a quiet window claim" in no_frames["status_reason"]


# ---------------------------------------------------------------- the recording record decides the domain and vouches for the capture

def test_the_clock_comes_from_the_recording_record(bundle_copy):
    bundle = bundle_copy(HAPPY)
    patch_recording(bundle, header={"clock_type": "system_time", "reserved_flags": 2}, manifest_clock="system_time")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed", result
    _, meta = rows_and_meta(bundle)
    assert meta["time_domain"] == "system_time" and meta["native_time_range"]["unit"] == "filetime_100ns"
    patch_recording(bundle, header={"clock_type": "cpu_cycle_counter", "reserved_flags": 3}, manifest_clock="cpu_cycle_counter")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "cpu_cycle_counter clock" in result["reason"]
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["time_domain"] == "none" and meta["status"] == "decode_failed"
    patch_recording(bundle, header={"clock_type": "qpc", "reserved_flags": 1}, manifest_clock="system_time")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "the manifest says clock 'system_time'" in result["reason"]
    patch_recording(bundle, header={"found": False, "error": "synthetic: unreadable"}, manifest_clock="qpc")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "could not read the recording's log file header" in result["reason"]


def test_loss_overflow_or_an_unconfirmed_window_in_the_record_is_decode_failed(bundle_copy):
    cases = {
        "events": ({"events_lost": 7}, "lost data (events lost 7"),
        "buffers": ({"buffers_lost": 2}, "buffers lost 2"),
        "header events": ({"header": {"events_lost": 3}}, "header 3 and 0"),
        "no end time": ({"header": {"end_time_utc": None}}, "carries no end time"),
        "overflow": ({"presentmon": {"overflowed_presents": 12, "warnings": [], "errors": []}}, "threw 12 presents away"),
        "stop": ({"stop_confirmed": False}, "stop was not confirmed"),
        "early": ({"session_ended_early": True}, "did not run for the whole window"),
        "not in progress": ({"in_progress_at_end": False}, "did not run for the whole window"),
    }
    for name, (changes, reason) in cases.items():
        bundle = bundle_copy(HAPPY)
        patch_recording(bundle, **changes)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (name, result)
        rows, meta = rows_and_meta(bundle)
        assert rows == [] and meta["status"] == "decode_failed" and meta["checks"][-1]["name"] == "capture_read"


MANIFEST_LOSS_TAMPERS = {
    "entry events_lost": (lambda c: c.__setitem__("events_lost", 1), "the manifest records events_lost 1"),
    "entry buffers_lost": (lambda c: c.__setitem__("buffers_lost", 3), "the manifest records buffers_lost 3 for an observed capture, the record 0"),
    "options buffers_lost": (lambda c: c["enabled"]["options"].__setitem__("buffers_lost", 3), "enabled.options record buffers_lost 3 for an observed capture, the record 0"),
}


@pytest.mark.parametrize("name", sorted(MANIFEST_LOSS_TAMPERS))
def test_a_manifest_loss_count_that_disagrees_with_the_record_is_decode_failed(bundle_copy, name):
    tamper, reason = MANIFEST_LOSS_TAMPERS[name]
    bundle = bundle_copy(HAPPY)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    tamper(manifest["collectors"][0])
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and reason in result["reason"], result
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["status"] == "decode_failed"


def test_an_observed_capture_with_no_frame_row_is_refused(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, _ = read_csv(bundle)
    rewrite_csv(bundle, header, [])
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "no frame row" in result["reason"]
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["row_count"] == 0 and meta["native_time_range"] is None


# ---------------------------------------------------------------- the committed first buffer settles the header layout the collector reads

def test_the_committed_first_buffer_is_the_vendor_recording_and_reads_as_the_collector_reads_it():
    data = GOLD.read_bytes()
    assert len(data) == 4096 and hashlib.sha256(data).hexdigest() == GOLD_SHA256
    # The buffer header: the first buffer's size, the saved offset (where the data ends) and the current offset.
    buffer_size, saved_offset, current_offset = struct.unpack_from("<III", data, 0)
    assert buffer_size == 4096 and 0x48 < saved_offset <= 4096 and current_offset == 0
    assert all(b == 0xFF for b in data[saved_offset:]), "the buffer after the saved offset is fill"
    # The system trace header of the log file header event at offset 0x48: version 2, 64 bit header type, hook id 0.
    version, header_type, flags, size, hook_id = struct.unpack_from("<HBBHH", data, 0x48)
    assert (version, header_type, flags, hook_id) == (2, 2, 0xC0, 0)
    assert 0x48 + size <= saved_offset
    # TRACE_LOGFILE_HEADER at 0x68, the offsets Read-WfEtlHeader uses.
    p = 0x68
    assert struct.unpack_from("<I", data, p)[0] == 65536, "BufferSize of the session that wrote the file"
    assert tuple(data[p + 4:p + 6]) == (10, 0), "Version major.minor"
    assert struct.unpack_from("<I", data, p + 8)[0] == 17763, "ProviderVersion (the Windows build)"
    assert struct.unpack_from("<I", data, p + 12)[0] == 16, "NumberOfProcessors"
    pointer_size = struct.unpack_from("<I", data, p + 44)[0]
    assert pointer_size == 8
    assert struct.unpack_from("<I", data, p + 36)[0] == 663, "BuffersWritten"
    assert struct.unpack_from("<I", data, p + 48)[0] == 0, "EventsLost"
    tail = p + 56 + 2 * pointer_size + 176
    assert struct.unpack_from("<q", data, tail + 8)[0] == 10_000_000, "PerfFreq"
    assert struct.unpack_from("<I", data, tail + 24)[0] == 1, "ReservedFlags: the performance counter clock"
    assert struct.unpack_from("<I", data, tail + 28)[0] == 0, "BuffersLost"
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    start = epoch + timedelta(microseconds=struct.unpack_from("<q", data, tail + 16)[0] // 10)
    end = epoch + timedelta(microseconds=struct.unpack_from("<q", data, p + 16)[0] // 10)
    assert start.year == 2020 and end > start, "a recording from the vendor's own machine, years before this project"
    name = data[tail + 32:tail + 32 + 16].decode("utf-16-le")
    assert name == "Relogger", "the vendor relogged its recordings; the logger name says so"


# ---------------------------------------------------------------- shapes the pinned source documents

def test_git_keeps_the_vendor_first_buffer_and_no_other_etl_in_its_folder():
    # .gitignore is asked through git itself: exit 0 means ignored, 1 means kept.
    def ignored(relative: str) -> bool:
        done = subprocess.run(["git", "check-ignore", "--no-index", "-q", relative], cwd=REPO_ROOT, capture_output=True)
        assert done.returncode in (0, 1), done.stderr
        return done.returncode == 0

    assert not ignored("fixtures/presentmon/gold-test_case_0.first-buffer.etl")
    assert ignored("fixtures/presentmon/trace.etl"), "a real trace dropped next to the fixture cannot be committed"
    assert ignored("fixtures/presentmon/gold-test_case_1.first-buffer.etl")
    assert not ignored("fixtures/presentmon/PROVENANCE.md") and not ignored("fixtures/presentmon/LICENSE-PresentMon.txt")


def test_only_cpustartqpc_is_accepted_as_the_frame_start(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    index = header.index("CPUStartQPC")
    for other in ("CPUStartTimeInMs", "CPUStartTime", "CPUStartQPCTime", "CPUStartDateTime"):
        header[index] = other
        rewrite_csv(bundle, header, records)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and other in result["reason"] and "no CPUStartQPC column" in result["reason"], other
        rows, meta = rows_and_meta(bundle)
        assert rows == [] and meta["status"] == "decode_failed"


def test_unknown_columns_are_kept_verbatim_under_raw_columns(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    header += ["VidPnSourceId", "LayerIndex", "PresentId", "SomethingNew"]
    records = [r + ["0", "0", str(1000 + i), "NA"] for i, r in enumerate(records)]
    rewrite_csv(bundle, header, records)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed", result
    rows, meta = rows_and_meta(bundle)
    assert wf_schema.validate_rows(rows, "decoded/presentmon_frames.schema.json") == []
    assert rows[0]["raw_columns"] == {"VidPnSourceId": "0", "LayerIndex": "0", "PresentId": "1000", "SomethingNew": None}
    mapped = next(c for c in meta["checks"] if c["name"].startswith("header_mapped"))
    assert "unmapped kept in raw_columns: VidPnSourceId, LayerIndex, PresentId, SomethingNew" in mapped["detail"]
    assert "28 of 32 columns mapped" in mapped["detail"]


def test_malformed_csv_content_is_decode_failed_with_the_row_named(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    qpc = header.index("CPUStartQPC")
    busy = header.index("MsCPUBusy")
    cases = {
        "ragged": ([r[:6] if i == 2 else r for i, r in enumerate(records)], "data row 3 has 6 cells"),
        "process id": ([[*r[:1], "abc", *r[2:]] if i == 0 else r for i, r in enumerate(records)], "column ProcessID: 'abc' is not an integer"),
        "qpc": ([[*r[:qpc], "12.5", *r[qpc + 1:]] if i == 4 else r for i, r in enumerate(records)], "column CPUStartQPC: '12.5' is not an integer"),
        "number": ([[*r[:busy], "fast", *r[busy + 1:]] if i == 1 else r for i, r in enumerate(records)], "column MsCPUBusy: 'fast' is not a number"),
    }
    for name, (bad_records, reason) in cases.items():
        rewrite_csv(bundle, header, bad_records)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (name, result)
        rows, meta = rows_and_meta(bundle)
        assert rows == [] and meta["status"] == "decode_failed" and meta["row_count"] == 0
        assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    rewrite_csv(bundle, ["time", "value"], [["1", "2"]])
    assert "not a PresentMon header" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]
    rewrite_csv(bundle, header + ["Application"], [r + ["x"] for r in records])
    assert "repeats the column 'Application'" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]
    (bundle / CSV_SOURCE).write_bytes(b"")
    relist(bundle, CSV_SOURCE)
    assert "not even a header" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]


def test_schema_violations_in_a_well_formed_csv_are_decode_failed(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    records[3][header.index("AllowsTearing")] = "2"
    rewrite_csv(bundle, header, records)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "allows_tearing" in result["reason"]
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["checks"][-1] == {"name": "rows_validate", "ok": False, "detail": meta["status_reason"]}


def test_a_swap_chain_whose_qpc_goes_backwards_is_reported_not_refused(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    index = header.index("CPUStartQPC")
    game = [r for r in records if r[0] == "SyntheticGame.exe"]
    game[1][index], game[2][index] = game[2][index], game[1][index]
    rewrite_csv(bundle, header, records)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed"
    _, meta = rows_and_meta(bundle)
    check = next(c for c in meta["checks"] if c["name"].startswith("qpc_increases_per_swap_chain"))
    assert check["ok"] is False and "does not increase" in check["detail"]


# ---------------------------------------------------------------- inputs the decoder refuses

def test_decoder_refuses_inputs_it_cannot_vouch_for(bundle_copy):
    bundle = bundle_copy(HAPPY)
    (bundle / "raw" / "presentmon_frames" / "unlisted.csv").write_text("Application,ProcessID\n", encoding="utf-8")
    cases = {
        "raw/presentmon_frames/missing.csv": "not listed",
        "raw/../raw/presentmon_frames/frames.csv": "not a normalised path",
        "../outside.csv": "not a normalised path",
        "/etc/passwd": "not a bundle relative path",
        "raw/presentmon_frames/command.json": "not listed",
        "raw/presentmon_frames/console.txt": "not listed",
        "raw/presentmon_frames/result.json": "not listed",
        "raw/presentmon_frames/unlisted.csv": "not listed",
    }
    for source, reason in cases.items():
        result = decode_presentmon.decode(bundle, sources=[source], decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (source, result)
        assert not (bundle / "decoded").exists(), source
    assert decode_presentmon.decode(bundle, sources=[], decoded_at=DECODED_AT)["reason"] == "no source was named"
    # Naming either file of the capture decodes the capture.
    assert decode_presentmon.decode(bundle, sources=[RECORD_SOURCE], decoded_at=DECODED_AT)["status"] == "observed"
    shutil.rmtree(bundle / "decoded")
    (bundle / CSV_SOURCE).unlink()
    for sources in ([CSV_SOURCE], [RECORD_SOURCE], None):
        result = decode_presentmon.decode(bundle, sources=sources, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and "missing from the bundle" in result["reason"], result
        assert not (bundle / "decoded").exists()
    nowhere = bundle / "nowhere"
    assert decode_presentmon.decode(nowhere, decoded_at=DECODED_AT)["status"] == "decode_failed"
    assert not nowhere.exists()


def test_only_observed_captures_are_inputs(bundle_copy):
    bundle = bundle_copy(HAPPY)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collectors"][0]["status"] = "observed_zero"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "not_collected" and not (bundle / "decoded").exists(), "observed_zero is not a status this collector reports, so it is never an input"


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_presentmon.main(["--bundle", str(bundle_copy(HAPPY)), "--decoded-at", DECODED_AT]) == 0
    assert "10 rows from 2 source files, status observed" in capsys.readouterr().out
    assert decode_presentmon.main(["--bundle", str(bundle_copy("presentmon-frames-no-frames"))]) == 2
    assert "not_collected" in capsys.readouterr().err
    assert decode_presentmon.main(["--bundle", str(bundle_copy("presentmon-frames-no-binary"))]) == 2


# ---------------------------------------------------------------- the pinned column list

def test_the_column_map_matches_the_schema_and_the_fixture_header():
    schema = wf_schema.schema("decoded/presentmon_frames.schema.json")
    columns = set(schema["properties"]) - {"provenance", "raw_columns"}
    assert set(decode_presentmon.COLUMN_MAP.values()) == columns, "every schema column has exactly one PresentMon column and nothing else is mapped"
    assert "cpu_start_qpc" in schema["required"] and "cpu_start_time_s" not in schema["properties"]
    header, _ = read_csv(BUNDLES / HAPPY)
    assert header == HEADER_2_6_0
    assert set(header) <= set(decode_presentmon.COLUMN_MAP), set(header) - set(decode_presentmon.COLUMN_MAP)
