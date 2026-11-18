"""The PresentMon decoder turns the synthetic frame captures into presentmon_frames rows with provenance.

The inputs are the ``presentmon-frames*`` bundles under fixtures/collector-bundles, written by the
real collector against the synthetic backend: an invented recording whose log file header follows
TRACE_LOGFILE_HEADER, and an invented CSV in the header PresentMon 2.6.0 writes for its default
options with --qpc_time. Nothing here comes from a real machine.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
import struct
from pathlib import Path

import pytest

import decode_presentmon
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
HAPPY = "presentmon-frames"
QUIET = "presentmon-frames-quiet"
CSV_SOURCE = "raw/presentmon_frames/frames.csv"
ETL_SOURCE = "raw/presentmon_frames/trace.etl"
DECODED_AT = "2026-09-03T00:00:00Z"
OBSERVED = ("observed", "observed_zero")
# The header PresentMon 2.6.0 writes for the console application's default options with --qpc_time
# (CsvOutput.cpp WriteCsvHeader<FrameMetrics>, lines 531 to 667 at tag v2.6.0).
HEADER_2_6_0 = ("Application,ProcessID,SwapChainAddress,PresentRuntime,SyncInterval,PresentFlags,AllowsTearing,PresentMode,TimeInQPC,"
                "MsBetweenSimulationStart,MsBetweenPresents,MsBetweenDisplayChange,MsInPresentAPI,MsRenderPresentLatency,MsUntilDisplayed,"
                "CPUStartQPC,MsBetweenAppStart,MsCPUBusy,MsCPUWait,MsGPULatency,MsGPUTime,MsGPUBusy,MsGPUWait,MsAnimationError,AnimationTime,"
                "MsFlipDelay,MsAllInputToPhotonLatency,MsClickToPhotonLatency").split(",")


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str) -> Path:
        dst = tmp_path / case
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
    with (bundle / CSV_SOURCE).open("w", encoding="utf-8-sig", newline="") as fh:
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


def patch_etl_header(bundle: Path, *, reserved_flags: int | None = None, events_lost: int | None = None, break_guid: bool = False) -> None:
    """Edit the invented recording's header the way the decoder reads it."""
    path = bundle / ETL_SOURCE
    data = bytearray(path.read_bytes())
    at = data.find(decode_presentmon.EVENT_TRACE_GUID, 24)
    p = at - 24 + 48
    pointer_size = struct.unpack_from("<I", data, p + 44)[0]
    tail = p + 56 + 2 * pointer_size + 176
    if reserved_flags is not None:
        struct.pack_into("<I", data, tail + 24, reserved_flags)
    if events_lost is not None:
        struct.pack_into("<I", data, p + 48, events_lost)
    if break_guid:
        data[at] ^= 0xFF
    path.write_bytes(bytes(data))
    relist(bundle, ETL_SOURCE)


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
    assert names == [f"etl_header:{ETL_SOURCE}", f"etl_no_loss:{ETL_SOURCE}", f"header_mapped:{CSV_SOURCE}", f"rows_read:{CSV_SOURCE}",
                     f"qpc_increases_per_swap_chain:{CSV_SOURCE}", "processes", "rows_validate"]
    assert "clock qpc, PerfFreq 10000000 Hz" in meta["checks"][0]["detail"]
    assert "28 of 28 columns mapped" in meta["checks"][2]["detail"]
    assert "2 frames of <unknown> processes" in meta["checks"][3]["detail"]
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    listed = {a["path"]: a for c in manifest["collectors"] for a in c["artifacts"]}
    assert meta["source_files"] == [{"path": ETL_SOURCE, "sha256": listed[ETL_SOURCE]["sha256"]}, {"path": CSV_SOURCE, "sha256": listed[CSV_SOURCE]["sha256"]}]
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


def test_a_recording_without_frames_is_observed_zero_and_an_uncaptured_bundle_is_not_decoded(bundle_copy):
    bundle = bundle_copy(QUIET)
    assert not (bundle / CSV_SOURCE).exists(), "PresentMon creates the CSV at the first frame; none here"
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed_zero" and result["rows"] == 0 and result["sources"] == 1
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["row_count"] == 0 and meta["native_time_range"] is None
    assert meta["status"] == "observed_zero" and "no frame" in meta["status_reason"]
    assert meta["time_domain"] == "etw_qpc" and [s["path"] for s in meta["source_files"]] == [ETL_SOURCE]
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    for case in ("presentmon-frames-no-binary", "presentmon-frames-access-denied", "presentmon-frames-lost-events"):
        bundle = bundle_copy(case)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "not_collected" and result["rows"] == 0, case
        assert not (bundle / "decoded").exists(), "an absent or failed capture is not decoded into an empty table"
    # A recording with lost events is kept in its bundle but is never an input: naming it does not help.
    assert (bundle / ETL_SOURCE).exists(), "the lost events bundle keeps its recording for inspection"
    result = decode_presentmon.decode(bundle, sources=[ETL_SOURCE], decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "not listed" in result["reason"]
    assert not (bundle / "decoded").exists()


# ---------------------------------------------------------------- the recording's header decides the domain

def test_the_clock_comes_from_the_recording_header(bundle_copy):
    bundle = bundle_copy(HAPPY)
    patch_etl_header(bundle, reserved_flags=2)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed", result
    _, meta = rows_and_meta(bundle)
    assert meta["time_domain"] == "system_time" and meta["native_time_range"]["unit"] == "filetime_100ns"
    patch_etl_header(bundle, reserved_flags=3)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "CPU cycle counter" in result["reason"]
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["time_domain"] == "none" and meta["status"] == "decode_failed"
    patch_etl_header(bundle, reserved_flags=1, break_guid=True)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "log file header could not be read" in result["reason"]


def test_loss_in_the_header_is_reported_against_the_manifest(bundle_copy):
    bundle = bundle_copy(HAPPY)
    patch_etl_header(bundle, events_lost=7)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed", "the collector's status is the authority; the decoder reports the disagreement"
    _, meta = rows_and_meta(bundle)
    checks = {c["name"]: c for c in meta["checks"]}
    assert checks[f"etl_no_loss:{ETL_SOURCE}"]["ok"] is False
    assert checks[f"etl_events_lost_agrees:{ETL_SOURCE}"]["ok"] is False
    assert "the manifest records 0 events lost" in checks[f"etl_events_lost_agrees:{ETL_SOURCE}"]["detail"]


def test_read_etl_header_reads_the_documented_fields():
    header = decode_presentmon.read_etl_header(BUNDLES / HAPPY / ETL_SOURCE)
    assert header["found"] is True
    assert header["clock_type"] == "qpc" and header["reserved_flags"] == 1
    assert header["perf_freq_hz"] == 10_000_000 and header["pointer_size"] == 8
    assert header["events_lost"] == 0 and header["buffers_lost"] == 0 and header["buffers_written"] == 40
    assert header["start_time_utc"] < header["end_time_utc"]
    assert header["end_time_utc"].startswith("2026-03-01T12:01:0")
    lost = decode_presentmon.read_etl_header(BUNDLES / "presentmon-frames-lost-events" / ETL_SOURCE)
    assert lost["events_lost"] == 12
    missing = decode_presentmon.read_etl_header(BUNDLES / HAPPY / "raw" / "presentmon_frames" / "command.json")
    assert missing["found"] is False and "EventTraceGuid" in missing["error"]


# ---------------------------------------------------------------- shapes the pinned source documents

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
        "raw/presentmon_frames/unlisted.csv": "not listed",
    }
    for source, reason in cases.items():
        result = decode_presentmon.decode(bundle, sources=[source], decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (source, result)
        assert not (bundle / "decoded").exists(), source
    assert decode_presentmon.decode(bundle, sources=[], decoded_at=DECODED_AT)["reason"] == "no source was named"
    # Naming either file of the capture decodes the capture.
    assert decode_presentmon.decode(bundle, sources=[ETL_SOURCE], decoded_at=DECODED_AT)["status"] == "observed"
    shutil.rmtree(bundle / "decoded")
    (bundle / CSV_SOURCE).unlink()
    for sources in ([CSV_SOURCE], None):
        result = decode_presentmon.decode(bundle, sources=sources, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and ("missing from the bundle" in result["reason"] or "no frames.csv" in result["reason"]), result
        assert not (bundle / "decoded").exists()
    nowhere = bundle / "nowhere"
    assert decode_presentmon.decode(nowhere, decoded_at=DECODED_AT)["status"] == "decode_failed"
    assert not nowhere.exists()


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_presentmon.main(["--bundle", str(bundle_copy(HAPPY)), "--decoded-at", DECODED_AT]) == 0
    assert "10 rows from 2 source files, status observed" in capsys.readouterr().out
    assert decode_presentmon.main(["--bundle", str(bundle_copy(QUIET))]) == 0
    assert decode_presentmon.main(["--bundle", str(bundle_copy("presentmon-frames-no-binary"))]) == 2
    assert "not_collected" in capsys.readouterr().err


# ---------------------------------------------------------------- the pinned column list

def test_the_column_map_matches_the_schema_and_the_fixture_header():
    schema = wf_schema.schema("decoded/presentmon_frames.schema.json")
    columns = set(schema["properties"]) - {"provenance", "raw_columns"}
    assert set(decode_presentmon.COLUMN_MAP.values()) == columns, "every schema column has exactly one PresentMon column and nothing else is mapped"
    assert "cpu_start_qpc" in schema["required"] and "cpu_start_time_s" not in schema["properties"]
    header, _ = read_csv(BUNDLES / HAPPY)
    assert header == HEADER_2_6_0
    assert set(header) <= set(decode_presentmon.COLUMN_MAP), set(header) - set(decode_presentmon.COLUMN_MAP)
    contract = (REPO_ROOT / "docs" / "contracts" / "decoded-tables.md").read_text(encoding="utf-8")
    section = contract[contract.index("### 5.5"):contract.index("### 5.6")]
    for term in ("scripts/decode_presentmon.py", "raw_columns", "etw_qpc", "--etl_file", "TRACE_LOGFILE_HEADER", "CPUStartQPC", "0.2.0"):
        assert term in section, term
    assert "scripts/decode_presentmon.py` (later phase)" not in section
    assert "the former `cpu_start_time_s` is gone" in section, "the contract records the 0.1.0 to 0.2.0 correction"
