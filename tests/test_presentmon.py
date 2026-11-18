"""The PresentMon decoder turns the synthetic frame captures into presentmon_frames rows with provenance.

The inputs are the ``presentmon-frames*`` bundles under fixtures/collector-bundles, written by the
real collector against the synthetic backend; every frame in them is invented. Nothing here comes
from a real machine.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
from pathlib import Path

import pytest

import decode_presentmon
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
HAPPY = "presentmon-frames"
QUIET = "presentmon-frames-quiet"
SOURCE = "raw/presentmon_frames/frames.csv"
DECODED_AT = "2026-09-03T00:00:00Z"
OBSERVED = ("observed", "observed_zero")


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
    with (bundle / SOURCE).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\r\n")
        writer.writerow(header)
        writer.writerows(records)
    relist(bundle, SOURCE)


def read_csv(bundle: Path) -> tuple[list[str], list[list[str]]]:
    with (bundle / SOURCE).open("r", encoding="utf-8-sig", newline="") as fh:
        records = list(csv.reader(fh))
    return records[0], records[1:]


def rows_and_meta(bundle: Path):
    rows = wf_schema.read_jsonl(bundle / "decoded" / "presentmon_frames.jsonl")
    meta = json.loads((bundle / "decoded" / "presentmon_frames.meta.json").read_text(encoding="utf-8"))
    return rows, meta


# ---------------------------------------------------------------- the committed captures

def test_the_capture_decodes_into_validated_rows_with_qpc_time(bundle_copy):
    bundle = bundle_copy(HAPPY)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result == {"status": "observed", "reason": None, "rows": 10, "sources": 1}
    rows, meta = rows_and_meta(bundle)
    assert wf_schema.validate_rows(rows, "decoded/presentmon_frames.schema.json") == []
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["row_count"] == len(rows) == 10
    assert meta["time_domain"] == "etw_qpc", "the collector passes --qpc_time, so CPUStartQPC is present"
    assert meta["tool"] == {"name": decode_presentmon.TOOL_NAME, "version": "2.6.0"}, "the version the collector verified"
    assert meta["native_time_range"]["unit"] == "qpc_ticks" and meta["native_time_range"]["domain"] == "etw_qpc"
    qpc = [r["cpu_start_qpc"] for r in rows]
    assert meta["native_time_range"] == {"start": min(qpc), "end": max(qpc), "domain": "etw_qpc", "unit": "qpc_ticks"}
    assert all(r["cpu_start_time_s"] is None and isinstance(r["cpu_start_qpc"], int) for r in rows)
    assert {r["application"] for r in rows} == {"SyntheticGame.exe", "<unknown>"}
    assert sum(r["application"] == "<unknown>" for r in rows) == 2
    assert all(c["ok"] for c in meta["checks"]), meta["checks"]
    names = [c["name"] for c in meta["checks"]]
    assert names == [f"header_mapped:{SOURCE}", f"rows_read:{SOURCE}", f"qpc_increases_per_swap_chain:{SOURCE}", "processes", "rows_validate"]
    assert "32 of 32 columns mapped" in meta["checks"][0]["detail"]
    assert "2 frames of <unknown> processes" in meta["checks"][1]["detail"]
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    listed = next(a for c in manifest["collectors"] for a in c["artifacts"] if a["path"] == SOURCE)
    assert meta["source_files"] == [{"path": SOURCE, "sha256": listed["sha256"]}]
    # The decoded table is part of the container: the bundle still verifies with it present.
    assert verify_bundle.verify(bundle)["ok"]


def test_every_row_points_at_its_csv_row_and_keeps_na_as_null(bundle_copy):
    bundle = bundle_copy(HAPPY)
    decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    rows, _ = rows_and_meta(bundle)
    header, records = read_csv(bundle)
    inverse = {v: k for k, v in decode_presentmon.COLUMN_MAP.items()}
    for row in rows:
        prov = row["provenance"]
        assert prov["source_file"] == SOURCE and prov["decoded_table"] == "presentmon_frames"
        assert prov["decoder_version"] == decode_presentmon.DECODER_VERSION
        assert prov["schema_version"] == wf_schema.table_schema_version("presentmon_frames")
        n = int(re.fullmatch(r"row:(\d+)", prov["row_id_or_offset"]).group(1))
        record = dict(zip(header, records[n - 1]))
        assert record["Application"] == row["application"] and int(record["ProcessID"]) == row["process_id"]
        assert int(record["CPUStartQPC"]) == row["cpu_start_qpc"]
        assert record["PresentMode"] == row["present_mode"] and record["SwapChainAddress"] == row["swap_chain_address"]
        for column, value in row.items():
            if column in ("provenance", "raw_columns", "cpu_start_time_s"):
                continue
            cell = record[inverse[column]].strip()
            if value is None:
                assert cell == "NA", (column, cell)
            elif isinstance(value, str):
                assert cell == value
            elif isinstance(value, bool):
                raise AssertionError("no boolean column")
            else:
                assert float(cell) == value, (column, cell, value)
        assert "raw_columns" not in row, "every 2.6.0 default column is mapped"
    # The documented NA case is present in the fixture: a frame that was not displayed.
    assert any(r["displayed_time_ms"] is None for r in rows)
    assert all(r["ms_click_to_photon_latency"] is None or r["ms_click_to_photon_latency"] > 0 for r in rows)


def test_a_header_only_capture_is_observed_zero_and_an_uncaptured_bundle_is_not_decoded(bundle_copy):
    bundle = bundle_copy(QUIET)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed_zero" and result["rows"] == 0
    rows, meta = rows_and_meta(bundle)
    assert rows == [] and meta["row_count"] == 0 and meta["native_time_range"] is None
    assert meta["status"] == "observed_zero" and "no frame rows" in meta["status_reason"]
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    for case in ("presentmon-frames-no-binary", "presentmon-frames-access-denied"):
        bundle = bundle_copy(case)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "not_collected" and result["rows"] == 0, case
        assert not (bundle / "decoded").exists(), "an absent input is not decoded into an empty table"
        # Naming the CSV explicitly does not help: the manifest lists no observed capture.
        result = decode_presentmon.decode(bundle, sources=[SOURCE], decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and "not listed" in result["reason"]
        assert not (bundle / "decoded").exists()


# ---------------------------------------------------------------- shapes the pinned README documents

def test_cpustarttime_is_relative_monotonic_and_other_start_columns_are_refused(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    index = header.index("CPUStartQPC")
    header[index] = "CPUStartTime"
    for record in records:
        record[index] = f"{int(record[index]) / 10_000_000:.6f}"
    rewrite_csv(bundle, header, records)
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "observed", result
    rows, meta = rows_and_meta(bundle)
    assert meta["time_domain"] == "relative_monotonic" and meta["native_time_range"]["unit"] == "s"
    assert all(r["cpu_start_qpc"] is None and isinstance(r["cpu_start_time_s"], float) for r in rows)
    assert wf_schema.validate_rows(rows, "decoded/presentmon_frames.schema.json") == []
    for other in ("CPUStartQPCTime", "CPUStartDateTime"):
        header[index] = other
        rewrite_csv(bundle, header, records)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and other in result["reason"] and "exactly one is needed" in result["reason"]
        rows, meta = rows_and_meta(bundle)
        assert rows == [] and meta["status"] == "decode_failed"
    header[index] = "CPUStartQPC"
    header.append("CPUStartTime")
    rewrite_csv(bundle, header, [r + ["0.5"] for r in records])
    result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
    assert result["status"] == "decode_failed" and "2 of CPUStartQPC and CPUStartTime" in result["reason"]


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
    assert "unmapped kept in raw_columns: VidPnSourceId, LayerIndex, PresentId, SomethingNew" in meta["checks"][0]["detail"]
    assert "32 of 36 columns mapped" in meta["checks"][0]["detail"]


def test_malformed_csv_content_is_decode_failed_with_the_row_named(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    cases = {
        "ragged": ([r[:6] if i == 2 else r for i, r in enumerate(records)], "data row 3 has 6 cells"),
        "process id": ([[*r[:1], "abc", *r[2:]] if i == 0 else r for i, r in enumerate(records)], "column ProcessID: 'abc' is not an integer"),
        "qpc": ([[*r[:9], "12.5", *r[10:]] if i == 4 else r for i, r in enumerate(records)], "column CPUStartQPC: '12.5' is not an integer"),
        "number": ([[*r[:10], "fast", *r[11:]] if i == 1 else r for i, r in enumerate(records)], "column MsCPUBusy: 'fast' is not a number"),
    }
    for name, (bad_records, reason) in cases.items():
        rewrite_csv(bundle, header, bad_records)
        result = decode_presentmon.decode(bundle, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and reason in result["reason"], (name, result)
        rows, meta = rows_and_meta(bundle)
        assert rows == [] and meta["status"] == "decode_failed" and meta["row_count"] == 0
        assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    # A header that is not PresentMon's, a repeated column, and an empty file.
    rewrite_csv(bundle, ["time", "value"], [["1", "2"]])
    assert "not a PresentMon header" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]
    rewrite_csv(bundle, header + ["Application"], [r + ["x"] for r in records])
    assert "repeats the column 'Application'" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]
    (bundle / SOURCE).write_bytes(b"")
    relist(bundle, SOURCE)
    assert "not even a header" in decode_presentmon.decode(bundle, decoded_at=DECODED_AT)["reason"]


def test_schema_violations_in_a_well_formed_csv_are_decode_failed(bundle_copy):
    bundle = bundle_copy(HAPPY)
    header, records = read_csv(bundle)
    index = header.index("AllowsTearing")
    records[3][index] = "2"
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
    (bundle / SOURCE).unlink()
    for sources in ([SOURCE], None):
        result = decode_presentmon.decode(bundle, sources=sources, decoded_at=DECODED_AT)
        assert result["status"] == "decode_failed" and "missing from the bundle" in result["reason"]
        assert not (bundle / "decoded").exists()
    nowhere = bundle / "nowhere"
    assert decode_presentmon.decode(nowhere, decoded_at=DECODED_AT)["status"] == "decode_failed"
    assert not nowhere.exists()


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_presentmon.main(["--bundle", str(bundle_copy(HAPPY)), "--decoded-at", DECODED_AT]) == 0
    assert "10 rows from 1 CSV files, status observed" in capsys.readouterr().out
    assert decode_presentmon.main(["--bundle", str(bundle_copy(QUIET))]) == 0
    assert decode_presentmon.main(["--bundle", str(bundle_copy("presentmon-frames-no-binary"))]) == 2
    assert "not_collected" in capsys.readouterr().err


# ---------------------------------------------------------------- the pinned column list

def test_the_column_map_matches_the_schema_and_the_fixture_header():
    schema = wf_schema.schema("decoded/presentmon_frames.schema.json")
    columns = set(schema["properties"]) - {"provenance", "raw_columns"}
    assert set(decode_presentmon.COLUMN_MAP.values()) == columns, "every schema column has exactly one PresentMon column and nothing else is mapped"
    header, _ = read_csv(BUNDLES / HAPPY)
    assert set(header) <= set(decode_presentmon.COLUMN_MAP), set(header) - set(decode_presentmon.COLUMN_MAP)
    assert "CPUStartQPC" in header and "CPUStartTime" not in header
    # The contract's section 5.5 names the decoder and the time domain rule this decoder applies.
    contract = (REPO_ROOT / "docs" / "contracts" / "decoded-tables.md").read_text(encoding="utf-8")
    section = contract[contract.index("### 5.5"):contract.index("### 5.6")]
    assert "scripts/decode_presentmon.py" in section and "later phase" not in section
    assert "raw_columns" in section and "etw_qpc" in section
