"""The two phase 0a decoders parse the format fixtures with real provenance."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timedelta

import pandas as pd
import pytest

import decode_dpcisr
import decode_pdh
import wf_schema

DPCISR_SOURCE = "raw/dpcisr/xperf_analysis.txt"
PDH_SOURCE = "raw/pdh/percpu_dpc_20260424_slow.csv"


def copy_raw(example_bundle, tmp_path, source):
    dst = tmp_path / source
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes((example_bundle / source).read_bytes())
    return dst


@pytest.fixture(scope="module")
def dpcisr_out(example_bundle, tmp_path_factory):
    bundle = tmp_path_factory.mktemp("dpcisr")
    copy_raw(example_bundle, bundle, DPCISR_SOURCE)
    result = decode_dpcisr.decode(bundle, DPCISR_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "observed", result
    return bundle


@pytest.fixture(scope="module")
def pdh_out(example_bundle, tmp_path_factory):
    bundle = tmp_path_factory.mktemp("pdh")
    copy_raw(example_bundle, bundle, PDH_SOURCE)
    result = decode_pdh.decode(bundle, PDH_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "observed", result
    return bundle


def raw_lines(bundle, source):
    return (bundle / source).read_text(encoding="utf-8-sig").splitlines()


# ---------------------------------------------------------------- dpcisr

def test_dpcisr_module_rows_validate_and_cover_every_cell(dpcisr_out):
    rows = wf_schema.read_jsonl(dpcisr_out / "decoded" / "dpcisr_module_cpu.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/dpcisr_module_cpu.schema.json") == []
    df = pd.DataFrame(rows)
    cpus = sorted(df["cpu"].unique())
    assert cpus == list(range(len(cpus))), "CPU indices must be contiguous from 0"
    for kind, group in df.groupby("kind"):
        modules = group["module"].nunique()
        assert len(group) == modules * len(cpus), f"{kind}: one row per module per CPU, zero cells included"
    assert set(df["kind"]) == {"dpc", "isr"}


def test_dpcisr_provenance_points_at_the_raw_line(dpcisr_out):
    lines = raw_lines(dpcisr_out, DPCISR_SOURCE)
    rows = wf_schema.read_jsonl(dpcisr_out / "decoded" / "dpcisr_module_cpu.jsonl")
    for row in rows:
        prov = row["provenance"]
        assert prov["source_file"] == DPCISR_SOURCE
        line_no = int(prov["row_id_or_offset"].removeprefix("line:"))
        raw = lines[line_no - 1]
        assert raw.rstrip().endswith(row["module"]), (line_no, row["module"])
        cells = raw.split(",")[:-1]
        usec, pct = cells[row["cpu"]].split()
        assert int(usec) == row["usec"] and float(pct) == row["percent"]


def test_dpcisr_interval_rows_validate_and_tile_the_trace(dpcisr_out):
    rows = wf_schema.read_jsonl(dpcisr_out / "decoded" / "dpcisr_interval.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/dpcisr_interval.schema.json") == []
    df = pd.DataFrame(rows)
    lines = raw_lines(dpcisr_out, DPCISR_SOURCE)
    for kind, group in df.groupby("kind"):
        intervals = group[["interval_start_ms", "interval_end_ms"]].drop_duplicates().sort_values("interval_start_ms")
        starts = intervals["interval_start_ms"].tolist()
        ends = intervals["interval_end_ms"].tolist()
        assert starts[0] == 0
        assert starts[1:] == ends[:-1], f"{kind}: intervals must be contiguous"
        assert len(group) == len(intervals) * group["cpu"].nunique()
    for row in rows[:50]:
        line_no = int(row["provenance"]["row_id_or_offset"].removeprefix("line:"))
        raw = lines[line_no - 1]
        assert re.match(rf"^\s*{row['interval_start_ms']}-{row['interval_end_ms']}\s*:,", raw), raw


def test_dpcisr_sidecars_validate_and_report_checks(dpcisr_out):
    for table in ("dpcisr_module_cpu", "dpcisr_interval"):
        meta = json.loads((dpcisr_out / "decoded" / f"{table}.meta.json").read_text())
        assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
        assert meta["status"] == "observed"
        assert meta["time_domain"] == "etw_qpc_relative"
        assert all(c["ok"] for c in meta["checks"]), meta["checks"]
        names = {c["name"] for c in meta["checks"]}
        assert {"dpc_report_equal_line", "dpc_histogram_totals_reconcile", "isr_report_equal_line"} <= names
        rows = wf_schema.read_jsonl(dpcisr_out / "decoded" / f"{table}.jsonl")
        assert meta["row_count"] == len(rows)
        assert meta["source_files"][0]["sha256"] == wf_schema.sha256_of(dpcisr_out / DPCISR_SOURCE)


def test_dpcisr_broken_report_is_decode_failed(tmp_path, example_bundle):
    bundle = tmp_path
    dst = copy_raw(example_bundle, bundle, DPCISR_SOURCE)
    text = dst.read_text(encoding="utf-8-sig")
    dst.write_text(text.replace("EQUAL", "NOT EQUAL", 1), encoding="utf-8")
    result = decode_dpcisr.decode(bundle, DPCISR_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "decode_failed"
    meta = json.loads((bundle / "decoded" / "dpcisr_module_cpu.meta.json").read_text())
    assert meta["status"] == "decode_failed"
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []


def test_dpcisr_truncated_report_is_decode_failed(tmp_path, example_bundle):
    dst = copy_raw(example_bundle, tmp_path, DPCISR_SOURCE)
    lines = dst.read_text(encoding="utf-8-sig").splitlines()
    dst.write_text("\n".join(lines[:20]), encoding="utf-8")
    result = decode_dpcisr.decode(tmp_path, DPCISR_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "decode_failed"


# ---------------------------------------------------------------- pdh

def test_pdh_rows_validate_and_cover_every_cell(pdh_out):
    rows = wf_schema.read_jsonl(pdh_out / "decoded" / "pdh_counters.jsonl")
    assert wf_schema.validate_rows(rows, "decoded/pdh_counters.schema.json") == []
    with (pdh_out / PDH_SOURCE).open(encoding="utf-8-sig", newline="") as fh:
        records = list(csv.reader(fh))
    header, data = records[0], [r for r in records[1:] if any(c.strip() for c in r)]
    assert len(rows) == len(data) * (len(header) - 1)
    df = pd.DataFrame(rows)
    assert df["sample_index"].min() == 1 and df["sample_index"].max() == len(data)
    assert set(df["counter"]) == {"% processor time", "% interrupt time", "% dpc time"}
    assert df[df["sample_index"] == 1]["value"].isna().all(), "PDH writes blanks for the first sample of rate counters"
    assert df[df["sample_index"] > 1]["value"].notna().all()


def test_pdh_provenance_points_at_the_raw_cell(pdh_out):
    with (pdh_out / PDH_SOURCE).open(encoding="utf-8-sig", newline="") as fh:
        records = list(csv.reader(fh))
    rows = wf_schema.read_jsonl(pdh_out / "decoded" / "pdh_counters.jsonl")
    for row in rows:
        m = re.fullmatch(r"row:(\d+);col:(\d+)", row["provenance"]["row_id_or_offset"])
        r, c = int(m.group(1)), int(m.group(2))
        assert records[0][c - 1] == row["counter_path"]
        cell = records[r][c - 1].strip()
        assert (row["value"] is None and cell == "") or float(cell) == row["value"]
        assert records[r][0] == row["timestamp_local"]


def test_pdh_utc_conversion_adds_the_header_bias(pdh_out):
    rows = wf_schema.read_jsonl(pdh_out / "decoded" / "pdh_counters.jsonl")
    for row in rows[::97]:
        local = datetime.strptime(row["timestamp_local"], "%m/%d/%Y %H:%M:%S.%f")
        expected = local + timedelta(minutes=row["tz_bias_minutes"])
        assert row["timestamp_utc"] == expected.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expected.microsecond // 1000:03d}Z"


def test_pdh_sidecar_validates(pdh_out):
    meta = json.loads((pdh_out / "decoded" / "pdh_counters.meta.json").read_text())
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["time_domain"] == "system_time"
    assert meta["status"] == "observed"
    assert meta["native_time_range"]["start"] < meta["native_time_range"]["end"]
    assert meta["checks"][0]["name"] == "pdh_header" and meta["checks"][0]["detail"].startswith("(PDH-CSV 4.0)")


def test_pdh_header_only_is_observed_zero(tmp_path, example_bundle):
    dst = copy_raw(example_bundle, tmp_path, PDH_SOURCE)
    first = dst.read_text(encoding="utf-8-sig").splitlines()[0]
    dst.write_text(first + "\n", encoding="utf-8")
    result = decode_pdh.decode(tmp_path, PDH_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "observed_zero" and result["rows"] == 0


def test_pdh_non_pdh_csv_is_decode_failed(tmp_path, example_bundle):
    dst = copy_raw(example_bundle, tmp_path, PDH_SOURCE)
    dst.write_text('"time","a"\n"1","2"\n', encoding="utf-8")
    result = decode_pdh.decode(tmp_path, PDH_SOURCE, decoded_at="2026-09-03T00:00:00Z")
    assert result["status"] == "decode_failed"


# ---------------------------------------------------------------- committed outputs are current

@pytest.mark.parametrize("table,fixture", [("dpcisr_module_cpu", "dpcisr_out"), ("dpcisr_interval", "dpcisr_out"), ("pdh_counters", "pdh_out")])
def test_committed_decoded_tables_match_a_fresh_decode(request, example_bundle, table, fixture):
    fresh = request.getfixturevalue(fixture)
    for suffix in (".jsonl", ".meta.json"):
        committed = (example_bundle / "decoded" / f"{table}{suffix}").read_bytes()
        regenerated = (fresh / "decoded" / f"{table}{suffix}").read_bytes()
        assert committed == regenerated, f"{table}{suffix} in the example bundle is stale; re-run the decoder"
