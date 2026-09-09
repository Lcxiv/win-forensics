#!/usr/bin/env python3
"""Decode a PDH CSV counter log into the ``pdh_counters`` long form table.

See docs/contracts/decoded-tables.md section 5.4. One row per (sample, counter
path) cell; the provenance ``row_id_or_offset`` is ``row:<n>;col:<m>`` with the
1-based data row and the 1-based CSV column of the cell.

Usage::

    python scripts/decode_pdh.py --bundle fixtures/example-bundle \
        --source raw/pdh/percpu_dpc_20260424_slow.csv [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_pdh"
DECODER_VERSION = "1.0.0"
TABLE = "pdh_counters"
TOOL = {"name": "PDH CSV (Get-Counter, typeperf, or logman)", "version": None}

RE_HEADER = re.compile(r"^\(PDH-CSV (?P<ver>\d+\.\d+)\) \((?P<tz>.*)\)\((?P<bias>-?\d+)\)$")
RE_PATH = re.compile(r"^(?:\\\\(?P<machine>[^\\]+))?\\(?P<object>[^\\(]+?)(?:\((?P<instance>[^)]*)\))?\\(?P<counter>.+)$")
TIMESTAMP_FORMATS = ("%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S")


class DecodeError(Exception):
    pass


def parse_timestamp_local(text: str) -> datetime | None:
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def to_utc(local: datetime, bias_minutes: int) -> str:
    """PDH bias follows TIME_ZONE_INFORMATION: UTC = local + bias."""
    utc = (local + timedelta(minutes=bias_minutes)).replace(tzinfo=timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def parse_value(cell: str) -> float | None:
    s = cell.strip()
    if s == "":
        return None
    try:
        return float(s)
    except ValueError as exc:
        raise DecodeError(f"cannot parse counter value {cell!r}") from exc


def decode(bundle: Path, source: str, decoded_at: str | None = None) -> dict[str, Any]:
    raw_path = bundle / source
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    header_cells: list[str] = []
    null_counts: dict[int, int] = {}
    unparsed_timestamps = 0
    sample_count = 0
    try:
        with raw_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            header_cells = next(reader)
            m = RE_HEADER.match(header_cells[0])
            if not m:
                raise DecodeError(f"first header cell is not a PDH-CSV header: {header_cells[0]!r}")
            tz_name, bias = m.group("tz"), int(m.group("bias"))
            checks.append({"name": "pdh_header", "ok": True, "detail": header_cells[0]})
            paths = header_cells[1:]
            parsed_paths = []
            for idx, p in enumerate(paths, start=2):
                pm = RE_PATH.match(p)
                if not pm:
                    raise DecodeError(f"cannot parse counter path in column {idx}: {p!r}")
                parsed_paths.append((idx, p, pm.group("machine"), pm.group("object"), pm.group("instance"), pm.group("counter")))
            for data_row_index, record in enumerate(reader, start=1):
                if not record or all(not c.strip() for c in record):
                    continue
                if len(record) != len(header_cells):
                    raise DecodeError(f"data row {data_row_index} has {len(record)} cells, header has {len(header_cells)}")
                sample_count += 1
                ts_local = record[0]
                dt = parse_timestamp_local(ts_local)
                ts_utc = to_utc(dt, bias) if dt else None
                if dt is None:
                    unparsed_timestamps += 1
                for (col, path, machine, obj, inst, counter), cell in zip(parsed_paths, record[1:]):
                    value = parse_value(cell)
                    if value is None:
                        null_counts[col] = null_counts.get(col, 0) + 1
                    rows.append({
                        "sample_index": data_row_index,
                        "timestamp_local": ts_local,
                        "timestamp_utc": ts_utc,
                        "tz_name": tz_name,
                        "tz_bias_minutes": bias,
                        "counter_path": path,
                        "machine": machine,
                        "object": obj,
                        "instance": inst,
                        "counter": counter,
                        "value": value,
                        "provenance": {
                            "source_file": source,
                            "row_id_or_offset": f"row:{data_row_index};col:{col}",
                            "decoded_table": TABLE,
                            "decoder_version": DECODER_VERSION,
                            "schema_version": schema_version,
                        },
                    })
        checks.append({"name": "samples_present", "ok": sample_count > 0, "detail": f"{sample_count} samples, {len(header_cells) - 1} counter columns"})
        checks.append({"name": "timestamps_parsed", "ok": unparsed_timestamps == 0, "detail": f"{unparsed_timestamps} unparsed timestamps"})
        checks.append({"name": "null_cells", "ok": True,
                       "detail": ";".join(f"col:{c} nulls={n}" for c, n in sorted(null_counts.items())) or "none"})
        if sample_count == 0:
            status, reason = "observed_zero", "CSV has a header and no samples"
        errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    except (DecodeError, StopIteration, UnicodeDecodeError) as exc:
        status, reason, rows = "decode_failed", str(exc) or "empty file", []

    native_range = None
    if rows:
        stamps = [r["timestamp_utc"] for r in rows if r["timestamp_utc"]]
        if stamps:
            native_range = {"start": min(stamps), "end": max(stamps), "domain": "system_time", "unit": "iso_utc"}
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": schema_version,
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": TOOL,
        "source_files": [{"path": source, "sha256": wf_schema.sha256_of(raw_path)}],
        "row_count": len(rows),
        "time_domain": "system_time",
        "native_time_range": native_range,
        "status": status,
        "status_reason": reason,
        "checks": checks,
        "decoded_at_utc": decoded_at,
    }
    meta_errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if meta_errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {meta_errors}")
    wf_schema.write_json(decoded_dir / f"{TABLE}.meta.json", meta)
    return {"status": status, "reason": reason, "rows": len(rows), "samples": sample_count}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--source", required=True, help="bundle relative path of the PDH CSV, for example raw/pdh/counters.csv")
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    print(f"{TABLE}: {result['rows']} rows from {result['samples']} samples, status {result['status']}")
    if result["status"] not in ("observed", "observed_zero"):
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
