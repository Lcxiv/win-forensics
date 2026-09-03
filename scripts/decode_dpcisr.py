#!/usr/bin/env python3
"""Decode an ``xperf -i trace.etl -a dpcisr`` text report into two decoded tables.

Tables (see docs/contracts/decoded-tables.md sections 5.1 and 5.2):

* ``dpcisr_module_cpu``: one row per (kind, module, cpu) cell of the
  "CPU Usage Summing By Module For the Whole Trace" tables.
* ``dpcisr_interval``: one row per (kind, interval, cpu) cell of the
  "Usage From ... Summing In N second intervals" tables.

Every row carries a provenance object whose ``row_id_or_offset`` is the 1-based
line number of the raw line it was parsed from.

Usage::

    python scripts/decode_dpcisr.py --bundle fixtures/example-bundle \
        --source raw/dpcisr/xperf_analysis.txt [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_dpcisr"
DECODER_VERSION = "1.0.0"
TOOL = {"name": "xperf -a dpcisr", "version": None}

RE_SECTION = {"DPC Info": "dpc", "Interrupt Info": "isr"}
RE_SPAN = re.compile(r"^CPU Usage from (\d+) us to (\d+) us:\s*$")
RE_CPU_HEADER = re.compile(r"CPU (\d+) Usage")
RE_CELL = re.compile(r"^\s*(\d+)\s+([\d.]+)\s*$")
RE_TOTAL = re.compile(r"^Total = (\d+)\s*$")
RE_MODULE_TOTAL = re.compile(r"^Total = (\d+) for module (.+?)\s*$")
RE_EQUAL = re.compile(r"^All Module = (\d+),\s+Total = (\d+),\s+(EQUAL|NOT EQUAL)\s*$")
RE_INTERVAL_HDR = re.compile(r"^Usage From (\d+) ms to (\d+) ms, Summing In (\d+) second intervals\. Intervals=(\d+)\s*$")
RE_INTERVAL_ROW = re.compile(r"^\s*(\d+)-(\d+)\s*:,(.*)$")


@dataclass
class Section:
    kind: str
    span_start_us: int | None = None
    span_end_us: int | None = None
    cpus: list[int] = field(default_factory=list)
    module_rows: list[dict[str, Any]] = field(default_factory=list)
    interval_rows: list[dict[str, Any]] = field(default_factory=list)
    total_count: int | None = None
    module_totals: dict[str, int] = field(default_factory=dict)
    equal_line: str | None = None
    equal_ok: bool = False
    unconsumed_sections: list[str] = field(default_factory=list)


class DecodeError(Exception):
    pass


def provenance(source_file: str, line_no: int, table: str) -> dict[str, str]:
    return {
        "source_file": source_file,
        "row_id_or_offset": f"line:{line_no}",
        "decoded_table": table,
        "decoder_version": DECODER_VERSION,
        "schema_version": wf_schema.table_schema_version(table),
    }


def parse_report(text: str, source_file: str) -> list[Section]:
    lines = text.splitlines()
    sections: list[Section] = []
    current: Section | None = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        line_no = i + 1
        stripped = line.strip()
        if stripped in RE_SECTION:
            current = Section(kind=RE_SECTION[stripped])
            sections.append(current)
            i += 1
            continue
        if current is None:
            i += 1
            continue
        m = RE_SPAN.match(stripped)
        if m:
            current.span_start_us = int(m.group(1))
            current.span_end_us = int(m.group(2))
            # header line with "CPU n Usage" cells follows after a blank line
            j = i + 1
            while j < n and not RE_CPU_HEADER.search(lines[j]):
                j += 1
            if j >= n:
                raise DecodeError(f"line {line_no}: CPU header not found after span line")
            current.cpus = [int(c) for c in RE_CPU_HEADER.findall(lines[j])]
            # next line is the "usec %, ..., Module" legend
            j += 2
            while j < n and lines[j].strip():
                row_line = lines[j]
                cells = [c for c in row_line.split(",")]
                if len(cells) != len(current.cpus) + 1:
                    raise DecodeError(f"line {j + 1}: expected {len(current.cpus) + 1} fields, found {len(cells)}")
                module = cells[-1].strip()
                if not module:
                    raise DecodeError(f"line {j + 1}: empty module name")
                for cpu, cell in zip(current.cpus, cells[:-1]):
                    mc = RE_CELL.match(cell)
                    if not mc:
                        raise DecodeError(f"line {j + 1}: cannot parse cell {cell!r}")
                    current.module_rows.append({
                        "kind": current.kind,
                        "module": module,
                        "cpu": cpu,
                        "usec": int(mc.group(1)),
                        "percent": float(mc.group(2)),
                        "trace_span_start_us": current.span_start_us,
                        "trace_span_end_us": current.span_end_us,
                        "provenance": provenance(source_file, j + 1, "dpcisr_module_cpu"),
                    })
                j += 1
            i = j
            continue
        m = RE_MODULE_TOTAL.match(stripped)
        if m:
            current.module_totals[m.group(2)] = int(m.group(1))
            i += 1
            continue
        m = RE_TOTAL.match(stripped)
        if m and current.total_count is None:
            current.total_count = int(m.group(1))
            i += 1
            continue
        m = RE_EQUAL.match(stripped)
        if m:
            current.equal_line = stripped
            current.equal_ok = m.group(3) == "EQUAL"
            i += 1
            continue
        m = RE_INTERVAL_HDR.match(stripped)
        if m:
            j = i + 1
            while j < n and not RE_CPU_HEADER.search(lines[j]):
                j += 1
            if j >= n:
                raise DecodeError(f"line {line_no}: interval CPU header not found")
            cpus = [int(c) for c in RE_CPU_HEADER.findall(lines[j])]
            j += 2  # skip the "(usec) %" legend line
            while j < n and lines[j].strip():
                mr = RE_INTERVAL_ROW.match(lines[j])
                if not mr:
                    raise DecodeError(f"line {j + 1}: cannot parse interval row {lines[j]!r}")
                cells = mr.group(3).split(",")
                if len(cells) != len(cpus):
                    raise DecodeError(f"line {j + 1}: expected {len(cpus)} interval cells, found {len(cells)}")
                for cpu, cell in zip(cpus, cells):
                    mc = RE_CELL.match(cell)
                    if not mc:
                        raise DecodeError(f"line {j + 1}: cannot parse interval cell {cell!r}")
                    current.interval_rows.append({
                        "kind": current.kind,
                        "interval_start_ms": int(mr.group(1)),
                        "interval_end_ms": int(mr.group(2)),
                        "cpu": cpu,
                        "usec": int(mc.group(1)),
                        "percent": float(mc.group(2)),
                        "provenance": provenance(source_file, j + 1, "dpcisr_interval"),
                    })
                j += 1
            i = j
            continue
        if stripped.startswith("Distribution of number of"):
            current.unconsumed_sections.append(f"line:{line_no} {stripped}")
        i += 1
    if not sections:
        raise DecodeError("no 'DPC Info' or 'Interrupt Info' section found")
    return sections


def checks_for(sections: list[Section]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for s in sections:
        checks.append({"name": f"{s.kind}_span_present", "ok": s.span_start_us is not None,
                       "detail": None if s.span_start_us is None else f"{s.span_start_us} us to {s.span_end_us} us"})
        checks.append({"name": f"{s.kind}_report_equal_line", "ok": s.equal_ok,
                       "detail": s.equal_line})
        hist_sum = sum(s.module_totals.values())
        checks.append({"name": f"{s.kind}_histogram_totals_reconcile",
                       "ok": s.total_count is not None and hist_sum == s.total_count,
                       "detail": f"sum of per module totals {hist_sum}, section total {s.total_count}"})
        modules_in_table = {r["module"] for r in s.module_rows}
        checks.append({"name": f"{s.kind}_histogram_modules_match_table",
                       "ok": set(s.module_totals) == modules_in_table,
                       "detail": f"table modules {len(modules_in_table)}, histogram modules {len(s.module_totals)}"})
        for u in s.unconsumed_sections:
            checks.append({"name": f"{s.kind}_unconsumed_section", "ok": True, "detail": u})
    return checks


def decode(bundle: Path, source: str, decoded_at: str | None = None) -> dict[str, Any]:
    raw_path = bundle / source
    text = raw_path.read_text(encoding="utf-8-sig")
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, reason, sections, checks = "observed", None, [], []
    try:
        sections = parse_report(text, source)
        checks = checks_for(sections)
        if not all(c["ok"] for c in checks):
            status, reason = "decode_failed", "a decoder self check failed; see checks"
    except DecodeError as exc:
        status, reason = "decode_failed", str(exc)

    module_rows = [r for s in sections for r in s.module_rows]
    interval_rows = [r for s in sections for r in s.interval_rows]
    if status == "observed" and not module_rows:
        status, reason = "decode_failed", "report parsed but no module rows were found"

    span = None
    if sections and sections[0].span_start_us is not None:
        span = {"start": sections[0].span_start_us, "end": sections[0].span_end_us, "domain": "etw_qpc_relative", "unit": "us"}
    result: dict[str, Any] = {"status": status, "reason": reason, "tables": {}}
    src_entry = [{"path": source, "sha256": wf_schema.sha256_of(raw_path)}]
    for table, rows, rng in (("dpcisr_module_cpu", module_rows, span),
                             ("dpcisr_interval", interval_rows,
                              None if not interval_rows else {"start": min(r["interval_start_ms"] for r in interval_rows),
                                                              "end": max(r["interval_end_ms"] for r in interval_rows),
                                                              "domain": "etw_qpc_relative", "unit": "ms"})):
        errors = wf_schema.validate_rows(rows, f"decoded/{table}.schema.json")
        if errors:
            status, reason = "decode_failed", "; ".join(errors[:3])
            rows = []
        out_path = decoded_dir / f"{table}.jsonl"
        wf_schema.write_jsonl(out_path, rows)
        meta = {
            "decoded_table": table,
            "schema_version": wf_schema.table_schema_version(table),
            "decoder": DECODER,
            "decoder_version": DECODER_VERSION,
            "tool": TOOL,
            "source_files": src_entry,
            "row_count": len(rows),
            "time_domain": "etw_qpc_relative",
            "native_time_range": rng if rows else None,
            "status": status if rows or status != "observed" else "observed_zero",
            "status_reason": reason,
            "checks": checks,
            "decoded_at_utc": decoded_at,
        }
        meta_errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
        if meta_errors:
            raise SystemExit(f"internal error: sidecar for {table} fails its schema: {meta_errors}")
        wf_schema.write_json(decoded_dir / f"{table}.meta.json", meta)
        result["tables"][table] = {"rows": len(rows), "status": meta["status"]}
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path, help="bundle directory (contains raw/ and decoded/)")
    ap.add_argument("--source", required=True, help="bundle relative path of the xperf dpcisr report, for example raw/dpcisr/report.txt")
    ap.add_argument("--decoded-at", default=None, help="override decoded_at_utc (ISO 8601 Z) for reproducible fixtures")
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    for table, info in result["tables"].items():
        print(f"{table}: {info['rows']} rows, status {info['status']}")
    if result["status"] != "observed":
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
