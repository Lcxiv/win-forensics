#!/usr/bin/env python3
"""Decode a PresentMon console CSV into the ``presentmon_frames`` table.

See docs/contracts/decoded-tables.md section 5.5. The input is the CSV the
``presentmon-frames`` collector keeps untouched as ``raw/presentmon_frames/frames.csv``
(collectors/windows/README.md names the pinned PresentMon version and the
options in effect). One row per CSV data row; the provenance
``row_id_or_offset`` is ``row:<n>`` with the 1-based data row, not counting
the header line.

Column names follow the PresentMon 2.6.0 console README ("CSV columns"),
turned into snake case with the unit suffixes the table contract uses. A
cell PresentMon writes as ``NA`` decodes to null. A column the decoder does
not know is kept verbatim under ``raw_columns`` so nothing is dropped when a
later PresentMon adds one. The CSV carries ``CPUStartQPC`` when PresentMon
ran with ``--qpc_time`` (the collector always passes it) and the table's time
domain is then ``etw_qpc``; a CSV with ``CPUStartTime`` instead is
``relative_monotonic``; a CSV with neither cannot be placed in a time domain
and is ``decode_failed``.

Without ``--source`` the decoder reads the manifest and takes the primary CSV
of every collector of kind ``presentmon`` whose status is ``observed`` or
``observed_zero``. A collector that did not capture has no such artifact,
and the decoder then reports ``not_collected`` and writes nothing: an input
that is absent is never decoded into zero rows.

Every ``--source`` must be a normalised bundle relative path, inside the
bundle, listed in the manifest as the primary CSV of a PresentMon collector
that is ``observed`` or ``observed_zero``, and present on disk; anything else
is ``decode_failed`` and nothing is written.

Usage::

    python scripts/decode_presentmon.py --bundle <bundle directory> \
        [--source raw/presentmon_frames/frames.csv ...] [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_presentmon"
DECODER_VERSION = "1.0.0"
TABLE = "presentmon_frames"
TOOL_NAME = "PresentMon console application (GameTechDev/PresentMon)"
OBSERVED = ("observed", "observed_zero")

# PresentMon 2.6.0 console README, "CSV columns", to the table's column names.
# The three columns that need --write_display_metadata (VidPnSourceId,
# LayerIndex, PresentId) are not mapped and land in raw_columns when present.
COLUMN_MAP = {
    "Application": "application",
    "ProcessID": "process_id",
    "SwapChainAddress": "swap_chain_address",
    "PresentRuntime": "present_runtime",
    "SyncInterval": "sync_interval",
    "PresentFlags": "present_flags",
    "AllowsTearing": "allows_tearing",
    "PresentMode": "present_mode",
    "FrameType": "frame_type",
    "CPUStartQPC": "cpu_start_qpc",
    "CPUStartTime": "cpu_start_time_s",
    "MsCPUBusy": "ms_cpu_busy",
    "MsCPUWait": "ms_cpu_wait",
    "MsGPULatency": "ms_gpu_latency",
    "MsGPUTime": "ms_gpu_time",
    "MsGPUBusy": "ms_gpu_busy",
    "MsGPUWait": "ms_gpu_wait",
    "VideoBusy": "video_busy_ms",
    "DisplayLatency": "display_latency_ms",
    "DisplayedTime": "displayed_time_ms",
    "MsAnimationError": "ms_animation_error",
    "AnimationTime": "animation_time_ms",
    "MsClickToPhotonLatency": "ms_click_to_photon_latency",
    "MsAllInputToPhotonLatency": "ms_all_input_to_photon_latency",
    "InstrumentedLatency": "instrumented_latency_ms",
    "MsBetweenPresents": "ms_between_presents",
    "MsInPresentAPI": "ms_in_present_api",
    "MsBetweenDisplayChange": "ms_between_display_change",
    "MsUntilDisplayed": "ms_until_displayed",
    "MsRenderPresentLatency": "ms_render_present_latency",
    "MsBetweenSimulationStart": "ms_between_simulation_start",
    "MsPCLatency": "ms_pc_latency",
    "MsBetweenAppStart": "ms_between_app_start",
}
# Required by the schema and never null: the strings PresentMon always writes
# and the integers that identify the present.
REQUIRED_STRINGS = ("application", "swap_chain_address", "present_runtime", "present_mode")
REQUIRED_INTEGERS = ("process_id", "sync_interval", "present_flags", "allows_tearing")
OPTIONAL_STRINGS = ("frame_type",)
# The start column decides the time domain (docs/contracts/timestamps.md).
START_COLUMNS = {"CPUStartQPC": ("cpu_start_qpc", "etw_qpc", "qpc_ticks"), "CPUStartTime": ("cpu_start_time_s", "relative_monotonic", "s")}
OTHER_START_COLUMNS = ("CPUStartQPCTime", "CPUStartDateTime")
NA = "NA"


class DecodeError(Exception):
    pass


def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc


def decodable_primaries(manifest: dict[str, Any]) -> list[str]:
    """The primary CSV artifacts of every PresentMon collector that is observed or observed_zero."""
    out = []
    for collector in manifest["collectors"]:
        if collector["kind"] != "presentmon" or collector["status"] not in OBSERVED:
            continue
        out += [a["path"] for a in collector["artifacts"] if a["role"] == "primary" and a["path"].endswith(".csv")]
    return out


def tool_version(manifest: dict[str, Any]) -> str | None:
    """The PresentMon version the collector verified, from manifest.tools."""
    for tool in manifest.get("tools", []):
        if tool.get("name") == "presentmon":
            return tool.get("version")
    return None


def check_source_path(bundle: Path, source: str, allowed: list[str]) -> None:
    """A source must be a normalised relative path inside the bundle, listed as decodable, and present."""
    if source != source.strip() or source.startswith(("/", "\\")) or "\\" in source:
        raise DecodeError(f"{source}: not a bundle relative path")
    parts = source.split("/")
    if any(part in ("", ".", "..") for part in parts) or not source.startswith("raw/"):
        raise DecodeError(f"{source}: not a normalised path under raw/")
    root = bundle.resolve()
    target = (bundle / source).resolve()
    if root not in target.parents:
        raise DecodeError(f"{source}: resolves outside the bundle")
    if source not in allowed:
        raise DecodeError(f"{source}: not listed in the manifest as the primary CSV of an observed PresentMon collector")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def parse_integer(text: str, column: str, source: str, row: int) -> int:
    s = text.strip()
    try:
        return int(s)
    except ValueError as exc:
        raise DecodeError(f"{source}: row {row}, column {column}: {text!r} is not an integer") from exc


def parse_number(text: str, column: str, source: str, row: int) -> float | None:
    s = text.strip()
    if s == NA or s == "":
        return None
    try:
        return float(s)
    except ValueError as exc:
        raise DecodeError(f"{source}: row {row}, column {column}: {text!r} is not a number") from exc


def read_header(header: list[str], source: str) -> tuple[list[tuple[int, str, str | None]], tuple[str, str, str]]:
    """Map the header to (column index, CSV name, table column or None) and pick the start column."""
    cells = [h.strip() for h in header]
    if not cells or "Application" not in cells or "ProcessID" not in cells:
        raise DecodeError(f"{source}: the header is not a PresentMon header (no Application and ProcessID columns): {','.join(cells)!r}")
    seen: set[str] = set()
    for cell in cells:
        if cell in seen:
            raise DecodeError(f"{source}: the header repeats the column {cell!r}")
        seen.add(cell)
    starts = [c for c in cells if c in START_COLUMNS]
    if len(starts) != 1:
        others = [c for c in cells if c in OTHER_START_COLUMNS]
        raise DecodeError(f"{source}: the header has {len(starts)} of CPUStartQPC and CPUStartTime"
                          + (f" (found {', '.join(others)}, which the table does not place in a time domain)" if others else "")
                          + "; exactly one is needed")
    mapped = [(index, cell, COLUMN_MAP.get(cell)) for index, cell in enumerate(cells)]
    return mapped, START_COLUMNS[starts[0]]


def decode_source(bundle: Path, source: str, schema_version: str) -> dict[str, Any]:
    """Return the rows of one CSV with the header facts the sidecar reports."""
    rows: list[dict[str, Any]] = []
    na_cells = 0
    unknown_rows = 0
    processes: dict[tuple[str, int], int] = {}
    unmapped: list[str] = []
    last_qpc: dict[tuple[int, str], int] = {}
    qpc_monotonic = True
    try:
        with (bundle / source).open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise DecodeError(f"{source}: the file is empty, not even a header") from exc
            mapped, (start_column, domain, unit) = read_header(header, source)
            unmapped = [name for _, name, column in mapped if column is None]
            for data_row, record in enumerate(reader, start=1):
                if not record or all(not c.strip() for c in record):
                    continue
                if len(record) != len(mapped):
                    raise DecodeError(f"{source}: data row {data_row} has {len(record)} cells, the header has {len(mapped)}")
                row: dict[str, Any] = {column: None for column in COLUMN_MAP.values()}
                raw_columns: dict[str, str | None] = {}
                for index, name, column in mapped:
                    text = record[index]
                    if column is None:
                        raw_columns[name] = None if text.strip() == NA else text
                        continue
                    if column in REQUIRED_STRINGS:
                        row[column] = text
                    elif column in OPTIONAL_STRINGS:
                        row[column] = None if text.strip() == NA else text
                    elif column in REQUIRED_INTEGERS or column == "cpu_start_qpc":
                        row[column] = parse_integer(text, name, source, data_row)
                    else:
                        value = parse_number(text, name, source, data_row)
                        if value is None:
                            na_cells += 1
                        row[column] = value
                if raw_columns:
                    row["raw_columns"] = raw_columns
                row["provenance"] = {
                    "source_file": source,
                    "row_id_or_offset": f"row:{data_row}",
                    "decoded_table": TABLE,
                    "decoder_version": DECODER_VERSION,
                    "schema_version": schema_version,
                }
                if row["application"] == "<unknown>":
                    unknown_rows += 1
                key = (row["application"], row["process_id"])
                processes[key] = processes.get(key, 0) + 1
                if start_column == "cpu_start_qpc":
                    chain = (row["process_id"], row["swap_chain_address"])
                    previous = last_qpc.get(chain)
                    if previous is not None and row["cpu_start_qpc"] <= previous:
                        qpc_monotonic = False
                    last_qpc[chain] = row["cpu_start_qpc"]
                rows.append(row)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    return {
        "rows": rows, "start_column": start_column, "domain": domain, "unit": unit, "unmapped": unmapped,
        "na_cells": na_cells, "unknown_rows": unknown_rows, "processes": processes, "qpc_monotonic": qpc_monotonic,
        "columns": len(mapped),
    }


def decode(bundle: Path, sources: list[str] | None = None, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    try:
        manifest = load_manifest(bundle)
        allowed = decodable_primaries(manifest)
        if sources is None:
            sources = allowed
            if not sources:
                # Nothing is written: a sidecar must name at least one source
                # file, and a table with no input does not exist for this bundle.
                return {"status": "not_collected", "reason": "the bundle holds no PresentMon CSV of an observed capture to decode", "rows": 0, "sources": 0}
        if not sources:
            raise DecodeError("no source was named")
        for source in sources:
            check_source_path(bundle, source, allowed)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}

    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    domain, unit = "etw_qpc", "qpc_ticks"
    start_column = "cpu_start_qpc"
    try:
        domains: set[str] = set()
        processes: dict[tuple[str, int], int] = {}
        for source in sources:
            result = decode_source(bundle, source, schema_version)
            rows += result["rows"]
            domains.add(result["domain"])
            domain, unit, start_column = result["domain"], result["unit"], result["start_column"]
            for key, count in result["processes"].items():
                processes[key] = processes.get(key, 0) + count
            checks.append({"name": f"header_mapped:{source}", "ok": True,
                           "detail": f"{result['columns'] - len(result['unmapped'])} of {result['columns']} columns mapped; "
                                     f"start column {result['start_column']}; unmapped kept in raw_columns: {', '.join(result['unmapped']) or 'none'}"})
            checks.append({"name": f"rows_read:{source}", "ok": True,
                           "detail": f"{len(result['rows'])} frames, {result['na_cells']} NA cells, {result['unknown_rows']} frames of <unknown> processes"})
            if result["start_column"] == "cpu_start_qpc" and result["rows"]:
                checks.append({"name": f"qpc_increases_per_swap_chain:{source}", "ok": result["qpc_monotonic"],
                               "detail": "CPUStartQPC increases from one frame to the next within each (process, swap chain)"
                               if result["qpc_monotonic"] else "CPUStartQPC does not increase within at least one (process, swap chain); the rows are kept in CSV order"})
        if len(domains) > 1:
            raise DecodeError(f"the sources disagree on the time domain ({', '.join(sorted(domains))}); decode them separately")
        summary = sorted(processes.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
        checks.append({"name": "processes", "ok": True,
                       "detail": "; ".join(f"{application} pid {pid}: {count} frames" for (application, pid), count in summary[:20]) or "none"})
        errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
        elif not rows:
            status, reason = "observed_zero", "every CSV has a header and no frame rows"
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        checks.append({"name": "csv_read", "ok": False, "detail": str(exc)})

    native_range = None
    if rows:
        values = [r[start_column] for r in rows if r[start_column] is not None]
        if values:
            native_range = {"start": min(values), "end": max(values), "domain": domain, "unit": unit}
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": schema_version,
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version(manifest)},
        "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows),
        "time_domain": domain,
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
    return {"status": status, "reason": reason, "rows": len(rows), "sources": len(sources)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--source", action="append", default=None,
                    help="bundle relative path of a PresentMon CSV, for example raw/presentmon_frames/frames.csv; repeatable")
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    print(f"{TABLE}: {result['rows']} rows from {result['sources']} CSV files, status {result['status']}")
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
