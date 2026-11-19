#!/usr/bin/env python3
"""Decode a presentmon-frames capture into the ``presentmon_frames`` table.

See docs/contracts/decoded-tables.md section 5.5. The ``presentmon-frames``
collector records an ETW trace with Windows Performance Recorder on the PC,
runs the pinned PresentMon console application over that file with
``--etl_file``, ``--output_stdout`` and ``--qpc_time``, keeps the CSV it
printed as ``raw/presentmon_frames/frames.csv`` (the primary artifact), and
deletes the recording (a merged WPR trace can carry network adapter
addresses, which never enter a bundle). What the recording's log file header
said (its clock, its loss counters, its start and end) is in
``raw/presentmon_frames/recording.json`` (role report) and repeated in the
manifest entry's ``enabled.options``; the decoder reads both and refuses to
build a table when they disagree or report loss. One row per CSV data row;
the provenance ``row_id_or_offset`` is ``row:<n>`` with the 1-based data row,
not counting the header line.

The time domain comes from the recording's header as the collector read it:
``clock_type`` ``qpc`` (ReservedFlags 1, the performance counter) gives
``etw_qpc`` in ``qpc_ticks``; ``system_time`` (2) gives ``system_time`` with
the values as FILETIME units; the CPU cycle counter (3) or a header the
collector could not read is ``decode_failed``, because the frames could not
be placed in a domain.

Column names follow the PresentMon 2.6.0 console README ("CSV columns") and
the header its source writes for the default options (CsvOutput.cpp
WriteCsvHeader<FrameMetrics>), turned into snake case with the unit suffixes
the table contract uses. A cell PresentMon writes as ``NA`` decodes to null.
A column the decoder does not know is kept verbatim under ``raw_columns``.
Only ``CPUStartQPC`` is accepted as the frame start: the other start columns
PresentMon can write (``CPUStartTime``, ``CPUStartTimeInMs``,
``CPUStartQPCTime`` and so on) are relative or converted values the table
does not place in a domain, and a CSV carrying one is ``decode_failed``.

Without ``--source`` the decoder reads the manifest and takes every
collector of kind ``presentmon`` whose status is ``observed``. The collector
never reports ``observed_zero`` (with the pinned binary an empty output cannot
be told from a read that stopped early), so an observed capture always has a
CSV with at least one frame. A collector that did not capture has nothing to
decode, and the decoder then reports ``not_collected`` and writes nothing.
Every ``--source`` must be the bundle relative path of such a collector's
CSV or of its ``recording.json``.

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
DECODER_VERSION = "3.0.0"
TABLE = "presentmon_frames"
TOOL_NAME = "PresentMon console application (GameTechDev/PresentMon), --etl_file over a Windows Performance Recorder trace read on the PC"
# The one status the collector reports for a capture with frames; it never reports observed_zero.
OBSERVED = ("observed",)

# PresentMon 2.6.0 console README, "CSV columns", plus the two v1 metric
# columns its source writes with --qpc_time (TimeInQPC, MsFlipDelay), to the
# table's column names. The three columns that need --write_display_metadata
# (VidPnSourceId, LayerIndex, PresentId) are not mapped and land in
# raw_columns when present.
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
    "TimeInQPC": "time_in_qpc",
    "CPUStartQPC": "cpu_start_qpc",
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
    "MsFlipDelay": "ms_flip_delay",
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
REQUIRED_STRINGS = ("application", "swap_chain_address", "present_runtime", "present_mode")
REQUIRED_INTEGERS = ("process_id", "sync_interval", "present_flags", "allows_tearing", "cpu_start_qpc")
OPTIONAL_INTEGERS = ("time_in_qpc",)
OPTIONAL_STRINGS = ("frame_type",)
START_COLUMN = "CPUStartQPC"
OTHER_START_COLUMNS = ("CPUStartTime", "CPUStartTimeInMs", "CPUStartTimeInSeconds", "CPUStartQPCTime", "CPUStartQPCTimeInMs", "CPUStartDateTime")
NA = "NA"
# The clock names the collector writes from the header's ReservedFlags (WNODE_HEADER ClientContext: 1 QPC, 2 system time, 3 CPU cycle counter).
DOMAINS = {"qpc": ("etw_qpc", "qpc_ticks"), "system_time": ("system_time", "filetime_100ns")}


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


def captures(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Every observed PresentMon collector: its CSV (the primary), its recording record, its status and loss."""
    out = []
    for collector in manifest["collectors"]:
        if collector["kind"] != "presentmon" or collector["status"] not in OBSERVED:
            continue
        primary = [a["path"] for a in collector["artifacts"] if a["role"] == "primary"]
        records = [a["path"] for a in collector["artifacts"] if a["path"].endswith("/recording.json")]
        if len(primary) != 1 or not primary[0].endswith("/frames.csv"):
            raise DecodeError(f"collector {collector['id']}: expected one primary frames.csv artifact, found {primary}")
        if len(records) != 1:
            raise DecodeError(f"collector {collector['id']}: expected one recording.json artifact, found {len(records)}")
        out.append({"id": collector["id"], "csv": primary[0], "recording": records[0], "status": collector["status"],
                    "events_lost": collector.get("events_lost"), "buffers_lost": collector.get("buffers_lost"), "options": (collector.get("enabled") or {}).get("options") or {}})
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
        raise DecodeError(f"{source}: not listed in the manifest as the CSV or recording record of an observed PresentMon collector")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def read_recording(bundle: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """The recording record the collector wrote, cross checked against the manifest entry; raises when it cannot vouch for the capture."""
    path = capture["recording"]
    try:
        record = json.loads((bundle / path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{path}: {exc}") from exc
    header = record.get("header") or {}
    options = capture["options"]
    if not header.get("found"):
        raise DecodeError(f"{path}: the collector could not read the recording's log file header ({header.get('error')}), so the frames cannot be placed in a time domain")
    clock = header.get("clock_type")
    if clock not in DOMAINS:
        raise DecodeError(f"{path}: the recording was stamped with the {clock or 'unknown'} clock, which the table does not place in a time domain")
    if not header.get("end_time_utc"):
        raise DecodeError(f"{path}: the recording's header carries no end time, so the session cannot be shown to have run until the stop")
    if options.get("clock_type") != clock:
        raise DecodeError(f"{path}: the manifest says clock {options.get('clock_type')!r}, the recording record {clock!r}")
    events_lost = record.get("events_lost")
    buffers_lost = record.get("buffers_lost")
    if events_lost != 0 or buffers_lost != 0 or header.get("events_lost") != 0 or header.get("buffers_lost") != 0:
        raise DecodeError(f"{path}: the recording lost data (events lost {events_lost}, buffers lost {buffers_lost}, header {header.get('events_lost')} and {header.get('buffers_lost')}); a recording with loss is capture_failed, not a table")
    if capture["events_lost"] != 0:
        raise DecodeError(f"{path}: the manifest records events_lost {capture['events_lost']!r} for an observed capture, the record 0")
    if capture["buffers_lost"] != buffers_lost:
        raise DecodeError(f"{path}: the manifest records buffers_lost {capture['buffers_lost']!r} for an observed capture, the record {buffers_lost!r}")
    if options.get("buffers_lost") != buffers_lost:
        raise DecodeError(f"{path}: the manifest's enabled.options record buffers_lost {options.get('buffers_lost')!r} for an observed capture, the record {buffers_lost!r}")
    if record.get("stop_confirmed") is not True or record.get("in_progress_at_end") is not True or record.get("session_ended_early"):
        raise DecodeError(f"{path}: the recording did not run for the whole window or its stop was not confirmed")
    overflow = (record.get("presentmon") or {}).get("overflowed_presents")
    if overflow:
        raise DecodeError(f"{path}: PresentMon threw {overflow} presents away while reading the recording, so the table would be incomplete")
    return {"clock": clock, "header": header, "record": record}


def parse_integer(text: str, column: str, source: str, row: int, optional: bool = False) -> int | None:
    s = text.strip()
    if optional and (s == NA or s == ""):
        return None
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


def read_header(header: list[str], source: str) -> list[tuple[int, str, str | None]]:
    """Map the header to (column index, CSV name, table column or None); CPUStartQPC must be present."""
    cells = [h.strip() for h in header]
    if not cells or "Application" not in cells or "ProcessID" not in cells:
        raise DecodeError(f"{source}: the header is not a PresentMon header (no Application and ProcessID columns): {','.join(cells)!r}")
    seen: set[str] = set()
    for cell in cells:
        if cell in seen:
            raise DecodeError(f"{source}: the header repeats the column {cell!r}")
        seen.add(cell)
    if START_COLUMN not in cells:
        others = [c for c in cells if c in OTHER_START_COLUMNS]
        raise DecodeError(f"{source}: the header has no CPUStartQPC column"
                          + (f" (found {', '.join(others)}, a start column the table does not place in a time domain)" if others else "")
                          + "; the collector passes --qpc_time, so this CSV did not come from it as configured")
    return [(index, cell, COLUMN_MAP.get(cell)) for index, cell in enumerate(cells)]


def decode_csv(bundle: Path, source: str, schema_version: str) -> dict[str, Any]:
    """Return the rows of one CSV with the header facts the sidecar reports."""
    rows: list[dict[str, Any]] = []
    na_cells = 0
    unknown_rows = 0
    processes: dict[tuple[str, int], int] = {}
    unmapped: list[str] = []
    last_qpc: dict[tuple[int, str], int] = {}
    qpc_monotonic = True
    columns = 0
    try:
        with (bundle / source).open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise DecodeError(f"{source}: the file is empty, not even a header") from exc
            mapped = read_header(header, source)
            columns = len(mapped)
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
                    elif column in REQUIRED_STRINGS:
                        row[column] = text
                    elif column in OPTIONAL_STRINGS:
                        row[column] = None if text.strip() == NA else text
                    elif column in REQUIRED_INTEGERS:
                        row[column] = parse_integer(text, name, source, data_row)
                    elif column in OPTIONAL_INTEGERS:
                        row[column] = parse_integer(text, name, source, data_row, optional=True)
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
                chain = (row["process_id"], row["swap_chain_address"])
                previous = last_qpc.get(chain)
                if previous is not None and row["cpu_start_qpc"] <= previous:
                    qpc_monotonic = False
                last_qpc[chain] = row["cpu_start_qpc"]
                rows.append(row)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    return {"rows": rows, "unmapped": unmapped, "na_cells": na_cells, "unknown_rows": unknown_rows,
            "processes": processes, "qpc_monotonic": qpc_monotonic, "columns": columns}


def decode(bundle: Path, sources: list[str] | None = None, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    try:
        manifest = load_manifest(bundle)
        found = captures(manifest)
        allowed = [c["csv"] for c in found] + [c["recording"] for c in found]
        if sources is None:
            selected = found
            if not selected:
                # Nothing is written: a sidecar must name at least one source
                # file, and a table with no input does not exist for this bundle.
                return {"status": "not_collected", "reason": "the bundle holds no observed PresentMon capture to decode", "rows": 0, "sources": 0}
        else:
            if not sources:
                raise DecodeError("no source was named")
            selected = []
            for source in sources:
                check_source_path(bundle, source, allowed)
                selected += [c for c in found if source in (c["csv"], c["recording"]) and c not in selected]
        for capture in selected:
            check_source_path(bundle, capture["csv"], allowed)
            check_source_path(bundle, capture["recording"], allowed)
    except DecodeError as exc:
        # Nothing is written either: an input that is missing, unlisted, or
        # outside the bundle must not become a table, and the sidecar could
        # not name the source files honestly.
        return {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}

    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    domain, unit = "none", "none"
    source_files: list[str] = []
    try:
        clocks: set[str] = set()
        processes: dict[tuple[str, int], int] = {}
        for capture in selected:
            source_files.append(capture["csv"])
            source_files.append(capture["recording"])
            recording = read_recording(bundle, capture)
            header = recording["header"]
            clocks.add(recording["clock"])
            checks.append({"name": f"recording:{capture['recording']}", "ok": True,
                           "detail": f"clock {recording['clock']}, PerfFreq {header.get('perf_freq_hz')} Hz, {header.get('buffers_written')} buffers written, "
                                     f"0 events lost, 0 buffers lost, session {header.get('start_time_utc')} to {header.get('end_time_utc')}, "
                                     f"stop confirmed, {recording['record'].get('etl_bytes')} byte recording deleted on the PC (sha256 {recording['record'].get('etl_sha256')})"})
            result = decode_csv(bundle, capture["csv"], schema_version)
            if not result["rows"]:
                raise DecodeError(f"{capture['csv']}: an observed capture with no frame row; the collector never reports one (zero frames is capture_failed)")
            rows += result["rows"]
            for key, count in result["processes"].items():
                processes[key] = processes.get(key, 0) + count
            checks.append({"name": f"header_mapped:{capture['csv']}", "ok": True,
                           "detail": f"{result['columns'] - len(result['unmapped'])} of {result['columns']} columns mapped; "
                                     f"unmapped kept in raw_columns: {', '.join(result['unmapped']) or 'none'}"})
            checks.append({"name": f"rows_read:{capture['csv']}", "ok": True,
                           "detail": f"{len(result['rows'])} frames, {result['na_cells']} NA cells, {result['unknown_rows']} frames of <unknown> processes"})
            checks.append({"name": f"qpc_increases_per_swap_chain:{capture['csv']}", "ok": result["qpc_monotonic"],
                           "detail": "CPUStartQPC increases from one frame to the next within each (process, swap chain)"
                           if result["qpc_monotonic"] else "CPUStartQPC does not increase within at least one (process, swap chain); the rows are kept in CSV order"})
        if len(clocks) > 1:
            raise DecodeError(f"the recordings disagree on the clock ({', '.join(sorted(clocks))}); decode them separately")
        domain, unit = DOMAINS[next(iter(clocks))]
        summary = sorted(processes.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
        checks.append({"name": "processes", "ok": True,
                       "detail": "; ".join(f"{application} pid {pid}: {count} frames" for (application, pid), count in summary[:20]) or "none"})
        errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        domain, unit = "none", "none"
        checks.append({"name": "capture_read", "ok": False, "detail": str(exc)})
        if not source_files:
            source_files = [c["csv"] for c in selected]

    native_range = None
    if rows:
        values = [r["cpu_start_qpc"] for r in rows]
        native_range = {"start": min(values), "end": max(values), "domain": domain, "unit": unit}
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": schema_version,
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version(manifest)},
        "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in source_files],
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
    return {"status": status, "reason": reason, "rows": len(rows), "sources": len(source_files)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--source", action="append", default=None,
                    help="bundle relative path of a capture's CSV or recording record, for example raw/presentmon_frames/frames.csv; repeatable")
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    print(f"{TABLE}: {result['rows']} rows from {result['sources']} source files, status {result['status']}")
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
