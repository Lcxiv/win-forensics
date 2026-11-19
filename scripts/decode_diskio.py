#!/usr/bin/env python3
"""Decode a diskio-trace capture into the ``diskio_activity`` table.

See docs/contracts/decoded-tables.md section 5.20. The ``diskio-trace``
collector records a kernel trace with Windows Performance Recorder on the PC
(DiskIO, Filename, HardFaults and ProcessThread), has the inbox ``tracerpt``
dump it to XML there, aggregates the dump into one row per one second bin,
process, volume, directory, extension, disk and operation, writes the rows as
``raw/diskio_aggregate/aggregate.jsonl`` (the primary artifact) with what it
read in ``raw/diskio_aggregate/result.json`` (role report), and deletes the
trace and the dump. The trace source (``wpr_trace``, kind ``wpr``) carries the
session facts; its loss figures are decoded separately into ``tracestats`` by
``scripts/decode_tracestats.py``.

The decoder refuses to build a table it cannot vouch for: the aggregate must
belong to an observed ``diskio_aggregate`` collector whose ``wpr_trace``
sibling is observed with zero events and buffers lost, a confirmed stop and a
performance counter clock; ``result.json`` must say the trace and the dump
were removed, that the dump held as many events as the tracerpt summary says
were processed, that no counted event was malformed, and it must agree with
the manifest on the trace's SHA-256, the clock, the row count and the totals
per operation. One row per aggregate line; the provenance ``row_id_or_offset``
is ``line:<n>``. The decoder adds ``paging_operations`` and ``paging_bytes``,
the share of the row's disk requests whose IrpFlags carry ``IRP_PAGING_IO``
(0x2 in wdm.h; Microsoft Learn names the flag without its value, so this is
on the collectors README's verification list), and keeps the verbatim
per flag counts beside them.

Time domain: ``etw_qpc_relative``. ``bin_start_s`` counts whole seconds from
the trace header's StartTime, which ``result.json`` records with the header's
clock and PerfFreq.

Without ``--source`` the decoder reads the manifest and takes every observed
``diskio_aggregate`` collector. A bundle without one has nothing to decode:
the decoder reports ``not_collected`` and writes nothing.

Usage::

    python scripts/decode_diskio.py --bundle <bundle directory> \
        [--source raw/diskio_aggregate/aggregate.jsonl ...] [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_diskio"
DECODER_VERSION = "0.1.0"
TABLE = "diskio_activity"
TOOL_NAME = "tracerpt XML dump of a Windows Performance Recorder kernel trace, aggregated on the PC by the diskio-trace collector"
AGGREGATE_ID = "diskio_aggregate"
TRACE_ID = "wpr_trace"
OBSERVED = ("observed",)
# IRP_PAGING_IO in wdm.h. Microsoft Learn lists the flag for DiskIo_TypeGroup1 IrpFlags without its value.
IRP_PAGING_IO = 0x2
OPERATIONS = ("read", "write", "hard_fault")
RAW_KEYS = ("bin_start_s", "process_id", "process_image", "volume", "directory", "path_class", "extension", "disk_number", "operation",
            "operations", "transferred_bytes", "irp_flags_operations", "irp_flags_bytes", "response_time_sum_us", "response_time_max_us",
            "response_time_p50_us", "response_time_p95_us")


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
    """Every observed aggregate: its rows (the primary), its result record, and the trace source beside it."""
    out = []
    collectors = manifest["collectors"]
    for collector in collectors:
        if collector["id"] != AGGREGATE_ID or collector["status"] not in OBSERVED:
            continue
        primary = [a["path"] for a in collector["artifacts"] if a["role"] == "primary"]
        results = [a["path"] for a in collector["artifacts"] if a["path"] == f"raw/{AGGREGATE_ID}/result.json"]
        if primary != [f"raw/{AGGREGATE_ID}/aggregate.jsonl"]:
            raise DecodeError(f"collector {AGGREGATE_ID}: expected the one primary aggregate.jsonl, found {primary}")
        if len(results) != 1:
            raise DecodeError(f"collector {AGGREGATE_ID}: expected one result.json artifact, found {len(results)}")
        traces = [c for c in collectors if c["id"] == TRACE_ID and c["kind"] == "wpr"]
        if len(traces) != 1:
            raise DecodeError(f"collector {AGGREGATE_ID}: the bundle has {len(traces)} {TRACE_ID} sources of kind wpr; the aggregate is made from exactly one")
        out.append({"aggregate": primary[0], "result": results[0], "collector": collector, "trace": traces[0]})
    return out


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
        raise DecodeError(f"{source}: not listed in the manifest as the aggregate or result record of an observed diskio-trace capture")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def same(a: Any, b: Any) -> bool:
    """Equal in value and JSON type (true is not 1)."""
    return type(a) is type(b) and a == b


def read_result(bundle: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """The collector's record of what it read, cross checked against the manifest; raises when it cannot vouch for the aggregate."""
    path = capture["result"]
    try:
        result = json.loads((bundle / path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{path}: {exc}") from exc
    trace = capture["trace"]
    trace_options = (trace.get("enabled") or {}).get("options") or {}
    options = (capture["collector"].get("enabled") or {}).get("options") or {}
    if trace["status"] not in OBSERVED:
        raise DecodeError(f"{path}: the trace source {TRACE_ID} is {trace['status']}; an aggregate is only decoded from an observed trace")
    if trace.get("events_lost") != 0 or trace.get("buffers_lost") != 0:
        raise DecodeError(f"{path}: the trace source records events_lost {trace.get('events_lost')!r} and buffers_lost {trace.get('buffers_lost')!r}; both must be 0")
    if trace_options.get("session_confirmed_stopped") is not True:
        raise DecodeError(f"{path}: the trace session's stop is not confirmed in the manifest")
    header = result.get("trace_header") or {}
    if not header.get("found") or header.get("clock_type") != "qpc" or not header.get("end_time_utc"):
        raise DecodeError(f"{path}: the trace header is not a readable performance counter header with an end time ({header.get('clock_type')!r}, end {header.get('end_time_utc')!r})")
    if not isinstance(header.get("perf_freq_hz"), int) or header["perf_freq_hz"] <= 0:
        raise DecodeError(f"{path}: the trace header carries no PerfFreq")
    if header.get("events_lost") != 0 or header.get("buffers_lost") != 0:
        raise DecodeError(f"{path}: the trace header records loss ({header.get('events_lost')} events, {header.get('buffers_lost')} buffers)")
    for name, in_manifest, in_result in (("clock_type", trace_options.get("clock_type"), header.get("clock_type")),
                                         ("perf_freq_hz", trace_options.get("perf_freq_hz"), header.get("perf_freq_hz")),
                                         ("trace_sha256", trace_options.get("trace_sha256"), result.get("trace_sha256")),
                                         ("trace_sha256 (aggregate)", options.get("trace_sha256"), result.get("trace_sha256")),
                                         ("dump_sha256", options.get("dump_sha256"), result.get("dump_sha256")),
                                         ("rows", options.get("rows"), result.get("rows"))):
        if not same(in_manifest, in_result):
            raise DecodeError(f"{path}: the manifest records {name} {in_manifest!r}, the result record {in_result!r}")
    if result.get("recording_and_dump_removed") is not True:
        raise DecodeError(f"{path}: the result record does not say the trace and its dump were removed on the PC")
    counts = result.get("counts") or {}
    if not isinstance(result.get("dump_events"), int) or result.get("dump_events") != result.get("trace_events_processed"):
        raise DecodeError(f"{path}: the dump held {result.get('dump_events')!r} events and the tracerpt summary states {result.get('trace_events_processed')!r} processed")
    if counts.get("malformed") != 0 or counts.get("timed_out") is not False:
        raise DecodeError(f"{path}: the read of the dump was not whole ({counts.get('malformed')!r} malformed events, timed out {counts.get('timed_out')!r})")
    if not isinstance(counts.get("disk_read"), int) or not isinstance(counts.get("disk_write"), int) or counts["disk_read"] + counts["disk_write"] == 0:
        raise DecodeError(f"{path}: the result record counts no disk request; the collector never reports such an aggregate as observed")
    return result


def to_row(raw: Any, source: str, line: int, schema_version: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DecodeError(f"{source}: line {line} is not a JSON object")
    keys = tuple(raw.keys())
    if set(keys) != set(RAW_KEYS):
        missing = sorted(set(RAW_KEYS) - set(keys))
        extra = sorted(set(keys) - set(RAW_KEYS))
        raise DecodeError(f"{source}: line {line} has the wrong keys (missing {missing}, unknown {extra})")
    row = {key: raw[key] for key in RAW_KEYS[:11]}
    flags_ops, flags_bytes = raw["irp_flags_operations"], raw["irp_flags_bytes"]
    if raw["operation"] == "hard_fault":
        if flags_ops is not None or flags_bytes is not None:
            raise DecodeError(f"{source}: line {line} is a hard fault with IrpFlags counts")
        row["paging_operations"] = None
        row["paging_bytes"] = None
    else:
        if not isinstance(flags_ops, dict) or not isinstance(flags_bytes, dict) or set(flags_ops) != set(flags_bytes):
            raise DecodeError(f"{source}: line {line} is a disk request row without matching IrpFlags counts")
        try:
            values = {flag: int(flag, 16) for flag in flags_ops}
        except ValueError as exc:
            raise DecodeError(f"{source}: line {line}: an IrpFlags key is not hexadecimal") from exc
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in list(flags_ops.values()) + list(flags_bytes.values())):
            raise DecodeError(f"{source}: line {line}: an IrpFlags count is not an integer")
        if sum(flags_ops.values()) != raw["operations"] or sum(flags_bytes.values()) != raw["transferred_bytes"]:
            raise DecodeError(f"{source}: line {line}: the IrpFlags counts do not add up to the row's operations and bytes")
        row["paging_operations"] = sum(n for flag, n in flags_ops.items() if values[flag] & IRP_PAGING_IO)
        row["paging_bytes"] = sum(n for flag, n in flags_bytes.items() if values[flag] & IRP_PAGING_IO)
    row["irp_flags_operations"] = flags_ops
    row["irp_flags_bytes"] = flags_bytes
    for key in RAW_KEYS[13:]:
        row[key] = raw[key]
    row["provenance"] = {"source_file": source, "row_id_or_offset": f"line:{line}", "decoded_table": TABLE,
                         "decoder_version": DECODER_VERSION, "schema_version": schema_version}
    return row


def decode_aggregate(bundle: Path, source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    try:
        text = (bundle / source).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise DecodeError(f"{source}: line {number} is empty")
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DecodeError(f"{source}: line {number}: {exc}") from exc
        rows.append(to_row(raw, source, number, schema_version))
    return rows


def totals_of(rows: list[dict[str, Any]]) -> dict[str, int]:
    totals = {f"{op}_{what}": 0 for op in OPERATIONS for what in ("operations", "bytes")}
    for row in rows:
        totals[f"{row['operation']}_operations"] += row["operations"]
        totals[f"{row['operation']}_bytes"] += row["transferred_bytes"]
    return totals


def decode(bundle: Path, sources: list[str] | None = None, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    try:
        manifest = load_manifest(bundle)
        found = captures(manifest)
        allowed = [c["aggregate"] for c in found] + [c["result"] for c in found]
        if sources is None:
            selected = found
            if not selected:
                # Nothing is written: a sidecar must name at least one source file.
                return {"status": "not_collected", "reason": "the bundle holds no observed diskio-trace aggregate to decode", "rows": 0, "sources": 0}
        else:
            if not sources:
                raise DecodeError("no source was named")
            selected = []
            for source in sources:
                check_source_path(bundle, source, allowed)
                selected += [c for c in found if source in (c["aggregate"], c["result"]) and c not in selected]
        for capture in selected:
            check_source_path(bundle, capture["aggregate"], allowed)
            check_source_path(bundle, capture["result"], allowed)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}

    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    domain = "etw_qpc_relative"
    source_files: list[str] = []
    try:
        for capture in selected:
            source_files += [capture["aggregate"], capture["result"]]
            result = read_result(bundle, capture)
            header = result["trace_header"]
            checks.append({"name": f"trace:{capture['result']}", "ok": True,
                           "detail": f"clock qpc, PerfFreq {header['perf_freq_hz']} Hz, session {header.get('start_time_utc')} to {header.get('end_time_utc')}, "
                                     f"0 events and 0 buffers lost, stop confirmed; {result.get('trace_bytes')} byte trace (sha256 {result.get('trace_sha256')}) "
                                     f"and {result.get('dump_bytes')} byte dump deleted on the PC"})
            checks.append({"name": f"dump_whole:{capture['result']}", "ok": True,
                           "detail": f"{result['dump_events']} events in the dump, as many as the tracerpt summary processed; 0 malformed"})
            found_rows = decode_aggregate(bundle, capture["aggregate"], schema_version)
            if not found_rows:
                raise DecodeError(f"{capture['aggregate']}: an observed aggregate with no row; the collector never reports one")
            if len(found_rows) != result.get("rows"):
                raise DecodeError(f"{capture['aggregate']}: {len(found_rows)} lines, the result record says {result.get('rows')!r} rows")
            totals = totals_of(found_rows)
            recorded = result.get("totals") or {}
            if any(not same(recorded.get(key), value) for key, value in totals.items()):
                raise DecodeError(f"{capture['aggregate']}: the rows add up to {totals}, the result record says {recorded}")
            counts = result["counts"]
            if totals["read_operations"] != counts["disk_read"] or totals["write_operations"] != counts["disk_write"] or totals["hard_fault_operations"] != counts.get("hard_fault"):
                raise DecodeError(f"{capture['aggregate']}: the rows hold {totals['read_operations']} reads, {totals['write_operations']} writes and {totals['hard_fault_operations']} hard faults, "
                                  f"the dump counted {counts['disk_read']}, {counts['disk_write']} and {counts.get('hard_fault')}")
            classes = {c: sum(r["operations"] for r in found_rows if r["path_class"] == c) for c in ("named", "unnamed", "collector")}
            unattributed = sum(r["operations"] for r in found_rows if r["process_id"] is None)
            checks.append({"name": f"rows_read:{capture['aggregate']}", "ok": True,
                           "detail": f"{len(found_rows)} rows; {totals['read_operations']} reads, {totals['write_operations']} writes, {totals['hard_fault_operations']} hard faults; "
                                     f"operations by path class {classes}; {unattributed} operations without a process"})
            rows += found_rows
        errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        checks.append({"name": "capture_read", "ok": False, "detail": str(exc)})
        if not source_files:
            source_files = [c["aggregate"] for c in selected]

    native_range = None
    if rows:
        bins = [r["bin_start_s"] for r in rows]
        native_range = {"start": min(bins), "end": max(bins) + 1, "domain": domain, "unit": "s"}
    else:
        domain = "none"
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": schema_version,
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": {"name": TOOL_NAME, "version": None},
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
                    help="bundle relative path of the aggregate or its result record, for example raw/diskio_aggregate/aggregate.jsonl; repeatable")
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
