#!/usr/bin/env python3
"""Decode the trace session statistics of a kernel trace into the ``tracestats`` table.

See docs/contracts/decoded-tables.md section 5.3. The sources are the two texts
the ``dpcisr-trace`` collector writes for its ``wpr`` source:

* ``raw/<collector id>/status.txt``, the output of ``wpr -status profiles
  collectors -details`` read right after the session started, whose shape
  Microsoft documents on the WPR command line page (labelled lines
  ``Label : value``, one ``Collector Name`` block per collector with ``Buffer
  Size (KB)`` and ``Events Lost``, bare keyword lines under a ``System
  Keywords`` header). Its loss figures are a live snapshot.
* ``raw/<collector id>/tracerpt-summary.txt``, the summary ``tracerpt`` wrote
  for the saved trace after the stop. Microsoft documents that the tool writes
  a summary report and nothing about its text; the collector reads the
  ``events lost`` and ``buffers lost`` figures by their label. These are the
  final figures of the trace, the ones the manifest carries.

One row per labelled line (``Label : value`` or ``Label   value`` with two or
more spaces) and one per bare list item, verbatim, with the normalized subset
the contract names; ``value_number`` is set only when the whole value is a
decimal integer, so ``1,234`` or ``n/a`` decodes to null, never to a number.
The provenance ``row_id_or_offset`` is ``line:<n>``.

Without ``--source`` the decoder reads the manifest and takes both artifacts of
every collector of kind ``wpr`` that has them, whatever its status: a trace
that lost events is exactly the one whose loss must be visible in a table.
When no such artifact exists the decoder reports ``not_collected`` and writes
nothing, because an absent input is never decoded into zero rows.

The sidecar's checks require a single whole number for the final events lost
and the final buffers lost (the summary rows) and compare both with the
``events_lost`` and ``buffers_lost`` the manifest records for that collector;
a missing figure, a figure that is not a number or a disagreement is
``decode_failed``. The collector's measurement status is recorded as an
informational check and never changed by the decoder.

Usage::

    python scripts/decode_tracestats.py --bundle <bundle directory> \
        [--source raw/<collector id>/status.txt ...] [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_tracestats"
DECODER_VERSION = "1.1.0"
TABLE = "tracestats"
TOOL = {"name": "wpr -status profiles collectors -details; tracerpt -summary", "version": None}
RE_LABELLED = re.compile(r"^([A-Za-z][A-Za-z ()]*[A-Za-z)])\s*(?::\s*(.*)|\s{2,}(\S.*))$")
RE_LIST_ITEM = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
RE_INTEGER = re.compile(r"^\d+$")
RE_EVENTS_LOST = re.compile(r"^(total\s+)?events\s+lost$", re.I)
RE_BUFFERS_LOST = re.compile(r"^(total\s+)?(log\s+)?buffers\s+lost$", re.I)
LIST_HEADERS = {"System Keywords", "System Stacks", "Providers", "CaptureState Providers on Save", "CaptureState Providers on Start"}
BLOCK_HEADERS = ("Actively recording collectors", "Recording system activity")
NUMERIC = {"events_lost", "buffers_lost", "buffer_size_kb", "buffer_count", "perf_freq_hz", "cpu_count"}
RECORDING_SECTION = "recording"
SUMMARY_SECTION = "summary"
STATUS_FILE = "status.txt"
SUMMARY_FILE = "tracerpt-summary.txt"


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


def statistics_artifacts(manifest: dict[str, Any]) -> dict[str, tuple[dict[str, Any], str]]:
    """The status and summary artifacts of the ``wpr`` collectors, keyed by path, with their kind."""
    out: dict[str, tuple[dict[str, Any], str]] = {}
    for collector in manifest["collectors"]:
        if collector["kind"] != "wpr":
            continue
        for artifact in collector["artifacts"]:
            if artifact["path"] == f"raw/{collector['id']}/{STATUS_FILE}" and artifact["role"] == "report":
                out[artifact["path"]] = (collector, "status")
            elif artifact["path"] == f"raw/{collector['id']}/{SUMMARY_FILE}" and artifact["role"] == "primary":
                out[artifact["path"]] = (collector, "summary")
    return out


def check_source_path(bundle: Path, source: str, allowed: dict[str, Any]) -> None:
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
        raise DecodeError(f"{source}: not listed in the manifest as the status report or the summary of a wpr collector")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def parse_integer(text: str) -> int | None:
    """The whole value must be a decimal integer; anything else is null, never zero."""
    text = text.strip()
    return int(text) if RE_INTEGER.fullmatch(text) else None


def normalize(label: str) -> str | None:
    collapsed = re.sub(r"\s+", " ", label.strip())
    if RE_EVENTS_LOST.fullmatch(collapsed) or collapsed in ("Dropped event", "Dropped events"):
        return "events_lost"
    if RE_BUFFERS_LOST.fullmatch(collapsed):
        return "buffers_lost"
    if collapsed == "Buffer Size (KB)":
        return "buffer_size_kb"
    if collapsed == "Number of Buffers":
        return "buffer_count"
    return None


def parse_text(text: str, source: str, kind: str, schema_version: str) -> list[dict[str, Any]]:
    """Rows of one text, in line order. ``kind`` is ``status`` or ``summary``."""
    rows: list[dict[str, Any]] = []
    section = SUMMARY_SECTION if kind == "summary" else RECORDING_SECTION
    list_header: str | None = None

    def provenance(line_no: int) -> dict[str, str]:
        return {"source_file": source, "row_id_or_offset": f"line:{line_no}", "decoded_table": TABLE,
                "decoder_version": DECODER_VERSION, "schema_version": schema_version}

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        m = RE_LABELLED.match(stripped)
        if m and not re.fullmatch(r"\d{1,2}", m.group(1).strip()):
            key = m.group(1).strip()
            value = (m.group(2) if m.group(2) is not None else m.group(3) or "").strip()
            list_header = None
            if kind == "status" and key == "Collector Name":
                section = value or RECORDING_SECTION
            normalized = normalize(key)
            number = parse_integer(value) if normalized in NUMERIC else None
            rows.append({"section": section, "key": key, "value_text": value, "normalized_key": normalized,
                         "value_number": number, "provenance": provenance(line_no)})
            continue
        if kind == "status" and stripped in LIST_HEADERS:
            list_header = stripped
            continue
        if kind == "status" and stripped.startswith(BLOCK_HEADERS):
            list_header = None
            continue
        if kind == "status" and list_header is not None and RE_LIST_ITEM.fullmatch(stripped):
            rows.append({"section": section, "key": list_header, "value_text": stripped, "normalized_key": None,
                         "value_number": None, "provenance": provenance(line_no)})
    return rows


def final_figure(rows: list[dict[str, Any]], normalized_key: str) -> int | None:
    """The single final figure the summary rows state: null when absent, not a number, or disagreeing."""
    values = [r["value_number"] for r in rows if r["section"] == SUMMARY_SECTION and r["normalized_key"] == normalized_key]
    if not values or any(v is None for v in values) or len(set(values)) != 1:
        return None
    return values[0]


def events_lost_of(rows: list[dict[str, Any]]) -> int | None:
    return final_figure(rows, "events_lost")


def buffers_lost_of(rows: list[dict[str, Any]]) -> int | None:
    return final_figure(rows, "buffers_lost")


def decode(bundle: Path, sources: list[str] | None = None, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    result: dict[str, Any] = {"status": "observed", "reason": None, "table": TABLE, "rows": 0, "sources": []}
    try:
        manifest = load_manifest(bundle)
        allowed = statistics_artifacts(manifest)
        if sources is None:
            sources = sorted(allowed)
        if not sources:
            result["status"], result["reason"] = "not_collected", "no wpr collector in the manifest has a status text or a tracerpt summary; nothing to decode"
            return result
        for source in sources:
            check_source_path(bundle, source, allowed)
    except DecodeError as exc:
        result["status"], result["reason"] = "decode_failed", str(exc)
        return result

    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    by_collector: dict[str, dict[str, Any]] = {}
    rows_by_collector: dict[str, list[dict[str, Any]]] = {}
    for source in sources:
        collector, kind = allowed[source]
        try:
            text = (bundle / source).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            status, reason = "decode_failed", f"{source}: {exc}"
            break
        source_rows = parse_text(text, source, kind, schema_version)
        rows += source_rows
        by_collector[collector["id"]] = collector
        rows_by_collector.setdefault(collector["id"], []).extend(source_rows)
    for collector_id, collector in by_collector.items():
        crows = rows_by_collector[collector_id]
        lost = events_lost_of(crows)
        buffers = buffers_lost_of(crows)
        checks.append({"name": f"{collector_id}_final_events_lost_present", "ok": lost is not None,
                       "detail": None if lost is None else f"events lost {lost}"})
        checks.append({"name": f"{collector_id}_final_buffers_lost_present", "ok": buffers is not None,
                       "detail": None if buffers is None else f"buffers lost {buffers}"})
        checks.append({"name": f"{collector_id}_events_lost_matches_manifest", "ok": lost is not None and lost == collector["events_lost"],
                       "detail": f"rows {lost}, manifest {collector['events_lost']}"})
        checks.append({"name": f"{collector_id}_buffers_lost_matches_manifest", "ok": buffers is not None and buffers == collector.get("buffers_lost"),
                       "detail": f"rows {buffers}, manifest {collector.get('buffers_lost')}"})
        checks.append({"name": f"{collector_id}_collector_status", "ok": True,
                       "detail": collector["status"] + (f": {collector['status_reason']}" if collector["status_reason"] else "")})
    gating = [c for c in checks if not c["name"].endswith("_collector_status")]
    if status == "observed" and not all(c["ok"] for c in gating):
        status, reason = "decode_failed", "a decoder self check failed; see checks"
    errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
    if errors:
        status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    if status == "observed" and not rows:
        status, reason = "decode_failed", "the texts held no labelled line"

    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": schema_version,
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": TOOL,
        "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows),
        "time_domain": "system_time",
        "native_time_range": None,
        "status": status,
        "status_reason": reason,
        "checks": checks,
        "decoded_at_utc": decoded_at,
    }
    meta_errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if meta_errors:
        raise SystemExit(f"internal error: sidecar for {TABLE} fails its schema: {meta_errors}")
    wf_schema.write_json(decoded_dir / f"{TABLE}.meta.json", meta)
    result.update({"status": status, "reason": reason, "rows": len(rows), "sources": sources})
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path, help="bundle directory (contains manifest.json and raw/)")
    ap.add_argument("--source", action="append", default=None, help="bundle relative path of a wpr status text or tracerpt summary; repeatable; default: both of every wpr collector")
    ap.add_argument("--decoded-at", default=None, help="override decoded_at_utc (ISO 8601 Z) for reproducible fixtures")
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    print(f"{TABLE}: {result['rows']} rows, status {result['status']}")
    if result["status"] != "observed":
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
