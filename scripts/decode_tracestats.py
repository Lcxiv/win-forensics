#!/usr/bin/env python3
"""Decode the trace session statistics of a kernel trace into the ``tracestats`` table.

See docs/contracts/decoded-tables.md section 5.3. The first source of these
statistics is the text the ``dpcisr-trace`` collector writes as
``raw/<collector id>/status.txt``: the output of
``wpr -status profiles collectors -details`` read just before the session was
stopped, whose shape Microsoft documents on the WPR command line page
(labelled lines ``Label : value``, one ``Collector Name`` block per collector
with ``Buffer Size (KB)`` and ``Events Lost``, bare keyword lines under a
``System Keywords`` header). One row per labelled line and one per bare list
item, verbatim, with the normalized subset the contract names; the provenance
``row_id_or_offset`` is ``line:<n>``.

Without ``--source`` the decoder reads the manifest and takes the
``status.txt`` report artifact of every collector of kind ``wpr`` that has
one, whatever its status: a trace that lost events is exactly the one whose
loss must be visible in a table. When no such artifact exists the decoder
reports ``not_collected`` and writes nothing, because an absent input is never
decoded into zero rows.

The sidecar's checks compare the events lost the rows state with the
``events_lost`` the manifest records for that collector; a mismatch is
``decode_failed``.

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
DECODER_VERSION = "1.0.0"
TABLE = "tracestats"
TOOL = {"name": "wpr -status profiles collectors -details", "version": None}
RE_LABELLED = re.compile(r"^\s*([^:]+?)\s*:\s*(.*)$")
RE_LIST_ITEM = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
RE_INTEGER = re.compile(r"^\s*(\d+)")
LIST_HEADERS = {"System Keywords", "System Stacks", "Providers", "CaptureState Providers on Save", "CaptureState Providers on Start"}
BLOCK_HEADERS = ("Actively recording collectors", "Recording system activity")
# Verbatim label -> normalized key. Only the keys the contract names; everything else stays null.
NORMALIZED = {
    "Events Lost": "events_lost",
    "Dropped event": "events_lost",
    "Dropped events": "events_lost",
    "Buffer Size (KB)": "buffer_size_kb",
    "Number of Buffers": "buffer_count",
}
NUMERIC = {"events_lost", "buffers_lost", "buffer_size_kb", "buffer_count", "perf_freq_hz", "cpu_count"}
RECORDING_SECTION = "recording"


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


def status_artifacts(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``raw/<id>/status.txt`` report artifacts of the ``wpr`` collectors, keyed by path."""
    out: dict[str, dict[str, Any]] = {}
    for collector in manifest["collectors"]:
        if collector["kind"] != "wpr":
            continue
        for artifact in collector["artifacts"]:
            if artifact["role"] == "report" and artifact["path"] == f"raw/{collector['id']}/status.txt":
                out[artifact["path"]] = collector
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
        raise DecodeError(f"{source}: not listed in the manifest as the status.txt report of a wpr collector")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def parse_integer(text: str) -> int | None:
    m = RE_INTEGER.match(text)
    return int(m.group(1)) if m else None


def parse_status(text: str, source: str, schema_version: str) -> list[dict[str, Any]]:
    """Rows of one status text, in line order."""
    rows: list[dict[str, Any]] = []
    section = RECORDING_SECTION
    list_header: str | None = None

    def provenance(line_no: int) -> dict[str, str]:
        return {"source_file": source, "row_id_or_offset": f"line:{line_no}", "decoded_table": TABLE,
                "decoder_version": DECODER_VERSION, "schema_version": schema_version}

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        m = RE_LABELLED.match(line)
        if m and m.group(1).strip() and not re.fullmatch(r"\d{1,2}", m.group(1).strip()):
            key, value = m.group(1).strip(), m.group(2).strip()
            list_header = None
            if key == "Collector Name":
                section = value or RECORDING_SECTION
            normalized = NORMALIZED.get(key)
            number = parse_integer(value) if normalized in NUMERIC else None
            rows.append({"section": section, "key": key, "value_text": value, "normalized_key": normalized,
                         "value_number": number, "provenance": provenance(line_no)})
            continue
        if stripped in LIST_HEADERS:
            list_header = stripped
            continue
        if stripped.startswith(BLOCK_HEADERS):
            list_header = None
            continue
        if list_header is not None and RE_LIST_ITEM.fullmatch(stripped):
            rows.append({"section": section, "key": list_header, "value_text": stripped, "normalized_key": None,
                         "value_number": None, "provenance": provenance(line_no)})
    return rows


def events_lost_of(rows: list[dict[str, Any]]) -> int | None:
    """The loss the rows state: the sum of the collector rows when there are any, else the recording row."""
    collector_rows = [r for r in rows if r["normalized_key"] == "events_lost" and r["section"] != RECORDING_SECTION]
    if collector_rows:
        return sum(int(r["value_number"] or 0) for r in collector_rows)
    recording = [r for r in rows if r["normalized_key"] == "events_lost" and r["section"] == RECORDING_SECTION]
    if recording and recording[0]["value_number"] is not None:
        return int(recording[0]["value_number"])
    return None


def decode(bundle: Path, sources: list[str] | None = None, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    schema_version = wf_schema.table_schema_version(TABLE)
    result: dict[str, Any] = {"status": "observed", "reason": None, "table": TABLE, "rows": 0, "sources": []}
    try:
        manifest = load_manifest(bundle)
        allowed = status_artifacts(manifest)
        if sources is None:
            sources = sorted(allowed)
        if not sources:
            result["status"], result["reason"] = "not_collected", "no wpr collector in the manifest has a status.txt report; nothing to decode"
            return result
        for source in sources:
            check_source_path(bundle, source, allowed)
    except DecodeError as exc:
        result["status"], result["reason"] = "decode_failed", str(exc)
        return result

    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    for source in sources:
        collector = allowed[source]
        try:
            text = (bundle / source).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            status, reason = "decode_failed", f"{source}: {exc}"
            break
        source_rows = parse_status(text, source, schema_version)
        lost = events_lost_of(source_rows)
        checks.append({"name": f"{collector['id']}_events_lost_row_present", "ok": lost is not None,
                       "detail": None if lost is None else f"events lost {lost}"})
        checks.append({"name": f"{collector['id']}_events_lost_matches_manifest", "ok": lost == collector["events_lost"],
                       "detail": f"rows {lost}, manifest {collector['events_lost']}"})
        checks.append({"name": f"{collector['id']}_collector_status", "ok": True,
                       "detail": f"{collector['status']}" + (f": {collector['status_reason']}" if collector["status_reason"] else "")})
        rows += source_rows
    gating = [c for c in checks if not c["name"].endswith("_collector_status")]
    if status == "observed" and not all(c["ok"] for c in gating):
        status, reason = "decode_failed", "a decoder self check failed; see checks"
    errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
    if errors:
        status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    if status == "observed" and not rows:
        status, reason = "decode_failed", "the status text held no labelled line"

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
    ap.add_argument("--source", action="append", default=None, help="bundle relative path of a wpr status text; repeatable; default: every wpr collector's status.txt")
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
