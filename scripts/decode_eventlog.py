#!/usr/bin/env python3
"""Decode event log exports into the ``eventlog_events`` table.

See docs/contracts/decoded-tables.md section 5.6. The input is the JSON array
an event log collector writes as ``raw/<collector id>/events.json`` (the
format is in collectors/windows/README.md): one element per record, with the
table's column names plus ``xml``, the complete event XML, which stays in the
raw artifact and is not copied into the table. One row per element; the
provenance ``row_id_or_offset`` is ``index:<n>;record:<id>`` with the 0-based
element index and the RecordId.

Without ``--source`` the decoder reads the manifest and takes the primary
artifact of every collector of kind ``eventlog`` whose status is ``observed``
or ``observed_zero``. A collector that could not read its channel has no such
artifact, and the decoder then reports ``not_collected``: an input that is
absent is never decoded into zero rows. A primary artifact the manifest names
but the bundle lacks is ``decode_failed``.

Every ``--source`` must be a normalised bundle relative path, inside the
bundle, listed in the manifest as a primary JSON artifact of an event log
collector that is ``observed`` or ``observed_zero``, and present on disk;
anything else is ``decode_failed`` and nothing is written.

Usage::

    python scripts/decode_eventlog.py --bundle <bundle directory> \
        [--source raw/<collector id>/events.json ...] [--decoded-at 2026-09-03T00:00:00Z]
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

DECODER = "decode_eventlog"
DECODER_VERSION = "1.0.0"
TABLE = "eventlog_events"
TOOL = {"name": "collectors/windows event log export (System.Diagnostics.Eventing.Reader)", "version": None}
COLUMNS = ["record_id", "log_name", "provider_name", "event_id", "version", "level", "level_display", "task",
           "task_display", "opcode", "keywords", "time_created_utc", "machine_name", "user_id", "process_id",
           "thread_id", "message", "properties"]
OBSERVED = ("observed", "observed_zero")
RE_XML_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
RE_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z")


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
    """The primary JSON artifacts of every event log collector that is observed or observed_zero."""
    out = []
    for collector in manifest["collectors"]:
        if collector["kind"] != "eventlog" or collector["status"] not in OBSERVED:
            continue
        out += [a["path"] for a in collector["artifacts"] if a["role"] == "primary" and a["path"].endswith(".json")]
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
        raise DecodeError(f"{source}: not listed in the manifest as the primary JSON artifact of an observed event log collector")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")


def parse_time(text: str) -> datetime:
    """``time_created_utc`` as an aware UTC datetime; the fraction may be absent or up to seven digits."""
    m = RE_TIME.fullmatch(text)
    if not m:
        raise DecodeError(f"time_created_utc {text!r} is not ISO 8601 UTC")
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    fraction = (m.group(2) or "")[:6].ljust(6, "0")
    return base.replace(microsecond=int(fraction))


def time_key(text: str) -> tuple[datetime, str]:
    """Sort key at the full 100 ns precision: the parsed time, then the fraction padded to seven digits."""
    m = RE_TIME.fullmatch(text)
    return parse_time(text), ((m.group(2) if m else "") or "").ljust(7, "0")


def decode_source(bundle: Path, source: str, schema_version: str) -> tuple[list[dict[str, Any]], int]:
    """Return the rows of one export and how many elements carried XML that agreed on the RecordId."""
    try:
        elements = json.loads((bundle / source).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    if not isinstance(elements, list):
        raise DecodeError(f"{source}: the export is not a JSON array")
    rows, xml_agree = [], 0
    for index, element in enumerate(elements):
        if not isinstance(element, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        missing = [c for c in COLUMNS if c not in element]
        if missing:
            raise DecodeError(f"{source}: element {index} lacks {', '.join(missing)}")
        record_id = element["record_id"]
        if not isinstance(record_id, int) or isinstance(record_id, bool):
            raise DecodeError(f"{source}: element {index} has no integer record_id")
        xml = element.get("xml")
        if isinstance(xml, str):
            m = RE_XML_RECORD_ID.search(xml)
            if m and int(m.group(1)) != record_id:
                raise DecodeError(f"{source}: element {index} says record {record_id}, its XML says {m.group(1)}")
            xml_agree += 1 if m else 0
        if not isinstance(element["time_created_utc"], str):
            raise DecodeError(f"{source}: element {index} has no time_created_utc text")
        parse_time(element["time_created_utc"])
        row = {c: element[c] for c in COLUMNS}
        row["provenance"] = {
            "source_file": source,
            "row_id_or_offset": f"index:{index};record:{record_id}",
            "decoded_table": TABLE,
            "decoder_version": DECODER_VERSION,
            "schema_version": schema_version,
        }
        rows.append(row)
    return rows, xml_agree


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
                return {"status": "not_collected", "reason": "the bundle holds no event log export to decode", "rows": 0, "sources": 0}
        if not sources:
            raise DecodeError("no source was named")
        for source in sources:
            check_source_path(bundle, source, allowed)
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
    try:
        for source in sources:
            source_rows, xml_agree = decode_source(bundle, source, schema_version)
            rows += source_rows
            checks.append({"name": f"export_read:{source}", "ok": True,
                           "detail": f"{len(source_rows)} records, {xml_agree} with XML that agrees on the RecordId"})
        errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
        elif not rows:
            status, reason = "observed_zero", "every export is an empty array"
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        checks.append({"name": "export_read", "ok": False, "detail": str(exc)})

    native_range = None
    if rows:
        # Compare parsed times: as text, a whole second timestamp would sort
        # after a fractional one at the same second.
        stamps = sorted((r["time_created_utc"] for r in rows), key=time_key)
        native_range = {"start": stamps[0], "end": stamps[-1], "domain": "system_time", "unit": "iso_utc"}
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
                    help="bundle relative path of an export, for example raw/system_restart_events/events.json; repeatable")
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at)
    print(f"{TABLE}: {result['rows']} rows from {result['sources']} exports, status {result['status']}")
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
