#!/usr/bin/env python3
"""Build the session and incident ledger from collector bundles and a periods file.

See docs/session-ledger.md for the method and docs/contracts/decoded-tables.md
sections 5.21 and 5.22 for the two tables. The inputs are bundles written by
the read only collectors (one or more ``session-ledger`` bundles, and any of
``bugcheck-history``, ``tdr-events``, ``application-errors`` and
``whea-errors``, all from one machine) and the operator's configuration
periods file (schemas/input/config_periods.schema.json). The output directory
holds:

* ``raw/config_periods/periods.json``: a byte copy of the periods file;
* ``raw/inputs/<bundle id>/``: each input bundle's manifest and the raw
  artifacts the ledger read, byte copies, so every row's provenance points at
  a file inside the output and its hash can be checked there;
* ``inputs.json``: the input bundles with their manifest SHA-256;
* ``decoded/session_ledger.jsonl`` and ``decoded/session_ledger_periods.jsonl``
  with their sidecars.

Nothing is read from the PC and nothing is written when an input fails a
check: a bundle whose artifacts do not match its manifest, bundles from two
machines, a periods file that fails its schema, overlaps, or names another
machine, or an output directory that is not empty all end in
``decode_failed`` with nothing written. Without a ``session-ledger`` bundle
there are no play sessions to place, and the result is ``not_collected``.

Usage::

    python scripts/build_session_ledger.py --bundle <dir> [--bundle <dir> ...] \
        --periods <periods.json> --out <output dir> [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_bundle  # noqa: E402
import wf_schema  # noqa: E402

DECODER = "build_session_ledger"
DECODER_VERSION = "1.0.0"
LEDGER = "session_ledger"
PERIODS = "session_ledger_periods"
TOOL = {"name": "collectors/windows bundles joined by scripts/build_session_ledger.py", "version": None}
OBSERVED = ("observed", "observed_zero")
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
RE_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z")
RE_BUNDLE_ID = re.compile(r"^[A-Za-z0-9_]{1,128}$")
RE_DECIMAL = re.compile(r"^[0-9]{1,10}$")

# The game and launcher log sources of the session-ledger collector.
TITLES = {
    "overwatch_logs": ("overwatch", "game"),
    "fortnite_logs": ("fortnite", "game"),
    "battlenet_logs": ("battlenet", "launcher"),
    "epic_launcher_logs": ("epic_games_launcher", "launcher"),
}
GAME_TITLES = sorted(t for t, role in TITLES.values() if role == "game")
# Image names kept in the ledger when a crash or hang record names one; any
# other image name is left out (null), so no other program's name is copied.
# These are the names the games and launchers are known to run under; no
# vendor documents them, so a crash under another name keeps image_name null
# and is still counted.
IMAGE_TITLES = {
    "overwatch.exe": "overwatch",
    "fortniteclient-win64-shipping.exe": "fortnite",
    "battle.net.exe": "battlenet",
    "epicgameslauncher.exe": "epic_games_launcher",
}

# Which collector source yields which incidents. "complete": the provider is
# documented and the source proves its coverage, so a count over a fully
# covered period is complete. "found_only": the provider name is a working
# assumption (the collector marks the source QuietClaimVerified false), so a
# count is the records found and never a rate. "snapshot": files present when
# the collector ran, which Windows may have removed earlier, never a rate.
EVENT_SOURCES = {
    ("bugcheck-history", "system_restart_events"): "system",
    ("tdr-events", "system_bugcheck_events"): "system",
    ("tdr-events", "system_display_events"): "display",
    ("application-errors", "application_error_events"): "application",
    ("whea-errors", "system_whea_events"): "whea",
    ("session-ledger", "display_driver_events"): "display_driver",
    ("session-ledger", "werkernel_events"): "werkernel",
}
FILE_SOURCES = {
    "live_kernel_reports": "live_kernel_report",
    "minidumps": "minidump",
    "wer_report_queue": "wer_report_queued",
    "wer_report_archive": "wer_report_archived",
}
INCIDENT_TYPES = {
    "kernel_power_41": ("complete", ["system"]),
    "bugcheck_1001": ("complete", ["system"]),
    "whea_event": ("complete", ["whea"]),
    "app_crash_1000": ("complete", ["application"]),
    "app_hang_1002": ("complete", ["application"]),
    "wer_1001": ("complete", ["application"]),
    "dotnet_1026": ("complete", ["application"]),
    "display_4101": ("found_only", ["display"]),
    "display_event": ("found_only", ["display"]),
    "display_driver_event": ("found_only", ["display_driver"]),
    "werkernel_event": ("found_only", ["werkernel"]),
    "live_kernel_report": ("snapshot", ["live_kernel_report"]),
    "minidump": ("snapshot", ["minidump"]),
    "wer_report_queued": ("snapshot", ["wer_report_queued"]),
    "wer_report_archived": ("snapshot", ["wer_report_archived"]),
}


class LedgerError(Exception):
    pass


# --- time ---------------------------------------------------------------------------------------------------------

def parse_utc(text: str) -> datetime:
    m = RE_TIME.fullmatch(text or "")
    if not m:
        raise LedgerError(f"{text!r} is not an ISO 8601 UTC time")
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return base.replace(microsecond=int((m.group(2) or "")[:6].ljust(6, "0")))


def parse_offset_time(text: str) -> datetime:
    """A periods file time: ISO 8601 with an explicit offset or Z, as an aware UTC datetime."""
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})", text):
        raise LedgerError(f"periods file: {text!r} is not ISO 8601 with an explicit offset or Z")
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return value.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def hours(seconds: float) -> float:
    return round(seconds / 3600.0, 4)


def union(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    out: list[tuple[datetime, datetime]] = []
    for start, end in sorted(i for i in intervals if i[1] > i[0]):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def covered_seconds(intervals: list[tuple[datetime, datetime]], start: datetime, end: datetime) -> float:
    total = 0.0
    for a, b in union(intervals):
        lo, hi = max(a, start), min(b, end)
        if hi > lo:
            total += (hi - lo).total_seconds()
    return total


# --- inputs -------------------------------------------------------------------------------------------------------

def load_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError(f"{what}: {exc}") from exc


def load_bundle(path: Path) -> dict[str, Any]:
    result = verify_bundle.verify(path)
    if not result["ok"]:
        failed = "; ".join(f"{c['name']}: {c['detail']}" for c in result["checks"] if not c["ok"])
        raise LedgerError(f"{path}: the bundle does not match its manifest ({failed})")
    manifest = load_json(path / "manifest.json", f"{path}/manifest.json")
    orchestrator = manifest["capture"]["orchestrator"]
    if not orchestrator.startswith("wf-collector:"):
        raise LedgerError(f"{path}: not written by a named collector ({orchestrator})")
    collector = orchestrator.split(":", 1)[1]
    if collector not in ("session-ledger", "bugcheck-history", "tdr-events", "application-errors", "whea-errors"):
        raise LedgerError(f"{path}: the ledger does not join {collector} bundles")
    if not RE_BUNDLE_ID.fullmatch(manifest["bundle_id"]):
        raise LedgerError(f"{path}: bundle_id {manifest['bundle_id']!r} is not a plain identifier")
    return {"path": path, "manifest": manifest, "collector": collector, "bundle_id": manifest["bundle_id"],
            "machine_id": manifest["machine"]["machine_id"], "capture_start": parse_utc(manifest["capture"]["start_utc"]),
            "manifest_sha256": wf_schema.sha256_of(path / "manifest.json")}


def load_periods(path: Path, machine_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    document = load_json(path, "periods file")
    errors = wf_schema.validate_object(document, "input/config_periods.schema.json")
    if errors:
        raise LedgerError("periods file: " + "; ".join(errors[:3]))
    if document.get("machine_id") not in (None, machine_id):
        raise LedgerError("periods file: machine_id names another machine than the bundles")
    periods = []
    for index, period in enumerate(document["periods"]):
        start = parse_offset_time(period["start"])
        end = parse_offset_time(period["end"]) if period["end"] is not None else None
        if end is not None and end <= start:
            raise LedgerError(f"periods file: period {period['period_id']} ends before it starts")
        periods.append({"index": index, "id": period["period_id"], "label": period["label"], "start": start, "end": end})
    ids = [p["id"] for p in periods]
    if len(set(ids)) != len(ids):
        raise LedgerError("periods file: period_id values repeat")
    for earlier, later in zip(periods, periods[1:]):
        if earlier["end"] is None:
            raise LedgerError(f"periods file: period {earlier['id']} is open but another period follows it")
        if later["start"] < earlier["end"]:
            raise LedgerError(f"periods file: periods {earlier['id']} and {later['id']} overlap or are out of order")
    return document, periods


# --- reading the bundles ------------------------------------------------------------------------------------------

class Reader:
    """Reads the artifacts of the input bundles and remembers which ones were read, to copy them."""

    def __init__(self) -> None:
        self.used: dict[tuple[str, str], Path] = {}

    def artifact(self, bundle: dict[str, Any], collector: dict[str, Any], name: str) -> tuple[str, Any] | None:
        for artifact in collector["artifacts"]:
            if artifact["path"].rsplit("/", 1)[-1] == name:
                self.used[(bundle["bundle_id"], artifact["path"])] = bundle["path"] / artifact["path"]
                return artifact["path"], load_json(bundle["path"] / artifact["path"], f"{bundle['bundle_id']}/{artifact['path']}")
        return None


def named_event_data(xml: str | None) -> dict[str, str]:
    """The named Data items of an event's XML; unnamed items are not returned."""
    if not isinstance(xml, str):
        return {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    out = {}
    for data in root.iter(f"{EVENT_NS}Data"):
        name = data.get("Name")
        if name:
            out[name] = data.text or ""
    return out


def event_incident(kind: str, element: dict[str, Any]) -> dict[str, Any] | None:
    provider, event_id = element["provider_name"], element["event_id"]
    fields: dict[str, Any] = {}
    if kind == "system":
        if provider == "Microsoft-Windows-Kernel-Power" and event_id == 41:
            code = named_event_data(element.get("xml")).get("BugcheckCode")
            value = int(code) if code is not None and RE_DECIMAL.fullmatch(code.strip()) else None
            fields = {"incident_type": "kernel_power_41", "bugcheck_code": value,
                      "bugcheck_code_hex": f"0x{value:08X}" if value is not None else None}
        elif event_id == 1001 and provider == "Microsoft-Windows-WER-SystemErrorReporting":
            fields = {"incident_type": "bugcheck_1001"}
        else:
            return None
    elif kind == "display":
        fields = {"incident_type": "display_4101" if event_id == 4101 else "display_event"}
    elif kind == "application":
        types = {("Application Error", 1000): "app_crash_1000", ("Application Hang", 1002): "app_hang_1002",
                 ("Windows Error Reporting", 1001): "wer_1001", (".NET Runtime", 1026): "dotnet_1026"}
        incident = types.get((provider, event_id))
        if incident is None:
            return None
        fields = {"incident_type": incident}
        if incident in ("app_crash_1000", "app_hang_1002"):
            properties = element.get("properties") or []
            image = str(properties[0]).lower() if properties and isinstance(properties[0], str) else None
            if image in IMAGE_TITLES:
                fields.update({"image_name": image, "title": IMAGE_TITLES[image],
                               "title_role": "game" if IMAGE_TITLES[image] in GAME_TITLES else "launcher"})
    elif kind == "whea":
        fields = {"incident_type": "whea_event"}
    elif kind == "display_driver":
        fields = {"incident_type": "display_driver_event"}
    elif kind == "werkernel":
        fields = {"incident_type": "werkernel_event"}
    return fields


def blank_row() -> dict[str, Any]:
    return {
        "entry_id": None, "entry_kind": None, "title": None, "title_role": None, "incident_type": None,
        "start_utc": None, "end_utc": None, "start_basis": None, "end_basis": None, "start_inferred": False,
        "end_inferred": False, "duration_s": None, "session_check": None, "event_log": None, "event_provider": None,
        "event_id": None, "event_record_id": None, "bugcheck_code": None, "bugcheck_code_hex": None, "image_name": None,
        "file_name": None, "file_bytes": None, "component": None, "report_kind": None, "period_id": None,
        "period_label": None, "source_bundle_id": None, "source_collector": None, "source_id": None,
        "observations": 1, "provenance": None,
    }


def collect(bundles: list[dict[str, Any]], reader: Reader) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every observation (session or incident) in every bundle, and the coverage each source proves."""
    observations: list[dict[str, Any]] = []
    play_cover: dict[str, list[tuple[datetime, datetime]]] = {t: [] for t, _ in TITLES.values()}
    source_cover: dict[str, list[tuple[datetime, datetime]]] = {}
    sources_seen: dict[str, list[str]] = {}
    for bundle in bundles:
        name = bundle["collector"]
        for collector in bundle["manifest"]["collectors"]:
            sid, status = collector["id"], collector["status"]
            key = f"{bundle['bundle_id']}/{sid}"
            kind = EVENT_SOURCES.get((name, sid))
            if kind is not None:
                sources_seen.setdefault(kind, []).append(f"{key}:{status}")
                if status not in OBSERVED:
                    continue
                window = collector["raw_time_range"]
                source_cover.setdefault(kind, []).append((parse_utc(window["start"]), parse_utc(window["end"])))
                found = reader.artifact(bundle, collector, "events.json")
                if found is None:
                    raise LedgerError(f"{key}: {status} without its events.json")
                path, elements = found
                for index, element in enumerate(elements):
                    fields = event_incident(kind, element)
                    if fields is None:
                        continue
                    when = parse_utc(element["time_created_utc"])
                    observations.append({
                        "kind": "incident", "bundle": bundle, "source_id": sid, "path": path,
                        "offset": f"index:{index};record:{element['record_id']}", "start": when, "start_text": element["time_created_utc"],
                        "identity": ("event", element["log_name"], element["record_id"], element["provider_name"], element["event_id"], element["time_created_utc"]),
                        "fields": {"event_log": element["log_name"], "event_provider": element["provider_name"], "event_id": element["event_id"],
                                   "event_record_id": element["record_id"], "start_basis": "event_time", **fields},
                    })
                continue
            if name != "session-ledger":
                continue
            if sid in TITLES or sid in FILE_SOURCES:
                if sid in FILE_SOURCES:
                    sources_seen.setdefault(FILE_SOURCES[sid], []).append(f"{key}:{status}")
                if status not in OBSERVED:
                    continue
                found = reader.artifact(bundle, collector, "listing.json")
                if found is None:
                    raise LedgerError(f"{key}: {status} without its listing.json")
                path, listing = found
                reader.artifact(bundle, collector, "result.json")
                if sid in TITLES:
                    title, role = TITLES[sid]
                    logs = [(i, e) for i, e in enumerate(listing) if e["type"] == "file" and e["folder"] is None and e["extension"] == ".log"]
                    if logs:
                        oldest = min(parse_utc(e["creation_time_utc"]) for _, e in logs)
                        play_cover[title].append((oldest, bundle["capture_start"]))
                    for index, entry in logs:
                        observations.append({
                            "kind": "session", "bundle": bundle, "source_id": sid, "path": path, "offset": f"index:{index}",
                            "title": title, "role": role, "created": parse_utc(entry["creation_time_utc"]),
                            "written": parse_utc(entry["last_write_time_utc"]), "bytes": entry["bytes"],
                            "created_text": entry["creation_time_utc"], "written_text": entry["last_write_time_utc"],
                            "name": entry["name"] if entry["name_kept"] else None,
                        })
                    continue
                incident = FILE_SOURCES[sid]
                for index, entry in enumerate(listing):
                    if incident in ("live_kernel_report", "minidump"):
                        if entry["type"] != "file" or entry["extension"] != ".dmp":
                            continue
                        fields = {"incident_type": incident, "file_name": entry["name"] if entry["name_kept"] else None,
                                  "file_bytes": entry["bytes"], "component": entry["folder"] if (entry["folder"] and not entry["folder"].startswith("name-")) else None}
                        identity = ("file", incident, entry["folder"] if fields["component"] else None, entry["extension"], entry["bytes"], entry["creation_time_utc"])
                    else:
                        if entry["type"] != "folder" or entry["folder"] is not None:
                            continue
                        fields = {"incident_type": incident, "report_kind": entry["name_prefix"]}
                        identity = ("report", incident, entry["name_prefix"], entry["creation_time_utc"])
                    observations.append({
                        "kind": "incident", "bundle": bundle, "source_id": sid, "path": path, "offset": f"index:{index}",
                        "start": parse_utc(entry["creation_time_utc"]), "start_text": entry["creation_time_utc"], "identity": identity,
                        "fields": {"start_basis": "file_creation_time", **fields},
                    })
    return observations, {"play": play_cover, "sources": source_cover, "seen": sources_seen}


# --- sessions and incidents ---------------------------------------------------------------------------------------

def entry_id(identity: tuple[Any, ...]) -> str:
    return "e-" + hashlib.sha256(json.dumps(identity, default=str).encode("utf-8")).hexdigest()[:16]


def build_sessions(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per log file, merged across bundles. See docs/session-ledger.md, "Play sessions"."""
    sessions = [o for o in observations if o["kind"] == "session"]
    # Inside one bundle, logs of one title that share a creation time: file name tunnelling gives a file created under
    # a name that was just renamed or deleted the old file's creation time, so only the first written keeps the start.
    shared: set[int] = set()
    groups: dict[tuple[str, str, datetime], list[dict[str, Any]]] = {}
    for o in sessions:
        groups.setdefault((o["bundle"]["bundle_id"], o["title"], o["created"]), []).append(o)
    for group in groups.values():
        for later in sorted(group, key=lambda o: o["written"])[1:]:
            shared.add(id(later))
    merged: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for o in sessions:
        identity = ("session", o["title"], o["name"], o["created_text"], "shared" if id(o) in shared else "own",
                    o["written_text"] if id(o) in shared else None)
        merged.setdefault(identity, []).append(o)
    rows = []
    for identity, group in merged.items():
        group.sort(key=lambda o: o["bundle"]["capture_start"])
        latest = group[-1]
        check = "ok"
        # A later snapshot whose file is smaller or was last written earlier is not the same file grown: it was
        # replaced in place, so the earlier observation's end cannot be trusted as this file's history either.
        for earlier, later in zip(group, group[1:]):
            if later["written"] < earlier["written"] or (later["bytes"] is not None and earlier["bytes"] is not None and later["bytes"] < earlier["bytes"]):
                check = "replaced_in_place"
        start = latest["created"]
        end = latest["written"]
        if id(latest) in shared:
            check, start = "creation_shared", None
        if check == "replaced_in_place":
            start = None
        if start is not None and end < start:
            check = "end_before_start"
        row = blank_row()
        row.update({
            "entry_kind": "session", "title": latest["title"], "title_role": latest["role"],
            "start_utc": latest["created_text"] if start is not None else None, "end_utc": latest["written_text"], "start_basis": "file_creation_time" if start is not None else None,
            "end_basis": "file_last_write_time", "start_inferred": start is not None, "end_inferred": True,
            "duration_s": round((end - start).total_seconds(), 3) if (start is not None and check == "ok") else None,
            "session_check": check, "file_name": latest["name"], "file_bytes": latest["bytes"],
            "source_bundle_id": latest["bundle"]["bundle_id"], "source_collector": latest["bundle"]["collector"],
            "source_id": latest["source_id"], "observations": len(group),
            "_path": latest["path"], "_offset": latest["offset"], "_identity": identity,
        })
        rows.append(row)
    return rows


def build_incidents(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for o in observations:
        if o["kind"] == "incident":
            merged.setdefault(o["identity"], []).append(o)
    rows = []
    for identity, group in merged.items():
        group.sort(key=lambda o: (o["bundle"]["capture_start"], o["bundle"]["bundle_id"]))
        latest = group[-1]
        row = blank_row()
        row.update(latest["fields"])
        row.update({
            "entry_kind": "incident", "start_utc": latest["start_text"], "source_bundle_id": latest["bundle"]["bundle_id"],
            "source_collector": latest["bundle"]["collector"], "source_id": latest["source_id"], "observations": len(group),
            "_path": latest["path"], "_offset": latest["offset"], "_identity": identity,
        })
        rows.append(row)
    return rows


def assign_periods(rows: list[dict[str, Any]], periods: list[dict[str, Any]], as_of: datetime) -> None:
    for row in rows:
        anchor_text = row["start_utc"] or row["end_utc"]
        anchor = parse_utc(anchor_text) if anchor_text else None
        for period in periods:
            end = period["end"] or as_of
            if anchor is not None and period["start"] <= anchor < end:
                row["period_id"], row["period_label"] = period["id"], period["label"]
                break


def summarise(periods: list[dict[str, Any]], tracked: list[str], rows: list[dict[str, Any]], cover: dict[str, Any],
              as_of: datetime, schema_version: str) -> list[dict[str, Any]]:
    out = []
    sessions = [r for r in rows if r["entry_kind"] == "session"]
    incidents = [r for r in rows if r["entry_kind"] == "incident"]
    for period in periods:
        start, end = period["start"], period["end"] or as_of
        span = max((end - start).total_seconds(), 0.0)
        play = []
        total_seconds, total_sessions, total_missing, complete = 0.0, 0, 0, span > 0
        gaps = []
        for title in tracked:
            mine = [s for s in sessions if s["title"] == title and s["period_id"] == period["id"]]
            seconds = 0.0
            for s in sessions:
                if s["title"] != title or s["duration_s"] is None:
                    continue
                a, b = parse_utc(s["start_utc"]), parse_utc(s["end_utc"])
                lo, hi = max(a, start), min(b, end)
                if hi > lo:
                    seconds += (hi - lo).total_seconds()
            missing = sum(1 for s in mine if s["duration_s"] is None)
            covered = covered_seconds(cover["play"].get(title, []), start, end)
            status = "none" if covered <= 0 else ("full" if covered >= span - 1.0 else "partial")
            if status != "full":
                complete = False
                gaps.append(f"{title} play coverage is {status}")
            if missing:
                complete = False
                gaps.append(f"{missing} {title} session(s) without a known duration")
            play.append({"title": title, "coverage_status": status, "covered_hours": hours(covered), "sessions": len(mine),
                         "sessions_without_duration": missing, "hours_played": hours(seconds)})
            total_seconds += seconds
            total_sessions += len(mine)
            total_missing += missing
        played = hours(total_seconds)
        entries = []
        for incident_type, (basis, kinds) in INCIDENT_TYPES.items():
            found = [r for r in incidents if r["incident_type"] == incident_type and r["period_id"] == period["id"]]
            intervals = [i for k in kinds for i in cover["sources"].get(k, [])]
            seen = [s for k in kinds for s in cover["seen"].get(k, [])]
            if basis == "snapshot":
                status = "snapshot" if seen and any(s.rsplit(":", 1)[1] in OBSERVED for s in seen) else "none"
                covered = 0.0
            else:
                covered = covered_seconds(intervals, start, end)
                status = "none" if covered <= 0 else ("full" if covered >= span - 1.0 else "partial")
            count: int | None = len(found)
            if status == "none" and not found:
                count = None
            reason = None
            if count is None:
                reason = "not measured: no input source covers this period"
            elif basis == "snapshot":
                reason = "a snapshot of the files present when the collector ran; Windows may have removed earlier ones"
            elif basis == "found_only":
                reason = "the provider is a working assumption, so records not found are not proven absent"
            elif status != "full":
                reason = f"incident coverage is {status}"
            elif not complete:
                reason = "; ".join(gaps) or "the period has no length"
            elif total_seconds <= 0:
                reason = "no hours played in the period"
            entries.append({
                "incident_type": incident_type, "count": count, "count_basis": basis if count is not None else "not_measured",
                "coverage_status": status, "covered_hours": hours(covered), "hours_played": played,
                "per_hour": round(count / (total_seconds / 3600.0), 4) if reason is None and count is not None else None,
                "withheld_reason": reason,
            })
        out.append({
            "period_id": period["id"], "period_label": period["label"], "start_utc": iso(start), "end_utc": iso(end),
            "end_is_as_of": period["end"] is None, "period_hours": hours(span), "tracked_titles": list(tracked),
            "sessions": total_sessions, "sessions_without_duration": total_missing, "hours_played": played,
            "hours_played_complete": complete, "hours_played_gaps": gaps, "play": play, "incidents": entries,
            "provenance": {"source_file": "raw/config_periods/periods.json", "row_id_or_offset": f"index:{period['index']}",
                           "decoded_table": PERIODS, "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return out


# --- writing ------------------------------------------------------------------------------------------------------

def sidecar(table: str, schema_version: str, sources: list[tuple[str, Path]], rows: list[dict[str, Any]], status: str,
            reason: str | None, checks: list[dict[str, Any]], decoded_at: str, time_range: dict[str, Any] | None) -> dict[str, Any]:
    meta = {
        "decoded_table": table, "schema_version": schema_version, "decoder": DECODER, "decoder_version": DECODER_VERSION,
        "tool": TOOL, "source_files": [{"path": p, "sha256": wf_schema.sha256_of(f)} for p, f in sources],
        "row_count": len(rows), "time_domain": "system_time", "native_time_range": time_range, "status": status,
        "status_reason": reason, "checks": checks, "decoded_at_utc": decoded_at,
    }
    errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {errors}")
    return meta


def build(bundle_paths: list[Path], periods_path: Path, out: Path, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger_version = wf_schema.table_schema_version(LEDGER)
    periods_version = wf_schema.table_schema_version(PERIODS)
    try:
        if out.exists() and (not out.is_dir() or any(out.iterdir())):
            raise LedgerError(f"{out}: the output directory exists and is not empty")
        if not bundle_paths:
            raise LedgerError("no input bundle was named")
        bundles = [load_bundle(p) for p in bundle_paths]
        ids = [b["bundle_id"] for b in bundles]
        if len(set(ids)) != len(ids):
            raise LedgerError("the same bundle_id was named twice")
        machines = {b["machine_id"] for b in bundles}
        if len(machines) != 1:
            raise LedgerError("the bundles come from more than one machine (machine_id differs)")
        machine_id = machines.pop()
        document, periods = load_periods(periods_path, machine_id)
        ledger_bundles = [b for b in bundles if b["collector"] == "session-ledger"]
        if not ledger_bundles:
            return {"status": "not_collected", "reason": "no session-ledger bundle among the inputs, so there are no play sessions to place",
                    "rows": 0, "periods": 0}
        as_of = max(b["capture_start"] for b in ledger_bundles)
        reader = Reader()
        observations, cover = collect(bundles, reader)
    except LedgerError as exc:
        return {"status": "decode_failed", "reason": str(exc), "rows": 0, "periods": 0}

    tracked = [t for t in document["tracked_titles"]]
    rows = build_sessions(observations) + build_incidents(observations)
    assign_periods(rows, periods, as_of)
    for row in rows:
        row["entry_id"] = entry_id(row.pop("_identity"))
        path, offset = row.pop("_path"), row.pop("_offset")
        row["provenance"] = {"source_file": f"raw/inputs/{row['source_bundle_id']}/{path}", "row_id_or_offset": offset,
                             "decoded_table": LEDGER, "decoder_version": DECODER_VERSION, "schema_version": ledger_version}
    rows.sort(key=lambda r: (r["start_utc"] or r["end_utc"] or "", r["entry_kind"], r["entry_id"]))
    summary = summarise(periods, tracked, rows, cover, as_of, periods_version)

    checks = [{"name": "bundles_verified", "ok": True, "detail": f"{len(bundles)} bundles match their manifests"},
              {"name": "one_machine", "ok": True, "detail": None},
              {"name": "periods_valid", "ok": True, "detail": f"{len(periods)} periods, revision {document['revision']}"}]
    ledger_errors = wf_schema.validate_rows(rows, f"decoded/{LEDGER}.schema.json")
    summary_errors = wf_schema.validate_rows(summary, f"decoded/{PERIODS}.schema.json")
    checks.append({"name": "rows_validate", "ok": not (ledger_errors or summary_errors), "detail": "; ".join((ledger_errors + summary_errors)[:3]) or None})
    if ledger_errors or summary_errors:
        return {"status": "decode_failed", "reason": "; ".join((ledger_errors + summary_errors)[:3]), "rows": 0, "periods": 0}

    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw"
    (raw / "config_periods").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(periods_path, raw / "config_periods" / "periods.json")
    copied: list[tuple[str, Path]] = []
    for bundle in bundles:
        target = raw / "inputs" / bundle["bundle_id"]
        target.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(bundle["path"] / "manifest.json", target / "manifest.json")
    for (bundle_id, path), source in sorted(reader.used.items()):
        target = raw / "inputs" / bundle_id / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append((f"raw/inputs/{bundle_id}/{path}", target))
    inputs = {
        "decoder": DECODER, "decoder_version": DECODER_VERSION, "machine_id": machine_id, "as_of_utc": iso(as_of),
        "periods": {"path": "raw/config_periods/periods.json", "sha256": wf_schema.sha256_of(raw / "config_periods" / "periods.json"),
                    "revision": document["revision"]},
        "bundles": [{"bundle_id": b["bundle_id"], "collector": b["collector"], "capture_start_utc": b["manifest"]["capture"]["start_utc"],
                     "manifest": f"raw/inputs/{b['bundle_id']}/manifest.json", "manifest_sha256": b["manifest_sha256"],
                     "sources": {c["id"]: c["status"] for c in b["manifest"]["collectors"]}}
                    for b in sorted(bundles, key=lambda b: b["bundle_id"])],
    }
    wf_schema.write_json(out / "inputs.json", inputs)
    decoded = out / "decoded"
    decoded.mkdir(exist_ok=True)
    stamps = sorted(t for r in rows for t in (r["start_utc"], r["end_utc"]) if t)
    time_range = {"start": stamps[0], "end": stamps[-1], "domain": "system_time", "unit": "iso_utc"} if stamps else None
    # Zero rows is a measurement only when some input was observed; otherwise nothing was measured, and the summary rows
    # say not_measured period by period.
    measured = any(cover["play"].values()) or any(cover["sources"].values()) or \
        any(s.rsplit(":", 1)[1] in OBSERVED for kind in FILE_SOURCES.values() for s in cover["seen"].get(kind, []))
    status, reason = "observed", None
    if not rows:
        status, reason = ("observed_zero", "the observed inputs hold no session and no incident") if measured else \
            ("not_collected", "no input source was observed: no game log, event export or dump folder could be read")
    wf_schema.write_jsonl(decoded / f"{LEDGER}.jsonl", rows)
    wf_schema.write_json(decoded / f"{LEDGER}.meta.json",
                         sidecar(LEDGER, ledger_version, copied or [("raw/config_periods/periods.json", raw / "config_periods" / "periods.json")],
                                 rows, status, reason, checks, decoded_at, time_range))
    periods_file = [("raw/config_periods/periods.json", raw / "config_periods" / "periods.json")]
    period_range = {"start": summary[0]["start_utc"], "end": summary[-1]["end_utc"], "domain": "system_time", "unit": "iso_utc"} if summary else None
    wf_schema.write_jsonl(decoded / f"{PERIODS}.jsonl", summary)
    wf_schema.write_json(decoded / f"{PERIODS}.meta.json",
                         sidecar(PERIODS, periods_version, periods_file + copied, summary, "observed" if summary else "observed_zero",
                                 None if summary else "the periods file lists no period", checks, decoded_at, period_range))
    return {"status": status, "reason": reason, "rows": len(rows), "periods": len(summary)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", action="append", default=[], type=Path, help="an input bundle directory; repeatable")
    ap.add_argument("--periods", required=True, type=Path, help="the operator's configuration periods file")
    ap.add_argument("--out", required=True, type=Path, help="the output directory, absent or empty")
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = build(args.bundle, args.periods, args.out, args.decoded_at)
    print(f"{LEDGER}: {result['rows']} rows, {PERIODS}: {result['periods']} rows, status {result['status']}")
    if result["status"] not in OBSERVED:
        print(f"ledger status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
