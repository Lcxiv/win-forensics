#!/usr/bin/env python3
"""Decode a bundle's driver inventory into the ``driver_service_class`` table.

See docs/contracts/decoded-tables.md section 5.22 and docs/driver-classes.md.
The table joins two sources of the ``driver-inventory`` collector on the
driver service name:

* ``system_drivers`` (Win32_SystemDriver): ``Name`` is the service, ``PathName``
  the fully qualified path to the service binary.
* ``pnp_device_services`` (Win32_PnPEntity, present devices only, read with
  only ``Service`` and ``ClassGuid``): ``Service`` names the service that
  supports the device, ``ClassGuid`` its device setup class.

Win32_SystemDriverPNPEntity is the association Microsoft documents between the
two classes; joining on the service name gives the same pairs without reading
the association's references, which carry device instance paths:
https://learn.microsoft.com/windows/win32/cimwin32prov/win32-systemdriver
https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity
https://learn.microsoft.com/windows/win32/cimwin32prov/win32-systemdriverpnpentity

One row per driver service: the service name, the file name of its binary,
the setup classes of its present devices with a count each, and the driver
class those classes give (``scripts/driver_classes.py``), or null with the
reason when they give none. Nothing else leaves the export: no device
instance path, hardware identifier, device name, or full binary path.

Any bundle that lists both sources is accepted, a ``driver_inventory`` run or
a scenario run such as S1. The table needs both sources. When either was not observed the table is
``not_collected`` and not written: a service list without the device read
would look like services without devices, which it is not.

Usage::

    python scripts/decode_driver_inventory.py --bundle <bundle directory> [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import driver_classes  # noqa: E402
import wf_schema  # noqa: E402

DECODER = "decode_driver_inventory"
DECODER_VERSION = "1.0.0"
OBSERVED = ("observed", "observed_zero")
TABLE = "driver_service_class"
SERVICES = "system_drivers"
DEVICES = "pnp_device_services"
TOOL = {"name": "collectors/windows driver-inventory (Win32_SystemDriver, Win32_PnPEntity)", "version": None}


class DecodeError(Exception):
    pass


def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc
    return manifest


def read_primary_array(bundle: Path, entry: dict[str, Any]) -> tuple[str, list[Any]]:
    """The primary export of an observed source, as a JSON array, from a normalised path inside the bundle."""
    primaries = [a["path"] for a in entry["artifacts"] if a["role"] == "primary"]
    if not primaries:
        raise DecodeError(f"{entry['id']}: observed but without a primary artifact")
    source = primaries[0]
    if "\\" in source or not source.startswith("raw/") or any(p in ("", ".", "..") for p in source.split("/")):
        raise DecodeError(f"{source}: not a normalised path under raw/")
    path = (bundle / source).resolve()
    if bundle.resolve() not in path.parents:
        raise DecodeError(f"{source}: resolves outside the bundle")
    if not path.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    if not isinstance(data, list):
        raise DecodeError(f"{source}: the export is not a JSON array")
    return source, data


def build_rows(services: list[Any], services_source: str, devices: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    version = wf_schema.table_schema_version(TABLE)
    by_service: dict[str, list[int]] = {}
    no_service = 0
    for index, device in enumerate(devices):
        if not isinstance(device, dict):
            raise DecodeError(f"device record {index}: not an object")
        service = device.get("Service")
        if not isinstance(service, str) or not service.strip():
            no_service += 1
            continue
        by_service.setdefault(service.strip().lower(), []).append(index)
    rows: list[dict[str, Any]] = []
    matched: set[str] = set()
    unparsed_paths = 0
    for index, record in enumerate(services):
        if not isinstance(record, dict):
            raise DecodeError(f"{services_source} index {index}: not an object")
        name = record.get("Name")
        if not isinstance(name, str) or not name.strip():
            raise DecodeError(f"{services_source} index {index}: a driver service without a name")
        key = name.strip().lower()
        if key in matched:
            raise DecodeError(f"{services_source} index {index}: the service {name} is listed twice")
        matched.add(key)
        driver_file = driver_classes.file_name_of(record.get("PathName"))
        if driver_file is None and record.get("PathName"):
            unparsed_paths += 1
        device_indexes = by_service.get(key, [])
        counts: dict[str | None, int] = {}
        for i in device_indexes:
            guid = driver_classes.normalise_guid(devices[i].get("ClassGuid"))
            counts[guid] = counts.get(guid, 0) + 1
        setup_classes = []
        for guid in sorted(counts, key=lambda g: (g is None, g or "")):
            mapped = driver_classes.SETUP_CLASSES.get(guid) if guid else None
            setup_classes.append({"class_guid": guid, "setup_class": mapped[0] if mapped else None, "device_count": counts[guid]})
        driver_class, reason = driver_classes.classify_service(setup_classes)
        rows.append({
            "service": name.strip(),
            "driver_file": driver_file,
            "device_count": len(device_indexes),
            "setup_classes": setup_classes,
            "driver_class": driver_class,
            "class_reason": reason,
            "class_map_version": driver_classes.MAP_VERSION,
            "device_records": device_indexes,
            "provenance": {"source_file": services_source, "row_id_or_offset": f"index:{index}", "decoded_table": TABLE,
                           "decoder_version": DECODER_VERSION, "schema_version": version},
        })
    orphan = sorted(s for s in by_service if s not in matched)
    checks = [
        {"name": "driver_class_map", "ok": True, "detail": f"map version {driver_classes.MAP_VERSION}"},
        {"name": "devices_without_service", "ok": True, "detail": f"{no_service} present devices name no service"},
        {"name": "devices_with_unlisted_service", "ok": True,
         "detail": f"{sum(len(by_service[s]) for s in orphan)} present devices name {len(orphan)} services that Win32_SystemDriver does not list"},
        {"name": "service_paths_without_file_name", "ok": True, "detail": f"{unparsed_paths} service paths give no driver file name"},
    ]
    return rows, checks


def decode(bundle: Path, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        manifest = load_manifest(bundle)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "tables": {}}
    entries = {c["id"]: c for c in manifest["collectors"]}
    missing = [f"{sid} is {entries[sid]['status']}" if sid in entries else f"{sid} is not in the bundle"
               for sid in (SERVICES, DEVICES) if sid not in entries or entries[sid]["status"] not in OBSERVED]
    if missing:
        reason = "the join needs both sources observed: " + "; ".join(missing)
        return {"status": "not_collected", "reason": reason, "tables": {TABLE: {"rows": 0, "status": "not_collected"}}}
    status, reason = "observed", None
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    source_files: list[str] = []
    try:
        services_source, services = read_primary_array(bundle, entries[SERVICES])
        devices_source, devices = read_primary_array(bundle, entries[DEVICES])
        source_files = [services_source, devices_source]
        rows, checks = build_rows(services, services_source, devices)
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        source_files = [p for p in (next((a["path"] for a in entries[s]["artifacts"] if a["role"] == "primary"), None) for s in (SERVICES, DEVICES))
                        if p and (bundle / p).is_file()]
        if not source_files:
            return {"status": status, "reason": reason, "tables": {}}
    errors = wf_schema.validate_rows(rows, f"decoded/{TABLE}.schema.json")
    if errors:
        status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    if status == "observed" and not rows:
        status, reason = "observed_zero", "Win32_SystemDriver listed no driver service"
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{TABLE}.jsonl", rows)
    meta = {
        "decoded_table": TABLE,
        "schema_version": wf_schema.table_schema_version(TABLE),
        "decoder": DECODER,
        "decoder_version": DECODER_VERSION,
        "tool": TOOL,
        "source_files": [{"path": p, "sha256": wf_schema.sha256_of(bundle / p)} for p in source_files],
        "row_count": len(rows),
        "time_domain": "none",
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
    return {"status": status, "reason": reason, "tables": {TABLE: {"rows": len(rows), "status": status}}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path, help="bundle directory listing system_drivers and pnp_device_services")
    ap.add_argument("--decoded-at", default=None, help="override decoded_at_utc (ISO 8601 Z) for reproducible fixtures")
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.decoded_at)
    for table, info in result["tables"].items():
        print(f"{table}: {info['rows']} rows, status {info['status']}")
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
