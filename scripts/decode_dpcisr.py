#!/usr/bin/env python3
"""Decode an ``xperf -i trace.etl -a dpcisr`` text report into three decoded tables.

Tables (see docs/contracts/decoded-tables.md sections 5.1, 5.2 and 5.21):

* ``dpcisr_module_cpu``: one row per (kind, module, cpu) cell of the
  "CPU Usage Summing By Module For the Whole Trace" tables, with the module's
  driver class and how it was decided (docs/driver-classes.md).
* ``dpcisr_interval``: one row per (kind, interval, cpu) cell of the
  "Usage From ... Summing In N second intervals" tables.
* ``dpcisr_class_cpu``: the module rows summed per (kind, driver class, cpu),
  and over all CPUs, with each class's share of that kind's time.

A module is classed first through the PC's own driver inventory, when
``--inventory`` names a decoded ``driver-inventory`` bundle of the same
machine (its ``driver_service_class`` table), then through the cited map of
Microsoft inbox binaries in ``scripts/driver_classes.py``, and otherwise is
``unclassified`` with source ``none``. An inventory of another machine, or one
whose sources were observed but that was not decoded, is refused and nothing
is written; an inventory whose sources were not observed is recorded in the
``driver_inventory_join`` check and the inbox map alone is used.

Every row carries a provenance object whose ``row_id_or_offset`` is the 1-based
line number of the raw line it was parsed from.

The bundle must have a ``manifest.json``, and ``--source`` must be a normalised
bundle relative path, inside the bundle, listed in the manifest as a primary
artifact of a collector of kind ``xperf``, and present on disk; anything else is
``decode_failed`` and nothing is written. The sidecar also records that
collector's measurement status as the ``collector_status`` check, which does
not change the decoder's own status: a report decoded from a trace whose
collector is ``capture_failed`` (lost events) still yields rows, and the
manifest and the ``tracestats`` table are where the loss is read. A decoder
never upgrades a collector's status (docs/contracts/measurement-status.md,
section 2, rule 3).

Usage::

    python scripts/decode_dpcisr.py --bundle fixtures/example-bundle \
        --source raw/dpcisr/xperf_analysis.txt [--inventory <driver-inventory bundle>] \
        [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import driver_classes  # noqa: E402
import wf_schema  # noqa: E402

DECODER = "decode_dpcisr"
DECODER_VERSION = "1.2.0"
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


OBSERVED = ("observed", "observed_zero")


def collector_for_source(bundle: Path, source: str) -> dict[str, Any]:
    """The manifest collector that lists ``source`` as a primary xperf artifact.

    Raises DecodeError when the bundle has no manifest, when the source is not such an artifact,
    or when the path is not a normalised bundle relative path inside the bundle.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc
    if source != source.strip() or source.startswith(("/", "\\")) or "\\" in source:
        raise DecodeError(f"{source}: not a bundle relative path")
    if any(part in ("", ".", "..") for part in source.split("/")) or not source.startswith("raw/"):
        raise DecodeError(f"{source}: not a normalised path under raw/")
    if bundle.resolve() not in (bundle / source).resolve().parents:
        raise DecodeError(f"{source}: resolves outside the bundle")
    for collector in manifest["collectors"]:
        if collector["kind"] != "xperf":
            continue
        if any(a["role"] == "primary" and a["path"] == source for a in collector["artifacts"]):
            return collector
    raise DecodeError(f"{source}: not listed in the manifest as the primary artifact of an xperf collector")


def machine_id_of(bundle: Path) -> str | None:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    return (manifest.get("machine") or {}).get("machine_id")


INVENTORY_TABLE = "driver_service_class"
INVENTORY_SOURCES = ("system_drivers", "pnp_device_services")


def load_inventory(bundle: Path, inventory: Path | None) -> tuple[driver_classes.InventoryIndex | None, dict[str, Any]]:
    """The inventory index to classify with, and the ``driver_inventory_join`` check that says what was used.

    Raises DecodeError for an inventory that must not be used or skipped silently:
    another machine, an unreadable bundle, sources observed but no decoded table, a
    table that failed to decode, or rows that fail their schema.
    """
    if inventory is None:
        return None, {"name": "driver_inventory_join", "ok": True,
                      "detail": f"no driver inventory given; classes come from the driver class map {driver_classes.MAP_VERSION} only, so vendor drivers stay unclassified"}
    manifest_path = inventory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"inventory: {manifest_path}: {exc}") from exc
    if manifest.get("scenario", {}).get("id") != "driver_inventory":
        raise DecodeError(f"inventory: the bundle's scenario is {manifest.get('scenario', {}).get('id')!r}, not driver_inventory")
    ours, theirs = machine_id_of(bundle), (manifest.get("machine") or {}).get("machine_id")
    if not ours or ours != theirs:
        raise DecodeError(f"inventory: machine {theirs} is not the machine of this trace ({ours})")
    bundle_id = manifest.get("bundle_id") or inventory.name
    rows_path = inventory / "decoded" / f"{INVENTORY_TABLE}.jsonl"
    meta_path = inventory / "decoded" / f"{INVENTORY_TABLE}.meta.json"
    if not meta_path.is_file():
        statuses = {c["id"]: c["status"] for c in manifest.get("collectors", [])}
        unobserved = [f"{s} {statuses.get(s, 'absent')}" for s in INVENTORY_SOURCES if statuses.get(s) not in OBSERVED]
        if not unobserved:
            raise DecodeError(f"inventory: {bundle_id} has no decoded {INVENTORY_TABLE} table; run scripts/decode_driver_inventory.py on it first")
        return None, {"name": "driver_inventory_join", "ok": False,
                      "detail": f"{bundle_id}: no {INVENTORY_TABLE} table because {', '.join(unobserved)}; classes come from the driver class map {driver_classes.MAP_VERSION} only"}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"inventory: {exc}") from exc
    if meta.get("status") not in OBSERVED:
        raise DecodeError(f"inventory: {bundle_id} {INVENTORY_TABLE} is {meta.get('status')}: {meta.get('status_reason')}")
    if meta.get("schema_version") != wf_schema.table_schema_version(INVENTORY_TABLE) or len(rows) != meta.get("row_count"):
        raise DecodeError(f"inventory: {bundle_id} {INVENTORY_TABLE} is schema {meta.get('schema_version')} with {len(rows)} rows for a row count of {meta.get('row_count')}")
    errors = wf_schema.validate_rows(rows, f"decoded/{INVENTORY_TABLE}.schema.json")
    if errors:
        raise DecodeError(f"inventory: {bundle_id} {INVENTORY_TABLE}: {'; '.join(errors[:3])}")
    index = driver_classes.InventoryIndex(rows, f"{bundle_id}/decoded/{INVENTORY_TABLE}.jsonl#")
    classed = sum(1 for r in rows if r["driver_class"])
    captured = (manifest.get("capture") or {}).get("start_utc")
    return index, {"name": "driver_inventory_join", "ok": True,
                   "detail": f"{bundle_id} (captured {captured}): {len(rows)} driver services, {classed} with a driver class, map {driver_classes.MAP_VERSION}"}


def class_rows(sections: list[Section], source_file: str) -> list[dict[str, Any]]:
    """dpcisr_class_cpu rows: per section, per class with a module, per CPU and over all CPUs."""
    version = wf_schema.table_schema_version("dpcisr_class_cpu")
    rows: list[dict[str, Any]] = []
    for s in sections:
        by_class: dict[str, list[dict[str, Any]]] = {}
        for r in s.module_rows:
            by_class.setdefault(r["driver_class"], []).append(r)
        kind_usec: dict[int | None, int] = {cpu: 0 for cpu in s.cpus}
        for r in s.module_rows:
            kind_usec[r["cpu"]] += r["usec"]
        kind_usec[None] = sum(v for k, v in kind_usec.items() if k is not None)
        for cls in driver_classes.DRIVER_CLASSES:
            members = by_class.get(cls)
            if not members:
                continue
            modules = sorted({r["module"] for r in members})
            sources = sorted({r["classification_source"] for r in members})
            lines = sorted({int(r["provenance"]["row_id_or_offset"].split(":")[1]) for r in members})
            ref = ";".join(f"line:{n}" for n in lines)
            for cpu in [*s.cpus, None]:
                usec = sum(r["usec"] for r in members if cpu is None or r["cpu"] == cpu)
                total = kind_usec[cpu]
                rows.append({
                    "kind": s.kind, "driver_class": cls, "cpu": cpu, "usec": usec, "kind_usec": total,
                    "share": None if total == 0 else usec / total,
                    "module_count": len(modules), "modules": modules, "classification_sources": sources,
                    "class_map_version": driver_classes.MAP_VERSION,
                    "trace_span_start_us": s.span_start_us, "trace_span_end_us": s.span_end_us,
                    "provenance": {"source_file": source_file, "row_id_or_offset": ref, "decoded_table": "dpcisr_class_cpu",
                                   "decoder_version": DECODER_VERSION, "schema_version": version},
                })
    return rows


def class_checks(sections: list[Section], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks = [{"name": "driver_class_map", "ok": True, "detail": f"map version {driver_classes.MAP_VERSION}"}]
    for s in sections:
        mine = [r for r in rows if r["kind"] == s.kind]
        bad = [cpu for cpu in [*s.cpus, None]
               if sum(r["usec"] for r in mine if r["cpu"] == cpu) != sum(r["usec"] for r in s.module_rows if cpu is None or r["cpu"] == cpu)]
        counts = {src: len({r["module"] for r in s.module_rows if r["classification_source"] == src}) for src in driver_classes.SOURCES}
        checks.append({"name": f"{s.kind}_class_totals_reconcile", "ok": not bad,
                       "detail": f"modules by classification source: {', '.join(f'{k} {v}' for k, v in counts.items())}"
                                 + (f"; class sums differ from module sums on cpu {bad}" if bad else "")})
    return checks


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


def decode(bundle: Path, source: str, decoded_at: str | None = None, inventory: Path | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        collector = collector_for_source(bundle, source)
        index, join_check = load_inventory(bundle, inventory)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "tables": {}}
    raw_path = bundle / source
    if not raw_path.is_file():
        return {"status": "decode_failed", "reason": f"{source}: missing from the bundle", "tables": {}}
    text = raw_path.read_text(encoding="utf-8-sig")
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    status, reason, sections, checks = "observed", None, [], []
    try:
        sections = parse_report(text, source)
        checks = checks_for(sections)
        classes: dict[str, dict[str, Any]] = {}
        for s in sections:
            for r in s.module_rows:
                if r["module"] not in classes:
                    classes[r["module"]] = driver_classes.classify_module(r["module"], index)
                # Keep provenance last, as the schema lists it.
                prov = r.pop("provenance")
                r.update(classes[r["module"]])
                r["provenance"] = prov
        checks += class_checks(sections, class_rows(sections, source))
        if not all(c["ok"] for c in checks):
            status, reason = "decode_failed", "a decoder self check failed; see checks"
    except DecodeError as exc:
        status, reason = "decode_failed", str(exc)
    # Informational, never gating: the collector decided its status before any decoder ran.
    detail = collector["status"] + (f": {collector['status_reason']}" if collector["status_reason"] else "")
    checks.append({"name": "collector_status", "ok": collector["status"] in OBSERVED, "detail": f"{collector['id']} {detail}"})
    checks.append(join_check)

    module_rows = [r for s in sections for r in s.module_rows]
    interval_rows = [r for s in sections for r in s.interval_rows]
    summary_rows = class_rows(sections, source) if status == "observed" else []
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
                                                              "domain": "etw_qpc_relative", "unit": "ms"}),
                             ("dpcisr_class_cpu", summary_rows, span)):
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
    ap.add_argument("--inventory", default=None, type=Path,
                    help="decoded driver-inventory bundle of the same machine, whose driver_service_class table classes the modules first")
    ap.add_argument("--decoded-at", default=None, help="override decoded_at_utc (ISO 8601 Z) for reproducible fixtures")
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.source, args.decoded_at, args.inventory)
    for table, info in result["tables"].items():
        print(f"{table}: {info['rows']} rows, status {info['status']}")
    if result["status"] != "observed":
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
