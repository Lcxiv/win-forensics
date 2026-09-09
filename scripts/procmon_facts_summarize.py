#!/usr/bin/env python3
"""Summarize the outputs of scripts/procmon_facts.ps1 into facts.json and small fixtures.

Usage: python scripts/procmon_facts_summarize.py <out_dir> <fixture_out_dir> <committed_pmc_dir>

Reads runner.json, procmon-version.json, runs.json, registry-after-run.json, every
CSV and XML export, every PML backing file (through procmon-parser, best effort),
and the committed .pmc files. Writes <fixture_out_dir>/facts.json plus the head of
each export (header and first rows) so the facts can be committed without the
full exports.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

HEAD_ROWS = 20
XML_HEAD_LINES = 120
STACK_SCAN_LIMIT = 5000
CLOCK_RE = re.compile(r"^(?P<h>\d{1,2}):(?P<m>[0-5]\d):(?P<s>[0-5]\d)\.(?P<f>\d{7}) (?P<ampm>AM|PM)$")
DATE_TIME_RE = re.compile(r"^\d{1,2}/\d{1,2}/\d{4} \d{1,2}:[0-5]\d:[0-5]\d (AM|PM)$")
RELATIVE_RE = re.compile(r"^\d{2}:[0-5]\d:[0-5]\d\.\d{7}$")
DECIMAL_7_RE = re.compile(r"^\d+\.\d{7}$")
INTEGER_RE = re.compile(r"^\d+$")
TEXT_RE = re.compile(r"^.+$")


def clock_ticks(value: str) -> int:
    match = CLOCK_RE.fullmatch(value)
    if not match:
        raise ValueError(value)
    hour = int(match["h"]) % 12 + (12 if match["ampm"] == "PM" else 0)
    return ((hour * 60 + int(match["m"])) * 60 + int(match["s"])) * 10_000_000 + int(match["f"])


def format_checks(header: list[str], rows: list[list[str]], row_count: int) -> dict:
    checks = {"rows_checked": row_count, "mismatches": {}}
    positions = {name: header.index(name) for name in header}
    def field(row: list[str], name: str) -> str | None:
        index = positions[name]
        return row[index] if index < len(row) else None

    def matches(row: list[str], name: str, pattern: re.Pattern[str]) -> bool:
        value = field(row, name)
        return value is not None and pattern.fullmatch(value) is not None

    checks["mismatches"]["row_width"] = sum(len(row) != len(header) for row in rows)
    for name in ("Time of Day", "Completion Time"):
        checks["mismatches"][name] = sum(not matches(row, name, CLOCK_RE) for row in rows)
    checks["mismatches"]["Date & Time"] = sum(not matches(row, "Date & Time", DATE_TIME_RE) for row in rows)
    checks["mismatches"]["Relative Time"] = sum(not matches(row, "Relative Time", RELATIVE_RE) for row in rows)
    checks["mismatches"]["Duration"] = sum(not matches(row, "Duration", DECIMAL_7_RE) for row in rows)
    for name in ("PID", "TID", "Parent PID", "Session"):
        checks["mismatches"][name] = sum(not matches(row, name, INTEGER_RE) for row in rows)
    checks["mismatches"]["Event Class"] = sum(field(row, "Event Class") not in {
        "File System", "Registry", "Process", "Network", "Profiling", "IPC"
    } for row in rows)
    checks["mismatches"]["Category"] = sum(field(row, "Category") is None for row in rows)
    for name in ("Integrity", "Architecture", "Virtualized"):
        checks["mismatches"][name] = sum(not matches(row, name, TEXT_RE) for row in rows)
    return checks


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else None


def summarize_csv(path: Path, fixture_dir: Path) -> dict:
    info: dict = {"bytes": path.stat().st_size, "sha256": sha256(path)}
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader)
            rows = 0
            head: list[list[str]] = []
            duration_matches = 0
            duration_checked = 0
            sequence_not_na = 0
            format_rows: list[list[str]] = []
            path_prefix_hits = 0
            process_names: dict[str, int] = {}
            for row in reader:
                rows += 1
                if rows <= HEAD_ROWS:
                    head.append(row)
                if set(("Time of Day", "Date & Time", "Relative Time", "Duration", "Completion Time",
                        "Sequence", "PID", "TID", "Parent PID", "Session", "Event Class")) <= set(header):
                    if rows <= 2000:
                        duration_checked += 1
                        try:
                            expected = (clock_ticks(row[header.index("Completion Time")]) -
                                        clock_ticks(row[header.index("Time of Day")]))
                            if expected < 0:
                                expected += 24 * 60 * 60 * 10_000_000
                            actual = Decimal(row[header.index("Duration")])
                            duration_matches += actual == (Decimal(expected) / Decimal(10_000_000))
                        except (IndexError, InvalidOperation, ValueError):
                            pass
                    sequence_index = header.index("Sequence")
                    sequence_not_na += sequence_index >= len(row) or row[sequence_index] != "n/a"
                    if set(("Category", "Integrity", "Architecture", "Virtualized")) <= set(header):
                        format_rows.append(row)
                if header and "Path" in header:
                    p = row[header.index("Path")]
                    if p.startswith("C:\\wf-procmon-facts"):
                        path_prefix_hits += 1
                if header and "Process Name" in header:
                    n = row[header.index("Process Name")]
                    process_names[n] = process_names.get(n, 0) + 1
        info.update({
            "columns": header,
            "column_count": len(header),
            "rows": rows,
            "rows_with_load_path_prefix": path_prefix_hits,
            "distinct_process_names": len(process_names),
            "top_process_names": sorted(process_names.items(), key=lambda kv: -kv[1])[:8],
        })
        if duration_checked:
            info["duration_check"] = {"rows_checked": duration_checked, "exact_matches": duration_matches}
            info["sequence_check"] = {"rows_checked": rows, "not_n_a": sequence_not_na}
            info["format_checks"] = format_checks(header, format_rows, len(format_rows))
        head_path = fixture_dir / (path.stem + ".head.csv")
        with head_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
            w.writerow(header)
            for row in head:
                w.writerow(row)
        info["head_fixture"] = head_path.name
    except Exception as exc:  # noqa: BLE001
        info["error"] = repr(exc)
    return info


def summarize_xml(path: Path, fixture_dir: Path) -> dict:
    info: dict = {"bytes": path.stat().st_size, "sha256": sha256(path)}
    try:
        events = stacks = frames = 0
        head: list[str] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i < XML_HEAD_LINES:
                    head.append(line.rstrip("\r\n"))
                events += line.count("<event>")
                stacks += line.count("<stack>")
                frames += line.count("<frame>")
        info.update({"event_elements": events, "stack_elements": stacks, "frame_elements": frames})
        (fixture_dir / (path.stem + ".head.xml")).write_text("\n".join(head) + "\n", encoding="utf-8")
        info["head_fixture"] = path.stem + ".head.xml"
    except Exception as exc:  # noqa: BLE001
        info["error"] = repr(exc)
    return info


def summarize_pml(path: Path) -> dict:
    info: dict = {"bytes": path.stat().st_size}
    try:
        from procmon_parser import ProcmonLogsReader
        with path.open("rb") as fh:
            reader = ProcmonLogsReader(fh)
            total = len(reader)
            scanned = with_stack = 0
            max_depth = 0
            for ev in reader:
                scanned += 1
                st = getattr(ev, "stacktrace", None) or []
                if st:
                    with_stack += 1
                    max_depth = max(max_depth, len(st))
                if scanned >= STACK_SCAN_LIMIT:
                    break
            details = reader.system_details()
            info.update({
                "parser": "procmon-parser",
                "events_total": total,
                "events_scanned_for_stacks": scanned,
                "events_with_stack": with_stack,
                "max_stack_depth_seen": max_depth,
                "system_details_keys": sorted(str(k) for k in details.keys()) if isinstance(details, dict) else str(type(details)),
            })
    except Exception as exc:  # noqa: BLE001
        info["parser_error"] = repr(exc)
    return info


def summarize_pmc(path: Path) -> dict:
    info: dict = {"bytes": path.stat().st_size, "sha256": sha256(path)}
    try:
        from procmon_parser import load_configuration
        with path.open("rb") as fh:
            cfg = load_configuration(fh)
        records = {}
        for name, value in cfg.items():
            if name in ("FilterRules", "HighlightRules"):
                records[name] = [str(r) for r in value]
            elif name == "ColumnMap":
                records[name] = [c.name for c in value if getattr(c, "name", "NONE") != "NONE"]
            elif name == "Columns":
                records[name] = [w for w in value if w]
            elif isinstance(value, (int, str)):
                records[name] = value
            else:
                records[name] = repr(value)[:200]
        info["records"] = records
    except Exception as exc:  # noqa: BLE001
        info["parser_error"] = repr(exc)
    return info


def main(argv: list[str]) -> int:
    out = Path(argv[1])
    fixture_dir = Path(argv[2])
    pmc_dir = Path(argv[3])
    fixture_dir.mkdir(parents=True, exist_ok=True)
    facts = {
        "runner": load_json(out / "runner.json"),
        "procmon": load_json(out / "procmon-version.json"),
        "runs": load_json(out / "runs.json"),
        "registry_after_run": load_json(out / "registry-after-run.json"),
        "csv_exports": {p.name: summarize_csv(p, fixture_dir) for p in sorted(out.glob("*.csv"))},
        "xml_exports": {p.name: summarize_xml(p, fixture_dir) for p in sorted(out.glob("*.xml"))},
        "pml_files": {p.name: summarize_pml(p) for p in sorted(out.glob("*.pml"))},
        "committed_pmc": {p.name: summarize_pmc(p) for p in sorted(pmc_dir.glob("*.pmc"))},
    }
    (fixture_dir / "facts.json").write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
    for name in ("runner.json", "procmon-version.json", "runs.json", "registry-after-run.json", "harness.log"):
        src = out / name
        if src.exists():
            (fixture_dir / name).write_bytes(src.read_bytes())
    print(json.dumps({k: (list(v.keys()) if isinstance(v, dict) else type(v).__name__) for k, v in facts.items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
