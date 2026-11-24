#!/usr/bin/env python3
"""Decode a connection-quality session into the ``net_quality`` and ``net_quality_bursts`` tables.

See docs/contracts/decoded-tables.md sections 5.21 and 5.22. The
``connection-quality`` collector runs a bounded session on the PC with one
slot per second on the performance counter and writes one samples file per
source, ``raw/<source>/samples.jsonl`` (the primary artifact), beside its
``command.json`` (config) and ``result.json`` (report):

- ``gateway_probes``: an ICMP echo to the default gateway (label ``gateway``)
  every slot and an A query sent to it every 10 slots;
- ``public_probes``: an echo to ``cloudflare`` and ``google`` in the same slot
  and an A query sent to ``cloudflare`` every 10 slots;
- ``link_state``: the adapter behind the default route every 10 slots and at
  the stop, with whether the preferred default route is still the one the
  session started on.

Every probe line carries ``qpc_before``, ``filetime_utc_100ns`` and
``qpc_after`` (the timestamp contract's order) read right before the probe
was sent and ``qpc_done`` read right after it completed, so a row sits on the
``etw_qpc`` master clock without calibration. A slot the session reached more
than one interval late is a ``missed`` line: a sampling gap, never a loss.

``net_quality`` has one row per probe line. ``net_quality_bursts`` has one row
per run of consecutive lines of one target and probe that failed (``loss_burst``
for echoes, ``dns_failure_burst`` for queries, ``link_down`` for readings that
were not connected and up), whose outcome is unknown (``probe_unknown``,
``link_unknown``), whose default route had changed (``route_changed``), and one
per run of consecutive missed lines of a source (``sampling_gap``). The table
sidecars carry the per target summary.

The decoder refuses (``decode_failed``) a bundle whose samples differ from
the manifest's checksums, whose lines are not exactly the shapes the collector
writes, carry a target the source does not probe, are out of order or carry a
string shaped like a network or hardware address, or whose counts disagree with
``result.json``. It decodes the sources that are ``observed``; a bundle with
none has nothing to decode, and the decoder reports ``not_collected`` and
writes nothing.

Usage::

    python scripts/decode_net_quality.py --bundle <bundle directory> [--decoded-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402
from decode_rf_survey import MEDIA_CONNECT_STATE, OPERATIONAL_STATUS  # noqa: E402

DECODER = "decode_net_quality"
DECODER_VERSION = "0.1.0"
TABLES = ("net_quality", "net_quality_bursts")
TOOL = {"name": "connection-quality collector samples (Ping.SendPingAsync, Resolve-DnsName, MSFT_NetAdapter)", "version": None}
HUNDRED_NS_PER_SECOND = 10_000_000
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# What each source probes: probe kind -> the target labels it may carry (None for the link reading).
SOURCES: dict[str, dict[str, set[str] | None]] = {
    "gateway_probes": {"ping": {"gateway"}, "dns": {"gateway"}},
    "public_probes": {"ping": {"cloudflare", "google"}, "dns": {"cloudflare"}},
    "link_state": {"link": None},
}
STAMP = ["slot_qpc", "qpc_before", "filetime_utc_100ns", "qpc_after", "qpc_done"]
KEYS = {
    "ping": ["seq", "kind", "target"] + STAMP + ["status", "rtt_ms", "error_type"],
    "dns": ["seq", "kind", "target"] + STAMP + ["status", "answer_records", "error_type", "error_id", "error_code"],
    "link": ["seq", "kind"] + STAMP + ["status", "media_connect_state", "operational_status", "receive_link_speed_bps",
                                       "transmit_link_speed_bps", "physical_medium", "route_same", "error_type"],
    "missed": ["seq", "kind", "slot_qpc", "seen_qpc"],
}
# IPStatus member names: https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipstatus
IP_STATUS = {"Success", "DestinationNetworkUnreachable", "DestinationHostUnreachable", "DestinationProtocolUnreachable", "DestinationProhibited",
             "DestinationPortUnreachable", "NoResources", "BadOption", "HardwareError", "PacketTooBig", "TimedOut", "BadRoute", "TtlExpired",
             "TtlReassemblyTimeExceeded", "ParameterProblem", "SourceQuench", "BadDestination", "DestinationUnreachable", "TimeExceeded",
             "BadHeader", "UnrecognizedNextHeader", "IcmpError", "DestinationScopeMismatch", "Unknown"}
PING_UNKNOWN = {"error", "not_completed"}
DNS_STATUS = {"answered", "failed"}
LINK_STATUS = {"read", "not_found", "error"}
# NdisPhysicalMedium: https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
PHYSICAL_MEDIUM = {0: "Unspecified", 1: "Wireless LAN", 2: "Cable Modem", 3: "Phone Line", 4: "Power Line", 5: "DSL", 6: "FC", 7: "1394",
                   8: "Wireless WAN", 9: "Native 802.11", 10: "BlueTooth", 11: "Infiniband", 12: "WiMAX", 13: "UWB", 14: "802.3", 15: "802.5",
                   16: "IRDA", 17: "Wired WAN", 18: "Wired Connection Oriented WAN", 19: "Other"}
TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+`]{0,200}$")
ERROR_ID = re.compile(r"^[A-Za-z0-9_]{1,64},Microsoft\.DnsClient\.Commands\.ResolveDnsName$")
# Strings shaped like an address must never reach a decoded table (the collector never writes one).
ADDRESS_SHAPES = (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), re.compile(r"\b([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b"),
                  re.compile(r"\b[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{0,4}){2,7}\b"))


class DecodeError(Exception):
    pass


def filetime_to_iso(filetime_100ns: int) -> str:
    when = FILETIME_EPOCH + timedelta(microseconds=filetime_100ns // 10)
    fraction = filetime_100ns % HUNDRED_NS_PER_SECOND
    return when.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:07d}Z"


def half_width_100ns(qpc_before: int, qpc_after: int, frequency_hz: int) -> int:
    """timestamps.md section 3: half the bracket plus one tick, in 100 ns, rounded up."""
    return math.ceil((Fraction(qpc_after - qpc_before, 2) + 1) * HUNDRED_NS_PER_SECOND / frequency_hz)


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc


def observed_sources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for collector in manifest.get("collectors", []):
        if collector.get("id") in SOURCES and collector.get("status") == "observed":
            out.append(collector)
    return out


def artifact(bundle: Path, collector: dict[str, Any], name: str, role: str) -> str:
    """The bundle relative path of one of the source's artifacts, checked against its manifest checksum."""
    path = f"raw/{collector['id']}/{name}"
    listed = [a for a in collector.get("artifacts", []) if a.get("path") == path]
    if len(listed) != 1 or listed[0].get("role") != role:
        raise DecodeError(f"collector {collector['id']}: expected {path} listed once with role {role}")
    target = bundle / path
    if not target.is_file():
        raise DecodeError(f"{path}: listed in the manifest but missing from the bundle")
    if wf_schema.sha256_of(target) != listed[0].get("sha256"):
        raise DecodeError(f"{path}: its SHA-256 differs from the manifest")
    return path


def check_no_address(value: Any, where: str) -> None:
    if isinstance(value, str):
        for shape in ADDRESS_SHAPES:
            if shape.search(value):
                raise DecodeError(f"{where}: a value shaped like a network or hardware address; the collector never writes one")


def check_line(raw: Any, source_id: str, slots: int, where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DecodeError(f"{where}: not a JSON object")
    kind = raw.get("kind")
    if kind not in KEYS or (kind != "missed" and kind not in SOURCES[source_id]):
        raise DecodeError(f"{where}: kind {kind!r} is not one source {source_id} writes")
    if list(raw) != KEYS[kind]:
        raise DecodeError(f"{where}: keys {list(raw)} differ from the {kind} line the collector writes")
    for value in raw.values():
        check_no_address(value, where)
    seq = raw["seq"]
    if not is_int(seq) or seq < 0 or seq > slots or (seq == slots and kind != "link"):
        raise DecodeError(f"{where}: seq {seq!r} outside the session's {slots} slots")
    if kind == "missed":
        if not (is_int(raw["slot_qpc"]) and is_int(raw["seen_qpc"]) and raw["seen_qpc"] > raw["slot_qpc"]):
            raise DecodeError(f"{where}: a missed line must carry the slot and a later counter reading")
        return raw
    if not all(is_int(raw[k]) for k in STAMP):
        raise DecodeError(f"{where}: the counter and file time stamps must be integers")
    if not (raw["slot_qpc"] <= raw["qpc_before"] <= raw["qpc_after"] <= raw["qpc_done"]) or raw["filetime_utc_100ns"] < 0:
        raise DecodeError(f"{where}: the stamps are not in the order slot, before, after, done")
    if kind in ("ping", "dns") and raw["target"] not in SOURCES[source_id][kind]:
        raise DecodeError(f"{where}: target {raw['target']!r} is not one source {source_id} probes with {kind}")
    if raw["error_type"] is not None and not (isinstance(raw["error_type"], str) and TYPE_NAME.match(raw["error_type"])):
        raise DecodeError(f"{where}: error_type is not a type name")
    status = raw["status"]
    if kind == "ping":
        if status not in IP_STATUS and status not in PING_UNKNOWN:
            raise DecodeError(f"{where}: status {status!r} is neither an IPStatus name nor error or not_completed")
        if (status == "Success") != (is_int(raw["rtt_ms"]) and raw["rtt_ms"] >= 0) or (status != "Success" and raw["rtt_ms"] is not None):
            raise DecodeError(f"{where}: rtt_ms is kept for Success only, as a whole number of milliseconds")
        if (status == "error") != (raw["error_type"] is not None):
            raise DecodeError(f"{where}: an error carries its exception type and nothing else does")
    elif kind == "dns":
        if status not in DNS_STATUS:
            raise DecodeError(f"{where}: status {status!r} is not answered or failed")
        answered = status == "answered"
        if answered != (is_int(raw["answer_records"]) and raw["answer_records"] >= 0) or (not answered and raw["answer_records"] is not None):
            raise DecodeError(f"{where}: answer_records is kept for an answered query only")
        if answered and any(raw[k] is not None for k in ("error_type", "error_id", "error_code")):
            raise DecodeError(f"{where}: an answered query carries no error")
        if raw["error_id"] is not None and raw["error_id"] != "withheld" and not ERROR_ID.match(str(raw["error_id"])):
            raise DecodeError(f"{where}: error_id is neither withheld nor a Resolve-DnsName error id")
        if raw["error_code"] is not None and not is_int(raw["error_code"]):
            raise DecodeError(f"{where}: error_code is not an integer")
    else:
        if status not in LINK_STATUS:
            raise DecodeError(f"{where}: status {status!r} is not read, not_found or error")
        values = ("media_connect_state", "operational_status", "receive_link_speed_bps", "transmit_link_speed_bps", "physical_medium")
        if any(raw[k] is not None and not (is_int(raw[k]) and raw[k] >= 0) for k in values):
            raise DecodeError(f"{where}: the adapter values are non negative integers or null")
        if status != "read" and any(raw[k] is not None for k in values):
            raise DecodeError(f"{where}: a reading that was not read carries no adapter value")
        if (status == "error") != (raw["error_type"] is not None):
            raise DecodeError(f"{where}: an error carries its exception type and nothing else does")
        if raw["route_same"] not in (True, False, None):
            raise DecodeError(f"{where}: route_same is true, false or null")
    return raw


def read_lines(bundle: Path, path: str, source_id: str, slots: int) -> list[tuple[int, dict[str, Any]]]:
    out = []
    try:
        text = (bundle / path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"{path}: {exc}") from exc
    if text and not text.endswith("\n"):
        raise DecodeError(f"{path}: the last line is cut short")
    last_seq = -1
    for number, line in enumerate(text.split("\n")[:-1] if text else [], start=1):
        where = f"{path} line {number}"
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DecodeError(f"{where}: {exc}") from exc
        checked = check_line(raw, source_id, slots, where)
        if checked["seq"] < last_seq:
            raise DecodeError(f"{where}: seq {checked['seq']} after seq {last_seq}; the collector writes slots in order")
        last_seq = checked["seq"]
        out.append((number, checked))
    return out


def ok_of(line: dict[str, Any]) -> bool | None:
    kind, status = line["kind"], line["status"]
    if kind == "ping":
        return True if status == "Success" else (None if status in PING_UNKNOWN else False)
    if kind == "dns":
        return status == "answered"
    if status != "read" or line["media_connect_state"] is None or line["operational_status"] is None:
        return None
    return line["media_connect_state"] == 1 and line["operational_status"] == 1


def to_row(line: dict[str, Any], number: int, source_id: str, path: str, frequency_hz: int, schema_version: str) -> dict[str, Any]:
    kind = line["kind"]
    get = line.get
    media, oper, medium = get("media_connect_state"), get("operational_status"), get("physical_medium")
    return {
        "source_id": source_id,
        "probe": kind,
        "target": get("target"),
        "seq": line["seq"],
        "slot_qpc": line["slot_qpc"],
        "qpc_before": line["qpc_before"],
        "qpc_after": line["qpc_after"],
        "qpc_done": line["qpc_done"],
        "filetime_utc_100ns": line["filetime_utc_100ns"],
        "time_utc": filetime_to_iso(line["filetime_utc_100ns"]),
        "qpc_mid": (line["qpc_before"] + line["qpc_after"]) // 2,
        "half_width_100ns": half_width_100ns(line["qpc_before"], line["qpc_after"], frequency_hz),
        "elapsed_ms": round((line["qpc_done"] - line["qpc_after"]) * 1000 / frequency_hz, 3),
        "status": line["status"],
        "ok": ok_of(line),
        "rtt_ms": get("rtt_ms"),
        "answer_records": get("answer_records"),
        "error_type": get("error_type"),
        "error_id": get("error_id"),
        "error_code": get("error_code"),
        "media_connect_state": media,
        "media_connect_state_text": MEDIA_CONNECT_STATE.get(media) if media is not None else None,
        "operational_status": oper,
        "operational_status_text": OPERATIONAL_STATUS.get(oper) if oper is not None else None,
        "receive_link_speed_bps": get("receive_link_speed_bps"),
        "transmit_link_speed_bps": get("transmit_link_speed_bps"),
        "physical_medium": medium,
        "physical_medium_text": PHYSICAL_MEDIUM.get(medium) if medium is not None else None,
        "route_same": get("route_same"),
        "provenance": {"source_file": path, "row_id_or_offset": f"line:{number}", "decoded_table": "net_quality",
                       "decoder_version": DECODER_VERSION, "schema_version": schema_version},
    }


def burst_condition(line: dict[str, Any]) -> list[str]:
    """The burst kinds a probe line belongs to (a link reading can be down and on a changed route at once)."""
    ok = ok_of(line)
    kind = line["kind"]
    out = []
    if kind == "ping":
        out.append("loss_burst" if ok is False else "probe_unknown" if ok is None else "")
    elif kind == "dns":
        out.append("dns_failure_burst" if ok is False else "")
    else:
        out.append("link_down" if ok is False else "link_unknown" if ok is None else "")
        if line["route_same"] is False:
            out.append("route_changed")
    return [c for c in out if c]


def burst_rows(lines: list[tuple[int, dict[str, Any]]], source_id: str, path: str, schema_version: str) -> list[dict[str, Any]]:
    """Runs of consecutive lines of one probe and target with the same condition, and runs of consecutive missed lines."""
    rows: list[dict[str, Any]] = []

    def emit(kind: str, probe: str | None, target: str | None, run: list[tuple[int, dict[str, Any]]]) -> None:
        first, last = run[0][1], run[-1][1]
        missed = kind == "sampling_gap"
        rows.append({
            "kind": kind, "source_id": source_id, "probe": probe, "target": target,
            "first_seq": first["seq"], "last_seq": last["seq"], "count": len(run),
            "qpc_start": first["slot_qpc"] if missed else first["qpc_before"],
            "qpc_end": last["seen_qpc"] if missed else last["qpc_done"],
            "start_utc": None if missed else filetime_to_iso(first["filetime_utc_100ns"]),
            "end_utc": None if missed else filetime_to_iso(last["filetime_utc_100ns"]),
            "provenance": {"source_file": path, "row_id_or_offset": ";".join(f"line:{n}" for n, _ in run), "decoded_table": "net_quality_bursts",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })

    # Sampling gaps: consecutive missed lines of the file.
    run: list[tuple[int, dict[str, Any]]] = []
    for number, line in lines + [(0, {"kind": "end"})]:
        if line["kind"] == "missed":
            run.append((number, line))
            continue
        if run:
            emit("sampling_gap", None, None, run)
            run = []
    # Conditions per probe and target, over that series' own lines in file order.
    series: dict[tuple[str, str | None], list[tuple[int, dict[str, Any]]]] = {}
    for number, line in lines:
        if line["kind"] != "missed":
            series.setdefault((line["kind"], line.get("target")), []).append((number, line))
    for (probe, target), items in series.items():
        for condition in ("loss_burst", "probe_unknown", "dns_failure_burst", "link_down", "link_unknown", "route_changed"):
            run = []
            for number, line in items + [(0, None)]:
                if line is not None and condition in burst_condition(line):
                    run.append((number, line))
                    continue
                if run:
                    emit(condition, probe, target, run)
                    run = []
    rows.sort(key=lambda r: (r["qpc_start"], r["kind"], r["target"] or ""))
    return rows


def percentile(values: list[int], p: float) -> int:
    """Nearest rank percentile."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p / 100 * len(ordered)) - 1)]


def summary_checks(rows: list[dict[str, Any]], bursts: list[dict[str, Any]], results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    checks = []
    keys: list[tuple[str, str, str | None]] = []
    for row in rows:
        key = (row["source_id"], row["probe"], row["target"])
        if key not in keys:
            keys.append(key)
    for source_id, probe, target in keys:
        series = [r for r in rows if (r["source_id"], r["probe"], r["target"]) == (source_id, probe, target)]
        good = sum(1 for r in series if r["ok"] is True)
        bad = sum(1 for r in series if r["ok"] is False)
        unknown = sum(1 for r in series if r["ok"] is None)
        known = good + bad
        share = f"{100 * bad / known:.1f} %" if known else "n/a"
        if probe == "ping":
            rtts = [r["rtt_ms"] for r in series if r["rtt_ms"] is not None]
            extra = f"; round trip p50 {percentile(rtts, 50)} ms, p95 {percentile(rtts, 95)} ms, max {max(rtts)} ms" if rtts else "; no reply"
            detail = f"{len(series)} echoes: {good} answered, {bad} not answered ({share} of those with a known outcome), {unknown} unknown{extra}"
        elif probe == "dns":
            times = [r["elapsed_ms"] for r in series if r["ok"] is True]
            extra = f"; answer time (upper bound) median {sorted(times)[(len(times) - 1) // 2]} ms, max {max(times)} ms" if times else ""
            detail = f"{len(series)} queries: {good} answered, {bad} failed ({share}){extra}"
        else:
            speeds = sorted({r["receive_link_speed_bps"] for r in series if r["receive_link_speed_bps"] is not None})
            changed = sum(1 for r in series if r["route_same"] is False)
            detail = (f"{len(series)} readings: {good} connected and up, {bad} not, {unknown} unknown; receive link speeds seen {speeds} bit/s; "
                      f"default route changed at {changed} readings")
        checks.append({"name": f"summary:{source_id}:{probe}:{target or 'adapter'}", "ok": bad == 0 and unknown == 0, "detail": detail})
    gaps = [b for b in bursts if b["kind"] == "sampling_gap"]
    for source_id, result in results.items():
        source_gaps = [b for b in gaps if b["source_id"] == source_id]
        checks.append({"name": f"sampling:{source_id}", "ok": not source_gaps,
                       "detail": f"{result['slots_taken']} of {result['slots']} slots taken; missed lines {sum(b['count'] for b in source_gaps)} in {len(source_gaps)} gap(s)"
                                 + (f", longest {max(b['count'] for b in source_gaps)}" if source_gaps else "")
                                 + "; a missed slot is a sampling gap, not a loss"})
    losses = [b for b in bursts if b["kind"] in ("loss_burst", "dns_failure_burst", "link_down")]
    checks.append({"name": "bursts", "ok": not losses,
                   "detail": ", ".join(f"{k} {sum(1 for b in bursts if b['kind'] == k)}" for k in
                                       ("loss_burst", "dns_failure_burst", "link_down", "probe_unknown", "link_unknown", "route_changed", "sampling_gap"))
                             + (f"; longest loss burst {max(b['count'] for b in losses if b['kind'] == 'loss_burst')} echoes"
                                if any(b["kind"] == "loss_burst" for b in losses) else "")})
    return checks


def check_result(result: dict[str, Any], lines: list[tuple[int, dict[str, Any]]], path: str) -> None:
    probes = sum(1 for _, line in lines if line["kind"] != "missed")
    missed = [line["seq"] for _, line in lines if line["kind"] == "missed"]
    if result.get("status") != "observed" or result.get("samples_kept") is not True:
        raise DecodeError(f"{path}: the result record does not say the samples were kept from an observed session")
    if result.get("lines") != len(lines) or result.get("probes") != probes or result.get("missed_seqs") != missed:
        raise DecodeError(f"{path}: {len(lines)} lines, {probes} probes and missed slots {missed}; the result record says "
                          f"{result.get('lines')!r}, {result.get('probes')!r} and {result.get('missed_seqs')!r}")
    if result.get("failure") is not None:
        raise DecodeError(f"{path}: the result record names a failure in an observed session")


def remove_tables(bundle: Path) -> None:
    for table in TABLES:
        for suffix in (".jsonl", ".meta.json"):
            path = bundle / "decoded" / f"{table}{suffix}"
            if path.is_file():
                path.unlink()


def write_table(bundle: Path, table: str, rows: list[dict[str, Any]], sources: list[str], native_range: dict[str, Any] | None,
                checks: list[dict[str, Any]], status: str, reason: str | None, decoded_at: str) -> None:
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{table}.jsonl", rows)
    meta = {
        "decoded_table": table, "schema_version": wf_schema.table_schema_version(table), "decoder": DECODER, "decoder_version": DECODER_VERSION,
        "tool": TOOL, "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows), "time_domain": "etw_qpc" if rows or native_range else "none", "native_time_range": native_range,
        "status": status, "status_reason": reason, "checks": checks, "decoded_at_utc": decoded_at,
    }
    errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {errors}")
    wf_schema.write_json(decoded_dir / f"{table}.meta.json", meta)


def decode(bundle: Path, decoded_at: str | None = None) -> dict[str, dict[str, Any]]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        manifest = load_manifest(bundle)
        selected = observed_sources(manifest)
    except DecodeError as exc:
        return {t: {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0} for t in TABLES}
    if not selected:
        remove_tables(bundle)
        reason = "the bundle holds no observed connection-quality source to decode"
        return {t: {"status": "not_collected", "reason": reason, "rows": 0, "sources": 0} for t in TABLES}

    row_version = wf_schema.table_schema_version("net_quality")
    burst_version = wf_schema.table_schema_version("net_quality_bursts")
    rows: list[dict[str, Any]] = []
    bursts: list[dict[str, Any]] = []
    sources: list[str] = []
    results: dict[str, dict[str, Any]] = {}
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    try:
        for collector in selected:
            source_id = collector["id"]
            samples = artifact(bundle, collector, "samples.jsonl", "primary")
            result_path = artifact(bundle, collector, "result.json", "report")
            sources += [samples, result_path]
            try:
                result = json.loads((bundle / result_path).read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DecodeError(f"{result_path}: {exc}") from exc
            frequency = result.get("qpc_frequency_hz")
            calibrated = (manifest.get("calibration") or {}).get("qpc_frequency_hz")
            if not is_int(frequency) or frequency < 1 or (calibrated is not None and calibrated != frequency):
                raise DecodeError(f"{result_path}: qpc_frequency_hz {frequency!r} is not a positive integer equal to the manifest's {calibrated!r}")
            slots = result.get("slots")
            if not is_int(slots) or slots < 1:
                raise DecodeError(f"{result_path}: slots {slots!r} is not a positive integer")
            lines = read_lines(bundle, samples, source_id, slots)
            check_result(result, lines, samples)
            if not any(line["kind"] != "missed" for _, line in lines):
                raise DecodeError(f"{samples}: an observed source with no probe line; the collector never reports one")
            results[source_id] = result
            rows += [to_row(line, n, source_id, samples, frequency, row_version) for n, line in lines if line["kind"] != "missed"]
            bursts += burst_rows(lines, source_id, samples, burst_version)
        for table, table_rows in (("net_quality", rows), ("net_quality_bursts", bursts)):
            errors = wf_schema.validate_rows(table_rows, f"decoded/{table}.schema.json")
            if errors:
                raise DecodeError(f"{table} rows fail their schema: " + "; ".join(errors[:3]))
        checks = summary_checks(rows, bursts, results)
    except DecodeError as exc:
        status, reason, rows, bursts = "decode_failed", str(exc), [], []
        checks = [{"name": "samples_read", "ok": False, "detail": str(exc)}]
        if not sources:
            sources = [f"raw/{c['id']}/samples.jsonl" for c in selected if (bundle / f"raw/{c['id']}/samples.jsonl").is_file()]
        if not sources:
            remove_tables(bundle)
            return {t: {"status": status, "reason": reason, "rows": 0, "sources": 0} for t in TABLES}

    native_range = None
    if rows:
        stamps = sorted(r["time_utc"] for r in rows)
        native_range = {"start": stamps[0], "end": stamps[-1], "domain": "etw_qpc", "unit": "iso_utc_of_the_probe_process"}
    out = {}
    write_table(bundle, "net_quality", rows, sources, native_range, checks, status, reason, decoded_at)
    out["net_quality"] = {"status": status, "reason": reason, "rows": len(rows), "sources": len(sources)}
    burst_status, burst_reason = status, reason
    if status == "observed" and not bursts:
        burst_status, burst_reason = "observed_zero", "no loss, failure, link down, unknown outcome, route change or sampling gap in the observed sources"
    write_table(bundle, "net_quality_bursts", bursts, sources, native_range, checks, burst_status, burst_reason, decoded_at)
    out["net_quality_bursts"] = {"status": burst_status, "reason": burst_reason, "rows": len(bursts), "sources": len(sources)}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    results = decode(args.bundle, args.decoded_at)
    worst = 0
    for table in TABLES:
        result = results[table]
        print(f"{table}: {result['rows']} rows from {result['sources']} source files, status {result['status']}")
        if result["status"] not in ("observed", "observed_zero"):
            print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
            worst = 2
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
