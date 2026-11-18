#!/usr/bin/env python3
"""Decode a config-snapshot bundle into its typed tables.

See docs/contracts/decoded-tables.md sections 5.7 to 5.9. The collector
(``collectors/windows/config-snapshot.ps1``) writes nineteen sources; this
decoder reads the primary artifact of every source that is ``observed`` or
``observed_zero`` and writes three tables:

=====================  ==================================================  ===================
Table                  Sources                                             Provenance
=====================  ==================================================  ===================
``config_snapshot``    interrupt_policy, graphics_tdr, processors,          ``index:<n>``,
                       cpu_caches, power_active_scheme, power_settings,     ``line:<n>``,
                       power_settings_hidden, power_aliases, processes,     ``offset:0``
                       timer_helper_process, process_lasso_install,
                       process_lasso_config, process_lasso_log,
                       stutter_guard_install, stutter_guard_journal
``powercfg``           power_active_scheme, power_schemes, power_aliases,   ``line:<n>``,
                       power_settings, power_settings_hidden                ``line:<a>-<b>``
``process_inventory``  processes                                            ``index:<n>``
=====================  ==================================================  ===================

A table whose sources were all unreadable is reported ``not_collected`` and
not written: an absent input is never decoded into an empty table. The three
sources the collector records ``not_collected`` by design (the logical
processor map, the power mode, the timer resolution) produce no row: a status
is never turned into evidence.

Registry values are decoded only where Microsoft documents their meaning
(``DevicePolicy`` by IRQ_DEVICE_POLICY, ``AssignmentSetOverride`` as a
KAFFINITY mask, ``MSISupported``, ``MessageNumberLimit``, the TDR values);
every other value present under those keys is kept verbatim with its type and
bytes and ``documented_by`` null. A mask names logical processors of a group
by bit position, as Microsoft defines KAFFINITY; it says which processors the
policy asks for, never which processor services the interrupt, which only a
trace can show.

powercfg output is localized. Scheme, subgroup and setting lines are found by
the GUID they carry and their indentation; the AC and DC index lines by their
English label when present, else by the shape and order of the two hex lines
(``classified_by`` says which); names in parentheses are kept verbatim.

Usage::

    python scripts/decode_config_snapshot.py --bundle <bundle directory> [--decoded-at 2026-09-03T00:00:00Z]
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

DECODER = "decode_config_snapshot"
DECODER_VERSION = "1.0.0"
OBSERVED = ("observed", "observed_zero")
SCENARIO = "config_snapshot"
TOOL = {"name": "collectors/windows config-snapshot (registry, Win32_Processor, Win32_CacheMemory, Win32_Process, powercfg, file and folder reads)", "version": None}

TABLE_SOURCES = {
    "config_snapshot": ["interrupt_policy", "graphics_tdr", "processors", "cpu_caches", "power_active_scheme", "power_settings",
                        "power_settings_hidden", "power_aliases", "processes", "timer_helper_process", "process_lasso_install",
                        "process_lasso_config", "process_lasso_log", "stutter_guard_install", "stutter_guard_journal"],
    "powercfg": ["power_active_scheme", "power_schemes", "power_aliases", "power_settings", "power_settings_hidden"],
    "process_inventory": ["processes"],
}

# Microsoft documentation the decoded readings rest on.
DOC_AFFINITY = "https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority"
DOC_POLICY = "https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_irq_device_policy"
DOC_MSI = "https://learn.microsoft.com/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry"
DOC_TDR = "https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys"
DOC_PROCESSOR = "https://learn.microsoft.com/windows/win32/cimwin32prov/win32-processor"
DOC_CACHE = "https://learn.microsoft.com/windows/win32/cimwin32prov/win32-cachememory"
DOC_GROUPS = "https://learn.microsoft.com/windows/win32/procthread/processor-groups"
DOC_POWERCFG = "https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options"
DOC_SLIDER = "https://learn.microsoft.com/windows-hardware/customize/desktop/customize-power-slider"
DOC_PROCESS = "https://learn.microsoft.com/windows/win32/cimwin32prov/win32-process"
DOC_LASSO_COMPONENTS = "https://bitsum.com/apps/process-lasso/docs/getting-started/how-it-works/"

# IRQ_DEVICE_POLICY (wdm.h), and the TDR enumerations, as Microsoft lists them.
IRQ_DEVICE_POLICY = {0: "IrqPolicyMachineDefault", 1: "IrqPolicyAllCloseProcessors", 2: "IrqPolicyOneCloseProcessor",
                     3: "IrqPolicyAllProcessorsInMachine", 4: "IrqPolicySpecifiedProcessors",
                     5: "IrqPolicySpreadMessagesAcrossAllProcessors", 6: "IrqPolicyAllProcessorsInMachineWhenSteered"}
TDR_LEVEL = {0: "TdrLevelOff", 1: "TdrLevelBugcheck", 2: "TdrLevelRecoverVGA", 3: "TdrLevelRecover"}
TDR_DEBUG_MODE = {0: "TDR_DEBUG_MODE_OFF", 1: "TDR_DEBUG_MODE_IGNORE_TIMEOUT", 2: "TDR_DEBUG_MODE_RECOVER_NO_PROMPT", 3: "TDR_DEBUG_MODE_RECOVER_UNCONDITIONAL"}
TDR_VALUES = ("TdrLevel", "TdrDelay", "TdrDdiDelay", "TdrDebugMode", "TdrLimitTime", "TdrLimitCount", "TdrTestMode")
# The values Microsoft documents under each Interrupt Management subkey; anything else present is kept verbatim.
AFFINITY_SUBKEY = "Interrupt Management\\Affinity Policy"
MSI_SUBKEY = "Interrupt Management\\MessageSignaledInterruptProperties"
DOCUMENTED_VALUES = {AFFINITY_SUBKEY: ("DevicePolicy", "AssignmentSetOverride"), MSI_SUBKEY: ("MSISupported", "MessageNumberLimit")}

# Win32_CacheMemory enumerations (Level, CacheType, Associativity).
CACHE_LEVEL = {1: "Other", 2: "Unknown", 3: "Primary", 4: "Secondary", 5: "Tertiary", 6: "Not Applicable"}
CACHE_TYPE = {1: "Other", 2: "Unknown", 3: "Instruction", 4: "Data", 5: "Unified"}
CACHE_ASSOCIATIVITY = {1: "Other", 2: "Unknown", 3: "Direct Mapped", 4: "2-way Set-Associative", 5: "4-way Set-Associative",
                       6: "Fully Associative", 7: "8-way Set-Associative", 8: "16-way Set-Associative"}

# The two power mode overlays whose GUIDs are not also a power scheme (the Better Performance overlay shares the Balanced scheme's GUID).
OVERLAYS = {"961cc777-2547-4f9d-8174-7d86181b8a7a": "better_battery", "ded574b5-45a0-4f42-8737-46345c09c238": "best_performance"}
BALANCED_GUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
# Processor power settings whose aliases Microsoft documents, and the category each belongs to.
PROCESSOR_ALIASES = {
    "PROCTHROTTLEMIN": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-perf-state-engine-minperformance"),
    "PROCTHROTTLEMAX": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-perf-state-engine-maxperformance"),
    "PERFBOOSTMODE": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfboostmode"),
    "PERFBOOSTPOL": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/legacy-config-options-perfboostpol"),
    "PERFEPP": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-perf-state-engine-perfepp"),
    "IDLEDISABLE": ("processor_power", "https://learn.microsoft.com/windows-hardware/customize/power-settings/configure-processor-power-management-options"),
    "CPMINCORES": ("core_parking", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-core-parking-cpmincores"),
    "CPMAXCORES": ("core_parking", "https://learn.microsoft.com/windows-hardware/customize/power-settings/options-for-core-parking-cpmaxcores"),
}
# Process Lasso components as the vendor names them.
LASSO_COMPONENTS = {"processlasso.exe": "gui", "processgovernor.exe": "governor", "bitsumsessionagent.exe": "session_agent"}
TIMER_HELPER = "dpctimerres.exe"

RE_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
RE_HEX = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
RE_INDEX = re.compile(r"^\d{3}$")
RE_PARENS = re.compile(r"\(([^()]*)\)\s*(\*?)\s*$")

LABEL_AC = "current ac power setting index"
LABEL_DC = "current dc power setting index"
LABEL_MIN = "minimum possible setting"
LABEL_MAX = "maximum possible setting"
LABEL_UNITS = "possible settings units"
LABEL_ALIAS = "guid alias"
LABEL_INDEX = "possible setting index"
LABEL_FRIENDLY = "possible setting friendly name"


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------- bundle access

def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc
    if manifest.get("scenario", {}).get("id") != SCENARIO:
        raise DecodeError(f"the bundle's scenario is {manifest.get('scenario', {}).get('id')!r}, not {SCENARIO}")
    return manifest


def source_entries(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in manifest["collectors"]}


def primary_of(entry: dict[str, Any]) -> str | None:
    primaries = [a["path"] for a in entry["artifacts"] if a["role"] == "primary"]
    return primaries[0] if primaries else None


def read_primary(bundle: Path, entry: dict[str, Any]) -> tuple[str, Path]:
    """The primary artifact of an observed source: a normalised path inside the bundle, present on disk."""
    source = primary_of(entry)
    if source is None:
        raise DecodeError(f"{entry['id']}: observed but without a primary artifact")
    parts = source.split("/")
    if "\\" in source or not source.startswith("raw/") or any(p in ("", ".", "..") for p in parts):
        raise DecodeError(f"{source}: not a normalised path under raw/")
    target = (bundle / source).resolve()
    if bundle.resolve() not in target.parents:
        raise DecodeError(f"{source}: resolves outside the bundle")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")
    return source, target


def read_json(path: Path, source: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc


def read_json_array(path: Path, source: str) -> list[Any]:
    data = read_json(path, source)
    if not isinstance(data, list):
        raise DecodeError(f"{source}: the export is not a JSON array")
    return data


def read_lines(path: Path, source: str) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    except (OSError, UnicodeDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc


def captured_at(entry: dict[str, Any]) -> str:
    rng = entry.get("raw_time_range") or {}
    return rng.get("start") or entry["started_utc"]


def provenance(table: str, source: str, ref: str, schema_version: str) -> dict[str, str]:
    return {"source_file": source, "row_id_or_offset": ref, "decoded_table": table, "decoder_version": DECODER_VERSION, "schema_version": schema_version}


# ---------------------------------------------------------------- config_snapshot rows

def snapshot_row(category: str, key: str, value_text: str, source_command: str, when: str, prov: dict[str, str], **extra: Any) -> dict[str, Any]:
    row = {"category": category, "key": key, "value_text": value_text, "source_command": source_command, "captured_at_utc": when, "provenance": prov}
    for name in ("value_number", "device_instance_id", "device_name", "registry_path", "present", "registry_value_kind", "raw_bytes_hex",
                 "decoded", "documented_by", "device_status", "device_problem_code", "source_id"):
        row[name] = extra.get(name)
    return row


def mask_from_value(kind: str | None, data: Any, bytes_hex: str | None) -> int | None:
    """A KAFFINITY mask from the value as the registry holds it: binary bytes are little endian; the numeric kinds are numbers."""
    if kind == "Binary" and bytes_hex:
        return int.from_bytes(bytes.fromhex(bytes_hex), "little")
    if kind in ("DWord", "QWord") and isinstance(data, int) and not isinstance(data, bool):
        return data
    if kind in ("DWord", "QWord") and isinstance(data, str) and data.isdigit():
        return int(data)
    return None


def processors_in(mask: int) -> list[int]:
    return [bit for bit in range(mask.bit_length()) if mask >> bit & 1]


def decode_registry_value(subkey: str, value: dict[str, Any]) -> tuple[str, float | None, dict[str, Any] | None, str | None]:
    """value_text, value_number, decoded and documented_by for one value present under an Interrupt Management subkey."""
    name, kind, data, bytes_hex = value.get("name"), value.get("kind"), value.get("data"), value.get("bytes_hex")
    number = data if isinstance(data, (int, float)) and not isinstance(data, bool) else None
    if subkey == AFFINITY_SUBKEY and name == "DevicePolicy":
        policy = IRQ_DEVICE_POLICY.get(data) if isinstance(data, int) else None
        return f"{data} ({policy or 'value not in IRQ_DEVICE_POLICY'})", number, {"policy": policy, "value": data}, DOC_POLICY
    if subkey == AFFINITY_SUBKEY and name == "AssignmentSetOverride":
        mask = mask_from_value(kind, data, bytes_hex)
        if mask is None:
            return f"{data} (kind {kind}, not a mask the documentation allows)", None, {"mask": None, "kind": kind}, DOC_AFFINITY
        cpus = processors_in(mask)
        decoded = {"mask_hex": hex(mask), "processors": cpus, "kind": kind, "byte_order": "little endian" if kind == "Binary" else "numeric",
                   "note": "bit i names logical processor i of the device's group; the group is not recorded here and the mask is the requested set, not the processor that services the interrupt"}
        return f"{hex(mask)} (processors {', '.join(str(c) for c in cpus) or 'none'})", float(mask), decoded, DOC_AFFINITY
    if subkey == MSI_SUBKEY and name == "MSISupported":
        enabled = data == 1
        return f"{data} ({'MSI enabled in configuration' if enabled else 'MSI not enabled in configuration'})", number, {"msi_enabled_in_configuration": enabled, "note": "configuration, not the active message mode or routing"}, DOC_MSI
    if subkey == MSI_SUBKEY and name == "MessageNumberLimit":
        return str(data), number, {"message_number_limit": data}, DOC_MSI
    text = data if isinstance(data, str) else json.dumps(data) if data is not None else "null"
    return text, number, None, None


def decode_interrupt_policy(elements: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    for index, device in enumerate(elements):
        if not isinstance(device, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        common = {"device_instance_id": device.get("instance_id"), "device_name": device.get("name"), "device_status": device.get("status"),
                  "device_problem_code": device.get("problem_code"), "source_id": entry["id"]}
        state = device.get("hardware_key_state") or {}
        if device.get("registry_error"):
            rows.append(snapshot_row("interrupt_affinity", "interrupt_management_key", "unreadable: " + str(device["registry_error"]), command, when, prov,
                                     registry_path=device.get("hardware_key"), present=None, decoded={"error": device["registry_error"]}, documented_by=DOC_MSI, **common))
            continue
        subkeys = {k.get("subkey"): k for k in device.get("interrupt_keys") or [] if isinstance(k, dict)}
        has_im = any(k.get("exists") for k in subkeys.values()) or "Interrupt Management" in (state.get("subkeys") or [])
        rows.append(snapshot_row("interrupt_affinity", "interrupt_management_key", "present" if has_im else "absent", command, when, prov,
                                 registry_path=(device.get("hardware_key") or "") + "\\Interrupt Management", present=has_im,
                                 decoded={"hardware_key_exists": state.get("exists")}, documented_by=DOC_MSI, **common))
        for subkey, category, doc in ((AFFINITY_SUBKEY, "interrupt_affinity", DOC_AFFINITY), (MSI_SUBKEY, "msi_mode", DOC_MSI)):
            record = subkeys.get(subkey)
            path = (device.get("hardware_key") or "") + "\\" + subkey
            present_names = set()
            if record and record.get("exists") and not record.get("error_kind"):
                for value in record.get("values") or []:
                    name = value.get("name")
                    present_names.add(name)
                    text, number, decoded, documented = decode_registry_value(subkey, value)
                    rows.append(snapshot_row(category, name or "(default)", text, command, when, prov, value_number=number, registry_path=path, present=True,
                                             registry_value_kind=value.get("kind"), raw_bytes_hex=value.get("bytes_hex"), decoded=decoded, documented_by=documented, **common))
            elif record and record.get("error_kind"):
                rows.append(snapshot_row(category, "subkey", "unreadable: " + str(record.get("error")), command, when, prov, registry_path=path, present=None,
                                         decoded={"error": record.get("error")}, documented_by=doc, **common))
                continue
            for name in DOCUMENTED_VALUES[subkey]:
                if name not in present_names:
                    rows.append(snapshot_row(category, name, "absent", command, when, prov, registry_path=path, present=False, documented_by=doc, **common))
    return rows


def decode_graphics_tdr(elements: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    for index, record in enumerate(elements):
        if not isinstance(record, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        path = record.get("path")
        if record.get("error_kind"):
            rows.append(snapshot_row("tdr", "GraphicsDrivers", "unreadable: " + str(record.get("error")), command, when, prov, registry_path=path, present=None,
                                     decoded={"error": record.get("error")}, documented_by=DOC_TDR, source_id=entry["id"]))
            continue
        if not record.get("exists"):
            for name in TDR_VALUES:
                rows.append(snapshot_row("tdr", name, "absent (key absent)", command, when, prov, registry_path=path, present=False, documented_by=DOC_TDR, source_id=entry["id"]))
            continue
        for value in record.get("values") or []:
            name = value.get("name")
            if not value.get("present"):
                rows.append(snapshot_row("tdr", name, "absent (Windows default applies)", command, when, prov, registry_path=path, present=False, documented_by=DOC_TDR, source_id=entry["id"]))
                continue
            data = value.get("data")
            number = data if isinstance(data, (int, float)) and not isinstance(data, bool) else None
            decoded: dict[str, Any] | None = None
            text = str(data)
            if name == "TdrLevel" and isinstance(data, int):
                decoded = {"level": TDR_LEVEL.get(data)}
                text = f"{data} ({TDR_LEVEL.get(data) or 'value not documented'})"
            elif name == "TdrDebugMode" and isinstance(data, int):
                decoded = {"mode": TDR_DEBUG_MODE.get(data)}
                text = f"{data} ({TDR_DEBUG_MODE.get(data) or 'value not documented'})"
            elif name in ("TdrDelay", "TdrDdiDelay", "TdrLimitTime") and isinstance(data, int):
                decoded = {"seconds": data}
            elif name == "TdrLimitCount" and isinstance(data, int):
                decoded = {"count": data}
            rows.append(snapshot_row("tdr", name, text, command, when, prov, value_number=number, registry_path=path, present=True,
                                     registry_value_kind=value.get("kind"), raw_bytes_hex=value.get("bytes_hex"), decoded=decoded, documented_by=DOC_TDR, source_id=entry["id"]))
    return rows


def as_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return float(value) if "." in value else int(value)
        except ValueError:
            return None
    return None


def decode_processors(records: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    fields = {"Name": "name", "Manufacturer": "manufacturer", "SocketDesignation": "socket", "NumberOfCores": "number_of_cores",
              "NumberOfEnabledCore": "number_of_enabled_cores", "NumberOfLogicalProcessors": "number_of_logical_processors", "ThreadCount": "thread_count",
              "L2CacheSize": "l2_cache_kb", "L3CacheSize": "l3_cache_kb", "MaxClockSpeed": "max_clock_mhz", "CurrentClockSpeed": "current_clock_mhz",
              "ProcessorId": "processor_id", "Status": "status"}
    total_logical = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        device = record.get("DeviceID")
        for prop, key in fields.items():
            value = record.get(prop)
            if value is None:
                continue
            rows.append(snapshot_row("cpu_topology", key, str(value), command, when, prov, value_number=as_number(value), device_instance_id=device,
                                     device_name=record.get("Name"), present=True, documented_by=DOC_PROCESSOR, source_id=entry["id"]))
        cores, logical = as_number(record.get("NumberOfCores")), as_number(record.get("NumberOfLogicalProcessors"))
        if cores is not None and logical is not None:
            total_logical += int(logical)
            smt = logical > cores
            rows.append(snapshot_row("cpu_topology", "smt_enabled", "true" if smt else "false", command, when, prov, value_number=1 if smt else 0, device_instance_id=device,
                                     device_name=record.get("Name"), present=True,
                                     decoded={"rule": "NumberOfCores is less than NumberOfLogicalProcessors when hyperthreading is enabled (Win32_Processor remarks)",
                                              "logical_per_core": (logical / cores) if cores else None,
                                              "note": "which logical processors are siblings is not recorded; see the logical_processor_map source"},
                                     documented_by=DOC_PROCESSOR, source_id=entry["id"]))
    if records:
        prov = provenance("config_snapshot", source, "index:0", schema_version)
        if 0 < total_logical < 64:
            rows.append(snapshot_row("cpu_topology", "processor_groups", "1", command, when, prov, value_number=1, present=True,
                                     decoded={"groups": [0], "rule": "systems with fewer than 64 logical processors always have a single group, Group 0", "logical_processors": total_logical},
                                     documented_by=DOC_GROUPS, source_id=entry["id"]))
        else:
            rows.append(snapshot_row("cpu_topology", "processor_groups", "unknown", command, when, prov, present=None,
                                     decoded={"logical_processors": total_logical, "note": "64 or more logical processors; the group layout needs GetLogicalProcessorInformationEx"},
                                     documented_by=DOC_GROUPS, source_id=entry["id"]))
    return rows


def decode_caches(records: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        level = record.get("Level")
        size = as_number(record.get("InstalledSize"))
        decoded = {"level": CACHE_LEVEL.get(level) if isinstance(level, int) else None, "type": CACHE_TYPE.get(record.get("CacheType")),
                   "associativity": CACHE_ASSOCIATIVITY.get(record.get("Associativity")), "installed_kb": size, "purpose": record.get("Purpose"),
                   "note": "Win32_CacheMemory describes each cache, not which logical processors share it"}
        text = f"{record.get('Purpose') or record.get('DeviceID')}: {decoded['level']}, {decoded['type']}, {size} KB"
        rows.append(snapshot_row("cpu_topology", "cache", text, command, when, prov, value_number=size, device_instance_id=record.get("DeviceID"), present=True,
                                 decoded=decoded, documented_by=DOC_CACHE, source_id=entry["id"]))
    return rows


# ---------------------------------------------------------------- powercfg

def guid_in(line: str) -> str | None:
    m = RE_GUID.search(line)
    return m.group(0).lower() if m else None


def label_value(line: str) -> tuple[str, str]:
    colon = line.find(":")
    if colon < 0:
        return "", line.strip()
    return line[:colon].strip().lower(), line[colon + 1:].strip()


def name_in_parens(line: str) -> tuple[str | None, bool]:
    m = RE_PARENS.search(line)
    if not m:
        return None, line.rstrip().endswith("*")
    return m.group(1).strip(), m.group(2) == "*"


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def power_row(kind: str, command: str, when: str, prov: dict[str, str], **extra: Any) -> dict[str, Any]:
    row = {"kind": kind, "command": command, "captured_at_utc": when, "provenance": prov}
    for name in ("scheme_guid", "scheme_name", "subgroup_guid", "subgroup_name", "setting_guid", "setting_name", "ac_value_hex", "dc_value_hex",
                 "possible_values", "unit", "request_type", "requester", "requester_type", "reason", "report_path", "is_active", "alias", "hidden",
                 "classified_by", "min_value_hex", "max_value_hex", "overlay", "source_id"):
        row[name] = extra.get(name)
    return row


def decode_scheme_listing(lines: list[str], source: str, entry: dict[str, Any], schema_version: str, from_active: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    for number, line in enumerate(lines, start=1):
        guid = guid_in(line)
        if not guid:
            continue
        name, starred = name_in_parens(line)
        rows.append(power_row("scheme", command, when, provenance("powercfg", source, f"line:{number}", schema_version), scheme_guid=guid, scheme_name=name,
                              is_active=True if from_active else starred, overlay=OVERLAYS.get(guid), source_id=entry["id"]))
    return rows


def decode_aliases(lines: list[str], source: str, entry: dict[str, Any], schema_version: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    rows: list[dict[str, Any]] = []
    aliases: dict[str, str] = {}
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    subgroup: str | None = None
    for number, line in enumerate(lines, start=1):
        guid = guid_in(line)
        if not guid:
            continue
        alias = line.split()[-1] if line.split() else None
        if alias and RE_GUID.fullmatch(alias):
            alias = None
        aliases[guid] = alias or ""
        prov = provenance("powercfg", source, f"line:{number}", schema_version)
        if indent_of(line) == 0 and alias and alias.upper().startswith("SCHEME_"):
            rows.append(power_row("alias", command, when, prov, scheme_guid=guid, alias=alias, source_id=entry["id"]))
        elif indent_of(line) == 0:
            subgroup = guid
            rows.append(power_row("alias", command, when, prov, subgroup_guid=guid, alias=alias, source_id=entry["id"]))
        else:
            rows.append(power_row("alias", command, when, prov, subgroup_guid=subgroup, setting_guid=guid, alias=alias, source_id=entry["id"]))
    return rows, aliases


def decode_query(lines: list[str], source: str, entry: dict[str, Any], schema_version: str, aliases: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Setting rows and the scheme header of a /query or /qh listing.

    Structure, language independent: the first GUID line is the scheme, a GUID line indented less than a setting but more than the scheme is a
    subgroup, deeper GUID lines are settings. Inside a setting the lines until the next GUID line carry the alias, the possible values and the
    two current indices. Labels are matched in English when they are English; otherwise the two hex index lines after the possible values
    are taken as AC then DC in the order powercfg prints them, and classified_by says so.
    """
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    guid_lines = [(n, line) for n, line in enumerate(lines, start=1) if guid_in(line)]
    if not guid_lines:
        return rows, {}
    header_number, header_line = guid_lines[0]
    scheme_guid = guid_in(header_line)
    scheme_name, _ = name_in_parens(header_line)
    scheme_indent = indent_of(header_line)
    header = {"scheme_guid": scheme_guid, "scheme_name": scheme_name, "line": header_number}
    rows.append(power_row("scheme", command, when, provenance("powercfg", source, f"line:{header_number}", schema_version), scheme_guid=scheme_guid,
                          scheme_name=scheme_name, is_active=True, alias=aliases.get(scheme_guid) or None, overlay=OVERLAYS.get(scheme_guid), source_id=entry["id"]))
    indents = sorted({indent_of(line) for _, line in guid_lines[1:]})
    subgroup_indent = indents[0] if indents else None
    subgroup_guid = subgroup_name = None
    for position, (number, line) in enumerate(guid_lines[1:], start=1):
        guid = guid_in(line)
        name, _ = name_in_parens(line)
        if indent_of(line) == subgroup_indent and indent_of(line) > scheme_indent and len(indents) > 1:
            subgroup_guid, subgroup_name = guid, name
            continue
        # A setting: its block runs to the line before the next GUID line.
        end = guid_lines[position + 1][0] - 1 if position + 1 < len(guid_lines) else len(lines)
        block = lines[number:end]
        setting: dict[str, Any] = {"alias": aliases.get(guid) or None, "ac": None, "dc": None, "min": None, "max": None, "unit": None, "possible": [], "classified": None}
        hex_lines: list[tuple[str, str]] = []
        pending_index: str | None = None
        for raw in block:
            label, value = label_value(raw)
            if not raw.strip():
                continue
            if label == LABEL_ALIAS or (not setting["alias"] and label.replace("-", " ").startswith("guid") and "alias" in label):
                setting["alias"] = value
                continue
            if RE_HEX.match(value):
                if label == LABEL_AC:
                    setting["ac"], setting["classified"] = value.lower(), "label"
                elif label == LABEL_DC:
                    setting["dc"], setting["classified"] = value.lower(), "label"
                elif label == LABEL_MIN:
                    setting["min"] = value.lower()
                elif label == LABEL_MAX:
                    setting["max"] = value.lower()
                else:
                    hex_lines.append((label, value.lower()))
                continue
            if label == LABEL_INDEX or (RE_INDEX.match(value) and "index" in label):
                pending_index = value
                continue
            if RE_INDEX.match(value):
                pending_index = value
                continue
            if label == LABEL_FRIENDLY or pending_index is not None:
                setting["possible"].append(f"{pending_index}: {value}" if pending_index is not None else value)
                pending_index = None
                continue
            if label == LABEL_UNITS or value == "%":
                setting["unit"] = value
        if setting["ac"] is None and setting["dc"] is None and hex_lines:
            # Labels in another language: the index lines are the ones printed less indented than the possible settings, i.e. after them.
            # powercfg prints the minimum, maximum and increment first, then the current AC and DC indices, so the last two hex lines are AC, DC.
            if len(hex_lines) >= 2:
                setting["ac"], setting["dc"], setting["classified"] = hex_lines[-2][1], hex_lines[-1][1], "value"
                rest = [v for _, v in hex_lines[:-2]]
                if len(rest) >= 2:
                    setting["min"], setting["max"] = rest[0], rest[1]
        rows.append(power_row("setting", command, when, provenance("powercfg", source, f"line:{number}-{end}", schema_version), scheme_guid=scheme_guid,
                              scheme_name=scheme_name, subgroup_guid=subgroup_guid, subgroup_name=subgroup_name, setting_guid=guid, setting_name=name,
                              ac_value_hex=setting["ac"], dc_value_hex=setting["dc"], possible_values=setting["possible"] or None, unit=setting["unit"],
                              alias=setting["alias"], classified_by=setting["classified"], min_value_hex=setting["min"], max_value_hex=setting["max"],
                              hidden=False if entry["id"] == "power_settings" else None, source_id=entry["id"]))
    return rows, header


def hex_to_int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def power_snapshot_rows(powercfg_rows: list[dict[str, Any]], headers: dict[str, dict[str, Any]], entries: dict[str, dict[str, Any]], schema_version: str) -> list[dict[str, Any]]:
    """config_snapshot rows derived from the powercfg tables: the active scheme, the overlay reading, and the documented processor settings."""
    rows: list[dict[str, Any]] = []
    active = [r for r in powercfg_rows if r["source_id"] == "power_active_scheme" and r["kind"] == "scheme"]
    if active:
        r = active[0]
        entry = entries["power_active_scheme"]
        prov = provenance("config_snapshot", r["provenance"]["source_file"], r["provenance"]["row_id_or_offset"], schema_version)
        rows.append(snapshot_row("power_scheme", "active_scheme_guid", r["scheme_guid"], " ".join(entry["command"] or []), captured_at(entry), prov, present=True,
                                 decoded={"name": r["scheme_name"], "overlay_guid": OVERLAYS.get(r["scheme_guid"])}, documented_by=DOC_POWERCFG, source_id="power_active_scheme"))
        header = headers.get("power_settings")
        if header and header.get("scheme_guid"):
            q = entries["power_settings"]
            qprov = provenance("config_snapshot", primary_of(q) or "", f"line:{header['line']}", schema_version)
            if header["scheme_guid"] == r["scheme_guid"]:
                text, present, overlay = "none evident: /query without arguments printed the active scheme's GUID", False, None
            else:
                overlay = OVERLAYS.get(header["scheme_guid"]) or ("better_performance (the GUID Microsoft lists for that overlay is the Balanced scheme's)" if header["scheme_guid"] == BALANCED_GUID else None)
                text, present = (overlay or f"unknown GUID {header['scheme_guid']}"), True
            rows.append(snapshot_row("power_scheme", "active_overlay", text, " ".join(q["command"] or []), captured_at(q), qprov, present=present,
                                     decoded={"query_header_guid": header["scheme_guid"], "active_scheme_guid": r["scheme_guid"], "overlay": overlay,
                                              "rule": "powercfg /q without a scheme argument enumerates the currently active overlay scheme when one is active, else the current power scheme (Microsoft); the reading compares the GUID it printed with /getactivescheme"},
                                     documented_by=DOC_POWERCFG + " ; " + DOC_SLIDER, source_id="power_settings"))
    seen: set[tuple[str, str]] = set()
    for r in powercfg_rows:
        if r["kind"] != "setting" or not r.get("alias"):
            continue
        alias = r["alias"].upper()
        if alias not in PROCESSOR_ALIASES or (alias, r["source_id"]) in seen:
            continue
        seen.add((alias, r["source_id"]))
        category, doc = PROCESSOR_ALIASES[alias]
        entry = entries[r["source_id"]]
        prov = provenance("config_snapshot", r["provenance"]["source_file"], r["provenance"]["row_id_or_offset"], schema_version)
        ac, dc = hex_to_int(r["ac_value_hex"]), hex_to_int(r["dc_value_hex"])
        rows.append(snapshot_row(category, alias.lower(), f"AC {r['ac_value_hex']}, DC {r['dc_value_hex']}", " ".join(entry["command"] or []), captured_at(entry), prov,
                                 value_number=ac, present=True,
                                 decoded={"ac": ac, "dc": dc, "unit": r["unit"], "possible_values": r["possible_values"], "setting_guid": r["setting_guid"],
                                          "classified_by": r["classified_by"], "listing": r["source_id"]},
                                 documented_by=doc, source_id=r["source_id"]))
    return rows


# ---------------------------------------------------------------- processes and third party tools

def decode_process_inventory(records: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    snapshot = (entry.get("requested") or {}).get("options", {}).get("snapshot") or "start"
    if snapshot not in ("start", "stop"):
        raise DecodeError(f"{source}: snapshot {snapshot!r} is neither start nor stop")
    when = captured_at(entry)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        pid = as_number(record.get("ProcessId"))
        if pid is None:
            raise DecodeError(f"{source}: element {index} has no ProcessId")
        kernel, user = as_number(record.get("KernelModeTime")), as_number(record.get("UserModeTime"))
        cpu = ((kernel or 0) + (user or 0)) / 1e7 if kernel is not None or user is not None else None
        rows.append({
            "snapshot": snapshot, "captured_at_utc": when, "pid": int(pid), "name": str(record.get("Name") or ""),
            "parent_pid": int(as_number(record.get("ParentProcessId"))) if as_number(record.get("ParentProcessId")) is not None else None,
            "image_path": record.get("ExecutablePath"), "command_line": record.get("CommandLine"), "priority_class": None, "affinity_mask_hex": None,
            "session_id": int(as_number(record.get("SessionId"))) if as_number(record.get("SessionId")) is not None else None,
            "start_time_utc": record.get("CreationDate"), "user": None, "cpu_time_s": cpu,
            "working_set_bytes": int(as_number(record.get("WorkingSetSize"))) if as_number(record.get("WorkingSetSize")) is not None else None,
            "handle_count": int(as_number(record.get("HandleCount"))) if as_number(record.get("HandleCount")) is not None else None,
            "thread_count": int(as_number(record.get("ThreadCount"))) if as_number(record.get("ThreadCount")) is not None else None,
            "base_priority": int(as_number(record.get("Priority"))) if as_number(record.get("Priority")) is not None else None,
            "page_faults": int(as_number(record.get("PageFaults"))) if as_number(record.get("PageFaults")) is not None else None,
            "source_id": entry["id"],
            "provenance": provenance("process_inventory", source, f"index:{index}", schema_version),
        })
    return rows


def decode_lasso_components(records: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    """Which Process Lasso components are running, by the executable names the vendor documents; process names only."""
    rows: list[dict[str, Any]] = []
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    found: dict[str, list[tuple[int, dict[str, Any]]]] = {name: [] for name in LASSO_COMPONENTS}
    for index, record in enumerate(records):
        if isinstance(record, dict) and str(record.get("Name") or "").lower() in found:
            found[str(record["Name"]).lower()].append((index, record))
    for exe, component in LASSO_COMPONENTS.items():
        matches = found[exe]
        if matches:
            index, record = matches[0]
            prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
            pids = [int(as_number(r.get("ProcessId")) or 0) for _, r in matches]
            rows.append(snapshot_row("process_lasso", f"running:{component}", f"{exe} running, pid {', '.join(str(p) for p in pids)}", command, when, prov, present=True,
                                     value_number=len(matches), decoded={"process": exe, "pids": pids, "session_ids": [r.get("SessionId") for _, r in matches],
                                                                         "created_utc": [r.get("CreationDate") for _, r in matches], "base_priority": [r.get("Priority") for _, r in matches]},
                                     documented_by=DOC_LASSO_COMPONENTS, source_id=entry["id"]))
        else:
            prov = provenance("config_snapshot", source, "offset:0", schema_version)
            rows.append(snapshot_row("process_lasso", f"running:{component}", f"{exe} not in the process list", command, when, prov, present=False, value_number=0,
                                     decoded={"process": exe}, documented_by=DOC_LASSO_COMPONENTS, source_id=entry["id"]))
    return rows


def decode_timer_helper(records: list[Any], source: str, entry: dict[str, Any], schema_version: str) -> list[dict[str, Any]]:
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    rows: list[dict[str, Any]] = []
    matches = [(i, r) for i, r in enumerate(records) if isinstance(r, dict) and str(r.get("Name") or "").lower() == TIMER_HELPER]
    if not matches:
        prov = provenance("config_snapshot", source, "offset:0", schema_version)
        rows.append(snapshot_row("stutter_guard", "timer_helper_running", f"{TIMER_HELPER} not in the process list", command, when, prov, present=False, value_number=0,
                                 decoded={"process": TIMER_HELPER, "note": "the helper requests a timer resolution while it runs; absent means no such request from it at this moment, and says nothing about other requesters"},
                                 documented_by=None, source_id=entry["id"]))
        return rows
    for index, record in matches:
        prov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        rows.append(snapshot_row("stutter_guard", "timer_helper_running", f"{TIMER_HELPER} running, pid {record.get('ProcessId')}", command, when, prov, present=True, value_number=1,
                                 decoded={"process": TIMER_HELPER, "pid": record.get("ProcessId"), "command_line": record.get("CommandLine"), "image_path": record.get("ExecutablePath"),
                                          "created_utc": record.get("CreationDate"), "session_id": record.get("SessionId"),
                                          "note": "the command line is what the process was started with (Win32_Process.CommandLine); null when the provider could not read it for another user's process"},
                                 documented_by=DOC_PROCESS, source_id=entry["id"]))
    return rows


def decode_install_listing(listing: Any, source: str, entry: dict[str, Any], schema_version: str, category: str) -> list[dict[str, Any]]:
    if not isinstance(listing, dict) or not isinstance(listing.get("files"), list):
        raise DecodeError(f"{source}: the listing is not an object with a files array")
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    rows: list[dict[str, Any]] = []
    prov = provenance("config_snapshot", source, "offset:0", schema_version)
    exists = bool(listing.get("exists"))
    rows.append(snapshot_row(category, "install_folder", str(listing.get("path")), command, when, prov, present=exists, value_number=len(listing["files"]),
                             decoded={"exists": exists, "file_count": len(listing["files"]), "truncated": listing.get("truncated"),
                                      "note": "the conventional install folder; a program installed elsewhere is not seen here"},
                             documented_by=None, source_id=entry["id"]))
    for index, file in enumerate(listing["files"]):
        if not isinstance(file, dict):
            raise DecodeError(f"{source}: files element {index} is not an object")
        fprov = provenance("config_snapshot", source, f"index:{index}", schema_version)
        version = file.get("file_version") or file.get("product_version")
        rows.append(snapshot_row(category, f"file:{file.get('name')}", version or "no version resource", command, when, fprov, present=True,
                                 decoded={"sha256": file.get("sha256"), "bytes": file.get("bytes"), "last_write_time_utc": file.get("last_write_time_utc"),
                                          "file_version": file.get("file_version"), "product_version": file.get("product_version"), "product_name": file.get("product_name"),
                                          "company_name": file.get("company_name"), "error": file.get("error")},
                                 documented_by=None, source_id=entry["id"]))
    return rows


def decode_copied_file(bundle: Path, source: str, entry: dict[str, Any], schema_version: str, category: str, key: str) -> list[dict[str, Any]]:
    """One row for a copied text file: its presence, the hash of the original, and whether the copy is verbatim (from result.json)."""
    command = " ".join(entry["command"] or [])
    when = captured_at(entry)
    report_path = [a["path"] for a in entry["artifacts"] if a["role"] == "report"]
    report: dict[str, Any] = {}
    if report_path and (bundle / report_path[0]).is_file():
        loaded = read_json(bundle / report_path[0], report_path[0])
        if isinstance(loaded, dict):
            report = loaded
    size = next((a["bytes"] for a in entry["artifacts"] if a["path"] == source), None)
    prov = provenance("config_snapshot", source, f"offset:0;len:{size}" if size is not None else "offset:0", schema_version)
    return [snapshot_row(category, key, str(report.get("path") or source), command, when, prov, present=True, value_number=report.get("source_bytes"),
                         decoded={"source_sha256": report.get("source_sha256"), "source_bytes": report.get("source_bytes"), "last_write_time_utc": report.get("last_write_time_utc"),
                                  "copy_is_verbatim": report.get("copy_is_verbatim"), "protection": report.get("protection"), "source_encoding": report.get("source_encoding")},
                         documented_by=None, source_id=entry["id"])]


# ---------------------------------------------------------------- tables

def time_range(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    starts = [e["raw_time_range"]["start"] for e in entries if e.get("raw_time_range")]
    ends = [e["raw_time_range"]["end"] for e in entries if e.get("raw_time_range")]
    if not starts:
        return None
    return {"start": min(starts), "end": max(ends), "domain": "system_time", "unit": "iso_utc"}


def write_table(bundle: Path, table: str, rows: list[dict[str, Any]], sources: list[str], entries: list[dict[str, Any]], checks: list[dict[str, Any]],
                status: str, reason: str | None, decoded_at: str) -> dict[str, Any]:
    schema_version = wf_schema.table_schema_version(table)
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{table}.jsonl", rows)
    meta = {
        "decoded_table": table, "schema_version": schema_version, "decoder": DECODER, "decoder_version": DECODER_VERSION, "tool": TOOL,
        "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows), "time_domain": "system_time", "native_time_range": time_range(entries) if rows else None,
        "status": status, "status_reason": reason, "checks": checks, "decoded_at_utc": decoded_at,
    }
    errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {errors}")
    wf_schema.write_json(decoded_dir / f"{table}.meta.json", meta)
    return {"status": status, "reason": reason, "rows": len(rows), "sources": len(sources)}


def finish_table(bundle: Path, table: str, rows: list[dict[str, Any]], sources: list[str], observed: dict[str, dict[str, Any]], checks: list[dict[str, Any]],
                 status: str, reason: str | None, decoded_at: str, nothing_observed: str) -> dict[str, Any]:
    """Write the table and its sidecar, or report why not.

    A table none of whose sources was observed is not_collected and not written. A decode that failed before every source was read still
    writes its sidecar (empty rows, status decode_failed) naming the observed primaries that exist on disk, so the failure is visible in the
    bundle; when not one of them exists, nothing can be named honestly and nothing is written.
    """
    expected = [sid for sid in TABLE_SOURCES[table] if sid in observed]
    if not expected:
        return {"status": "not_collected", "reason": nothing_observed, "rows": 0, "sources": 0}
    if status == "decode_failed":
        on_disk = [primary_of(observed[sid]) for sid in expected if primary_of(observed[sid]) and (bundle / (primary_of(observed[sid]) or "")).is_file()]
        if not on_disk:
            return {"status": "decode_failed", "reason": reason, "rows": 0, "sources": 0}
        return write_table(bundle, table, [], [s for s in on_disk if s], [observed[s] for s in expected], checks, status, reason, decoded_at)
    return write_table(bundle, table, rows, sources, [observed[s] for s in expected], checks, status, reason, decoded_at)


def decode(bundle: Path, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        manifest = load_manifest(bundle)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "tables": {}}
    entries = source_entries(manifest)
    observed = {sid: e for sid, e in entries.items() if e["status"] in OBSERVED}
    results: dict[str, Any] = {}
    versions = {t: wf_schema.table_schema_version(t) for t in TABLE_SOURCES}

    # powercfg first: the config_snapshot power rows derive from its rows.
    power_rows: list[dict[str, Any]] = []
    power_sources: list[str] = []
    power_checks: list[dict[str, Any]] = []
    power_status, power_reason = "observed", None
    headers: dict[str, dict[str, Any]] = {}
    aliases: dict[str, str] = {}
    try:
        if "power_aliases" in observed:
            source, path = read_primary(bundle, observed["power_aliases"])
            rows, aliases = decode_aliases(read_lines(path, source), source, observed["power_aliases"], versions["powercfg"])
            power_rows += rows
            power_sources.append(source)
            power_checks.append({"name": "power_aliases", "ok": True, "detail": f"{len(rows)} alias rows"})
        for sid in ("power_active_scheme", "power_schemes"):
            if sid in observed:
                source, path = read_primary(bundle, observed[sid])
                rows = decode_scheme_listing(read_lines(path, source), source, observed[sid], versions["powercfg"], from_active=(sid == "power_active_scheme"))
                power_rows += rows
                power_sources.append(source)
                power_checks.append({"name": sid, "ok": True, "detail": f"{len(rows)} scheme rows"})
        visible: set[str] = set()
        for sid in ("power_settings", "power_settings_hidden"):
            if sid in observed:
                source, path = read_primary(bundle, observed[sid])
                rows, header = decode_query(read_lines(path, source), source, observed[sid], versions["powercfg"], aliases)
                headers[sid] = header
                if sid == "power_settings":
                    visible = {r["setting_guid"] for r in rows if r["kind"] == "setting"}
                elif "power_settings" in observed:
                    for r in rows:
                        if r["kind"] == "setting":
                            r["hidden"] = r["setting_guid"] not in visible
                power_rows += rows
                power_sources.append(source)
                by_value = sum(1 for r in rows if r["kind"] == "setting" and r["classified_by"] == "value")
                power_checks.append({"name": sid, "ok": True, "detail": f"{len(rows)} rows, {by_value} settings classified by value order"})
        errors = wf_schema.validate_rows(power_rows, "decoded/powercfg.schema.json")
        power_checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            power_status, power_reason, power_rows = "decode_failed", "; ".join(errors[:3]), []
        elif power_sources and not power_rows:
            power_status, power_reason = "observed_zero", "every powercfg listing is empty"
    except DecodeError as exc:
        power_status, power_reason, power_rows = "decode_failed", str(exc), []
        power_checks.append({"name": "read", "ok": False, "detail": str(exc)})
    results["powercfg"] = finish_table(bundle, "powercfg", power_rows, power_sources, observed, power_checks, power_status, power_reason, decoded_at,
                                       "no powercfg listing was observed")

    # process_inventory
    if "processes" in observed:
        try:
            source, path = read_primary(bundle, observed["processes"])
            rows = decode_process_inventory(read_json_array(path, source), source, observed["processes"], versions["process_inventory"])
            errors = wf_schema.validate_rows(rows, "decoded/process_inventory.schema.json")
            checks = [{"name": "processes", "ok": True, "detail": f"{len(rows)} processes, snapshot {rows[0]['snapshot'] if rows else 'n/a'}"},
                      {"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None}]
            status, reason = ("decode_failed", "; ".join(errors[:3])) if errors else ("observed", None) if rows else ("observed_zero", "the process list is empty")
            results["process_inventory"] = write_table(bundle, "process_inventory", rows if not errors else [], [source], [observed["processes"]], checks, status, reason, decoded_at)
        except DecodeError as exc:
            results["process_inventory"] = write_table(bundle, "process_inventory", [], [primary_of(observed["processes"]) or ""], [observed["processes"]],
                                                       [{"name": "read", "ok": False, "detail": str(exc)}], "decode_failed", str(exc), decoded_at) if primary_of(observed["processes"]) else {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}
    else:
        results["process_inventory"] = {"status": "not_collected", "reason": "the processes source was not observed", "rows": 0, "sources": 0}

    # config_snapshot
    rows: list[dict[str, Any]] = []
    sources: list[str] = []
    checks: list[dict[str, Any]] = []
    status, reason = "observed", None
    decoders = {
        "interrupt_policy": lambda s, p, e: decode_interrupt_policy(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "graphics_tdr": lambda s, p, e: decode_graphics_tdr(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "processors": lambda s, p, e: decode_processors(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "cpu_caches": lambda s, p, e: decode_caches(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "processes": lambda s, p, e: decode_lasso_components(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "timer_helper_process": lambda s, p, e: decode_timer_helper(read_json_array(p, s), s, e, versions["config_snapshot"]),
        "process_lasso_install": lambda s, p, e: decode_install_listing(read_json(p, s), s, e, versions["config_snapshot"], "process_lasso"),
        "stutter_guard_install": lambda s, p, e: decode_install_listing(read_json(p, s), s, e, versions["config_snapshot"], "stutter_guard"),
        "process_lasso_config": lambda s, p, e: decode_copied_file(bundle, s, e, versions["config_snapshot"], "process_lasso", "config_copied"),
        "process_lasso_log": lambda s, p, e: decode_copied_file(bundle, s, e, versions["config_snapshot"], "process_lasso", "log_copied"),
        "stutter_guard_journal": lambda s, p, e: decode_copied_file(bundle, s, e, versions["config_snapshot"], "stutter_guard", "journal_copied"),
    }
    try:
        for sid, fn in decoders.items():
            if sid not in observed:
                continue
            source, path = read_primary(bundle, observed[sid])
            produced = fn(source, path, observed[sid])
            rows += produced
            sources.append(source)
            checks.append({"name": sid, "ok": True, "detail": f"{len(produced)} rows"})
        if power_status in OBSERVED and power_rows:
            derived = power_snapshot_rows(power_rows, headers, entries, versions["config_snapshot"])
            rows += derived
            for sid in ("power_active_scheme", "power_settings", "power_settings_hidden"):
                if sid in observed and primary_of(observed[sid]) not in sources and any(r["source_id"] == sid for r in derived):
                    sources.append(primary_of(observed[sid]) or "")
            checks.append({"name": "power_rows", "ok": True, "detail": f"{len(derived)} rows derived from the powercfg table"})
        for sid in ("logical_processor_map", "power_mode", "timer_resolution"):
            if sid in entries:
                checks.append({"name": sid, "ok": True, "detail": f"status {entries[sid]['status']}: no row, a status is never turned into evidence"})
        errors = wf_schema.validate_rows(rows, "decoded/config_snapshot.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
        elif sources and not rows:
            status, reason = "observed_zero", "every source was empty"
    except DecodeError as exc:
        status, reason, rows = "decode_failed", str(exc), []
        checks.append({"name": "read", "ok": False, "detail": str(exc)})
    results["config_snapshot"] = finish_table(bundle, "config_snapshot", rows, sources, observed, checks, status, reason, decoded_at,
                                              "no config-snapshot source was observed")
    worst = "observed"
    for r in results.values():
        if r["status"] == "decode_failed":
            worst = "decode_failed"
        elif r["status"] == "not_collected" and worst != "decode_failed":
            worst = "not_collected"
    return {"status": worst, "reason": "; ".join(f"{t}: {r['reason']}" for t, r in results.items() if r["status"] not in OBSERVED) or None, "tables": results}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.decoded_at)
    for table, r in result["tables"].items():
        print(f"{table}: {r['rows']} rows from {r['sources']} sources, status {r['status']}")
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
