#!/usr/bin/env python3
"""Decode an rf-survey bundle into its typed tables.

See docs/contracts/decoded-tables.md sections 5.12 to 5.16. The collector
(``collectors/windows/rf-survey.ps1``) writes ten sources; this decoder reads
the primary artifact of every source that is ``observed`` or
``observed_zero`` and writes five tables:

================  =========================================  ===================
Table             Sources                                    Provenance
================  =========================================  ===================
``netsh_fields``  wlan_interfaces, wlan_drivers, wlan_profiles  ``line:<n>``
``wlan_bss``      wlan_networks                              ``line:<a>-<b>``
``pnp_device``    usb_device_tree, bluetooth_devices         ``index:<n>``
``net_adapter``   net_adapters                               ``index:<n>``
``net_route``     default_routes                             ``index:<n>``
================  =========================================  ===================

A table whose sources were all unreadable is reported ``not_collected`` and
not written: an absent input is never decoded into an empty table. A primary
the manifest lists but the bundle lacks, or text the parser cannot follow, is
``decode_failed`` for that table.

The netsh outputs are localized. Labels are classified against an English
table; when a label is unknown the value's shape is used instead (an
``802.11x`` radio type, a ``GHz`` band, a percentage signal, a channel number
after the band line, a ``mac-``/``ssid-`` pseudonym, a GUID). The sidecar says
how many rows each path produced, so a bundle from a display language the
parser has not seen still decodes the numbers that matter and says what it
could not name. Network names and addresses are the collector's pseudonyms
and are copied as they are.

Usage::

    python scripts/decode_rf_survey.py --bundle <bundle directory> [--decoded-at 2026-09-03T00:00:00Z]
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

DECODER = "decode_rf_survey"
DECODER_VERSION = "1.0.0"
OBSERVED = ("observed", "observed_zero")
TOOL = {"name": "collectors/windows rf-survey (netsh wlan show, MSFT_NetAdapter, MSFT_NetRoute, Win32_PnPEntity)", "version": None}

TABLE_SOURCES = {
    "netsh_fields": ["wlan_interfaces", "wlan_drivers", "wlan_profiles"],
    "wlan_bss": ["wlan_networks"],
    "pnp_device": ["usb_device_tree", "bluetooth_devices"],
    "net_adapter": ["net_adapters"],
    "net_route": ["default_routes"],
}
COMMAND_OF_SOURCE = {"wlan_interfaces": "interfaces", "wlan_drivers": "drivers", "wlan_profiles": "profiles"}

RE_MAC_PSEUDONYM = re.compile(r"^mac-[0-9a-f]{12}$")
RE_SSID_PSEUDONYM = re.compile(r"^ssid-[0-9a-f]{12}$")
RE_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$")
RE_RADIO = re.compile(r"^802\.11[a-z]*$")
RE_RADIO_LIST = re.compile(r"^(802\.11[a-z]*)(\s+802\.11[a-z]*)+$")
RE_BAND = re.compile(r"^(\d+(?:[.,]\d+)?)\s*GHz$", re.IGNORECASE)
RE_PERCENT = re.compile(r"^(\d{1,3})\s*%$")
RE_INTEGER = re.compile(r"^\d{1,4}$")
RE_NUMBER = re.compile(r"^\d+(?:[.,]\d+)?$")
RE_SSID_LABEL = re.compile(r"^SSID(?:\s+(\d+))?$", re.IGNORECASE)
RE_USB_IDS = re.compile(r"^USB\\VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)
RE_RECEIVER = re.compile(r"receiver|dongle|wireless|unifying|lightspeed|hyperspeed|slipstream", re.IGNORECASE)

# English labels, lower case, without the trailing colon.
LABELS_INTERFACES = {
    "name": "interface_name", "description": "description", "guid": "guid", "physical address": "physical_address",
    "interface type": "interface_type", "state": "state", "ssid": "ssid", "bssid": "bssid", "network type": "network_type",
    "radio type": "radio_type", "authentication": "authentication", "cipher": "cipher", "connection mode": "connection_mode",
    "band": "band", "channel": "channel", "receive rate (mbps)": "receive_rate_mbps", "transmit rate (mbps)": "transmit_rate_mbps",
    "signal": "signal_pct", "profile": "profile", "radio status": "radio_status", "hosted network status": "hosted_network_status",
}
LABELS_DRIVERS = {
    "interface name": "interface_name", "driver": "driver", "vendor": "vendor", "provider": "provider", "date": "driver_date",
    "version": "driver_version", "inf file": "inf_file", "type": "driver_type", "radio types supported": "radio_types_supported",
    "fips 140-2 mode supported": "fips_mode_supported", "802.11w management frame protection supported": "mfp_supported",
    "hosted network supported": "hosted_network_supported",
    "authentication and cipher supported in infrastructure mode": "auth_cipher_infrastructure",
    "ihv service present": "ihv_service_present", "ihv adapter oui": "ihv_adapter_oui", "ihv extensibility dll path": "ihv_dll_path",
    "ihv ui extensibility clsid": "ihv_ui_clsid", "ihv diagnostics clsid": "ihv_diagnostics_clsid",
    "wireless display supported": "wireless_display_supported",
}
LABELS_PROFILES = {"all user profile": "profile", "current user profile": "profile"}
LABELS_NETWORKS = {
    "network type": "network_type", "authentication": "authentication", "encryption": "encryption",
    "signal": "signal_pct", "radio type": "radio_type", "band": "band", "channel": "channel",
}

# Documented enumerations of MSFT_NetAdapter and MSFT_NetRoute:
# https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
# https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netroute
PHYSICAL_MEDIUM = {0: "Unspecified", 1: "Wireless LAN", 2: "Cable Modem", 3: "Phone Line", 4: "Power Line", 5: "DSL", 6: "FC", 7: "1394",
                   8: "Wireless WAN", 9: "Native 802.11", 10: "BlueTooth", 11: "Infiniband", 12: "WiMAX", 13: "UWB", 14: "802.3", 15: "802.5",
                   16: "IRDA", 17: "Wired WAN", 18: "Wired Connection Oriented WAN", 19: "Other"}
OPERATIONAL_STATUS = {1: "Up", 2: "Down", 3: "Testing", 4: "Unknown", 5: "Dormant", 6: "Not Present", 7: "Lower layer down"}
MEDIA_CONNECT_STATE = {0: "Unknown", 1: "Connected", 2: "Disconnected"}
PNP_STATE = {0: "Unknown", 1: "Present", 2: "Started", 3: "Disabled"}
ROUTE_PROTOCOL = {1: "Other", 2: "Local", 3: "NetMgmt", 4: "Icmp", 5: "Egp", 6: "Ggp", 7: "Hello", 8: "Rip", 9: "IsIs", 10: "EsIs", 11: "Igrp",
                  12: "Bbn", 13: "Ospf", 14: "Bgp", 15: "Idpr", 16: "Eigrp", 17: "Dvmrp", 18: "Rpl", 19: "Dhcp"}
ADDRESS_FAMILY = {2: "IPv4", 23: "IPv6"}
CONTROLLER_SERVICES = {"usbxhci": "usb3_xhci", "usbehci": "usb2_ehci", "usbohci": "usb1_ohci_uhci", "usbuhci": "usb1_ohci_uhci"}


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------- bundle access

def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc


def source_entries(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in manifest["collectors"]}


def primary_of(entry: dict[str, Any]) -> str | None:
    primaries = [a["path"] for a in entry["artifacts"] if a["role"] == "primary"]
    return primaries[0] if primaries else None


def read_primary(bundle: Path, entry: dict[str, Any]) -> tuple[str, Path]:
    """The primary artifact path of an observed source, checked to sit inside the bundle and exist."""
    source = primary_of(entry)
    if source is None:
        raise DecodeError(f"{entry['id']}: {entry['status']} but the manifest lists no primary artifact")
    if not source.startswith(f"raw/{entry['id']}/") or ".." in source.split("/"):
        raise DecodeError(f"{source}: not a normalised path under raw/{entry['id']}/")
    target = (bundle / source).resolve()
    if bundle.resolve() not in target.parents:
        raise DecodeError(f"{source}: resolves outside the bundle")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")
    return source, target


def read_json_array(path: Path, source: str) -> list[Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{source}: {exc}") from exc
    if not isinstance(data, list):
        raise DecodeError(f"{source}: the export is not a JSON array")
    return data


# ---------------------------------------------------------------- netsh text

def parse_number(text: str) -> float | None:
    if RE_NUMBER.match(text):
        return float(text.replace(",", "."))
    return None


def netsh_fields(text: str) -> list[dict[str, Any]]:
    """Every labelled line: 1-based line number, indentation, block, label, value (the collector's structure)."""
    out = []
    block = -1
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        colon = line.find(":")
        if colon < 0:
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent == 0:
            block += 1
        out.append({"line": number, "indent": indent, "block": max(block, 0), "label": line[:colon].strip(), "value": line[colon + 1:].strip()})
    return out


def classify_by_value(value: str, state: dict[str, Any]) -> tuple[str | None, float | None]:
    """A normalized key from the shape of a value, using what came before in the same block."""
    if RE_GUID.match(value):
        return "guid", None
    if RE_MAC_PSEUDONYM.match(value):
        return ("bssid" if state.get("last") == "ssid" else "physical_address"), None
    if RE_SSID_PSEUDONYM.match(value):
        return ("profile" if state.get("ssid_seen") else "ssid"), None
    if RE_RADIO_LIST.match(value):
        return "radio_types_supported", None
    if RE_RADIO.match(value):
        return "radio_type", None
    m = RE_BAND.match(value)
    if m:
        return "band", float(m.group(1).replace(",", "."))
    m = RE_PERCENT.match(value)
    if m:
        return "signal_pct", float(m.group(1))
    if RE_INTEGER.match(value) and state.get("last") in ("band", "radio_type"):
        return "channel", float(value)
    number = parse_number(value)
    if number is not None and state.get("last") == "channel":
        return "receive_rate_mbps", number
    if number is not None and state.get("last") == "receive_rate_mbps":
        return "transmit_rate_mbps", number
    return None, None


def decode_netsh_fields(text: str, command: str, source: str, schema_version: str,
                        profiles: dict[str, str] | None = None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    labels = {"interfaces": LABELS_INTERFACES, "drivers": LABELS_DRIVERS, "profiles": LABELS_PROFILES}[command]
    profiles = profiles or {}
    rows, counts = [], {"label": 0, "value": 0, "unclassified": 0}
    state: dict[str, Any] = {"block": -1}
    for field in netsh_fields(text):
        if field["block"] != state["block"]:
            state = {"block": field["block"], "last": None, "ssid_seen": False}
        key, number, how = None, None, None
        label = field["label"].lower()
        if label in labels:
            key, how = labels[label], "label"
            if key in ("signal_pct", "channel", "receive_rate_mbps", "transmit_rate_mbps", "band"):
                number = parse_number(field["value"].rstrip("%").strip().split(" ")[0]) if field["value"] else None
        elif field["value"]:
            key, number = classify_by_value(field["value"], state)
            how = "value" if key else None
        pseudonym = None
        if command == "profiles" and field["value"] in profiles:
            # Every name in a profile listing is a saved profile, whatever the label says;
            # the collector kept the owner's names readable and recorded their pseudonyms.
            key, how, pseudonym = "profile", (how or "value"), profiles[field["value"]]
        counts[how or "unclassified"] += 1
        if key == "ssid":
            state["ssid_seen"] = True
        if key:
            state["last"] = key
        rows.append({
            "command": command, "block": field["block"], "line": field["line"], "indent": field["indent"],
            "label_text": field["label"], "value_text": field["value"], "value_pseudonym": pseudonym, "normalized_key": key, "value_number": number,
            "classified_by": how,
            "provenance": {"source_file": source, "row_id_or_offset": f"line:{field['line']}", "decoded_table": "netsh_fields",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows, counts


# A convenience inference, used only when netsh prints no Band line (Windows 11
# prints one): channels 1 to 14 are the 2.4 GHz numbering, 36 to 165 the 5 GHz
# UNII-1 to UNII-3 channels Cisco lists for the 802.11 5 GHz band
# (https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/wireless-rf-reference-guide.html).
# 6 GHz reuses these numbers, so an inferred band is marked as such in the
# sidecar and a 6 GHz access point without a Band line would be misread as 5 GHz.
CHANNELS_24GHZ = range(1, 15)
CHANNELS_5GHZ = range(36, 166)


def band_from_channel(channel: int | None) -> float | None:
    """The convenience inference above; None when the number is outside both ranges."""
    if channel is None:
        return None
    if channel in CHANNELS_24GHZ:
        return 2.4
    if channel in CHANNELS_5GHZ:
        return 5
    return None


def decode_wlan_bss(text: str, source: str, schema_version: str, known_profiles: set[str] | None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """known_profiles: the pseudonyms of this PC's saved profiles, or None when they were not readable."""
    fields = netsh_fields(text)
    rows: list[dict[str, Any]] = []
    counts = {"networks": 0, "labels_recognised": 0, "band_inferred": 0}
    interface_name = next((f["value"] for f in fields if f["indent"] == 0 and f["value"]), None)
    blocks: dict[int, list[dict[str, Any]]] = {}
    for f in fields:
        blocks.setdefault(f["block"], []).append(f)
    running = 0
    for block_fields in blocks.values():
        head = block_fields[0]
        if head["indent"] != 0:
            continue
        has_mac = any(RE_MAC_PSEUDONYM.match(f["value"]) for f in block_fields[1:])
        m = RE_SSID_LABEL.match(head["label"])
        if not m and not has_mac:
            continue
        running += 1
        counts["networks"] += 1
        network_index = int(m.group(1)) if (m and m.group(1)) else running
        ssid = head["value"] if RE_SSID_PSEUDONYM.match(head["value"]) else None
        network: dict[str, Any] = {"network_type": None, "authentication": None, "encryption": None}
        bss_groups: list[list[dict[str, Any]]] = []
        for f in block_fields[1:]:
            if RE_MAC_PSEUDONYM.match(f["value"]):
                bss_groups.append([f])
            elif bss_groups:
                bss_groups[-1].append(f)
            else:
                key = LABELS_NETWORKS.get(f["label"].lower())
                if key in network:
                    network[key] = f["value"]
        for group in bss_groups:
            bssid_field = group[0]
            depth = None
            labels_hit = False
            signal = radio = band_text = channel = None
            band_ghz: float | None = None
            channel_source = None
            last = None
            for f in group[1:]:
                if depth is None:
                    depth = f["indent"]
                deeper = f["indent"] > depth
                key = LABELS_NETWORKS.get(f["label"].lower())
                if key in ("signal_pct", "radio_type", "band", "channel"):
                    labels_hit = True
                value = f["value"]
                if key == "signal_pct" or (key is None and RE_PERCENT.match(value) and not deeper):
                    pm = RE_PERCENT.match(value)
                    signal = int(pm.group(1)) if pm else None
                    last = "signal"
                elif key == "radio_type" or (key is None and RE_RADIO.match(value)):
                    radio = value
                    last = "radio"
                elif key == "band" or (key is None and RE_BAND.match(value)):
                    bm = RE_BAND.match(value)
                    band_text = value
                    band_ghz = float(bm.group(1).replace(",", ".")) if bm else None
                    last = "band"
                elif key == "channel" or (key is None and RE_INTEGER.match(value) and not deeper and last in ("band", "radio")):
                    channel = int(value)
                    channel_source = "label" if key == "channel" else "value"
                    last = "channel"
            if band_ghz is None and channel is not None:
                band_ghz = band_from_channel(channel)
                if band_ghz is not None:
                    counts["band_inferred"] += 1
            if band_ghz is not None and band_ghz not in (2.4, 5, 6):
                band_ghz = None
            if labels_hit:
                counts["labels_recognised"] += 1
            first_line, last_line = bssid_field["line"], group[-1]["line"]
            rows.append({
                "interface_name": interface_name, "network_index": network_index, "ssid_pseudonym": ssid,
                "bssid_pseudonym": bssid_field["value"], "signal_pct": signal,
                "signal_dbm_estimate": (-100 + signal / 2) if signal is not None else None,
                "radio_type": radio, "band_text": band_text, "band_ghz": band_ghz, "channel": channel, "channel_source": channel_source,
                "network_type": network["network_type"], "authentication": network["authentication"], "encryption": network["encryption"],
                "is_known_profile": (ssid in known_profiles) if (known_profiles is not None and ssid is not None) else None,
                "labels_recognised": labels_hit,
                "provenance": {"source_file": source, "row_id_or_offset": f"line:{first_line}-{last_line}", "decoded_table": "wlan_bss",
                               "decoder_version": DECODER_VERSION, "schema_version": schema_version},
            })
    return rows, counts


def profile_mapping(bundle: Path, entries: dict[str, dict[str, Any]]) -> dict[str, str] | None:
    """Saved profile name to pseudonym, from the wlan_profiles result artifact; None when the source was not readable."""
    entry = entries.get("wlan_profiles")
    if entry is None or entry["status"] not in OBSERVED:
        return None
    reports = [a["path"] for a in entry["artifacts"] if a["role"] == "report" and a["path"].endswith("/result.json")]
    if not reports:
        return None
    try:
        report = json.loads((bundle / reports[0]).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    out = {}
    listed = report.get("profiles") or []
    if isinstance(listed, dict):  # a one element list a PowerShell pipeline unrolled
        listed = [listed]
    for item in listed:
        if isinstance(item, dict) and item.get("name") and RE_SSID_PSEUDONYM.match(str(item.get("pseudonym") or "")):
            out[str(item["name"])] = str(item["pseudonym"])
    return out


# ---------------------------------------------------------------- devices, adapters, routes

def decode_pnp(records: list[Any], source: str, source_id: str, schema_version: str) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not record.get("instance_id"):
            raise DecodeError(f"{source}: element {index} is not a device with an instance_id")
        by_id[str(record["instance_id"]).upper()] = record

    def chain(record: dict[str, Any]) -> list[dict[str, Any]]:
        out, seen = [], set()
        current = record
        while True:
            parent = current.get("parent_instance_id")
            if not parent or parent.upper() in seen or parent.upper() not in by_id:
                return out
            seen.add(parent.upper())
            current = by_id[parent.upper()]
            out.append(current)

    rows = []
    for index, record in enumerate(records):
        instance = str(record["instance_id"])
        ancestors = chain(record)
        controller = next((a for a in ancestors if (a.get("service") or "").lower() in CONTROLLER_SERVICES
                           or ((a.get("class") or "").upper() == "USB" and instance_prefix(a) == "PCI")), None)
        if controller is None and (record.get("service") or "").lower() in CONTROLLER_SERVICES:
            controller = record
        controller_service = controller.get("service") if controller else None
        stack = None
        if controller is not None:
            stack = CONTROLLER_SERVICES.get((controller_service or "").lower(), "unknown")
        m = RE_USB_IDS.match(instance)
        names = " ".join(str(record.get(k) or "") for k in ("name", "description", "bus_reported_description"))
        klass = (record.get("class") or "")
        rows.append({
            "source_id": source_id, "instance_id": instance, "class": record.get("class"), "name": record.get("name"),
            "description": record.get("description"), "manufacturer": record.get("manufacturer"), "service": record.get("service"),
            "status": record.get("status"), "problem_code": record.get("problem_code"), "is_seed": bool(record.get("is_seed")),
            "parent_instance_id": record.get("parent_instance_id"),
            "location_path": (record.get("location_paths") or [None])[0], "location_info": record.get("location_info"),
            "bus_reported_description": record.get("bus_reported_description"),
            "vendor_id": m.group(1).upper() if m else None, "product_id": m.group(2).upper() if m else None,
            "controller_instance_id": controller.get("instance_id") if controller else None, "controller_service": controller_service,
            "usb_stack": stack, "hub_chain": [a["instance_id"] for a in ancestors],
            "is_root_hub": "ROOT_HUB" in instance.upper(),
            "is_receiver_candidate": bool(instance_prefix(record) == "USB" and klass.upper() != "BLUETOOTH" and RE_RECEIVER.search(names)),
            "is_bluetooth_radio": bool(klass.upper() == "BLUETOOTH" and instance_prefix(record) in ("USB", "PCI")),
            # A present BTHENUM or BTHLE node is a remembered peer; whether it is paired or connected is not measured.
            "is_bluetooth_peer_node": instance_prefix(record) in ("BTHENUM", "BTHLE"),
            "provenance": {"source_file": source, "row_id_or_offset": f"index:{index}", "decoded_table": "pnp_device",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


def instance_prefix(record: dict[str, Any]) -> str:
    return str(record.get("instance_id") or "").split("\\")[0].upper()


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def as_text(value: Any) -> str | None:
    return str(value) if value is not None else None


def decode_net_adapter(records: list[Any], source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    for index, r in enumerate(records):
        if not isinstance(r, dict):
            raise DecodeError(f"{source}: element {index} is not an object")
        medium, status, connect, state = as_int(r.get("NdisPhysicalMedium")), as_int(r.get("InterfaceOperationalStatus")), as_int(r.get("MediaConnectState")), as_int(r.get("State"))
        rows.append({
            "name": as_text(r.get("Name")), "interface_description": as_text(r.get("InterfaceDescription")),
            "interface_index": as_int(r.get("InterfaceIndex")), "interface_guid": as_text(r.get("InterfaceGuid")),
            "physical_medium": medium, "physical_medium_text": PHYSICAL_MEDIUM.get(medium) if medium is not None else None,
            "operational_status": status, "operational_status_text": OPERATIONAL_STATUS.get(status) if status is not None else None,
            "media_connect_state": connect, "media_connect_state_text": MEDIA_CONNECT_STATE.get(connect) if connect is not None else None,
            "pnp_state": state, "pnp_state_text": PNP_STATE.get(state) if state is not None else None,
            "status": as_text(r.get("Status")), "virtual": as_bool(r.get("Virtual")), "hidden": as_bool(r.get("Hidden")),
            "hardware_interface": as_bool(r.get("HardwareInterface")),
            "receive_link_speed_bps": as_int(r.get("ReceiveLinkSpeed")), "transmit_link_speed_bps": as_int(r.get("TransmitLinkSpeed")),
            "driver_description": as_text(r.get("DriverDescription")), "driver_version": as_text(r.get("DriverVersionString")),
            "driver_provider": as_text(r.get("DriverProvider")), "pnp_device_id": as_text(r.get("PnPDeviceID")),
            "provenance": {"source_file": source, "row_id_or_offset": f"index:{index}", "decoded_table": "net_adapter",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


def decode_net_route(records: list[Any], source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    for index, r in enumerate(records):
        if not isinstance(r, dict) or not r.get("DestinationPrefix"):
            raise DecodeError(f"{source}: element {index} is not a route with a DestinationPrefix")
        protocol, family = as_int(r.get("Protocol")), as_int(r.get("AddressFamily"))
        rows.append({
            "destination_prefix": str(r["DestinationPrefix"]), "next_hop": as_text(r.get("NextHop")),
            "interface_index": as_int(r.get("InterfaceIndex")), "interface_alias": as_text(r.get("InterfaceAlias")),
            "route_metric": as_int(r.get("RouteMetric")), "protocol": protocol,
            "protocol_text": ROUTE_PROTOCOL.get(protocol) if protocol is not None else None,
            "address_family": family, "address_family_text": ADDRESS_FAMILY.get(family) if family is not None else None,
            "store": as_int(r.get("Store")),
            "provenance": {"source_file": source, "row_id_or_offset": f"index:{index}", "decoded_table": "net_route",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


# ---------------------------------------------------------------- tables

def time_range(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    ranges = [e["raw_time_range"] for e in entries if e.get("raw_time_range")]
    if not ranges:
        return None
    return {"start": min(r["start"] for r in ranges), "end": max(r["end"] for r in ranges), "domain": "system_time", "unit": "iso_utc"}


def write_table(bundle: Path, table: str, rows: list[dict[str, Any]], sources: list[str], entries: list[dict[str, Any]],
                checks: list[dict[str, Any]], status: str, reason: str | None, decoded_at: str) -> None:
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{table}.jsonl", rows)
    meta = {
        "decoded_table": table, "schema_version": wf_schema.table_schema_version(table), "decoder": DECODER, "decoder_version": DECODER_VERSION,
        "tool": TOOL, "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows), "time_domain": "system_time", "native_time_range": time_range(entries),
        "status": status, "status_reason": reason, "checks": checks, "decoded_at_utc": decoded_at,
    }
    errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {errors}")
    wf_schema.write_json(decoded_dir / f"{table}.meta.json", meta)


def decode_table(bundle: Path, table: str, entries: dict[str, dict[str, Any]], decoded_at: str, profiles: dict[str, str] | None) -> dict[str, Any]:
    known_profiles = set(profiles.values()) if profiles is not None else None
    schema_version = wf_schema.table_schema_version(table)
    usable = [entries[s] for s in TABLE_SOURCES[table] if s in entries and entries[s]["status"] in OBSERVED]
    if not usable:
        reasons = "; ".join(f"{s}: {entries[s]['status']}" if s in entries else f"{s}: not in the manifest" for s in TABLE_SOURCES[table])
        return {"status": "not_collected", "reason": f"no readable source for {table} ({reasons})", "rows": 0, "sources": 0}
    rows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    sources: list[str] = []
    status, reason = "observed", None
    try:
        for entry in usable:
            source, target = read_primary(bundle, entry)
            sources.append(source)
            if table == "netsh_fields":
                part, counts = decode_netsh_fields(target.read_text(encoding="utf-8"), COMMAND_OF_SOURCE[entry["id"]], source, schema_version, profiles)
                checks.append({"name": f"labels:{entry['id']}", "ok": counts["label"] > 0 or not part,
                               "detail": f"{counts['label']} by English label, {counts['value']} by value shape, {counts['unclassified']} unclassified"})
            elif table == "wlan_bss":
                part, counts = decode_wlan_bss(target.read_text(encoding="utf-8"), source, schema_version, known_profiles)
                checks.append({"name": "networks_parsed", "ok": len(part) > 0 or entry["status"] == "observed_zero",
                               "detail": f"{counts['networks']} networks, {len(part)} access points, {counts['labels_recognised']} with English labels, "
                                         f"{counts['band_inferred']} with the band inferred from the channel number (a convenience bound, see CHANNELS_5GHZ)"})
                checks.append({"name": "known_profiles", "ok": True,
                               "detail": "matched against wlan_profiles" if known_profiles is not None else "wlan_profiles not readable; is_known_profile is null"})
                if entry["status"] == "observed" and not part:
                    raise DecodeError(f"{source}: the collector counted access points but the parser found none; the layout is not the one the parser knows")
            elif table == "pnp_device":
                part = decode_pnp(read_json_array(target, source), source, entry["id"], schema_version)
                checks.append({"name": f"devices:{entry['id']}", "ok": True,
                               "detail": f"{len(part)} devices, {sum(1 for r in part if r['is_receiver_candidate'])} receiver candidates, "
                                         f"{sum(1 for r in part if r['controller_instance_id'])} with a host controller"})
            elif table == "net_adapter":
                part = decode_net_adapter(read_json_array(target, source), source, schema_version)
                checks.append({"name": "adapters", "ok": True, "detail": f"{len(part)} adapters"})
            else:
                part = decode_net_route(read_json_array(target, source), source, schema_version)
                checks.append({"name": "routes", "ok": True, "detail": f"{len(part)} default routes"})
            rows += part
        errors = wf_schema.validate_rows(rows, f"decoded/{table}.schema.json")
        checks.append({"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None})
        if errors:
            status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
        elif not rows:
            status, reason = "observed_zero", "every readable source holds zero records"
    except DecodeError as exc:
        if not sources:
            return {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}
        status, reason, rows = "decode_failed", str(exc), []
        checks.append({"name": "export_read", "ok": False, "detail": str(exc)})
    write_table(bundle, table, rows, sources, usable, checks, status, reason, decoded_at)
    return {"status": status, "reason": reason, "rows": len(rows), "sources": len(sources)}


def decode(bundle: Path, decoded_at: str | None = None) -> dict[str, Any]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        manifest = load_manifest(bundle)
    except DecodeError as exc:
        return {"status": "decode_failed", "reason": str(exc), "tables": {}}
    entries = source_entries(manifest)
    if manifest["scenario"]["id"] != "rf_survey":
        return {"status": "not_applicable", "reason": f"the bundle was written by {manifest['scenario']['id']}, not rf_survey", "tables": {}}
    profiles = profile_mapping(bundle, entries)
    tables = {table: decode_table(bundle, table, entries, decoded_at, profiles) for table in TABLE_SOURCES}
    statuses = {t["status"] for t in tables.values()}
    if statuses & {"observed", "observed_zero"}:
        status = "observed" if "observed" in statuses else "observed_zero"
    elif "decode_failed" in statuses:
        status = "decode_failed"
    else:
        status = "not_collected"
    return {"status": status, "reason": None, "tables": tables}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--decoded-at", default=None)
    args = ap.parse_args(argv)
    result = decode(args.bundle, args.decoded_at)
    for table, info in result["tables"].items():
        print(f"{table}: {info['rows']} rows from {info['sources']} exports, status {info['status']}")
        if info["status"] not in OBSERVED:
            print(f"{table}: {info['status']}: {info['reason']}", file=sys.stderr)
    if result["status"] not in OBSERVED:
        print(f"decode status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
