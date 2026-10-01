#!/usr/bin/env python3
"""Turn the decoded rf-survey tables into evidence rows and a plain language result.

The PC is on Ethernet. Its wireless mouse and headset share the 2.4 GHz band
with the router, the neighbours' networks, Bluetooth and the noise that USB 3
ports and devices radiate, so this analyzer answers four questions from the
decoded tables and the manifest, never from raw files:

1. which adapter carries the PC's traffic (``net_route`` joined to ``net_adapter``);
2. how busy each 2.4 GHz channel is around the desk and which channel the
   router should use (``wlan_bss``), and whether the router offers 5 GHz for
   the household's other devices;
3. where the wireless receivers sit on the USB tree and whether they share a
   USB 3 (xHCI) controller or hub with USB 3 devices (``pnp_device``);
4. which radios are on but unused (``net_adapter``, ``pnp_device``).

Receiver distance and line of sight cannot be measured by a survey, so that
finding carries cited guidance and a before and after test (docs/rf-survey.md)
instead of evidence rows. Every threshold and every RF claim cites a vendor
or standards document; the citations are listed in CITATIONS and attached to
each finding.

Status follows docs/contracts/measurement-status.md: evidence rows are
``observed`` (confidence 1, provenance into the decoded rows) or ``inferred``
(a recommendation, confidence below 1, linked to the observed rows it rests
on). No absence row is ever written; a source that was not read is reported
as not measured, never as quiet. The coverage table comes first in every
output.

Writes ``evidence.jsonl`` (replacing its own rows, keeping any other
analyzer's), ``reports/rf-survey.md`` and ``reports/rf-survey.json``
(``schemas/analysis/rf_survey.schema.json``).

Usage::

    python scripts/analyze_rf_survey.py --bundle <bundle directory> [--analyzed-at 2026-09-03T00:00:00Z]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

ANALYZER = {"id": "rf_survey", "version": "1.0.0"}
PLAYBOOK = "rf_survey"
OBSERVED = ("observed", "observed_zero")
TABLES = ["net_adapter", "net_route", "wlan_bss", "netsh_fields", "pnp_device", "eventlog_events"]
TABLE_OF_SOURCE = {
    "net_adapters": "net_adapter", "default_routes": "net_route", "wlan_networks": "wlan_bss",
    "wlan_interfaces": "netsh_fields", "wlan_drivers": "netsh_fields", "wlan_profiles": "netsh_fields",
    "usb_device_tree": "pnp_device", "bluetooth_devices": "pnp_device", "wlan_autoconfig_events": "eventlog_events",
    "wlan_report": None,
}
CANDIDATE_CHANNELS = (1, 6, 11)
# 2.4 GHz channels are 5 MHz apart and a channel is 22 MHz wide, so two channels
# interfere unless they are 25 MHz (five channel numbers) apart (Cisco, below).
OVERLAP_DISTANCE = 4

CITATIONS = {
    "cisco_channels": {"title": "Cisco, WLAN Radio Frequency Design Considerations: each 2.4 GHz channel is 22 MHz wide with 5 MHz separation; only channels 1, 6 and 11 (25 MHz apart) do not overlap",
                       "url": "https://www.cisco.com/en/US/docs/solutions/Enterprise/Mobility/emob30dg/RFDesign.html"},
    "intel_protocols": {"title": "Intel, Different Wi-Fi Protocols and Data Rates: three non overlapping channels in the 2.4 GHz ISM band; 802.11a and 802.11ac use 5 GHz, 802.11b and g 2.4 GHz, 802.11n and ax either",
                        "url": "https://www.intel.com/content/www/us/en/support/articles/000005725/wireless/legacy-intel-wireless-products.html"},
    "intel_usb3": {"title": "Intel, USB 3.0 Radio Frequency Interference Impact on 2.4 GHz Wireless Devices (white paper 327216-001, April 2012): USB 3.0 noise falls in 2.4 to 2.5 GHz, raised the noise floor by nearly 20 dB next to a USB 3.0 drive, a mouse dongle stacked above a USB 3.0 port stopped responding while the same dongle on a USB 2 extension cable on the far side worked",
                   "url": "https://www.usb.org/sites/default/files/327216.pdf"},
    "logitech_usb3": {"title": "Logitech, Wireless product not working properly when also using a USB 3.0 device: separate the receiver from USB 3.0 connectors as far as possible, use a USB extender, keep the receiver as close as possible to the device",
                      "url": "https://support.logi.com/hc/en-ca/articles/360023414273-Wireless-product-not-working-properly-when-also-using-a-USB-3-0-device"},
    "logitech_distance": {"title": "Logitech, Operating distance between the mouse or keyboard and USB receiver: up to 10 m in a clear line of sight; move phones, radios, Wi-Fi routers and microwaves away from the work area",
                          "url": "https://support.logi.com/hc/en-us/articles/360023402233-Operating-distance-between-the-mouse-or-keyboard-and-USB-receiver"},
    "logitech_interference": {"title": "Logitech, Troubleshooting recommendations for interference issues: receiver in direct line of sight, as little distance as possible, no metal or electronics between, front USB panel, not under the desk, test with USB 3.0 devices unplugged",
                              "url": "https://hub.sync.logitech.com/mx-master-3s/post/troubleshooting-recommendations-for-interference-issues-goEfm9QOsiJ4efB"},
    "ms_bluetooth_faq": {"title": "Microsoft, Bluetooth FAQ: Bluetooth and Wi-Fi radios both operate in the 2.4 GHz range and can reduce each other's transfer rates; adaptive frequency hopping mitigates",
                         "url": "https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-faq"},
    "ms_wdi_scan": {"title": "Microsoft, OID_WDI_TASK_SCAN: a Wi-Fi port surveys networks per IEEE 802.11 with probe requests, as a background or user initiated scan",
                    "url": "https://learn.microsoft.com/windows-hardware/drivers/netcx/oid-wdi-task-scan"},
    "ms_signal": {"title": "Microsoft, WLAN_ASSOCIATION_ATTRIBUTES: signal quality 0 is -100 dBm and 100 is -50 dBm, linear between",
                  "url": "https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_association_attributes"},
    "ms_usb_stack": {"title": "Microsoft, USB host side drivers in Windows: Usbxhci.sys and Usbhub3.sys serve xHCI (USB 3) controllers, Usbehci.sys and Usbhub.sys serve USB 2 controllers",
                     "url": "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture"},
    "ms_usb_faq": {"title": "Microsoft, USB in Windows FAQ: the driver stack follows the host controller type, not the connected device's speed; a USB 3.0 hub appears as a SuperSpeed hub and a USB 2.0 hub",
                   "url": "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-faq--introductory-level"},
    "ms_netadapter": {"title": "Microsoft, MSFT_NetAdapter class: NdisPhysicalMedium 14 is 802.3, 9 is Native 802.11, 10 is BlueTooth; State 3 is Disabled",
                      "url": "https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter"},
    "ms_netroute": {"title": "Microsoft, Get-NetRoute: the next hop of the 0.0.0.0/0 route is the default gateway",
                    "url": "https://learn.microsoft.com/powershell/module/nettcpip/get-netroute"},
    "ms_location": {"title": "Microsoft, Changes to API behavior for Wi-Fi access and location: without location consent the scan APIs return access denied",
                    "url": "https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes"},
    "ms_wlan_troubleshooting": {"title": "Microsoft, Advanced troubleshooting wireless network connectivity: netsh wlan show networks mode=bssid lists BSSID, signal, channel and radio type; the WLAN AutoConfig operational log holds the service's events",
                                "url": "https://learn.microsoft.com/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting"},
    "ms_win11_6e": {"title": "Microsoft, Windows 11 requirements: Wi-Fi 6E needs new WLAN hardware and driver and a Wi-Fi 6E capable access point",
                    "url": "https://learn.microsoft.com/windows/whats-new/windows-11-requirements"},
}


def cite(*keys: str) -> list[dict[str, str]]:
    return [CITATIONS[k] for k in keys]


# ---------------------------------------------------------------- loading

def load_tables(bundle: Path) -> dict[str, dict[str, Any]]:
    """Every decoded table of interest: rows and sidecar, or status not_collected when the sidecar is absent."""
    out = {}
    for table in TABLES:
        meta_path = bundle / "decoded" / f"{table}.meta.json"
        rows_path = bundle / "decoded" / f"{table}.jsonl"
        if not meta_path.is_file() or not rows_path.is_file():
            out[table] = {"status": "not_collected", "reason": "no decoded table in the bundle", "rows": [], "meta": None}
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        rows = wf_schema.read_jsonl(rows_path) if meta["status"] in OBSERVED else []
        out[table] = {"status": meta["status"], "reason": meta.get("status_reason"), "rows": rows, "meta": meta}
    return out


def pct_to_dbm(pct: int | None) -> float | None:
    return None if pct is None else -100 + pct / 2


# ---------------------------------------------------------------- evidence rows

class Evidence:
    def __init__(self, captured_utc: str, analyzed_at: str):
        self.rows: list[dict[str, Any]] = []
        self.captured = captured_utc
        self.analyzed_at = analyzed_at

    def add(self, *, signal: str, metric: str, unit: str, value: Any, source: str, subsystem: str, severity: str,
            kind: str, provenance: list[dict[str, Any]] | None = None, links: list[str] | None = None,
            payload: dict[str, Any] | None = None, confidence: float = 1.0) -> str:
        row_id = f"rf_survey:{len(self.rows) + 1:03d}"
        self.rows.append({
            "row_id": row_id, "ts_utc": self.captured, "window": None, "t_master_100ns": None, "clock_error_bound_100ns": None,
            "collected_ts_utc": self.analyzed_at, "source": source, "subsystem": subsystem, "signal": signal, "metric": metric,
            "unit": unit, "value": value, "severity": severity, "faulting_module": None, "cpu": None,
            "confidence": confidence if kind == "inferred" else 1.0, "evidence_kind": kind, "coverage_ref": None,
            "provenance": provenance or [], "links": links or [], "incident_id": None, "analyzer": ANALYZER, "playbook": PLAYBOOK,
            "payload": payload or {},
        })
        return row_id


def finding(fid: str, kind: str, severity: str, title: str, statement: str, recommendation: str | None,
            rows: list[str], citations: list[dict[str, str]], measured: bool = True, details: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {"id": fid, "kind": kind, "severity": severity, "title": title, "statement": statement, "recommendation": recommendation,
           "evidence_row_ids": rows, "citations": citations, "measured": measured}
    if details is not None:
        out["details"] = details
    return out


def not_measured(entries: dict[str, dict[str, Any]], source_id: str, tables: dict[str, dict[str, Any]]) -> str:
    """Why a source is unavailable, in the collector's own words or the decoder's."""
    entry = entries.get(source_id)
    if entry is None:
        return f"the bundle has no {source_id} source"
    if entry["status"] not in OBSERVED:
        return f"{source_id} is {entry['status']}: {entry['status_reason']}"
    table = TABLE_OF_SOURCE.get(source_id)
    if table and tables[table]["status"] not in OBSERVED:
        return f"{source_id} was read but its table {table} is {tables[table]['status']}: {tables[table]['reason']}"
    return f"{source_id} holds no record"


# ---------------------------------------------------------------- the four questions

def analyze_traffic_path(tables, entries, ev) -> dict[str, Any]:
    routes = [r for r in tables["net_route"]["rows"] if r["destination_prefix"] in ("0.0.0.0/0", "::/0")]
    adapters = tables["net_adapter"]["rows"]
    if tables["net_route"]["status"] not in OBSERVED or tables["net_adapter"]["status"] not in OBSERVED:
        why = not_measured(entries, "default_routes", tables) if tables["net_route"]["status"] not in OBSERVED else not_measured(entries, "net_adapters", tables)
        return {"finding": finding("traffic_path", "traffic_path", "warn", "Which connection carries the PC's traffic",
                                   f"Not measured: {why}.", None, [], cite("ms_netroute", "ms_netadapter"), measured=False), "default_interface": None}
    ipv4 = sorted((r for r in routes if r["destination_prefix"] == "0.0.0.0/0"), key=lambda r: (r["route_metric"] if r["route_metric"] is not None else 1 << 16))
    if not ipv4:
        rid = ev.add(signal="default_route_absent", metric="route_count", unit="count", value=0, source="default_routes", subsystem="network",
                     severity="warn", kind="observed", provenance=[r["provenance"] for r in routes] or [tables["net_route"]["rows"][0]["provenance"]] if tables["net_route"]["rows"] else None)
        return {"finding": finding("traffic_path", "traffic_path", "warn", "Which connection carries the PC's traffic",
                                   "The routing table holds no IPv4 default route, so no adapter was carrying internet traffic when the survey ran.",
                                   None, [rid] if rid else [], cite("ms_netroute")), "default_interface": None}
    route = ipv4[0]
    adapter = next((a for a in adapters if a["interface_index"] == route["interface_index"]), None)
    medium = adapter["physical_medium_text"] if adapter else None
    carrier = {"802.3": "Ethernet (wired)", "Native 802.11": "Wi-Fi", "BlueTooth": "Bluetooth"}.get(medium or "", medium or "an adapter the survey could not describe")
    provenance = [route["provenance"]] + ([adapter["provenance"]] if adapter else [])
    rid = ev.add(signal="traffic_default_route", metric="route_metric", unit="count", value=route["route_metric"], source="default_routes",
                 subsystem="network", severity="info", kind="observed", provenance=provenance,
                 payload={"next_hop": route["next_hop"], "interface_index": route["interface_index"], "interface_alias": route["interface_alias"],
                          "adapter": adapter["interface_description"] if adapter else None, "physical_medium": medium, "carrier": carrier})
    statement = (f"The PC's internet traffic goes through {adapter['interface_description'] if adapter else route['interface_alias']} ({carrier}), "
                 f"the interface behind the IPv4 default route to {route['next_hop']}.")
    if medium == "802.3":
        statement += " The Wi-Fi link is not in the path, so the PC's own Wi-Fi connection cannot be the cause of mouse or headset trouble; the Wi-Fi adapter is used below only as a receiver that sees the 2.4 GHz networks around the desk."
    return {"finding": finding("traffic_path", "traffic_path", "info", "Default route and adapter", statement, None, [rid],
                               cite("ms_netroute", "ms_netadapter"), details={"carrier": carrier}),
            "default_interface": route["interface_index"]}


def analyze_airspace(tables, entries, ev) -> dict[str, Any]:
    result: dict[str, Any] = {"findings": [], "channels": []}
    if tables["wlan_bss"]["status"] not in OBSERVED:
        result["findings"].append(finding("wifi_scan", "wifi_24ghz", "warn", "The 2.4 GHz airspace around the desk",
                                          f"The scan is unavailable, so nothing can be said about the channels around the desk: {not_measured(entries, 'wlan_networks', tables)}.",
                                          "Run the location consent check from the verification list in collectors/windows/README.md, then run the survey again.",
                                          [], cite("ms_location", "ms_wlan_troubleshooting"), measured=False))
        return result
    bss = tables["wlan_bss"]["rows"]
    band24 = [r for r in bss if r["band_ghz"] == 2.4 and r["channel"] is not None]
    band5 = [r for r in bss if r["band_ghz"] in (5, 6)]
    unknown = [r for r in bss if r["band_ghz"] is None or r["channel"] is None]
    if not band24:
        rid = ev.add(signal="wifi_24ghz_bss_count", metric="bss_count", unit="count", value=0, source="wlan_networks", subsystem="network",
                     severity="info", kind="observed", provenance=[r["provenance"] for r in bss] or None) if bss else None
        result["findings"].append(finding("wifi_24ghz_empty", "wifi_24ghz", "info", "The 2.4 GHz airspace around the desk",
                                          f"The scan lists {len(bss)} access points and none of them on 2.4 GHz" + (f" ({len(unknown)} with a band or channel the parser could not read)." if unknown else "."),
                                          None, [rid] if rid else [], cite("ms_wlan_troubleshooting")))
        return result

    # Whose router is it? A network with a saved profile on this PC is the owner's; failing that the strongest 2.4 GHz signal is the nearest.
    known = [r for r in band24 if r["is_known_profile"]]
    strongest = max(band24, key=lambda r: r["signal_pct"] or 0)
    if known:
        own_rows, own_basis = known, "a saved Wi-Fi profile on this PC names it"
    else:
        own_rows, own_basis = [strongest], "it is the strongest 2.4 GHz signal, which usually means the nearest access point; no saved profile confirmed it"
    own_ids = {r["bssid_pseudonym"] for r in own_rows}
    own_ssids = {r["ssid_pseudonym"] for r in own_rows if r["ssid_pseudonym"]}
    own_channel = own_rows[0]["channel"]
    own_rid = ev.add(signal="own_router_identified", metric="bss_count", unit="count", value=len(own_rows), source="wlan_networks", subsystem="network",
                     severity="info", kind="observed", provenance=[r["provenance"] for r in own_rows],
                     payload={"basis": own_basis, "channel": own_channel, "signal_pct": own_rows[0]["signal_pct"],
                              "signal_dbm_estimate": pct_to_dbm(own_rows[0]["signal_pct"]), "ssid_pseudonym": own_rows[0]["ssid_pseudonym"],
                              "confirmed_by_profile": bool(known)})

    # Per channel counts and the overlap load of the three non overlapping channels.
    by_channel: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in band24:
        by_channel[r["channel"]].append(r)
    channel_rows: list[dict[str, Any]] = []
    load_rids: dict[int, str] = {}
    for channel in range(1, 15):
        here = by_channel.get(channel, [])
        overlap = [r for r in band24 if abs(r["channel"] - channel) <= OVERLAP_DISTANCE and r["bssid_pseudonym"] not in own_ids]
        strongest_here = max((r["signal_pct"] or 0 for r in here), default=None)
        strongest_overlap = max((r["signal_pct"] or 0 for r in overlap), default=None)
        channel_rows.append({"channel": channel, "bss_count": len(here), "strongest_signal_pct": strongest_here,
                             "overlap_bss_count": len(overlap), "overlap_strongest_signal_pct": strongest_overlap,
                             "own_router_here": any(r["bssid_pseudonym"] in own_ids for r in here), "candidate": channel in CANDIDATE_CHANNELS})
        if here:
            ev.add(signal="wifi_24ghz_bss_count", metric="bss_count", unit="count", value=len(here), source="wlan_networks", subsystem="network",
                   severity="info", kind="observed", provenance=[r["provenance"] for r in here],
                   payload={"channel": channel, "strongest_signal_pct": strongest_here, "strongest_signal_dbm_estimate": pct_to_dbm(strongest_here)})
        if channel in CANDIDATE_CHANNELS:
            load_rids[channel] = ev.add(signal="wifi_24ghz_overlap_load", metric="bss_count", unit="count", value=len(overlap), source="wlan_networks",
                                        subsystem="network", severity="info", kind="observed",
                                        provenance=[r["provenance"] for r in overlap] or [r["provenance"] for r in band24],
                                        payload={"channel": channel, "overlap_distance_channels": OVERLAP_DISTANCE, "excludes_own_router": True,
                                                 "strongest_signal_pct": strongest_overlap, "strongest_signal_dbm_estimate": pct_to_dbm(strongest_overlap)})
    result["channels"] = channel_rows

    def load(channel: int) -> tuple[int, int]:
        row = channel_rows[channel - 1]
        return (row["overlap_bss_count"], row["overlap_strongest_signal_pct"] or 0)

    best = min(CANDIDATE_CHANNELS, key=load)
    own_load = load(own_channel) if own_channel in CANDIDATE_CHANNELS else None
    neighbours = len(band24) - len(own_rows)
    busiest = max(channel_rows, key=lambda c: (c["bss_count"], c["strongest_signal_pct"] or 0))
    statement = (f"The scan saw {len(band24)} access points on 2.4 GHz ({neighbours} besides the router identified as yours) and {len(band5)} on 5 GHz. "
                 f"Your router's 2.4 GHz network is on channel {own_channel} ({own_rows[0]['signal_pct']}%, about {pct_to_dbm(own_rows[0]['signal_pct']):.0f} dBm); {own_basis}. "
                 f"Counting every network within four channels, the load the router competes with is: "
                 + ", ".join(describe_load(c, load(c)) for c in CANDIDATE_CHANNELS)
                 + f". The busiest single channel is {busiest['channel']} with {busiest['bss_count']} access points.")
    if own_load is not None and own_load <= load(best):
        recommendation = f"Keep the router on channel {own_channel}: it already has the lowest overlap load of channels 1, 6 and 11."
        severity = "info"
    else:
        current = f"from channel {own_channel} " if own_channel is not None else ""
        recommendation = (f"Move the router's 2.4 GHz network {current}to channel {best} ({describe_load(best, load(best))}), "
                          f"and set its 2.4 GHz channel width to 20 MHz if the router offers the choice, so it stays inside one non overlapping channel. "
                          f"Change nothing else at the same time and run the before and after test in docs/rf-survey.md.")
        severity = "warn" if (own_load is None or own_load[0] >= 2) else "info"
    rec_rid = ev.add(signal="router_channel_recommendation", metric="channel", unit="none", value=best, source="wlan_networks", subsystem="network",
                     severity=severity, kind="inferred", confidence=0.7, links=[own_rid] + [load_rids[c] for c in CANDIDATE_CHANNELS],
                     payload={"recommended_channel": best, "current_channel": own_channel, "rule": "lowest count of networks within four channels, then lowest strongest signal, excluding your own router",
                              "citations": [CITATIONS["cisco_channels"]["url"], CITATIONS["intel_protocols"]["url"]]})
    result["findings"].append(finding("wifi_24ghz_congestion", "wifi_24ghz", severity, "The 2.4 GHz airspace around the desk", statement, recommendation,
                                      [own_rid] + list(load_rids.values()) + [rec_rid], cite("cisco_channels", "intel_protocols", "ms_signal", "ms_wlan_troubleshooting"),
                                      details={"recommended_channel": best, "own_channel": own_channel, "own_basis": own_basis,
                                               "bss_24ghz": len(band24), "bss_5ghz": len(band5), "unparsed": len(unknown)}))

    # The router's 5 GHz band for the household's other devices.
    own_5 = [r for r in band5 if r["ssid_pseudonym"] in own_ssids]
    if own_5:
        rids = [ev.add(signal="wifi_5ghz_bss", metric="signal_quality", unit="pct", value=r["signal_pct"], source="wlan_networks", subsystem="network",
                       severity="info", kind="observed", provenance=[r["provenance"]],
                       payload={"channel": r["channel"], "band_ghz": r["band_ghz"], "radio_type": r["radio_type"], "same_name_as_own_router": True}) for r in own_5]
        rec = ev.add(signal="move_household_devices_to_5ghz", metric="bss_count", unit="count", value=len(own_5), source="wlan_networks", subsystem="network",
                     severity="info", kind="inferred", confidence=0.7, links=[own_rid] + rids)
        result["findings"].append(finding("wifi_5ghz_available", "wifi_24ghz", "info", "Your router also offers 5 GHz",
                                          f"The same network name as your router is on the air on 5 GHz ({len(own_5)} access point{'s' if len(own_5) != 1 else ''}, channel {own_5[0]['channel']}, {own_5[0]['signal_pct']}%). "
                                          f"802.11a, 802.11ac and 5 GHz 802.11n and ax traffic does not share the band the mouse and headset receivers use.",
                                          "Connect the household's phones, tablets, TVs and laptops to the router's 5 GHz network so they stop transmitting on 2.4 GHz near the desk; if the router offers a band steering or separate SSID option, give the 5 GHz network its own name so devices do not fall back to 2.4 GHz.",
                                          rids + [rec], cite("intel_protocols", "cisco_channels")))
    else:
        others_5 = len(band5)
        result["findings"].append(finding("wifi_5ghz_absent", "wifi_24ghz", "info", "No 5 GHz network from your router was seen",
                                          f"No 5 GHz access point carries your router's network name ({others_5} other 5 GHz access points were seen, so the adapter can see that band). "
                                          "Either the router has no 5 GHz radio, it is switched off, or it uses a different name that this PC has no profile for.",
                                          "Check the router's settings: if it has a 5 GHz band, switch it on and move the household's other devices to it; a 5 GHz only name keeps them off the band the receivers use.",
                                          [own_rid], cite("intel_protocols"), measured=True))
    if unknown:
        result["findings"].append(finding("wifi_unparsed", "wifi_24ghz", "info", "Access points the parser could not place",
                                          f"{len(unknown)} access point(s) had no band or channel the parser could read; they are in the wlan_bss table with null fields and the raw netsh text in the bundle.",
                                          None, [], cite("ms_wlan_troubleshooting")))
    return result


def analyze_receivers(tables, entries, ev) -> list[dict[str, Any]]:
    if tables["pnp_device"]["status"] not in OBSERVED:
        return [finding("usb_receivers", "usb_receiver", "warn", "Where the wireless receivers sit",
                        f"Not measured: {not_measured(entries, 'usb_device_tree', tables)}.", None, [], cite("ms_usb_stack"), measured=False)]
    devices = [r for r in tables["pnp_device"]["rows"] if r["source_id"] == "usb_device_tree"]
    by_id = {r["instance_id"].upper(): r for r in devices}
    candidates = {r["instance_id"].upper() for r in devices if r["is_receiver_candidate"]}
    receivers = [r for r in devices if r["is_receiver_candidate"] and r["parent_instance_id"]
                 and not any(a.upper() in candidates for a in r["hub_chain"])]
    controllers = {r["instance_id"]: r for r in devices if r["usb_stack"] and r["controller_instance_id"] == r["instance_id"]}
    ehci = [c for c in controllers.values() if c["usb_stack"] == "usb2_ehci"]
    xhci = [c for c in controllers.values() if c["usb_stack"] == "usb3_xhci"]
    out = []
    controller_rid = ev.add(signal="usb_host_controllers", metric="controller_count", unit="count", value=len(controllers), source="usb_device_tree",
                            subsystem="input", severity="info", kind="observed", provenance=[c["provenance"] for c in controllers.values()] or [devices[0]["provenance"]],
                            payload={"xhci": [c["name"] for c in xhci], "ehci": [c["name"] for c in ehci]})
    if not receivers:
        hid = [r for r in devices if r["usb_stack"] and (r["class"] or "").upper() in ("HIDCLASS", "MOUSE", "KEYBOARD", "MEDIA")]
        out.append(finding("usb_receivers_unrecognised", "usb_receiver", "info", "Where the wireless receivers sit",
                           f"No USB device announced itself as a receiver or dongle by name. {len(hid)} input or audio devices sit on USB; each is listed in the pnp_device table with its controller, "
                           "so the receiver can be identified by unplugging it and comparing.", None, [controller_rid], cite("ms_usb_stack")))
        return out
    for receiver in receivers:
        siblings = [r for r in devices if r["parent_instance_id"] and r["parent_instance_id"].upper() == receiver["parent_instance_id"].upper()
                    and r["instance_id"] != receiver["instance_id"] and not r["is_bluetooth_radio"]]
        controller = controllers.get(receiver["controller_instance_id"] or "")
        hub = by_id.get((receiver["parent_instance_id"] or "").upper())
        name = receiver["bus_reported_description"] or receiver["name"] or receiver["instance_id"]
        rid = ev.add(signal="usb_receiver_candidate", metric="usb_stack_is_xhci", unit="bool", value=(receiver["usb_stack"] == "usb3_xhci"),
                     source="usb_device_tree", subsystem="input", severity="info", kind="observed",
                     provenance=[receiver["provenance"]] + ([hub["provenance"]] if hub else []) + ([controller["provenance"]] if controller else []),
                     payload={"name": name, "vendor_id": receiver["vendor_id"], "product_id": receiver["product_id"], "location_path": receiver["location_path"],
                              "location_info": receiver["location_info"], "hub": hub["name"] if hub else None, "hub_service": hub["service"] if hub else None,
                              "controller": controller["name"] if controller else None, "usb_stack": receiver["usb_stack"],
                              "devices_on_same_hub": [{"name": s["bus_reported_description"] or s["name"], "location_path": s["location_path"], "service": s["service"]} for s in siblings]})
        where = f"port {receiver['location_info'] or receiver['location_path']} of {hub['name'] if hub else 'an unknown hub'}"
        if receiver["usb_stack"] == "usb3_xhci":
            statement = (f"{name} sits on {where}, served by the USB 3 host controller ({controller['name'] if controller else 'xHCI'}). "
                         f"Windows shows the controller and hub chain but not the speed of each port, so this says the receiver shares a USB 3 capable controller, not that USB 3 traffic runs next to it. "
                         + (f"Other devices on the same hub: {', '.join((s['bus_reported_description'] or s['name'] or s['instance_id']) for s in siblings)}." if siblings else "No other device shares that hub."))
            if ehci:
                recommendation = (f"Move the receiver to a port served by the USB 2 controller ({ehci[0]['name']}), the ports whose root hub is {next((r['name'] for r in devices if r['controller_instance_id'] == ehci[0]['instance_id'] and r['is_root_hub']), 'USB Root Hub')}, "
                                  "or put it on a short USB 2 extension cable as far from the USB 3 connectors as possible and as close to the mouse or headset as possible. Change one thing at a time and run the before and after test.")
            else:
                recommendation = ("This PC exposes only USB 3 (xHCI) host controllers, so there is no USB 2 only port to move to. Put the receiver on a short USB 2 extension cable, as far from the case's USB 3 connectors and any USB 3 drive as possible and as close to the mouse or headset as possible, then run the before and after test.")
            severity = "warn"
        elif receiver["usb_stack"] == "usb2_ehci":
            statement = (f"{name} sits on {where}, served by the USB 2 host controller ({controller['name'] if controller else 'EHCI'}), so it does not share a USB 3 controller. "
                         + (f"Other devices on the same hub: {', '.join((s['bus_reported_description'] or s['name'] or s['instance_id']) for s in siblings)}." if siblings else "No other device shares that hub."))
            recommendation = "No port change is indicated by the tree. If USB 3 drives or hubs sit next to this port on the case, the before and after test with them unplugged tells whether their noise reaches the receiver."
            severity = "info"
        else:
            statement = f"{name} sits on {where}; the host controller type could not be resolved from the device tree."
            recommendation = "Follow the receiver's chain in the pnp_device table by hand, then apply the USB 3 guidance if its controller is xHCI."
            severity = "info"
        rec_rid = ev.add(signal="usb_receiver_relocation", metric="usb_stack_is_xhci", unit="bool", value=(receiver["usb_stack"] == "usb3_xhci"), source="usb_device_tree",
                         subsystem="input", severity=severity, kind="inferred", confidence=0.6, links=[rid, controller_rid],
                         payload={"ehci_available": bool(ehci), "recommendation": recommendation})
        out.append(finding(f"usb_receiver_{receiver['vendor_id'] or 'x'}_{receiver['product_id'] or 'x'}".lower(), "usb_receiver", severity, f"Receiver: {name}",
                           statement, recommendation, [rid, controller_rid, rec_rid], cite("intel_usb3", "logitech_usb3", "ms_usb_stack", "ms_usb_faq"),
                           details={"usb_stack": receiver["usb_stack"], "ehci_available": bool(ehci)}))
    # USB storage and hubs on the xHCI stack are the classic noise sources.
    noisy = [r for r in devices if r["usb_stack"] == "usb3_xhci" and not r["is_root_hub"] and not r["is_receiver_candidate"] and not r["is_bluetooth_radio"]
             and ((r["service"] or "").upper() == "USBSTOR" or (r["class"] or "").upper() == "USB" and "HUB" in (r["name"] or "").upper())]
    if noisy:
        rids = [ev.add(signal="usb3_stack_device", metric="device_count", unit="count", value=1, source="usb_device_tree", subsystem="input", severity="info",
                       kind="observed", provenance=[r["provenance"]], payload={"name": r["bus_reported_description"] or r["name"], "location_path": r["location_path"], "service": r["service"]}) for r in noisy]
        out.append(finding("usb3_noise_sources", "usb_receiver", "info", "Storage and hubs on the USB 3 controller",
                           "These devices hang off the USB 3 controller: " + ", ".join(f"{r['bus_reported_description'] or r['name']} ({r['location_info'] or r['location_path']})" for r in noisy)
                           + ". Windows does not expose whether each one runs at USB 3 speed, so they are suspects, not culprits: a USB 3 drive or hub next to a receiver is the case Intel measured.",
                           "During the before and after test, unplug these one at a time while watching the mouse and headset; if one of them matters, move it to a port far from the receivers or onto its own cable away from the desk.",
                           rids, cite("intel_usb3", "logitech_interference", "ms_usb_faq")))
    return out


def analyze_unused_radios(tables, entries, ev, default_interface: int | None) -> list[dict[str, Any]]:
    out = []
    adapters = tables["net_adapter"]["rows"] if tables["net_adapter"]["status"] in OBSERVED else []
    wifi = [a for a in adapters if a["physical_medium"] == 9 and a["hardware_interface"] and not a["virtual"]]
    fields = tables["netsh_fields"]["rows"] if tables["netsh_fields"]["status"] in OBSERVED else []
    connected_ssid = next((f["value_text"] for f in fields if f["command"] == "interfaces" and f["normalized_key"] == "ssid"), None)
    for a in wifi:
        enabled = a["pnp_state"] != 3
        unused = default_interface is not None and a["interface_index"] != default_interface
        rid = ev.add(signal="wifi_adapter_state", metric="adapter_enabled", unit="bool", value=enabled, source="net_adapters", subsystem="network", severity="info",
                     kind="observed", provenance=[a["provenance"]],
                     payload={"adapter": a["interface_description"], "pnp_state": a["pnp_state_text"], "operational_status": a["operational_status_text"],
                              "media_connect_state": a["media_connect_state_text"], "carries_default_route": not unused, "connected_ssid_pseudonym": connected_ssid})
        if enabled and unused:
            connected = f" It is connected to network {connected_ssid}." if connected_ssid else ""
            rec = ev.add(signal="unused_radio_could_be_off", metric="adapter_enabled", unit="bool", value=True, source="net_adapters", subsystem="network",
                         severity="info", kind="inferred", confidence=0.6, links=[rid], payload={"radio": "wifi", "adapter": a["interface_description"]})
            out.append(finding("wifi_adapter_unused", "unused_radio", "info", "The Wi-Fi adapter is on but carries no traffic",
                               f"{a['interface_description']} is {a['pnp_state_text'] or 'present'}, {a['operational_status_text'] or 'status unknown'}, {a['media_connect_state_text'] or 'connection state unknown'}, and it is not the interface behind the default route.{connected}"
                               " An enabled Wi-Fi adapter keeps scanning for networks, and a scan transmits probe requests on the same 2.4 GHz band the receivers listen on.",
                               "If you do not use Wi-Fi on this PC, turn the adapter off yourself (Settings, Network and internet, Wi-Fi) and see whether the mouse and headset improve; the collector never changes it. Turn it back on when you want to run this survey again, because the survey needs it to see the networks around the desk.",
                               [rid, rec], cite("ms_wdi_scan", "ms_netadapter", "ms_bluetooth_faq")))
    devices = tables["pnp_device"]["rows"] if tables["pnp_device"]["status"] in OBSERVED else []
    radios = [r for r in devices if r["source_id"] == "bluetooth_devices" and r["is_bluetooth_radio"]]
    peers = [r for r in devices if r["source_id"] == "bluetooth_devices" and r["is_bluetooth_peer"]]
    bt_entry = entries.get("bluetooth_devices")
    if radios:
        rid = ev.add(signal="bluetooth_radio_state", metric="paired_device_count", unit="count", value=len(peers), source="bluetooth_devices", subsystem="network",
                     severity="info", kind="observed", provenance=[r["provenance"] for r in radios] + [r["provenance"] for r in peers],
                     payload={"radio": radios[0]["name"], "status": radios[0]["status"], "paired": [p["name"] for p in peers]})
        if not peers:
            rec = ev.add(signal="unused_radio_could_be_off", metric="paired_device_count", unit="count", value=0, source="bluetooth_devices", subsystem="network",
                         severity="info", kind="inferred", confidence=0.6, links=[rid], payload={"radio": "bluetooth", "adapter": radios[0]["name"]})
            out.append(finding("bluetooth_unused", "unused_radio", "info", "Bluetooth is on with nothing paired",
                               f"The Bluetooth radio {radios[0]['name']} is present and {radios[0]['status'] or 'of unknown status'}, and no paired Bluetooth device is registered. Bluetooth shares the 2.4 GHz band with the receivers.",
                               "If you do not use Bluetooth on this PC, turn it off yourself in Settings and include that step in the before and after test; the collector never changes it.",
                               [rid, rec], cite("ms_bluetooth_faq")))
        else:
            out.append(finding("bluetooth_in_use", "unused_radio", "info", "Bluetooth is in use",
                               f"The Bluetooth radio {radios[0]['name']} has {len(peers)} paired device(s): {', '.join(p['name'] or p['instance_id'] for p in peers)}. It shares the 2.4 GHz band with the receivers; Windows and the radio use adaptive frequency hopping to avoid busy channels.",
                               None, [rid], cite("ms_bluetooth_faq")))
    elif bt_entry is not None and bt_entry["status"] == "observed_zero":
        out.append(finding("bluetooth_absent", "unused_radio", "info", "No Bluetooth radio", "The device enumeration completed and lists no Bluetooth radio, so Bluetooth is not a 2.4 GHz transmitter on this PC.", None, [], cite("ms_bluetooth_faq")))
    elif bt_entry is None or bt_entry["status"] not in OBSERVED:
        out.append(finding("bluetooth_not_measured", "unused_radio", "warn", "Bluetooth not measured", f"Not measured: {not_measured(entries, 'bluetooth_devices', tables)}.", None, [], cite("ms_bluetooth_faq"), measured=False))
    return out


def placement_finding() -> dict[str, Any]:
    return finding("receiver_placement", "placement", "info", "Receiver distance and line of sight (not measurable here)",
                   "No survey can measure how far the receiver is from the mouse and headset or what sits between them. Vendor guidance: keep as little distance as possible between receiver and device, "
                   "put the receiver in direct line of sight (a front panel port rather than the back of a PC under the desk), keep metal objects and other electronics out of the path, "
                   "keep it away from USB 3.0 connectors and devices, and keep phones, routers and microwaves away from the work area.",
                   "Run the before and after test in docs/rf-survey.md: change one thing at a time (receiver port, extension cable, Wi-Fi adapter off, Bluetooth off, router channel), "
                   "judge the mouse by tracking smoothness and missed clicks over a minute of normal play, and the headset by dropouts and crackle over the same minute, and write both down before and after each change.",
                   [], cite("logitech_interference", "logitech_distance", "logitech_usb3", "intel_usb3"), measured=False)


def analyze_events(tables, entries, ev) -> list[dict[str, Any]]:
    entry = entries.get("wlan_autoconfig_events")
    if entry is None:
        return []
    if entry["status"] not in OBSERVED or tables["eventlog_events"]["status"] not in OBSERVED:
        return [finding("wlan_events_not_measured", "wlan_events", "info", "Wi-Fi service events", f"Not measured: {not_measured(entries, 'wlan_autoconfig_events', tables)}.", None, [], cite("ms_wlan_troubleshooting"), measured=False)]
    rows = [r for r in tables["eventlog_events"]["rows"] if "WLAN-AutoConfig" in (r["log_name"] or "")]
    if not rows:
        return [finding("wlan_events_quiet", "wlan_events", "info", "Wi-Fi service events", f"The WLAN AutoConfig operational log holds no event in the window ({entry['raw_time_range']['start'][:10]} to {entry['raw_time_range']['end'][:10]}).", None, [], cite("ms_wlan_troubleshooting"))]
    counts = Counter(r["event_id"] for r in rows)
    rids = []
    for event_id, count in counts.most_common():
        sample = next(r for r in rows if r["event_id"] == event_id)
        rids.append(ev.add(signal="wlan_autoconfig_event_count", metric="event_count", unit="count", value=count, source="wlan_autoconfig_events", subsystem="network",
                           severity="info", kind="observed", provenance=[r["provenance"] for r in rows if r["event_id"] == event_id],
                           payload={"event_id": event_id, "message_sample": (sample["message"] or "")[:160] or None}))
    text = "; ".join(f"id {event_id}: {count}" for event_id, count in counts.most_common(8))
    return [finding("wlan_events_summary", "wlan_events", "info", "Wi-Fi service events",
                    f"{len(rows)} WLAN AutoConfig events in the window, by event id: {text}. They describe the PC's own Wi-Fi service (connections, disconnections, adapter state), not the receivers; the rendered messages are in the eventlog_events table.",
                    None, rids, cite("ms_wlan_troubleshooting"))]


# ---------------------------------------------------------------- report

def coverage_table(manifest, tables) -> list[dict[str, Any]]:
    out = []
    for c in manifest["collectors"]:
        table = TABLE_OF_SOURCE.get(c["id"])
        info = tables.get(table) if table else None
        out.append({"id": c["id"], "kind": "collector", "collector_status": c["status"], "collector_status_reason": c["status_reason"],
                    "decoded_table": table, "decoded_status": info["status"] if info else None, "rows": len(info["rows"]) if info else None})
    for table in TABLES:
        info = tables[table]
        out.append({"id": table, "kind": "table", "collector_status": None, "collector_status_reason": None, "decoded_table": table,
                    "decoded_status": info["status"], "rows": len(info["rows"]) if info["status"] in OBSERVED else None})
    return out


def render_report(manifest, result: dict[str, Any], findings: list[dict[str, Any]], channels: list[dict[str, Any]], coverage) -> str:
    lines = [f"# RF survey of the desk: bundle {manifest['bundle_id']}", "",
             f"Captured {manifest['capture']['stop_utc'][:19].replace('T', ' ')} UTC on {manifest['machine']['hostname']}; analysed {result['analyzed_at_utc'][:19].replace('T', ' ')} UTC by {ANALYZER['id']} {ANALYZER['version']}. "
             "Read the coverage table first: a source that was not read is not measured, and nothing below claims it was quiet.", "",
             "## What was measured", "", "| Source | Collector status | Why |", "|---|---|---|"]
    for c in coverage:
        if c["kind"] != "collector":
            continue
        why = (c["collector_status_reason"] or "").replace("|", "/")
        lines.append(f"| {c['id']} | {c['collector_status']} | {why} |")
    lines += ["", "| Decoded table | Status | Rows |", "|---|---|---|"]
    for c in coverage:
        if c["kind"] == "table":
            lines.append(f"| {c['id']} | {c['decoded_status']} | {'' if c['rows'] is None else c['rows']} |")
    lines += ["", f"Analyzer status: {result['status']}" + (f" ({result['status_reason']})" if result["status_reason"] else "") + ".", ""]
    sections = [("traffic_path", "## 1. Which connection carries the PC's traffic"), ("wifi_24ghz", "## 2. The 2.4 GHz airspace around the desk"),
                ("usb_receiver", "## 3. Where the wireless receivers sit"), ("unused_radio", "## 4. Radios that are on"),
                ("placement", "## 5. Receiver placement, distance and line of sight"), ("wlan_events", "## 6. Wi-Fi service events")]
    for kind, heading in sections:
        group = [f for f in findings if f["kind"] == kind]
        if not group:
            continue
        lines += [heading, ""]
        if kind == "wifi_24ghz" and channels:
            lines += ["| Channel | Access points here | Strongest here | Networks within four channels (your router excluded) | Strongest of those | Your router | Non overlapping |", "|---|---|---|---|---|---|---|"]
            for c in channels:
                if c["bss_count"] == 0 and not c["candidate"]:
                    continue
                lines.append(f"| {c['channel']} | {c['bss_count']} | {fmt_pct(c['strongest_signal_pct'])} | {c['overlap_bss_count']} | {fmt_pct(c['overlap_strongest_signal_pct'])} | {'yes' if c['own_router_here'] else ''} | {'yes' if c['candidate'] else ''} |")
            lines.append("")
        for f in group:
            lines += [f"### {f['title']}", "", f["statement"], ""]
            if f["recommendation"]:
                lines += [f"Try: {f['recommendation']}", ""]
            if f["evidence_row_ids"]:
                lines += ["Evidence rows: " + ", ".join(f["evidence_row_ids"]) + ".", ""]
            elif not f["measured"]:
                lines += ["Not measured by this survey; the guidance above is cited, not observed here.", ""]
            lines += ["Sources: " + "; ".join(c["title"].split(":")[0] for c in f["citations"]) + ".", ""]
    lines += ["## What this survey can and cannot prove", "",
              "It can show which networks and channels are on the air around the desk, which adapter carries the PC's traffic, where each receiver sits on the USB tree, and which radios are on. "
              "It cannot measure the 2.4 GHz noise floor at the receiver, the speed each USB port negotiated, the distance or obstacles between receiver and mouse, or whether any of this is what the mouse and headset suffer from. "
              "Only the before and after test in docs/rf-survey.md can show that, one change at a time. Network names and addresses in this report are pseudonyms chosen by the collector; the same network keeps the same pseudonym inside this bundle only.", "",
              "## Sources", ""]
    seen = set()
    for f in findings:
        for c in f["citations"]:
            if c["url"] not in seen:
                seen.add(c["url"])
                lines.append(f"- {c['title']}. {c['url']}")
    return "\n".join(lines) + "\n"


def fmt_pct(value: int | None) -> str:
    return "" if value is None else f"{value}%"


def describe_load(channel: int, load: tuple[int, int]) -> str:
    count, strongest = load
    if count == 0:
        return f"channel {channel}: no other network within four channels"
    return f"channel {channel}: {count} network{'s' if count != 1 else ''} within four channels, strongest {strongest}%"


# ---------------------------------------------------------------- entry point

def analyze(bundle: Path, analyzed_at: str | None = None) -> dict[str, Any]:
    analyzed_at = analyzed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    entries = {c["id"]: c for c in manifest["collectors"]}
    tables = load_tables(bundle)
    ev = Evidence(manifest["capture"]["stop_utc"], analyzed_at)
    findings: list[dict[str, Any]] = []
    channels: list[dict[str, Any]] = []
    status, reason = "observed", None
    if not any(t["status"] in OBSERVED for t in tables.values()):
        status, reason = "not_collected", "no decoded table of this bundle is readable; run scripts/decode_rf_survey.py first"
    else:
        try:
            traffic = analyze_traffic_path(tables, entries, ev)
            findings.append(traffic["finding"])
            airspace = analyze_airspace(tables, entries, ev)
            findings += airspace["findings"]
            channels = airspace["channels"]
            findings += analyze_receivers(tables, entries, ev)
            findings += analyze_unused_radios(tables, entries, ev, traffic["default_interface"])
            findings.append(placement_finding())
            findings += analyze_events(tables, entries, ev)
        except Exception as exc:  # noqa: BLE001 - the contract wants analyzer_failed, not a traceback in the bundle
            status, reason, findings, channels = "analyzer_failed", f"{type(exc).__name__}: {exc}", [], []
            ev.rows = []
        if status == "observed" and not ev.rows:
            status, reason = "observed_zero", "the tables were readable and yielded no evidence row"
    errors = wf_schema.validate_rows(ev.rows, "evidence.schema.json")
    if errors:
        status, reason, findings = "analyzer_failed", "evidence rows fail their schema: " + "; ".join(errors[:3]), []
        ev.rows = []
    result = {"analyzer": ANALYZER, "analyzed_at_utc": analyzed_at, "bundle_id": manifest["bundle_id"], "status": status, "status_reason": reason,
              "coverage": coverage_table(manifest, tables), "findings": findings, "channels_24ghz": channels, "report_path": "reports/rf-survey.md"}
    result_errors = wf_schema.validate_object(result, "analysis/rf_survey.schema.json")
    if result_errors:
        raise SystemExit(f"internal error: the analysis result fails its schema: {result_errors[:3]}")
    reports = bundle / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "rf-survey.md").write_text(render_report(manifest, result, findings, channels, result["coverage"]), encoding="utf-8")
    wf_schema.write_json(reports / "rf-survey.json", result)
    evidence_path = bundle / "evidence.jsonl"
    kept = [r for r in wf_schema.read_jsonl(evidence_path) if r.get("analyzer", {}).get("id") != ANALYZER["id"]] if evidence_path.is_file() else []
    wf_schema.write_jsonl(evidence_path, kept + ev.rows)
    return {"status": status, "reason": reason, "evidence_rows": len(ev.rows), "findings": len(findings), "report": str(reports / "rf-survey.md")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--analyzed-at", default=None)
    args = ap.parse_args(argv)
    result = analyze(args.bundle, args.analyzed_at)
    print(f"rf_survey: {result['evidence_rows']} evidence rows, {result['findings']} findings, status {result['status']}; report {result['report']}")
    if result["status"] not in OBSERVED:
        print(f"analysis status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
