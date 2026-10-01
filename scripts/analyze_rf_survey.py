#!/usr/bin/env python3
"""Turn the decoded rf-survey tables into evidence rows and a plain language result.

The PC is on Ethernet. Its wireless mouse and headset share the 2.4 GHz band
with the router, the neighbours' networks, Bluetooth and the noise that USB 3
ports and devices radiate, so this analyzer answers four questions from the
decoded tables and the manifest, never from raw files:

1. which adapter carries the PC's traffic (``net_route`` joined to ``net_adapter``,
   across both address families);
2. how busy each 2.4 GHz channel is around the desk (``wlan_bss``), and, only
   when the owner has named his network, which channel his router should use
   and whether it offers 5 or 6 GHz for the household's other devices;
3. where the wireless receivers sit on the USB tree and whether they share a
   USB 3 (xHCI) controller or hub with USB 3 devices (``pnp_device``);
4. which radios are present and on (``net_adapter``, ``pnp_device``), with the
   limits of what presence proves.

The owner's network is never guessed: a saved profile can be stale and the
strongest signal can be a neighbour's. The owner names it on the Mac with
``--own-network <name as saved on this PC>`` (matched through the saved
profile names the collector kept readable, each with its pseudonym) or
``--own-network-pseudonym ssid-...`` (an access point listed in the
channel table of a report of this bundle; the salt is new on every run, so
a pseudonym from another bundle never matches); only then are all matching access points aggregated and a router
recommendation made. Neighbours stay pseudonyms in every output.

Receiver distance and line of sight cannot be measured by a survey, so that
finding carries cited guidance and a before and after test (docs/rf-survey.md)
instead of evidence rows. Every threshold and every RF claim cites a vendor
or standards document; the citations are listed in CITATIONS and attached to
each finding. A quieter 802.11 channel is not proof about the proprietary
frequencies a mouse or headset receiver uses; the before and after test is
the causal check, and the report says so.

Status follows docs/contracts/measurement-status.md: evidence rows are
``observed`` (confidence 1, provenance into the decoded rows) or ``inferred``
(a recommendation, confidence below 1, linked to the observed rows it rests
on). No absence row is ever written; a source that was not read is reported
as not measured, never as quiet. Each of the six sections runs on its own: a
failure inside one becomes a finding of severity error for that section and
the other sections' evidence stands. The coverage table comes first in every
output.

Writes ``evidence.jsonl`` (replacing its own rows, keeping any other
analyzer's), ``reports/rf-survey.md`` and ``reports/rf-survey.json``
(``schemas/analysis/rf_survey.schema.json``).

Usage::

    python scripts/analyze_rf_survey.py --bundle <bundle directory> [--analyzed-at 2026-09-03T00:00:00Z]
        [--own-network <name>] [--own-network-pseudonym ssid-<12 hex>]
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

ANALYZER = {"id": "rf_survey", "version": "1.2.0"}
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
# Win32 Configuration Manager error code 22: "Device is disabled" (documented on the MSFT_NetAdapter page).
PNP_DISABLED = 22
RECEIVER_CAVEAT = ("A quieter 802.11 channel is evidence about Wi-Fi, not proof about the mouse or headset: their receivers use the vendor's own "
                   "2.4 GHz protocol on frequencies this survey cannot see, so only the before and after test shows whether a change helped.")

CITATIONS = {
    "cisco_channels": {"title": "Cisco, WLAN Radio Frequency Design Considerations: each 2.4 GHz channel is 22 MHz wide with 5 MHz separation; only channels 1, 6 and 11 (25 MHz apart) do not overlap",
                       "url": "https://www.cisco.com/en/US/docs/solutions/Enterprise/Mobility/emob30dg/RFDesign.html"},
    "cisco_5ghz": {"title": "Cisco, Wireless RF Reference Guide: the 5 GHz band's 20 MHz channels, 36 to 165 across UNII-1 to UNII-3",
                   "url": "https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/wireless-rf-reference-guide.html"},
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
    "ms_bluetooth_faq": {"title": "Microsoft, Bluetooth FAQ: Bluetooth and Wi-Fi radios both operate in the 2.4 GHz range and can reduce each other's transfer rates; Bluetooth 2.0 and later radios use adaptive frequency hopping, and Windows' shared spectrum channel avoidance is disabled by default unless the OEM enabled it",
                         "url": "https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-faq"},
    "ms_wdi_scan": {"title": "Microsoft, OID_WDI_TASK_SCAN: a Wi-Fi port surveys networks per IEEE 802.11 as a background or user initiated scan, and a scan sends probe requests",
                    "url": "https://learn.microsoft.com/windows-hardware/drivers/netcx/oid-wdi-task-scan"},
    "ms_signal": {"title": "Microsoft, WLAN_AVAILABLE_NETWORK and WLAN_ASSOCIATION_ATTRIBUTES: signal quality 0 is -100 dBm and 100 is -50 dBm, linear between",
                  "url": "https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_available_network"},
    "ms_signal_association": {"title": "Microsoft, WLAN_ASSOCIATION_ATTRIBUTES: the same signal quality mapping for the connected network",
                              "url": "https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_association_attributes"},
    "ms_usb_stack": {"title": "Microsoft, USB host side drivers in Windows: Usbxhci.sys and Usbhub3.sys serve xHCI (USB 3) controllers, Usbehci.sys and Usbhub.sys serve USB 2 controllers",
                     "url": "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture"},
    "ms_usb_faq": {"title": "Microsoft, USB in Windows FAQ: the driver stack follows the host controller type, not the connected device's speed; a USB 3.0 hub appears as a SuperSpeed hub and a USB 2.0 hub",
                   "url": "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-faq--introductory-level"},
    "ms_netadapter": {"title": "Microsoft, MSFT_NetAdapter class: NdisPhysicalMedium 14 is 802.3, 9 is Native 802.11, 10 is BlueTooth; State 3 is Disabled; ConfigManagerErrorCode 22 is a disabled device",
                      "url": "https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter"},
    "ms_netroute": {"title": "Microsoft, Get-NetRoute and MSFT_NetRoute: the next hop of the 0.0.0.0/0 route is the default gateway; AddressFamily 2 is IPv4 and 23 is IPv6",
                    "url": "https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netroute"},
    "ms_location": {"title": "Microsoft, Changes to API behavior for Wi-Fi access and location: without location consent the scan APIs return access denied",
                    "url": "https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes"},
    "ms_wlan_troubleshooting": {"title": "Microsoft, Advanced troubleshooting wireless network connectivity: netsh wlan show networks mode=bssid lists BSSID, signal, channel and radio type; when WlanSvc is stopped the netsh wlan commands say so; the WLAN AutoConfig operational log holds the service's events",
                                "url": "https://learn.microsoft.com/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting"},
    "ms_get_pnpdevice": {"title": "Microsoft, Get-PnpDevice and Win32_PnPEntity: present devices are the ones physically present; presence says nothing about pairing or radio power",
                         "url": "https://learn.microsoft.com/powershell/module/pnpdevice/get-pnpdevice"},
}


def cite(*keys: str) -> list[dict[str, str]]:
    return [CITATIONS[k] for k in keys]


# ---------------------------------------------------------------- loading and formatting

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


def fmt_signal(pct: int | None) -> str:
    """'94% (about -53 dBm)' or 'signal unknown' when netsh printed none."""
    if pct is None:
        return "signal unknown"
    return f"{pct}% (about {pct_to_dbm(pct):.0f} dBm)"


def fmt_pct(value: int | None) -> str:
    return "" if value is None else f"{value}%"


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


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


# ---------------------------------------------------------------- owner selection

def resolve_owner(tables, own_network: str | None, own_pseudonym: str | None) -> dict[str, Any]:
    """The owner's network as a pseudonym, from an explicit selection only; never guessed."""
    owner = {"provided": False, "method": None, "pseudonym": None, "name": None, "matched_access_points": 0, "problem": None}
    fields = tables["netsh_fields"]["rows"] if tables["netsh_fields"]["status"] in OBSERVED else []
    saved = {f["value_text"]: f["value_pseudonym"] for f in fields if f["command"] == "profiles" and f["normalized_key"] == "profile" and f["value_pseudonym"]}
    owner["saved_profile_names"] = sorted(saved)
    if own_pseudonym:
        owner.update(provided=True, method="pseudonym", pseudonym=own_pseudonym)
    elif own_network:
        owner.update(provided=True, method="profile_name", name=own_network)
        if own_network in saved:
            owner["pseudonym"] = saved[own_network]
        else:
            owner["problem"] = (f"the name is not among this PC's saved profiles ({', '.join(sorted(saved)) or 'none readable'}), so it cannot be matched to a pseudonym; "
                                "use --own-network-pseudonym with your access point's pseudonym from the channel table of this bundle's report instead")
    if owner["pseudonym"] and tables["wlan_bss"]["status"] in OBSERVED:
        owner["matched_access_points"] = sum(1 for r in tables["wlan_bss"]["rows"] if r["ssid_pseudonym"] == owner["pseudonym"])
        if owner["matched_access_points"] == 0:
            owner["problem"] = "no access point in the scan carries that name, so no router finding can be made from this bundle"
    return owner


# ---------------------------------------------------------------- the questions

def analyze_traffic_path(tables, entries, ev) -> dict[str, Any]:
    title = "Which connection carries the PC's traffic"
    if tables["net_route"]["status"] not in OBSERVED or tables["net_adapter"]["status"] not in OBSERVED:
        missing = "default_routes" if tables["net_route"]["status"] not in OBSERVED else "net_adapters"
        return {"finding": finding("traffic_path", "traffic_path", "warn", title, f"Not measured: {not_measured(entries, missing, tables)}.",
                                   None, [], cite("ms_netroute", "ms_netadapter"), measured=False), "default_interface": None}
    routes = [r for r in tables["net_route"]["rows"] if r["destination_prefix"] in ("0.0.0.0/0", "::/0")]
    adapters = tables["net_adapter"]["rows"]
    if not routes:
        rid = None
        if tables["net_route"]["rows"]:
            rid = ev.add(signal="default_route_absent", metric="route_count", unit="count", value=0, source="default_routes", subsystem="network",
                         severity="warn", kind="observed", provenance=[r["provenance"] for r in tables["net_route"]["rows"]])
        return {"finding": finding("traffic_path", "traffic_path", "warn", title,
                                   "The routing table holds no default route in either address family, so no adapter was carrying internet traffic when the survey ran.",
                                   None, [rid] if rid else [], cite("ms_netroute"), measured=bool(rid)), "default_interface": None}

    def metric_of(route):
        return route["route_metric"] if route["route_metric"] is not None else 1 << 16

    # Lowest metric across both families; on an equal metric IPv4 first (its family value, 2, sorts before IPv6's 23).
    best = sorted(routes, key=lambda r: (metric_of(r), r["address_family"] if r["address_family"] is not None else 99))[0]
    by_family = {}
    for r in sorted(routes, key=metric_of):
        by_family.setdefault(r["address_family_text"] or "unknown", r)
    adapter = next((a for a in adapters if a["interface_index"] == best["interface_index"]), None)
    medium = adapter["physical_medium_text"] if adapter else None
    carrier = {"802.3": "Ethernet (wired)", "Native 802.11": "Wi-Fi", "BlueTooth": "Bluetooth"}.get(medium or "", medium or "an adapter the survey could not describe")
    provenance = [r["provenance"] for r in by_family.values()] + ([adapter["provenance"]] if adapter else [])
    families = {fam: r["interface_index"] for fam, r in by_family.items()}
    split = len(set(families.values())) > 1
    rid = ev.add(signal="traffic_default_route", metric="route_metric", unit="count", value=best["route_metric"], source="default_routes",
                 subsystem="network", severity="info", kind="observed", provenance=provenance,
                 payload={"address_family": best["address_family_text"], "next_hop": best["next_hop"], "interface_index": best["interface_index"],
                          "interface_alias": best["interface_alias"], "adapter": adapter["interface_description"] if adapter else None,
                          "physical_medium": medium, "carrier": carrier, "families_present": sorted(families),
                          "interface_by_family": families, "families_use_different_interfaces": split,
                          "tie_rule": "lowest route metric across IPv4 and IPv6; on an equal metric IPv4 is listed first"})
    name = adapter["interface_description"] if adapter else best["interface_alias"]
    statement = (f"The PC's internet traffic goes through {name} ({carrier}), the interface behind the {best['address_family_text'] or 'default'} default route "
                 f"to {best['next_hop']} (metric {best['route_metric']}; default routes present for {', '.join(sorted(families))}).")
    if split:
        other = [f"{fam} on interface {idx}" for fam, idx in families.items() if idx != best["interface_index"]]
        statement += f" The address families use different interfaces ({'; '.join(other)}), so both are listed in the evidence row."
    if medium == "802.3":
        statement += (" The Wi-Fi link is not in the path, so the PC's own Wi-Fi connection cannot be the cause of mouse or headset trouble; "
                      "the Wi-Fi adapter is used below only as a receiver that sees the 2.4 GHz networks around the desk.")
    return {"finding": finding("traffic_path", "traffic_path", "info", title, statement, None, [rid], cite("ms_netroute", "ms_netadapter"),
                               details={"carrier": carrier, "address_family": best["address_family_text"], "split_families": split}),
            "default_interface": best["interface_index"]}


def scan_unavailable(tables, entries) -> dict[str, Any]:
    entry = entries.get("wlan_networks")
    reason = not_measured(entries, "wlan_networks", tables)
    zero_records = bool(entry and entry["status"] == "capture_failed" and (entry["status_reason"] or "").startswith("zero records"))
    if zero_records:
        recommendation = ("netsh ran and listed nothing, which is what the location consent rules produce for a session that cannot answer the prompt. "
                          "Run verification item 15 in collectors/windows/README.md (compare the collector account's listing with your own session), then run the survey again.")
        citations = cite("ms_location", "ms_wlan_troubleshooting")
    else:
        recommendation = ("The listing failed for the reason recorded above, not for want of location consent. Check that the WLAN AutoConfig service is running and the "
                          "Wi-Fi adapter is present and enabled (Microsoft's wireless troubleshooting guide), fix that, and run the survey again.")
        citations = cite("ms_wlan_troubleshooting")
    return finding("wifi_scan", "wifi_24ghz", "warn", "The 2.4 GHz airspace around the desk",
                   f"The scan is unavailable, so nothing can be said about the channels around the desk: {reason}.", recommendation, [], citations, measured=False)


def analyze_airspace(tables, entries, ev, owner: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"findings": [], "channels": []}
    if tables["wlan_bss"]["status"] not in OBSERVED:
        result["findings"].append(scan_unavailable(tables, entries))
        return result
    bss = tables["wlan_bss"]["rows"]
    band24 = [r for r in bss if r["band_ghz"] == 2.4 and r["channel"] is not None]
    high = [r for r in bss if r["band_ghz"] in (5, 6)]
    unknown = [r for r in bss if r["band_ghz"] is None or r["channel"] is None]
    if not band24:
        rid = ev.add(signal="wifi_24ghz_bss_count", metric="bss_count", unit="count", value=0, source="wlan_networks", subsystem="network",
                     severity="info", kind="observed", provenance=[r["provenance"] for r in bss]) if bss else None
        result["findings"].append(finding("wifi_24ghz_empty", "wifi_24ghz", "info", "The 2.4 GHz airspace around the desk",
                                          f"The scan lists {plural(len(bss), 'access point')} and none of them on 2.4 GHz"
                                          + (f" ({len(unknown)} with a band or channel the parser could not read)." if unknown else "."),
                                          None, [rid] if rid else [], cite("ms_wlan_troubleshooting")))
        return result

    own_ids: set[str] = set()
    own_rows: list[dict[str, Any]] = []
    if owner["pseudonym"] and owner["matched_access_points"]:
        own_rows = [r for r in bss if r["ssid_pseudonym"] == owner["pseudonym"]]
        own_ids = {r["bssid_pseudonym"] for r in own_rows}
    own_24 = [r for r in own_rows if r["band_ghz"] == 2.4 and r["channel"] is not None]
    own_high = [r for r in own_rows if r["band_ghz"] in (5, 6)]

    # Per channel counts and the overlap load of the three non overlapping channels (the owner's own access points excluded once named).
    by_channel: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in band24:
        by_channel[r["channel"]].append(r)
    channel_rows: list[dict[str, Any]] = []
    load_rids: dict[int, str] = {}
    for channel in range(1, 15):
        here = by_channel.get(channel, [])
        overlap = [r for r in band24 if abs(r["channel"] - channel) <= OVERLAP_DISTANCE and r["bssid_pseudonym"] not in own_ids]
        strongest_here = max((r["signal_pct"] for r in here if r["signal_pct"] is not None), default=None)
        strongest_overlap = max((r["signal_pct"] for r in overlap if r["signal_pct"] is not None), default=None)
        channel_rows.append({"channel": channel, "bss_count": len(here), "strongest_signal_pct": strongest_here,
                             "overlap_bss_count": len(overlap), "overlap_strongest_signal_pct": strongest_overlap,
                             "ssid_pseudonyms": sorted({r["ssid_pseudonym"] for r in here if r["ssid_pseudonym"]}),
                             "own_router_here": any(r["bssid_pseudonym"] in own_ids for r in here), "candidate": channel in CANDIDATE_CHANNELS})
        if here:
            ev.add(signal="wifi_24ghz_bss_count", metric="bss_count", unit="count", value=len(here), source="wlan_networks", subsystem="network",
                   severity="info", kind="observed", provenance=[r["provenance"] for r in here],
                   payload={"channel": channel, "strongest_signal_pct": strongest_here, "strongest_signal_dbm_estimate": pct_to_dbm(strongest_here),
                            "access_points": [{"ssid_pseudonym": r["ssid_pseudonym"], "bssid_pseudonym": r["bssid_pseudonym"], "signal_pct": r["signal_pct"],
                                               "radio_type": r["radio_type"], "has_saved_profile": r["is_known_profile"]} for r in here]})
        if channel in CANDIDATE_CHANNELS:
            load_rids[channel] = ev.add(signal="wifi_24ghz_overlap_load", metric="bss_count", unit="count", value=len(overlap), source="wlan_networks",
                                        subsystem="network", severity="info", kind="observed",
                                        provenance=[r["provenance"] for r in overlap] or [r["provenance"] for r in band24],
                                        payload={"channel": channel, "overlap_distance_channels": OVERLAP_DISTANCE, "excludes_own_router": bool(own_ids),
                                                 "strongest_signal_pct": strongest_overlap, "strongest_signal_dbm_estimate": pct_to_dbm(strongest_overlap)})
    result["channels"] = channel_rows

    def load(channel: int) -> tuple[int, int | None]:
        row = channel_rows[channel - 1]
        return (row["overlap_bss_count"], row["overlap_strongest_signal_pct"])

    def load_rank(channel: int) -> tuple[int, int]:
        count, strongest = load(channel)
        return (count, 101 if strongest is None else strongest)

    def describe_load(channel: int) -> str:
        count, strongest = load(channel)
        if count == 0:
            return f"channel {channel}: no other network within four channels"
        return f"channel {channel}: {plural(count, 'network')} within four channels, strongest {'signal unknown' if strongest is None else f'{strongest}%'}"

    busiest = max(channel_rows, key=lambda c: (c["bss_count"], c["strongest_signal_pct"] or 0))
    strongest_ap = max(band24, key=lambda r: r["signal_pct"] if r["signal_pct"] is not None else -1)
    survey = (f"The scan saw {plural(len(band24), 'access point')} on 2.4 GHz and {len(high)} on 5 or 6 GHz. The busiest 2.4 GHz channel is {busiest['channel']} "
              f"with {plural(busiest['bss_count'], 'access point')}; the strongest 2.4 GHz signal is {strongest_ap['ssid_pseudonym'] or 'a hidden network'} on channel "
              f"{strongest_ap['channel']} at {fmt_signal(strongest_ap['signal_pct'])}. Load of the three non overlapping channels, counting every network within four channels: "
              + ", ".join(describe_load(c) for c in CANDIDATE_CHANNELS) + ".")

    if not own_rows:
        # No owner named: report the airspace, never a router recommendation.
        why = owner["problem"] or "no network was named as yours"
        saved = owner.get("saved_profile_names") or []
        how = ("Run the analysis again with --own-network followed by your Wi-Fi network's name as it is saved on this PC"
               + (f" (saved profiles: {', '.join(saved)})" if saved else " (no saved profile was readable)")
               + ", or --own-network-pseudonym followed by the ssid- pseudonym of your access point from the Networks here column of the channel table in this report, and the report will aggregate every access point "
               "of that network and recommend a channel for it. A saved profile alone is not taken as proof: profiles go stale and the strongest signal can be a neighbour's.")
        result["findings"].append(finding("wifi_24ghz_survey", "wifi_24ghz", "info", "The 2.4 GHz airspace around the desk",
                                          survey + f" Which of these is your router is not known to the analysis ({why}), so no router change is recommended. " + RECEIVER_CAVEAT,
                                          how, list(load_rids.values()), cite("cisco_channels", "intel_protocols", "ms_signal", "ms_wlan_troubleshooting"),
                                          details={"owner_named": False, "bss_24ghz": len(band24), "bss_high": len(high), "unparsed": len(unknown),
                                                   "candidate_loads": {str(c): list(load(c)) for c in CANDIDATE_CHANNELS}}))
    else:
        own_rid = ev.add(signal="own_network_selected", metric="bss_count", unit="count", value=len(own_rows), source="wlan_networks", subsystem="network",
                         severity="info", kind="observed", provenance=[r["provenance"] for r in own_rows],
                         payload={"method": owner["method"], "ssid_pseudonym": owner["pseudonym"], "access_points": [
                             {"bssid_pseudonym": r["bssid_pseudonym"], "band_ghz": r["band_ghz"], "channel": r["channel"], "signal_pct": r["signal_pct"], "radio_type": r["radio_type"]} for r in own_rows]})
        own_channels = sorted({r["channel"] for r in own_24})
        best = min(CANDIDATE_CHANNELS, key=load_rank)
        own_text = ", ".join(f"channel {ch} ({', '.join(fmt_signal(r['signal_pct']) for r in own_24 if r['channel'] == ch)})" for ch in own_channels) or "no 2.4 GHz access point"
        statement = (survey + f" Your network ({owner['pseudonym']}, named by you{' as ' + owner['name'] if owner['name'] else ''}) has {plural(len(own_rows), 'access point')} in the scan: "
                     f"{plural(len(own_24), 'on 2.4 GHz')} at {own_text}, {len(own_high)} on 5 or 6 GHz. " + RECEIVER_CAVEAT)
        if not own_24:
            recommendation = "Your network has no 2.4 GHz access point in this scan, so there is no router channel to change; the household's 2.4 GHz devices are not on it either."
            severity = "info"
        elif all(ch in CANDIDATE_CHANNELS and load_rank(ch) <= load_rank(best) for ch in own_channels) and len(own_channels) == 1:
            recommendation = f"Keep the router on channel {own_channels[0]}: it already has the lowest overlap load of channels 1, 6 and 11."
            severity = "info"
        else:
            nodes = f"all {len(own_24)} of its 2.4 GHz access points" if len(own_24) > 1 else "its 2.4 GHz network"
            recommendation = (f"Move {nodes} to channel {best} ({describe_load(best)}), and set the 2.4 GHz channel width to 20 MHz if the router offers the choice, "
                              f"so it stays inside one non overlapping channel. Change nothing else at the same time and run the before and after test in docs/rf-survey.md.")
            severity = "warn" if any(load(ch)[0] >= 2 for ch in own_channels if ch in CANDIDATE_CHANNELS) or any(ch not in CANDIDATE_CHANNELS for ch in own_channels) else "info"
        rec_rid = ev.add(signal="router_channel_recommendation", metric="channel", unit="none", value=best, source="wlan_networks", subsystem="network",
                         severity=severity, kind="inferred", confidence=0.7, links=[own_rid] + [load_rids[c] for c in CANDIDATE_CHANNELS],
                         payload={"recommended_channel": best, "current_channels": own_channels,
                                  "rule": "lowest count of networks within four channels, then lowest strongest signal, the named network's own access points excluded",
                                  "citations": [CITATIONS["cisco_channels"]["url"], CITATIONS["intel_protocols"]["url"]]})
        result["findings"].append(finding("wifi_24ghz_congestion", "wifi_24ghz", severity, "The 2.4 GHz airspace around the desk and your router", statement, recommendation,
                                          [own_rid] + list(load_rids.values()) + [rec_rid], cite("cisco_channels", "intel_protocols", "ms_signal", "ms_wlan_troubleshooting"),
                                          details={"owner_named": True, "recommended_channel": best, "own_channels": own_channels, "own_access_points": len(own_rows),
                                                   "bss_24ghz": len(band24), "bss_high": len(high), "unparsed": len(unknown)}))
        if own_high:
            rids = [ev.add(signal="wifi_high_band_bss", metric="signal_quality", unit="pct", value=r["signal_pct"], source="wlan_networks", subsystem="network",
                           severity="info", kind="observed", provenance=[r["provenance"]],
                           payload={"channel": r["channel"], "band_ghz": r["band_ghz"], "radio_type": r["radio_type"], "same_network_as_selected": True}) for r in own_high]
            rec = ev.add(signal="move_household_devices_off_24ghz", metric="bss_count", unit="count", value=len(own_high), source="wlan_networks", subsystem="network",
                         severity="info", kind="inferred", confidence=0.7, links=[own_rid] + rids)
            bands = sorted({r["band_ghz"] for r in own_high})
            result["findings"].append(finding("wifi_high_band_available", "wifi_24ghz", "info", "Your network also offers 5 or 6 GHz",
                                              f"Your network is on the air on {plural(len(own_high), 'access point')} at {' and '.join(f'{b:g} GHz' for b in bands)} "
                                              f"(channel {own_high[0]['channel']}, {fmt_signal(own_high[0]['signal_pct'])}). 802.11a, 802.11ac and 5 GHz 802.11n and ax traffic does not share the band the receivers use.",
                                              "Connect the household's phones, tablets, TVs and laptops to that band so they stop transmitting on 2.4 GHz near the desk; if the router offers a band steering or separate name option, give the higher band its own name so devices do not fall back to 2.4 GHz.",
                                              rids + [rec], cite("intel_protocols", "cisco_5ghz", "cisco_channels")))
        else:
            result["findings"].append(finding("wifi_high_band_absent", "wifi_24ghz", "info", "No 5 or 6 GHz access point of your network was seen",
                                              f"None of your network's access points is on 5 or 6 GHz in this scan ({len(high)} other access points were seen there, so the adapter can see those bands). "
                                              "Either the router has no higher band, it is switched off, or it uses another name.",
                                              "Check the router's settings: if it has a 5 GHz band, switch it on and move the household's other devices to it; a separate name keeps them off the band the receivers use.",
                                              [own_rid], cite("intel_protocols", "cisco_5ghz")))
    if unknown:
        result["findings"].append(finding("wifi_unparsed", "wifi_24ghz", "info", "Access points the parser could not place",
                                          f"{plural(len(unknown), 'access point')} had no band or channel the parser could read; they are in the wlan_bss table with null fields and the raw netsh text is in the bundle.",
                                          None, [], cite("ms_wlan_troubleshooting")))
    return result


def analyze_receivers(tables, entries, ev) -> list[dict[str, Any]]:
    if tables["pnp_device"]["status"] not in OBSERVED:
        return [finding("usb_receivers", "usb_receiver", "warn", "Where the wireless receivers sit",
                        f"Not measured: {not_measured(entries, 'usb_device_tree', tables)}.", None, [], cite("ms_usb_stack"), measured=False)]
    devices = [r for r in tables["pnp_device"]["rows"] if r["source_id"] == "usb_device_tree"]
    if not devices:
        return [finding("usb_receivers", "usb_receiver", "warn", "Where the wireless receivers sit",
                        f"Not measured: {not_measured(entries, 'usb_device_tree', tables)}.", None, [], cite("ms_usb_stack"), measured=False)]
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
                           f"No USB device announced itself as a receiver or dongle by name. {plural(len(hid), 'input or audio device')} sit on USB; each is listed in the pnp_device table with its controller, "
                           "so the receiver can be identified by unplugging it and comparing.", None, [controller_rid], cite("ms_usb_stack")))
        return out
    separation = ("First, physical separation, which is what Intel measured and Logitech advises: put the receiver on a short USB extension cable so it sits as far from the case's USB 3 connectors "
                  "and any USB 3 drive or hub as possible and as close to the mouse or headset as possible, in direct line of sight.")
    for receiver in receivers:
        siblings = [r for r in devices if r["parent_instance_id"] and r["parent_instance_id"].upper() == receiver["parent_instance_id"].upper()
                    and r["instance_id"] != receiver["instance_id"] and not r["is_bluetooth_radio"]]
        controller = controllers.get(receiver["controller_instance_id"] or "")
        hub = by_id.get((receiver["parent_instance_id"] or "").upper())
        name = receiver["bus_reported_description"] or receiver["name"] or receiver["instance_id"]
        sibling_names = ", ".join((s["bus_reported_description"] or s["name"] or s["instance_id"]) for s in siblings)
        rid = ev.add(signal="usb_receiver_candidate", metric="usb_stack_is_xhci", unit="bool", value=(receiver["usb_stack"] == "usb3_xhci"),
                     source="usb_device_tree", subsystem="input", severity="info", kind="observed",
                     provenance=[receiver["provenance"]] + ([hub["provenance"]] if hub else []) + ([controller["provenance"]] if controller else []),
                     payload={"name": name, "vendor_id": receiver["vendor_id"], "product_id": receiver["product_id"], "location_path": receiver["location_path"],
                              "location_info": receiver["location_info"], "hub": hub["name"] if hub else None, "hub_service": hub["service"] if hub else None,
                              "controller": controller["name"] if controller else None, "usb_stack": receiver["usb_stack"],
                              "devices_on_same_hub": [{"name": s["bus_reported_description"] or s["name"], "location_path": s["location_path"], "service": s["service"]} for s in siblings]})
        where = f"port {receiver['location_info'] or receiver['location_path']} of {hub['name'] if hub else 'an unknown hub'}"
        tree_note = ("The device tree names the controller and hub chain, not the speed each port negotiated or which socket on the case the port is, "
                     "so this says the receiver shares a USB 3 capable controller, not that USB 3 traffic runs next to it.")
        if receiver["usb_stack"] == "usb3_xhci":
            statement = (f"{name} sits on {where}, served by the USB 3 host controller ({controller['name'] if controller else 'xHCI'}). {tree_note} "
                         + (f"Other devices on the same hub: {sibling_names}." if siblings else "No other device shares that hub."))
            recommendation = separation
            if ehci:
                recommendation += (f" Second, this PC also has a USB 2 host controller ({ehci[0]['name']}); a port it serves helps only if that socket is also away from the USB 3 connectors, "
                                   "and the tree cannot say which socket that is, so try it as a second step and judge it by the before and after test.")
            else:
                recommendation += " This PC exposes only USB 3 (xHCI) host controllers, so there is no USB 2 only port to move to; the extension cable is the change to try."
            recommendation += " Change one thing at a time and run the before and after test."
            severity = "warn"
        elif receiver["usb_stack"] == "usb2_ehci":
            statement = (f"{name} sits on {where}, served by the USB 2 host controller ({controller['name'] if controller else 'EHCI'}), so it does not share a USB 3 controller. {tree_note} "
                         + (f"Other devices on the same hub: {sibling_names}." if siblings else "No other device shares that hub."))
            recommendation = ("No controller change is indicated by the tree. If USB 3 drives, hubs or connectors sit next to this socket on the case, the extension cable and the before and after test "
                              "with them unplugged tell whether their noise reaches the receiver.")
            severity = "info"
        else:
            statement = f"{name} sits on {where}; the host controller type could not be resolved from the device tree."
            recommendation = separation + " Follow the receiver's chain in the pnp_device table by hand to learn its controller."
            severity = "info"
        rec_rid = ev.add(signal="usb_receiver_relocation", metric="usb_stack_is_xhci", unit="bool", value=(receiver["usb_stack"] == "usb3_xhci"), source="usb_device_tree",
                         subsystem="input", severity=severity, kind="inferred", confidence=0.6, links=[rid, controller_rid],
                         payload={"ehci_available": bool(ehci), "first_step": "physical separation with a short extension cable", "recommendation": recommendation})
        out.append(finding(f"usb_receiver_{receiver['vendor_id'] or 'x'}_{receiver['product_id'] or 'x'}".lower(), "usb_receiver", severity, f"Receiver: {name}",
                           statement, recommendation, [rid, controller_rid, rec_rid], cite("intel_usb3", "logitech_usb3", "logitech_interference", "ms_usb_stack", "ms_usb_faq"),
                           details={"usb_stack": receiver["usb_stack"], "ehci_available": bool(ehci)}))
    noisy = [r for r in devices if r["usb_stack"] == "usb3_xhci" and not r["is_root_hub"] and not r["is_receiver_candidate"] and not r["is_bluetooth_radio"]
             and ((r["service"] or "").upper() == "USBSTOR" or ((r["class"] or "").upper() == "USB" and "HUB" in (r["name"] or "").upper()))]
    if noisy:
        rids = [ev.add(signal="usb3_stack_device", metric="device_count", unit="count", value=1, source="usb_device_tree", subsystem="input", severity="info",
                       kind="observed", provenance=[r["provenance"]], payload={"name": r["bus_reported_description"] or r["name"], "location_path": r["location_path"], "service": r["service"]}) for r in noisy]
        out.append(finding("usb3_noise_sources", "usb_receiver", "info", "Storage and hubs on the USB 3 controller",
                           "These devices hang off the USB 3 controller: " + ", ".join(f"{r['bus_reported_description'] or r['name']} ({r['location_info'] or r['location_path']})" for r in noisy)
                           + ". Windows does not expose whether each one runs at USB 3 speed, so they are suspects, not culprits: a USB 3 drive or hub next to a receiver is the case Intel measured.",
                           "During the before and after test, unplug these one at a time while watching the mouse and headset; if one of them matters, move it to a port far from the receivers or onto its own cable away from the desk.",
                           rids, cite("intel_usb3", "logitech_interference", "ms_usb_faq")))
    return out


def analyze_radios(tables, entries, ev, default_interface: int | None) -> list[dict[str, Any]]:
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
            connected = f" It is connected to network {connected_ssid} (a pseudonym; the PC's traffic still leaves over Ethernet)." if connected_ssid else ""
            rec = ev.add(signal="unused_radio_could_be_off", metric="adapter_enabled", unit="bool", value=True, source="net_adapters", subsystem="network",
                         severity="info", kind="inferred", confidence=0.6, links=[rid], payload={"radio": "wifi", "adapter": a["interface_description"]})
            out.append(finding("wifi_adapter_unused", "unused_radio", "info", "The Wi-Fi adapter is on but carries no traffic",
                               f"{a['interface_description']} is {a['pnp_state_text'] or 'present'}, {a['operational_status_text'] or 'status unknown'}, {a['media_connect_state_text'] or 'connection state unknown'}, and it is not the interface behind the default route.{connected}"
                               " An enabled Wi-Fi adapter may issue background scans, and an active scan sends probe requests on the 2.4 GHz band the receivers listen on; how often an idle adapter scans is not documented.",
                               "If you do not use Wi-Fi on this PC, turn the adapter off yourself (Settings, Network and internet, Wi-Fi) and see whether the mouse and headset improve; the collector never changes it. Turn it back on when you want to run this survey again, because the survey needs it to see the networks around the desk.",
                               [rid, rec], cite("ms_wdi_scan", "ms_netadapter")))
    devices = tables["pnp_device"]["rows"] if tables["pnp_device"]["status"] in OBSERVED else []
    radios = [r for r in devices if r["source_id"] == "bluetooth_devices" and r["is_bluetooth_radio"]]
    peers = [r for r in devices if r["source_id"] == "bluetooth_devices" and r["is_bluetooth_peer_node"]]
    bt_entry = entries.get("bluetooth_devices")
    limits = ("Presence in the device tree says nothing about pairing or about the radio switch in Settings, neither of which this survey measures. Bluetooth shares the 2.4 GHz band with the receivers; "
              "Bluetooth 2.0 and later radios hop around busy channels on their own, and Windows' shared spectrum avoidance is off unless the PC's maker enabled it.")
    if radios:
        radio = radios[0]
        disabled = radio["problem_code"] == PNP_DISABLED
        rid = ev.add(signal="bluetooth_device_nodes", metric="peer_node_count", unit="count", value=len(peers), source="bluetooth_devices", subsystem="network",
                     severity="info", kind="observed", provenance=[r["provenance"] for r in radios] + [r["provenance"] for r in peers],
                     payload={"radio": radio["name"], "radio_status": radio["status"], "radio_problem_code": radio["problem_code"], "radio_disabled_in_device_manager": disabled,
                              "peer_nodes": [{"name_pseudonym": p["name"], "instance_id": p["instance_id"]} for p in peers],
                              "not_measured": ["pairing state", "connection state", "radio power switch"]})
        if disabled:
            out.append(finding("bluetooth_disabled", "unused_radio", "info", "The Bluetooth radio is disabled in Device Manager",
                               f"The Bluetooth radio {radio['name']} is present with problem code {PNP_DISABLED} (device is disabled), and {plural(len(peers), 'remembered peer device node')} are present. {limits}",
                               None, [rid], cite("ms_bluetooth_faq", "ms_netadapter", "ms_get_pnpdevice")))
        else:
            recommendation = ("If you do not use Bluetooth on this PC, turn it off yourself in Settings and include that step in the before and after test; the collector never changes it."
                              if not peers else
                              "If the remembered devices are not in use at the desk, turning Bluetooth off in Settings during the before and after test shows whether it matters; the collector never changes it.")
            rec = ev.add(signal="unused_radio_could_be_off", metric="peer_node_count", unit="count", value=len(peers), source="bluetooth_devices", subsystem="network",
                         severity="info", kind="inferred", confidence=0.5, links=[rid], payload={"radio": "bluetooth", "adapter": radio["name"]})
            out.append(finding("bluetooth_present", "unused_radio", "info", "A Bluetooth radio is present",
                               f"The Bluetooth radio {radio['name']} is present with no problem code, and {plural(len(peers), 'remembered peer device node')} are present (their names and addresses are pseudonyms). {limits}",
                               recommendation, [rid, rec], cite("ms_bluetooth_faq", "ms_get_pnpdevice")))
    elif bt_entry is not None and bt_entry["status"] == "observed_zero":
        out.append(finding("bluetooth_no_node", "unused_radio", "info", "No Bluetooth device node is present",
                           "The device enumeration completed and lists no present Bluetooth device node. That is consistent with a PC without a Bluetooth radio; it is not a measurement of a radio switch, which the survey does not read.",
                           None, [], cite("ms_get_pnpdevice", "ms_bluetooth_faq")))
    elif bt_entry is None or bt_entry["status"] not in OBSERVED:
        out.append(finding("bluetooth_not_measured", "unused_radio", "warn", "Bluetooth not measured", f"Not measured: {not_measured(entries, 'bluetooth_devices', tables)}.", None, [], cite("ms_bluetooth_faq"), measured=False))
    return out


def placement_finding() -> dict[str, Any]:
    return finding("receiver_placement", "placement", "info", "Receiver distance and line of sight (not measurable here)",
                   "No survey can measure how far the receiver is from the mouse and headset or what sits between them. Vendor guidance: keep as little distance as possible between receiver and device, "
                   "put the receiver in direct line of sight (a front panel port rather than the back of a PC under the desk), keep metal objects and other electronics out of the path, "
                   "keep it away from USB 3.0 connectors and devices, and keep phones, routers and microwaves away from the work area. " + RECEIVER_CAVEAT,
                   "Run the before and after test in docs/rf-survey.md: change one thing at a time (extension cable and placement first, then receiver port, USB 3 devices, Wi-Fi adapter off, Bluetooth off, router channel), "
                   "judge the mouse by tracking smoothness and missed clicks over a minute of normal play, and the headset by dropouts and crackle over the same minute, and write both down before and after each change.",
                   [], cite("logitech_interference", "logitech_distance", "logitech_usb3", "intel_usb3"), measured=False)


def analyze_events(tables, entries, ev) -> list[dict[str, Any]]:
    entry = entries.get("wlan_autoconfig_events")
    if entry is None:
        return []
    if entry["status"] not in OBSERVED or tables["eventlog_events"]["status"] not in OBSERVED:
        return [finding("wlan_events_not_measured", "wlan_events", "info", "Wi-Fi service events", f"Not measured: {not_measured(entries, 'wlan_autoconfig_events', tables)}.", None, [], cite("ms_wlan_troubleshooting"), measured=False)]
    rows = [r for r in tables["eventlog_events"]["rows"] if "WLAN-AutoConfig" in (r["log_name"] or "")]
    window = entry.get("raw_time_range") or {}
    span = f" ({window['start'][:10]} to {window['end'][:10]})" if window.get("start") and window.get("end") else ""
    if not rows:
        return [finding("wlan_events_quiet", "wlan_events", "info", "Wi-Fi service events", f"The WLAN AutoConfig operational log holds no event in the window{span}.", None, [], cite("ms_wlan_troubleshooting"))]
    counts = Counter(r["event_id"] for r in rows)
    rids = [ev.add(signal="wlan_autoconfig_event_count", metric="event_count", unit="count", value=count, source="wlan_autoconfig_events", subsystem="network",
                   severity="info", kind="observed", provenance=[r["provenance"] for r in rows if r["event_id"] == event_id], payload={"event_id": event_id})
            for event_id, count in counts.most_common()]
    text = "; ".join(f"id {event_id}: {count}" for event_id, count in counts.most_common(8))
    return [finding("wlan_events_summary", "wlan_events", "info", "Wi-Fi service events",
                    f"{plural(len(rows), 'WLAN AutoConfig event')} in the window{span}, by event id: {text}. They describe the PC's own Wi-Fi service, not the receivers. "
                    "The collector keeps only each record's System section (the message and data can name networks), so the ids are what there is to count.",
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


SECTIONS = [("traffic_path", "## 1. Which connection carries the PC's traffic"), ("wifi_24ghz", "## 2. The 2.4 GHz airspace around the desk"),
            ("usb_receiver", "## 3. Where the wireless receivers sit"), ("unused_radio", "## 4. Radios that are present"),
            ("placement", "## 5. Receiver placement, distance and line of sight"), ("wlan_events", "## 6. Wi-Fi service events")]


def render_report(manifest, result: dict[str, Any], findings: list[dict[str, Any]], channels: list[dict[str, Any]], coverage) -> str:
    owner = result["owner"]
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
    lines += ["", f"Analyzer status: {result['status']}" + (f" ({result['status_reason']})" if result["status_reason"] else "") + ".",
              ("Your network: " + (f"{owner['pseudonym']} ({owner['method'].replace('_', ' ')}{', ' + owner['name'] if owner['name'] else ''}), {plural(owner['matched_access_points'], 'access point')} in the scan."
                                   if owner["pseudonym"] else "not named; the airspace is reported without a router recommendation.")
               + (f" {owner['problem']}." if owner["problem"] else "")), ""]
    for kind, heading in SECTIONS:
        group = [f for f in findings if f["kind"] == kind]
        if not group:
            continue
        lines += [heading, ""]
        if kind == "wifi_24ghz" and channels:
            lines += ["| Channel | Access points here | Strongest here | Networks within four channels" + (" (yours excluded)" if owner["pseudonym"] else "") + " | Strongest of those | Yours | Non overlapping | Networks here |", "|---|---|---|---|---|---|---|---|"]
            for c in channels:
                if c["bss_count"] == 0 and not c["candidate"]:
                    continue
                lines.append(f"| {c['channel']} | {c['bss_count']} | {fmt_pct(c['strongest_signal_pct'])} | {c['overlap_bss_count']} | {fmt_pct(c['overlap_strongest_signal_pct'])} | {'yes' if c['own_router_here'] else ''} | {'yes' if c['candidate'] else ''} | {', '.join(c['ssid_pseudonyms'])} |")
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
              "It can show which networks and channels are on the air around the desk, which adapter carries the PC's traffic, where each receiver sits on the USB tree, and which radios are present. "
              "It cannot measure the 2.4 GHz noise floor at the receiver, the frequencies the mouse and headset receivers use, the speed each USB port negotiated, which socket a port is, "
              "the distance or obstacles between receiver and mouse, whether Bluetooth is paired or switched on, or whether any of this is what the mouse and headset suffer from. "
              "Only the before and after test in docs/rf-survey.md can show that, one change at a time. Network names, addresses and Bluetooth peer names in this report are pseudonyms chosen by the collector "
              "(this PC's saved Wi-Fi profiles excepted); the same value keeps the same pseudonym inside this bundle only.", "",
              "## Sources", ""]
    seen = set()
    for f in findings:
        for c in f["citations"]:
            if c["url"] not in seen:
                seen.add(c["url"])
                lines.append(f"- {c['title']}. {c['url']}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- entry point

def run_section(name: str, kind: str, title: str, fn, findings: list[dict[str, Any]], failures: list[str]):
    """Run one section; a failure becomes a finding of severity error and leaves the other sections alone."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - the contract wants a section level failure, not a traceback in the bundle
        failures.append(name)
        findings.append(finding(f"{name}_failed", kind, "error", f"{title}: analysis failed",
                                f"This section could not be analysed ({type(exc).__name__}: {exc}). Evidence rows it had already written stand; its findings are missing.",
                                None, [], cite("ms_wlan_troubleshooting"), measured=False))
        return None


def analyze(bundle: Path, analyzed_at: str | None = None, own_network: str | None = None, own_network_pseudonym: str | None = None) -> dict[str, Any]:
    analyzed_at = analyzed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    entries = {c["id"]: c for c in manifest["collectors"]}
    tables = load_tables(bundle)
    ev = Evidence(manifest["capture"]["stop_utc"], analyzed_at)
    findings: list[dict[str, Any]] = []
    failures: list[str] = []
    channels: list[dict[str, Any]] = []
    owner = resolve_owner(tables, own_network, own_network_pseudonym)
    status, reason = "observed", None
    if not any(t["status"] in OBSERVED for t in tables.values()):
        status, reason = "not_collected", "no decoded table of this bundle is readable; run scripts/decode_rf_survey.py first"
    else:
        traffic = run_section("traffic", "traffic_path", "Which connection carries the PC's traffic", lambda: analyze_traffic_path(tables, entries, ev), findings, failures)
        default_interface = traffic["default_interface"] if traffic else None
        if traffic:
            findings.append(traffic["finding"])
        airspace = run_section("airspace", "wifi_24ghz", "The 2.4 GHz airspace around the desk", lambda: analyze_airspace(tables, entries, ev, owner), findings, failures)
        if airspace:
            findings += airspace["findings"]
            channels = airspace["channels"]
        receivers = run_section("receivers", "usb_receiver", "Where the wireless receivers sit", lambda: analyze_receivers(tables, entries, ev), findings, failures)
        if receivers:
            findings += receivers
        radios = run_section("radios", "unused_radio", "Radios that are present", lambda: analyze_radios(tables, entries, ev, default_interface), findings, failures)
        if radios:
            findings += radios
        findings.append(placement_finding())
        events = run_section("events", "wlan_events", "Wi-Fi service events", lambda: analyze_events(tables, entries, ev), findings, failures)
        if events:
            findings += events
        if failures:
            reason = "sections failed: " + ", ".join(failures)
        if not ev.rows:
            status = "observed_zero" if not failures else "analyzer_failed"
            reason = reason or "the tables were readable and yielded no evidence row"
    errors = wf_schema.validate_rows(ev.rows, "evidence.schema.json")
    if errors:
        status, reason, findings = "analyzer_failed", "evidence rows fail their schema: " + "; ".join(errors[:3]), []
        ev.rows = []
    owner_out = {k: owner[k] for k in ("provided", "method", "pseudonym", "name", "matched_access_points", "problem")}
    result = {"analyzer": ANALYZER, "analyzed_at_utc": analyzed_at, "bundle_id": manifest["bundle_id"], "status": status, "status_reason": reason,
              "owner": owner_out, "coverage": coverage_table(manifest, tables), "findings": findings, "channels_24ghz": channels, "report_path": "reports/rf-survey.md"}
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
    return {"status": status, "reason": reason, "evidence_rows": len(ev.rows), "findings": len(findings), "failed_sections": failures, "report": str(reports / "rf-survey.md")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--analyzed-at", default=None)
    ap.add_argument("--own-network", default=None, help="your Wi-Fi network's name as saved on the PC; matched through the saved profiles the collector kept readable")
    ap.add_argument("--own-network-pseudonym", default=None, help="the ssid- pseudonym of your access point from the channel table of a report of this bundle (pseudonyms differ between bundles)")
    args = ap.parse_args(argv)
    result = analyze(args.bundle, args.analyzed_at, args.own_network, args.own_network_pseudonym)
    print(f"rf_survey: {result['evidence_rows']} evidence rows, {result['findings']} findings, status {result['status']}; report {result['report']}")
    if result["status"] not in OBSERVED or result["failed_sections"]:
        print(f"analysis status: {result['status']}: {result['reason']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
