"""The rf-survey decoder and analyzer over the synthetic rf-survey bundles.

Five committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a congested 2.4 GHz
airspace whose strongest signal is a neighbour's and whose owner network has two 2.4 GHz access
points plus one on 5 GHz, with the receiver on the USB 3 controller; a clean airspace with the
receiver on USB 2, two remembered Bluetooth peers and no 5 GHz; a PC whose wireless service is
not running; a connected Wi-Fi interface on an Ethernet PC; and a German display language with a
translated SSID label and a Bluetooth radio disabled in Device Manager. Nothing here comes from a
real machine.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

import analyze_rf_survey
import decode_eventlog
import decode_rf_survey
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = ["rf-survey", "rf-survey-clean", "rf-survey-no-wifi", "rf-survey-connected", "rf-survey-non-english"]
OBSERVED = ("observed", "observed_zero")
DASHES = re.compile("[–—]")
TABLES = ["netsh_fields", "wlan_bss", "pnp_device", "net_adapter", "net_route"]
# Neighbours' names, a name only the report and an event carried, every address, and the Bluetooth peers of the fixtures.
SECRETS = ["Neighbour-A", "Neighbour-F", "Nachbar-A", "Unseen-Guest", "02:aa:bb:cc:dd:01", "02-AA-BB-CC-DD-01", "02:aa:bb:cc:dd:99", "02:11:22:33:44:55",
           "Synthetic Earbuds", "Synthetic Game Controller", "Synthetic BLE Mouse", "F0F1F2000001", "F0F1F2000002", "F0F1F2000003"]
OWN = "Harbor-Home"


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str, tag: str = "") -> Path:
        dst = tmp_path / (case + tag)
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


def decoded(bundle: Path) -> dict:
    result = decode_rf_survey.decode(bundle, decoded_at="2026-09-03T00:00:00Z")
    decode_eventlog.decode(bundle, decoded_at="2026-09-03T00:00:00Z")
    return result


def rows(bundle: Path, table: str) -> list[dict]:
    return wf_schema.read_jsonl(bundle / "decoded" / f"{table}.jsonl")


def analysis(bundle: Path, **kwargs) -> dict:
    decoded(bundle)
    analyze_rf_survey.analyze(bundle, analyzed_at="2026-09-03T00:00:00Z", **kwargs)
    return json.loads((bundle / "reports" / "rf-survey.json").read_text(encoding="utf-8"))


def finding(result: dict, fid: str) -> dict:
    matches = [f for f in result["findings"] if f["id"] == fid]
    assert len(matches) == 1, [f["id"] for f in result["findings"]]
    return matches[0]


def has_finding(result: dict, fid: str) -> bool:
    return any(f["id"] == fid for f in result["findings"])


def rewrite_artifact(bundle: Path, relative: str, text: str) -> None:
    """Replace a raw artifact and keep the manifest's size and hash honest, so the bundle still verifies."""
    path = bundle / relative
    path.write_text(text, encoding="utf-8")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            if artifact["path"] == relative:
                artifact["bytes"], artifact["sha256"] = path.stat().st_size, wf_schema.sha256_of(path)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def every_file(bundle: Path) -> list[Path]:
    return [p for p in bundle.rglob("*") if p.is_file()]


# ---------------------------------------------------------------- decoder

@pytest.mark.parametrize("case", CASES)
def test_every_table_validates_and_points_into_its_source(case, bundle_copy):
    bundle = bundle_copy(case)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    listed = {a["path"]: a for c in manifest["collectors"] for a in c["artifacts"]}
    result = decoded(bundle)
    assert result["status"] in OBSERVED
    for table in TABLES:
        info = result["tables"][table]
        meta_path = bundle / "decoded" / f"{table}.meta.json"
        if info["status"] == "not_collected":
            assert not meta_path.exists(), "an absent input is not decoded into an empty table"
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
        table_rows = rows(bundle, table)
        assert wf_schema.validate_rows(table_rows, f"decoded/{table}.schema.json") == []
        assert meta["row_count"] == len(table_rows) == info["rows"]
        assert meta["status"] == info["status"] == ("observed" if table_rows else "observed_zero")
        for src in meta["source_files"]:
            assert listed[src["path"]]["sha256"] == src["sha256"]
        for row in table_rows:
            prov = row["provenance"]
            assert prov["source_file"] in {s["path"] for s in meta["source_files"]}
            assert prov["decoded_table"] == table
    assert verify_bundle.verify(bundle)["ok"]


@pytest.mark.parametrize("case", CASES)
def test_no_neighbour_name_address_or_peer_name_anywhere_after_analysis(case, bundle_copy):
    """The privacy boundary holds in raw/, logs/, manifest.json, decoded/, evidence.jsonl and reports/."""
    bundle = bundle_copy(case)
    analysis(bundle, own_network=OWN)
    for path in every_file(bundle):
        text = path.read_text(encoding="utf-8", errors="replace")
        for secret in SECRETS:
            assert secret not in text, f"{path.relative_to(bundle)} carries {secret}"
        # The owner's saved profile names are readable only in the profiles source, the netsh_fields table built
        # from it, and the analysis outputs after the owner named the network.
        if OWN in text:
            assert path.relative_to(bundle).as_posix().startswith(("raw/wlan_profiles/", "decoded/netsh_fields", "reports/", "evidence.jsonl")), path.relative_to(bundle)


def test_bss_rows_point_at_the_lines_that_carry_them(bundle_copy):
    bundle = bundle_copy("rf-survey")
    decoded(bundle)
    text = (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8").split("\n")
    bss = rows(bundle, "wlan_bss")
    assert len(bss) == 10
    for row in bss:
        a, b = map(int, re.fullmatch(r"line:(\d+)-(\d+)", row["provenance"]["row_id_or_offset"]).groups())
        span = text[a - 1:b]
        assert row["bssid_pseudonym"] in span[0]
        assert any(str(row["channel"]) in line for line in span)
        assert any(f"{row['signal_pct']}%" in line for line in span)
        assert row["signal_dbm_estimate"] == -100 + row["signal_pct"] / 2
    by_channel = {}
    for row in bss:
        by_channel.setdefault((row["band_ghz"], row["channel"]), []).append(row)
    assert len(by_channel[(2.4, 6)]) == 3 and len(by_channel[(2.4, 1)]) == 2 and len(by_channel[(2.4, 11)]) == 2 and len(by_channel[(5, 36)]) == 1
    known = [r for r in bss if r["is_known_profile"]]
    assert len(known) == 3 and {r["band_ghz"] for r in known} == {2.4, 5}, "the saved profile's name is on three access points"
    hidden = [r for r in bss if r["ssid_pseudonym"] is None]
    assert len(hidden) == 1 and hidden[0]["is_known_profile"] is None
    assert all(r["labels_recognised"] for r in bss)


def test_saved_profiles_stay_readable_with_their_pseudonyms(bundle_copy):
    bundle = bundle_copy("rf-survey")
    decoded(bundle)
    fields = rows(bundle, "netsh_fields")
    profiles = [r for r in fields if r["command"] == "profiles" and r["normalized_key"] == "profile"]
    assert [r["value_text"] for r in profiles] == ["Harbor-Home", "Coffee-Guest"]
    assert all(re.fullmatch(r"ssid-[0-9a-f]{12}", r["value_pseudonym"]) for r in profiles)
    bss = rows(bundle, "wlan_bss")
    harbor = profiles[0]["value_pseudonym"]
    assert sum(1 for r in bss if r["ssid_pseudonym"] == harbor) == 3, "the profile's pseudonym is the scan's pseudonym"
    assert not any(r["ssid_pseudonym"] == profiles[1]["value_pseudonym"] for r in bss), "the stale profile is not in the scan"
    others = [r for r in fields if r["command"] != "profiles"]
    assert all(r["value_pseudonym"] is None for r in others)


def test_non_english_output_decodes_by_the_shape_of_the_values(bundle_copy):
    bundle = bundle_copy("rf-survey-non-english")
    result = decoded(bundle)
    assert result["tables"]["wlan_bss"]["status"] == "observed"
    bss = rows(bundle, "wlan_bss")
    assert [(r["band_ghz"], r["channel"], r["signal_pct"], r["radio_type"]) for r in bss] == [
        (2.4, 6, 94, "802.11ax"), (5, 36, 88, "802.11ax"), (2.4, 6, 70, "802.11n"), (2.4, 6, 62, "802.11ax"), (2.4, 11, 35, "802.11n")]
    assert all(r["network_type"] is None for r in bss), "translated labels are not guessed"
    fields = rows(bundle, "netsh_fields")
    keys = {(r["command"], r["normalized_key"]): r for r in fields if r["normalized_key"]}
    assert keys[("interfaces", "guid")]["classified_by"] == "label"
    assert keys[("interfaces", "physical_address")]["classified_by"] == "value"
    assert keys[("interfaces", "ssid")]["classified_by"] == "value" and keys[("interfaces", "ssid")]["value_text"].startswith("ssid-"), "a translated SSID label, caught by structure"
    assert keys[("interfaces", "bssid")]["value_text"].startswith("mac-")
    assert keys[("interfaces", "channel")]["value_number"] == 6
    assert keys[("drivers", "radio_types_supported")]["classified_by"] == "value"
    assert keys[("profiles", "profile")]["value_text"] == "Harbor-Home"
    assert [r for r in fields if r["normalized_key"] is None], "labels the parser does not know stay verbatim with a null key"
    assert "ü" in (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8"), "the raw text keeps its non ASCII characters"


def test_connected_interface_fields_are_pseudonyms(bundle_copy):
    bundle = bundle_copy("rf-survey-connected")
    decoded(bundle)
    fields = {r["normalized_key"]: r for r in rows(bundle, "netsh_fields") if r["command"] == "interfaces" and r["normalized_key"]}
    assert fields["state"]["value_text"] == "connected"
    assert fields["ssid"]["value_text"].startswith("ssid-") and fields["profile"]["value_text"] == fields["ssid"]["value_text"]
    assert fields["bssid"]["value_text"].startswith("mac-") and fields["physical_address"]["value_text"].startswith("mac-")
    assert fields["channel"]["value_number"] == 1 and fields["band"]["value_number"] == 2.4 and fields["signal_pct"]["value_number"] == 90
    assert fields["receive_rate_mbps"]["value_number"] == 144.4


def test_device_rows_resolve_the_controller_and_the_receivers(bundle_copy):
    bundle = bundle_copy("rf-survey")
    decoded(bundle)
    devices = {r["instance_id"]: r for r in rows(bundle, "pnp_device") if r["source_id"] == "usb_device_tree"}
    receiver = devices["USB\\VID_FFF1&PID_0001\\5&1e2f3a4b&0&3"]
    assert receiver["is_receiver_candidate"] and receiver["usb_stack"] == "usb3_xhci"
    assert receiver["controller_service"] == "USBXHCI" and receiver["vendor_id"] == "FFF1" and receiver["product_id"] == "0001"
    assert receiver["hub_chain"][0] == "USB\\ROOT_HUB30\\4&2a1b3c4d&0&0" and receiver["hub_chain"][-1] == "HTREE\\ROOT\\0"
    keyboard = devices["USB\\VID_FFF4&PID_0004\\5&1e2f3a4b&0&1"]
    assert keyboard["usb_stack"] == "usb2_ehci" and not keyboard["is_receiver_candidate"]
    assert devices["USB\\ROOT_HUB30\\4&2a1b3c4d&0&0"]["is_root_hub"]
    radio = devices["USB\\VID_FFF5&PID_0005\\5&1e2f3a4b&0&14"]
    assert radio["is_bluetooth_radio"] and not radio["is_receiver_candidate"]
    adapters = {r["name"]: r for r in rows(bundle, "net_adapter")}
    assert adapters["Ethernet"]["physical_medium_text"] == "802.3" and adapters["Wi-Fi"]["physical_medium_text"] == "Native 802.11"
    routes = rows(bundle, "net_route")
    assert [(r["destination_prefix"], r["address_family_text"], r["protocol_text"]) for r in routes] == [("0.0.0.0/0", "IPv4", "NetMgmt"), ("::/0", "IPv6", "Other")]


def test_bluetooth_peer_nodes_are_pseudonymised_and_not_called_paired(bundle_copy):
    bundle = bundle_copy("rf-survey-clean")
    decoded(bundle)
    bt = [r for r in rows(bundle, "pnp_device") if r["source_id"] == "bluetooth_devices"]
    peers = [r for r in bt if r["is_bluetooth_peer_node"]]
    assert len(peers) == 3
    for peer in peers:
        assert re.fullmatch(r"name-[0-9a-f]{12}", peer["name"])
        assert "mac-" in peer["instance_id"] and "F0F1F2" not in peer["instance_id"]
    # A peer's GATT service and HID nodes carry its address too, in both sources, and the chain survives pseudonymisation.
    for source in ("bluetooth_devices", "usb_device_tree"):
        devices = [r for r in rows(bundle, "pnp_device") if r["source_id"] == source]
        gatt = [r for r in devices if r["instance_id"].startswith("BTHLEDEVICE\\")]
        assert len(gatt) == 1, source
        assert "F0F1F2" not in json.dumps(devices) and "Synthetic BLE Mouse" not in json.dumps(devices)
        assert gatt[0]["parent_instance_id"] in {p["instance_id"] for p in devices if p["is_bluetooth_peer_node"]}
    tree = [r for r in rows(bundle, "pnp_device") if r["source_id"] == "usb_device_tree"]
    mouse = [r for r in tree if r["instance_id"].startswith("HID\\{00001812")]
    assert len(mouse) == 1 and mouse[0]["parent_instance_id"] == next(r["instance_id"] for r in tree if r["instance_id"].startswith("BTHLEDEVICE\\"))
    assert not any("is_bluetooth_peer" in r and r.get("is_bluetooth_peer") for r in bt), "the old flag that implied pairing is gone"


def test_decoder_refuses_a_foreign_bundle_a_missing_primary_and_a_strange_layout(bundle_copy, tmp_path):
    assert decode_rf_survey.decode(bundle_copy("bugcheck-history"), decoded_at="2026-09-03T00:00:00Z")["status"] == "not_applicable"
    assert decode_rf_survey.decode(tmp_path / "nowhere", decoded_at="2026-09-03T00:00:00Z")["status"] == "decode_failed"
    bundle = bundle_copy("rf-survey", "-missing")
    (bundle / "raw" / "wlan_networks" / "output.txt").unlink()
    result = decode_rf_survey.decode(bundle, decoded_at="2026-09-03T00:00:00Z")
    assert result["tables"]["wlan_bss"]["status"] == "decode_failed" and "missing from the bundle" in result["tables"]["wlan_bss"]["reason"]
    assert not (bundle / "decoded" / "wlan_bss.jsonl").exists()
    assert result["tables"]["net_adapter"]["status"] == "observed", "the other tables still decode"
    bundle2 = bundle_copy("rf-survey", "-layout")
    rewrite_artifact(bundle2, "raw/wlan_networks/output.txt", "Interface name : Wi-Fi\nThere are 2 networks currently visible.\n\nsome layout the parser has never seen\n")
    result2 = decode_rf_survey.decode(bundle2, decoded_at="2026-09-03T00:00:00Z")
    assert result2["tables"]["wlan_bss"]["status"] == "decode_failed" and "layout" in result2["tables"]["wlan_bss"]["reason"]
    meta = json.loads((bundle2 / "decoded" / "wlan_bss.meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "decode_failed" and meta["row_count"] == 0


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("rf-survey")), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    assert "wlan_bss: 10 rows from 1 exports, status observed" in capsys.readouterr().out
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("rf-survey-no-wifi")), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("whea-errors-quiet"))]) == 2
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("bugcheck-history"))]) == 2


# ---------------------------------------------------------------- analyzer

@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("own", [None, OWN])
def test_analysis_outputs_validate_and_are_tied_to_evidence(case, own, bundle_copy):
    bundle = bundle_copy(case)
    result = analysis(bundle, own_network=own)
    assert wf_schema.validate_object(result, "analysis/rf_survey.schema.json") == []
    assert result["status"] == "observed" and result["status_reason"] is None
    evidence = wf_schema.read_jsonl(bundle / "evidence.jsonl")
    assert wf_schema.validate_rows(evidence, "evidence.schema.json") == []
    ids = {r["row_id"] for r in evidence}
    assert len(ids) == len(evidence) and all(r["analyzer"]["id"] == "rf_survey" for r in evidence)
    decoded_tables = {t: rows(bundle, t) for t in TABLES + ["eventlog_events"] if (bundle / "decoded" / f"{t}.jsonl").exists()}
    offsets = {(p["decoded_table"], p["source_file"], p["row_id_or_offset"]) for t in decoded_tables.values() for r in t for p in [r["provenance"]]}
    for row in evidence:
        if row["evidence_kind"] == "observed":
            assert row["provenance"] and all((p["decoded_table"], p["source_file"], p["row_id_or_offset"]) in offsets for p in row["provenance"])
        else:
            assert row["evidence_kind"] == "inferred" and row["links"] and set(row["links"]) <= ids and row["confidence"] < 1
    assert not any(r["evidence_kind"] == "absent" for r in evidence), "no absence row without a verdict's coverage table"
    for f in result["findings"]:
        assert f["citations"], f["id"]
        assert all(c["url"].startswith("https://") for c in f["citations"])
        assert set(f["evidence_row_ids"]) <= ids
        if f["recommendation"] and f["measured"]:
            assert f["evidence_row_ids"], f["id"]
        assert f["severity"] != "error"
    assert [c["kind"] for c in result["coverage"]][:10] == ["collector"] * 10, "the coverage table comes first and names every source"
    assert result["owner"]["provided"] is (own is not None)
    report = (bundle / "reports" / "rf-survey.md").read_text(encoding="utf-8")
    assert report.startswith("# RF survey") and "## What was measured" in report and report.index("## What was measured") < report.index("## 1.")
    assert not DASHES.search(report)
    assert "docs/rf-survey.md" in report
    assert verify_bundle.verify(bundle)["ok"]


def test_without_an_owner_no_router_is_named_and_no_router_change_is_recommended(bundle_copy):
    result = analysis(bundle_copy("rf-survey"))
    assert result["owner"] == {"provided": False, "method": None, "pseudonym": None, "name": None, "matched_access_points": 0, "problem": None}
    survey = finding(result, "wifi_24ghz_survey")
    assert survey["details"]["owner_named"] is False
    assert "no router change is recommended" in survey["statement"]
    assert "--own-network" in survey["recommendation"] and "Harbor-Home" in survey["recommendation"], "the saved profile names are offered as the way to name it"
    assert "profiles go stale" in survey["recommendation"] and "strongest signal can be a neighbour" in survey["recommendation"]
    assert "not proof about the mouse or headset" in survey["statement"]
    assert not has_finding(result, "wifi_24ghz_congestion") and not has_finding(result, "wifi_high_band_available") and not has_finding(result, "wifi_high_band_absent")
    channels = {c["channel"]: c for c in result["channels_24ghz"]}
    assert channels[6]["bss_count"] == 3 and channels[6]["overlap_bss_count"] == 4 and channels[6]["strongest_signal_pct"] == 96, "the strongest signal is a neighbour's and nothing is excluded"
    assert not any(c["own_router_here"] for c in result["channels_24ghz"])
    bundle = bundle_copy("rf-survey", "-ev")
    analysis(bundle)
    assert not any(r["signal"] in ("router_channel_recommendation", "own_network_selected", "own_router_identified") for r in wf_schema.read_jsonl(bundle / "evidence.jsonl"))


def test_a_named_network_aggregates_every_access_point_and_gets_a_router_recommendation(bundle_copy):
    result = analysis(bundle_copy("rf-survey"), own_network=OWN)
    assert result["owner"]["method"] == "profile_name" and result["owner"]["matched_access_points"] == 3 and result["owner"]["problem"] is None
    congestion = finding(result, "wifi_24ghz_congestion")
    assert congestion["details"]["own_channels"] == [6, 11] and congestion["details"]["own_access_points"] == 3, "a mesh with two 2.4 GHz nodes is aggregated"
    assert congestion["details"]["recommended_channel"] == 1 and congestion["severity"] == "warn"
    assert congestion["recommendation"].startswith("Move all 2 of its 2.4 GHz access points to channel 1")
    assert "channel 6 (94% (about -53 dBm))" in congestion["statement"] and "channel 11 (60%" in congestion["statement"]
    channels = {c["channel"]: c for c in result["channels_24ghz"]}
    assert channels[6]["own_router_here"] and channels[11]["own_router_here"]
    assert channels[6]["overlap_bss_count"] == 3 and channels[11]["overlap_bss_count"] == 2 and channels[1]["overlap_bss_count"] == 2, "the named network's own access points are excluded from the load"
    assert channels[1]["overlap_strongest_signal_pct"] == 40 and channels[11]["overlap_strongest_signal_pct"] == 55
    high = finding(result, "wifi_high_band_available")
    assert "5 GHz" in high["statement"] and "channel 36" in high["statement"]
    assert analyze_rf_survey.CITATIONS["cisco_5ghz"]["url"] in {c["url"] for c in high["citations"]}
    # The same selection by pseudonym gives the same result.
    by_pseudonym = analysis(bundle_copy("rf-survey", "-pseudonym"), own_network_pseudonym=result["owner"]["pseudonym"])
    assert by_pseudonym["owner"]["method"] == "pseudonym" and finding(by_pseudonym, "wifi_24ghz_congestion")["details"] == congestion["details"]


def test_a_stale_profile_or_an_unknown_name_never_produces_a_router_finding(bundle_copy):
    stale = analysis(bundle_copy("rf-survey", "-stale"), own_network="Coffee-Guest")
    assert stale["owner"]["matched_access_points"] == 0 and "no access point in the scan carries that name" in stale["owner"]["problem"]
    assert has_finding(stale, "wifi_24ghz_survey") and not has_finding(stale, "wifi_24ghz_congestion")
    assert "no access point in the scan carries that name" in finding(stale, "wifi_24ghz_survey")["statement"]
    unknown = analysis(bundle_copy("rf-survey", "-unknown"), own_network="Not-Saved-Here")
    assert unknown["owner"]["pseudonym"] is None and "not among this PC's saved profiles" in unknown["owner"]["problem"]
    assert has_finding(unknown, "wifi_24ghz_survey") and not has_finding(unknown, "wifi_24ghz_congestion")


def test_clean_airspace_keeps_the_channel_and_says_the_higher_band_is_absent(bundle_copy):
    result = analysis(bundle_copy("rf-survey-clean"), own_network=OWN)
    congestion = finding(result, "wifi_24ghz_congestion")
    assert congestion["severity"] == "info" and congestion["recommendation"].startswith("Keep the router on channel 1")
    assert congestion["details"]["own_channels"] == [1] and congestion["details"]["bss_high"] == 0
    absent = finding(result, "wifi_high_band_absent")
    assert "None of your network's access points is on 5 or 6 GHz" in absent["statement"]
    mouse = finding(result, "usb_receiver_fff1_0001")
    assert mouse["severity"] == "info" and mouse["details"]["usb_stack"] == "usb2_ehci"
    assert "No controller change is indicated" in mouse["recommendation"]
    headset = finding(result, "usb_receiver_fff2_0002")
    assert headset["severity"] == "warn" and headset["recommendation"].startswith("First, physical separation")
    quiet = finding(result, "wlan_events_quiet")
    assert quiet["measured"] and "no event in the window" in quiet["statement"]


def test_receiver_advice_leads_with_separation_and_never_names_a_socket(bundle_copy):
    result = analysis(bundle_copy("rf-survey"))
    receivers = [f for f in result["findings"] if f["kind"] == "usb_receiver" and f["id"].startswith("usb_receiver_")]
    assert [f["id"] for f in receivers] == ["usb_receiver_fff1_0001", "usb_receiver_fff2_0002"], "a composite receiver is reported once"
    for f in receivers:
        assert f["severity"] == "warn" and f["details"]["usb_stack"] == "usb3_xhci" and f["details"]["ehci_available"] is True
        rec = f["recommendation"]
        assert rec.startswith("First, physical separation") and "extension cable" in rec
        assert rec.index("extension cable") < rec.index("USB 2 host controller"), "separation first, the USB 2 controller second"
        assert "cannot say which socket" in rec and "root hub" not in rec.lower()
        assert "not the speed each port negotiated" in f["statement"]
        assert {c["url"] for c in f["citations"]} >= {analyze_rf_survey.CITATIONS["intel_usb3"]["url"], analyze_rf_survey.CITATIONS["logitech_usb3"]["url"]}
    no_ehci = analysis(bundle_copy("rf-survey-no-wifi"))
    for fid in ("usb_receiver_fff1_0001", "usb_receiver_fff2_0002"):
        f = finding(no_ehci, fid)
        assert f["details"]["ehci_available"] is False and f["recommendation"].startswith("First, physical separation")
        assert "only USB 3 (xHCI) host controllers" in f["recommendation"]
    noise = finding(result, "usb3_noise_sources")
    assert "Synthetic Portable SSD" in noise["statement"] and "suspects, not culprits" in noise["statement"]


def test_bluetooth_findings_claim_presence_only(bundle_copy):
    present = finding(analysis(bundle_copy("rf-survey")), "bluetooth_present")
    assert "0 remembered peer device nodes" in present["statement"] and "says nothing about pairing" in present["statement"]
    assert "off unless the PC's maker enabled it" in present["statement"], "Windows shared spectrum avoidance is not claimed to be on"
    assert "hop around busy channels on their own" in present["statement"]
    in_use = finding(analysis(bundle_copy("rf-survey-clean")), "bluetooth_present")
    assert "3 remembered peer device nodes" in in_use["statement"] and "Synthetic Earbuds" not in in_use["statement"]
    assert "remembered devices are not in use" in in_use["recommendation"]
    disabled = analysis(bundle_copy("rf-survey-non-english"))
    f = finding(disabled, "bluetooth_disabled")
    assert "problem code 22" in f["statement"] and f["recommendation"] is None
    assert not has_finding(disabled, "bluetooth_present")
    none = finding(analysis(bundle_copy("rf-survey-no-wifi")), "bluetooth_no_node")
    assert "not a measurement of a radio switch" in none["statement"]
    for result in (present_result := analysis(bundle_copy("rf-survey", "-ids")),):
        assert not any(f["id"] in ("bluetooth_unused", "bluetooth_in_use", "bluetooth_absent") for f in result["findings"])
    assert all("Bluetooth is on with nothing paired" not in f["statement"] and "No Bluetooth radio" not in f["title"] for f in present_result["findings"])
    bundle = bundle_copy("rf-survey-clean", "-metric")
    analysis(bundle)
    bt_rows = [r for r in wf_schema.read_jsonl(bundle / "evidence.jsonl") if r["signal"] == "bluetooth_device_nodes"]
    assert len(bt_rows) == 1 and bt_rows[0]["metric"] == "peer_node_count" and bt_rows[0]["value"] == 3
    assert bt_rows[0]["payload"]["not_measured"] == ["pairing state", "connection state", "radio power switch"]
    assert all(p["name_pseudonym"].startswith("name-") for p in bt_rows[0]["payload"]["peer_nodes"])
    assert not any(r["metric"] == "paired_device_count" for r in wf_schema.read_jsonl(bundle / "evidence.jsonl"))


def test_connected_wifi_adapter_finding_uses_the_pseudonym(bundle_copy):
    result = analysis(bundle_copy("rf-survey-connected"))
    f = finding(result, "wifi_adapter_unused")
    assert re.search(r"connected to network ssid-[0-9a-f]{12}", f["statement"]) and "Harbor-Home" not in f["statement"]
    assert "may issue background scans" in f["statement"] and "how often an idle adapter scans is not documented" in f["statement"]
    assert "keeps scanning" not in f["statement"]
    traffic = finding(result, "traffic_path")
    assert "Ethernet" in traffic["statement"]


def test_scan_unavailable_recommendation_follows_the_recorded_reason(bundle_copy):
    stopped = analysis(bundle_copy("rf-survey-no-wifi"))
    scan = finding(stopped, "wifi_scan")
    assert scan["measured"] is False and scan["severity"] == "warn" and scan["evidence_row_ids"] == []
    assert "wlansvc" in scan["statement"] and "WLAN AutoConfig service is running" in scan["recommendation"]
    assert "verification item 15" not in scan["recommendation"], "the consent check is advised only for the zero record case"
    assert analyze_rf_survey.CITATIONS["ms_location"]["url"] not in {c["url"] for c in scan["citations"]}
    assert finding(stopped, "wlan_events_not_measured")["measured"] is False
    # Zero records with exit code 0 is the location consent case.
    bundle = bundle_copy("rf-survey", "-zero")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(c for c in manifest["collectors"] if c["id"] == "wlan_networks")
    entry["status"], entry["status_reason"], entry["raw_time_range"] = "capture_failed", "zero records: netsh exited with code 0 and listed no network. Windows withholds the scan list from a process without location consent", None
    entry["expectation"]["met"] = False
    entry["artifacts"] = [a for a in entry["artifacts"] if a["role"] != "primary"]
    (bundle / "raw" / "wlan_networks" / "output.txt").unlink()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    consent = finding(analysis(bundle), "wifi_scan")
    assert "verification item 15" in consent["recommendation"] and "location consent" in consent["recommendation"]
    assert analyze_rf_survey.CITATIONS["ms_location"]["url"] in {c["url"] for c in consent["citations"]}


def test_traffic_path_is_address_family_complete(bundle_copy):
    bundle = bundle_copy("rf-survey", "-ipv6")
    routes = json.loads((bundle / "raw" / "default_routes" / "records.json").read_text(encoding="utf-8"))
    ipv6_only = [r for r in routes if r["DestinationPrefix"] == "::/0"]
    rewrite_artifact(bundle, "raw/default_routes/records.json", json.dumps(ipv6_only))
    result = analysis(bundle)
    traffic = finding(result, "traffic_path")
    assert traffic["details"]["address_family"] == "IPv6" and "IPv6 default route" in traffic["statement"] and "Ethernet" in traffic["statement"]
    assert "no adapter was carrying" not in traffic["statement"]
    # Dual stack with a tie on the metric and different interfaces: IPv4 is listed first and the split is reported.
    bundle2 = bundle_copy("rf-survey", "-tie")
    tie = [dict(r) for r in routes if r["DestinationPrefix"] in ("0.0.0.0/0", "::/0")]
    for r in tie:
        r["RouteMetric"] = 0
        if r["DestinationPrefix"] == "::/0":
            r["InterfaceIndex"], r["InterfaceAlias"] = 7, "Wi-Fi"
    rewrite_artifact(bundle2, "raw/default_routes/records.json", json.dumps(tie))
    result2 = analysis(bundle2)
    traffic2 = finding(result2, "traffic_path")
    assert traffic2["details"]["address_family"] == "IPv4" and traffic2["details"]["split_families"] is True
    assert "different interfaces" in traffic2["statement"]
    evidence = wf_schema.read_jsonl(bundle2 / "evidence.jsonl")
    row = next(r for r in evidence if r["signal"] == "traffic_default_route")
    assert row["payload"]["interface_by_family"] == {"IPv4": 12, "IPv6": 7} and "IPv4 is listed first" in row["payload"]["tie_rule"]
    # No default route at all.
    bundle3 = bundle_copy("rf-survey", "-noroute")
    rewrite_artifact(bundle3, "raw/default_routes/records.json", json.dumps([r for r in routes if r["DestinationPrefix"] == "192.168.1.0/24"]))
    traffic3 = finding(analysis(bundle3), "traffic_path")
    assert "no default route in either address family" in traffic3["statement"]


def test_an_unknown_overlap_signal_is_never_rendered_as_zero(bundle_copy):
    bundle = bundle_copy("rf-survey-clean", "-weak-unknown")
    text = (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8")
    lines = [line for line in text.split("\n") if not re.search(r"Signal\s+: (28|20)%", line)]
    rewrite_artifact(bundle, "raw/wlan_networks/output.txt", "\n".join(lines))
    survey = finding(analysis(bundle), "wifi_24ghz_survey")
    assert "strongest 0%" not in survey["statement"]
    assert "channel 6: 1 network within four channels, strongest signal unknown" in survey["statement"]


def test_the_channel_table_lists_the_pseudonyms_the_owner_can_name(bundle_copy):
    bundle = bundle_copy("rf-survey")
    result = analysis(bundle)
    report = (bundle / "reports" / "rf-survey.md").read_text(encoding="utf-8")
    survey = finding(result, "wifi_24ghz_survey")
    assert "Networks here column of the channel table" in survey["recommendation"]
    assert "| Networks here |" in report
    listed = {p for c in result["channels_24ghz"] for p in c["ssid_pseudonyms"]}
    assert listed == {r["ssid_pseudonym"] for r in rows(bundle, "wlan_bss") if r["band_ghz"] == 2.4 and r["ssid_pseudonym"]}
    for pseudonym in listed:
        assert pseudonym in report


def test_partial_evidence_and_a_failing_section_do_not_erase_the_rest(bundle_copy, monkeypatch):
    bundle = bundle_copy("rf-survey", "-nosignal")
    text = (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8")
    lines = text.split("\n")
    first_signal = next(i for i, line in enumerate(lines) if "Signal" in line)
    del lines[first_signal]
    rewrite_artifact(bundle, "raw/wlan_networks/output.txt", "\n".join(lines))
    result = analysis(bundle, own_network=OWN)
    assert result["status"] == "observed" and result["status_reason"] is None
    assert wf_schema.validate_object(result, "analysis/rf_survey.schema.json") == []
    congestion = finding(result, "wifi_24ghz_congestion")
    assert "signal unknown" in congestion["statement"]
    for fid in ("traffic_path", "usb_receiver_fff1_0001", "receiver_placement", "wlan_events_summary"):
        assert has_finding(result, fid), fid
    bss = rows(bundle, "wlan_bss")
    assert sum(1 for r in bss if r["signal_pct"] is None) == 1

    def boom(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(analyze_rf_survey, "analyze_receivers", boom)
    bundle2 = bundle_copy("rf-survey", "-section")
    decoded(bundle2)
    outcome = analyze_rf_survey.analyze(bundle2, analyzed_at="2026-09-03T00:00:00Z", own_network=OWN)
    assert outcome["status"] == "observed" and outcome["failed_sections"] == ["receivers"] and "sections failed: receivers" in outcome["reason"]
    result2 = json.loads((bundle2 / "reports" / "rf-survey.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(result2, "analysis/rf_survey.schema.json") == []
    failed = finding(result2, "receivers_failed")
    assert failed["severity"] == "error" and "synthetic failure" in failed["statement"] and failed["measured"] is False
    for fid in ("traffic_path", "wifi_24ghz_congestion", "wifi_adapter_unused", "receiver_placement", "wlan_events_summary"):
        assert has_finding(result2, fid), fid
    assert not any(f["id"].startswith("usb_receiver_") for f in result2["findings"])
    evidence = wf_schema.read_jsonl(bundle2 / "evidence.jsonl")
    assert any(r["signal"] == "router_channel_recommendation" for r in evidence), "evidence from the other sections stands"
    assert analyze_rf_survey.main(["--bundle", str(bundle2), "--analyzed-at", "2026-09-03T00:00:00Z", "--own-network", OWN]) == 2


def test_rf_wording_and_citations(bundle_copy):
    assert "ms_win11_6e" not in analyze_rf_survey.CITATIONS
    assert analyze_rf_survey.CITATIONS["ms_signal"]["url"].endswith("ns-wlanapi-wlan_available_network")
    assert "disabled by default" in analyze_rf_survey.CITATIONS["ms_bluetooth_faq"]["title"]
    result = analysis(bundle_copy("rf-survey"), own_network=OWN)
    survey_text = " ".join(f["statement"] for f in result["findings"])
    assert "5 or 6 GHz" in survey_text and "keeps scanning" not in survey_text
    for f in result["findings"]:
        if f["kind"] in ("wifi_24ghz",) and f["id"] in ("wifi_24ghz_congestion", "wifi_24ghz_survey"):
            assert "not proof about the mouse or headset" in f["statement"]
    placement = finding(result, "receiver_placement")
    assert "not proof about the mouse or headset" in placement["statement"] and "extension cable and placement first" in placement["recommendation"]
    md = (REPO_ROOT / "docs" / "rf-survey.md").read_text(encoding="utf-8")
    for url in (analyze_rf_survey.CITATIONS["cisco_5ghz"]["url"], analyze_rf_survey.CITATIONS["ms_signal"]["url"], analyze_rf_survey.CITATIONS["ms_get_pnpdevice"]["url"]):
        assert url in md, url
    assert "disabled by default" in md or "off unless" in md


def test_analyzer_without_decoded_tables_is_not_collected_and_replaces_only_its_own_rows(bundle_copy):
    bundle = bundle_copy("rf-survey")
    foreign = {"row_id": "other:1", "ts_utc": None, "window": None, "t_master_100ns": None, "clock_error_bound_100ns": None,
               "collected_ts_utc": "2026-09-03T00:00:00Z", "source": "pdh", "subsystem": "cpu_dpc", "signal": "s", "metric": "m", "unit": "count",
               "value": 1, "severity": "info", "faulting_module": None, "cpu": None, "confidence": 1.0, "evidence_kind": "observed", "coverage_ref": None,
               "provenance": [{"source_file": "raw/x/y.csv", "row_id_or_offset": "row:1", "decoded_table": "pdh_counters", "decoder_version": "1.0.0", "schema_version": "1.0.0"}],
               "links": [], "incident_id": None, "analyzer": {"id": "other", "version": "0.0.0"}, "playbook": None, "payload": {}}
    wf_schema.write_jsonl(bundle / "evidence.jsonl", [foreign])
    result = analyze_rf_survey.analyze(bundle, analyzed_at="2026-09-03T00:00:00Z")
    assert result["status"] == "not_collected" and result["evidence_rows"] == 0
    assert [r["row_id"] for r in wf_schema.read_jsonl(bundle / "evidence.jsonl")] == ["other:1"]
    report = json.loads((bundle / "reports" / "rf-survey.json").read_text(encoding="utf-8"))
    assert report["status"] == "not_collected" and report["findings"] == []
    decoded(bundle)
    analyze_rf_survey.analyze(bundle, analyzed_at="2026-09-03T00:00:00Z")
    ids = [r["row_id"] for r in wf_schema.read_jsonl(bundle / "evidence.jsonl")]
    assert ids[0] == "other:1" and len(ids) > 10
    analyze_rf_survey.analyze(bundle, analyzed_at="2026-09-03T00:00:00Z")
    assert [r["row_id"] for r in wf_schema.read_jsonl(bundle / "evidence.jsonl")] == ids, "a second run replaces its own rows and keeps the other analyzer's"


def test_analyzer_cli_exit_codes(bundle_copy, capsys):
    bundle = bundle_copy("rf-survey")
    assert analyze_rf_survey.main(["--bundle", str(bundle), "--analyzed-at", "2026-09-03T00:00:00Z"]) == 2, "no decoded table yet"
    decoded(bundle)
    assert analyze_rf_survey.main(["--bundle", str(bundle), "--analyzed-at", "2026-09-03T00:00:00Z", "--own-network", OWN]) == 0
    assert "status observed" in capsys.readouterr().out
