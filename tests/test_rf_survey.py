"""The rf-survey decoder and analyzer over the synthetic rf-survey bundles.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a congested 2.4 GHz
airspace with the receiver on the USB 3 controller and 5 GHz available, a clean airspace with the
receiver on USB 2 and no 5 GHz, a PC whose wireless service is not running, and a German display
language. Nothing here comes from a real machine.
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
CASES = ["rf-survey", "rf-survey-clean", "rf-survey-no-wifi", "rf-survey-non-english"]
OBSERVED = ("observed", "observed_zero")
DASHES = re.compile("[–—]")
TABLES = ["netsh_fields", "wlan_bss", "pnp_device", "net_adapter", "net_route"]


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


def analysis(bundle: Path) -> dict:
    decoded(bundle)
    analyze_rf_survey.analyze(bundle, analyzed_at="2026-09-03T00:00:00Z")
    return json.loads((bundle / "reports" / "rf-survey.json").read_text(encoding="utf-8"))


def finding(result: dict, fid: str) -> dict:
    matches = [f for f in result["findings"] if f["id"] == fid]
    assert len(matches) == 1, [f["id"] for f in result["findings"]]
    return matches[0]


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
    # The decoded tables are part of the container: the bundle still verifies with them present.
    assert verify_bundle.verify(bundle)["ok"]


def test_bss_rows_point_at_the_lines_that_carry_them(bundle_copy):
    bundle = bundle_copy("rf-survey")
    decoded(bundle)
    text = (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8").split("\n")
    bss = rows(bundle, "wlan_bss")
    assert len(bss) == 9
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
    assert len(by_channel[(2.4, 6)]) == 3 and len(by_channel[(2.4, 1)]) == 2 and len(by_channel[(5, 36)]) == 1
    known = [r for r in bss if r["is_known_profile"]]
    assert len(known) == 2 and {r["band_ghz"] for r in known} == {2.4, 5}, "the saved profile is the router, on both bands"
    hidden = [r for r in bss if r["ssid_pseudonym"] is None]
    assert len(hidden) == 1 and hidden[0]["is_known_profile"] is None
    assert all(r["labels_recognised"] for r in bss)


def test_non_english_output_decodes_by_the_shape_of_the_values(bundle_copy):
    bundle = bundle_copy("rf-survey-non-english")
    result = decoded(bundle)
    assert result["tables"]["wlan_bss"]["status"] == "observed"
    bss = rows(bundle, "wlan_bss")
    assert [(r["band_ghz"], r["channel"], r["signal_pct"], r["radio_type"]) for r in bss] == [
        (2.4, 6, 94, "802.11ax"), (5, 36, 88, "802.11ax"), (2.4, 6, 70, "802.11n"), (2.4, 6, 62, "802.11ax"), (2.4, 11, 35, "802.11n")]
    assert all(r["network_type"] is None for r in bss), "translated labels are not guessed"
    assert bss[0]["is_known_profile"] is True
    fields = rows(bundle, "netsh_fields")
    keys = {(r["command"], r["normalized_key"]): r for r in fields if r["normalized_key"]}
    assert keys[("interfaces", "guid")]["classified_by"] == "label"
    assert keys[("interfaces", "physical_address")]["classified_by"] == "value"
    assert keys[("drivers", "radio_types_supported")]["classified_by"] == "value"
    assert keys[("profiles", "profile")]["value_text"].startswith("ssid-")
    unclassified = [r for r in fields if r["normalized_key"] is None]
    assert unclassified, "labels the parser does not know stay verbatim with a null key"
    meta = json.loads((bundle / "decoded" / "netsh_fields.meta.json").read_text(encoding="utf-8"))
    detail = next(c["detail"] for c in meta["checks"] if c["name"] == "labels:wlan_interfaces")
    assert "by value shape" in detail
    assert "ü" in (bundle / "raw" / "wlan_networks" / "output.txt").read_text(encoding="utf-8"), "the raw text keeps its non ASCII characters"


def test_english_fields_classify_by_label_and_keep_numbers(bundle_copy):
    bundle = bundle_copy("rf-survey")
    decoded(bundle)
    fields = rows(bundle, "netsh_fields")
    by_key = {(r["command"], r["normalized_key"]): r for r in fields if r["normalized_key"]}
    assert by_key[("interfaces", "state")]["value_text"] == "disconnected"
    assert by_key[("interfaces", "physical_address")]["value_text"].startswith("mac-")
    assert by_key[("drivers", "radio_types_supported")]["value_text"].split() == ["802.11b", "802.11g", "802.11n", "802.11a", "802.11ac", "802.11ax"]
    profiles = [r for r in fields if r["command"] == "profiles" and r["normalized_key"] == "profile"]
    assert len(profiles) == 2 and all(r["value_text"].startswith("ssid-") for r in profiles)
    assert all(r["classified_by"] == "label" for r in fields if r["normalized_key"] and r["command"] == "interfaces")


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
    bt = [r for r in rows(bundle, "pnp_device") if r["source_id"] == "bluetooth_devices"]
    assert not any(r["is_bluetooth_peer"] for r in bt)
    adapters = {r["name"]: r for r in rows(bundle, "net_adapter")}
    assert adapters["Ethernet"]["physical_medium_text"] == "802.3" and adapters["Wi-Fi"]["physical_medium_text"] == "Native 802.11"
    routes = rows(bundle, "net_route")
    assert [(r["destination_prefix"], r["address_family_text"], r["protocol_text"]) for r in routes] == [("0.0.0.0/0", "IPv4", "NetMgmt"), ("::/0", "IPv6", "Other")]


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
    path = bundle2 / "raw" / "wlan_networks" / "output.txt"
    path.write_text("Interface name : Wi-Fi\nThere are 2 networks currently visible.\n\nsome layout the parser has never seen\n", encoding="utf-8")
    result2 = decode_rf_survey.decode(bundle2, decoded_at="2026-09-03T00:00:00Z")
    assert result2["tables"]["wlan_bss"]["status"] == "decode_failed" and "layout" in result2["tables"]["wlan_bss"]["reason"]
    meta = json.loads((bundle2 / "decoded" / "wlan_bss.meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "decode_failed" and meta["row_count"] == 0


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("rf-survey")), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    out = capsys.readouterr().out
    assert "wlan_bss: 9 rows from 1 exports, status observed" in out
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("rf-survey-no-wifi")), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("whea-errors-quiet"))]) == 2
    assert decode_rf_survey.main(["--bundle", str(bundle_copy("bugcheck-history"))]) == 2


# ---------------------------------------------------------------- analyzer

@pytest.mark.parametrize("case", CASES)
def test_analysis_outputs_validate_and_are_tied_to_evidence(case, bundle_copy):
    bundle = bundle_copy(case)
    result = analysis(bundle)
    assert wf_schema.validate_object(result, "analysis/rf_survey.schema.json") == []
    assert result["status"] == "observed"
    evidence = wf_schema.read_jsonl(bundle / "evidence.jsonl")
    assert wf_schema.validate_rows(evidence, "evidence.schema.json") == []
    ids = {r["row_id"] for r in evidence}
    assert len(ids) == len(evidence) and all(r["analyzer"]["id"] == "rf_survey" for r in evidence)
    # Every observed row points at decoded rows; every inferred row links to rows in the file.
    decoded_tables = {t: rows(bundle, t) for t in TABLES + ["eventlog_events"] if (bundle / "decoded" / f"{t}.jsonl").exists()}
    offsets = {(p["decoded_table"], p["source_file"], p["row_id_or_offset"]) for t in decoded_tables.values() for r in t for p in [r["provenance"]]}
    for row in evidence:
        if row["evidence_kind"] == "observed":
            assert row["provenance"] and all((p["decoded_table"], p["source_file"], p["row_id_or_offset"]) in offsets for p in row["provenance"])
        else:
            assert row["evidence_kind"] == "inferred" and row["links"] and set(row["links"]) <= ids and row["confidence"] < 1
    assert not any(r["evidence_kind"] == "absent" for r in evidence), "no absence row without a verdict's coverage table"
    # Every recommendation rests on evidence rows that exist, or says it is not measured, and cites a source.
    for f in result["findings"]:
        assert f["citations"], f["id"]
        assert all(c["url"].startswith("https://") for c in f["citations"])
        assert set(f["evidence_row_ids"]) <= ids
        if f["recommendation"] and f["measured"]:
            assert f["evidence_row_ids"], f["id"]
    assert [c["kind"] for c in result["coverage"]][:10] == ["collector"] * 10, "the coverage table comes first and names every source"
    report = (bundle / "reports" / "rf-survey.md").read_text(encoding="utf-8")
    assert report.startswith("# RF survey") and "## What was measured" in report and report.index("## What was measured") < report.index("## 1.")
    assert not DASHES.search(report)
    assert "Harbor-Home" not in report and "02:aa:bb" not in report
    assert "docs/rf-survey.md" in report
    assert verify_bundle.verify(bundle)["ok"]


def test_congested_airspace_recommends_the_least_loaded_channel_and_5ghz(bundle_copy):
    result = analysis(bundle_copy("rf-survey"))
    traffic = finding(result, "traffic_path")
    assert "Ethernet" in traffic["statement"] and traffic["recommendation"] is None
    congestion = finding(result, "wifi_24ghz_congestion")
    assert congestion["details"]["own_channel"] == 6 and congestion["details"]["recommended_channel"] == 1
    assert "saved Wi-Fi profile" in congestion["statement"]
    assert congestion["severity"] == "warn" and "channel 1" in congestion["recommendation"]
    channels = {c["channel"]: c for c in result["channels_24ghz"]}
    assert channels[6]["bss_count"] == 3 and channels[6]["own_router_here"] and channels[6]["overlap_bss_count"] == 3
    assert channels[8]["overlap_bss_count"] == 4, "channel 8 overlaps 6 and 11 and the hidden network does not count twice"
    assert channels[1]["overlap_bss_count"] == 2 and channels[11]["overlap_bss_count"] == 2
    assert channels[1]["overlap_strongest_signal_pct"] == 40 and channels[11]["overlap_strongest_signal_pct"] == 55
    five = finding(result, "wifi_5ghz_available")
    assert "5 GHz" in five["recommendation"] and "channel 36" in five["statement"]
    assert not any(f["id"].startswith("wifi_5ghz_absent") for f in result["findings"])


def test_clean_airspace_keeps_the_channel_and_says_5ghz_is_absent(bundle_copy):
    result = analysis(bundle_copy("rf-survey-clean"))
    congestion = finding(result, "wifi_24ghz_congestion")
    assert congestion["severity"] == "info" and congestion["recommendation"].startswith("Keep the router on channel 1")
    assert congestion["details"]["bss_5ghz"] == 0
    absent = finding(result, "wifi_5ghz_absent")
    assert "No 5 GHz access point carries your router's network name" in absent["statement"]
    mouse = finding(result, "usb_receiver_fff1_0001")
    assert mouse["severity"] == "info" and mouse["details"]["usb_stack"] == "usb2_ehci"
    assert "No port change is indicated" in mouse["recommendation"]
    headset = finding(result, "usb_receiver_fff2_0002")
    assert headset["severity"] == "warn" and "USB 2 controller" in headset["recommendation"]
    assert finding(result, "bluetooth_in_use")["recommendation"] is None
    assert "2 paired" in finding(result, "bluetooth_in_use")["statement"]
    quiet = finding(result, "wlan_events_quiet")
    assert quiet["measured"] and "no event in the window" in quiet["statement"]


def test_receiver_on_the_usb3_controller_gets_the_port_and_cable_advice(bundle_copy):
    result = analysis(bundle_copy("rf-survey"))
    receivers = [f for f in result["findings"] if f["kind"] == "usb_receiver" and f["id"].startswith("usb_receiver_")]
    assert [f["id"] for f in receivers] == ["usb_receiver_fff1_0001", "usb_receiver_fff2_0002"], "a composite receiver is reported once"
    for f in receivers:
        assert f["severity"] == "warn" and f["details"]["usb_stack"] == "usb3_xhci" and f["details"]["ehci_available"] is True
        assert "USB 2 controller" in f["recommendation"] and "extension cable" in f["recommendation"]
        assert "not the speed of each port" in f["statement"]
        assert {c["url"] for c in f["citations"]} >= {analyze_rf_survey.CITATIONS["intel_usb3"]["url"], analyze_rf_survey.CITATIONS["logitech_usb3"]["url"]}
    noise = finding(result, "usb3_noise_sources")
    assert "Synthetic Portable SSD" in noise["statement"] and "suspects, not culprits" in noise["statement"]
    wifi = finding(result, "wifi_adapter_unused")
    assert "carries no traffic" in wifi["title"] and "the collector never changes it" in wifi["recommendation"]
    bt = finding(result, "bluetooth_unused")
    assert "nothing paired" in bt["title"]
    placement = finding(result, "receiver_placement")
    assert placement["measured"] is False and placement["evidence_row_ids"] == [] and "line of sight" in placement["statement"]
    events = finding(result, "wlan_events_summary")
    assert "id 8003: 1" in events["statement"]


def test_no_usb2_controller_means_the_extension_cable(bundle_copy):
    result = analysis(bundle_copy("rf-survey-no-wifi"))
    for fid in ("usb_receiver_fff1_0001", "usb_receiver_fff2_0002"):
        f = finding(result, fid)
        assert f["details"]["ehci_available"] is False
        assert "only USB 3 (xHCI) host controllers" in f["recommendation"] and "extension cable" in f["recommendation"]
    assert finding(result, "bluetooth_absent")["measured"] is True
    assert not any(f["id"] == "wifi_adapter_unused" for f in result["findings"]), "no Wi-Fi adapter, nothing to switch off"


def test_an_unreadable_scan_is_reported_as_not_measured_never_as_quiet(bundle_copy):
    result = analysis(bundle_copy("rf-survey-no-wifi"))
    scan = finding(result, "wifi_scan")
    assert scan["measured"] is False and scan["severity"] == "warn" and scan["evidence_row_ids"] == []
    assert "capture_failed" in scan["statement"] and "wlansvc" in scan["statement"]
    assert analyze_rf_survey.CITATIONS["ms_location"]["url"] in {c["url"] for c in scan["citations"]}
    assert result["channels_24ghz"] == []
    events = finding(result, "wlan_events_not_measured")
    assert events["measured"] is False and "unsupported" in events["statement"]
    coverage = {c["id"]: c for c in result["coverage"] if c["kind"] == "collector"}
    assert coverage["wlan_networks"]["collector_status"] == "capture_failed" and coverage["wlan_networks"]["decoded_status"] == "not_collected"
    assert coverage["wlan_report"]["collector_status"] == "not_collected"


def test_non_english_bundle_gets_the_same_recommendations(bundle_copy):
    result = analysis(bundle_copy("rf-survey-non-english"))
    congestion = finding(result, "wifi_24ghz_congestion")
    assert congestion["details"]["own_channel"] == 6 and congestion["details"]["recommended_channel"] == 1
    assert "no other network within four channels" in congestion["recommendation"]
    assert finding(result, "wifi_5ghz_available")
    assert finding(result, "usb_receiver_fff1_0001")["severity"] == "warn"


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
    assert analyze_rf_survey.main(["--bundle", str(bundle), "--analyzed-at", "2026-09-03T00:00:00Z"]) == 0
    assert "status observed" in capsys.readouterr().out
