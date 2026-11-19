"""Driver classes for DPC and ISR modules: the cited map, the PC's inventory join, and the class summary.

The inventory comes from the synthetic ``driver-inventory`` fixture bundle and the trace from the
synthetic ``dpcisr-trace`` bundle; both are the same invented machine, so the join is allowed.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

import decode_dpcisr
import decode_driver_inventory
import driver_classes
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
REPORT = "raw/dpcisr_report/dpcisr.txt"
DECODED_AT = "2026-09-03T00:00:00Z"
DOC = REPO_ROOT / "docs" / "driver-classes.md"


@pytest.fixture
def bundles(tmp_path):
    """Fresh copies of the inventory and trace bundles."""
    inv, dpc = tmp_path / "inv", tmp_path / "dpc"
    shutil.copytree(BUNDLES / "driver-inventory", inv)
    shutil.copytree(BUNDLES / "dpcisr-trace", dpc)
    return inv, dpc


def rows_of(bundle: Path, table: str) -> list[dict]:
    return wf_schema.read_jsonl(bundle / "decoded" / f"{table}.jsonl")


def meta_of(bundle: Path, table: str) -> dict:
    return json.loads((bundle / "decoded" / f"{table}.meta.json").read_text(encoding="utf-8"))


def by_module(rows: list[dict]) -> dict[str, dict]:
    return {r["module"]: r for r in rows}


def set_source_status(bundle: Path, source_id: str, status: str) -> None:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for c in manifest["collectors"]:
        if c["id"] == source_id:
            c["status"], c["status_reason"], c["artifacts"] = status, "synthetic: the read failed", []
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


# ---------------------------------------------------------------- the map

def test_every_map_entry_is_lower_case_cited_on_learn_and_a_known_class():
    for name, (cls, url) in driver_classes.INBOX_MAP.items():
        assert name == name.lower() and cls in driver_classes.DRIVER_CLASSES and cls != "unclassified", name
        assert url.startswith("https://learn.microsoft.com/"), name
    for name, (why, url) in driver_classes.INBOX_UNCLASSIFIED.items():
        assert name == name.lower() and name not in driver_classes.INBOX_MAP and why and url.startswith("https://learn.microsoft.com/")
    for guid, (setup, cls, url) in driver_classes.SETUP_CLASSES.items():
        assert driver_classes.normalise_guid(guid) == guid, guid
        assert setup and (cls is None or cls in driver_classes.DRIVER_CLASSES) and cls != "unclassified"
        assert url in (driver_classes.DOC_SETUP_CLASSES, driver_classes.DOC_SETUP_CLASSES_RESERVED)


def test_the_document_lists_every_entry_with_its_citation_and_the_map_version():
    text = DOC.read_text(encoding="utf-8")
    assert f"Map version {driver_classes.MAP_VERSION}" in text
    rows = {m.group(1).lower(): (m.group(2), m.group(3)) for m in re.finditer(r"^\| `([^`]+)` \| `?([a-z]+)`? \| <?(https://[^ >|]+)>? \|$", text, re.M)}
    expected = {**{k: v for k, v in driver_classes.INBOX_MAP.items()},
                **{k: ("unclassified", url) for k, (_, url) in driver_classes.INBOX_UNCLASSIFIED.items()}}
    assert rows == expected
    for guid, (setup, cls, url) in driver_classes.SETUP_CLASSES.items():
        assert re.search(rf"^\| {re.escape(setup)} \| `{guid}` \| {cls or 'none'} \| <?{re.escape(url)}>? \|$", text, re.M), setup


def test_vendor_drivers_are_never_in_the_inbox_map():
    # Vendor drivers are classed through the PC's inventory only; the synthetic ones stand in for them here.
    for name in ("synthgfx.sys", "synthnic.sys", "synthusb.sys", "synthaudio.sys", "synthbt.sys"):
        assert driver_classes.classify_module(name, None)["classification_source"] == "none"


@pytest.mark.parametrize("path,name", [
    ("\\SystemRoot\\System32\\drivers\\afd.sys", "afd.sys"),
    ("System32\\drivers\\USBXHCI.SYS", "USBXHCI.SYS"),
    ("C:\\Windows\\System32\\DriverStore\\FileRepository\\x.inf_amd64_0\\x.sys", "x.sys"),
    ('"C:\\Program Files\\Vendor\\drv.sys"', "drv.sys"),
    ("\\??\\C:\\Windows\\system32\\drivers\\y.sys", "y.sys"),
    ("", None), (None, None), ("C:\\Windows\\System32\\drivers\\", None), ("C:\\Tools\\tool.exe -k arg", None),
])
def test_the_file_name_comes_from_the_end_of_the_path_or_not_at_all(path, name):
    assert driver_classes.file_name_of(path) == name


def test_guids_are_normalised_or_refused():
    assert driver_classes.normalise_guid("{4D36E972-E325-11CE-BFC1-08002BE10318}") == "4d36e972-e325-11ce-bfc1-08002be10318"
    for bad in (None, "", "{not-a-guid}", "4d36e972e32511cebfc108002be10318", 7):
        assert driver_classes.normalise_guid(bad) is None


NET = {"class_guid": "4d36e972-e325-11ce-bfc1-08002be10318", "setup_class": "Net", "device_count": 1}
MEDIA = {"class_guid": "4d36e96c-e325-11ce-bfc1-08002be10318", "setup_class": "Media", "device_count": 1}
SYSTEM = {"class_guid": "4d36e97d-e325-11ce-bfc1-08002be10318", "setup_class": "System", "device_count": 2}
VENDOR = {"class_guid": "01234567-89ab-cdef-0123-456789abcdef", "setup_class": None, "device_count": 1}


@pytest.mark.parametrize("classes,expected", [
    ([], None),
    ([NET], "network"),
    ([NET, SYSTEM], "network"),
    ([NET, VENDOR], "network"),
    ([NET, MEDIA], "unclassified"),
    ([SYSTEM], None),
    ([VENDOR], None),
    ([{"class_guid": None, "setup_class": None, "device_count": 1}], None),
])
def test_a_service_class_needs_exactly_one_informative_setup_class(classes, expected):
    cls, reason = driver_classes.classify_service(classes)
    assert cls == expected and reason


def test_the_inventory_comes_first_then_the_map_then_nothing():
    rows = [
        {"service": "HDAudBus", "driver_file": "HDAudBus.sys", "driver_class": None, "class_reason": "present devices only in System (says nothing about the driver class)"},
        {"service": "vendornic", "driver_file": "vendornic.sys", "driver_class": "network", "class_reason": "present devices in setup class Net"},
        {"service": "a", "driver_file": "shared.sys", "driver_class": "audio", "class_reason": "present devices in setup class Media"},
        {"service": "b", "driver_file": "SHARED.SYS", "driver_class": "usb", "class_reason": "present devices in setup class USB"},
        {"service": "storport", "driver_file": "storport.sys", "driver_class": "network", "class_reason": "present devices in setup class Net"},
    ]
    index = driver_classes.InventoryIndex(rows, "inv/decoded/driver_service_class.jsonl#")
    nic = driver_classes.classify_module("VendorNic.sys", index)
    assert (nic["driver_class"], nic["classification_source"], nic["classification_reference"]) == ("network", "inventory", "inv/decoded/driver_service_class.jsonl#line:2")
    hda = driver_classes.classify_module("HDAudBus.sys", index)
    assert (hda["driver_class"], hda["classification_source"]) == ("audio", "inbox-map")
    assert "System" in hda["classification_reason"] and hda["classification_reference"] == driver_classes.DOC_LOW_LATENCY_AUDIO
    shared = driver_classes.classify_module("shared.sys", index)
    assert (shared["driver_class"], shared["classification_source"]) == ("unclassified", "inventory")
    assert shared["classification_reference"].endswith("#line:3;line:4")
    # The machine's own inventory wins over the map, whatever the map says.
    assert driver_classes.classify_module("storport.sys", index)["driver_class"] == "network"
    wdf = driver_classes.classify_module("Wdf01000.sys", index)
    assert (wdf["driver_class"], wdf["classification_source"]) == ("unclassified", "inbox-map") and "KMDF" in wdf["classification_reason"]
    unknown = driver_classes.classify_module("mystery.sys", index)
    assert unknown == {"driver_class": "unclassified", "classification_source": "none", "classification_reference": None,
                       "classification_reason": unknown["classification_reason"]}
    assert "no driver service in the inventory" in unknown["classification_reason"]


# ---------------------------------------------------------------- the inventory table

def test_the_inventory_decodes_into_service_file_and_class_only(bundles):
    inv, _ = bundles
    result = decode_driver_inventory.decode(inv, DECODED_AT)
    assert result["status"] == "observed", result
    rows = rows_of(inv, "driver_service_class")
    assert wf_schema.validate_rows(rows, "decoded/driver_service_class.schema.json") == []
    got = {r["service"]: (r["driver_file"], r["driver_class"], r["device_count"]) for r in rows}
    assert got == {
        "synthdisp": ("synthdisp.sys", None, 0), "ACPI": ("ACPI.sys", None, 1), "synthgfx": ("synthgfx.sys", "gpu", 1),
        "synthnic": ("synthnic.sys", "network", 1), "synthusb": ("synthusb.sys", "usb", 2), "synthaudio": ("synthaudio.sys", "audio", 1),
        "synthbt": ("synthbt.sys", "bluetooth", 1), "HDAudBus": ("HDAudBus.sys", None, 1),
    }
    # The device that is not present (an audio function of synthgfx) never reached the bundle, or synthgfx would be in conflict.
    assert next(r for r in rows if r["service"] == "synthgfx")["setup_classes"] == [
        {"class_guid": "4d36e968-e325-11ce-bfc1-08002be10318", "setup_class": "Display", "device_count": 1}]
    meta = meta_of(inv, "driver_service_class")
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert [s["path"] for s in meta["source_files"]] == ["raw/system_drivers/records.json", "raw/pnp_device_services/records.json"]
    checks = {c["name"]: c["detail"] for c in meta["checks"]}
    assert checks["devices_without_service"] == "1 present devices name no service"
    assert checks["devices_with_unlisted_service"].startswith("1 present devices name 1 services")
    devices = json.loads((inv / "raw/pnp_device_services/records.json").read_text(encoding="utf-8"))
    for row in rows:
        for i in row["device_records"]:
            assert devices[i]["Service"].lower() == row["service"].lower()


def test_no_device_identity_reaches_the_bundle_or_the_table(bundles):
    inv, _ = bundles
    decode_driver_inventory.decode(inv, DECODED_AT)
    records = json.loads((inv / "raw/pnp_device_services/records.json").read_text(encoding="utf-8"))
    assert records and all(set(r) == {"Service", "ClassGuid"} for r in records)
    # The synthetic devices carry instance paths with serial numbers, an adapter address and names; none may leave.
    texts = [(inv / "raw/pnp_device_services/records.json").read_text(encoding="utf-8"),
             (inv / "decoded/driver_service_class.jsonl").read_text(encoding="utf-8")]
    for secret in ("SN0123456789", "5C4D3E2F1A0B", "01000000684CE00000", "VEN_FFFF", "ROOT_HUB30", "Synthetic Ethernet Adapter", "DriverStore", "SystemRoot"):
        assert all(secret not in t for t in texts), secret


@pytest.mark.parametrize("source_id", ["pnp_device_services", "system_drivers"])
def test_without_both_sources_the_table_is_not_collected_and_not_written(bundles, source_id):
    inv, _ = bundles
    set_source_status(inv, source_id, "capture_failed")
    result = decode_driver_inventory.decode(inv, DECODED_AT)
    assert result["status"] == "not_collected" and source_id in result["reason"]
    assert not (inv / "decoded" / "driver_service_class.jsonl").exists()


def test_an_inventory_from_before_the_device_source_is_not_collected(bundles):
    inv, _ = bundles
    manifest = json.loads((inv / "manifest.json").read_text(encoding="utf-8"))
    manifest["collectors"] = [c for c in manifest["collectors"] if c["id"] != "pnp_device_services"]
    (inv / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_driver_inventory.decode(inv, DECODED_AT)
    assert result["status"] == "not_collected" and "pnp_device_services is not in the bundle" in result["reason"]


@pytest.mark.parametrize("damage,words", [
    (lambda r: r.append(dict(r[0])), "listed twice"),
    (lambda r: r.__setitem__(0, {"Name": None, "PathName": "x.sys"}), "without a name"),
    (lambda r: r.__setitem__(0, "text"), "not an object"),
])
def test_a_damaged_service_export_is_decode_failed_with_no_rows(bundles, damage, words):
    inv, _ = bundles
    path = inv / "raw/system_drivers/records.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    damage(records)
    path.write_text(json.dumps(records), encoding="utf-8")
    result = decode_driver_inventory.decode(inv, DECODED_AT)
    assert result["status"] == "decode_failed" and words in result["reason"]
    assert rows_of(inv, "driver_service_class") == []
    assert meta_of(inv, "driver_service_class")["status"] == "decode_failed"


# ---------------------------------------------------------------- the join in the dpcisr decoder

def test_vendor_drivers_are_broken_out_through_the_inventory(bundles):
    inv, dpc = bundles
    assert decode_driver_inventory.decode(inv, DECODED_AT)["status"] == "observed"
    result = decode_dpcisr.decode(dpc, REPORT, DECODED_AT, inventory=inv)
    assert result["status"] == "observed", result
    rows = rows_of(dpc, "dpcisr_module_cpu")
    assert wf_schema.validate_rows(rows, "decoded/dpcisr_module_cpu.schema.json") == []
    got = {m: (r["driver_class"], r["classification_source"]) for m, r in by_module(rows).items()}
    assert got == {"synthgfx.sys": ("gpu", "inventory"), "synthnic.sys": ("network", "inventory"), "synthusb.sys": ("usb", "inventory"),
                   "synthaudio.sys": ("audio", "inventory"), "ntoskrnl.exe": ("kernel", "inbox-map")}
    bundle_id = json.loads((inv / "manifest.json").read_text(encoding="utf-8"))["bundle_id"]
    inventory_rows = rows_of(inv, "driver_service_class")
    for r in rows:
        if r["classification_source"] == "inventory":
            prefix, lines = r["classification_reference"].split("#")
            assert prefix == f"{bundle_id}/decoded/driver_service_class.jsonl"
            for item in lines.split(";"):
                assert inventory_rows[int(item.removeprefix("line:")) - 1]["driver_file"].lower() == r["module"].lower()
    join = next(c for c in meta_of(dpc, "dpcisr_module_cpu")["checks"] if c["name"] == "driver_inventory_join")
    assert join["ok"] is True and bundle_id in join["detail"]


def test_the_class_summary_sums_the_module_rows_and_gives_each_class_its_share(bundles):
    inv, dpc = bundles
    decode_driver_inventory.decode(inv, DECODED_AT)
    decode_dpcisr.decode(dpc, REPORT, DECODED_AT, inventory=inv)
    modules = rows_of(dpc, "dpcisr_module_cpu")
    classes = rows_of(dpc, "dpcisr_class_cpu")
    assert wf_schema.validate_rows(classes, "decoded/dpcisr_class_cpu.schema.json") == []
    meta = meta_of(dpc, "dpcisr_class_cpu")
    assert meta["status"] == "observed" and meta["row_count"] == len(classes) and all(c["ok"] for c in meta["checks"])
    report = (dpc / REPORT).read_text(encoding="utf-8-sig").splitlines()
    for kind in ("dpc", "isr"):
        mine = [m for m in modules if m["kind"] == kind]
        cpus = sorted({m["cpu"] for m in mine})
        present = {m["driver_class"] for m in mine}
        assert {c["driver_class"] for c in classes if c["kind"] == kind} == present, "a class without a module has no row"
        for cpu in [*cpus, None]:
            cell = [c for c in classes if c["kind"] == kind and c["cpu"] == cpu]
            total = sum(m["usec"] for m in mine if cpu is None or m["cpu"] == cpu)
            assert sum(c["usec"] for c in cell) == total and all(c["kind_usec"] == total for c in cell)
            if total:
                assert abs(sum(c["share"] for c in cell) - 1) < 1e-9
            else:
                assert all(c["share"] is None for c in cell)
            for c in cell:
                members = [m for m in mine if m["driver_class"] == c["driver_class"]]
                assert c["modules"] == sorted({m["module"] for m in members})
                assert c["usec"] == sum(m["usec"] for m in members if cpu is None or m["cpu"] == cpu)
                assert c["classification_sources"] == sorted({m["classification_source"] for m in members})
                for item in c["provenance"]["row_id_or_offset"].split(";"):
                    assert report[int(item.removeprefix("line:")) - 1].rstrip().endswith(tuple(c["modules"]))


def test_without_an_inventory_vendor_drivers_stay_unclassified(bundles):
    _, dpc = bundles
    assert decode_dpcisr.decode(dpc, REPORT, DECODED_AT)["status"] == "observed"
    got = {m: (r["driver_class"], r["classification_source"]) for m, r in by_module(rows_of(dpc, "dpcisr_module_cpu")).items()}
    assert got["synthnic.sys"] == ("unclassified", "none") and got["ntoskrnl.exe"] == ("kernel", "inbox-map")
    join = next(c for c in meta_of(dpc, "dpcisr_class_cpu")["checks"] if c["name"] == "driver_inventory_join")
    assert join["ok"] is True and "no driver inventory given" in join["detail"]


def test_an_inventory_whose_device_read_failed_is_recorded_and_the_map_alone_is_used(bundles):
    inv, dpc = bundles
    set_source_status(inv, "pnp_device_services", "not_collected")
    assert decode_driver_inventory.decode(inv, DECODED_AT)["status"] == "not_collected"
    assert decode_dpcisr.decode(dpc, REPORT, DECODED_AT, inventory=inv)["status"] == "observed"
    assert by_module(rows_of(dpc, "dpcisr_module_cpu"))["synthnic.sys"]["classification_source"] == "none"
    join = next(c for c in meta_of(dpc, "dpcisr_module_cpu")["checks"] if c["name"] == "driver_inventory_join")
    assert join["ok"] is False and "pnp_device_services not_collected" in join["detail"]


def refuse(dpc: Path, inv: Path, words: str) -> None:
    result = decode_dpcisr.decode(dpc, REPORT, DECODED_AT, inventory=inv)
    assert result["status"] == "decode_failed" and words in result["reason"], result
    assert not (dpc / "decoded").exists(), "a refused inventory writes nothing"


def test_an_inventory_of_another_machine_is_refused(bundles):
    inv, dpc = bundles
    decode_driver_inventory.decode(inv, DECODED_AT)
    manifest = json.loads((inv / "manifest.json").read_text(encoding="utf-8"))
    manifest["machine"]["machine_id"] = "0" * 32
    (inv / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    refuse(dpc, inv, "is not the machine of this trace")


def test_an_inventory_that_was_not_decoded_is_refused(bundles):
    inv, dpc = bundles
    refuse(dpc, inv, "run scripts/decode_driver_inventory.py on it first")


def test_an_inventory_table_that_failed_or_was_altered_is_refused(bundles):
    inv, dpc = bundles
    decode_driver_inventory.decode(inv, DECODED_AT)
    path = inv / "decoded" / "driver_service_class.jsonl"
    rows = rows_of(inv, "driver_service_class")
    rows[0]["driver_class"] = "printer"
    wf_schema.write_jsonl(path, rows)
    refuse(dpc, inv, "driver_service_class")
    meta = meta_of(inv, "driver_service_class")
    meta["status"] = "decode_failed"
    (inv / "decoded" / "driver_service_class.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    refuse(dpc, inv, "is decode_failed")


def test_a_schema_valid_edit_of_the_inventory_table_is_refused(bundles):
    inv, dpc = bundles
    decode_driver_inventory.decode(inv, DECODED_AT)
    rows = rows_of(inv, "driver_service_class")
    nic = next(r for r in rows if r["driver_file"] == "synthnic.sys")
    assert nic["driver_class"] == "network"
    nic["driver_class"] = "gpu"
    assert not wf_schema.validate_rows(rows, "decoded/driver_service_class.schema.json")
    wf_schema.write_jsonl(inv / "decoded" / "driver_service_class.jsonl", rows)
    refuse(dpc, inv, "differs from the rows its hash checked raw exports give")


def test_a_bundle_that_is_not_an_inventory_is_refused(bundles):
    _, dpc = bundles
    other = dpc.parent / "other"
    shutil.copytree(BUNDLES / "diskio-trace", other)
    refuse(dpc, other, "so it is not a driver inventory")


S1 = REPO_ROOT / "fixtures" / "scenario-runs" / "s1"


def test_an_s1_run_is_its_own_inventory(tmp_path):
    s1 = tmp_path / "s1"
    shutil.copytree(S1, s1)
    result = decode_driver_inventory.decode(s1, DECODED_AT)
    assert result["status"] == "observed", result
    assert meta_of(s1, "driver_service_class")["status"] == "observed"
    result = decode_dpcisr.decode(s1, REPORT, DECODED_AT, inventory=s1)
    assert result["status"] == "observed", result
    rows = rows_of(s1, "dpcisr_module_cpu")
    assert any(r["classification_source"] == "inventory" for r in rows)
    bundle_id = json.loads((s1 / "manifest.json").read_text(encoding="utf-8"))["bundle_id"]
    join = next(c for c in meta_of(s1, "dpcisr_module_cpu")["checks"] if c["name"] == "driver_inventory_join")
    assert join["ok"] is True and bundle_id in join["detail"]


def test_an_s1_run_without_the_device_read_is_not_an_inventory_table(tmp_path):
    s1 = tmp_path / "s1"
    shutil.copytree(S1, s1)
    set_source_status(s1, "pnp_device_services", "capture_failed")
    result = decode_driver_inventory.decode(s1, DECODED_AT)
    assert result["status"] == "not_collected" and "pnp_device_services is capture_failed" in result["reason"]
    assert not (s1 / "decoded" / "driver_service_class.jsonl").exists()


def test_a_summary_of_failed_module_rows_is_never_written(bundles, monkeypatch):
    _, dpc = bundles
    monkeypatch.setattr(driver_classes, "classify_module", lambda module, index: {
        "driver_class": "printer", "classification_source": "none", "classification_reason": "broken", "classification_reference": None})
    result = decode_dpcisr.decode(dpc, REPORT, DECODED_AT)
    assert result["status"] == "decode_failed"
    for table in ("dpcisr_module_cpu", "dpcisr_class_cpu"):
        assert rows_of(dpc, table) == [] and meta_of(dpc, table)["status"] == "decode_failed"
