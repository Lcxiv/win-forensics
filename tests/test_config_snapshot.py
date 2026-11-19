"""The config-snapshot bundles decode into config_snapshot, powercfg and process_inventory, and keep status apart from evidence.

The three bundles under fixtures/collector-bundles are synthetic end to end (collectors/windows/tests/SyntheticScenarios.ps1,
New-WfSyntheticConfigMachine). Nothing in them comes from a real machine.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import decode_config_snapshot
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = ["config-snapshot", "config-snapshot-clean", "config-snapshot-denied"]
OBSERVED = ("observed", "observed_zero")
# What the synthetic owner's files carry on purpose, and what must never reach a bundle or a table in clear.
SECRETS = ("Synthetic Owner", "owner@example.test", "DESKTOP-SYNTH01", "Jane Doe", "F0F1F2000001")


@pytest.fixture()
def bundle_copy(tmp_path):
    counter = {"n": 0}

    def copy(case: str) -> Path:
        counter["n"] += 1
        target = tmp_path / f"{case}-{counter['n']}"
        shutil.copytree(BUNDLES / case, target)
        return target
    return copy


def decoded(bundle: Path) -> dict:
    return decode_config_snapshot.decode(bundle, decoded_at="2026-09-03T00:00:00Z")


def rows(bundle: Path, table: str) -> list[dict]:
    return wf_schema.read_jsonl(bundle / "decoded" / f"{table}.jsonl")


def meta(bundle: Path, table: str) -> dict:
    return json.loads((bundle / "decoded" / f"{table}.meta.json").read_text(encoding="utf-8"))


def every_file(bundle: Path) -> list[Path]:
    return [p for p in bundle.rglob("*") if p.is_file()]


@pytest.mark.parametrize("case", ["config-snapshot", "config-snapshot-clean"])
def test_every_table_validates_and_points_into_its_source(case, bundle_copy):
    bundle = bundle_copy(case)
    result = decoded(bundle)
    assert result["status"] == "observed", result
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    listed = {a["path"]: a["sha256"] for c in manifest["collectors"] for a in c["artifacts"]}
    for table in ("config_snapshot", "powercfg", "process_inventory"):
        table_rows = rows(bundle, table)
        assert table_rows, table
        assert wf_schema.validate_rows(table_rows, f"decoded/{table}.schema.json") == []
        sidecar = meta(bundle, table)
        assert wf_schema.validate_object(sidecar, "decoded/table_meta.schema.json") == []
        assert sidecar["row_count"] == len(table_rows) and sidecar["status"] == "observed"
        assert sidecar["schema_version"] == wf_schema.table_schema_version(table) == "1.1.0"
        sources = {s["path"]: s["sha256"] for s in sidecar["source_files"]}
        for path, sha in sources.items():
            assert listed[path] == sha, "a sidecar names manifest artifacts by path and hash"
        for row in table_rows:
            prov = row["provenance"]
            assert prov["source_file"] in sources and prov["decoded_table"] == table
            assert prov["schema_version"] == sidecar["schema_version"] and prov["decoder_version"] == sidecar["decoder_version"]
            # Every observed source the table lists is observed in the manifest; a not_collected source never feeds a row.
            entry = next(c for c in manifest["collectors"] if any(a["path"] == prov["source_file"] for a in c["artifacts"]))
            assert entry["status"] in OBSERVED
            assert row["source_id"] == entry["id"]


@pytest.mark.parametrize("case", ["config-snapshot", "config-snapshot-clean", "config-snapshot-denied"])
def test_no_user_profile_name_or_email_anywhere_after_decoding(case, bundle_copy):
    bundle = bundle_copy(case)
    decoded(bundle)
    for path in every_file(bundle):
        text = path.read_text(encoding="utf-8", errors="replace")
        for secret in SECRETS:
            assert secret not in text, f"{path.relative_to(bundle)} carries {secret}"


def test_copied_files_are_protected_and_their_original_hash_is_recorded(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    ini = (bundle / "raw" / "process_lasso_config" / "prolasso.ini").read_text(encoding="utf-8")
    assert "ExcludedProcesses=C:\\Users\\user-" in ini and "SupportContact=mail-" in ini
    assert "TargetPowerPlan=Synthetic Low Latency" in ini, "the owner's own settings stay readable"
    report = json.loads((bundle / "raw" / "process_lasso_config" / "result.json").read_text(encoding="utf-8"))
    assert report["protection"] == {"user_profile_names_replaced": 2, "email_addresses_replaced": 1, "unc_hosts_replaced": 1, "mac_addresses_replaced": 0}
    assert "ConfigPath=\\\\host-" in ini, "a UNC host is a computer name and leaves as a pseudonym"
    assert report["copy_is_verbatim"] is False and len(report["source_sha256"]) == 64
    assert report["source_sha256"] != wf_schema.sha256_of(bundle / "raw" / "process_lasso_config" / "prolasso.ini"), "a protected copy differs from the original"
    journal = (bundle / "raw" / "stutter_guard_journal" / "journal.json").read_text(encoding="utf-8")
    assert '"exportedBy": "C:\\\\Users\\\\user-' in journal, "a doubled separator in an escaped path is still a user profile path"
    # The same owner maps to the same pseudonym in every copied file of the bundle.
    log = (bundle / "raw" / "process_lasso_log" / "processlasso.log").read_text(encoding="utf-8")
    pseudonym = ini.split("ExcludedProcesses=C:\\Users\\")[1].split("\\")[0]
    assert pseudonym in log and pseudonym in journal
    # In the vendor log everything after the first program on a line is gone, with the columns that followed it.
    log_report = json.loads((bundle / "raw" / "process_lasso_log" / "result.json").read_text(encoding="utf-8"))
    assert log_report["protection"]["command_arguments_removed"] == 3 and log_report["copy_is_verbatim"] is False
    assert log.count("<arguments omitted>") == 3 and "Priority lowered" not in log and "GPU adapter preference set" not in log
    decoded(bundle)
    copied = {r["key"]: r for r in rows(bundle, "config_snapshot") if r["key"] in ("config_copied", "log_copied", "journal_copied")}
    assert set(copied) == {"config_copied", "log_copied", "journal_copied"}
    assert copied["config_copied"]["decoded"]["source_sha256"] == report["source_sha256"]
    # The row's facts live in result.json, so that is what the provenance names; the copy is a raw artifact the row points at.
    assert copied["config_copied"]["provenance"]["source_file"] == "raw/process_lasso_config/result.json"
    assert copied["config_copied"]["provenance"]["row_id_or_offset"] == "offset:0"
    assert copied["config_copied"]["decoded"]["copy"] == "raw/process_lasso_config/prolasso.ini"
    assert copied["log_copied"]["decoded"]["copy_gate"]["passed"] is True, "the vendor log was copied because the INI says command lines are off"
    assert copied["log_copied"]["decoded"]["protection"]["command_arguments_removed"] == 3, "the row carries the count of lines cut after their program"
    assert copied["log_copied"]["decoded"]["copy_is_verbatim"] is False
    assert "command_arguments_removed" not in copied["config_copied"]["decoded"]["protection"], "only the vendor log asks for the rule"
    sidecar = meta(bundle, "config_snapshot")
    assert {"raw/process_lasso_config/result.json", "raw/process_lasso_config/prolasso.ini"} <= {f["path"] for f in sidecar["source_files"]}


def test_a_summarised_log_is_never_labelled_a_copy(bundle_copy):
    """The copy gate did not pass (the INI does not say command lines are off), so the collector wrote a summary as the primary."""
    bundle = bundle_copy("config-snapshot")
    folder = bundle / "raw" / "process_lasso_log"
    report = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    gate = dict(report["copy_gate"], passed=False, detail="the gating file does not match the pattern")
    report.update({"mode": "summary", "copy_gate": gate, "summarised": True, "copied": False, "source_encoding": None,
                   "source_byte_order_mark": None, "copy_is_verbatim": None, "protection": None})
    summary = {"path": report["path"], "bytes": report["source_bytes"], "last_write_time_utc": report["last_write_time_utc"],
               "sha256": report["source_sha256"], "lines": 4, "address_tokens": 0, "content_kept": False}
    (folder / "result.json").write_text(json.dumps(report), encoding="utf-8")
    (folder / "processlasso.log").write_text(json.dumps(summary), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    entry = next(c for c in manifest["collectors"] if c["id"] == "process_lasso_log")
    for artifact in entry["artifacts"]:
        artifact["bytes"] = (bundle / artifact["path"]).stat().st_size
        artifact["sha256"] = wf_schema.sha256_of(bundle / artifact["path"])
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert decoded(bundle)["tables"]["config_snapshot"]["status"] == "observed"
    table = rows(bundle, "config_snapshot")
    assert wf_schema.validate_rows(table, "decoded/config_snapshot.schema.json") == []
    by_key = {r["key"]: r for r in table if r["source_id"] in ("process_lasso_config", "process_lasso_log", "stutter_guard_journal")}
    assert set(by_key) == {"config_copied", "log_summarised", "journal_copied"}, "a summary is never keyed as a copy"
    row = by_key["log_summarised"]
    assert row["present"] is True and row["category"] == "process_lasso"
    assert "summarised" in row["value_text"] and "copy gate did not pass" in row["value_text"]
    assert row["decoded"]["copy"] is None and row["decoded"]["summary"] == "raw/process_lasso_log/processlasso.log"
    assert row["decoded"]["copy_gate"]["passed"] is False and row["decoded"]["copy_is_verbatim"] is None and row["decoded"]["protection"] is None
    assert row["decoded"]["source_sha256"] == report["source_sha256"] and row["value_number"] == report["source_bytes"]
    assert row["provenance"]["source_file"] == "raw/process_lasso_log/result.json" and row["provenance"]["row_id_or_offset"] == "offset:0"
    assert by_key["config_copied"]["decoded"]["summary"] is None

    unclear = bundle_copy("config-snapshot")
    report_path = unclear / "raw" / "process_lasso_log" / "result.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["copied"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")
    result = decoded(unclear)
    assert result["tables"]["config_snapshot"]["status"] == "decode_failed" and "a copy or a summary" in result["tables"]["config_snapshot"]["reason"]


@pytest.mark.parametrize("value", [
    {"name": "MSISupported", "kind": "REG_BINARY", "data": "01000000", "bytes_hex": "01000000"},
    {"name": "MSISupported", "kind": "REG_DWORD", "data": None, "bytes_hex": "0100"},
    {"name": "MSISupported", "kind": "REG_DWORD", "data": 2, "bytes_hex": "02000000"},
], ids=["binary", "short_dword", "other_number"])
def test_msi_supported_that_is_not_a_readable_dword_reads_as_unknown(value):
    text, number, reading, documented_by = decode_config_snapshot.decode_registry_value(decode_config_snapshot.MSI_SUBKEY, value)
    assert reading["msi_enabled_in_configuration"] is None and number is None
    assert "not a readable REG_DWORD" in text and "not enabled" not in text
    assert documented_by == decode_config_snapshot.DOC_MSI
    for data, expected in ((1, True), (0, False)):
        known = decode_config_snapshot.decode_registry_value(decode_config_snapshot.MSI_SUBKEY, {"name": "MSISupported", "kind": "REG_DWORD", "data": data, "bytes_hex": f"0{data}000000"})
        assert known[2]["msi_enabled_in_configuration"] is expected and known[1] == data


def test_interrupt_policy_rows_carry_raw_bytes_and_documented_decodings(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    decoded(bundle)
    table = rows(bundle, "config_snapshot")
    gpu = [r for r in table if r["device_name"] == "Synthetic Display Adapter"]
    by_key = {r["key"]: r for r in gpu}
    assert by_key["interrupt_management_key"]["present"] is True
    assert by_key["interrupt_management_key"]["registry_path"] == "SetupDiOpenDevRegKey(DICS_FLAG_GLOBAL, DIREG_DEV, KEY_READ)\\Interrupt Management"
    policy = by_key["DevicePolicy"]
    assert policy["category"] == "interrupt_affinity" and policy["raw_bytes_hex"] == "04000000" and policy["registry_value_kind"] == "REG_DWORD"
    assert policy["decoded"] == {"policy": "IrqPolicySpecifiedProcessors", "value": 4} and "ne-wdm-_irq_device_policy" in policy["documented_by"]
    assert policy["registry_path"].endswith("\\Interrupt Management\\Affinity Policy") and "Enum" not in policy["registry_path"]
    mask = by_key["AssignmentSetOverride"]
    assert mask["raw_bytes_hex"] == "2000000000000000" and mask["registry_value_kind"] == "REG_BINARY"
    assert mask["decoded"]["processors"] == [5] and mask["decoded"]["mask_hex"] == "0x20" and mask["decoded"]["byte_order"] == "little endian"
    assert mask["value_number"] == 32 and isinstance(mask["value_number"], int), "a mask is an exact integer, never a float"
    assert "not the processor that services the interrupt" in mask["decoded"]["note"], "registry intention is not effective routing"
    priority = by_key["DevicePriority"]
    assert priority["documented_by"] is None and priority["decoded"] is None and priority["value_text"] == "3", "an undocumented value is kept verbatim, never named"
    assert by_key["MSISupported"]["category"] == "msi_mode" and by_key["MSISupported"]["decoded"]["msi_enabled_in_configuration"] is True
    assert by_key["MessageNumberLimit"]["value_number"] == 16
    # The network adapter's mask is a REG_DWORD, the host controller's a REG_QWORD; both decode to processors by bit.
    nic = {r["key"]: r for r in table if r["device_name"] == "Synthetic 2.5GbE Controller"}
    assert nic["AssignmentSetOverride"]["decoded"]["processors"] == [8, 9, 10, 11] and nic["AssignmentSetOverride"]["registry_value_kind"] == "REG_DWORD"
    xhci = {r["key"]: r for r in table if r["device_name"] == "Synthetic USB 3.1 eXtensible Host Controller"}
    assert xhci["AssignmentSetOverride"]["decoded"]["processors"] == [2] and xhci["AssignmentSetOverride"]["registry_value_kind"] == "REG_QWORD"
    assert xhci["MSISupported"]["present"] is False and xhci["MSISupported"]["value_text"] == "absent", "an absent documented value is a row that says absent"
    assert xhci["Comment"]["value_text"].startswith("omitted:") and xhci["Comment"]["raw_bytes_hex"] is None, "a string typed value arrives omitted and stays so"
    # The HD Audio controller (the PCI function whose bus driver owns the interrupt), disabled in Device Manager: problem code 22
    # next to its MSI row, MSI switched off, and no affinity policy at all.
    audio = {r["key"]: r for r in table if r["device_name"] == "Synthetic High Definition Audio Controller"}
    assert audio["MSISupported"]["device_problem_code"] == 22 and audio["MSISupported"]["device_status"] == "Error"
    assert audio["MSISupported"]["decoded"]["msi_enabled_in_configuration"] is False
    assert audio["DevicePolicy"]["present"] is False and audio["AssignmentSetOverride"]["present"] is False
    # The storage controller: policy 5 and no mask, which is a documented combination.
    nvme = {r["key"]: r for r in table if r["device_name"] == "Synthetic NVMe Controller"}
    assert nvme["DevicePolicy"]["decoded"]["policy"] == "IrqPolicySpreadMessagesAcrossAllProcessors" and nvme["AssignmentSetOverride"]["present"] is False
    # Only PCI functions are selected: the codec, the USB receiver and the Bluetooth peer never reach the table.
    assert {r["device_instance_id"].split("\\")[0] for r in table if r["source_id"] == "interrupt_policy"} == {"PCI"}
    assert not [r for r in table if r["device_name"] in ("Synthetic Wireless Receiver", "Synthetic High Definition Audio Device")]


def test_unknown_is_never_written_as_absent(bundle_copy):
    """A device whose hardware key could not be opened, or whose enumeration was cut short, leaves present null in every row."""
    bundle = bundle_copy("config-snapshot")
    path = bundle / "raw" / "interrupt_policy" / "keys.json"
    devices = json.loads(path.read_text(encoding="utf-8"))
    nic = next(d for d in devices if d["class"] == "Net")
    nic.update({"stage": "open_hardware_key", "error_code": 5, "registry_error": "ERROR_ACCESS_DENIED", "device_opened": True})
    nic["hardware_key_state"] = {"exists": None, "error_code": 5, "error": "ERROR_ACCESS_DENIED"}
    nic["interrupt_management"] = {"exists": None, "error_code": None, "error": None}
    for leaf in nic["interrupt_keys"]:
        leaf.update({"exists": None, "values": [], "enumeration_complete": False})
    xhci = next(d for d in devices if d["service"] == "USBXHCI")
    affinity = next(k for k in xhci["interrupt_keys"] if k["subkey"].endswith("Affinity Policy"))
    affinity["values"] = [v for v in affinity["values"] if v["name"] == "DevicePolicy"]
    affinity["enumeration_complete"] = False
    affinity["error"] = "the cap of 1 values was reached; the rest are unknown"
    path.write_text(json.dumps(devices), encoding="utf-8")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for c in manifest["collectors"]:
        for a in c["artifacts"]:
            if a["path"] == "raw/interrupt_policy/keys.json":
                a["sha256"] = wf_schema.sha256_of(path)
                a["bytes"] = path.stat().st_size
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert decoded(bundle)["tables"]["config_snapshot"]["status"] == "observed"
    table = rows(bundle, "config_snapshot")
    denied = [r for r in table if r["device_name"] == "Synthetic 2.5GbE Controller"]
    assert len(denied) == 1 and denied[0]["present"] is None and denied[0]["value_text"].startswith("unknown (stage open_hardware_key)")
    assert denied[0]["decoded"]["error_code"] == 5
    capped = {r["key"]: r for r in table if r["device_name"] == "Synthetic USB 3.1 eXtensible Host Controller" and r["category"] == "interrupt_affinity"}
    assert capped["DevicePolicy"]["present"] is True
    assert capped["AssignmentSetOverride"]["present"] is None and "did not complete" in capped["AssignmentSetOverride"]["value_text"]
    assert wf_schema.validate_rows(table, "decoded/config_snapshot.schema.json") == []


def test_a_clean_machine_records_absence_not_missing_data(bundle_copy):
    bundle = bundle_copy("config-snapshot-clean")
    decoded(bundle)
    table = rows(bundle, "config_snapshot")
    affinity = [r for r in table if r["category"] in ("interrupt_affinity", "msi_mode")]
    assert affinity and all(r["present"] is False for r in affinity)
    assert all(r["value_text"] == "absent" for r in affinity), "the hardware keys open and hold no Interrupt Management: absence, not an unknown"
    assert {r["device_instance_id"].split("\\")[0] for r in affinity} == {"PCI"} and len({r["device_instance_id"] for r in affinity}) == 5
    tdr = {r["key"]: r for r in table if r["category"] == "tdr"}
    assert set(tdr) == {"TdrLevel", "TdrDelay", "TdrDdiDelay", "TdrDebugMode", "TdrLimitTime", "TdrLimitCount", "TdrTestMode"}
    assert all(r["present"] is False and "default" in r["value_text"] for r in tdr.values())
    installs = {r["category"]: r for r in table if r["key"] == "install_folder"}
    assert installs["process_lasso"]["present"] is False and installs["stutter_guard"]["present"] is False
    running = {r["key"]: r for r in table if r["key"].startswith("running:") or r["key"] == "timer_helper_running"}
    assert set(running) == {"running:gui", "running:governor", "running:session_agent", "timer_helper_running"}
    assert all(r["present"] is False and r["provenance"]["row_id_or_offset"] == "offset:0" for r in running.values())
    assert not [r for r in table if r["key"].endswith(("_copied", "_summarised"))], "a not_collected file produces no row"


def test_tdr_rows_name_the_documented_level(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    decoded(bundle)
    tdr = {r["key"]: r for r in rows(bundle, "config_snapshot") if r["category"] == "tdr"}
    assert tdr["TdrLevel"]["decoded"] == {"level": "TdrLevelRecover"} and tdr["TdrLevel"]["raw_bytes_hex"] == "03000000"
    assert tdr["TdrDelay"]["decoded"] == {"seconds": 10} and tdr["TdrDdiDelay"]["present"] is False
    assert all("tdr-registry-keys" in r["documented_by"] for r in tdr.values())
    assert all(r["registry_path"].endswith("\\Control\\GraphicsDrivers") for r in tdr.values())


def test_cpu_topology_rows_come_from_the_documented_api_and_cim_rows_say_what_they_cannot_tell(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    topology_source = next(c for c in manifest["collectors"] if c["id"] == "logical_processor_map")
    assert topology_source["status"] == "observed" and topology_source["command"] == ["kernel32.dll!GetLogicalProcessorInformationEx", "RelationAll"]
    decoded(bundle)
    table = rows(bundle, "config_snapshot")
    cim = {r["key"]: r for r in table if r["category"] == "cpu_topology" and r["source_id"] in ("processors", "cpu_caches") and r["key"] != "cache"}
    assert cim["number_of_cores"]["value_number"] == 6 and cim["number_of_logical_processors"]["value_number"] == 12
    assert cim["smt_enabled"]["value_text"] == "true" and "logical_processor_map" in cim["smt_enabled"]["decoded"]["note"]
    assert "processor_groups" not in cim, "the group layout is observed from the topology records, never inferred from a count"
    caches = [r for r in table if r["key"] == "cache"]
    assert [c["decoded"]["level"] for c in caches] == ["Primary", "Secondary", "Tertiary"]
    assert all("not which logical processors share it" in c["decoded"]["note"] for c in caches)
    # The sibling map comes from GetLogicalProcessorInformationEx records, by index into topology.json, never from adjacency.
    topo = {r["key"]: r for r in table if r["source_id"] == "logical_processor_map"}
    assert all(r["provenance"]["source_file"] == "raw/logical_processor_map/topology.json" and r["provenance"]["row_id_or_offset"].startswith("index:") for r in topo.values())
    assert all("getlogicalprocessorinformationex" in r["documented_by"] for r in topo.values())
    assert topo["core:0"]["decoded"]["logical_processors"] == [{"group": 0, "processor": 0}, {"group": 0, "processor": 6}] and topo["core:0"]["decoded"]["smt"] is True
    assert topo["logical_processor:0:6"]["decoded"]["siblings"] == [0] and topo["logical_processor:0:6"]["decoded"]["core"] == 0
    assert topo["logical_processor:0:5"]["decoded"]["siblings"] == [11] and topo["logical_processor:0:11"]["decoded"]["siblings"] == [5]
    assert [c["level"] for c in topo["logical_processor:0:6"]["decoded"]["caches"]] == [1, 1, 2, 3]
    assert topo["logical_processor:0:6"]["decoded"]["caches"][3]["shared_with"] == [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11]
    assert topo["group:0"]["decoded"]["active_processor_count"] == 12 and topo["group:0"]["decoded"]["active_mask_hex"] == "0xfff"
    assert len([k for k in topo if k.startswith("cache:")]) == 19 and topo["package:0"]["present"] is True
    assert len([k for k in topo if k.startswith("logical_processor:")]) == 12


def test_a_failed_topology_read_is_a_status_and_no_sibling_row(bundle_copy):
    bundle = bundle_copy("config-snapshot-denied")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    failed = next(c for c in manifest["collectors"] if c["id"] == "logical_processor_map")
    assert failed["status"] == "not_collected" and "stage compile" in failed["status_reason"]
    assert sorted(a["role"] for a in failed["artifacts"]) == ["config", "report"], "the report says why; there is no primary"
    # A full bundle whose topology source is marked failed decodes the rest and writes no sibling row.
    partial = bundle_copy("config-snapshot")
    path = partial / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    entry = next(c for c in manifest["collectors"] if c["id"] == "logical_processor_map")
    entry["status"], entry["status_reason"] = "capture_failed", "stage read: the call returned FALSE (Win32 error 1450)"
    entry["artifacts"] = [a for a in entry["artifacts"] if a["role"] == "config"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert decoded(partial)["tables"]["config_snapshot"]["status"] == "observed"
    assert not [r for r in rows(partial, "config_snapshot") if r["source_id"] == "logical_processor_map"]
    assert any(c["name"] == "logical_processor_map" and "never turned into evidence" in c["detail"] for c in meta(partial, "config_snapshot")["checks"])


def test_powercfg_rows_follow_the_structure_in_english_and_by_shape_in_german(bundle_copy):
    english = bundle_copy("config-snapshot")
    decoded(english)
    table = rows(english, "powercfg")
    schemes = [r for r in table if r["kind"] == "scheme" and r["source_id"] == "power_schemes"]
    assert [(r["scheme_name"], r["is_active"]) for r in schemes] == [("Balanced", False), ("High performance", False), ("Power saver", False), ("Synthetic Low Latency", True)]
    active = next(r for r in table if r["source_id"] == "power_active_scheme")
    assert active["scheme_guid"] == "11111111-2222-4333-8444-555555555555" and active["is_active"] is True
    settings = {(r["alias"], r["source_id"]): r for r in table if r["kind"] == "setting"}
    boost = settings[("PERFBOOSTMODE", "power_settings")]
    assert boost["ac_value_hex"] == "0x00000002" and boost["dc_value_hex"] == "0x00000001" and boost["classified_by"] == "label"
    assert boost["possible_values"] == ["000: Disabled", "001: Enabled", "002: Aggressive"] and boost["hidden"] is False
    assert boost["subgroup_guid"] == "54533251-82be-4824-96c1-47b60b740d00" and boost["provenance"]["row_id_or_offset"] == "line:22-32"
    throttle = settings[("PROCTHROTTLEMIN", "power_settings")]
    assert throttle["unit"] == "%" and throttle["min_value_hex"] == "0x00000000" and throttle["max_value_hex"] == "0x00000064"
    parking = settings[("CPMINCORES", "power_settings_hidden")]
    assert parking["hidden"] is True, "a setting only /qh lists is hidden"
    assert settings[("PROCTHROTTLEMIN", "power_settings_hidden")]["hidden"] is False, "a setting both listings carry is not"
    aliases = [r for r in table if r["kind"] == "alias"]
    assert {r["alias"] for r in aliases} >= {"SCHEME_BALANCED", "SUB_PROCESSOR", "CPMINCORES", "IDLEDISABLE"}
    assert next(r for r in aliases if r["alias"] == "CPMINCORES")["subgroup_guid"] == "54533251-82be-4824-96c1-47b60b740d00"

    german = bundle_copy("config-snapshot-clean")
    decoded(german)
    table = rows(german, "powercfg")
    settings = {r["alias"]: r for r in table if r["kind"] == "setting"}
    assert settings["PROCTHROTTLEMIN"]["classified_by"] == "value"
    assert settings["PROCTHROTTLEMIN"]["ac_value_hex"] == "0x00000005" and settings["PROCTHROTTLEMIN"]["dc_value_hex"] == "0x00000005"
    assert settings["PROCTHROTTLEMIN"]["min_value_hex"] == "0x00000000" and settings["PROCTHROTTLEMIN"]["max_value_hex"] == "0x00000064"
    assert settings["PERFBOOSTMODE"]["possible_values"] == ["000: Deaktiviert", "001: Aktiviert"]
    assert settings["PROCTHROTTLEMIN"]["setting_name"] == "Minimaler Leistungszustand des Prozessors", "names stay verbatim"
    assert all(r["hidden"] is False for r in settings.values()), "/qh failed, so nothing is called hidden"
    listing = [r for r in table if r["kind"] == "scheme" and r["source_id"] == "power_schemes"]
    assert [r["is_active"] for r in listing] == [True, False, False], "the active marker is read by its star, not by a label"


def test_power_rows_in_config_snapshot_are_derived_and_say_so(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    decoded(bundle)
    table = rows(bundle, "config_snapshot")
    power = {r["key"]: r for r in table if r["category"] in ("power_scheme", "processor_power", "core_parking")}
    assert power["active_scheme_guid"]["value_text"] == "11111111-2222-4333-8444-555555555555"
    overlay = power["active_overlay"]
    assert overlay["present"] is None and overlay["value_text"].startswith("none evident"), "whether /query prints the overlay GUID is unverified, so this is not an absence"
    assert "currently active overlay scheme" in overlay["decoded"]["rule"] and "customize-power-slider" in overlay["documented_by"]
    assert power["cpmincores"]["category"] == "core_parking" and power["cpmincores"]["decoded"]["ac"] == 100 and "cpmincores" in power["cpmincores"]["documented_by"]
    assert power["idledisable"]["decoded"] == {"ac": 1, "dc": 0, "unit": None, "possible_values": ["000: Enable idle", "001: Disable idle"],
                                                "setting_guid": "5d76a2ca-e8c0-402f-a133-2158492d58ad", "classified_by": "label", "listing": "power_settings_hidden"}
    assert power["perfboostmode"]["decoded"]["ac"] == 2 and power["perfboostmode"]["source_id"] == "power_settings"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    mode = next(c for c in manifest["collectors"] if c["id"] == "power_mode")
    assert mode["status"] == "not_collected" and "overlay" in mode["status_reason"]
    timer = next(c for c in manifest["collectors"] if c["id"] == "timer_resolution")
    assert timer["status"] == "not_collected" and "powercfg /energy" in timer["status_reason"] and "never requests" in timer["status_reason"].lower().replace("nothing here requests", "never requests")
    assert not [r for r in table if r["category"] == "timer"], "no timer row: the question has no documented read, so it stays a status"


def test_process_inventory_rows_carry_the_snapshot_and_no_handles_were_asked_for(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    processes = next(c for c in manifest["collectors"] if c["id"] == "processes")
    assert processes["requested"]["options"]["snapshot"] == "start" and processes["requested"]["options"]["command_line_requested"] is False
    assert "CommandLine" not in processes["command"][7] and "ExecutablePath" not in processes["command"][7]
    helper = next(c for c in manifest["collectors"] if c["id"] == "timer_helper_process")
    assert helper["requested"]["options"]["filter"] == "Name = 'DpcTimerRes.exe'" and helper["requested"]["options"]["command_line_requested"] is True
    decoded(bundle)
    table = rows(bundle, "process_inventory")
    assert {r["snapshot"] for r in table} == {"start"} and len(table) == 7
    helper_row = next(r for r in table if r["name"] == "DpcTimerRes.exe")
    assert helper_row["command_line"] is None and helper_row["image_path"] is None, "the general list carries no command line or image path"
    assert helper_row["base_priority"] == 8 and helper_row["cpu_time_s"] == 0.07 and helper_row["start_time_utc"].endswith("Z")
    stutter = [r for r in rows(bundle, "config_snapshot") if r["key"] == "timer_helper_running"]
    assert len(stutter) == 1 and stutter[0]["present"] is True
    assert stutter[0]["decoded"]["command_line"].startswith('"C:\\Users\\user-') and stutter[0]["decoded"]["command_line"].endswith('\\Stutter Guard\\DpcTimerRes.exe" 10000')
    assert "Synthetic Owner" not in json.dumps(stutter[0]), "the helper's path under the owner's profile leaves as a pseudonym"
    assert stutter[0]["source_id"] == "timer_helper_process"
    components = {r["key"]: r for r in rows(bundle, "config_snapshot") if r["key"].startswith("running:")}
    assert components["running:governor"]["decoded"]["pids"] == [6140] and "how-it-works" in components["running:governor"]["documented_by"]
    stop = bundle_copy("config-snapshot-clean")
    decoded(stop)
    assert {r["snapshot"] for r in rows(stop, "process_inventory")} == {"stop"}


def test_install_listings_hash_and_version_without_copying(bundle_copy):
    bundle = bundle_copy("config-snapshot")
    decoded(bundle)
    lasso = {r["key"]: r for r in rows(bundle, "config_snapshot") if r["category"] == "process_lasso" and r["key"].startswith("file:")}
    assert lasso["file:ProcessLasso.exe"]["value_text"] == "19.0.0.94" and lasso["file:ProcessLasso.exe"]["decoded"]["sha256"] == "a5" * 32
    assert lasso["file:prolasso.chm"]["value_text"] == "no version resource"
    guard = {r["key"]: r for r in rows(bundle, "config_snapshot") if r["category"] == "stutter_guard" and r["key"].startswith("file:")}
    assert set(guard) == {"file:DpcTimerRes.exe", "file:StutterGuard.exe"}
    listing = json.loads((bundle / "raw" / "stutter_guard_install" / "listing.json").read_text(encoding="utf-8"))
    assert isinstance(listing, list) and all(len(f["sha256"]) == 64 for f in listing)
    folder = next(r for r in rows(bundle, "config_snapshot") if r["category"] == "stutter_guard" and r["key"] == "install_folder")
    assert folder["present"] is True and folder["provenance"] ["source_file"] == "raw/stutter_guard_install/result.json" and folder["provenance"]["row_id_or_offset"] == "offset:0"
    assert folder["decoded"]["file_count"] == 2 and folder["value_number"] == 2
    assert guard["file:StutterGuard.exe"]["provenance"]["source_file"] == "raw/stutter_guard_install/listing.json" and guard["file:StutterGuard.exe"]["provenance"]["row_id_or_offset"] == "index:1"
    assert not any(p.suffix == ".exe" for p in every_file(bundle)), "binaries are never copied"


def test_denied_bundle_decodes_to_no_table_and_a_status(bundle_copy):
    bundle = bundle_copy("config-snapshot-denied")
    result = decoded(bundle)
    assert result["status"] == "not_collected"
    assert {t: r["status"] for t, r in result["tables"].items()} == {"config_snapshot": "not_collected", "powercfg": "not_collected", "process_inventory": "not_collected"}
    assert not (bundle / "decoded").exists(), "an input that is absent is never decoded into an empty table"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for collector in manifest["collectors"]:
        assert collector["status"] == "not_collected" and collector["status_reason"]
        assert [a for a in collector["artifacts"] if a["role"] == "primary"] == []
    registry = next(c for c in manifest["collectors"] if c["id"] == "interrupt_policy")
    assert "none of the 5 selected devices could be read" in registry["status_reason"] and "ERROR_ACCESS_DENIED" in registry["status_reason"]
    assert "CurrentControlSet\\Enum" not in json.dumps(manifest), "no physical Enum path is named anywhere"


def test_decoder_refuses_a_foreign_bundle_and_a_missing_primary(bundle_copy, tmp_path):
    foreign = bundle_copy("config-snapshot")
    manifest = json.loads((foreign / "manifest.json").read_text(encoding="utf-8"))
    manifest["scenario"]["id"] = "rf_survey"
    (foreign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = decoded(foreign)
    assert result["status"] == "decode_failed" and "not config_snapshot" in result["reason"] and not (foreign / "decoded").exists()

    missing = bundle_copy("config-snapshot")
    (missing / "raw" / "interrupt_policy" / "keys.json").unlink()
    result = decoded(missing)
    assert result["tables"]["config_snapshot"]["status"] == "decode_failed" and "missing from the bundle" in result["tables"]["config_snapshot"]["reason"]
    assert result["tables"]["powercfg"]["status"] == "observed", "the other tables still decode"
    assert rows(missing, "config_snapshot") == [] and meta(missing, "config_snapshot")["status"] == "decode_failed"

    broken = bundle_copy("config-snapshot")
    (broken / "raw" / "processes" / "records.json").write_text('[{"Name": "x"}]', encoding="utf-8")
    result = decoded(broken)
    assert result["tables"]["process_inventory"]["status"] == "decode_failed" and "no ProcessId" in result["tables"]["process_inventory"]["reason"]

    gone = bundle_copy("config-snapshot")
    (gone / "raw" / "processes" / "records.json").unlink()
    result = decoded(gone)
    assert result["tables"]["process_inventory"]["status"] == "decode_failed" and "missing from the bundle" in result["tables"]["process_inventory"]["reason"]
    assert not (gone / "decoded" / "process_inventory.meta.json").exists(), "with no primary on disk nothing can be named honestly, so nothing is written"


def test_decoder_cli_exit_codes(bundle_copy, capsys):
    good = bundle_copy("config-snapshot")
    assert decode_config_snapshot.main(["--bundle", str(good), "--decoded-at", "2026-09-03T00:00:00Z"]) == 0
    out = capsys.readouterr().out
    assert "config_snapshot:" in out and "powercfg:" in out and "process_inventory:" in out
    denied = bundle_copy("config-snapshot-denied")
    assert decode_config_snapshot.main(["--bundle", str(denied)]) == 2
    assert "not_collected" in capsys.readouterr().err


def test_fixture_content_is_invented_and_carries_no_machine_fact():
    """The synthetic masks and limits must not mirror a real machine: the fixture pins the display adapter to logical processor 5, not 6."""
    keys = json.loads((BUNDLES / "config-snapshot" / "raw" / "interrupt_policy" / "keys.json").read_text(encoding="utf-8"))
    gpu = next(d for d in keys if d["class"] == "Display")
    affinity = next(k for k in gpu["interrupt_keys"] if k["subkey"].endswith("Affinity Policy"))
    mask = next(v for v in affinity["values"] if v["name"] == "AssignmentSetOverride")
    assert mask["bytes_hex"] == "2000000000000000"
    assert gpu["name"].startswith("Synthetic")
    manifest = json.loads((BUNDLES / "config-snapshot" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["machine"]["hostname"] == "SYNTHETIC-PC"
