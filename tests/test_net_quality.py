"""The connection quality session: its synthetic bundles, the privacy rule, and the net_quality tables.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a clean 30 second session with a short
loss beyond the router and one failed query to the router; a cable drop with missed slots and a route change; a PC
whose only default route has no gateway; and a session that failed before its stop. Nothing here comes from a real
machine.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

import decode_net_quality
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = ["connection-quality", "connection-quality-link-drop", "connection-quality-no-gateway", "connection-quality-session-failed"]
SOURCES = ("gateway_probes", "public_probes", "link_state")
AT = "2026-09-03T00:00:00Z"
# What the invented network holds that must never reach a bundle: both gateway addresses and both hardware addresses.
CANARIES = ("10.213.47.1", "10.99.0.1", "02-5E-AA-13-47-01", "02-5E-AA-13-47-02")
# Any dotted quad but the default route's destination prefix, 0.0.0.0/0, which the records name as a constant.
DOTTED = re.compile(r"\b(?!0\.0\.0\.0/0)\d{1,3}(?:\.\d{1,3}){3}\b")


def manifest(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))


def lines(bundle: Path, source_id: str) -> list[dict]:
    return wf_schema.read_jsonl(bundle / "raw" / source_id / "samples.jsonl")


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str) -> Path:
        dst = tmp_path / case
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


def rewrite(bundle: Path, source_id: str, edit) -> None:
    """Edits one samples file and puts its new checksum in the manifest, so only the decoder's own checks can object."""
    path = bundle / "raw" / source_id / "samples.jsonl"
    rows = wf_schema.read_jsonl(path)
    edit(rows)
    wf_schema.write_jsonl(path, rows)
    data = manifest(bundle)
    for collector in data["collectors"]:
        for item in collector["artifacts"]:
            if item["path"] == f"raw/{source_id}/samples.jsonl":
                item["sha256"] = wf_schema.sha256_of(path)
    (bundle / "manifest.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- the bundles and the privacy rule

@pytest.mark.parametrize("case", CASES)
def test_no_gateway_or_hardware_address_reaches_a_bundle(case):
    for path in (BUNDLES / case).rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            for canary in CANARIES:
                assert canary not in text, (path.name, canary)
            if path.name in ("samples.jsonl", "result.json", "collector.log", "summary.json"):
                # The public targets are named by label everywhere but their own source's configuration record.
                assert not DOTTED.search(text), path
    # The manifest's machine section carries version numbers of the same shape; its collector entries carry no address.
    assert not DOTTED.search(json.dumps(manifest(BUNDLES / case)["collectors"]))


@pytest.mark.parametrize("case", CASES)
def test_bundles_verify_and_every_slot_is_accounted_for(case):
    bundle = BUNDLES / case
    assert verify_bundle.verify(bundle)["ok"]
    data = manifest(bundle)
    for collector in data["collectors"]:
        if collector["status"] != "observed":
            assert not (bundle / "raw" / collector["id"] / "samples.jsonl").exists()
            continue
        result = json.loads((bundle / "raw" / collector["id"] / "result.json").read_text(encoding="utf-8"))
        rows = lines(bundle, collector["id"])
        if collector["id"] == "link_state":
            seqs = sorted(r["seq"] for r in rows)
            assert seqs == list(range(0, result["slots"] + 1, 10)), "a reading or a missed line every 10 slots and one at the stop"
        else:
            for target in collector["requested"]["options"]["targets"]:
                taken = {r["seq"] for r in rows if r["kind"] == "ping" and r["target"] == target}
                missed = {r["seq"] for r in rows if r["kind"] == "missed"}
                assert taken | missed == set(range(result["slots"])) and not taken & missed, target


def test_the_public_configuration_names_its_constants_and_the_gateway_by_label():
    bundle = BUNDLES / "connection-quality"
    public = json.loads((bundle / "raw/public_probes/command.json").read_text(encoding="utf-8"))
    assert [(t["label"], t["address"]) for t in public["targets"]] == [("cloudflare", "1.1.1.1"), ("google", "8.8.8.8")]
    gateway = json.loads((bundle / "raw/gateway_probes/command.json").read_text(encoding="utf-8"))
    assert gateway["targets"][0]["label"] == "gateway" and not DOTTED.search(json.dumps(gateway))


# ---------------------------------------------------------------- the tables

def test_a_clean_session_decodes_into_probe_rows_and_bursts(bundle_copy):
    bundle = bundle_copy("connection-quality")
    results = decode_net_quality.decode(bundle, AT)
    assert results["net_quality"]["status"] == "observed" and results["net_quality_bursts"]["status"] == "observed"
    rows = wf_schema.read_jsonl(bundle / "decoded/net_quality.jsonl")
    assert not wf_schema.validate_rows(rows, "decoded/net_quality.schema.json")
    by = lambda probe, target: [r for r in rows if r["probe"] == probe and r["target"] == target]  # noqa: E731
    assert len(by("ping", "gateway")) == len(by("ping", "cloudflare")) == len(by("ping", "google")) == 30
    assert [r["seq"] for r in by("ping", "cloudflare") if r["ok"] is False] == [12, 13, 14]
    assert all(r["rtt_ms"] is None for r in rows if r["probe"] == "ping" and r["ok"] is False)
    assert [r["ok"] for r in by("dns", "gateway")] == [True, True, False]
    failed = by("dns", "gateway")[2]
    assert failed["error_id"] == "ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName" and failed["error_code"] == 1460
    link = [r for r in rows if r["probe"] == "link"]
    assert [r["seq"] for r in link] == [0, 10, 20, 30]
    assert link[0]["media_connect_state_text"] == "Connected" and link[0]["physical_medium_text"] == "802.3"
    for row in rows:
        prov = row["provenance"]
        assert prov["decoded_table"] == "net_quality" and prov["row_id_or_offset"].startswith("line:")
        raw = wf_schema.read_jsonl(bundle / prov["source_file"])[int(prov["row_id_or_offset"][5:]) - 1]
        assert raw["qpc_before"] == row["qpc_before"] and raw["seq"] == row["seq"]
        assert row["qpc_mid"] == (row["qpc_before"] + row["qpc_after"]) // 2 and row["half_width_100ns"] >= 1
    bursts = wf_schema.read_jsonl(bundle / "decoded/net_quality_bursts.jsonl")
    assert not wf_schema.validate_rows(bursts, "decoded/net_quality_bursts.schema.json")
    summary = sorted((b["kind"], b["target"], b["first_seq"], b["last_seq"], b["count"]) for b in bursts)
    assert summary == [("dns_failure_burst", "gateway", 20, 20, 1), ("loss_burst", "cloudflare", 12, 14, 3), ("loss_burst", "google", 13, 13, 1)]
    loss = next(b for b in bursts if b["target"] == "cloudflare")
    assert loss["provenance"]["row_id_or_offset"].count("line:") == 3
    meta = json.loads((bundle / "decoded/net_quality.meta.json").read_text(encoding="utf-8"))
    assert not wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    assert meta["time_domain"] == "etw_qpc" and meta["native_time_range"]["domain"] == "etw_qpc"
    checks = {c["name"]: c for c in meta["checks"]}
    assert checks["summary:public_probes:ping:cloudflare"]["detail"].startswith("30 echoes: 27 answered, 3 not answered (10.0 %")
    assert checks["summary:gateway_probes:ping:gateway"]["ok"] is True


def test_a_cable_drop_shows_as_link_down_losses_gaps_and_a_route_change(bundle_copy):
    bundle = bundle_copy("connection-quality-link-drop")
    decode_net_quality.decode(bundle, AT)
    bursts = wf_schema.read_jsonl(bundle / "decoded/net_quality_bursts.jsonl")
    kinds = {(b["source_id"], b["kind"]) for b in bursts}
    assert ("link_state", "link_down") in kinds and ("link_state", "route_changed") in kinds
    assert ("gateway_probes", "loss_burst") in kinds and ("public_probes", "sampling_gap") in kinds
    gaps = [b for b in bursts if b["kind"] == "sampling_gap" and b["source_id"] == "public_probes"]
    assert sum(b["count"] for b in gaps) == 5 and all(b["start_utc"] is None for b in gaps)
    rows = wf_schema.read_jsonl(bundle / "decoded/net_quality.jsonl")
    down = next(r for r in rows if r["probe"] == "link" and r["seq"] == 10)
    assert down["ok"] is False and down["operational_status_text"] == "Lower layer down" and down["receive_link_speed_bps"] == 0
    # A missed slot is never a row of the probe table: it is not a loss.
    assert not any(r["status"] == "missed" for r in rows)


def test_a_bundle_without_a_gateway_decodes_the_public_probes_alone(bundle_copy):
    bundle = bundle_copy("connection-quality-no-gateway")
    results = decode_net_quality.decode(bundle, AT)
    assert results["net_quality"]["status"] == "observed"
    assert results["net_quality_bursts"]["status"] == "observed_zero"
    rows = wf_schema.read_jsonl(bundle / "decoded/net_quality.jsonl")
    assert {r["source_id"] for r in rows} == {"public_probes"}


def test_a_failed_session_has_nothing_to_decode(bundle_copy):
    bundle = bundle_copy("connection-quality-session-failed")
    results = decode_net_quality.decode(bundle, AT)
    assert {r["status"] for r in results.values()} == {"not_collected"}
    assert not (bundle / "decoded").exists()


@pytest.mark.parametrize("mutation, message", [
    ("address_in_status", "shaped like a network or hardware address"),
    ("extra_key", "differ from the ping line"),
    ("unknown_target", "is not one source public_probes probes"),
    ("rtt_on_timeout", "rtt_ms is kept for Success only"),
    ("stamps_out_of_order", "not in the order slot, before, after, done"),
    ("seq_backwards", "the collector writes slots in order"),
    ("dropped_line", "the result record says"),
])
def test_the_decoder_refuses_samples_it_cannot_vouch_for(bundle_copy, mutation, message):
    bundle = bundle_copy("connection-quality")

    def edit(rows):
        if mutation == "address_in_status":
            rows[0]["error_type"] = "Reply from 192.0.2.7"
            rows[0]["status"] = "error"
            rows[0]["rtt_ms"] = None
        elif mutation == "extra_key":
            rows[0]["address"] = "x"
        elif mutation == "unknown_target":
            rows[0]["target"] = "gateway"
        elif mutation == "rtt_on_timeout":
            rows[0]["status"] = "TimedOut"
        elif mutation == "stamps_out_of_order":
            rows[0]["qpc_done"] = rows[0]["qpc_before"] - 1
        elif mutation == "seq_backwards":
            rows[3]["seq"] = 0
            rows[1]["seq"] = 5
        elif mutation == "dropped_line":
            del rows[-1]

    rewrite(bundle, "public_probes", edit)
    results = decode_net_quality.decode(bundle, AT)
    assert results["net_quality"]["status"] == "decode_failed"
    assert message in results["net_quality"]["reason"], results["net_quality"]["reason"]
    meta = json.loads((bundle / "decoded/net_quality.meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "decode_failed" and meta["row_count"] == 0
    assert (bundle / "decoded/net_quality.jsonl").read_text(encoding="utf-8") == ""


def test_the_decoder_refuses_a_samples_file_that_differs_from_the_manifest(bundle_copy):
    bundle = bundle_copy("connection-quality")
    path = bundle / "raw/gateway_probes/samples.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace('"rtt_ms":1,', '"rtt_ms":2,', 1), encoding="utf-8")
    results = decode_net_quality.decode(bundle, AT)
    assert results["net_quality"]["status"] == "decode_failed" and "SHA-256 differs" in results["net_quality"]["reason"]


def test_the_command_line_reports_each_table(bundle_copy, capsys):
    assert decode_net_quality.main(["--bundle", str(bundle_copy("connection-quality")), "--decoded-at", AT]) == 0
    out = capsys.readouterr().out
    assert "net_quality: 100 rows" in out and "net_quality_bursts: 3 rows" in out
    assert decode_net_quality.main(["--bundle", str(bundle_copy("connection-quality-session-failed"))]) == 2


def test_decoding_twice_gives_the_same_tables(bundle_copy):
    bundle = bundle_copy("connection-quality-link-drop")
    decode_net_quality.decode(bundle, AT)
    first = {p.name: p.read_bytes() for p in (bundle / "decoded").iterdir()}
    decode_net_quality.decode(bundle, AT)
    assert first == {p.name: p.read_bytes() for p in (bundle / "decoded").iterdir()}
