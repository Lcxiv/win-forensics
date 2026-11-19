"""The scenario runner's bundles under fixtures/scenario-runs.

They are written by collectors/windows/_run-scenario.ps1 with the real collector scripts as its
children, against the synthetic backend (collectors/windows/tests/New-FixtureBundles.ps1), so
these checks see exactly what the runner writes. tests/test_collectors_pwsh.py fails when they
differ from a fresh run.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import decode_clock
import decode_eventlog
import decode_presentmon
import verify_bundle
import wf_schema
from conftest import REPO_ROOT
from test_collectors_pwsh import find_pwsh

RUNS = REPO_ROOT / "fixtures" / "scenario-runs"
BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
CASES = ["s1", "s1-preflight-refused"]
S1_ORDER = ["state_before", "clock", "dpcisr", "frames", "diskio", "bugchecks", "whea", "app_errors", "tdr", "reliability", "drivers", "state_after"]
OBSERVED = ("observed", "observed_zero")


def load(case: str) -> dict:
    return json.loads((RUNS / case / "manifest.json").read_text(encoding="utf-8"))


def test_every_run_case_is_committed():
    assert sorted(p.name for p in RUNS.iterdir() if p.is_dir()) == sorted(CASES)


@pytest.mark.parametrize("case", CASES)
def test_container_and_schema(case):
    result = verify_bundle.verify(RUNS / case)
    assert result["ok"], result["checks"]
    manifest = load(case)
    assert wf_schema.validate_object(manifest, "manifest.schema.json") == []
    assert manifest["manifest_version"] == wf_schema.schema("manifest.schema.json")["x-schema-version"] == "1.2.0"
    assert manifest["capture"]["orchestrator"] == "wf-runner:s1"
    summary = json.loads((RUNS / case / "logs" / "summary.json").read_text(encoding="utf-8"))
    assert summary == {"collector": "scenario-runner", "status": summary["status"], "bundle": f"fixtures/scenario-runs/{case}",
                       "artifacts": sum(len(c["artifacts"]) for c in manifest["collectors"])}
    assert manifest["capture"]["incomplete"] == (summary["status"] != "ok")


@pytest.mark.parametrize("case", CASES)
def test_steps_keep_the_fixed_order_and_say_how_each_ended(case):
    manifest = load(case)
    steps = manifest["run"]["steps"]
    assert [s["step"] for s in steps] == S1_ORDER
    required = {s["step"] for s in steps if s["required"]}
    assert required == {"clock", "dpcisr", "frames"}
    for step in steps:
        assert step["deadline_seconds"] > 0
        if step["outcome"] == "absent":
            assert step["collector"] == "config-snapshot" and step["sources"] == [] and step["started_utc"] is None
        listed = {c["id"] for c in manifest["collectors"]}
        assert set(step["sources"]) <= listed, "every declared source has a collectors[] entry, run or not"
    ids = [c["id"] for c in manifest["collectors"]]
    assert len(ids) == len(set(ids))


def test_s1_merges_each_collector_and_keeps_status_apart_from_evidence():
    manifest = load("s1")
    assert manifest["preflight"]["ok"] is True
    assert {s["step"]: s["outcome"] for s in manifest["run"]["steps"] if s["outcome"] != "absent"} == {s: "completed" for s in S1_ORDER[1:-1]}
    status = {c["id"]: c for c in manifest["collectors"]}
    for source in ("clock_calibration", "wpr_trace", "presentmon_frames"):
        assert status[source]["status"] == "observed" and status[source]["required"] is True
    # The disk trace is optional in S1 and its ids carry the step prefix, apart from dpcisr-trace's wpr_trace.
    for source in ("diskio_wpr_trace", "diskio_diskio_aggregate"):
        assert status[source]["status"] == "observed" and status[source]["required"] is False
    for step in manifest["run"]["steps"]:
        if step["phase"] == "history":
            assert all(status[s]["required"] is False for s in step["sources"]), "history is optional in S1"
    for entry in manifest["collectors"]:
        assert entry["status"] in OBSERVED or entry["status_reason"]
        for artifact in entry["artifacts"]:
            assert artifact["path"].startswith(f"raw/{entry['id']}/")
    assert manifest["run"]["clock_brackets_live"] is True
    assert len(manifest["calibration"]["pairs"]) >= 2 and manifest["calibration"]["status"] == "observed"
    assert manifest["scenario"]["marks"], "the operator marks come from the clock session"
    assert manifest["machine"]["drivers"], "machine.drivers comes from the driver inventory step"
    # Each collector's own record stays beside the run, without its raw folder.
    for step in manifest["run"]["steps"]:
        if step["outcome"] != "completed":
            continue
        child = RUNS / "s1" / "logs" / "steps" / step["step"]
        assert (child / "manifest.json").is_file() and not (child / "raw").exists()
        assert json.loads((child / "logs" / "summary.json").read_text(encoding="utf-8"))["bundle"].startswith("<bundle>")


def test_a_refused_run_starts_nothing_and_lists_every_declared_source():
    manifest = load("s1-preflight-refused")
    assert manifest["preflight"]["ok"] is False
    failed = [c["name"] for c in manifest["preflight"]["checks"] if not c["ok"]]
    assert "rights:dpcisr" in failed and "rights:dpcisr" in manifest["preflight"]["required"]
    assert {s["outcome"] for s in manifest["run"]["steps"]} == {"not_started", "absent"}
    assert all(c["status"] == "not_collected" and "refused to start" in c["status_reason"] and c["artifacts"] == [] for c in manifest["collectors"])
    assert len(manifest["collectors"]) == 16
    assert list((RUNS / "s1-preflight-refused" / "raw").iterdir()) == [] if (RUNS / "s1-preflight-refused" / "raw").exists() else True
    assert not (RUNS / "s1-preflight-refused" / "logs" / "steps").exists()
    assert manifest["calibration"]["status"] == "not_collected" and manifest["calibration"]["pairs"] == []


@pytest.mark.parametrize("case", CASES)
def test_nothing_names_the_account_the_profile_or_a_machine_path(case):
    for path in (RUNS / case).rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "SYNTHETIC-PC\\\\wf-collector" not in text and "SYNTHETIC-PC\\wf-collector" not in text, path
        assert not re.search(r"(?i)c:\\\\+users\\\\+", text), path
        assert "/Users/" not in text and "/var/folders" not in text and "/tmp/" not in text, path
    for note in load(case)["notes"]:
        assert not note.startswith("Ran as ") or "its name is not recorded" in note


def test_the_decoders_read_the_merged_bundle(tmp_path):
    bundle = tmp_path / "s1"
    shutil.copytree(RUNS / "s1", bundle)
    decoded_at = "2026-09-03T00:00:00Z"
    events = decode_eventlog.decode(bundle, decoded_at=decoded_at)
    assert events["status"] == "observed" and events["rows"] > 0
    frames = decode_presentmon.decode(bundle, decoded_at=decoded_at)
    assert frames["status"] == "observed" and frames["rows"] > 0
    clock = decode_clock.decode(bundle, decoded_at=decoded_at)
    assert clock, "the clock tables decode from the merged calibration"
    for meta in (bundle / "decoded").glob("*.meta.json"):
        assert wf_schema.validate_object(json.loads(meta.read_text(encoding="utf-8")), "decoded/table_meta.schema.json") == [], meta.name
    for table in (bundle / "decoded").glob("*.jsonl"):
        name = table.name.removesuffix(".jsonl")
        assert wf_schema.validate_rows(wf_schema.read_jsonl(table), f"decoded/{name}.schema.json") == [], name
    assert verify_bundle.verify(bundle)["ok"]


def test_the_registry_declares_what_each_collector_writes():
    """Get-WfCollectorRegistry, run under pwsh, against each collector's committed fixture bundle."""
    pwsh = find_pwsh()
    if pwsh is None:
        pytest.skip("no pwsh; run scripts/fetch_pwsh.sh or set WF_PWSH")
    windows = REPO_ROOT / "collectors" / "windows"
    command = (
        f". '{windows / '_common.ps1'}'; . '{windows / '_scenarios.ps1'}'; "
        "$out = @(Get-WfCollectorRegistry | ForEach-Object { [ordered]@{ name = $_['Name']; "
        "sources = @($_['Sources'] | ForEach-Object { [string]$_['Id'] }) } }); "
        "[Console]::Out.WriteLine((ConvertTo-WfJson -Value $out))"
    )
    result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-3000:]
    registry = json.loads(result.stdout)
    names = [entry["name"] for entry in registry]
    assert len(names) == len(set(names))
    assert {"config-snapshot", "clock-calibration", "dpcisr-trace", "presentmon-frames", "diskio-trace"} <= set(names)
    for entry in registry:
        if entry["name"] == "config-snapshot":
            continue
        cases = sorted(d for d in BUNDLES.iterdir() if d.name == entry["name"] or d.name.startswith(entry["name"] + "-"))
        assert cases, entry["name"]
        bundle = json.loads((cases[0] / "manifest.json").read_text(encoding="utf-8"))
        assert entry["sources"] == [c["id"] for c in bundle["collectors"]], entry["name"]
