"""The session ledger: the session-ledger collector's bundle joined with the history bundles by scripts/build_session_ledger.py.

The committed example (fixtures/session-ledger/example) is rebuilt and compared, every row is checked against its schema and
its provenance, and the refusals, the dedupe, the rate rules and the privacy rules are exercised on copies of the synthetic
bundles. See docs/session-ledger.md.
"""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import build_session_ledger as ledger  # noqa: E402
import wf_schema  # noqa: E402

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
EXAMPLE = REPO_ROOT / "fixtures" / "session-ledger"
INPUTS = ["session-ledger", "bugcheck-history-ledger", "tdr-events-ledger", "application-errors", "whea-errors-quiet"]
DECODED_AT = "2026-09-03T00:00:00Z"


def build(tmp_path: Path, names=INPUTS, periods: Path | None = None, out_name: str = "out") -> tuple[dict, Path]:
    out = tmp_path / out_name
    result = ledger.build([BUNDLES / n if isinstance(n, str) else n for n in names], periods or EXAMPLE / "periods.json", out, DECODED_AT)
    return result, out


def rows(out: Path, table: str) -> list[dict]:
    return wf_schema.read_jsonl(out / "decoded" / f"{table}.jsonl")


def copy_bundle(tmp_path: Path, name: str) -> Path:
    target = tmp_path / "in" / name
    shutil.copytree(BUNDLES / name, target)
    return target


def write_periods(tmp_path: Path, **changes) -> Path:
    document = json.loads((EXAMPLE / "periods.json").read_text(encoding="utf-8"))
    document.update(changes)
    path = tmp_path / "periods.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_committed_example_is_what_the_builder_writes(tmp_path):
    result, out = build(tmp_path)
    assert result["status"] == "observed"
    committed = sorted(p.relative_to(EXAMPLE / "example").as_posix() for p in (EXAMPLE / "example").rglob("*") if p.is_file())
    fresh = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert committed == fresh
    for relative in fresh:
        assert (out / relative).read_bytes() == (EXAMPLE / "example" / relative).read_bytes(), \
            f"{relative} is stale: rebuild fixtures/session-ledger/example with the command in README.md"


def test_every_row_validates_and_points_at_a_hashed_copy_in_the_output():
    out = EXAMPLE / "example"
    for table in (ledger.LEDGER, ledger.PERIODS):
        table_rows = rows(out, table)
        assert table_rows and wf_schema.validate_rows(table_rows, f"decoded/{table}.schema.json") == []
        meta = json.loads((out / "decoded" / f"{table}.meta.json").read_text(encoding="utf-8"))
        assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
        assert meta["row_count"] == len(table_rows) and meta["status"] == "observed"
        hashes = {f["path"]: f["sha256"] for f in meta["source_files"]}
        for path, digest in hashes.items():
            assert wf_schema.sha256_of(out / path) == digest, path
        for row in table_rows:
            assert row["provenance"]["source_file"] in hashes, row["provenance"]
    # Each copy is byte for byte the artifact its bundle's manifest lists.
    inputs = json.loads((out / "inputs.json").read_text(encoding="utf-8"))
    for bundle in inputs["bundles"]:
        manifest = json.loads((out / bundle["manifest"]).read_text(encoding="utf-8"))
        assert wf_schema.sha256_of(out / bundle["manifest"]) == bundle["manifest_sha256"]
        listed = {a["path"]: a["sha256"] for c in manifest["collectors"] for a in c["artifacts"]}
        base = out / "raw" / "inputs" / bundle["bundle_id"]
        for copy in base.rglob("*"):
            if copy.is_file() and copy.name != "manifest.json":
                relative = copy.relative_to(base).as_posix()
                assert listed[relative] == wf_schema.sha256_of(copy), relative


def test_a_record_read_by_two_collectors_is_one_row_with_its_named_bugcheck_code():
    ledger_rows = rows(EXAMPLE / "example", ledger.LEDGER)
    power = [r for r in ledger_rows if r["incident_type"] == "kernel_power_41"]
    assert [r["event_record_id"] for r in power] == [40301, 41012]
    assert all(r["observations"] == 2 and r["bugcheck_code"] == 0 and r["bugcheck_code_hex"] == "0x00000000" for r in power)
    assert len({r["entry_id"] for r in ledger_rows}) == len(ledger_rows)


def test_an_unnamed_bugcheck_code_is_never_guessed_from_its_position(tmp_path):
    # The older bugcheck-history fixture writes its Kernel-Power 41 data without names: the first item holds 159, and
    # the ledger still leaves the code null rather than trusting a position.
    result, out = build(tmp_path, ["session-ledger", "bugcheck-history"])
    assert result["status"] == "observed"
    power = [r for r in rows(out, ledger.LEDGER) if r["incident_type"] == "kernel_power_41"]
    assert power and all(r["bugcheck_code"] is None for r in power)


def test_sessions_are_inferred_from_file_times_and_say_so():
    sessions = [r for r in rows(EXAMPLE / "example", ledger.LEDGER) if r["entry_kind"] == "session"]
    assert {r["title"] for r in sessions} == {"overwatch", "fortnite", "battlenet", "epic_games_launcher"}
    for row in sessions:
        assert row["start_basis"] == "file_creation_time" and row["end_basis"] == "file_last_write_time"
        assert row["start_inferred"] is True and row["end_inferred"] is True and row["session_check"] == "ok"
        start = datetime.fromisoformat(row["start_utc"][:19]).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(row["end_utc"][:19]).replace(tzinfo=timezone.utc)
        assert row["duration_s"] == (end - start).total_seconds()
    # The Overwatch log whose name carried the profile name is a session with no name in the ledger.
    assert sum(1 for r in sessions if r["title"] == "overwatch" and r["file_name"] is None) == 1


def test_rates_stand_beside_their_counts_and_only_when_every_input_is_complete():
    summary = {r["period_id"]: r for r in rows(EXAMPLE / "example", ledger.PERIODS)}
    before, after = summary["tdr-level-0"], summary["tdr-level-3-wer-on"]
    # Before: play coverage starts with the oldest retained log, inside the period, so no rate is given.
    assert before["hours_played_complete"] is False and "overwatch play coverage is partial" in before["hours_played_gaps"]
    assert all(i["per_hour"] is None and i["withheld_reason"] for i in before["incidents"])
    # After: both tracked games are covered and every session has a duration.
    assert after["hours_played_complete"] is True and after["hours_played"] == 9.0 and after["sessions"] == 3
    power = next(i for i in after["incidents"] if i["incident_type"] == "kernel_power_41")
    assert power == {"incident_type": "kernel_power_41", "count": 1, "count_basis": "complete", "coverage_status": "full",
                     "covered_hours": after["period_hours"], "hours_played": 9.0, "per_hour": 0.1111, "withheld_reason": None}
    for period in summary.values():
        for incident in period["incidents"]:
            assert incident["hours_played"] == period["hours_played"], "the denominator stands beside every rate"
            if incident["per_hour"] is not None:
                assert incident["count_basis"] == "complete" and incident["coverage_status"] == "full" and incident["count"] is not None
            if incident["count_basis"] in ("found_only", "snapshot"):
                assert incident["per_hour"] is None and incident["withheld_reason"]
    display = next(i for i in after["incidents"] if i["incident_type"] == "display_4101")
    assert display["count"] == 1 and display["count_basis"] == "found_only" and display["per_hour"] is None


def test_a_crash_of_another_program_is_counted_without_its_name():
    crashes = [r for r in rows(EXAMPLE / "example", ledger.LEDGER) if r["incident_type"] in ("app_crash_1000", "app_hang_1002")]
    assert len(crashes) == 2 and all(r["image_name"] is None and r["title"] is None for r in crashes)
    text = (EXAMPLE / "example" / "decoded" / "session_ledger.jsonl").read_text(encoding="utf-8")
    assert "example.exe" not in text


def test_nothing_measured_is_never_a_zero(tmp_path):
    # The standard account run: no game log could be listed, the dump folder refused, the archive timed out. Its incident
    # sources from the history collectors are absent too, so nothing is counted and nothing is rated.
    result, out = build(tmp_path, ["session-ledger-standard-account"])
    # The minidump folder was observed (absent: nothing in it now), so the empty ledger is a measured zero.
    assert result["status"] == "observed_zero" and rows(out, ledger.LEDGER) == []
    assert [r for r in rows(out, ledger.LEDGER) if r["entry_kind"] == "session"] == []
    for period in rows(out, ledger.PERIODS):
        assert period["hours_played_complete"] is False
        assert all(p["coverage_status"] == "none" for p in period["play"])
        by_type = {i["incident_type"]: i for i in period["incidents"]}
        assert by_type["kernel_power_41"]["count"] is None and by_type["kernel_power_41"]["count_basis"] == "not_measured"
        assert by_type["live_kernel_report"]["count"] is None, "a refused listing is not a folder without dumps"
        assert by_type["minidump"]["count"] == 0 and by_type["minidump"]["count_basis"] == "snapshot"
        assert all(i["per_hour"] is None for i in period["incidents"])


def test_privacy_no_profile_name_account_or_path_reaches_a_bundle_or_the_ledger():
    for root in (BUNDLES / "session-ledger", BUNDLES / "session-ledger-standard-account", EXAMPLE / "example"):
        for path in root.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                assert "synthetic-player" not in text, path
                assert "C:\\\\Users" not in text and "C:\\Users" not in text, path
    manifest = json.loads((BUNDLES / "session-ledger" / "manifest.json").read_text(encoding="utf-8"))
    assert any(note.startswith("Ran as the collector account (its name is not recorded)") for note in manifest["notes"])


@pytest.mark.parametrize("case", ["tampered", "two_machines", "same_twice", "not_joined", "overlap", "open_then_more", "other_machine",
                                  "no_offset", "out_not_empty"])
def test_inputs_it_cannot_vouch_for_are_refused_and_nothing_is_written(tmp_path, case):
    names: list = list(INPUTS)
    periods = None
    out_name = "out"
    if case == "tampered":
        bundle = copy_bundle(tmp_path, "session-ledger")
        listing = bundle / "raw" / "overwatch_logs" / "listing.json"
        listing.write_text(listing.read_text(encoding="utf-8").replace("48213", "48214"), encoding="utf-8")
        names[0] = bundle
    elif case == "two_machines":
        bundle = copy_bundle(tmp_path, "whea-errors-quiet")
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        manifest["machine"]["machine_id"] = "0" * 32
        (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        names[-1] = bundle
    elif case == "same_twice":
        names.append("session-ledger")
    elif case == "not_joined":
        names.append("rf-survey")
    elif case == "overlap":
        document = json.loads((EXAMPLE / "periods.json").read_text(encoding="utf-8"))
        document["periods"][1]["start"] = "2026-02-23T00:00:00Z"
        periods = write_periods(tmp_path, periods=document["periods"])
    elif case == "open_then_more":
        document = json.loads((EXAMPLE / "periods.json").read_text(encoding="utf-8"))
        document["periods"][0]["end"] = None
        periods = write_periods(tmp_path, periods=document["periods"])
    elif case == "other_machine":
        periods = write_periods(tmp_path, machine_id="f" * 32)
    elif case == "no_offset":
        document = json.loads((EXAMPLE / "periods.json").read_text(encoding="utf-8"))
        document["periods"][0]["start"] = "2026-02-09T16:00:00"
        periods = write_periods(tmp_path, periods=document["periods"])
    elif case == "out_not_empty":
        (tmp_path / "busy").mkdir()
        (tmp_path / "busy" / "keep.txt").write_text("x", encoding="utf-8")
        out_name = "busy"
    result, out = build(tmp_path, names, periods, out_name)
    assert result["status"] == "decode_failed", result
    if case == "out_not_empty":
        assert [p.name for p in out.iterdir()] == ["keep.txt"]
    else:
        assert not out.exists()


def test_without_a_session_ledger_bundle_there_is_nothing_to_place(tmp_path):
    result, out = build(tmp_path, ["bugcheck-history-ledger", "whea-errors-quiet"])
    assert result["status"] == "not_collected" and not out.exists()


def session(bundle_id: str, start: str, created: str, written: str, size: int, name: str | None = "FortniteGame.log") -> dict:
    stamp = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
    return {"kind": "session", "bundle": {"bundle_id": bundle_id, "capture_start": stamp, "collector": "session-ledger"},
            "source_id": "fortnite_logs", "path": "raw/fortnite_logs/listing.json", "offset": "index:0", "title": "fortnite",
            "role": "game", "created": ledger.parse_utc(created), "written": ledger.parse_utc(written), "bytes": size, "name": name,
            "created_text": created, "written_text": written}


def test_a_tunnelled_creation_time_leaves_the_later_log_without_a_start():
    # File name tunnelling: a log created under the name of one just renamed inherits its creation time
    # (https://learn.microsoft.com/openspecs/windows_protocols/ms-fsa/69f1cc34-20d8-4889-8108-e871065cf9f9).
    created = "2026-02-27T10:00:00.0000000Z"
    out = ledger.build_sessions([
        session("b1", "2026-03-01T12:00:00", created, "2026-02-27T13:00:00.0000000Z", 100, "FortniteGame-backup-2026.02.27-10.00.00.log"),
        session("b1", "2026-03-01T12:00:00", created, "2026-02-28T20:00:00.0000000Z", 100),
    ])
    by_name = {r["file_name"]: r for r in out}
    assert by_name["FortniteGame-backup-2026.02.27-10.00.00.log"]["session_check"] == "ok"
    later = by_name["FortniteGame.log"]
    assert later["session_check"] == "creation_shared" and later["start_utc"] is None and later["duration_s"] is None
    assert later["start_inferred"] is False and later["end_inferred"] is True


def test_a_log_seen_twice_is_one_session_and_a_replaced_one_loses_its_start():
    created = "2026-02-27T10:00:00.0000000Z"
    grown = ledger.build_sessions([
        session("b1", "2026-02-27T12:00:00", created, "2026-02-27T11:00:00.0000000Z", 100),
        session("b2", "2026-03-01T12:00:00", created, "2026-02-27T13:00:00.0000000Z", 300),
    ])
    assert len(grown) == 1 and grown[0]["observations"] == 2 and grown[0]["duration_s"] == 3 * 3600 and grown[0]["source_bundle_id"] == "b2"
    replaced = ledger.build_sessions([
        session("b1", "2026-02-27T12:00:00", created, "2026-02-27T13:00:00.0000000Z", 300),
        session("b2", "2026-03-01T12:00:00", created, "2026-02-27T11:00:00.0000000Z", 100),
    ])
    assert len(replaced) == 1 and replaced[0]["session_check"] == "replaced_in_place" and replaced[0]["start_utc"] is None
    assert replaced[0]["duration_s"] is None


def test_the_cli_exit_codes(tmp_path, capsys):
    args = []
    for name in INPUTS:
        args += ["--bundle", str(BUNDLES / name)]
    assert ledger.main(args + ["--periods", str(EXAMPLE / "periods.json"), "--out", str(tmp_path / "a"), "--decoded-at", DECODED_AT]) == 0
    assert ledger.main(args + ["--periods", str(EXAMPLE / "periods.json"), "--out", str(tmp_path / "a")]) == 2
    assert "decode_failed" in capsys.readouterr().err


def test_the_periods_schema_accepts_the_example_and_requires_an_offset():
    document = json.loads((EXAMPLE / "periods.json").read_text(encoding="utf-8"))
    assert wf_schema.validate_object(document, "input/config_periods.schema.json") == []
    document["periods"][0]["end"] = "2026-02-23T16:00:00"
    assert wf_schema.validate_object(document, "input/config_periods.schema.json")
