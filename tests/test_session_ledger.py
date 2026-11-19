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


def test_no_log_of_a_shared_creation_time_keeps_a_start():
    # File name tunnelling: a log created under the name of one just renamed inherits its creation time
    # (https://learn.microsoft.com/openspecs/windows_protocols/ms-fsa/69f1cc34-20d8-4889-8108-e871065cf9f9), and the
    # earlier log may itself have inherited it, so neither creation time is vouched for.
    created = "2026-02-27T10:00:00.0000000Z"
    out = ledger.build_sessions([
        session("b1", "2026-03-01T12:00:00", created, "2026-02-27T13:00:00.0000000Z", 100, "FortniteGame-backup-2026.02.27-10.00.00.log"),
        session("b1", "2026-03-01T12:00:00", created, "2026-02-28T20:00:00.0000000Z", 100),
    ])
    assert len(out) == 2
    for row in out:
        assert row["session_check"] == "creation_shared" and row["start_utc"] is None and row["duration_s"] is None
        assert row["start_basis"] is None and row["start_inferred"] is False and row["end_inferred"] is True


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


def test_a_log_renamed_to_a_backup_between_runs_is_still_one_session():
    created, written = "2026-02-27T10:00:00.0000000Z", "2026-02-27T13:00:00.0000000Z"
    backup = "FortniteGame-backup-2026.02.27-10.00.00.log"
    out = ledger.build_sessions([
        session("b1", "2026-02-27T14:00:00", created, written, 300),
        session("b2", "2026-03-01T12:00:00", created, written, 300, backup),
        session("b2", "2026-03-01T12:00:00", created, "2026-02-28T20:00:00.0000000Z", 100),
    ])
    first = [r for r in out if r["end_utc"] == written]
    assert len(first) == 1 and len(out) == 2, out
    assert first[0]["observations"] == 2 and first[0]["file_name"] == backup and first[0]["source_bundle_id"] == "b2"
    assert [r["session_check"] for r in out] == ["creation_shared", "creation_shared"]
    assert all(r["start_utc"] is None and r["duration_s"] is None for r in out)


def test_a_purged_backup_never_hands_its_start_to_the_next_log():
    t1 = "2026-02-27T10:00:00.0000000Z"
    w1, w2, w3 = "2026-02-27T12:00:00.0000000Z", "2026-02-28T13:00:00.0000000Z", "2026-03-02T20:00:00.0000000Z"
    run1 = [session("b1", "2026-03-01T12:00:00", t1, w1, 300, "FortniteGame-backup-2026.02.27-12.00.00.log"),
            session("b1", "2026-03-01T12:00:00", t1, w2, 200)]
    run2 = [session("b2", "2026-03-03T12:00:00", t1, w2, 200, "FortniteGame-backup-2026.02.28-13.00.00.log"),
            session("b2", "2026-03-03T12:00:00", t1, w3, 100)]
    out = ledger.build_sessions(run1 + run2)
    by_end = {r["end_utc"]: r for r in out}
    assert sorted(by_end) == [w1, w2, w3] and len(out) == 3
    assert by_end[w1]["observations"] == 1 and by_end[w2]["observations"] == 2 and by_end[w3]["observations"] == 1
    assert all(r["session_check"] == "creation_shared" and r["start_utc"] is None and r["duration_s"] is None for r in out)
    again = ledger.build_sessions(list(reversed(run2 + run1)))
    assert sorted(ledger.entry_id(r["_identity"]) for r in out) == sorted(ledger.entry_id(r["_identity"]) for r in again)


def test_a_chain_of_tunnelled_logs_whose_original_was_purged_gives_no_start_and_no_rate(tmp_path):
    # Every launch renames the log to a backup and creates a new one inside the tunnel window, so every log carries the
    # creation time of the first one, which the game purged before the collector ever ran. The oldest retained backup
    # must not become a session of weeks from that inherited time, and no period publishes a rate.
    bundle = copy_bundle(tmp_path, "session-ledger")
    inherited = "2026-02-01T10:00:00.0000000Z"
    writes = ["2026-02-25T22:00:00.0000000Z", "2026-02-26T22:00:00.0000000Z", "2026-02-27T13:00:00.0000000Z"]
    names = ["FortniteGame-backup-2026.02.25-20.00.00.log", "FortniteGame-backup-2026.02.26-20.00.00.log", "FortniteGame.log"]
    listing_path = bundle / "raw" / "fortnite_logs" / "listing.json"
    listing = [{"type": "file", "folder": None, "name": n, "name_kept": True, "name_prefix": None, "extension": ".log",
                "bytes": 1048576, "creation_time_utc": inherited, "last_write_time_utc": w, "entered": None} for n, w in zip(names, writes)]
    listing_path.write_text(json.dumps(listing), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            if artifact["path"] == "raw/fortnite_logs/listing.json":
                artifact["bytes"], artifact["sha256"] = listing_path.stat().st_size, wf_schema.sha256_of(listing_path)
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result, out = build(tmp_path, [bundle] + INPUTS[1:])
    assert result["status"] == "observed", result
    fortnite = [r for r in rows(out, ledger.LEDGER) if r["title"] == "fortnite"]
    assert sorted(r["end_utc"] for r in fortnite) == writes
    assert all(r["session_check"] == "creation_shared" and r["start_utc"] is None and r["duration_s"] is None for r in fortnite)
    summary = {r["period_id"]: r for r in rows(out, ledger.PERIODS)}
    for period in summary.values():
        assert next(p for p in period["play"] if p["title"] == "fortnite")["hours_played"] == 0.0
        assert all(i["per_hour"] is None and i["withheld_reason"] for i in period["incidents"])
    before = next(p for p in summary["tdr-level-0"]["play"] if p["title"] == "fortnite")
    assert before["coverage_status"] == "none", "coverage never starts at the inherited creation time"
    after = summary["tdr-level-3-wer-on"]
    assert after["hours_played_complete"] is False
    assert next(p for p in after["play"] if p["title"] == "fortnite")["sessions_without_duration"] == 3
    power = next(i for i in after["incidents"] if i["incident_type"] == "kernel_power_41")
    assert power["count"] == 1 and power["hours_played"] == after["hours_played"]


def test_a_log_whose_start_is_unknown_withholds_the_rate_of_every_period_it_reaches():
    t0 = "2026-02-01T10:00:00.0000000Z"
    sessions = ledger.build_sessions([
        session("b1", "2026-03-10T12:00:00", t0, "2026-02-20T22:00:00.0000000Z", 100, "FortniteGame-backup-2026.02.20-20.00.00.log"),
        session("b1", "2026-03-10T12:00:00", t0, "2026-03-05T22:00:00.0000000Z", 100),
    ])
    periods = [{"index": 0, "id": "p1", "label": "one", "start": ledger.parse_utc("2026-02-21T00:00:00Z"), "end": ledger.parse_utc("2026-03-01T00:00:00Z")},
               {"index": 1, "id": "p2", "label": "two", "start": ledger.parse_utc("2026-03-01T00:00:00Z"), "end": None}]
    as_of = ledger.parse_utc("2026-03-10T12:00:00Z")
    ledger.assign_periods(sessions, periods, as_of)
    cover = {"play": {"fortnite": [(ledger.parse_utc("2026-02-20T22:00:00Z"), as_of)]}, "sources": {}, "seen": {}}
    summary = {r["period_id"]: r for r in ledger.summarise(periods, ["fortnite"], sessions, cover, as_of, "1.0.0")}
    # The current log ran after the backup's last write, so its unknown start may lie in p1 as well as p2.
    assert summary["p1"]["sessions"] == 0 and summary["p1"]["sessions_without_duration"] == 1
    assert summary["p1"]["hours_played_complete"] is False and summary["p2"]["sessions_without_duration"] == 1


def test_a_log_written_before_it_was_created_has_no_start():
    out = ledger.build_sessions([session("b1", "2026-03-01T12:00:00", "2026-02-27T10:00:00.0000000Z", "2026-02-27T09:00:00.0000000Z", 100)])
    assert len(out) == 1 and out[0]["session_check"] == "end_before_start"
    assert out[0]["start_utc"] is None and out[0]["start_basis"] is None and out[0]["start_inferred"] is False
    assert out[0]["duration_s"] is None and out[0]["end_utc"] == "2026-02-27T09:00:00.0000000Z"


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
