"""The clock calibration decoder and fit over the synthetic clock-calibration bundles, plus the fit on invented pair lists.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a 60 s session with a
system clock 50 ppm fast and two operator marks; a 30 s session with a 250 ms forward step of the
system clock; a 30 s session with one missed interval slot on a coarse 15.625 ms timer; a session
whose counter read fails at the stop pair. Every number is invented by the synthetic backend.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import decode_clock
import verify_bundle
import wf_schema
from conftest import REPO_ROOT

BUNDLES = REPO_ROOT / "fixtures" / "collector-bundles"
OK = "clock-calibration"
STEP = "clock-calibration-clock-step"
MISSED = "clock-calibration-missed-slot"
FAILED = "clock-calibration-read-failed"
CASES = [OK, STEP, MISSED, FAILED]
TABLES = ["clock_pairs", "clock_segments", "operator_marks"]
FREQ = 10_000_000
AT = "2026-09-03T00:00:00Z"


@pytest.fixture()
def bundle_copy(tmp_path):
    def make(case: str, tag: str = "") -> Path:
        dst = tmp_path / (case + tag)
        shutil.copytree(BUNDLES / case, dst)
        return dst
    return make


def manifest_of(bundle: Path) -> dict:
    return json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))


def rows(bundle: Path, table: str) -> list[dict]:
    return wf_schema.read_jsonl(bundle / "decoded" / f"{table}.jsonl")


def meta(bundle: Path, table: str) -> dict:
    return json.loads((bundle / "decoded" / f"{table}.meta.json").read_text(encoding="utf-8"))


def join_validator() -> Draft202012Validator:
    return Draft202012Validator({"$ref": wf_schema.schema_id("common.schema.json") + "#/$defs/join"}, registry=wf_schema.registry())


def pair(seq: int, phase: str, seconds: float, ft_offset_100ns: int = 0, bracket: int = 100, freq: int = FREQ, base_qpc: int = 5_000_000_000,
         base_ft: int = 134_168_400_000_000_000, drift_ppm: float = 0.0) -> dict:
    """An invented pair at `seconds` into the session; the system clock is offset and drifts as asked."""
    qpc_before = base_qpc + int(seconds * freq)
    ft = base_ft + int(seconds * 10_000_000 * (1 + drift_ppm / 1_000_000)) + ft_offset_100ns
    return {"seq": seq, "phase": phase, "qpc_before": qpc_before, "qpc_after": qpc_before + bracket, "filetime_utc_100ns": ft}


def session(duration: int, interval: int = 5, **kwargs) -> list[dict]:
    pairs = [pair(0, "start", 0, **kwargs)]
    seq = 1
    for t in range(interval, duration, interval):
        pairs.append(pair(seq, "interval", t, **kwargs))
        seq += 1
    pairs.append(pair(seq, "stop", duration, **kwargs))
    return pairs


# ---------------------------------------------------------------- the fit on invented pairs

def test_fit_refuses_fewer_than_two_pairs_and_an_unknown_frequency():
    assert not decode_clock.fit_pairs([], FREQ).aligned
    one = decode_clock.fit_pairs(session(10)[:1], FREQ)
    assert not one.aligned and "at least two" in one.reason
    assert not one.align(134_168_400_000_000_000).aligned
    assert "calibration missing" in one.align(0).reason
    assert not decode_clock.fit_pairs(session(10), None).aligned


def test_fit_is_identity_on_a_perfect_clock_and_anchors_the_epoch_on_the_first_pair():
    pairs = session(30)
    model = decode_clock.fit_pairs(pairs, FREQ, increment_100ns=10_000)
    assert model.aligned and len(model.segments) == 6 and model.clock_step_segments == 0
    assert model.epoch_qpc == pairs[0]["qpc_before"] + 50 and model.epoch_source == "first_calibration_pair"
    first = model.align(pairs[0]["filetime_utc_100ns"])
    assert first.aligned and first.t_master_100ns == 0
    mid = model.align(pairs[0]["filetime_utc_100ns"] + 123_456_789, source_resolution_100ns=10_000)
    assert mid.t_master_100ns == 123_456_789
    # half width: bracket 100 ticks / 2 + 1 tick = 51 ticks = 51 x 100 ns at 10 MHz; plus increment, plus the source's own resolution.
    assert mid.error_bound_100ns == 51 + 10_000 + 10_000
    # A counter value from an etw_qpc source: rate 1, one tick of bound.
    assert model.align_qpc(model.epoch_qpc + 7_000_000) == decode_clock.Alignment(7_000_000, 1, None)


def test_fit_never_extrapolates_and_a_missing_stop_pair_leaves_the_tail_unaligned():
    pairs = session(30)
    model = decode_clock.fit_pairs(pairs, FREQ, 10_000)
    before = model.align(pairs[0]["filetime_utc_100ns"] - 1)
    after = model.align(pairs[-1]["filetime_utc_100ns"] + 1)
    assert not before.aligned and not after.aligned and "not extrapolated" in after.reason
    without_stop = decode_clock.fit_pairs(pairs[:-1], FREQ, 10_000)
    assert without_stop.aligned and without_stop.pairs[-1].phase == "interval"
    inside = without_stop.align(pairs[-2]["filetime_utc_100ns"])
    tail = without_stop.align(pairs[-2]["filetime_utc_100ns"] + 1_000_000)
    assert inside.aligned and not tail.aligned, "the last five seconds have no pair after them"
    join = decode_clock.check_join("tail", "pdh", "wpr", 100_000, tail, without_stop.align_qpc(without_stop.epoch_qpc))
    assert join["aligned"] is False and join["achieved_bound_100ns"] is None and "left unaligned" in join["reason"]


def test_a_steady_drift_within_the_rule_is_fitted_and_a_large_one_is_a_clock_step_on_every_segment():
    slow = decode_clock.fit_pairs(session(60, drift_ppm=-120), FREQ, 10_000)
    assert slow.aligned and slow.clock_step_segments == 0
    assert all(abs(s.deviation_ppm - 120) < 1 for s in slow.segments)
    # The last pair's own counter value is 60 s after the epoch whatever the system clock did.
    end = slow.align(slow.last_filetime)
    assert abs(end.t_master_100ns - 600_000_000) <= 1
    fast = decode_clock.fit_pairs(session(60, drift_ppm=2500), FREQ, 10_000)
    assert fast.aligned and fast.clock_step_segments == len(fast.segments)
    for segment in fast.segments:
        assert segment.clock_step and segment.error_bound_100ns == segment.span_100ns
    aligned = fast.align(fast.first_filetime + 10_000_000)
    assert aligned.aligned and aligned.clock_step and aligned.error_bound_100ns >= 50_000_000


def test_a_clock_step_in_one_segment_widens_only_that_segment():
    pairs = session(30)
    stepped = [dict(p, filetime_utc_100ns=p["filetime_utc_100ns"] + (2_500_000 if p["seq"] >= 3 else 0)) for p in pairs]
    model = decode_clock.fit_pairs(stepped, FREQ, 10_000)
    assert [s.clock_step for s in model.segments] == [False, False, True, False, False, False]
    flagged = model.segments[2]
    assert flagged.error_bound_100ns == flagged.span_100ns == 52_500_000
    assert model.segments[0].error_bound_100ns == 51 + 10_000
    inside = model.align(stepped[2]["filetime_utc_100ns"] + 10_000_000)
    outside = model.align(stepped[4]["filetime_utc_100ns"] + 10_000_000)
    assert inside.clock_step and not outside.clock_step
    refused = decode_clock.check_join("dpc_to_log", "eventlog", "wpr", 50_000, inside, model.align_qpc(model.epoch_qpc))
    accepted = decode_clock.check_join("dpc_to_log", "eventlog", "wpr", 50_000, outside, model.align_qpc(model.epoch_qpc))
    assert refused["aligned"] is False and refused["achieved_bound_100ns"] == 52_500_001 and "not widened" in refused["reason"]
    assert accepted == {"id": "dpc_to_log", "left": "eventlog", "right": "wpr", "tolerance_100ns": 50_000, "achieved_bound_100ns": 10_052, "aligned": True, "reason": None}
    validator = join_validator()
    assert list(validator.iter_errors(refused)) == [] and list(validator.iter_errors(accepted)) == []


def test_a_backward_step_cannot_be_fitted():
    pairs = session(20)
    pairs[2]["filetime_utc_100ns"] -= 60_000_000
    model = decode_clock.fit_pairs(pairs, FREQ, 10_000)
    assert not model.aligned and "backward step" in model.reason


def test_join_bounds_add_and_are_never_shrunk():
    left = decode_clock.Alignment(100, 30_000, 0)
    right = decode_clock.Alignment(100, 20_000, None)
    assert decode_clock.check_join("j", "a", "b", 50_000, left, right)["aligned"] is True
    assert decode_clock.check_join("j", "a", "b", 49_999, left, right)["aligned"] is False
    assert decode_clock.check_join("j", "a", "b", 49_999, left, right)["achieved_bound_100ns"] == 50_000
    with pytest.raises(ValueError):
        decode_clock.check_join("j", "a", "b", -1, left, right)


def test_an_unmeasured_increment_falls_back_to_the_documented_coarse_timer():
    model = decode_clock.fit_pairs(session(20), FREQ, None)
    assert model.increment_measured is False and model.increment_100ns == decode_clock.FALLBACK_INCREMENT_100NS == 156_250
    assert model.segments[0].error_bound_100ns == 51 + 156_250


def test_an_etl_header_epoch_overrides_the_first_pair():
    pairs = session(20)
    model = decode_clock.fit_pairs(pairs, FREQ, 10_000, epoch_qpc=pairs[0]["qpc_before"] - 10_000_000)
    assert model.epoch_source == "etl_header"
    assert model.align(pairs[0]["filetime_utc_100ns"]).t_master_100ns == 10_000_050


def test_file_time_conversions_round_trip_at_100_ns():
    assert decode_clock.filetime_to_iso(134_168_400_000_040_000) == "2026-03-01T12:00:00.0040000Z"
    assert decode_clock.iso_to_filetime("2026-03-01T12:00:00.0040000Z") == 134_168_400_000_040_000
    assert decode_clock.iso_to_filetime("2026-03-01T12:00:00Z") == 134_168_400_000_000_000
    with pytest.raises(ValueError):
        decode_clock.iso_to_filetime("01/03/2026 12:00")


# ---------------------------------------------------------------- the committed bundles

@pytest.mark.parametrize("case", CASES)
def test_decoded_tables_validate_and_the_bundle_still_verifies(case, bundle_copy):
    bundle = bundle_copy(case)
    result = decode_clock.decode(bundle, decoded_at=AT)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    for table in TABLES:
        if result[table]["status"] in ("observed", "observed_zero"):
            table_rows = rows(bundle, table)
            assert wf_schema.validate_rows(table_rows, f"decoded/{table}.schema.json") == []
            sidecar = meta(bundle, table)
            assert wf_schema.validate_object(sidecar, "decoded/table_meta.schema.json") == []
            assert sidecar["row_count"] == len(table_rows) == result[table]["rows"]
            listed = {a["path"]: a["sha256"] for c in manifest["collectors"] for a in c["artifacts"]}
            for source in sidecar["source_files"]:
                assert listed[source["path"]] == source["sha256"]
            for row in table_rows:
                assert row["provenance"]["source_file"] in listed
        else:
            assert not (bundle / "decoded" / f"{table}.jsonl").exists(), f"{table}: an absent input is never decoded into an empty table"
    if clock["status"] == "observed":
        assert result["clock_pairs"]["status"] == result["clock_segments"]["status"] == "observed"
        assert result["clock_pairs"]["rows"] == len(manifest["calibration"]["pairs"]) == result["clock_segments"]["rows"] + 1
        assert meta(bundle, "clock_pairs")["time_domain"] == "system_time"
    else:
        assert result["clock_pairs"]["status"] == "not_collected" and "capture_failed" in result["clock_pairs"]["reason"]
    assert verify_bundle.verify(bundle)["ok"]


def test_the_happy_case_fits_a_small_drift_and_places_both_marks(bundle_copy):
    bundle = bundle_copy(OK)
    decode_clock.decode(bundle, decoded_at=AT)
    manifest = manifest_of(bundle)
    pairs = rows(bundle, "clock_pairs")
    assert [p["phase"] for p in pairs] == ["start"] + ["interval"] * 11 + ["stop"]
    assert [p["seq"] for p in pairs] == list(range(13))
    for p in pairs:
        assert p["qpc_mid"] == (p["qpc_before"] + p["qpc_after"]) // 2 and p["bracket_ticks"] == 100 and p["half_width_100ns"] == 51
        assert p["system_time_increment_100ns"] == 10_000
        assert p["filetime_utc"] == decode_clock.filetime_to_iso(p["filetime_utc_100ns"])
    segments = rows(bundle, "clock_segments")
    assert len(segments) == 12 and not any(s["clock_step"] for s in segments)
    assert all(s["epoch_qpc"] == pairs[0]["qpc_mid"] and s["epoch_source"] == "first_calibration_pair" for s in segments)
    assert all(s["error_bound_100ns"] == 51 + 10_000 for s in segments)
    # The synthetic system clock runs 50 ppm fast; quantised to 1 ms over 5 s segments the fitted deviation stays well under the step rule.
    assert max(s["rate_deviation_ppm"] for s in segments) < 400 and all(abs(s["quantisation_limit_ppm"] - 400) < 5 for s in segments)
    checks = {c["name"]: c for c in meta(bundle, "clock_segments")["checks"]}
    assert checks["clock_steps"]["ok"] and checks["expected_pairs"]["ok"] and checks["phases"]["ok"] and checks["system_time_increment"]["ok"]
    marks = rows(bundle, "operator_marks")
    assert [m["label"] for m in marks] == ["felt a stutter", "second stutter, shorter"]
    assert [m["provenance"]["row_id_or_offset"] for m in marks] == ["line:1", "line:2"]
    assert manifest["scenario"]["marks"] == [{"label": m["label"], "at_utc": m["at_utc"], "qpc": m["qpc_mid"]} for m in marks]
    model = decode_clock.load_model(bundle)
    assert model.aligned
    for mark in marks:
        placed = model.align_mark(mark["qpc_before"], mark["qpc_after"])
        through_clock = model.align(mark["filetime_utc_100ns"])
        # The mark's own counter and the fitted system time agree to within the fit's bound.
        assert abs(placed.t_master_100ns - through_clock.t_master_100ns) <= through_clock.error_bound_100ns
        assert placed.error_bound_100ns == mark["half_width_100ns"]
    assert meta(bundle, "operator_marks")["time_domain"] == "etw_qpc"


def test_the_clock_step_case_flags_one_segment_and_refuses_joins_inside_it(bundle_copy):
    bundle = bundle_copy(STEP)
    decode_clock.decode(bundle, decoded_at=AT)
    segments = rows(bundle, "clock_segments")
    flagged = [s for s in segments if s["clock_step"]]
    assert len(flagged) == 1 and flagged[0]["segment"] == 2 and flagged[0]["error_bound_100ns"] == flagged[0]["span_100ns"]
    assert flagged[0]["rate_deviation_ppm"] > 1000 and flagged[0]["quantisation_limit_ppm"] < 1000, "the step is not quantisation"
    checks = {c["name"]: c for c in meta(bundle, "clock_segments")["checks"]}
    assert checks["clock_steps"]["ok"] is False and "segment 2" in checks["clock_steps"]["detail"]
    model = decode_clock.load_model(bundle)
    inside = model.align(decode_clock.iso_to_filetime("2026-03-01T12:00:12.6Z"), 10_000)
    outside = model.align(decode_clock.iso_to_filetime("2026-03-01T12:00:22.0Z"), 10_000)
    qpc_side = model.align_qpc(model.epoch_qpc)
    assert decode_clock.check_join("j", "eventlog", "wpr", 100_000, inside, qpc_side)["aligned"] is False
    assert decode_clock.check_join("j", "eventlog", "wpr", 100_000, outside, qpc_side)["aligned"] is True
    mark = rows(bundle, "operator_marks")[0]
    assert mark["label"] == "after the jump"
    # The mark sits on the counter, 20.1 s of true time after the synthetic reset and a few ms less after the first pair; the
    # segment that holds it lies after the step, so the fitted system time agrees with the counter to within the bound.
    placed = model.align_mark(mark["qpc_before"], mark["qpc_after"])
    assert 200_000_000 < placed.t_master_100ns < 201_000_000
    through_clock = model.align(mark["filetime_utc_100ns"])
    assert through_clock.aligned and not through_clock.clock_step
    assert abs(placed.t_master_100ns - through_clock.t_master_100ns) <= through_clock.error_bound_100ns


def test_the_missed_slot_case_is_observed_with_one_missing_pair_and_longer_segments(bundle_copy):
    bundle = bundle_copy(MISSED)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    assert clock["status"] == "observed" and clock["expectation"]["met"] is True, "the tolerance for missing pairs is the validator's check"
    assert "1 slots missed" in clock["expectation"]["detail"] and "missing_pairs" in clock["expectation"]["declared"]
    assert manifest["calibration"]["missing_pairs"] == 1 and manifest["calibration"]["expected_pairs"] == 7 and len(manifest["calibration"]["pairs"]) == 6
    assert any("1 of 7 expected pairs are missing" in note for note in manifest["notes"])
    result = decode_clock.decode(bundle, decoded_at=AT)
    assert result["clock_segments"]["status"] == "observed"
    segments = rows(bundle, "clock_segments")
    assert [s["seq_from"] for s in segments] == [0, 1, 3, 4, 5], "seq 2 is the missed slot"
    # The wait before the 10 s slot overran by six seconds: that slot is missed, and the 15 s slot is taken one second late.
    long = next(s for s in segments if s["seq_from"] == 1)
    assert long["seq_to"] == 3 and 105_000_000 <= long["span_100ns"] <= 115_000_000 and not long["clock_step"]
    checks = {c["name"]: c for c in meta(bundle, "clock_segments")["checks"]}
    assert checks["expected_pairs"]["ok"] is False and "1 missing" in checks["expected_pairs"]["detail"]
    # A coarse 15.625 ms timer: the increment is in every bound, and the sidecar says the step rule is quantisation limited on 5 s segments.
    assert all(s["system_time_increment_100ns"] == 156_250 for s in segments)
    assert checks["quantisation_below_step_rule"]["ok"] is False
    assert result["operator_marks"]["status"] == "observed_zero" and rows(bundle, "operator_marks") == []
    assert (bundle / "raw" / "operator_marks" / "marks.jsonl").read_text(encoding="utf-8") == ""


def test_the_failed_read_case_has_no_calibration_and_every_alignment_is_refused(bundle_copy):
    bundle = bundle_copy(FAILED)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    assert clock["status"] == "capture_failed" and "4 pairs had been taken and are not kept" in clock["status_reason"]
    assert [a["role"] for a in clock["artifacts"]] == ["report", "config"], "no samples file survives a failed session"
    assert not (bundle / "raw" / "clock_calibration" / "samples.jsonl").exists()
    assert manifest["calibration"]["status"] == "capture_failed" and manifest["calibration"]["pairs"] == []
    model = decode_clock.load_model(bundle)
    assert not model.aligned and "capture_failed" in model.reason
    refused = decode_clock.check_join("j", "pdh", "wpr", 10_000_000, model.align(134_168_400_100_000_000), None)
    assert refused["aligned"] is False and "calibration missing" in refused["reason"]
    result = decode_clock.decode(bundle, decoded_at=AT)
    assert result["clock_pairs"]["status"] == result["clock_segments"]["status"] == "not_collected"
    assert result["operator_marks"]["status"] == "observed_zero", "the marks file stood open for the whole session and holds nothing"


def test_decoder_refuses_a_samples_file_that_disagrees_with_the_manifest(bundle_copy):
    bundle = bundle_copy(OK)
    path = bundle / "raw" / "clock_calibration" / "samples.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[3])
    record["qpc_after"] += 1
    lines[3] = json.dumps(record, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            if artifact["path"].endswith("samples.jsonl"):
                artifact["bytes"], artifact["sha256"] = path.stat().st_size, wf_schema.sha256_of(path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = decode_clock.decode(bundle, decoded_at=AT)
    assert result["clock_pairs"]["status"] == "decode_failed" and "differs from the manifest pair" in result["clock_pairs"]["reason"]
    assert not (bundle / "decoded" / "clock_pairs.jsonl").exists()
    assert not decode_clock.load_model(bundle).aligned
    (bundle / "raw" / "clock_calibration" / "samples.jsonl").unlink()
    assert "missing from the bundle" in decode_clock.decode(bundle, decoded_at=AT)["clock_segments"]["reason"]


def test_decoder_cli(bundle_copy, capsys):
    bundle = bundle_copy(OK)
    code = decode_clock.main(["--bundle", str(bundle), "--decoded-at", AT, "--align", "2026-03-01T12:00:17.3Z", "--align", "2026-03-01T12:05:00Z",
                              "--source-resolution-100ns", "10000", "--tolerance-100ns", "100000"])
    out = capsys.readouterr().out
    assert code == 0
    assert "clock_segments: 12 rows from 1 sources, status observed" in out
    assert "operator_marks: 2 rows from 1 sources, status observed" in out
    assert "0 clock step segment(s)" in out
    assert "align 2026-03-01T12:00:17.3Z: t_master_100ns" in out and "join at tolerance 100000: accepted" in out
    assert "align 2026-03-01T12:05:00Z: unaligned" in out and "not extrapolated" in out
    assert decode_clock.main(["--bundle", str(bundle_copy(FAILED, "-f")), "--decoded-at", AT]) == 2
    assert "unalignable" in capsys.readouterr().out
