"""The clock calibration decoder and fit over the synthetic clock-calibration bundles, plus the fit on invented pair lists.

Four committed cases (collectors/windows/tests/SyntheticScenarios.ps1): a 60 s session with a
system clock 50 ppm fast and two operator marks; a 30 s session with a 250 ms forward step of the
system clock; a 30 s session with one missed interval slot on a coarse 15.625 ms timer; a session
whose counter read fails at the stop pair, so the stop pair is missing. Every number is invented by
the synthetic backend. The two blind reviews' reproductions of a backward clock step are regression
tests here.
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
NOSTOP = "clock-calibration-read-failed"
CASES = [OK, STEP, MISSED, NOSTOP]
TABLES = ["clock_pairs", "clock_segments", "operator_marks"]
FREQ = 10_000_000
AT = "2026-09-03T00:00:00Z"
FT0 = 134_168_400_000_000_000  # 2026-03-01T12:00:00Z as a file time


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


def outputs(bundle: Path, table: str) -> list[str]:
    return sorted(p.name for p in (bundle / "decoded").glob(f"{table}.*")) if (bundle / "decoded").is_dir() else []


def join_validator() -> Draft202012Validator:
    return Draft202012Validator({"$ref": wf_schema.schema_id("common.schema.json") + "#/$defs/join"}, registry=wf_schema.registry())


def pair(seq: int, phase: str, seconds: float, ft_offset_100ns: int = 0, bracket: int = 100, freq: int = FREQ, base_qpc: int = 5_000_000_000,
         base_ft: int = FT0, drift_ppm: float = 0.0, edge: bool = True, step: int | None = 10_000) -> dict:
    """An invented pair at `seconds` into the session, taken at a clock edge unless said otherwise."""
    qpc_before = base_qpc + int(seconds * freq)
    ft = base_ft + int(seconds * 10_000_000 * (1 + drift_ppm / 1_000_000)) + ft_offset_100ns
    return {"seq": seq, "phase": phase, "qpc_before": qpc_before, "qpc_after": qpc_before + bracket, "filetime_utc_100ns": ft,
            "edge": edge, "step_100ns": step if edge else None}


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
    assert not one.align(FT0).aligned
    assert "calibration missing" in one.align(0).reason
    assert not decode_clock.fit_pairs(session(10), None).aligned


def test_fit_is_identity_on_a_perfect_clock_and_anchors_the_epoch_on_the_first_pair_as_the_contract_says():
    pairs = session(30)
    model = decode_clock.fit_pairs(pairs, FREQ)
    assert model.aligned and len(model.segments) == 6 and model.clock_step_segments == 0
    # timestamps.md section 4.1: the epoch is the first pair's qpc_before, not its midpoint.
    assert model.epoch_qpc == pairs[0]["qpc_before"] and model.epoch_source == "first_calibration_pair"
    first = model.align(pairs[0]["filetime_utc_100ns"])
    assert first.aligned and first.t_master_100ns == 50, "the pair's midpoint sits half a bracket after the epoch"
    mid = model.align(pairs[0]["filetime_utc_100ns"] + 123_456_789, source_resolution_100ns=10_000)
    assert mid.t_master_100ns == 123_456_789 + 50
    # Edge pairs: the bound is the bracket (100 ticks / 2 + 1 tick = 51 x 100 ns) plus the source's own resolution only.
    assert mid.error_bound_100ns == 51 + 10_000
    assert model.align_qpc(model.epoch_qpc + 7_000_000) == decode_clock.Alignment(7_000_000, 1, None)


def test_a_pair_not_taken_at_a_clock_edge_carries_the_increment_term():
    pairs = session(20)
    pairs[2]["edge"], pairs[2]["step_100ns"] = False, None
    model = decode_clock.fit_pairs(pairs, FREQ)
    # The term is the larger of the largest step the collector saw (10000) and the documented default period:
    # the increment can change during a session, so a small step seen at other pairs does not bound this one.
    assert model.largest_step_100ns == 10_000 and model.fallback_increment_100ns == 156_250
    assert [s.increment_100ns for s in model.segments] == [0, 156_250, 156_250, 0]
    assert model.segments[1].error_bound_100ns == 51 + 156_250
    assert model.segments[1].quantisation_limit_ppm == pytest.approx(2 * (156_250 + 51) / 50_000_000 * 1e6)
    assert model.clock_step_segments == 0
    coarse = session(20, step=200_000)
    coarse[1]["edge"], coarse[1]["step_100ns"] = False, None
    coarse_model = decode_clock.fit_pairs(coarse, FREQ)
    assert coarse_model.fallback_increment_100ns == 200_000, "a step larger than the default period widens the term"
    none_seen = session(20, edge=False)
    assert decode_clock.fit_pairs(none_seen, FREQ).segments[0].increment_100ns == 156_250
    bad = session(20)
    bad[0]["step_100ns"] = None
    assert "edge pair without the clock step" in decode_clock.fit_pairs(bad, FREQ).reason


def test_fit_never_extrapolates_and_a_missing_stop_pair_leaves_the_tail_unaligned():
    pairs = session(30)
    model = decode_clock.fit_pairs(pairs, FREQ)
    before = model.align(pairs[0]["filetime_utc_100ns"] - 1)
    after = model.align(pairs[-1]["filetime_utc_100ns"] + 1)
    assert not before.aligned and not after.aligned and "not extrapolated" in after.reason
    without_stop = decode_clock.fit_pairs(pairs[:-1], FREQ)
    assert without_stop.aligned and without_stop.pairs[-1].phase == "interval"
    inside = without_stop.align(pairs[-2]["filetime_utc_100ns"])
    tail = without_stop.align(pairs[-2]["filetime_utc_100ns"] + 1_000_000)
    assert inside.aligned and not tail.aligned, "the last five seconds have no pair after them"
    join = decode_clock.check_join("tail", "pdh", "wpr", 100_000, tail, without_stop.align_qpc(without_stop.epoch_qpc))
    assert join["aligned"] is False and join["achieved_bound_100ns"] is None and "left unaligned" in join["reason"]


def test_a_steady_drift_within_the_rule_is_fitted_and_a_large_one_is_a_clock_step_on_every_segment():
    slow = decode_clock.fit_pairs(session(60, drift_ppm=-120), FREQ)
    assert slow.aligned and slow.clock_step_segments == 0
    assert all(abs(s.deviation_ppm - 120) < 1 for s in slow.segments)
    end = slow.align(slow.last_filetime)
    assert abs(end.t_master_100ns - 600_000_050) <= 1, "the last pair's own counter value, whatever the system clock did"
    fast = decode_clock.fit_pairs(session(60, drift_ppm=2500), FREQ)
    assert fast.aligned and fast.clock_step_segments == len(fast.segments)
    for segment in fast.segments:
        assert segment.clock_step and segment.step_kind == "forward"
        assert segment.error_bound_100ns == 51 + max(segment.span_100ns, segment.qpc_span_100ns)
    aligned = fast.align(fast.first_filetime + 10_000_000)
    assert aligned.aligned and aligned.clock_step and aligned.error_bound_100ns >= 50_000_000


def test_a_wide_counter_bracket_on_a_perfect_clock_is_not_a_clock_step():
    """An edge pair whose loop was preempted for 30 ms: its midpoint sits 15 ms from the edge, 3000 ppm over 5 s.

    The pair's own half width explains that deviation, so neither neighbouring segment is a clock step and no
    file time is refused as shown twice; the wide half width still enters the bound.
    """
    pairs = session(30)
    pairs[3]["qpc_after"] = pairs[3]["qpc_before"] + 300_000
    model = decode_clock.fit_pairs(pairs, FREQ)
    assert model.aligned and model.clock_step_segments == 0
    assert [s.step_kind for s in model.segments] == ["none"] * 6
    assert all(s.ambiguous_range is None for s in model.segments)
    for index in (2, 3):
        segment = model.segments[index]
        assert segment.deviation_ppm == pytest.approx(3000, abs=2) and segment.half_width_max_100ns == 150_001
        assert segment.quantisation_limit_ppm == pytest.approx(2 * 150_001 / 50_000_000 * 1e6)
        assert segment.error_bound_100ns == 150_001, "the wide half width is still in the bound"
    for seconds in (2, 7, 12, 17, 22, 27):
        placed = model.align(FT0 + seconds * 10_000_000)
        assert placed.aligned and not placed.clock_step
    assert model.align(FT0 + 70_000_000).error_bound_100ns == 51


def test_a_forward_clock_step_in_one_segment_widens_only_that_segment():
    pairs = session(30)
    stepped = [dict(p, filetime_utc_100ns=p["filetime_utc_100ns"] + (2_500_000 if p["seq"] >= 3 else 0)) for p in pairs]
    model = decode_clock.fit_pairs(stepped, FREQ)
    assert [s.clock_step for s in model.segments] == [False, False, True, False, False, False]
    flagged = model.segments[2]
    assert flagged.step_kind == "forward" and flagged.ambiguous_range is None
    assert flagged.error_bound_100ns == 51 + 52_500_000 and flagged.span_100ns == 52_500_000 > flagged.qpc_span_100ns
    assert model.segments[0].error_bound_100ns == 51
    inside = model.align(stepped[2]["filetime_utc_100ns"] + 10_000_000)
    outside = model.align(stepped[4]["filetime_utc_100ns"] + 10_000_000)
    assert inside.clock_step and not outside.clock_step
    refused = decode_clock.check_join("dpc_to_log", "eventlog", "wpr", 50_000, inside, model.align_qpc(model.epoch_qpc))
    accepted = decode_clock.check_join("dpc_to_log", "eventlog", "wpr", 50_000, outside, model.align_qpc(model.epoch_qpc))
    assert refused["aligned"] is False and refused["achieved_bound_100ns"] == 52_500_052 and "not widened" in refused["reason"]
    assert accepted == {"id": "dpc_to_log", "left": "eventlog", "right": "wpr", "tolerance_100ns": 50_000, "achieved_bound_100ns": 52, "aligned": True, "reason": None}
    validator = join_validator()
    assert list(validator.iter_errors(refused)) == [] and list(validator.iter_errors(accepted)) == []


def test_a_backward_step_smaller_than_the_interval_never_passes_a_tight_join():
    """Review 1's reproduction: five seconds of counter against one millisecond of file time.

    The step segment's bound must be the elapsed master span, never the shortened wall clock span, and must
    never come out smaller than an ordinary segment's bound.
    """
    pairs = [{"seq": i, "phase": phase, "qpc_before": qpc, "qpc_after": qpc + 100, "filetime_utc_100ns": stamp, "edge": True, "step_100ns": 10_000}
             for i, (phase, qpc, stamp) in enumerate([("start", 1_000_000_000, FT0), ("interval", 1_050_000_000, FT0 + 50_000_000), ("stop", 1_100_000_000, FT0 + 50_010_000)])]
    model = decode_clock.fit_pairs(pairs, FREQ)
    assert model.aligned
    step = model.segments[1]
    assert step.clock_step and step.step_kind == "backward" and step.span_100ns == 10_000 and step.qpc_span_100ns == 50_000_000
    assert step.error_bound_100ns == 51 + 50_000_000 >= model.segments[0].error_bound_100ns
    placed = model.align(FT0 + 50_005_000, 1)
    assert placed.aligned and placed.clock_step and placed.error_bound_100ns == 51 + 50_000_000 + 1
    join = decode_clock.check_join("j", "eventlog", "wpr", 100_000, placed, model.align_qpc(model.epoch_qpc))
    assert join["aligned"] is False and join["achieved_bound_100ns"] == 50_000_053
    # The file times the clock may have shown twice: from ft_a minus the lost 4.999 s up to ft_a plus the counter span.
    assert step.ambiguous_range == (FT0 + 50_000_000 - 49_990_000, FT0 + 50_000_000 + 50_000_000)
    assert not model.align(FT0 + 30_000_000).aligned, "a stamp in the first segment that the clock re-showed after the step is ambiguous"


def test_a_backward_step_of_three_seconds_makes_the_re_shown_file_times_unaligned():
    """Review 2's reproduction: pairs at 0, 5, 10, 15, 20 s of true time; the system clock steps back 3 s at 9 s.

    An event the clock stamped 8.5 s before the step falls, by file time, into the segment after the step,
    which would place it 3 s late with a millisecond bound. It must be refused instead.
    """
    true_times = [0, 5, 10, 15, 20]
    pairs = []
    for seq, t in enumerate(true_times):
        ft = FT0 + t * 10_000_000 - (30_000_000 if t >= 9 else 0)
        qpc = 1_000_000_000 + t * FREQ
        pairs.append({"seq": seq, "phase": "start" if seq == 0 else ("stop" if seq == 4 else "interval"), "qpc_before": qpc, "qpc_after": qpc + 100,
                      "filetime_utc_100ns": ft, "edge": True, "step_100ns": 10_000})
    model = decode_clock.fit_pairs(pairs, FREQ)
    assert model.aligned
    assert [s.step_kind for s in model.segments] == ["none", "backward", "none", "none"]
    step = model.segments[1]
    assert step.span_100ns == 20_000_000 and step.qpc_span_100ns == 50_000_000
    assert step.error_bound_100ns == 51 + 50_000_000, "the elapsed master span, not the 2 s file time span"
    assert step.ambiguous_range == (FT0 + 50_000_000 - 30_000_000, FT0 + 50_000_000 + 50_000_000)
    event = model.align(FT0 + 85_000_000)
    assert not event.aligned and "shown twice" in event.reason and "segment 1" in event.reason
    # Inside the step segment itself a stamp is placed with the wide bound; the re-shown range in the first segment is refused too.
    inside = model.align(FT0 + 60_000_000)
    assert inside.aligned and inside.clock_step and inside.error_bound_100ns >= 50_000_000
    assert not model.align(FT0 + 25_000_000).aligned
    assert model.align(FT0 + 15_000_000).aligned and model.align(FT0 + 15_000_000).error_bound_100ns == 51
    # Beyond the ambiguous range the model is tight again.
    late = model.align(FT0 + 150_000_000)
    assert late.aligned and not late.clock_step and late.error_bound_100ns == 51
    refused = decode_clock.check_join("j", "eventlog", "wpr", 100_000, event, model.align_qpc(model.epoch_qpc))
    assert refused["aligned"] is False and "shown twice" in refused["reason"]


def test_a_backward_step_larger_than_the_interval_cannot_be_fitted():
    pairs = session(20)
    pairs[2]["filetime_utc_100ns"] -= 60_000_000
    model = decode_clock.fit_pairs(pairs, FREQ)
    assert not model.aligned and "backward step larger than the interval" in model.reason


def test_join_bounds_add_and_are_never_shrunk():
    left = decode_clock.Alignment(100, 30_000, 0)
    right = decode_clock.Alignment(100, 20_000, None)
    assert decode_clock.check_join("j", "a", "b", 50_000, left, right)["aligned"] is True
    assert decode_clock.check_join("j", "a", "b", 49_999, left, right)["aligned"] is False
    assert decode_clock.check_join("j", "a", "b", 49_999, left, right)["achieved_bound_100ns"] == 50_000
    with pytest.raises(ValueError):
        decode_clock.check_join("j", "a", "b", -1, left, right)


def test_file_time_conversions_round_trip_at_100_ns():
    assert decode_clock.filetime_to_iso(134_168_400_000_040_000) == "2026-03-01T12:00:00.0040000Z"
    assert decode_clock.iso_to_filetime("2026-03-01T12:00:00.0040000Z") == 134_168_400_000_040_000
    assert decode_clock.iso_to_filetime("2026-03-01T12:00:00Z") == FT0
    with pytest.raises(ValueError):
        decode_clock.iso_to_filetime("01/03/2026 12:00")


# ---------------------------------------------------------------- the committed bundles

@pytest.mark.parametrize("case", CASES)
def test_decoded_tables_validate_and_the_bundle_still_verifies(case, bundle_copy):
    bundle = bundle_copy(case)
    result = decode_clock.decode(bundle, decoded_at=AT)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    assert clock["status"] == "observed", "every committed case keeps a calibration"
    for table in TABLES:
        assert result[table]["status"] in ("observed", "observed_zero"), (table, result[table])
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
    assert result["clock_pairs"]["rows"] == len(manifest["calibration"]["pairs"]) == result["clock_segments"]["rows"] + 1
    assert meta(bundle, "clock_pairs")["time_domain"] == "system_time"
    pairs = rows(bundle, "clock_pairs")
    assert all(p["edge"] and p["system_time_step_100ns"] in (10_000, 156_250) for p in pairs), "the synthetic session takes every pair at a clock edge"
    assert all(s["system_time_increment_100ns"] == 0 for s in rows(bundle, "clock_segments"))
    assert all(s["quantisation_limit_ppm"] == pytest.approx(2 * s["half_width_max_100ns"] / s["span_100ns"] * 1e6) for s in rows(bundle, "clock_segments"))
    assert all(s["epoch_qpc"] == pairs[0]["qpc_before"] for s in rows(bundle, "clock_segments"))
    assert verify_bundle.verify(bundle)["ok"]


def test_the_happy_case_fits_the_drift_and_places_both_marks(bundle_copy):
    bundle = bundle_copy(OK)
    decode_clock.decode(bundle, decoded_at=AT)
    manifest = manifest_of(bundle)
    pairs = rows(bundle, "clock_pairs")
    assert [p["phase"] for p in pairs] == ["start"] + ["interval"] * 11 + ["stop"]
    assert [p["seq"] for p in pairs] == list(range(13))
    for p in pairs:
        assert p["qpc_mid"] == (p["qpc_before"] + p["qpc_after"]) // 2 and p["bracket_ticks"] == 250 and p["half_width_100ns"] == 126
        assert p["filetime_utc"] == decode_clock.filetime_to_iso(p["filetime_utc_100ns"]) and p["filetime_utc_100ns"] % 10_000 == 0
    segments = rows(bundle, "clock_segments")
    assert len(segments) == 12 and not any(s["clock_step"] for s in segments)
    assert all(s["error_bound_100ns"] == 126 for s in segments)
    # The synthetic system clock runs 50 ppm fast, and edge pairs read it exactly.
    assert all(45 < s["rate_deviation_ppm"] < 55 for s in segments)
    checks = {c["name"]: c for c in meta(bundle, "clock_segments")["checks"]}
    assert checks["clock_steps"]["ok"] and checks["expected_pairs"]["ok"] and checks["phases"]["ok"] and checks["edge_pairs"]["ok"]
    marks = rows(bundle, "operator_marks")
    assert [m["label"] for m in marks] == ["felt a stutter", "second stutter, shorter"]
    assert [m["provenance"]["row_id_or_offset"] for m in marks] == ["line:1", "line:2"]
    assert manifest["scenario"]["marks"] == [{"label": m["label"], "at_utc": m["at_utc"], "qpc": m["qpc_mid"]} for m in marks]
    model = decode_clock.load_model(bundle)
    assert model.aligned
    for mark in marks:
        placed = model.align_mark(mark["qpc_before"], mark["qpc_after"])
        through_clock = model.align(mark["filetime_utc_100ns"])
        # A mark's plain system time reading can lag the true time by one increment; the counter and the fitted
        # clock agree within that plus the fit's bound.
        assert abs(placed.t_master_100ns - through_clock.t_master_100ns) <= through_clock.error_bound_100ns + 10_000
        assert placed.error_bound_100ns == mark["half_width_100ns"]
    assert meta(bundle, "operator_marks")["time_domain"] == "etw_qpc"


def test_the_clock_step_case_flags_one_forward_segment_and_refuses_joins_inside_it(bundle_copy):
    bundle = bundle_copy(STEP)
    decode_clock.decode(bundle, decoded_at=AT)
    segments = rows(bundle, "clock_segments")
    flagged = [s for s in segments if s["clock_step"]]
    assert len(flagged) == 1 and flagged[0]["segment"] == 2 and flagged[0]["step_kind"] == "forward"
    assert flagged[0]["error_bound_100ns"] == flagged[0]["half_width_max_100ns"] + max(flagged[0]["span_100ns"], flagged[0]["qpc_span_100ns"])
    assert flagged[0]["ambiguous_from_100ns"] is None and flagged[0]["rate_deviation_ppm"] > 1000
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
    placed = model.align_mark(mark["qpc_before"], mark["qpc_after"])
    assert 200_000_000 < placed.t_master_100ns < 201_000_000
    through_clock = model.align(mark["filetime_utc_100ns"])
    assert through_clock.aligned and not through_clock.clock_step
    assert abs(placed.t_master_100ns - through_clock.t_master_100ns) <= through_clock.error_bound_100ns + 10_000


def test_the_missed_slot_case_is_observed_with_one_missing_pair_and_a_longer_segment(bundle_copy):
    bundle = bundle_copy(MISSED)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    assert clock["status"] == "observed" and clock["expectation"]["met"] is False, "the full count is the expectation; the count carries the degradation"
    assert "1 missing" in clock["expectation"]["detail"]
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
    # The coarse 15.625 ms timer: every pair still sits on an edge, so the bound is the bracket.
    assert all(p["system_time_step_100ns"] == 156_250 for p in rows(bundle, "clock_pairs"))
    assert all(s["error_bound_100ns"] == 126 for s in segments)
    assert result["operator_marks"]["status"] == "observed_zero" and rows(bundle, "operator_marks") == []
    assert (bundle / "raw" / "operator_marks" / "marks.jsonl").read_text(encoding="utf-8") == ""


def test_the_missing_stop_case_keeps_its_pairs_and_leaves_the_tail_unaligned(bundle_copy):
    bundle = bundle_copy(NOSTOP)
    manifest = manifest_of(bundle)
    clock = next(c for c in manifest["collectors"] if c["id"] == "clock_calibration")
    assert clock["status"] == "observed" and clock["status_reason"] is None and clock["expectation"]["met"] is False
    assert "performance counter read failed" in clock["expectation"]["detail"] and "stop pair taken: False" in clock["expectation"]["detail"]
    assert manifest["calibration"]["status"] == "observed" and manifest["calibration"]["missing_pairs"] == 1
    assert [p["phase"] for p in manifest["calibration"]["pairs"]] == ["start", "interval", "interval", "interval"]
    assert any("the stop pair included" in note for note in manifest["notes"])
    result = decode_clock.decode(bundle, decoded_at=AT)
    assert result["clock_segments"]["status"] == "observed" and result["clock_segments"]["rows"] == 3
    checks = {c["name"]: c for c in meta(bundle, "clock_segments")["checks"]}
    assert checks["phases"]["ok"] is False and "stop pair is missing" in checks["phases"]["detail"]
    model = decode_clock.load_model(bundle)
    assert model.aligned
    last = model.pairs[-1].filetime_utc_100ns
    assert model.align(last).aligned
    tail = model.align(last + 10_000_000)
    assert not tail.aligned and "not extrapolated" in tail.reason
    assert decode_clock.check_join("j", "pdh", "wpr", 10_000_000, tail, model.align_qpc(model.epoch_qpc))["aligned"] is False
    assert result["operator_marks"]["status"] == "observed_zero", "the marks file stood open until the failure and holds nothing"


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


def test_a_failed_rerun_replaces_the_earlier_observed_tables(bundle_copy):
    """bundle.md section 1: re running a decoder replaces its own outputs. A failure after a success must not leave
    an observed sidecar behind for a reader to consume."""
    bundle = bundle_copy(OK)
    first = decode_clock.decode(bundle, decoded_at=AT)
    assert first["clock_segments"]["status"] == "observed" and outputs(bundle, "clock_segments") == ["clock_segments.jsonl", "clock_segments.meta.json"]
    # The raw artifact disappears: decode_failed, and nothing of the earlier run remains for the clock tables.
    (bundle / "raw" / "clock_calibration" / "samples.jsonl").unlink()
    second = decode_clock.decode(bundle, decoded_at=AT)
    assert second["clock_pairs"]["status"] == second["clock_segments"]["status"] == "decode_failed"
    assert outputs(bundle, "clock_pairs") == [] and outputs(bundle, "clock_segments") == []
    assert outputs(bundle, "operator_marks") == ["operator_marks.jsonl", "operator_marks.meta.json"], "the marks table still has its input"
    # The manifest now says the calibration failed: not_collected, and again no stale table.
    bundle2 = bundle_copy(OK, "-status")
    assert decode_clock.decode(bundle2, decoded_at=AT)["clock_pairs"]["status"] == "observed"
    manifest_path = bundle2 / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for collector in manifest["collectors"]:
        collector["status"], collector["status_reason"] = "capture_failed", "edited by the test"
    manifest["calibration"]["status"] = "capture_failed"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    third = decode_clock.decode(bundle2, decoded_at=AT)
    assert all(third[t]["status"] == "not_collected" for t in TABLES)
    assert all(outputs(bundle2, t) == [] for t in TABLES)
    # A bundle whose manifest is gone: every table of this decoder is removed.
    bundle3 = bundle_copy(OK, "-nomanifest")
    decode_clock.decode(bundle3, decoded_at=AT)
    (bundle3 / "manifest.json").unlink()
    fourth = decode_clock.decode(bundle3, decoded_at=AT)
    assert all(fourth[t]["status"] == "decode_failed" for t in TABLES) and all(outputs(bundle3, t) == [] for t in TABLES)


def test_decoder_cli(bundle_copy, capsys):
    bundle = bundle_copy(OK)
    code = decode_clock.main(["--bundle", str(bundle), "--decoded-at", AT, "--align", "2026-03-01T12:00:17.3Z", "--align", "2026-03-01T12:05:00Z",
                              "--source-resolution-100ns", "10000", "--tolerance-100ns", "100000"])
    out = capsys.readouterr().out
    assert code == 0
    assert "clock_segments: 12 rows from 1 sources, status observed" in out
    assert "operator_marks: 2 rows from 1 sources, status observed" in out
    assert "0 clock step segment(s), 13 of 13 pairs at a clock edge" in out
    assert "align 2026-03-01T12:00:17.3Z: t_master_100ns" in out and "join at tolerance 100000: accepted" in out
    assert "align 2026-03-01T12:05:00Z: unaligned" in out and "not extrapolated" in out
    broken = bundle_copy(OK, "-broken")
    (broken / "raw" / "clock_calibration" / "samples.jsonl").unlink()
    assert decode_clock.main(["--bundle", str(broken), "--decoded-at", AT]) == 2
    assert "unalignable" in capsys.readouterr().out
