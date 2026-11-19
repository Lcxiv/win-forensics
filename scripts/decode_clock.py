#!/usr/bin/env python3
"""Decode a clock-calibration bundle and fit the common clock model.

See docs/contracts/timestamps.md (sections 3 and 4) and
docs/contracts/decoded-tables.md sections 5.17 to 5.19. The collector
(``collectors/windows/clock-calibration.ps1``) writes two sources; this
decoder reads the primary artifact of each one that is ``observed`` or
``observed_zero`` and writes three tables:

==================  ======================================  ================
Table               Source                                  Provenance
==================  ======================================  ================
``clock_pairs``     clock_calibration (samples.jsonl)       ``line:<n>``
``clock_segments``  clock_calibration (the fit)             ``line:<a>-<b>``
``operator_marks``  operator_marks (marks.jsonl)            ``line:<n>``
==================  ======================================  ================

The fit is the contract's piecewise linear model over consecutive pairs.
For each segment the rate is the counter span over the file time span and
the bound is the larger half width of the two pairs plus an increment term:
zero when both pairs were taken at a change of the system clock (the
collector's edge reading, see docs/clock-calibration.md), else the larger
of the largest clock step the collector observed and the 15.625 ms period
of the 64 Hz PC real time clock from Microsoft's clock table, because the
increment can change during a session (Microsoft's timeBeginPeriod page)
and the steps seen at other pairs do not bound the one at this pair. A
segment whose rate is off the nominal ``qpc_frequency_hz / 10^7`` by more
than 1000 parts per million beyond what its two pairs' own uncertainty
(half widths and increment term) can explain is a ``clock_step``: its bound
also carries the larger of its file time span and its elapsed counter span,
and when the system clock lost time (a backward step) the file times it may
have shown twice are refused in every other segment. The master epoch is
the first pair's ``qpc_before``.

The same module is the library a correlator uses: ``load_model`` returns a
``ClockModel`` (or an ``Unalignable`` with the reason), ``ClockModel.align``
turns a UTC file time into master time with its bound or says why it
cannot, ``align_qpc`` places a counter value (a mark, an ETW event) on the
master clock, and ``check_join`` applies section 5 of the timestamp
contract: a join is refused when either side is unaligned or the summed
bounds exceed the playbook's tolerance, and the tolerance is never widened.

A calibration whose collector is not ``observed`` (fewer than two pairs, a
managed timer that is not the high resolution counter) is never fitted: the
clock tables are ``not_collected`` and every alignment through it is
refused. A samples file that disagrees with the manifest's own pairs list
is ``decode_failed``. Whatever the outcome, a run replaces this decoder's
earlier outputs: a table that is not written on this run is removed.

Usage::

    python scripts/decode_clock.py --bundle <bundle directory> [--decoded-at 2026-09-03T00:00:00Z]
        [--align 2026-03-01T12:00:17Z ...] [--source-resolution-100ns N] [--tolerance-100ns N]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

DECODER = "decode_clock"
DECODER_VERSION = "1.0.0"
OBSERVED = ("observed", "observed_zero")
TOOL = {"name": "collectors/windows clock-calibration (Stopwatch.GetTimestamp, DateTime.UtcNow)", "version": None}
CLOCK_SOURCE = "clock_calibration"
MARKS_SOURCE = "operator_marks"
TABLES = ("clock_pairs", "clock_segments", "operator_marks")
PHASES = ("start", "interval", "stop")
HUNDRED_NS_PER_SECOND = 10_000_000
# docs/contracts/timestamps.md section 4.3: more than 1000 ppm off nominal, beyond what the pairs'
# own uncertainty can explain, is a clock step.
CLOCK_STEP_PPM = 1000.0
# The floor of the increment term for a pair the collector could not take at a clock edge: the term is
# the larger of this and the largest clock step seen in the session. It is the 15.625 ms period of the
# 64 Hz PC real time clock in the clock table of
# https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
# ("PC RTC | 64 Hz | 15.625 milliseconds"), the conventional default system timer period. The larger of
# the two is taken because the increment can change during a session, so a smaller step seen at
# another pair does not bound this one: https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timebeginperiod
# (since Windows 10 version 2004 a process's request no longer affects global timer resolution; since
# Windows 11 an occluded or minimised process is not guaranteed a higher resolution than the default).
FALLBACK_INCREMENT_100NS = 156_250
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
RE_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z$")


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------- time helpers

def filetime_to_iso(filetime_100ns: int) -> str:
    """A Windows file time as ISO 8601 UTC with seven fractional digits."""
    seconds, fraction = divmod(int(filetime_100ns), HUNDRED_NS_PER_SECOND)
    when = FILETIME_EPOCH + timedelta(seconds=seconds)
    return when.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:07d}Z"


def iso_to_filetime(text: str) -> int:
    """ISO 8601 UTC (up to seven fractional digits) as a Windows file time."""
    m = RE_ISO.match(text.strip())
    if not m:
        raise ValueError(f"{text!r} is not ISO 8601 UTC with a trailing Z")
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    fraction = int((m.group(2) or "").ljust(7, "0"))
    return int((base - FILETIME_EPOCH).total_seconds()) * HUNDRED_NS_PER_SECOND + fraction


def ticks_to_100ns_ceil(ticks: Fraction | int, frequency_hz: int) -> int:
    return math.ceil(Fraction(ticks) * HUNDRED_NS_PER_SECOND / frequency_hz)


def half_width_100ns(qpc_before: int, qpc_after: int, frequency_hz: int) -> int:
    """The pair's uncertainty from its counter bracket: half the bracket plus one tick, in 100 ns, rounded up."""
    bracket = int(qpc_after) - int(qpc_before)
    if bracket < 0:
        raise DecodeError(f"qpc_after {qpc_after} is before qpc_before {qpc_before}")
    return ticks_to_100ns_ceil(Fraction(bracket, 2) + 1, frequency_hz)


def qpc_mid(qpc_before: int, qpc_after: int) -> int:
    return (int(qpc_before) + int(qpc_after)) // 2


# ---------------------------------------------------------------- the model

@dataclass(frozen=True)
class Pair:
    seq: int
    phase: str
    qpc_before: int
    qpc_after: int
    filetime_utc_100ns: int
    line: int  # 1-based line in samples.jsonl
    edge: bool = False
    step_100ns: int | None = None

    @property
    def qpc_mid(self) -> int:
        return qpc_mid(self.qpc_before, self.qpc_after)


@dataclass(frozen=True)
class Segment:
    index: int
    a: Pair
    b: Pair
    frequency_hz: int
    epoch_qpc: int
    increment_100ns: int  # the term added for this segment: 0 when both pairs are edge pairs

    @property
    def span_100ns(self) -> int:
        return self.b.filetime_utc_100ns - self.a.filetime_utc_100ns

    @property
    def qpc_span_ticks(self) -> int:
        return self.b.qpc_mid - self.a.qpc_mid

    @property
    def qpc_span_100ns(self) -> int:
        return ticks_to_100ns_ceil(self.qpc_span_ticks, self.frequency_hz)

    @property
    def rate_ticks_per_100ns(self) -> Fraction:
        return Fraction(self.qpc_span_ticks, self.span_100ns)

    @property
    def nominal_rate(self) -> Fraction:
        return Fraction(self.frequency_hz, HUNDRED_NS_PER_SECOND)

    @property
    def rate(self) -> Fraction:
        """Master 100 ns per source 100 ns."""
        return self.rate_ticks_per_100ns / self.nominal_rate

    @property
    def deviation_ppm(self) -> float:
        return abs(float(self.rate) - 1.0) * 1_000_000

    @property
    def quantisation_limit_ppm(self) -> float:
        """The rate deviation the two pairs' own uncertainty (increment term and half widths) can explain."""
        return 2 * (self.increment_100ns + self.half_width_max_100ns) / self.span_100ns * 1_000_000

    @property
    def clock_step(self) -> bool:
        return self.deviation_ppm > CLOCK_STEP_PPM + self.quantisation_limit_ppm

    @property
    def step_kind(self) -> str:
        if not self.clock_step:
            return "none"
        # The counter is the master clock: more counter time than file time means the system clock lost time.
        return "backward" if self.qpc_span_100ns > self.span_100ns else "forward"

    @property
    def ambiguous_range(self) -> tuple[int, int] | None:
        """For a backward step: the file times the system clock may have shown twice.

        The step of size delta = qpc span - file time span happened at an unknown moment inside the
        segment; wherever it happened, the clock re-showed the delta of file time before it, so the union
        over every possible moment runs from ft_a - delta to ft_a + qpc span. Both pairs are themselves
        only known to the segment's ordinary uncertainty (the larger half width of the two plus the
        increment term), so both ends carry that too.
        """
        if self.step_kind != "backward":
            return None
        delta = self.qpc_span_100ns - self.span_100ns
        u = self.half_width_max_100ns + self.increment_100ns
        return (self.a.filetime_utc_100ns - delta - u, self.a.filetime_utc_100ns + self.qpc_span_100ns + u)

    @property
    def half_width_max_100ns(self) -> int:
        return max(half_width_100ns(self.a.qpc_before, self.a.qpc_after, self.frequency_hz),
                   half_width_100ns(self.b.qpc_before, self.b.qpc_after, self.frequency_hz))

    @property
    def residual_max_100ns(self) -> int:
        # A segment between consecutive pairs has no interior pair.
        return 0

    @property
    def error_bound_100ns(self) -> int:
        bound = self.half_width_max_100ns + self.increment_100ns + self.residual_max_100ns
        if self.clock_step:
            # Widened to the full span between the pairs, on whichever clock elapsed more; the
            # ordinary terms stay, so a step never shrinks a bound.
            bound += max(self.span_100ns, self.qpc_span_100ns)
        return bound

    def master_of_qpc(self, qpc: Fraction | int) -> int:
        return math.floor(Fraction(qpc - self.epoch_qpc) * HUNDRED_NS_PER_SECOND / self.frequency_hz)

    @property
    def anchor_master_100ns(self) -> int:
        return self.master_of_qpc(self.a.qpc_mid)

    def contains(self, filetime_100ns: int) -> bool:
        return self.a.filetime_utc_100ns <= filetime_100ns <= self.b.filetime_utc_100ns

    def master_of_filetime(self, filetime_100ns: int) -> int:
        qpc = self.a.qpc_mid + (filetime_100ns - self.a.filetime_utc_100ns) * self.rate_ticks_per_100ns
        return self.master_of_qpc(qpc)


@dataclass(frozen=True)
class Alignment:
    t_master_100ns: int
    error_bound_100ns: int
    segment: int | None
    clock_step: bool = False

    @property
    def aligned(self) -> bool:
        return True


@dataclass(frozen=True)
class Unaligned:
    reason: str

    @property
    def aligned(self) -> bool:
        return False


@dataclass(frozen=True)
class Unalignable:
    """No model exists: calibration missing, not observed, or fewer than two pairs."""
    reason: str

    @property
    def aligned(self) -> bool:
        return False

    def align(self, filetime_100ns: int, source_resolution_100ns: int = 0) -> Unaligned:
        return Unaligned(f"calibration missing: {self.reason}")

    def align_qpc(self, qpc: int, extra_100ns: int = 0) -> Unaligned:
        return Unaligned(f"calibration missing: {self.reason}")


@dataclass
class ClockModel:
    frequency_hz: int
    epoch_qpc: int
    epoch_source: str
    largest_step_100ns: int | None  # the largest clock increment the collector saw at an edge pair
    pairs: list[Pair]
    segments: list[Segment] = field(default_factory=list)

    @property
    def aligned(self) -> bool:
        return True

    @property
    def first_filetime(self) -> int:
        return self.pairs[0].filetime_utc_100ns

    @property
    def last_filetime(self) -> int:
        return self.pairs[-1].filetime_utc_100ns

    @property
    def clock_step_segments(self) -> int:
        return sum(1 for s in self.segments if s.clock_step)

    @property
    def fallback_increment_100ns(self) -> int:
        """The term for a pair not taken at a clock edge: the larger of the largest step seen and the documented default period."""
        return max(self.largest_step_100ns or 0, FALLBACK_INCREMENT_100NS)

    def segment_for(self, filetime_100ns: int) -> Segment | None:
        for segment in self.segments:
            if segment.contains(filetime_100ns):
                return segment
        return None

    def ambiguity_for(self, filetime_100ns: int, segment: Segment) -> Segment | None:
        """The backward step segment, other than the one given, whose re-shown file times include this one."""
        for other in self.segments:
            if other is segment:
                continue
            span = other.ambiguous_range
            if span is not None and span[0] <= filetime_100ns <= span[1]:
                return other
        return None

    def align(self, filetime_100ns: int, source_resolution_100ns: int = 0) -> Alignment | Unaligned:
        """Master time of a system_time stamp with the bound e_S = segment bound + the source's own resolution.

        A stamp outside every pair is unaligned, never extrapolated (timestamps.md section 4.3). A stamp
        the system clock may have shown twice because of a backward step in another segment is unaligned,
        because the segment it falls in would place it with a bound that does not cover the step.
        """
        if source_resolution_100ns < 0:
            raise ValueError("a resolution cannot be negative")
        filetime_100ns = int(filetime_100ns)
        segment = self.segment_for(filetime_100ns)
        if segment is None:
            return Unaligned(f"{filetime_to_iso(filetime_100ns)} is outside every calibration pair "
                             f"({filetime_to_iso(self.first_filetime)} to {filetime_to_iso(self.last_filetime)}); not extrapolated")
        other = self.ambiguity_for(filetime_100ns, segment)
        if other is not None:
            span = other.ambiguous_range
            return Unaligned(f"{filetime_to_iso(filetime_100ns)} is a file time the system clock may have shown twice: "
                             f"segment {other.index} (pairs {other.a.seq} to {other.b.seq}) holds a backward clock step of "
                             f"{other.qpc_span_100ns - other.span_100ns} x 100 ns, so every file time from {filetime_to_iso(span[0])} "
                             f"to {filetime_to_iso(span[1])} is ambiguous")
        return Alignment(segment.master_of_filetime(filetime_100ns), segment.error_bound_100ns + int(source_resolution_100ns),
                         segment.index, segment.clock_step)

    def align_qpc(self, qpc: int, extra_100ns: int = 0) -> Alignment:
        """Master time of a counter value from the etw_qpc domain: rate 1, bound one tick plus the caller's term."""
        master = math.floor(Fraction(int(qpc) - self.epoch_qpc) * HUNDRED_NS_PER_SECOND / self.frequency_hz)
        return Alignment(master, ticks_to_100ns_ceil(1, self.frequency_hz) + int(extra_100ns), None)

    def align_mark(self, qpc_before: int, qpc_after: int) -> Alignment:
        return self.align_qpc(qpc_mid(qpc_before, qpc_after), half_width_100ns(qpc_before, qpc_after, self.frequency_hz)
                              - ticks_to_100ns_ceil(1, self.frequency_hz))


def fit_pairs(pairs: list[dict[str, Any]], frequency_hz: int | None) -> ClockModel | Unalignable:
    """Fit the contract's model to calibration pairs.

    Each pair has the manifest shape (seq, phase, qpc_before, qpc_after, filetime_utc_100ns) and may carry
    the samples file's ``edge`` and ``step_100ns``; a pair without ``edge`` is taken as a plain reading and
    gets the increment term. The master epoch is the first pair's ``qpc_before``.
    """
    if frequency_hz is None or int(frequency_hz) < 1:
        return Unalignable("qpc_frequency_hz is unknown")
    frequency_hz = int(frequency_hz)
    typed: list[Pair] = []
    for index, raw in enumerate(pairs):
        try:
            step = raw.get("step_100ns")
            pair = Pair(int(raw["seq"]), str(raw["phase"]), int(raw["qpc_before"]), int(raw["qpc_after"]),
                        int(raw["filetime_utc_100ns"]), int(raw.get("line", index + 1)), bool(raw.get("edge", False)),
                        int(step) if isinstance(step, int) and not isinstance(step, bool) and step > 0 else None)
        except (KeyError, TypeError, ValueError) as exc:
            return Unalignable(f"pair {index} is malformed: {exc}")
        if pair.phase not in PHASES:
            return Unalignable(f"pair {index} has phase {pair.phase!r}")
        if pair.qpc_after < pair.qpc_before:
            return Unalignable(f"pair {index}: qpc_after is before qpc_before")
        if pair.edge and pair.step_100ns is None:
            return Unalignable(f"pair {index}: an edge pair without the clock step it saw")
        typed.append(pair)
    if len(typed) < 2:
        return Unalignable(f"{len(typed)} calibration pair(s); at least two are needed for a segment (timestamps.md section 4.5)")
    for earlier, later in zip(typed, typed[1:]):
        if later.qpc_mid <= earlier.qpc_mid:
            return Unalignable(f"pairs {earlier.seq} and {later.seq}: the performance counter did not advance between them")
        if later.filetime_utc_100ns <= earlier.filetime_utc_100ns:
            # The system clock went backwards across a whole interval: a segment with no positive span cannot be fitted.
            return Unalignable(f"pairs {earlier.seq} and {later.seq}: the system time did not advance between them "
                               f"({filetime_to_iso(earlier.filetime_utc_100ns)} then {filetime_to_iso(later.filetime_utc_100ns)}); "
                               f"a backward step larger than the interval cannot be fitted")
    largest = max((p.step_100ns for p in typed if p.edge and p.step_100ns), default=None)
    epoch = typed[0].qpc_before
    model = ClockModel(frequency_hz, epoch, "first_calibration_pair", largest, typed)
    for i, (a, b) in enumerate(zip(typed, typed[1:])):
        increment = 0 if (a.edge and b.edge) else model.fallback_increment_100ns
        model.segments.append(Segment(i, a, b, frequency_hz, epoch, increment))
    return model


def check_join(join_id: str, left: str, right: str, tolerance_100ns: int,
               left_alignment: Alignment | Unaligned | None, right_alignment: Alignment | Unaligned | None) -> dict[str, Any]:
    """Section 5 of the timestamp contract as one record (common.schema.json join).

    The achieved bound is e_left + e_right, never shrunk; the join is refused when either side is
    unaligned or the bound exceeds the tolerance, and the tolerance is reported as given.
    """
    if tolerance_100ns < 0:
        raise ValueError("a tolerance cannot be negative")
    record = {"id": join_id, "left": left, "right": right, "tolerance_100ns": int(tolerance_100ns),
              "achieved_bound_100ns": None, "aligned": False, "reason": None}
    reasons = []
    for side, alignment in (("left", left_alignment), ("right", right_alignment)):
        if alignment is None or not alignment.aligned:
            reasons.append(f"{side} unaligned: {getattr(alignment, 'reason', 'no alignment')}")
    if reasons:
        record["reason"] = "refused: " + "; ".join(reasons)
        return record
    achieved = int(left_alignment.error_bound_100ns) + int(right_alignment.error_bound_100ns)
    record["achieved_bound_100ns"] = achieved
    if achieved > tolerance_100ns:
        record["reason"] = (f"refused: the achieved bound {achieved} x 100 ns exceeds the tolerance {int(tolerance_100ns)} x 100 ns; "
                            f"the tolerance is not widened and no looser join is attempted")
        return record
    record["aligned"] = True
    return record


# ---------------------------------------------------------------- bundle access

def load_manifest(bundle: Path) -> dict[str, Any]:
    path = bundle / "manifest.json"
    if not path.is_file():
        raise DecodeError("the bundle has no manifest.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"manifest.json: {exc}") from exc


def source_entry(manifest: dict[str, Any], source_id: str) -> dict[str, Any] | None:
    for entry in manifest["collectors"]:
        if entry["id"] == source_id:
            return entry
    return None


def primary_of(entry: dict[str, Any]) -> str | None:
    primaries = [a["path"] for a in entry["artifacts"] if a["role"] == "primary"]
    return primaries[0] if primaries else None


def read_primary(bundle: Path, entry: dict[str, Any]) -> tuple[str, Path]:
    source = primary_of(entry)
    if source is None:
        raise DecodeError(f"{entry['id']}: the manifest lists no primary artifact")
    root = bundle.resolve()
    target = (bundle / source).resolve()
    if root not in target.parents or ".." in source.split("/") or not source.startswith("raw/"):
        raise DecodeError(f"{source}: not a normalised path inside the bundle")
    if not target.is_file():
        raise DecodeError(f"{source}: listed in the manifest but missing from the bundle")
    return source, target


def read_json_lines(path: Path, source: str) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DecodeError(f"{source}: line {number} is not JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise DecodeError(f"{source}: line {number} is not an object")
        value["line"] = number
        rows.append(value)
    return rows


def load_model(bundle: Path) -> ClockModel | Unalignable:
    """The clock model of a bundle, from its manifest calibration section and the collector's samples file."""
    try:
        manifest = load_manifest(bundle)
    except DecodeError as exc:
        return Unalignable(str(exc))
    calibration = manifest.get("calibration") or {}
    if calibration.get("status") != "observed":
        return Unalignable(f"calibration status is {calibration.get('status')!r}: {manifest_calibration_reason(manifest)}")
    entry = source_entry(manifest, CLOCK_SOURCE)
    if entry is None or entry["status"] != "observed":
        return Unalignable(f"clock_calibration is {entry['status'] if entry else 'absent'}: {manifest_calibration_reason(manifest)}")
    try:
        source, target = read_primary(bundle, entry)
        samples = read_json_lines(target, source)
        check_samples_match(samples, calibration.get("pairs") or [], source)
    except DecodeError as exc:
        return Unalignable(str(exc))
    return fit_pairs(samples, calibration.get("qpc_frequency_hz"))


def manifest_calibration_reason(manifest: dict[str, Any]) -> str:
    entry = source_entry(manifest, CLOCK_SOURCE)
    if entry is None:
        return "the bundle has no clock_calibration collector"
    return entry.get("status_reason") or entry.get("status") or "unknown"


def check_samples_match(samples: list[dict[str, Any]], pairs: list[dict[str, Any]], source: str) -> None:
    """The samples file is the primary; the manifest's pairs must be exactly its pairs."""
    keys = ("seq", "phase", "qpc_before", "qpc_after", "filetime_utc_100ns")
    if len(samples) != len(pairs):
        raise DecodeError(f"{source}: {len(samples)} pairs in the samples file, {len(pairs)} in the manifest calibration section")
    for number, (sample, pair) in enumerate(zip(samples, pairs), start=1):
        for key in keys:
            if key not in sample:
                raise DecodeError(f"{source}: line {number} lacks {key}")
            if sample[key] != pair.get(key):
                raise DecodeError(f"{source}: line {number} {key} {sample[key]!r} differs from the manifest pair {pair.get(key)!r}")
        if "edge" not in sample:
            raise DecodeError(f"{source}: line {number} lacks edge")


# ---------------------------------------------------------------- tables

def pair_rows(model: ClockModel, source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    for pair in model.pairs:
        rows.append({
            "seq": pair.seq, "phase": pair.phase, "qpc_before": pair.qpc_before, "qpc_after": pair.qpc_after,
            "filetime_utc_100ns": pair.filetime_utc_100ns, "filetime_utc": filetime_to_iso(pair.filetime_utc_100ns),
            "qpc_mid": pair.qpc_mid, "bracket_ticks": pair.qpc_after - pair.qpc_before,
            "half_width_100ns": half_width_100ns(pair.qpc_before, pair.qpc_after, model.frequency_hz),
            "edge": pair.edge, "system_time_step_100ns": pair.step_100ns if pair.edge else None,
            "provenance": {"source_file": source, "row_id_or_offset": f"line:{pair.line}", "decoded_table": "clock_pairs",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


def segment_rows(model: ClockModel, source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    for segment in model.segments:
        rate = float(segment.rate)
        anchor_master = segment.anchor_master_100ns
        offset = anchor_master - segment.rate * segment.a.filetime_utc_100ns
        ambiguous = segment.ambiguous_range
        rows.append({
            "segment": segment.index, "seq_from": segment.a.seq, "seq_to": segment.b.seq,
            "phase_from": segment.a.phase, "phase_to": segment.b.phase,
            "qpc_from": segment.a.qpc_mid, "qpc_to": segment.b.qpc_mid,
            "filetime_from_100ns": segment.a.filetime_utc_100ns, "filetime_to_100ns": segment.b.filetime_utc_100ns,
            "span_100ns": segment.span_100ns, "qpc_span_ticks": segment.qpc_span_ticks, "qpc_span_100ns": segment.qpc_span_100ns,
            "qpc_frequency_hz": model.frequency_hz, "epoch_qpc": model.epoch_qpc, "epoch_source": model.epoch_source,
            "rate_ticks_per_100ns": float(segment.rate_ticks_per_100ns), "nominal_rate_ticks_per_100ns": float(segment.nominal_rate),
            "rate_deviation_ppm": segment.deviation_ppm, "quantisation_limit_ppm": segment.quantisation_limit_ppm,
            "clock_step": segment.clock_step, "step_kind": segment.step_kind,
            "ambiguous_from_100ns": ambiguous[0] if ambiguous else None, "ambiguous_to_100ns": ambiguous[1] if ambiguous else None,
            "anchor_filetime_100ns": segment.a.filetime_utc_100ns, "anchor_master_100ns": anchor_master,
            "rate": rate, "offset_100ns": int(round(offset)),
            "half_width_max_100ns": segment.half_width_max_100ns, "system_time_increment_100ns": segment.increment_100ns,
            "residual_max_100ns": segment.residual_max_100ns, "error_bound_100ns": segment.error_bound_100ns,
            "provenance": {"source_file": source, "row_id_or_offset": f"line:{segment.a.line}-{segment.b.line}", "decoded_table": "clock_segments",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


def mark_rows(marks: list[dict[str, Any]], frequency_hz: int, source: str, schema_version: str) -> list[dict[str, Any]]:
    rows = []
    for index, mark in enumerate(marks):
        missing = [k for k in ("label", "qpc_before", "qpc_after", "filetime_utc_100ns", "at_utc", "process_id") if k not in mark]
        if missing:
            raise DecodeError(f"{source}: line {mark['line']} lacks {', '.join(missing)}")
        before, after = int(mark["qpc_before"]), int(mark["qpc_after"])
        rows.append({
            "mark_index": index, "label": str(mark["label"]), "qpc_before": before, "qpc_after": after,
            "filetime_utc_100ns": int(mark["filetime_utc_100ns"]), "at_utc": str(mark["at_utc"]),
            "qpc_mid": qpc_mid(before, after), "bracket_ticks": after - before,
            "half_width_100ns": half_width_100ns(before, after, frequency_hz), "process_id": int(mark["process_id"]),
            "provenance": {"source_file": source, "row_id_or_offset": f"line:{mark['line']}", "decoded_table": "operator_marks",
                           "decoder_version": DECODER_VERSION, "schema_version": schema_version},
        })
    return rows


def remove_table(bundle: Path, table: str) -> None:
    """This decoder's earlier outputs for a table it does not write on this run (bundle.md section 1: a rerun replaces its own outputs)."""
    for suffix in (".jsonl", ".meta.json"):
        path = bundle / "decoded" / f"{table}{suffix}"
        if path.is_file():
            path.unlink()


def write_table(bundle: Path, table: str, rows: list[dict[str, Any]], sources: list[str], time_domain: str,
                native_range: dict[str, Any] | None, checks: list[dict[str, Any]], status: str, reason: str | None, decoded_at: str) -> None:
    decoded_dir = bundle / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)
    wf_schema.write_jsonl(decoded_dir / f"{table}.jsonl", rows)
    meta = {
        "decoded_table": table, "schema_version": wf_schema.table_schema_version(table), "decoder": DECODER, "decoder_version": DECODER_VERSION,
        "tool": TOOL, "source_files": [{"path": s, "sha256": wf_schema.sha256_of(bundle / s)} for s in sources],
        "row_count": len(rows), "time_domain": time_domain, "native_time_range": native_range,
        "status": status, "status_reason": reason, "checks": checks, "decoded_at_utc": decoded_at,
    }
    errors = wf_schema.validate_object(meta, "decoded/table_meta.schema.json")
    if errors:
        raise SystemExit(f"internal error: sidecar fails its schema: {errors}")
    wf_schema.write_json(decoded_dir / f"{table}.meta.json", meta)


def validated(rows: list[dict[str, Any]], table: str) -> list[str]:
    return wf_schema.validate_rows(rows, f"decoded/{table}.schema.json")


def not_written(bundle: Path, tables: tuple[str, ...], status: str, reason: str) -> dict[str, dict[str, Any]]:
    for table in tables:
        remove_table(bundle, table)
    return {table: {"status": status, "reason": reason, "rows": 0, "sources": 0} for table in tables}


def decode_clock_tables(bundle: Path, manifest: dict[str, Any], decoded_at: str) -> dict[str, dict[str, Any]]:
    clock_tables = ("clock_pairs", "clock_segments")
    entry = source_entry(manifest, CLOCK_SOURCE)
    if entry is None or entry["status"] != "observed":
        reason = "no clock_calibration source in the manifest" if entry is None else f"clock_calibration is {entry['status']}: {entry.get('status_reason')}"
        return not_written(bundle, clock_tables, "not_collected", reason)
    model = load_model(bundle)
    if not model.aligned:
        return not_written(bundle, clock_tables, "decode_failed", model.reason)
    source = primary_of(entry)
    calibration = manifest["calibration"]
    native_range = {"start": filetime_to_iso(model.first_filetime), "end": filetime_to_iso(model.last_filetime), "domain": "system_time", "unit": "iso_utc"}
    edge_pairs = sum(1 for p in model.pairs if p.edge)
    checks = [
        {"name": "samples_match_manifest", "ok": True, "detail": f"{len(model.pairs)} pairs, identical in samples.jsonl and manifest.calibration.pairs"},
        {"name": "expected_pairs", "ok": calibration.get("missing_pairs", 0) == 0,
         "detail": f"{len(model.pairs)} of {calibration.get('expected_pairs')} expected pairs; {calibration.get('missing_pairs')} missing"},
        {"name": "phases", "ok": model.pairs[0].phase == "start" and model.pairs[-1].phase == "stop",
         "detail": f"first {model.pairs[0].phase}, last {model.pairs[-1].phase}"
                   + ("" if model.pairs[-1].phase == "stop" else "; the stop pair is missing, so file times after the last pair are unaligned")},
        {"name": "edge_pairs", "ok": edge_pairs == len(model.pairs),
         "detail": f"{edge_pairs} of {len(model.pairs)} pairs taken at a change of the system clock"
                   + (f"; largest clock step seen {model.largest_step_100ns} x 100 ns" if model.largest_step_100ns else "; no clock step seen")
                   + ("" if edge_pairs == len(model.pairs) else f"; the other pairs carry an increment term of {model.fallback_increment_100ns} x 100 ns")},
    ]
    results = {}
    rows = pair_rows(model, source, wf_schema.table_schema_version("clock_pairs"))
    errors = validated(rows, "clock_pairs")
    status, reason = ("observed", None) if not errors else ("decode_failed", "; ".join(errors[:3]))
    write_table(bundle, "clock_pairs", rows if not errors else [], [source], "system_time", native_range,
                checks + [{"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None}], status, reason, decoded_at)
    results["clock_pairs"] = {"status": status, "reason": reason, "rows": len(rows) if not errors else 0, "sources": 1}

    seg_rows = segment_rows(model, source, wf_schema.table_schema_version("clock_segments"))
    errors = validated(seg_rows, "clock_segments")
    steps = [s for s in model.segments if s.clock_step]
    quantised = [s for s in model.segments if s.quantisation_limit_ppm > CLOCK_STEP_PPM]
    seg_checks = checks + [
        {"name": "clock_steps", "ok": not steps,
         "detail": (f"{len(steps)} segment(s) more than {CLOCK_STEP_PPM:.0f} ppm off nominal beyond what their pairs can explain: "
                    + ", ".join(f"segment {s.index} ({s.deviation_ppm:.0f} ppm, {s.step_kind})" for s in steps)
                    if steps else f"no segment more than {CLOCK_STEP_PPM:.0f} ppm off nominal beyond what its pairs can explain; "
                                  f"largest deviation {max(s.deviation_ppm for s in model.segments):.1f} ppm")},
        {"name": "quantisation_below_step_rule", "ok": not quantised,
         "detail": (f"{len(quantised)} segment(s) where the pairs' own uncertainty (increment term and half widths) can exceed "
                    f"{CLOCK_STEP_PPM:.0f} ppm, so a clock step smaller than that allowance is not detected there"
                    if quantised else "the pairs' own uncertainty explains less than the step threshold on every segment")},
        {"name": "master_epoch", "ok": True, "detail": f"epoch_qpc {model.epoch_qpc} from {model.epoch_source}"},
        {"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None},
    ]
    status, reason = ("observed", None) if not errors else ("decode_failed", "; ".join(errors[:3]))
    write_table(bundle, "clock_segments", seg_rows if not errors else [], [source], "system_time", native_range, seg_checks, status, reason, decoded_at)
    results["clock_segments"] = {"status": status, "reason": reason, "rows": len(seg_rows) if not errors else 0, "sources": 1}
    return results


def decode_marks_table(bundle: Path, manifest: dict[str, Any], decoded_at: str) -> dict[str, Any]:
    entry = source_entry(manifest, MARKS_SOURCE)
    if entry is None or entry["status"] not in OBSERVED:
        reason = "no operator_marks source in the manifest" if entry is None else f"operator_marks is {entry['status']}: {entry.get('status_reason')}"
        return not_written(bundle, ("operator_marks",), "not_collected", reason)["operator_marks"]
    frequency = (manifest.get("calibration") or {}).get("qpc_frequency_hz") or (manifest.get("machine") or {}).get("cpu", {}).get("qpc_frequency_hz")
    try:
        if not frequency:
            raise DecodeError("qpc_frequency_hz is unknown, so a mark's half width cannot be expressed in 100 ns")
        source, target = read_primary(bundle, entry)
        rows = mark_rows(read_json_lines(target, source), int(frequency), source, wf_schema.table_schema_version("operator_marks"))
    except DecodeError as exc:
        return not_written(bundle, ("operator_marks",), "decode_failed", str(exc))["operator_marks"]
    errors = validated(rows, "operator_marks")
    if errors:
        status, reason, rows = "decode_failed", "; ".join(errors[:3]), []
    elif rows:
        status, reason = "observed", None
    else:
        status, reason = "observed_zero", "the marks file is empty: no mark was dropped during the session"
    native_range = None
    if rows:
        stamps = sorted(r["at_utc"] for r in rows)
        native_range = {"start": stamps[0], "end": stamps[-1], "domain": "etw_qpc", "unit": "iso_utc_of_the_mark_process"}
    closed = bool(((entry.get("enabled") or {}).get("options") or {}).get("closed"))
    checks = [{"name": "rows_validate", "ok": not errors, "detail": "; ".join(errors[:3]) or None},
              {"name": "marks_closed", "ok": closed,
               "detail": "the collector renamed the live file when the session ended" if closed else "the live file was not closed"}]
    write_table(bundle, "operator_marks", rows, [source], "etw_qpc", native_range, checks, status, reason, decoded_at)
    return {"status": status, "reason": reason, "rows": len(rows), "sources": 1}


def decode(bundle: Path, decoded_at: str | None = None) -> dict[str, dict[str, Any]]:
    decoded_at = decoded_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        manifest = load_manifest(bundle)
    except DecodeError as exc:
        if bundle.is_dir():
            return not_written(bundle, TABLES, "decode_failed", str(exc))
        failed = {"status": "decode_failed", "reason": str(exc), "rows": 0, "sources": 0}
        return {table: dict(failed) for table in TABLES}
    results = decode_clock_tables(bundle, manifest, decoded_at)
    results["operator_marks"] = decode_marks_table(bundle, manifest, decoded_at)
    return results


# ---------------------------------------------------------------- command line

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--decoded-at", default=None)
    ap.add_argument("--align", action="append", default=[], metavar="ISO_UTC",
                    help="a system_time stamp to place on the master clock through the fitted model; repeatable")
    ap.add_argument("--source-resolution-100ns", type=int, default=0, help="the source's own resolution added to each --align bound")
    ap.add_argument("--tolerance-100ns", type=int, default=None,
                    help="with --align: also report whether a join between the stamp and an etw_qpc source (one tick bound) would be accepted")
    args = ap.parse_args(argv)
    results = decode(args.bundle, args.decoded_at)
    worst = 0
    for table in TABLES:
        result = results[table]
        print(f"{table}: {result['rows']} rows from {result['sources']} sources, status {result['status']}")
        if result["status"] not in OBSERVED:
            print(f"decode status: {table}: {result['status']}: {result['reason']}", file=sys.stderr)
            if result["status"] != "not_collected" or table != "operator_marks":
                worst = max(worst, 2)
    model = load_model(args.bundle)
    if model.aligned:
        edge_pairs = sum(1 for p in model.pairs if p.edge)
        print(f"master clock: epoch_qpc {model.epoch_qpc} ({model.epoch_source}), {model.frequency_hz} Hz, "
              f"{len(model.segments)} segments, {model.clock_step_segments} clock step segment(s), "
              f"{edge_pairs} of {len(model.pairs)} pairs at a clock edge, largest clock step seen "
              f"{model.largest_step_100ns if model.largest_step_100ns else 'none'}")
    else:
        print(f"master clock: unalignable: {model.reason}")
    for text in args.align:
        try:
            filetime = iso_to_filetime(text)
        except ValueError as exc:
            print(f"align {text}: {exc}", file=sys.stderr)
            worst = max(worst, 2)
            continue
        alignment = model.align(filetime, args.source_resolution_100ns)
        if alignment.aligned:
            print(f"align {text}: t_master_100ns {alignment.t_master_100ns}, bound {alignment.error_bound_100ns} x 100 ns"
                  f"{' (clock step segment)' if alignment.clock_step else ''}")
        else:
            print(f"align {text}: unaligned: {alignment.reason}")
        if args.tolerance_100ns is not None and model.aligned:
            qpc_side = model.align_qpc(model.epoch_qpc)
            join = check_join("stamp_to_qpc_source", "system_time_source", "etw_qpc_source", args.tolerance_100ns, alignment, qpc_side)
            print(f"  join at tolerance {args.tolerance_100ns}: {'accepted' if join['aligned'] else join['reason']}"
                  + (f" (achieved {join['achieved_bound_100ns']})" if join["achieved_bound_100ns"] is not None else ""))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
