# Timestamp contract

Status: phase 0a, version 1.2.0 (1.1.0 with the `presentmon` row in section 2 now describing the CSV printed from a Windows Performance Recorder recording read on the PC with `--etl_file --output_stdout --qpc_time` plus the collector's recording record, and with the `CPUStartTime` correction to 1.0.0 stated in that row; 1.1.0 was 1.0.0 plus, in sections 2, 3 and 4.3, how the `clock` collector reads the system time from Windows PowerShell 5.1 and the clock calibration exception: the cadence count, the status of a calibration with missing pairs, and the bound of a segment that holds a backward clock step. Each is a narrow rule for the clock calibration source, named as such where it stands, decided for the PR that added the collector; no general rule changed). Applies to every collector, decoder, analyzer, and playbook in this repository. Companion contracts: [decoded-tables.md](decoded-tables.md), [measurement-status.md](measurement-status.md), [bundle.md](bundle.md).

## 1. Why one clock story is not enough

The instruments in a bundle do not share a clock. Event Tracing for Windows stamps kernel events with the performance counter. Performance counter logs stamp samples with the system wall clock in local time. PresentMon derives frame times from the same performance counter as ETW but writes them as performance counter values only when told to. Event log records carry a FILETIME in UTC. Process Monitor writes a time of day per operation. CapFrameX writes times relative to its capture start. Any join between two of these sources is a claim that two clocks agree to within some bound, and that bound has to be measured, not assumed.

This contract therefore does four things. It names the clock domain of every source and the native timestamp that must be preserved. It defines the calibration pairs that every capture records so that the domains can be related. It defines the per source affine model with an error bound that the correlator uses. And it defines how a playbook declares the alignment uncertainty it tolerates, and what happens when a join cannot meet it.

## 2. Clock domains by source

Each row states the native timestamp the decoder must keep verbatim, the domain that timestamp lives in, its resolution, and whether it moves when the system clock is adjusted. Sources are identified by the collector ids used in the manifest (see [bundle.md](bundle.md)).

| Collector id | Raw artifact | Native timestamp kept in the decoded table | Domain | Resolution and epoch | Moves with system clock adjustments |
|---|---|---|---|---|---|
| `wpr` (also `xperf` captures) | `.etl` | Event timestamp as stored by the session: performance counter ticks when the session clock type is QPC, which is the default | `etw_qpc` | One tick of `QueryPerformanceFrequency`; consumers convert with `ticks * 10000000 / PerfFreq` to 100 ns units. Epoch is system boot. | No. QPC time stamps keep counting as if no adjustment happened. |
| `dpcisr` (decode of `wpr`) | `xperf -a dpcisr` text | Microseconds and milliseconds relative to the start of the trace, as printed in the report (for example the range header and the interval rows) | `etw_qpc_relative` | 1 us for ranges, 1 ms for interval rows, epoch is the trace start | No |
| `tracestats` (decode of `wpr`) | `xperf -a tracestats` text | Session start and end as printed, in the time zone selected by `-timezone` (the decoder always requests `utc`) | `system_time` | As printed by the tool | Yes, these are wall clock values |
| `pdh` | PDH CSV from `Get-Counter` or `typeperf` | The first column of each row, a local wall clock string, plus the time zone name and bias in minutes from the CSV header `(PDH-CSV 4.0) (<zone>)(<bias>)` | `system_time` | 1 ms as written in the CSV. `Get-Counter` exposes the same sample time as `Timestamp100NSec`, a FILETIME. Epoch is 1601-01-01 UTC. | Yes |
| `presentmon` | The PresentMon console CSV printed with `--etl_file --output_stdout --qpc_time` from an ETW recording made by Windows Performance Recorder on the PC, and the collector's record of that recording's log file header (`recording.json`; the recording itself is deleted on the PC) | `CPUStartQPC`, the frame's timestamp in the recording's own clock, which the log file header names (`ReservedFlags`: 1 is the performance counter, the default; 2 is system time) and the collector copies into `recording.json` and the manifest. Collectors must pass `--qpc_time`; the decoder refuses a CSV with another start column. Correction to 1.0.0: PresentMon writes `CPUStartTime` only under `--v2_metrics`, and in milliseconds, not seconds; the table no longer carries a `relative_monotonic` reading of it. | `etw_qpc` when the recording's clock is the performance counter; `system_time` when it is system time | One tick of the recording's clock (`PerfFreq` in its header); the per frame `Ms*` columns are differences in milliseconds | No for the performance counter clock |
| `capframex` | CapFrameX capture JSON | Frame rows relative to the capture start; sensor rows on their own cadence. CapFrameX documents no time base for its JSON. | `relative_monotonic` | Unknown until a phase 0b fixture is decoded | Unknown |
| `eventlog` | JSON export from `Get-WinEvent` | `TimeCreated` converted by the collector to ISO 8601 UTC with seven fractional digits, taken from the record's `SystemTime` | `system_time` | 100 ns (FILETIME) | Yes |
| `procmon` | `.pml` (authoritative) and CSV export | `Time of Day` as exported, a local wall clock string of the form `h:mm:ss.fffffff AM` or `PM` with no date; `Date & Time` carries the date at 1 s resolution when selected; the `.pml` holds a FILETIME per event (settled in [procmon-facts.md](procmon-facts.md)) | `system_time` | 100 ns in both the CSV `Time of Day` column and the `.pml` FILETIME | Yes |
| `powercfg`, `config_snapshot`, `process_inventory`, `cdb` | Text and JSON snapshots | A single `captured_at_utc` per snapshot, written by the collector from `GetSystemTimePreciseAsFileTime` (or the PowerShell equivalent `[DateTime]::UtcNow` when precision is not needed) | `system_time` | 100 ns | Yes |
| `clock` | Calibration pairs in the manifest and in `raw/clock_calibration/samples.jsonl` | `qpc_before`, `qpc_after`, `filetime_utc_100ns` per pair, with `edge` and `step_100ns` in the samples file | Both `etw_qpc` and `system_time` | See section 3; the file time is read at the instant the system clock changes value, so the pair's resolution is its counter bracket, and the clock's increment is recorded with the pair | Both, by construction |
| `marks` (operator marks, written by the `clock` collector) | `raw/operator_marks/marks.jsonl` | `qpc_before`, `qpc_after`, `filetime_utc_100ns` per mark, taken in the mark process | `etw_qpc` | One tick plus half the bracket; the person's reaction time is not measured | No |

Sources of these facts: Microsoft Learn, WNODE_HEADER `ClientContext` (default clock type is QPC; QPC time stamps do not reflect system clock updates; conversion formula); Acquiring high resolution time stamps (QPC is a difference clock, not synchronized to UTC; values from different threads that differ by one tick have ambiguous order; `GetSystemTimePreciseAsFileTime` for UTC synchronized stamps); File Times (FILETIME definition); TimeCreated element (`SystemTime` attribute); Get-Counter (`Timestamp` and `Timestamp100NSec` sample properties); PresentMon console README (`--qpc_time`, `CPUStartQPC`). Process Monitor's export format is settled by the committed runner fixtures rather than by documentation.

Rules that follow from the table:

1. Decoders never convert a native timestamp in place. The decoded table keeps the native value in its native column and adds derived columns beside it (for example `time_utc` beside `time_of_day`). A derived value that cannot be computed is null, never an estimate.
2. A source in the `system_time` domain must be captured together with its time zone and bias. The PDH CSV header carries them; every other collector records the machine's zone in the manifest (`machine.time_zone`).
3. A source in the `relative_monotonic` domain is unanchored until the collector records the master clock reading at the instant its relative zero was taken. PresentMon avoids the problem with `--qpc_time`. CapFrameX cannot be anchored better than the collector's own start record, so joins to it are limited to the bound of that record (section 4.4).

## 3. Calibration pairs

The `clock` collector is part of the always on set and is the only source of truth for relating `system_time` to `etw_qpc`.

Procedure, executed on the capture machine in one thread without affinity changes:

1. Read `QueryPerformanceCounter` into `qpc_before`.
2. Read the system time as a file time into `filetime_utc_100ns`. The precise form is `GetSystemTimePreciseAsFileTime`. The `clock` collector in this repository runs under Windows PowerShell 5.1, where that function is reachable only by compiling a P/Invoke declaration, which the collector rules forbid; it reads `[DateTime]::UtcNow.ToFileTimeUtc()` instead, the coarse system time, whose resolution Microsoft documents as "depends on the system timer, which depends on the underlying operating system. It tends to be between 0.5 and 15 milliseconds" ([DateTime.UtcNow](https://learn.microsoft.com/dotnet/api/system.datetime.utcnow)). To keep the pair's uncertainty at its counter bracket, the collector reads that clock in a bounded loop until it changes value and keeps the counter read before the last unchanged reading as `qpc_before` and the one after the changed reading as `qpc_after`: the instant the clock took its new value lies inside the bracket, and the size of the change (the clock's increment at that moment) is recorded with the pair as `step_100ns`, with `edge` true. A pair for which the clock did not change within the loop's budget is recorded as read, with `edge` false, and the fit adds an increment term to its bounds (section 4.3).
3. Read `QueryPerformanceCounter` into `qpc_after`.
4. Record the triple, the sequence number, the phase (`start`, `interval`, or `stop`), and the `QueryPerformanceFrequency` value once per capture. From managed code the counter and its frequency are `System.Diagnostics.Stopwatch.GetTimestamp` and `Stopwatch.Frequency`, which Microsoft documents as usable "in place of the unmanaged Windows APIs QueryPerformanceFrequency and QueryPerformanceCounter"; `Stopwatch.IsHighResolution` must be true, else the readings are not the counter ETW uses and the calibration is `unsupported`.

Cadence: one pair immediately before the first collector starts (`start`), one pair every 5 s during the capture (`interval`), and one pair immediately after the last collector stops (`stop`). A capture of duration `D` seconds is expected to hold `floor(D / 5) + 2` pairs. Missing pairs are recorded in the manifest as a count and the calibration status becomes `degraded`; fewer than two pairs make the calibration `capture_failed` and every `system_time` source in the bundle becomes unalignable (section 4.5).

Clock calibration exception (the `clock-calibration` collector, `collectors/windows/clock-calibration.ps1`, which is its own orchestrator and has no other collector to start or stop): its interval slots lie strictly inside the session, so a slot that falls on the stop instant is the stop pair and the expected count is `floor((D - 1) / 5) + 2` (25 for a 120 s session, where the formula above gives 26; the literal count would put an interval pair and the stop pair microseconds apart, and section 4.3 would flag that segment as a clock step on every run). `degraded` is not a value of the status vocabulary ([measurement-status.md](measurement-status.md) section 2): with two or more pairs the calibration's status is `observed`, `missing_pairs` carries the degradation (every expected pair not taken, the stop pair included, whatever stopped the session), the collector's expectation is the full count and `met` is false when any pair is missing, and the bundle's evidentiary adequacy check compares the count with the scenario's tolerance ([bundle.md](bundle.md) section 3). The pairs taken are kept and the fit uses them; file times after the last pair are unaligned (section 4.3). Fewer than two pairs are `capture_failed` and the pair taken is not kept.

The manifest also records, at start and stop, the result of `GetSystemTimeAdjustment` (whether periodic adjustment is enabled and its size) when the collector can call it, the machine time zone and bias, and the boot time. These are diagnostic: a system time step between two pairs shows up as a rate far from one in the affine model, and the adjustment record tells the reader whether the operating system was disciplining the clock at the time. The Windows PowerShell 5.1 collector cannot call `GetSystemTimeAdjustment` for the same reason as above and writes both members of `time_adjustment` as null with the reason in its manifest entry; the step detection in section 4.3 does not depend on it.

Why both QPC reads: the pair's uncertainty is the half width of the bracket, `(qpc_after - qpc_before) / 2`, plus one tick for the ordering ambiguity Microsoft documents for counter values taken from different threads. That half width is the error term a `system_time` source inherits from calibration; a pair that was not read at a change of the coarse system clock (`edge` false) adds the increment term of section 4.3.

## 4. Per source affine clock model

### 4.1 Master clock

The master clock is `etw_qpc`. Master time is expressed as `t_master_100ns`, an integer count of 100 ns units since the master epoch, computed as `(qpc - epoch_qpc) * 10000000 / qpc_frequency_hz` with integer arithmetic and the remainder discarded. The master epoch is the ETW session start counter value from the trace header when the bundle contains a kernel trace. When it does not, the epoch is the `qpc_before` of the first calibration pair. Both are readings of the same counter, so the choice affects only the zero, never the rate.

QPC is chosen as master because it has the finest resolution of the domains in the table, it is unaffected by adjustments to the system clock, and the kernel timeline (DPC, ISR, context switches, presents) already lives in it.

### 4.2 The model

For a source `S` with a native timestamp `t_S`, the correlator computes

```
t_master_100ns = offset_S + rate_S * t_S
```

together with an error bound `e_S` in 100 ns units that applies to every converted timestamp of that source within the segment the model was fitted on. The verdict's coverage table records `offset_S`, `rate_S`, the residual of the fit, `e_S`, and the pairs used (see [measurement-status.md](measurement-status.md), coverage table).

### 4.3 Fitting rules per domain

`etw_qpc` sources (`wpr`, `presentmon` with `CPUStartQPC`): `rate_S` is exactly 1 and `offset_S` is the epoch difference, which is zero when the source and the master share the same counter reading of the epoch. `e_S` is one tick plus the decoder's rounding (100 ns for TraceProcessing and wpaexporter output, 1 us for `xperf` text).

`etw_qpc_relative` sources (`dpcisr` text reports): `rate_S` is 1 and `offset_S` is the master time of the trace start, taken from the trace header through `tracestats` or the decoder. `e_S` is the print resolution of the report (1 us for ranges, 1 ms for interval rows) plus one tick.

`system_time` sources (`pdh`, `eventlog`, `procmon`, snapshots): the model is piecewise linear over consecutive calibration pairs. For a timestamp `t_S` (converted to FILETIME UTC using the recorded zone and bias when the source is local time), find the pairs `P_i` and `P_j` that bracket it. Then `rate_S = (qpc_j - qpc_i) / (ft_j - ft_i)` in ticks per 100 ns and `offset_S` follows from `P_i` (each pair's counter value is the midpoint of its bracket). `e_S` is the larger of the two pairs' half widths, plus the source's own resolution (1 ms for PDH CSV, 100 ns for event log JSON, the exported precision for Process Monitor), plus the largest residual of any interior pair against the segment's line. A segment whose rate differs from the nominal `qpc_frequency_hz / 10000000` by more than 1000 parts per million is marked `clock_step` and its `e_S` is widened to the full span between its pairs; timestamps inside such a segment are effectively unalignable for any sub second tolerance. A timestamp outside every pair is `unaligned` (not extrapolated).

Clock calibration exception, for pairs the `clock-calibration` collector took from the coarse system clock (section 3): when either pair of a segment was not read at a change of that clock (`edge` false), `e_S` also carries an increment term, the larger of the largest clock step the collector recorded in the session and 15.625 ms, the period of the 64 Hz PC real time clock in Microsoft's clock table ([Acquiring high-resolution time stamps](https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps), low level hardware clock characteristics); for two edge pairs the term is zero. The larger of the two is taken because the increment can change during a session, so a smaller step seen at another pair does not bound the one at this pair: Microsoft documents that since Windows 10 version 2004 a process's timer resolution request no longer affects global timer resolution, and that since Windows 11 an occluded or minimised process is not guaranteed a higher resolution than the default ([timeBeginPeriod](https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)). The 1000 parts per million rule applies to the deviation the pairs themselves cannot explain: a segment is marked `clock_step` only when its rate deviation exceeds 1000 parts per million plus `2 * (increment term + larger half width) / (ft_j - ft_i)`, the deviation the two pairs' own uncertainty can produce, so a wide counter bracket is not reported as a step of the system clock; the half width still enters `e_S`. The full span a `clock_step` segment is widened to is the larger of its file time span and its elapsed counter span `(qpc_j - qpc_i) * 10000000 / qpc_frequency_hz`, added to the ordinary terms, so a step never shrinks a bound: a backward step of the system clock makes the file time span shorter than the time that passed. For such a backward step (counter span longer than file time span), the file times the clock may have shown twice, from `ft_i - (counter span - file time span)` to `ft_i + counter span`, widened on both ends by the segment's own uncertainty (the larger half width of its two pairs plus its increment term), are `unaligned` in every other segment they fall into, with the reason naming the step; inside the step segment they carry its widened bound. A backward step longer than the interval (a later pair with an earlier file time) cannot be fitted and makes the calibration unalignable.

`relative_monotonic` sources (`capframex`; a PresentMon CSV without `CPUStartQPC` is refused by its decoder, section 2): `rate_S` is 1 and `offset_S` is the master time of the collector's recorded start instant. `e_S` is the uncertainty of that start record, which is the interval between the collector's own start timestamp and the master reading nearest to it; for a process launched by the orchestrator this is the launch latency and is typically far larger than any frame. A source whose start instant was not recorded is `unaligned`.

### 4.4 Joins

A join between sources `A` and `B` at master time carries the bound `e_A + e_B`. The correlator never subtracts, averages, or otherwise shrinks bounds. When either side is `unaligned`, the join is refused.

### 4.5 Degraded calibration

With fewer than two pairs no segment exists, so no `system_time` source can be aligned; those sources keep their native timestamps and every join involving them is refused. With pairs missing in the middle of a capture, the segments simply get longer and their bounds grow with the residuals; nothing else changes.

## 5. Playbook tolerance and refused joins

Every playbook declares, for each cross source join it performs, the maximum alignment uncertainty it accepts:

```yaml
joins:
  - id: dpc_to_frame
    left: dpcisr
    right: presentmon
    tolerance_100ns: <integer>
    rationale: <why this bound is tight enough for the question asked>
```

The contract fixes the mechanism, not the numbers. A join that compares a DPC to the frame it may have delayed needs a tolerance below the frame interval it is looking at; a join that places an event log record inside a window of seconds can tolerate tens of milliseconds. Each playbook writes its own value and its rationale, and the value is cited in the verdict.

When the correlator evaluates a join it compares `e_A + e_B` with `tolerance_100ns`:

- Within tolerance: the join proceeds and the verdict's `joins` list records the tolerance and the achieved bound.
- Exceeds tolerance: the join is refused. The verdict's `joins` list records `aligned: false`, the tolerance, the achieved bound, and the reason. No evidence row is produced from that join, and the analyzer that needed it reports its measurement status for that window as `not_applicable` with the refusal as the reason. The tolerance is never widened, the bound is never rounded down, and no fallback join with a looser tolerance is attempted unless the playbook itself declares that looser join as a separate entry with its own rationale.

A refused join is therefore visible in the coverage table and in the report, next to the findings, rather than being absorbed into a wider window.

## 6. What decoders and collectors must do

- Collectors: keep native timestamps in raw artifacts untouched; write the machine time zone and bias to the manifest; run PresentMon with `--qpc_time` (over a recording, never live); run `xperf -a tracestats` with `-timezone utc`; export event log records with `TimeCreated` in UTC and seven fractional digits; record the collector's own start and stop instants as calibration style triples so `relative_monotonic` sources can be anchored. The `clock` collector is `collectors/windows/clock-calibration.ps1`; its method, the operator marks and the Mac side fit (`scripts/decode_clock.py`, which writes the `clock_pairs`, `clock_segments` and `operator_marks` tables and is the library a correlator aligns and refuses joins with) are in [docs/clock-calibration.md](../clock-calibration.md).
- Decoders: emit the native column verbatim, the derived UTC column when computable, and the domain name in the table's sidecar metadata; never emit a master time (that is the correlator's job, because it depends on the calibration pairs and must be redone if the pairs are corrected).
- Correlator (later phase): compute the model per source, write it to the coverage table, and apply section 5.

## 7. Open questions

1. CapFrameX time base. The vendor does not document the capture JSON's time base. Decision for phase 0a: treat it as `relative_monotonic` anchored only by the collector start record, which makes it unusable for sub second joins until a phase 0b fixture shows otherwise. Keeping the status separate from any evidence, a CapFrameX table in a bundle contributes no evidence to sub second joins and the coverage table says why.
2. Process Monitor timestamp origin. The `.pml` stores a FILETIME per event; which kernel time source the driver reads is not documented. The decoder treats it as `system_time` with the exported precision as its resolution, and the coverage table carries that as the source's own resolution term. If a phase 0b comparison against ETW file events shows a systematic offset, that offset becomes part of `offset_S` for this source and this contract gets a version bump.
3. Trace start counter value. The decoder for `tracestats` must expose the session start as a counter value for section 4.3 to work for `dpcisr` reports without the `.etl` present. Until a decoder reads it from the trace header, a bundle that holds a `dpcisr` report without its `.etl` or `tracestats` output has an `unaligned` `dpcisr` table, which is how the example bundle in `fixtures/example-bundle` is recorded.
