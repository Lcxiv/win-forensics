# Clock calibration and operator marks

Status: version 1.0.0. Serves [docs/contracts/timestamps.md](contracts/timestamps.md) sections 3 and 4; the collector is `collectors/windows/clock-calibration.ps1`, the Mac side fit is `scripts/decode_clock.py`, and the tables are sections 5.17 to 5.19 of [docs/contracts/decoded-tables.md](contracts/decoded-tables.md).

## 1. What this piece is for

Every instrument in a bundle stamps time with its own clock: the kernel trace and PresentMon with the performance counter, counters and event logs with the system clock. The timestamp contract makes the performance counter (QPC) the master clock and asks for calibration pairs, readings of both clocks taken together, so that a system time stamp can be placed on the master clock with a known error bound. Nothing produced those pairs until now. This piece records them for a bounded session, fits the contract's model on the Mac, and refuses any join that the calibration cannot support.

It also gives the person at the PC a way to say "I felt it here" without touching the game: a mark command run in a second console that stamps the moment with the performance counter and appends it to the session's marks file. A mark sits on the master clock on its own, because it carries the same counter the kernel trace stamps events with.

## 2. What the collector records

`clock-calibration.ps1 -OutputDirectory <dir> [-DurationSeconds 120] [-IntervalSeconds 5]` runs one bounded session and writes a bundle with two sources.

`clock_calibration` takes a triple in one thread, in the order the contract fixes: a performance counter reading, the system time as a Windows file time, and a second counter reading. It does so at the start, once per interval strictly inside the session, and at the stop. Each triple is one line of `raw/clock_calibration/samples.jsonl` (the primary artifact) and one element of `calibration.pairs` in the manifest; the two must agree, and the decoder checks that they do. `session.json` records the parameters, the frequency, the APIs used with their citations and the method; `result.json` records the pairs taken, any slot missed, and the system clock increment measured before the start pair and after the stop pair.

`operator_marks` is the marks file. The session creates `raw/operator_marks/marks.open.jsonl` empty before the start pair and renames it to `marks.jsonl` right after the stop pair, so a mark can only land inside the session and a late mark is refused by construction. Each line is a mark: label, counter bracket, file time, process id of the mark command.

The manifest's `calibration` section carries the clock source's own status, the frequency, the expected and missing pair counts, the pairs, and `time_adjustment` set to null (see section 4). `scenario.marks` lists the marks with their label, UTC time and counter value, and `scenario.requested_duration_s` is the session length.

## 3. How the clocks are read from Windows PowerShell 5.1

Nothing is installed and nothing is compiled. The collector uses what the .NET Framework exposes to Windows PowerShell 5.1:

| Reading | Call | What Microsoft documents |
|---|---|---|
| Performance counter | `[System.Diagnostics.Stopwatch]::GetTimestamp()` | "For managed code, the System.Diagnostics.Stopwatch class uses QPC as its precise time basis" and its `Frequency` field and `GetTimestamp` method "can be used in place of the unmanaged Windows APIs QueryPerformanceFrequency and QueryPerformanceCounter" ([Acquiring high-resolution time stamps](https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps), [Stopwatch](https://learn.microsoft.com/dotnet/api/system.diagnostics.stopwatch)) |
| Counter frequency | `[System.Diagnostics.Stopwatch]::Frequency` | Same pages; the frequency "is fixed at system boot and is consistent across all processors" ([QueryPerformanceFrequency](https://learn.microsoft.com/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency)) |
| Is it the high resolution counter | `[System.Diagnostics.Stopwatch]::IsHighResolution` | True when the timer "is based on a high-resolution performance counter" ([IsHighResolution](https://learn.microsoft.com/dotnet/api/system.diagnostics.stopwatch.ishighresolution)); the collector refuses the session when it is false, because its counter values would then not be the counter ETW uses |
| System time | `[DateTime]::UtcNow.ToFileTimeUtc()` | A Windows file time, "the number of 100-nanosecond intervals that have elapsed since 12:00 midnight, January 1, 1601 A.D. (C.E.) Coordinated Universal Time" ([ToFileTimeUtc](https://learn.microsoft.com/dotnet/api/system.datetime.tofiletimeutc)); the resolution of `UtcNow` "depends on the system timer, which depends on the underlying operating system. It tends to be between 0.5 and 15 milliseconds" ([DateTime.UtcNow](https://learn.microsoft.com/dotnet/api/system.datetime.utcnow)) |
| Boot time, time zone | `Win32_OperatingSystem.LastBootUpTime`, `[System.TimeZoneInfo]::Local` | Already read by the shared helper for every bundle |

The counter the mark command reads in its own process is the same counter: Microsoft states that "the performance counter results are consistent across all processors in multi-core and multi-processor systems, even when measured on different threads or processes", with a one tick ordering ambiguity between threads, and the WNODE_HEADER page states that an ETW event's QPC time stamp "is equivalent to the value returned from the QueryPerformanceCounter API". Both citations are in the contract.

## 4. The deviation from the contract's named APIs, and why

The contract names `GetSystemTimePreciseAsFileTime` for the system time reading and `GetSystemTimeAdjustment` for the adjustment record. Both are Win32 functions with no .NET Framework wrapper; calling them from Windows PowerShell 5.1 means compiling a P/Invoke declaration with `Add-Type`, which `tests/test_collectors_static.py` forbids in every collector (it runs text as code, and the compiler writes temporary files outside the output directory, which a collector never does). The decision (recorded in the PR that added this piece) is to keep that rule, so:

- The system time is `[DateTime]::UtcNow`, which the .NET Framework reads with `GetSystemTimeAsFileTime`. Its value advances once per clock interrupt. The collector measures that increment at run time, before the start pair and after the stop pair, by reading the clock in a bounded loop until it changes a few times and keeping the smallest positive step; the measurements are in `result.json` and `enabled.options`, and the fit adds the larger of the two to every pair's error bound. Under a game that requests a 1 ms timer the increment is 1 ms; on an idle desktop it is 15.625 ms, and the bounds say so.
- `time_adjustment` is null in the manifest, with the reason in `enabled.options.time_adjustment`. The adjustment record was diagnostic only: a system time step shows up in the fit as a segment whose rate is far from nominal, and the fit flags it (section 5).

The contract's text has been amended where it named these APIs so that the contract and the collector agree. Calling the precise API through a fixed, reviewable P/Invoke block remains a possible follow-up; it must first answer the two costs above.

## 5. The fit on the Mac

`python scripts/decode_clock.py --bundle <bundle>` writes three tables and prints the model.

- `clock_pairs`: one row per pair, verbatim values plus the pair's half width: `ceil((bracket / 2 + 1 tick) * 10^7 / frequency)` in 100 ns units, the contract's bracket uncertainty.
- `clock_segments`: one row per pair of consecutive pairs, the contract's piecewise model for `system_time` sources. The rate is the counter span over the file time span; `rate_deviation_ppm` compares it with the nominal `frequency / 10^7`; a deviation above 1000 ppm marks the segment `clock_step` and its bound becomes the whole span. Otherwise the bound is the larger half width of the two pairs, plus the measured system clock increment, plus the largest interior residual (zero between consecutive pairs). A source adds its own resolution (1 ms for a PDH CSV, 100 ns for an event log record) to get its `e_S`. The master epoch is the first pair's counter value unless `--epoch-qpc` supplies the trace header's.
- `operator_marks`: one row per mark with its counter midpoint and half width; the table's domain is `etw_qpc`.

The same module is the library a later correlator calls: `load_model(bundle)` returns the model or the reason there is none; `model.align(filetime, source_resolution)` returns master time with its bound or says the stamp is outside every pair (never extrapolated); `model.align_qpc(qpc)` and `model.align_mark(before, after)` place counter values; `check_join(id, left, right, tolerance, left_alignment, right_alignment)` applies section 5 of the contract and returns the record the verdict's `joins` list wants. A join is refused when either side is unaligned or `e_left + e_right` exceeds the tolerance; the tolerance is never widened and the bound is never rounded down.

Two things the sidecar says that a reader should check before trusting a segment: `quantisation_limit_ppm` is how far off nominal the system clock's increment alone can push a segment's rate (two increments over the span); when that is above 1000 ppm, as on an idle desktop with 5 s segments, a flagged clock step may be quantisation, and the only honest answer is wider bounds. And `expected_pairs` shows how many slots were missed; a missed slot makes the segment around it twice as long and its bound no wider (section 4.5 of the contract).

A calibration whose source is not `observed` (fewer than two pairs, a counter read that failed, a managed timer that is not the high resolution counter) is never fitted; the tables are `not_collected` and every alignment through it is refused with that reason. Operator marks do not depend on the calibration and are decoded whenever their source is readable.

## 6. Dropping a mark at the PC

While the session runs, in a second console on the PC:

```
powershell.exe -NoProfile -NonInteractive -File <install directory>\clock-calibration.ps1 -OutputDirectory <the session directory> -Mark "felt a stutter"
```

The command prints one JSON line with the counter value and UTC time it recorded and exits 0, or prints the reason and exits 1: no session is accepting marks in that directory, the session has finished, the label is empty, longer than 80 characters or holds a control character, or the marks file would exceed its cap. It reads the two clocks, appends one line to the live marks file and exits; it opens, inspects, signals or changes no other process, and in particular never the game or its anti-cheat (the captain plays under Easy Anti-Cheat; the mark is a file append in a separate console). The time between the felt moment and the keypress is the person's reaction time, which nobody measures; a mark says "around here", with the counter bracket as its only instrument uncertainty.

Run by hand at the PC, the session directory is wherever the person pointed `-OutputDirectory`. Through the SSH front door the dispatcher creates the directory under its outbox as the collector account; whether the person's own account may append to a file there is on the verification list below, and until it is settled the by hand run is the way to use marks.

## 7. Limits

- The collector proves nothing about the ETW session clock. A kernel trace captured by another collector must use the QPC clock type (the default) for its stamps to live on this master clock; that collector's documentation says how it verifies that.
- With the coarse system timer every pair carries about 16 ms of uncertainty, and the clock step rule cannot be told from quantisation on 5 s segments; sub frame joins between a `system_time` source and the kernel trace are refused then, which is the right answer. Joins between two counter stamped sources (trace, PresentMon, marks) do not need the calibration at all.
- Drift is measured per segment, not modelled across the session; the contract's model is piecewise and this piece follows it. The sidecar reports the largest deviation so a reader can see a steady drift.
- Nothing here has run on Windows. The facts the collector relies on are on the verification list in `collectors/windows/README.md`.
