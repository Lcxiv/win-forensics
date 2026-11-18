# clock-calibration: How does the system clock relate to the performance counter during this session, and when did the person at the PC feel something?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account. Writes
# one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints one JSON
# summary line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md for the interface and docs/clock-calibration.md
# for the method, its limits and the facts still to be verified on a real
# machine. The contract it serves is docs/contracts/timestamps.md section 3.
#
# Two sources:
#   clock_calibration   a bounded session (-DurationSeconds) that records the
#                       calibration triples the timestamp contract asks for:
#                       a performance counter reading, the system time as a
#                       file time, and a second counter reading, at the start,
#                       every -IntervalSeconds, and at the stop. The counter
#                       is read through Stopwatch.GetTimestamp, which Microsoft
#                       documents as QueryPerformanceCounter for managed code,
#                       the frequency through Stopwatch.Frequency, and the
#                       system time through [DateTime]::UtcNow, whose
#                       resolution is the system timer's (0.5 to 15 ms per
#                       Microsoft); the collector measures that increment at
#                       run time and records it, because the precise system
#                       time API (GetSystemTimePreciseAsFileTime) cannot be
#                       called from Windows PowerShell 5.1 without compiling
#                       code, which a collector never does.
#   operator_marks      a file the person at the PC appends to from a second
#                       console while the session runs, by running this same
#                       script with -Mark <label> against the session
#                       directory; each mark carries its own counter bracket,
#                       so it sits on the master clock without calibration.
#                       Nothing here touches any other process.
#
# https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
# https://learn.microsoft.com/dotnet/api/system.diagnostics.stopwatch
# https://learn.microsoft.com/dotnet/api/system.datetime.utcnow
# https://learn.microsoft.com/dotnet/api/system.datetime.tofiletimeutc
# https://learn.microsoft.com/windows/win32/etw/wnode-header (ETW stamps events with the same counter)
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # Session length in seconds (10 to 840; the dispatcher stops a collector
    # after 900).
    [int]$DurationSeconds = 120,
    # Seconds between two calibration pairs (1 to 60). The timestamp contract
    # names 5.
    [int]$IntervalSeconds = 5,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Mark mode: append one counter stamped mark with this label to the marks
    # file of the session running in -OutputDirectory, then exit. Nothing else
    # is read or written.
    [string]$Mark = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'clock-calibration'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $common)) {
    # Without the helper or an output directory there is no bundle to write;
    # the summary line is still printed so the dispatcher gets its one line.
    if (-not $OutputDirectory) { [Console]::Error.WriteLine($collectorName + ': -OutputDirectory is required') }
    else { [Console]::Error.WriteLine($collectorName + ': the shared helper is missing: ' + $common) }
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}
. $common

# The live marks file exists only while a session runs: the session creates
# it empty at its start and renames it to marks.jsonl right after the stop
# pair, so a mark can only land inside the session.
function Get-WfClockMarksLiveName { return 'marks.open.jsonl' }
function Get-WfClockMarksFinalName { return 'marks.jsonl' }
function Get-WfClockMaxLabelLength { return 80 }

function Read-WfClockTriple {
    # One calibration triple, read in this thread in the order the contract
    # fixes: counter, system time, counter. The uncertainty of the pair is
    # the half width of the counter bracket plus one tick (Microsoft: counter
    # values taken from different threads that differ by one tick have an
    # ambiguous order) plus the system clock's increment, which the fit adds.
    $before = Get-WfQpcTimestamp
    $fileTime = Get-WfSystemFileTimeUtc
    $after = Get-WfQpcTimestamp
    return [ordered]@{ qpc_before = [int64]$before; filetime_utc_100ns = [int64]$fileTime; qpc_after = [int64]$after }
}

function ConvertFrom-WfFileTime {
    param([int64]$FileTime)
    return [datetime]::FromFileTimeUtc($FileTime)
}

function Measure-WfSystemTimeIncrement {
    # The step of the system clock as this process sees it: [DateTime]::UtcNow
    # advances once per clock interrupt (Microsoft documents 0.5 to 15 ms
    # depending on the system timer), so the collector reads it in a loop
    # until it changes, several times, and keeps the smallest positive step
    # and how many reads it took. The loop is bounded by -BudgetTicks of the
    # performance counter so a clock that never changes cannot hold the
    # session. Returns null fields when no change was seen inside the budget.
    param([int64]$QpcFrequency, [int]$BudgetMilliseconds = 100, [int]$Changes = 4)
    $budgetTicks = [int64][math]::Ceiling($BudgetMilliseconds * $QpcFrequency / 1000.0)
    $startQpc = Get-WfQpcTimestamp
    $previous = Get-WfSystemFileTimeUtc
    $smallest = $null
    $largest = $null
    $reads = 1
    $seen = 0
    while ($seen -lt $Changes) {
        $current = Get-WfSystemFileTimeUtc
        $reads += 1
        if ($current -ne $previous) {
            $step = $current - $previous
            if ($step -gt 0) {
                if ($null -eq $smallest -or $step -lt $smallest) { $smallest = $step }
                if ($null -eq $largest -or $step -gt $largest) { $largest = $step }
                $seen += 1
            }
            $previous = $current
        }
        if (((Get-WfQpcTimestamp) - $startQpc) -gt $budgetTicks) { break }
    }
    return [ordered]@{
        increment_100ns         = $smallest
        largest_step_100ns      = $largest
        changes_seen            = $seen
        reads                   = $reads
        budget_milliseconds     = $BudgetMilliseconds
        measured                = ($seen -gt 0)
    }
}

function Get-WfClockMarkPattern {
    # The exact shape Write-WfClockMarkLine produces, so a line that was not
    # written by this script (or was cut short) is recognised and the source
    # is marked capture_failed instead of silently losing a mark.
    return '^\{"label":"((?:[^"\\]|\\.)*)","qpc_before":(-?\d+),"filetime_utc_100ns":(\d+),"qpc_after":(-?\d+),"at_utc":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z)","process_id":(\d+)\}$'
}

function ConvertTo-WfClockMarkLine {
    param([string]$Label, $Triple, [int]$ProcessId)
    $record = [ordered]@{
        label              = $Label
        qpc_before         = [int64]$Triple['qpc_before']
        filetime_utc_100ns = [int64]$Triple['filetime_utc_100ns']
        qpc_after          = [int64]$Triple['qpc_after']
        at_utc             = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$Triple['filetime_utc_100ns']))
        process_id         = $ProcessId
    }
    return (ConvertTo-WfJson -Value $record)
}

function ConvertFrom-WfClockMarkLine {
    # Returns the mark as an ordered map, or $null when the line is not a mark.
    param([string]$Line)
    $m = [regex]::Match($Line, (Get-WfClockMarkPattern))
    if (-not $m.Success) { return $null }
    return [ordered]@{
        label              = [regex]::Unescape($m.Groups[1].Value)
        qpc_before         = [int64]$m.Groups[2].Value
        filetime_utc_100ns = [int64]$m.Groups[3].Value
        qpc_after          = [int64]$m.Groups[4].Value
        at_utc             = $m.Groups[5].Value
        process_id         = [int64]$m.Groups[6].Value
    }
}

function Add-WfClockMarkLine {
    # Appends one line to the live marks file. The file must already exist
    # (FileMode Open, never Create), so a mark cannot start a marks file of
    # its own after the session has renamed it. The handle allows other
    # readers and writers, and a collision with another mark process is
    # retried a few times.
    param([string]$Path, [string]$Line, [int64]$MaxBytes)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Line + "`n")
    $attempt = 0
    while ($true) {
        $attempt += 1
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            if (($stream.Length + $bytes.Length) -gt $MaxBytes) { throw ('the marks file would exceed its cap of ' + $MaxBytes + ' bytes') }
            $null = $stream.Seek(0, [System.IO.SeekOrigin]::End)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            return $bytes.Length
        } catch [System.IO.IOException] {
            if ($attempt -ge 5 -or -not (Test-Path -LiteralPath $Path)) { throw }
            Wait-WfMilliseconds -Milliseconds 20
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }
    }
}

function Invoke-WfClockMark {
    # Mark mode. Prints one JSON line and returns the exit code: 0 when the
    # mark was appended, 1 otherwise. The label is kept as typed (JSON
    # escaped), cut at the length limit, and must not be empty.
    param([string]$OutputDirectory, [string]$Label, [int64]$MaxArtifactBytes)
    $label = ([string]$Label).Trim()
    $summary = [ordered]@{ collector = $collectorName; mark = $label; qpc = $null; at_utc = $null; file = $null; error = $null }
    try {
        if ($label.Length -eq 0) { throw 'the mark label is empty' }
        if ($label.Length -gt (Get-WfClockMaxLabelLength)) { throw ('the mark label is longer than ' + (Get-WfClockMaxLabelLength) + ' characters') }
        if ($label -match '[\x00-\x1f]') { throw 'the mark label holds a control character' }
        $root = Resolve-WfBundleRoot -OutputDirectory $OutputDirectory
        $relative = 'raw/operator_marks/' + (Get-WfClockMarksLiveName)
        $live = Join-WfBundlePath -BundleRoot $root -RelativePath $relative
        if (Test-Path -LiteralPath (Join-WfBundlePath -BundleRoot $root -RelativePath 'manifest.json')) {
            throw 'the session in this directory has finished (manifest.json exists); a mark is accepted only while clock-calibration is running'
        }
        if (-not (Test-Path -LiteralPath $live -PathType Leaf)) {
            throw ('no clock-calibration session is accepting marks in this directory (' + $relative + ' does not exist)')
        }
        if (-not (Test-WfQpcHighResolution)) { throw 'the performance counter is not the high resolution counter on this machine, so a mark could not be placed on the master clock' }
        $triple = Read-WfClockTriple
        $line = ConvertTo-WfClockMarkLine -Label $label -Triple $triple -ProcessId (Get-WfProcessId)
        $null = Add-WfClockMarkLine -Path $live -Line $line -MaxBytes $MaxArtifactBytes
        $summary.qpc = [int64][math]::Floor(([double]$triple['qpc_before'] + [double]$triple['qpc_after']) / 2)
        $summary.at_utc = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$triple['filetime_utc_100ns']))
        $summary.file = $relative
        Write-WfStdoutLine -Text (ConvertTo-WfJson -Value $summary)
        return 0
    } catch {
        $summary.error = $_.Exception.Message
        Write-WfStderrLine -Text ($collectorName + ' mark: ' + $_.Exception.Message)
        Write-WfStdoutLine -Text (ConvertTo-WfJson -Value $summary)
        return 1
    }
}

function Invoke-WfClockSessionSource {
    # The custom source: runs the bounded session and returns the two
    # manifest entries (clock_calibration, operator_marks), the manifest
    # calibration section and the operator marks for scenario.marks.
    param($Source, [string]$BundleRoot, [int64]$MaxArtifactBytes, [int]$TimeoutSeconds, [System.Collections.Generic.List[string]]$Log, [System.Collections.Generic.List[string]]$Notes, $MachineInfo)
    $duration = [int]$Source['DurationSeconds']
    $interval = [int]$Source['IntervalSeconds']
    $clockId = 'clock_calibration'
    $marksId = 'operator_marks'
    $clockEntry = New-WfCollectorEntry -Id $clockId -Kind 'clock' -Required $true
    $marksEntry = New-WfCollectorEntry -Id $marksId -Kind 'other' -Required $false
    $clockRoles = @{ 'session.json' = 'config'; 'result.json' = 'report'; 'samples.jsonl' = 'primary' }
    $marksRoles = @{ 'instructions.json' = 'config'; 'result.json' = 'report'; (Get-WfClockMarksFinalName) = 'primary' }
    $clockDir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $clockId)
    $marksDir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId)
    $samplesPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $clockId + '/samples.jsonl')
    $livePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId + '/' + (Get-WfClockMarksLiveName))
    $finalPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId + '/' + (Get-WfClockMarksFinalName))
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $started = Get-WfUtcNow
    $clockEntry.started_utc = ConvertTo-WfUtcString -Value $started
    $marksEntry.started_utc = $clockEntry.started_utc

    $pairs = New-Object 'System.Collections.Generic.List[object]'
    $missedSlots = New-Object 'System.Collections.Generic.List[object]'
    $marks = New-Object 'System.Collections.Generic.List[object]'
    $failure = $null
    $failureKind = $null
    $frequency = $null
    $highResolution = $false
    $incrementStart = $null
    $incrementStop = $null
    $sessionStartQpc = $null
    $sessionStopQpc = $null
    $expectedPairs = 0
    $slots = 0
    $marksFileCreated = $false
    $marksRenamed = $false
    $marksReadError = $null
    $malformed = 0
    $samplesBytes = [int64]0
    $method = ('one thread reads Stopwatch.GetTimestamp (QueryPerformanceCounter), [DateTime]::UtcNow.ToFileTimeUtc() (GetSystemTimeAsFileTime, resolution the system timer increment, measured at run time and recorded in session.json), ' +
        'Stopwatch.GetTimestamp, at the session start, every {0} s strictly inside the session, and at the stop; the frequency is Stopwatch.Frequency (QueryPerformanceFrequency). ' +
        'GetSystemTimePreciseAsFileTime and GetSystemTimeAdjustment are not called: neither is reachable from Windows PowerShell 5.1 without compiling code, so time_adjustment is null. See docs/clock-calibration.md.') -f $interval
    try {
        $null = New-Item -ItemType Directory -Force -Path $clockDir
        $null = New-Item -ItemType Directory -Force -Path $marksDir
        $frequency = Get-WfQpcFrequency
        $highResolution = Test-WfQpcHighResolution
        if ($frequency -lt 1) { $frequency = $null }
        # Slots strictly inside (0, duration): a slot at exactly the duration
        # would be the stop pair taken twice.
        $slots = [int][math]::Floor(($duration - 1) / $interval)
        if ($slots -lt 0) { $slots = 0 }
        $expectedPairs = $slots + 2
        $preflightChecks = @(
            [ordered]@{ name = 'qpc_high_resolution'; ok = [bool]$highResolution; detail = 'Stopwatch.IsHighResolution: ' + [string]$highResolution },
            [ordered]@{ name = 'qpc_frequency'; ok = ($null -ne $frequency); detail = 'Stopwatch.Frequency: ' + [string]$frequency + ' Hz' }
        )
        $session = [ordered]@{
            duration_seconds       = $duration
            interval_seconds       = $interval
            expected_pairs         = $expectedPairs
            interval_slots         = $slots
            timeout_seconds        = $TimeoutSeconds
            max_artifact_bytes     = $MaxArtifactBytes
            qpc_frequency_hz       = $frequency
            qpc_high_resolution    = [bool]$highResolution
            counter_api            = 'System.Diagnostics.Stopwatch.GetTimestamp (QueryPerformanceCounter); frequency from Stopwatch.Frequency (QueryPerformanceFrequency); https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps'
            system_time_api        = 'System.DateTime.UtcNow.ToFileTimeUtc (GetSystemTimeAsFileTime; resolution is the system timer increment, 0.5 to 15 ms per https://learn.microsoft.com/dotnet/api/system.datetime.utcnow); GetSystemTimePreciseAsFileTime is not reachable from Windows PowerShell 5.1 without compiling code'
            time_adjustment_api    = 'GetSystemTimeAdjustment is not called (same reason); time_adjustment is null in the manifest'
            pair_order             = @('qpc_before', 'filetime_utc_100ns', 'qpc_after')
            samples_file           = 'samples.jsonl, one JSON object per pair, in the order taken; a decoder cites line:<n>'
            system_time_increment  = 'measured before the start pair and after the stop pair: the smallest positive step of the clock seen while reading it in a loop, with a budget of 100 ms of the counter per measurement'
            method                 = $method
        }
        $sessionPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $clockId + '/session.json')
        Write-WfJsonFile -Path $sessionPath -Object $session
        $clockEntry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $sessionPath) }
        $clockEntry.command = @('Stopwatch.GetTimestamp', 'DateTime.UtcNow.ToFileTimeUtc', 'Stopwatch.GetTimestamp')
        $clockEntry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{
                duration_seconds = $duration; interval_seconds = $interval; expected_pairs = $expectedPairs; timeout_seconds = $TimeoutSeconds; max_artifact_bytes = $MaxArtifactBytes
            } }
        $instructions = [ordered]@{
            how_to_mark      = 'While this session runs, in a second console on the PC: powershell.exe -NoProfile -NonInteractive -File <install directory>\clock-calibration.ps1 -OutputDirectory <this session directory> -Mark <label>'
            live_file        = 'raw/' + $marksId + '/' + (Get-WfClockMarksLiveName) + ' while the session runs; renamed to ' + (Get-WfClockMarksFinalName) + ' right after the stop pair, after which a mark is refused'
            record           = 'one JSON object per line: label, qpc_before, filetime_utc_100ns, qpc_after (read in that order in the mark process), at_utc, process_id; the mark sits on the master clock at (qpc_before + qpc_after) / 2 with half the bracket plus one tick of uncertainty'
            label_max_length = Get-WfClockMaxLabelLength
            max_file_bytes   = $MaxArtifactBytes
            touches          = 'only the marks file; no other process is opened, inspected or signalled'
        }
        $instructionsPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId + '/instructions.json')
        Write-WfJsonFile -Path $instructionsPath -Object $instructions
        $marksEntry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $instructionsPath) }
        $marksEntry.command = @('clock-calibration.ps1', '-OutputDirectory', '<session directory>', '-Mark', '<label>')
        $marksEntry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{
                live_file = (Get-WfClockMarksLiveName); final_file = (Get-WfClockMarksFinalName); label_max_length = (Get-WfClockMaxLabelLength); max_artifact_bytes = $MaxArtifactBytes
            } }
        $marksEntry.preflight = [ordered]@{ ok = $false; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @() }

        if (-not $highResolution -or $null -eq $frequency) {
            $failureKind = 'unsupported'
            $failure = 'Stopwatch.IsHighResolution is false or the frequency is not positive: the performance counter behind the managed timer is not the high resolution counter ETW stamps events with, so no calibration pair and no mark can be placed on the master clock'
            $clockEntry.preflight = [ordered]@{ ok = $false; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($preflightChecks) }
            $marksEntry.preflight.checks = @([ordered]@{ name = 'qpc_high_resolution'; ok = $false; detail = $failure })
        } else {
            # The live marks file: created empty before the start pair so a
            # mark can land anywhere inside the session.
            try {
                [System.IO.File]::WriteAllText($livePath, '', $utf8)
                $marksFileCreated = $true
            } catch {
                $marksReadError = 'the live marks file could not be created: ' + $_.Exception.Message
                $Log.Add('source ' + $marksId + ': ' + $marksReadError)
            }
            $marksEntry.preflight = [ordered]@{ ok = $marksFileCreated; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @(
                    [ordered]@{ name = 'live_marks_file_created'; ok = $marksFileCreated; detail = 'raw/' + $marksId + '/' + (Get-WfClockMarksLiveName) }
                ) }
            $incrementStart = Measure-WfSystemTimeIncrement -QpcFrequency $frequency
            $preflightChecks += [ordered]@{ name = 'system_time_increment_measured'; ok = [bool]$incrementStart['measured']; detail = ('{0} changes in {1} reads; smallest step {2} x 100 ns' -f $incrementStart['changes_seen'], $incrementStart['reads'], [string]$incrementStart['increment_100ns']) }
            $clockEntry.preflight = [ordered]@{ ok = $true; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($preflightChecks) }

            $deadlineTicks = [int64]$TimeoutSeconds * $frequency
            $seq = 0
            $triple = Read-WfClockTriple
            $sessionStartQpc = [int64][math]::Floor(([double]$triple['qpc_before'] + [double]$triple['qpc_after']) / 2)
            $pair = [ordered]@{ seq = $seq; phase = 'start'; qpc_before = $triple['qpc_before']; qpc_after = $triple['qpc_after']; filetime_utc_100ns = $triple['filetime_utc_100ns']
                at_utc = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$triple['filetime_utc_100ns'])); slot_qpc = $sessionStartQpc; late_ticks = 0 }
            $pairs.Add($pair)
            $line = ConvertTo-WfJson -Value $pair
            [System.IO.File]::AppendAllText($samplesPath, $line + "`n", $utf8)
            $samplesBytes += $line.Length + 1
            $seq += 1
            $Log.Add(('source {0}: start pair at qpc {1}, {2} interval slots of {3} s, stop at {4} s' -f $clockId, $sessionStartQpc, $slots, $interval, $duration))

            for ($k = 1; $k -le $slots; $k++) {
                $slotQpc = $sessionStartQpc + [int64]$k * $interval * $frequency
                $missed = $false
                while ($true) {
                    $now = Get-WfQpcTimestamp
                    if (($now - $sessionStartQpc) -gt $deadlineTicks) { throw ('the session passed its deadline of ' + $TimeoutSeconds + ' s before slot ' + $k) }
                    if ($now -ge $slotQpc) {
                        # More than a whole interval late: the slot is missed, not taken late.
                        if (($now - $slotQpc) -gt ([int64]$interval * $frequency)) { $missed = $true }
                        break
                    }
                    $remainingMs = [int][math]::Ceiling(($slotQpc - $now) * 1000.0 / $frequency)
                    Wait-WfMilliseconds -Milliseconds ([math]::Max(1, $remainingMs))
                }
                if ($missed) {
                    $missedSlots.Add([ordered]@{ seq = $seq; phase = 'interval'; slot_qpc = $slotQpc; seen_qpc = $now })
                    $message = ('source {0}: interval slot {1} (seq {2}) was missed: the counter was already {3} ticks past it' -f $clockId, $k, $seq, ($now - $slotQpc))
                    $Log.Add($message)
                    $Notes.Add($message)
                    $seq += 1
                    continue
                }
                $triple = Read-WfClockTriple
                $pair = [ordered]@{ seq = $seq; phase = 'interval'; qpc_before = $triple['qpc_before']; qpc_after = $triple['qpc_after']; filetime_utc_100ns = $triple['filetime_utc_100ns']
                    at_utc = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$triple['filetime_utc_100ns'])); slot_qpc = $slotQpc; late_ticks = ([int64]$triple['qpc_before'] - $slotQpc) }
                $pairs.Add($pair)
                $line = ConvertTo-WfJson -Value $pair
                [System.IO.File]::AppendAllText($samplesPath, $line + "`n", $utf8)
                $samplesBytes += $line.Length + 1
                if ($samplesBytes -gt $MaxArtifactBytes) { throw ('the samples file exceeded its cap of ' + $MaxArtifactBytes + ' bytes') }
                $seq += 1
            }

            $stopQpc = $sessionStartQpc + [int64]$duration * $frequency
            while ($true) {
                $now = Get-WfQpcTimestamp
                if (($now - $sessionStartQpc) -gt $deadlineTicks) { throw ('the session passed its deadline of ' + $TimeoutSeconds + ' s before the stop pair') }
                if ($now -ge $stopQpc) { break }
                $remainingMs = [int][math]::Ceiling(($stopQpc - $now) * 1000.0 / $frequency)
                Wait-WfMilliseconds -Milliseconds ([math]::Max(1, $remainingMs))
            }
            $triple = Read-WfClockTriple
            $sessionStopQpc = [int64][math]::Floor(([double]$triple['qpc_before'] + [double]$triple['qpc_after']) / 2)
            $pair = [ordered]@{ seq = $seq; phase = 'stop'; qpc_before = $triple['qpc_before']; qpc_after = $triple['qpc_after']; filetime_utc_100ns = $triple['filetime_utc_100ns']
                at_utc = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$triple['filetime_utc_100ns'])); slot_qpc = $stopQpc; late_ticks = ([int64]$triple['qpc_before'] - $stopQpc) }
            $pairs.Add($pair)
            $line = ConvertTo-WfJson -Value $pair
            [System.IO.File]::AppendAllText($samplesPath, $line + "`n", $utf8)
            $samplesBytes += $line.Length + 1
            $incrementStop = Measure-WfSystemTimeIncrement -QpcFrequency $frequency
        }
    } catch {
        $failureKind = 'capture_failed'
        $failure = 'the session failed: ' + $_.Exception.Message
        $Log.Add('source ' + $clockId + ' raised: ' + $_.Exception.Message)
    }

    # Close the marks file whatever happened to the session: rename it so a
    # late mark is refused, then read it.
    if ($marksFileCreated) {
        $attempt = 0
        while (-not $marksRenamed) {
            $attempt += 1
            try {
                [System.IO.File]::Move($livePath, $finalPath)
                $marksRenamed = $true
            } catch {
                if ($attempt -ge 5) {
                    $marksReadError = 'the live marks file could not be closed (renamed): ' + $_.Exception.Message
                    $Log.Add('source ' + $marksId + ': ' + $marksReadError)
                    break
                }
                Wait-WfMilliseconds -Milliseconds 20
            }
        }
        if ($marksRenamed) {
            try {
                $text = [System.IO.File]::ReadAllText($finalPath, $utf8)
                foreach ($rawLine in ($text -split "`n")) {
                    $candidate = $rawLine.TrimEnd("`r")
                    if ($candidate.Length -eq 0) { continue }
                    $mark = ConvertFrom-WfClockMarkLine -Line $candidate
                    if ($null -eq $mark) { $malformed += 1; continue }
                    $marks.Add($mark)
                }
            } catch {
                $marksReadError = 'the marks file could not be read: ' + $_.Exception.Message
                $Log.Add('source ' + $marksId + ': ' + $marksReadError)
            }
        }
    }
    $stopped = Get-WfUtcNow

    # --- the clock_calibration entry -------------------------------------
    $pairsTaken = $pairs.Count
    $missing = $missedSlots.Count
    if ($failureKind) {
        $clockEntry.status = $failureKind
        $clockEntry.status_reason = $failure
        if ($pairsTaken -gt 0) { $clockEntry.status_reason += ('; ' + $pairsTaken + ' pairs had been taken and are not kept, because an unfinished session is not a calibration') }
        # A failed source leaves no primary export (collectors/windows/README.md).
        if (Test-Path -LiteralPath $samplesPath) { Remove-Item -LiteralPath $samplesPath -Force }
        $pairs.Clear()
        $pairsTaken = 0
        $met = $false
    } else {
        $clockEntry.status = 'observed'
        $clockEntry.status_reason = $null
        # A missed interval slot does not fail the source: the pairs taken are real and the model is
        # usable over the longer segment (timestamps.md section 4.5). The count goes to missing_pairs,
        # and whether it is within the scenario's tolerance is the validator's adequacy check
        # (bundle.md section 3, item 5), not this collector's.
        $met = $true
        if ($missing -gt 0) {
            $message = ('source {0}: {1} of {2} expected pairs are missing (interval slots the session reached more than one interval late); the calibration is usable over longer segments, see docs/contracts/timestamps.md section 4.5' -f $clockId, $missing, $expectedPairs)
            $Notes.Add($message)
            $Log.Add($message)
        }
    }
    $manifestPairs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($pair in $pairs) {
        $manifestPairs.Add([ordered]@{ seq = [int]$pair['seq']; phase = [string]$pair['phase']; qpc_before = [int64]$pair['qpc_before']; qpc_after = [int64]$pair['qpc_after']; filetime_utc_100ns = [int64]$pair['filetime_utc_100ns'] })
    }
    $clockReport = [ordered]@{
        started_utc                 = ConvertTo-WfUtcString -Value $started
        stopped_utc                 = ConvertTo-WfUtcString -Value $stopped
        status                      = $clockEntry.status
        pairs_taken                 = $pairsTaken
        expected_pairs              = $expectedPairs
        missed_slots                = @($missedSlots.ToArray())
        session_start_qpc           = $sessionStartQpc
        session_stop_qpc            = $sessionStopQpc
        qpc_frequency_hz            = $frequency
        qpc_high_resolution         = [bool]$highResolution
        system_time_increment_start = $incrementStart
        system_time_increment_stop  = $incrementStop
        samples_bytes               = $samplesBytes
        failure                     = $failure
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $clockId + '/result.json')) -Object $clockReport
    if ($pairsTaken -gt 0) {
        $firstUtc = ConvertFrom-WfFileTime -FileTime ([int64]$pairs[0]['filetime_utc_100ns'])
        $lastUtc = ConvertFrom-WfFileTime -FileTime ([int64]$pairs[$pairs.Count - 1]['filetime_utc_100ns'])
        $clockEntry.raw_time_range = New-WfTimeRange -StartUtc $firstUtc -EndUtc $lastUtc
    }
    $clockEntry.enabled = [ordered]@{
        providers = @(); keywords = @(); stack_walk = @(); counters = @()
        options   = [ordered]@{
            pairs_taken                       = $pairsTaken
            missing_pairs                     = $missing
            qpc_frequency_hz                  = $frequency
            qpc_high_resolution               = [bool]$highResolution
            session_start_qpc                 = $sessionStartQpc
            session_stop_qpc                  = $sessionStopQpc
            system_time_increment_100ns_start = $(if ($null -ne $incrementStart) { $incrementStart['increment_100ns'] } else { $null })
            system_time_increment_100ns_stop  = $(if ($null -ne $incrementStop) { $incrementStop['increment_100ns'] } else { $null })
            time_adjustment                   = 'not read: GetSystemTimeAdjustment is not reachable from Windows PowerShell 5.1 without compiling code'
        }
        verified_by = 'the pairs themselves in samples.jsonl (one line per pair, in the order taken); result.json carries the missed slots and the measured system time increments'
    }
    $clockEntry.expectation = [ordered]@{
        declared = ('a start pair and a stop pair read through the high resolution performance counter, with one pair every {0} s strictly inside the {1} s session ({2} slots, {3} pairs in all) taken or counted in missing_pairs; the scenario''s tolerance for missing pairs is the validator''s check, not this collector''s' -f $interval, $duration, $slots, $expectedPairs)
        met      = $met
        detail   = ('{0} pairs taken, {1} slots missed; Stopwatch.IsHighResolution {2}' -f $pairsTaken, $missing, [string]$highResolution)
    }
    $clockEntry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $clockEntry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $clockId -Roles $clockRoles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $clockId, $clockEntry.status, @($clockEntry.artifacts).Count))

    # --- the operator_marks entry ------------------------------------------
    $marksMet = $false
    if ($failureKind -eq 'unsupported') {
        $marksEntry.status = 'unsupported'
        $marksEntry.status_reason = 'no mark can be placed on the master clock: ' + $failure
    } elseif (-not $marksFileCreated) {
        $marksEntry.status = 'not_collected'
        $marksEntry.status_reason = 'preflight failed, ' + $marksReadError
    } elseif (-not $marksRenamed -or $null -ne $marksReadError) {
        $marksEntry.status = 'capture_failed'
        $marksEntry.status_reason = $marksReadError
    } elseif ($malformed -gt 0) {
        $marksEntry.status = 'capture_failed'
        $marksEntry.status_reason = ('{0} line(s) of the marks file are not marks written by this script, so the set of marks is not known to be complete; {1} well formed marks were read and the file is kept as written' -f $malformed, $marks.Count)
    } elseif ($marks.Count -gt 0) {
        $marksEntry.status = 'observed'
        $marksEntry.status_reason = $null
        $marksMet = $true
    } else {
        $marksEntry.status = 'observed_zero'
        $marksEntry.status_reason = $null
        $marksMet = $true
    }
    if (-not (Test-WfObservedStatus -Status $marksEntry.status) -and $marksEntry.status -ne 'capture_failed') {
        # Not observed and not a kept partial set: leave no file that could be read as "no marks".
        if (Test-Path -LiteralPath $finalPath) { Remove-Item -LiteralPath $finalPath -Force }
        if (Test-Path -LiteralPath $livePath) { Remove-Item -LiteralPath $livePath -Force }
    }
    $scenarioMarks = New-Object 'System.Collections.Generic.List[object]'
    foreach ($mark in $marks) {
        $scenarioMarks.Add([ordered]@{
                label  = [string]$mark['label']
                at_utc = [string]$mark['at_utc']
                qpc    = [int64][math]::Floor(([double]$mark['qpc_before'] + [double]$mark['qpc_after']) / 2)
            })
    }
    $marksReport = [ordered]@{
        started_utc     = ConvertTo-WfUtcString -Value $started
        stopped_utc     = ConvertTo-WfUtcString -Value $stopped
        status          = $marksEntry.status
        live_file_created = $marksFileCreated
        closed          = $marksRenamed
        marks           = $marks.Count
        malformed_lines = $malformed
        error           = $marksReadError
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId + '/result.json')) -Object $marksReport
    if (Test-WfObservedStatus -Status $marksEntry.status) {
        # The range a mark could have landed in: the session, from the start pair to the stop pair when
        # both exist, else the collector's own start and stop.
        if ($pairsTaken -gt 0) { $marksEntry.raw_time_range = $clockEntry.raw_time_range }
        else { $marksEntry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
    }
    $marksEntry.enabled = [ordered]@{
        providers = @(); keywords = @(); stack_walk = @(); counters = @()
        options   = [ordered]@{ marks = $marks.Count; malformed_lines = $malformed; closed = $marksRenamed }
        verified_by = 'the marks file itself; every line is checked against the exact shape the mark command writes'
    }
    $marksEntry.expectation = [ordered]@{
        declared = 'the live marks file exists from the start pair to the stop pair, is closed right after it, and every line in it is a mark written by this script; zero marks is a legitimate observation'
        met      = $marksMet
        detail   = ('{0} marks, {1} malformed lines, closed: {2}' -f $marks.Count, $malformed, $marksRenamed)
    }
    $marksEntry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $marksEntry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $marksId -Roles $marksRoles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $marksId, $marksEntry.status, @($marksEntry.artifacts).Count))

    $calibration = [ordered]@{
        status           = $clockEntry.status
        method           = $method
        qpc_frequency_hz = $frequency
        expected_pairs   = $expectedPairs
        pairs            = @($manifestPairs.ToArray())
        missing_pairs    = $(if ($failureKind) { $expectedPairs } else { $missing })
        time_adjustment  = [ordered]@{ start = $null; stop = $null }
        boot_time_utc    = $MachineInfo['boot_time_utc']
    }
    return @{
        Entries                  = @($clockEntry, $marksEntry)
        Calibration              = $calibration
        Marks                    = @($scenarioMarks.ToArray())
        RequestedDurationSeconds = $duration
    }
}

if ($Mark) {
    $markExit = @(Invoke-WfClockMark -OutputDirectory $OutputDirectory -Label $Mark -MaxArtifactBytes $MaxArtifactBytes)[-1]
    exit $markExit
}

if ($DurationSeconds -lt 10 -or $DurationSeconds -gt 840 -or $IntervalSeconds -lt 1 -or $IntervalSeconds -gt 60 -or $IntervalSeconds -ge $DurationSeconds) {
    [Console]::Error.WriteLine($collectorName + ': DurationSeconds must be between 10 and 840 and IntervalSeconds between 1 and 60 and smaller than the duration')
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    Write-WfStdoutLine -Text ('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = 'How does the system clock relate to the performance counter during this session, and when did the person at the PC feel something?'
    Sources  = @(
        @{
            Id              = 'clock_calibration'
            Type            = 'custom'
            Invoke          = 'Invoke-WfClockSessionSource'
            DurationSeconds = $DurationSeconds
            IntervalSeconds = $IntervalSeconds
        }
    )
}

# The helper's per source deadline covers the whole session plus a margin.
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds ($DurationSeconds + 60) -CollectorPath $PSCommandPath)[-1]
exit $exitCode
