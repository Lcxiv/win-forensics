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
#                       every 5 seconds, and at the stop. The counter
#                       is read through Stopwatch.GetTimestamp, which Microsoft
#                       documents as QueryPerformanceCounter for managed code,
#                       the frequency through Stopwatch.Frequency, and the
#                       system time through [DateTime]::UtcNow, whose
#                       resolution is the system timer's (0.5 to 15 ms per
#                       Microsoft). Each pair is taken at the instant that
#                       clock changes value (the collector reads it in a
#                       bounded loop and keeps the counter bracket around the
#                       change), so the pair's uncertainty is the bracket and
#                       not the clock's increment; the increment itself is
#                       recorded with every pair. The precise system time API
#                       (GetSystemTimePreciseAsFileTime) cannot be called from
#                       Windows PowerShell 5.1 without compiling code, which a
#                       collector never does.
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
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Mark mode: append one counter stamped mark with this label to the marks
    # file of the session running in -OutputDirectory, then exit. Nothing else
    # is read or written.
    [string]$Mark
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
# it empty right after the start pair and renames it to marks.jsonl right
# after the stop pair (or right after the session fails), so a mark can only
# land between the two.
function Get-WfClockMarksLiveName { return 'marks.open.jsonl' }
function Get-WfClockMarksFinalName { return 'marks.jsonl' }
function Get-WfClockMaxLabelLength { return 80 }
function Get-WfClockEdgeBudgetMilliseconds { return 100 }
# Seconds between two calibration pairs: the cadence docs/contracts/timestamps.md section 3 names.
function Get-WfClockIntervalSeconds { return 5 }

function ConvertFrom-WfFileTime {
    param([int64]$FileTime)
    return [datetime]::FromFileTimeUtc($FileTime)
}

function Read-WfClockPair {
    # One calibration pair, read in this thread in the order the contract
    # fixes (counter, system time, counter), at the instant the system clock
    # changes value. The clock advances once per clock interrupt (Microsoft:
    # 0.5 to 15 ms), so a reading taken at a random instant can lag the true
    # time by up to one increment. Reading it in a loop until it changes, and
    # keeping the counter read before the last unchanged reading and the one
    # after the changed reading, puts the moment the clock took its new value
    # inside the bracket; the pair's uncertainty is then the bracket (half
    # its width plus one tick, timestamps.md section 3) and the increment is
    # recorded as data, not added to the bound. The loop is bounded by
    # -BudgetMilliseconds of the counter: when the clock did not change in
    # time (or went backwards during the loop) the last plain triple is
    # returned with edge false, and the Mac side fit adds the increment term
    # for that pair.
    param([int64]$QpcFrequency, [int]$BudgetMilliseconds)
    $budgetTicks = [int64][math]::Ceiling($BudgetMilliseconds * $QpcFrequency / 1000.0)
    $startQpc = Get-WfQpcTimestamp
    $qPrev = $startQpc
    $fPrev = Get-WfSystemFileTimeUtc
    $reads = 1
    while ($true) {
        $q = Get-WfQpcTimestamp
        $f = Get-WfSystemFileTimeUtc
        $qAfter = Get-WfQpcTimestamp
        $reads += 1
        if ($f -ne $fPrev) {
            if ($f -lt $fPrev) {
                return [ordered]@{ qpc_before = [int64]$q; filetime_utc_100ns = [int64]$f; qpc_after = [int64]$qAfter; edge = $false; step_100ns = $null; reads = $reads; note = 'the system time went backwards while the pair was read' }
            }
            return [ordered]@{ qpc_before = [int64]$qPrev; filetime_utc_100ns = [int64]$f; qpc_after = [int64]$qAfter; edge = $true; step_100ns = [int64]($f - $fPrev); reads = $reads; note = $null }
        }
        if (($qAfter - $startQpc) -gt $budgetTicks) {
            return [ordered]@{ qpc_before = [int64]$q; filetime_utc_100ns = [int64]$f; qpc_after = [int64]$qAfter; edge = $false; step_100ns = $null; reads = $reads; note = ('the system time did not change within ' + $BudgetMilliseconds + ' ms') }
        }
        $qPrev = $q
        $fPrev = $f
    }
}

function Read-WfClockTriple {
    # A plain triple for a mark: counter, system time, counter, at the moment
    # the command runs. A mark is a counter stamp; its system time is kept
    # for the reader, so no edge is waited for.
    $before = Get-WfQpcTimestamp
    $fileTime = Get-WfSystemFileTimeUtc
    $after = Get-WfQpcTimestamp
    return [ordered]@{ qpc_before = [int64]$before; filetime_utc_100ns = [int64]$fileTime; qpc_after = [int64]$after }
}

function Get-WfClockMarkPattern {
    # The exact shape ConvertTo-WfClockMarkLine produces, so a line that was
    # not written by this script (or was cut short) is recognised and the
    # source is marked capture_failed instead of silently losing a mark.
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
    # Returns the mark as an ordered map, or $null when the line is not a
    # mark this script wrote (including a label escape the JSON writer never
    # produces).
    param([string]$Line)
    $m = [regex]::Match($Line, (Get-WfClockMarkPattern))
    if (-not $m.Success) { return $null }
    $label = $null
    try { $label = [regex]::Unescape($m.Groups[1].Value) } catch { return $null }
    return [ordered]@{
        label              = $label
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
    # its own after the session has renamed it. The handle is the only one
    # open on the file while it writes (FileShare None: Microsoft documents
    # that it "declines sharing of the current file. Any request to open the
    # file (by this process or another process) will fail until the file is
    # closed", https://learn.microsoft.com/dotnet/api/system.io.fileshare),
    # so two mark commands cannot seek to the same end and overwrite each
    # other and the cap is checked against a length nobody else is changing;
    # nothing reads the live file before the session renames it. A second
    # writer gets a sharing violation and retries for up to half a second.
    param([string]$Path, [string]$Line, [int64]$MaxBytes)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Line + "`n")
    $attempt = 0
    while ($true) {
        $attempt += 1
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            if (($stream.Length + $bytes.Length) -gt $MaxBytes) { throw ('the marks file would exceed its cap of ' + $MaxBytes + ' bytes') }
            $null = $stream.Seek(0, [System.IO.SeekOrigin]::End)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            return $bytes.Length
        } catch [System.IO.IOException] {
            if ($attempt -ge 50 -or -not (Test-Path -LiteralPath $Path)) { throw }
            Wait-WfMilliseconds -Milliseconds 10
        } finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }
    }
}

function Get-WfClockMarksDeadline {
    # The instant after which a session cannot still be running (its start
    # plus its deadline), from session.json. $null when the file or the
    # field is missing.
    param([string]$SessionPath)
    if (-not (Test-Path -LiteralPath $SessionPath -PathType Leaf)) { return $null }
    $text = [System.IO.File]::ReadAllText($SessionPath)
    $m = [regex]::Match($text, '"accepts_marks_until_utc"\s*:\s*"([^"]+)"')
    if (-not $m.Success) { return $null }
    try { return (ConvertFrom-WfUtcString -Text $m.Groups[1].Value) } catch { return $null }
}

function Invoke-WfClockMark {
    # Mark mode. Prints one JSON line and returns the exit code: 0 when the
    # mark was appended, 1 otherwise. The label is kept as typed (JSON
    # escaped) and refused when empty, over the length limit, or holding a
    # control character.
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
        $deadline = Get-WfClockMarksDeadline -SessionPath (Join-WfBundlePath -BundleRoot $root -RelativePath 'raw/clock_calibration/session.json')
        if ($null -eq $deadline) { throw 'the session directory holds no readable raw/clock_calibration/session.json, so the session cannot be shown to be running' }
        if ((Get-WfUtcNow) -gt $deadline) {
            throw ('the session in this directory passed its deadline at ' + (ConvertTo-WfUtcString -Value $deadline) + ' without finishing (it was probably stopped); a mark into it would never reach a bundle')
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

function Add-WfClockSample {
    # One pair to the samples file (one JSON object per line, in the order
    # taken) and to the in memory list. Returns the bytes written.
    param([string]$Path, $Pair, [System.Collections.Generic.List[object]]$Pairs)
    $Pairs.Add($Pair)
    $line = ConvertTo-WfJson -Value $Pair
    [System.IO.File]::AppendAllText($Path, $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
    return [int64]($line.Length + 1)
}

function New-WfClockPairRecord {
    param([int]$Seq, [string]$Phase, $Reading, [int64]$SlotQpc)
    return [ordered]@{
        seq                = $Seq
        phase              = $Phase
        qpc_before         = [int64]$Reading['qpc_before']
        qpc_after          = [int64]$Reading['qpc_after']
        filetime_utc_100ns = [int64]$Reading['filetime_utc_100ns']
        at_utc             = ConvertTo-WfUtcString -Value (ConvertFrom-WfFileTime -FileTime ([int64]$Reading['filetime_utc_100ns']))
        slot_qpc           = $SlotQpc
        late_ticks         = ([int64]$Reading['qpc_before'] - $SlotQpc)
        edge               = [bool]$Reading['edge']
        step_100ns         = $Reading['step_100ns']
        reads              = [int]$Reading['reads']
        note               = $Reading['note']
    }
}

function Close-WfClockMarksFile {
    # Renames the live marks file to its final name, retrying for half a
    # second against a mark command that holds it for a few microseconds.
    # Returns the error message, or $null when the file is closed.
    param([string]$LivePath, [string]$FinalPath)
    $attempt = 0
    while ($true) {
        $attempt += 1
        try {
            [System.IO.File]::Move($LivePath, $FinalPath)
            return $null
        } catch {
            if ($attempt -ge 50) { return ('the live marks file could not be closed (renamed): ' + $_.Exception.Message) }
            Wait-WfMilliseconds -Milliseconds 10
        }
    }
}

function Invoke-WfClockSessionSource {
    # The custom source: runs the bounded session and returns the two
    # manifest entries (clock_calibration, operator_marks), the manifest
    # calibration section and the operator marks for scenario.marks.
    param($Source, [string]$BundleRoot, [int64]$MaxArtifactBytes, [int]$TimeoutSeconds, [System.Collections.Generic.List[string]]$Log, [System.Collections.Generic.List[string]]$Notes, $MachineInfo)
    $duration = [int]$Source['DurationSeconds']
    $interval = Get-WfClockIntervalSeconds
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
    $budgetMs = Get-WfClockEdgeBudgetMilliseconds

    $pairs = New-Object 'System.Collections.Generic.List[object]'
    $missedSlots = New-Object 'System.Collections.Generic.List[object]'
    $marks = New-Object 'System.Collections.Generic.List[object]'
    $failure = $null
    $unsupported = $false
    $frequency = $null
    $highResolution = $false
    $sessionStartQpc = $null
    $sessionStopQpc = $null
    $expectedPairs = 0
    $slots = 0
    $marksFileCreated = $false
    $marksRenamed = $false
    $marksReadError = $null
    $malformed = 0
    $samplesBytes = [int64]0
    $method = ('one thread reads Stopwatch.GetTimestamp (QueryPerformanceCounter), [DateTime]::UtcNow.ToFileTimeUtc() (the system time at the resolution of the system timer), Stopwatch.GetTimestamp, ' +
        'at the session start, every {0} s strictly inside the session, and at the stop. Each pair is taken at the instant the system clock changes value: the clock is read in a loop until it changes, and the counter read before the last unchanged reading and the one after the changed reading bracket the moment the clock took its new value; the size of that change (the clock increment) is recorded with the pair. ' +
        'The frequency is Stopwatch.Frequency (QueryPerformanceFrequency). GetSystemTimePreciseAsFileTime and GetSystemTimeAdjustment are not called: neither is reachable from Windows PowerShell 5.1 without compiling code, so both members of time_adjustment are null. See docs/clock-calibration.md.') -f $interval

    try {
        $null = New-Item -ItemType Directory -Force -Path $clockDir
        $null = New-Item -ItemType Directory -Force -Path $marksDir
        $frequency = Get-WfQpcFrequency
        $highResolution = Test-WfQpcHighResolution
        if ($frequency -lt 1) { $frequency = $null }
        # Interval slots strictly inside (0, duration): a slot at exactly the
        # duration is the stop pair (timestamps.md section 3, the clock
        # calibration exception).
        $slots = [int][math]::Floor(($duration - 1) / $interval)
        if ($slots -lt 0) { $slots = 0 }
        $expectedPairs = $slots + 2
        $preflightChecks = @(
            [ordered]@{ name = 'qpc_high_resolution'; ok = [bool]$highResolution; detail = 'Stopwatch.IsHighResolution: ' + [string]$highResolution },
            [ordered]@{ name = 'qpc_frequency'; ok = ($null -ne $frequency); detail = 'Stopwatch.Frequency: ' + [string]$frequency + ' Hz' }
        )
        $session = [ordered]@{
            started_utc              = ConvertTo-WfUtcString -Value $started
            accepts_marks_until_utc  = ConvertTo-WfUtcString -Value $started.AddSeconds($TimeoutSeconds)
            duration_seconds         = $duration
            interval_seconds         = $interval
            expected_pairs           = $expectedPairs
            interval_slots           = $slots
            timeout_seconds          = $TimeoutSeconds
            max_artifact_bytes       = $MaxArtifactBytes
            qpc_frequency_hz         = $frequency
            qpc_high_resolution      = [bool]$highResolution
            edge_budget_milliseconds = $budgetMs
            counter_api              = 'System.Diagnostics.Stopwatch.GetTimestamp (QueryPerformanceCounter); frequency from Stopwatch.Frequency (QueryPerformanceFrequency); https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps'
            system_time_api          = 'System.DateTime.UtcNow.ToFileTimeUtc, read at the instant it changes value; its resolution is the system timer increment, 0.5 to 15 ms per https://learn.microsoft.com/dotnet/api/system.datetime.utcnow; GetSystemTimePreciseAsFileTime is not reachable from Windows PowerShell 5.1 without compiling code'
            time_adjustment_api      = 'GetSystemTimeAdjustment is not called (same reason); both members of time_adjustment are null in the manifest'
            pair_order               = @('qpc_before', 'filetime_utc_100ns', 'qpc_after')
            samples_file             = 'samples.jsonl, one JSON object per pair, in the order taken; a decoder cites line:<n>; edge says whether the pair was taken at a change of the system clock, step_100ns is the size of that change'
            method                   = $method
        }
        $sessionPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $clockId + '/session.json')
        Write-WfJsonFile -Path $sessionPath -Object $session
        $clockEntry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $sessionPath) }
        $clockEntry.command = @('Stopwatch.GetTimestamp', 'DateTime.UtcNow.ToFileTimeUtc', 'Stopwatch.GetTimestamp')
        $clockEntry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{
                duration_seconds = $duration; interval_seconds = $interval; expected_pairs = $expectedPairs; timeout_seconds = $TimeoutSeconds; max_artifact_bytes = $MaxArtifactBytes; edge_budget_milliseconds = $budgetMs
            } }
        $instructions = [ordered]@{
            how_to_mark      = 'While this session runs, in a second console on the PC: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <install directory>\clock-calibration.ps1 -OutputDirectory <this session directory> -Mark <label>'
            execution_policy = '-ExecutionPolicy Bypass sets the policy for that one process only (about_PowerShell_exe); without it a Windows client, whose default policy is Restricted, refuses to run the script (about_Execution_Policies)'
            live_file        = 'raw/' + $marksId + '/' + (Get-WfClockMarksLiveName) + ' from the start pair to the stop pair; renamed to ' + (Get-WfClockMarksFinalName) + ' right after the stop pair or the session failure, after which a mark is refused; a mark is also refused once the session deadline (accepts_marks_until_utc in session.json) has passed'
            record           = 'one JSON object per line: label, qpc_before, filetime_utc_100ns, qpc_after (read in that order in the mark process), at_utc, process_id; the mark sits on the master clock at (qpc_before + qpc_after) / 2 with half the bracket plus one tick of uncertainty'
            writer           = 'one handle at a time (the file is opened with FileShare None), so two marks typed at once cannot overwrite each other; the second waits up to half a second'
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
            $unsupported = $true
            $failure = 'Stopwatch.IsHighResolution is false or the frequency is not positive: the performance counter behind the managed timer is not the high resolution counter ETW stamps events with, so no calibration pair and no mark can be placed on the master clock'
            $clockEntry.preflight = [ordered]@{ ok = $false; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($preflightChecks) }
            $marksEntry.preflight.checks = @([ordered]@{ name = 'qpc_high_resolution'; ok = $false; detail = $failure })
        } else {
            $clockEntry.preflight = [ordered]@{ ok = $true; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($preflightChecks) }
            $deadlineTicks = [int64]$TimeoutSeconds * $frequency
            # The session runs through the helper's one live session path,
            # Invoke-WfLiveSession. Its start is the start pair and the live
            # marks file; its bound is the interval slots on the counter; its
            # stop is the stop pair; and on every exit path its end is the
            # marks file closed (renamed), so no later mark can land in it.
            # The hooks write their results into $live, never into variables.
            $live = @{ Seq = 0; SessionStartQpc = $null; SessionStopQpc = $null; SamplesBytes = [int64]0; MarksFileCreated = $false; MarksRenamed = $false; MarksReadError = $null; Failure = $null }
            $closeMarks = {
                param($S)
                $closeError = Close-WfClockMarksFile -LivePath $livePath -FinalPath $finalPath
                if ($null -eq $closeError) { $S.MarksRenamed = $true; return $true }
                $S.MarksReadError = $closeError
                $Log.Add('source ' + $marksId + ': ' + $closeError)
                return $false
            }
            $liveHooks = @{
                Start   = {
                    param($S)
                    $reading = Read-WfClockPair -QpcFrequency $frequency -BudgetMilliseconds $budgetMs
                    $startQpc = [int64][math]::Floor(([double]$reading['qpc_before'] + [double]$reading['qpc_after']) / 2)
                    $S.SessionStartQpc = $startQpc
                    $S.SamplesBytes += Add-WfClockSample -Path $samplesPath -Pair (New-WfClockPairRecord -Seq $S.Seq -Phase 'start' -Reading $reading -SlotQpc $startQpc) -Pairs $pairs
                    $S.Seq += 1
                    # The live marks file opens right after the start pair, so no mark
                    # can precede it.
                    try {
                        [System.IO.File]::WriteAllText($livePath, '', $utf8)
                        $S.MarksFileCreated = $true
                    } catch {
                        $S.MarksReadError = 'the live marks file could not be created: ' + $_.Exception.Message
                        $Log.Add('source ' + $marksId + ': ' + $S.MarksReadError)
                    }
                    $marksEntry.preflight = [ordered]@{ ok = [bool]$S.MarksFileCreated; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @(
                            [ordered]@{ name = 'live_marks_file_created'; ok = [bool]$S.MarksFileCreated; detail = 'raw/' + $marksId + '/' + (Get-WfClockMarksLiveName) + ', opened right after the start pair' }
                        ) }
                    $Log.Add(('source {0}: start pair at qpc {1}, {2} interval slots of {3} s, stop at {4} s' -f $clockId, $startQpc, $slots, $interval, $duration))
                    return @{ Ok = $true; MayRemain = $true }
                }
                Bound   = {
                    # Interval slots strictly inside the session, then the wait for
                    # the stop slot, all on the counter and all under the deadline.
                    param($S)
                    $startQpc = [int64]$S.SessionStartQpc
                    for ($k = 1; $k -le $slots; $k++) {
                        $slotQpc = $startQpc + [int64]$k * $interval * $frequency
                        $missed = $false
                        while ($true) {
                            $now = Get-WfQpcTimestamp
                            if (($now - $startQpc) -gt $deadlineTicks) { throw ('the session passed its deadline of ' + $TimeoutSeconds + ' s before slot ' + $k) }
                            if ($now -ge $slotQpc) {
                                # More than a whole interval late: the slot is missed, not taken late.
                                if (($now - $slotQpc) -gt ([int64]$interval * $frequency)) { $missed = $true }
                                break
                            }
                            $remainingMs = [int][math]::Ceiling(($slotQpc - $now) * 1000.0 / $frequency)
                            Wait-WfMilliseconds -Milliseconds ([math]::Max(1, $remainingMs))
                        }
                        if ($missed) {
                            $missedSlots.Add([ordered]@{ seq = $S.Seq; phase = 'interval'; slot_qpc = $slotQpc; seen_qpc = $now })
                            $message = ('source {0}: interval slot {1} (seq {2}) was missed: the counter was already {3} ticks past it' -f $clockId, $k, $S.Seq, ($now - $slotQpc))
                            $Log.Add($message)
                            $Notes.Add($message)
                            $S.Seq += 1
                            continue
                        }
                        $reading = Read-WfClockPair -QpcFrequency $frequency -BudgetMilliseconds $budgetMs
                        $S.SamplesBytes += Add-WfClockSample -Path $samplesPath -Pair (New-WfClockPairRecord -Seq $S.Seq -Phase 'interval' -Reading $reading -SlotQpc $slotQpc) -Pairs $pairs
                        if ($S.SamplesBytes -gt $MaxArtifactBytes) { throw ('the samples file exceeded its cap of ' + $MaxArtifactBytes + ' bytes') }
                        $S.Seq += 1
                    }
                    $stopQpc = $startQpc + [int64]$duration * $frequency
                    while ($true) {
                        $now = Get-WfQpcTimestamp
                        if (($now - $startQpc) -gt $deadlineTicks) { throw ('the session passed its deadline of ' + $TimeoutSeconds + ' s before the stop pair') }
                        if ($now -ge $stopQpc) { break }
                        $remainingMs = [int][math]::Ceiling(($stopQpc - $now) * 1000.0 / $frequency)
                        Wait-WfMilliseconds -Milliseconds ([math]::Max(1, $remainingMs))
                    }
                    return $false
                }
                Stop    = {
                    # The stop pair, then the marks file closed at once.
                    param($S)
                    $stopQpc = [int64]$S.SessionStartQpc + [int64]$duration * $frequency
                    $reading = Read-WfClockPair -QpcFrequency $frequency -BudgetMilliseconds $budgetMs
                    $S.SessionStopQpc = [int64][math]::Floor(([double]$reading['qpc_before'] + [double]$reading['qpc_after']) / 2)
                    $S.SamplesBytes += Add-WfClockSample -Path $samplesPath -Pair (New-WfClockPairRecord -Seq $S.Seq -Phase 'stop' -Reading $reading -SlotQpc $stopQpc) -Pairs $pairs
                    if ($S.MarksFileCreated) { return (& $closeMarks $S) }
                    return $true
                }
                Fail    = {
                    param($S, [string]$Message)
                    $S.Failure = 'the session failed: ' + $Message
                    $Log.Add('source ' + $clockId + ' raised: ' + $Message)
                }
                Confirm = {
                    # The session is open while its live marks file is.
                    param($S, [string]$Moment)
                    if ($S.MarksFileCreated -and -not $S.MarksRenamed -and (Test-Path -LiteralPath $livePath)) { return 'active' }
                    return 'idle'
                }
                Cancel  = {
                    param($S, [string]$Read)
                    if ($S.MarksFileCreated -and -not $S.MarksRenamed) { return (& $closeMarks $S) }
                    return $true
                }
            }
            $liveRecord = Invoke-WfLiveSession -LiveHooks $liveHooks -LiveState $live -LiveSeconds $duration
            $sessionStartQpc = $live.SessionStartQpc
            $sessionStopQpc = $live.SessionStopQpc
            $samplesBytes = [int64]$live.SamplesBytes
            $marksFileCreated = [bool]$live.MarksFileCreated
            $marksRenamed = [bool]$live.MarksRenamed
            if ($null -ne $live.MarksReadError) { $marksReadError = [string]$live.MarksReadError }
            if ($null -ne $live.Failure) { $failure = [string]$live.Failure }
            if ($null -ne $liveRecord.end_error) { $Log.Add('source ' + $marksId + ': the end check raised: ' + [string]$liveRecord.end_error) }
        }
    } catch {
        $failure = 'the session failed: ' + $_.Exception.Message
        $Log.Add('source ' + $clockId + ' raised: ' + $_.Exception.Message)
    }

    # Read the closed marks file.
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
    $stopped = Get-WfUtcNow

    # --- the clock_calibration entry -------------------------------------
    # Status (timestamps.md section 3, the clock calibration exception in
    # measurement-status.md section 2): two or more pairs are a calibration,
    # with every slot not taken (the stop pair included) counted in
    # missing_pairs; fewer than two pairs are capture_failed and the pairs
    # taken are not kept.
    $pairsTaken = $pairs.Count
    $missing = $expectedPairs - $pairsTaken
    if ($missing -lt 0) { $missing = 0 }
    $hasStop = ($pairsTaken -gt 0 -and [string]$pairs[$pairs.Count - 1]['phase'] -eq 'stop')
    if ($unsupported) {
        $clockEntry.status = 'unsupported'
        $clockEntry.status_reason = $failure
        $met = $false
    } elseif ($pairsTaken -lt 2) {
        $clockEntry.status = 'capture_failed'
        $clockEntry.status_reason = $failure
        if ($null -eq $failure) { $clockEntry.status_reason = 'fewer than two calibration pairs were taken' }
        if ($pairsTaken -gt 0) { $clockEntry.status_reason += ('; ' + $pairsTaken + ' pair had been taken and is not kept, because one pair is not a calibration (timestamps.md section 4.5)') }
        # A failed source leaves no primary export (collectors/windows/README.md).
        if (Test-Path -LiteralPath $samplesPath) { Remove-Item -LiteralPath $samplesPath -Force }
        $pairs.Clear()
        $pairsTaken = 0
        $missing = $expectedPairs
        $met = $false
    } else {
        $clockEntry.status = 'observed'
        $clockEntry.status_reason = $null
        $met = ($missing -eq 0 -and $null -eq $failure -and $hasStop)
        if ($null -ne $failure) {
            $message = ('source {0}: {1}; the {2} pairs taken are kept and the {3} pairs not taken (the stop pair included) are counted in missing_pairs; timestamps after the last pair are unaligned' -f $clockId, $failure, $pairsTaken, $missing)
            $Notes.Add($message)
            $Log.Add($message)
        } elseif ($missing -gt 0) {
            $message = ('source {0}: {1} of {2} expected pairs are missing (interval slots the session reached more than one interval late); the calibration is usable over longer segments, see docs/contracts/timestamps.md section 4.5' -f $clockId, $missing, $expectedPairs)
            $Notes.Add($message)
            $Log.Add($message)
        }
    }
    $manifestPairs = New-Object 'System.Collections.Generic.List[object]'
    $edgePairs = 0
    $largestStep = $null
    foreach ($pair in $pairs) {
        $manifestPairs.Add([ordered]@{ seq = [int]$pair['seq']; phase = [string]$pair['phase']; qpc_before = [int64]$pair['qpc_before']; qpc_after = [int64]$pair['qpc_after']; filetime_utc_100ns = [int64]$pair['filetime_utc_100ns'] })
        if ($pair['edge']) {
            $edgePairs += 1
            if ($null -eq $largestStep -or [int64]$pair['step_100ns'] -gt $largestStep) { $largestStep = [int64]$pair['step_100ns'] }
        }
    }
    $missingReported = $missing
    if ($unsupported) { $missingReported = $expectedPairs }
    $clockReport = [ordered]@{
        started_utc        = ConvertTo-WfUtcString -Value $started
        stopped_utc        = ConvertTo-WfUtcString -Value $stopped
        status             = $clockEntry.status
        pairs_taken        = $pairsTaken
        expected_pairs     = $expectedPairs
        missing_pairs      = $missingReported
        stop_pair_taken    = $hasStop
        missed_slots       = @($missedSlots.ToArray())
        edge_pairs         = $edgePairs
        largest_step_100ns = $largestStep
        session_start_qpc  = $sessionStartQpc
        session_stop_qpc   = $sessionStopQpc
        qpc_frequency_hz   = $frequency
        qpc_high_resolution = [bool]$highResolution
        samples_bytes      = $samplesBytes
        failure            = $failure
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
            pairs_taken         = $pairsTaken
            missing_pairs       = $missingReported
            stop_pair_taken     = $hasStop
            edge_pairs          = $edgePairs
            largest_step_100ns  = $largestStep
            qpc_frequency_hz    = $frequency
            qpc_high_resolution = [bool]$highResolution
            session_start_qpc   = $sessionStartQpc
            session_stop_qpc    = $sessionStopQpc
            failure             = $failure
            time_adjustment     = 'not read: GetSystemTimeAdjustment is not reachable from Windows PowerShell 5.1 without compiling code; both members are null'
        }
        verified_by = 'the pairs themselves in samples.jsonl (one line per pair, in the order taken, each saying whether it was taken at a change of the system clock); result.json carries the missed slots, the largest clock step seen and any failure'
    }
    $failureDetail = ''
    if ($failure) { $failureDetail = '; ' + $failure }
    $clockEntry.expectation = [ordered]@{
        declared = ('{0} pairs: a start pair, one every {1} s strictly inside the {2} s session ({3} slots) and a stop pair, all read through the high resolution performance counter (timestamps.md section 3, clock calibration exception)' -f $expectedPairs, $interval, $duration, $slots)
        met      = $met
        detail   = ('{0} of {1} pairs taken, {2} missing, stop pair taken: {3}, {4} at a clock edge; Stopwatch.IsHighResolution {5}{6}' -f $pairsTaken, $expectedPairs, $missingReported, $hasStop, $edgePairs, [string]$highResolution, $failureDetail)
    }
    $clockEntry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $clockEntry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $clockId -Roles $clockRoles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $clockId, $clockEntry.status, @($clockEntry.artifacts).Count))

    # --- the operator_marks entry ------------------------------------------
    $marksMet = $false
    if ($unsupported) {
        $marksEntry.status = 'unsupported'
        $marksEntry.status_reason = 'no mark can be placed on the master clock: ' + $failure
    } elseif (-not $marksFileCreated) {
        $marksEntry.status = 'not_collected'
        if ($null -ne $marksReadError) { $marksEntry.status_reason = 'preflight failed, ' + $marksReadError }
        else { $marksEntry.status_reason = 'the session ended before the start pair, so the marks file was never opened: ' + [string]$failure }
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
        started_utc       = ConvertTo-WfUtcString -Value $started
        stopped_utc       = ConvertTo-WfUtcString -Value $stopped
        status            = $marksEntry.status
        live_file_created = $marksFileCreated
        closed            = $marksRenamed
        marks             = $marks.Count
        malformed_lines   = $malformed
        error             = $marksReadError
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $marksId + '/result.json')) -Object $marksReport
    if (Test-WfObservedStatus -Status $marksEntry.status) {
        # The range a mark could have landed in: from the start pair to the
        # stop pair (or to the collector's stop when the session failed).
        if ($pairsTaken -gt 0 -and $hasStop) { $marksEntry.raw_time_range = $clockEntry.raw_time_range }
        elseif ($pairsTaken -gt 0) { $marksEntry.raw_time_range = New-WfTimeRange -StartUtc (ConvertFrom-WfFileTime -FileTime ([int64]$pairs[0]['filetime_utc_100ns'])) -EndUtc $stopped }
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
        missing_pairs    = $missingReported
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

if ($PSBoundParameters.ContainsKey('Mark')) {
    $markExit = @(Invoke-WfClockMark -OutputDirectory $OutputDirectory -Label $Mark -MaxArtifactBytes $MaxArtifactBytes)[-1]
    exit $markExit
}

if ($DurationSeconds -lt 10 -or $DurationSeconds -gt 840) {
    [Console]::Error.WriteLine($collectorName + ': DurationSeconds must be between 10 and 840')
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
        }
    )
}

# The helper's per source deadline covers the whole session plus a margin.
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds ($DurationSeconds + 60) -CollectorPath $PSCommandPath)[-1]
exit $exitCode
