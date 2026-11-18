# dpcisr-trace: Where do DPC and interrupt time land, per CPU and per module, while the PC is in use?
#
# A bounded live capture. Runs under Windows PowerShell 5.1 as an elevated
# account (kernel tracing is an Administrator operation, see below), writes
# one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints one
# JSON summary line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md for the interface, the artifact formats, the
# elevation note and the facts still to be verified on a real machine.
#
# Sources:
#
#   wpr_trace       one Windows Performance Recorder session from the profile
#                   embedded below (NT Kernel Logger: Interrupt, DPC, Loader,
#                   ProcessThread, CSwitch, ReadyThread), file mode, started
#                   and stopped by this script within -DurationSeconds; the
#                   profile, the trace, the wpr status text read just before
#                   the stop (events lost per collector) and a session record
#                   are the artifacts
#   dpcisr_report   the per CPU, per module DPC and ISR report of that trace,
#                   "xperf -i trace.etl -a dpcisr", which only runs when the
#                   operator names an xperf.exe (-XperfPath) whose SHA-256 and
#                   version are pinned in _common.ps1 (Get-WfPinnedToolBuilds);
#                   scripts/decode_dpcisr.py turns the report into the
#                   dpcisr_module_cpu and dpcisr_interval tables
#
# Why these keywords (Keyword (in SystemProvider),
# https://learn.microsoft.com/windows-hardware/test/wpt/keyword--in-systemprovider-):
#   Interrupt      "Interrupts are logged" (the ISR events, EVENT_TRACE_FLAG_INTERRUPT)
#   DPC            "Deferred procedure calls are logged" (EVENT_TRACE_FLAG_DPC)
#   Loader         "Kernel and user mode load and unload events are logged": the
#                  Image events whose address ranges name the module behind a
#                  DPC or ISR routine address ("Use the address with the Image
#                  events to find which image started",
#                  https://learn.microsoft.com/windows/win32/etw/dpc)
#   ProcessThread  "Process and thread creation and deletion events are logged":
#                  the names behind the thread ids of the scheduling events
#   CSwitch        "Context switch activity is logged": which thread ran on
#                  which CPU (https://learn.microsoft.com/windows/win32/etw/cswitch)
#   ReadyThread    "Ready thread events are logged": when a thread became ready
#                  and had to wait for a CPU (https://learn.microsoft.com/windows/win32/etw/readythread)
# The scheduling events are recorded so the trace can later answer which
# threads ran on the CPU that takes the GPU interrupts; decoding them is a
# later piece. No stacks are requested (stack walking multiplies the volume
# and nothing here needs it).
#
# WPR command line: https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options
# Profile XML: https://learn.microsoft.com/windows-hardware/test/wpt/recording-profile-xml-reference
# Events lost: "wpr -status collectors" prints "Events Lost" per collector and
# "wpr -status" prints "Dropped event" (same page, Status). The session keeps
# that count because ETW discards events when every buffer is full
# (https://learn.microsoft.com/windows-hardware/test/wpt/sessions). A trace
# with lost events, or whose loss could not be read, is capture_failed: it can
# never be read as a clean absence (docs/contracts/measurement-status.md).
#
# Elevation: "Only users running with elevated administrative privileges,
# users in the Performance Log Users group, and applications running as
# LocalSystem, LocalService or NetworkService can control event tracing
# sessions" (https://learn.microsoft.com/windows/win32/etw/controlling-event-tracing-sessions),
# and a system (kernel) logger needs more than Performance Log Users
# (https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session).
# This collector refuses to start a session when the account is not elevated
# and reports not_collected with that reason. It builds no scheduled task,
# service or other persistent elevation.
#
# Read only toward the machine: it changes no setting, installs nothing,
# touches no process, and the one thing it starts (the trace session) it
# stops on every exit path, including failure and timeout, and reports when
# it could not confirm the stop. It never cancels a recording it did not
# start: a WPR recording that is already in progress makes the source
# not_collected. Anti-cheat note: ETW observes from the kernel, outside every
# process; nothing here opens a handle to, injects into, or changes the
# priority or affinity of any process. Easy Anti-Cheat's documentation does
# not state how it treats ETW sessions, so that is recorded as unknown in the
# README rather than asserted.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long the trace session records, in seconds (5 to 300). The session
    # is stopped when this elapses, when the recording reaches -MaxTraceBytes,
    # or when anything fails, whichever comes first.
    [int]$DurationSeconds = 60,
    # Cap on the trace file, in bytes (16 MiB to 16 GiB). The recording is
    # stopped early when the temporary recording reaches it, and a saved trace
    # above it is removed.
    [long]$MaxTraceBytes = 2147483648,
    # Full path of xperf.exe from the Windows Performance Toolkit, when the
    # operator has one. It runs only when its SHA-256 and file version match
    # a build pinned in _common.ps1; otherwise the report is not_collected.
    [string]$XperfPath = '',
    # Cap on the size of the xperf report, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for each tool process (every wpr call, the xperf report), in
    # seconds (1 to 3600). A process that does not finish in time is stopped
    # and the source is recorded as failed; the trace session is then
    # cancelled.
    [int]$TimeoutSeconds = 240
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'dpcisr-trace'
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

# ---------------------------------------------------------------------------
# The recording profile. Versioned with the collector (Comments carries the
# collector version); written byte for byte into raw/wpr_trace/ at capture
# time and hashed there as the source's config_hash, so the bundle carries
# the exact profile that ran. Elements and attributes follow the recording
# profile XML reference: WindowsPerformanceRecorder (Version and Author are
# required), SystemCollector (Name must be "NT Kernel Logger"; BufferSize in
# KB and Buffers are the two buffer settings, and both must be defined in a
# custom profile), SystemProvider with its Keywords, and a Profile per
# logging mode (a .wprp must define both the File and the Memory version;
# the Id is Name.DetailLevel.LoggingMode). The buffer size is the one the
# built in General profile uses for its NT Kernel Logger collector (1024 KB,
# https://learn.microsoft.com/windows-hardware/test/wpt/recording-for-basic-system-diagnosis)
# and the count is WPR's documented default (64), 64 MB in all. Lost events
# are the check on that choice: the status says so and the README says what
# to raise.
# ---------------------------------------------------------------------------
function Get-DpcIsrProfileName { return 'WfDpcIsrTrace' }
function Get-DpcIsrProfileFileName { return 'dpcisr-trace.wprp' }
function Get-DpcIsrRequestedKeywords { return @('Interrupt', 'DPC', 'Loader', 'ProcessThread', 'CSwitch', 'ReadyThread') }
function Get-DpcIsrBufferSizeKb { return 1024 }
function Get-DpcIsrBufferCount { return 64 }

function Get-DpcIsrProfileXml {
    $lines = @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<WindowsPerformanceRecorder Version="1.0" Author="win-forensics" Comments="dpcisr-trace 1.0.0: kernel DPC and interrupt events with the image, process, thread, context switch and ready thread events needed to attribute them to a module and a CPU and to see what ran on that CPU. No stacks.">',
        '  <Profiles>',
        '    <SystemCollector Id="WfDpcIsrSystemCollector" Name="NT Kernel Logger">',
        ('      <BufferSize Value="{0}"/>' -f (Get-DpcIsrBufferSizeKb)),
        ('      <Buffers Value="{0}"/>' -f (Get-DpcIsrBufferCount)),
        '    </SystemCollector>',
        '    <SystemProvider Id="WfDpcIsrSystemProvider">',
        '      <Keywords>'
    )
    foreach ($keyword in (Get-DpcIsrRequestedKeywords)) { $lines += ('        <Keyword Value="{0}"/>' -f $keyword) }
    $lines += @(
        '      </Keywords>',
        '    </SystemProvider>'
    )
    foreach ($mode in @('File', 'Memory')) {
        $lines += @(
            ('    <Profile Id="{0}.Verbose.{1}" Name="{0}" DetailLevel="Verbose" LoggingMode="{1}" Description="win-forensics dpcisr-trace: DPC, interrupt, image load, process, thread, context switch and ready thread events, per CPU, without stacks">' -f (Get-DpcIsrProfileName), $mode),
            '      <Collectors>',
            '        <SystemCollectorId Value="WfDpcIsrSystemCollector">',
            '          <SystemProviderId Value="WfDpcIsrSystemProvider"/>',
            '        </SystemCollectorId>',
            '      </Collectors>',
            '    </Profile>'
        )
    }
    $lines += @(
        '  </Profiles>',
        '</WindowsPerformanceRecorder>'
    )
    return (($lines -join "`n") + "`n")
}

# ---------------------------------------------------------------------------
# The wpr status text. Microsoft documents the shape (Status on the WPR
# command line page): labelled lines "Label : value", the collectors listing
# with "Collector Name", "Buffer Size (KB)" and "Events Lost" per collector,
# and bare keyword lines under a "System Keywords" header. Labels are read
# in English; what this PC prints is a verification item in the README, and
# a text without the loss labels makes the trace capture_failed, never
# observed.
# ---------------------------------------------------------------------------
function Test-DpcIsrRecordingText {
    param([string]$Text)
    return ([string]$Text -match '(?i)recording is in progress')
}

function Read-DpcIsrWprStatus {
    param([string]$Text)
    $result = [ordered]@{
        recording       = Test-DpcIsrRecordingText -Text $Text
        dropped_events  = $null
        logging_mode    = $null
        time_since_start = $null
        collectors      = @()
        fields          = @()
    }
    $collectors = New-Object 'System.Collections.Generic.List[object]'
    $fields = New-Object 'System.Collections.Generic.List[object]'
    $current = $null
    $listMode = ''
    $lineNo = 0
    foreach ($rawLine in ([string]$Text -split "`r?`n")) {
        $lineNo += 1
        $line = $rawLine.TrimEnd()
        if ($line.Trim().Length -eq 0) { continue }
        $m = [regex]::Match($line, '^\s*([^:]+?)\s*:\s*(.*)$')
        if ($m.Success -and $m.Groups[1].Value.Trim().Length -gt 0 -and $m.Groups[1].Value -notmatch '^\d{1,2}$') {
            $label = $m.Groups[1].Value.Trim()
            $value = $m.Groups[2].Value.Trim()
            $fields.Add([ordered]@{ line = $lineNo; label = $label; value = $value })
            $listMode = ''
            switch -Regex ($label) {
                '^Collector Name$' {
                    $current = [ordered]@{ name = $value; buffer_size_kb = $null; events_lost = $null; keywords = @(); stacks = @(); providers = @() }
                    $collectors.Add($current)
                }
                '^Buffer Size \(KB\)$' { if ($null -ne $current) { $current.buffer_size_kb = ConvertTo-DpcIsrInteger -Text $value } }
                '^Events Lost$' { if ($null -ne $current) { $current.events_lost = ConvertTo-DpcIsrInteger -Text $value } }
                '^Dropped events?$' { $result.dropped_events = ConvertTo-DpcIsrInteger -Text $value }
                '^Logging mode$' { $result.logging_mode = $value }
                '^Time since start$' { $result.time_since_start = $value }
            }
            # A provider line under a collector ("Name: keywords: level") is a
            # labelled line too; keep it with the collector.
            if ($listMode -eq '' -and $null -ne $current -and $label -notmatch '^(Collector Name|Buffer Size \(KB\)|Events Lost|Number of Buffers)$' -and $value -match '^0x') {
                $current.providers = @($current.providers) + @($line.Trim())
            }
            continue
        }
        # A bare line is a list header or a list item under a collector.
        $bare = $line.Trim()
        if ($bare -eq 'System Keywords') { $listMode = 'keywords'; continue }
        if ($bare -eq 'System Stacks') { $listMode = 'stacks'; continue }
        if ($bare -match '^(Providers|CaptureState Providers on (Save|Start))$') { $listMode = 'providers'; continue }
        if ($bare -match '^(Actively recording collectors|Recording system activity)') { $listMode = ''; continue }
        if ($null -eq $current -or $bare -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { continue }
        if ($listMode -eq 'keywords') { $current.keywords = @($current.keywords) + @($bare) }
        elseif ($listMode -eq 'stacks') { $current.stacks = @($current.stacks) + @($bare) }
    }
    $result.collectors = @($collectors.ToArray())
    $result.fields = @($fields.ToArray())
    return $result
}

function ConvertTo-DpcIsrInteger {
    param([string]$Text)
    $m = [regex]::Match([string]$Text, '^\s*(\d+)')
    if ($m.Success) { return [int64]$m.Groups[1].Value }
    return $null
}

function Get-DpcIsrEventsLost {
    # The session's loss as the status text states it: the sum over the
    # collectors' "Events Lost" lines when there is at least one, else the
    # "Dropped event" line, else null (unknown).
    param($Status)
    $sum = $null
    foreach ($collector in @($Status.collectors)) {
        if ($null -ne $collector.events_lost) { if ($null -eq $sum) { $sum = [int64]0 }; $sum += [int64]$collector.events_lost }
    }
    if ($null -ne $sum) { return $sum }
    if ($null -ne $Status.dropped_events) { return [int64]$Status.dropped_events }
    return $null
}

function Get-DpcIsrDirectoryBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }
    $total = [int64]0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse -ErrorAction SilentlyContinue)) { $total += [int64]$file.Length }
    return $total
}

function ConvertTo-DpcIsrRecordedText {
    # What the bundle records of a command line: the bundle root becomes the
    # placeholder <bundle> and the separators under it forward slashes, so a
    # manifest does not depend on where the dispatcher put the directory and
    # two runs of the fixture generator compare equal.
    param([string]$Text, [string]$BundleRoot)
    $out = [string]$Text
    if ($BundleRoot) {
        $index = $out.IndexOf($BundleRoot, [System.StringComparison]::Ordinal)
        while ($index -ge 0) {
            $tailStart = $index + $BundleRoot.Length
            $tailEnd = $tailStart
            while ($tailEnd -lt $out.Length -and $out[$tailEnd] -notmatch '[\s"!]') { $tailEnd += 1 }
            $tail = $out.Substring($tailStart, $tailEnd - $tailStart).Replace('\', '/')
            $out = $out.Substring(0, $index) + '<bundle>' + $tail + $out.Substring($tailEnd)
            $index = $out.IndexOf($BundleRoot, [System.StringComparison]::Ordinal)
        }
    }
    return $out
}

function Format-DpcIsrArgument {
    # One argument for a command line: quoted when it holds a space.
    param([string]$Value)
    if ($Value -match '[\s"]') { return ('"' + $Value.Replace('"', '\"') + '"') }
    return $Value
}

function Invoke-DpcIsrWpr {
    # One wpr.exe call through the shared process runner, recorded for the
    # session file: verb, arguments (with the bundle root as <bundle>), exit
    # code, timing, and the head of each stream.
    param([string]$Tool, [string]$Verb, [string[]]$Arguments, [int]$TimeoutSeconds, [System.Collections.Generic.List[object]]$Runs, [System.Collections.Generic.List[string]]$Log, [string]$BundleRoot = '')
    $argumentText = (@('-' + $Verb) + @($Arguments | ForEach-Object { Format-DpcIsrArgument -Value $_ })) -join ' '
    $run = Invoke-WfProcess -FilePath $Tool -Arguments $argumentText -TimeoutSeconds $TimeoutSeconds -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes 16777216
    $stdout = ConvertTo-DpcIsrRecordedText -Text ([string]$run['StdOut']) -BundleRoot $BundleRoot
    $stderr = ConvertTo-DpcIsrRecordedText -Text ([string]$run['StdErr']) -BundleRoot $BundleRoot
    $record = [ordered]@{
        verb        = $Verb
        arguments   = ConvertTo-DpcIsrRecordedText -Text $argumentText -BundleRoot $BundleRoot
        started     = [bool]$run['Started']
        exit_code   = $run['ExitCode']
        timed_out   = [bool]$run['TimedOut']
        duration_ms = $run['DurationMs']
        error       = $run['Error']
        stdout_head = $(if ($stdout.Length -gt 2000) { $stdout.Substring(0, 2000) } else { $stdout })
        stderr_head = $(if ($stderr.Length -gt 2000) { $stderr.Substring(0, 2000) } else { $stderr })
    }
    $Runs.Add($record)
    $Log.Add(('wpr -{0}: started {1}, exit code {2}, timed out {3}, {4} ms' -f $Verb, $record.started, $record.exit_code, $record.timed_out, $record.duration_ms))
    return $run
}

function Test-DpcIsrRunOk {
    param($Run)
    return ([bool]$Run['Started'] -and -not [bool]$Run['TimedOut'] -and -not [bool]$Run['Oversized'] -and $null -ne $Run['ExitCode'] -and [int]$Run['ExitCode'] -eq 0)
}

function Get-DpcIsrRunFailure {
    param($Run, [string]$Tool)
    if (-not [bool]$Run['Started']) { return ('the process could not be started: ' + [string]$Run['Error']) }
    if ([bool]$Run['TimedOut']) { return [string]$Run['Error'] }
    if ([bool]$Run['Oversized']) { return [string]$Run['Error'] }
    $said = (([string]$Run['StdOut'] + ' ' + [string]$Run['StdErr']).Trim() -replace '\s+', ' ')
    if ($said.Length -gt 500) { $said = $said.Substring(0, 500) }
    return ('{0} exited with code {1}: {2}' -f $Tool, $Run['ExitCode'], $said)
}

# ---------------------------------------------------------------------------
# Source 1: the trace session.
# ---------------------------------------------------------------------------
$invokeWprTrace = {
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    $id = [string]$Source['Id']
    $duration = [int]$Source['DurationSeconds']
    $maxTraceBytes = [int64]$Source['MaxTraceBytes']
    # The helper's artifact cap bounds the xperf report, not the trace; the
    # trace has its own cap (MaxTraceBytes).
    $null = $MaxArtifactBytes
    $entry = New-WfCollectorEntry -Id $id -Kind 'wpr' -Required ([bool]$Source['Required'])
    $roles = @{ 'dpcisr-trace.wprp' = 'config'; 'session.json' = 'report'; 'status.txt' = 'report'; 'trace.etl' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $etlPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/trace.etl')
    $tempDir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/temp')
    $profilePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/' + (Get-DpcIsrProfileFileName))
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $runs = New-Object 'System.Collections.Generic.List[object]'
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $tool = Get-WfWprPath
    $profileRef = $profilePath + '!' + (Get-DpcIsrProfileName) + '.Verbose'
    $startArguments = @($profileRef, '-filemode', '-recordtempto', $tempDir)
    $stopArguments = @($etlPath, ('win-forensics ' + $collectorName + ' ' + (ConvertTo-WfCompactUtc -Value $started)), '-skipPdbGen')
    $session = [ordered]@{
        tool                 = $tool
        profile_file         = $relativeDir + '/' + (Get-DpcIsrProfileFileName)
        profile_name         = Get-DpcIsrProfileName
        profile_id           = (Get-DpcIsrProfileName) + '.Verbose.File'
        requested_keywords   = @(Get-DpcIsrRequestedKeywords)
        buffer_size_kb       = Get-DpcIsrBufferSizeKb
        buffer_count         = Get-DpcIsrBufferCount
        logging_mode         = 'file'
        duration_seconds     = $duration
        max_trace_bytes      = $maxTraceBytes
        tool_timeout_seconds = $TimeoutSeconds
        events_lost_bound    = 0
        start_arguments      = @($startArguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
        stop_arguments       = @($stopArguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
        session_started_utc  = $null
        session_stopped_utc  = $null
        stopped_early_at_cap = $false
        temp_bytes_seen      = [int64]0
        trace_bytes          = $null
        status               = $null
        events_lost          = $null
        session_confirmed_stopped = $null
        runs                 = $runs
    }
    $sessionStarted = $false
    $sessionStopped = $false
    $confirmed = $null
    $readErrorKind = ''
    $readErrorMessage = ''
    $keepTrace = $false
    $statusText = $null
    $parsedStatus = $null
    $eventsLost = $null
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        Write-WfTextFile -Path $profilePath -Text (Get-DpcIsrProfileXml)
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $profilePath) }
        $entry.command = @($tool, '-start') + @($startArguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
        $entry.requested = [ordered]@{
            providers  = @('NT Kernel Logger')
            keywords   = @(Get-DpcIsrRequestedKeywords)
            stack_walk = @()
            counters   = @()
            options    = [ordered]@{
                profile_name = Get-DpcIsrProfileName; profile_id = (Get-DpcIsrProfileName) + '.Verbose.File'; logging_mode = 'file'
                buffer_size_kb = Get-DpcIsrBufferSizeKb; buffer_count = Get-DpcIsrBufferCount
                duration_seconds = $duration; max_trace_bytes = $maxTraceBytes; events_lost_bound = 0
                record_temp_to = $relativeDir + '/temp'; stop_arguments = @('-stop') + @($stopArguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
            }
        }
        $entry.buffers = [ordered]@{ size_kb = Get-DpcIsrBufferSizeKb; count = Get-DpcIsrBufferCount; mode = 'file' }

        # Preflight: the tool, the account, no recording in progress, and the
        # profile accepted by wpr itself (-profiles enumerates the profiles of
        # a file without starting anything).
        $account = Get-WfAccountInfo
        $present = Test-WfToolPresent -Path $tool
        $checks.Add([ordered]@{ name = 'tool_present'; ok = $present; detail = $tool })
        $elevated = [bool]$account['elevated']
        $checks.Add([ordered]@{ name = 'account_elevated'; ok = $elevated; detail = ('{0}; kernel tracing needs an elevated account (see the collector header for the citation)' -f $account['name']) })
        $idle = $false
        $accepted = $false
        if ($present -and $elevated) {
            $statusBefore = Invoke-DpcIsrWpr -Tool $tool -Verb 'status' -Arguments @() -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            $idle = ([bool]$statusBefore['Started'] -and -not [bool]$statusBefore['TimedOut'] -and -not (Test-DpcIsrRecordingText -Text ([string]$statusBefore['StdOut'])))
            $checks.Add([ordered]@{ name = 'no_recording_in_progress'; ok = $idle; detail = $(if ($idle) { 'wpr -status reports no recording' } else { 'wpr -status: ' + ((([string]$statusBefore['StdOut']) -replace '\s+', ' ').Trim()) }) })
            if ($idle) {
                $profiles = Invoke-DpcIsrWpr -Tool $tool -Verb 'profiles' -Arguments @($profilePath) -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
                $accepted = Test-DpcIsrRunOk -Run $profiles
                $checks.Add([ordered]@{ name = 'profile_accepted'; ok = $accepted; detail = $(if ($accepted) { 'wpr -profiles enumerated the profile file' } else { ConvertTo-DpcIsrRecordedText -Text (Get-DpcIsrRunFailure -Run $profiles -Tool $tool) -BundleRoot $BundleRoot }) })
            }
        }
        $preflightOk = ($present -and $elevated -and $idle -and $accepted)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks.ToArray()) }
        if (-not $present) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'the executable does not exist: ' + $tool
        } elseif (-not $elevated) {
            $readErrorKind = 'preflight'; $readErrorMessage = ('the account {0} is not elevated, and starting a kernel trace session is an Administrator operation; this collector never builds an elevation of its own (collectors/windows/README.md, Needs elevation)' -f $account['name'])
        } elseif (-not $idle) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'a WPR recording is already in progress on this machine and this collector never cancels a recording it did not start; stop it first, then rerun'
        } elseif (-not $accepted) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'wpr did not accept the recording profile: ' + $checks[$checks.Count - 1]['detail']
        }

        if (-not $readErrorKind) {
            $null = New-Item -ItemType Directory -Force -Path $tempDir
            $start = Invoke-DpcIsrWpr -Tool $tool -Verb 'start' -Arguments $startArguments -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            if (Test-DpcIsrRunOk -Run $start) {
                $sessionStarted = $true
                $sessionStart = Get-WfUtcNow
                $session.session_started_utc = ConvertTo-WfUtcString -Value $sessionStart
                $Log.Add(('session started, recording for {0} s' -f $duration))
            } else {
                # A start that failed may still have left a session behind;
                # the finally block below cancels and confirms in that case.
                $sessionStarted = ([bool]$start['Started'] -and [bool]$start['TimedOut'])
                $readErrorKind = 'preflight'
                $readErrorMessage = 'wpr -start was refused: ' + (ConvertTo-DpcIsrRecordedText -Text (Get-DpcIsrRunFailure -Run $start -Tool $tool) -BundleRoot $BundleRoot)
            }
        }

        if ($sessionStarted -and -not $readErrorKind) {
            # Record for the duration, one second at a time, watching the
            # temporary recording against the cap.
            $deadline = $sessionStart.AddSeconds($duration)
            while ((Get-WfUtcNow) -lt $deadline) {
                Start-WfSleep -Seconds 1
                $bytes = Get-DpcIsrDirectoryBytes -Path $tempDir
                if ($bytes -gt $session.temp_bytes_seen) { $session.temp_bytes_seen = $bytes }
                if ($bytes -gt $maxTraceBytes) {
                    $session.stopped_early_at_cap = $true
                    $Log.Add(('the temporary recording reached {0} bytes, above the cap of {1}; stopping early' -f $bytes, $maxTraceBytes))
                    break
                }
            }
            # Trace loss, from the tool's own output, read before the stop.
            $statusRun = Invoke-DpcIsrWpr -Tool $tool -Verb 'status' -Arguments @('profiles', 'collectors', '-details') -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            if ([bool]$statusRun['Started'] -and -not [bool]$statusRun['TimedOut']) {
                $statusText = [string]$statusRun['StdOut']
                if ([string]$statusRun['StdErr']) { $statusText = $statusText + "`n" + [string]$statusRun['StdErr'] }
                Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/status.txt')) -Text (($statusText -replace "`r`n", "`n").TrimEnd() + "`n")
                $parsedStatus = Read-DpcIsrWprStatus -Text $statusText
                $eventsLost = Get-DpcIsrEventsLost -Status $parsedStatus
                $session.status = [ordered]@{
                    recording = $parsedStatus.recording; dropped_events = $parsedStatus.dropped_events; logging_mode = $parsedStatus.logging_mode
                    time_since_start = $parsedStatus.time_since_start; collectors = @($parsedStatus.collectors)
                }
            }
            $session.events_lost = $eventsLost

            $sessionStopAt = Get-WfUtcNow
            $stop = Invoke-DpcIsrWpr -Tool $tool -Verb 'stop' -Arguments $stopArguments -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            $session.session_stopped_utc = ConvertTo-WfUtcString -Value $sessionStopAt
            if (Test-DpcIsrRunOk -Run $stop) {
                $sessionStopped = $true
            } else {
                $readErrorKind = 'other'
                $readErrorMessage = 'wpr -stop failed, so no trace was saved: ' + (ConvertTo-DpcIsrRecordedText -Text (Get-DpcIsrRunFailure -Run $stop -Tool $tool) -BundleRoot $BundleRoot)
            }
        }
    } catch {
        $readErrorKind = 'other'
        $readErrorMessage = 'the collector raised while running the trace session: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    } finally {
        # Every exit path ends here: a session that was started and not
        # stopped is cancelled, and whatever happened the stop is confirmed
        # (or reported as unconfirmed) from wpr -status.
        try {
            if ($sessionStarted -and -not $sessionStopped) {
                $cancel = Invoke-DpcIsrWpr -Tool $tool -Verb 'cancel' -Arguments @() -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
                $Log.Add('session cancelled after a failure: exit code ' + [string]$cancel['ExitCode'])
            }
            if ($sessionStarted) {
                $after = Invoke-DpcIsrWpr -Tool $tool -Verb 'status' -Arguments @() -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
                $confirmed = ([bool]$after['Started'] -and -not [bool]$after['TimedOut'] -and -not (Test-DpcIsrRecordingText -Text ([string]$after['StdOut'])))
            }
        } catch {
            $confirmed = $false
            $Log.Add('the stop could not be confirmed: ' + $_.Exception.Message)
        }
    }
    $session.session_confirmed_stopped = $confirmed
    if ($sessionStarted -and -not $confirmed) {
        $message = 'source ' + $id + ': the collector could not confirm that the trace session stopped; check "wpr -status" on the machine and run "wpr -cancel" if a recording is still in progress'
        $Notes.Add($message)
        $Log.Add($message)
    }

    # The trace file.
    $traceBytes = $null
    if (Test-Path -LiteralPath $etlPath) { $traceBytes = [int64](Get-Item -LiteralPath $etlPath).Length }
    $session.trace_bytes = $traceBytes
    $stopped = Get-WfUtcNow

    # Status.
    $met = $false
    if ($readErrorKind) {
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
    } elseif ($null -eq $traceBytes -or $traceBytes -le 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'wpr -stop exited 0 but the trace file is missing or empty'
    } elseif ($traceBytes -gt $maxTraceBytes) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the trace is {0} bytes, above the cap of {1}, and was not kept' -f $traceBytes, $maxTraceBytes)
    } elseif ($sessionStarted -and -not $confirmed) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the trace was saved but the collector could not confirm from wpr -status that the session stopped; the trace is kept and the note says what to check'
        $keepTrace = $true
    } elseif ($null -eq $eventsLost) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'events lost could not be read from the wpr -status output (no "Events Lost" or "Dropped event" line was found); a trace whose loss is unknown is not accepted as complete, so it is kept with this status and never read as a clean absence'
        $keepTrace = $true
    } elseif ($eventsLost -gt 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('wpr -status reported {0} events lost (the scenario bound is 0); the trace is kept because every event in it is real, but it is not the complete record and can never support an absence claim. Raise the buffer count in the profile or shorten the capture' -f $eventsLost)
        $keepTrace = $true
    } elseif ($session.stopped_early_at_cap) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the recording was stopped early because the temporary recording reached {0} bytes, above the cap of {1}; the trace is kept as a complete record of a shorter window' -f $session.temp_bytes_seen, $maxTraceBytes)
        $keepTrace = $true
    } else {
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
        $keepTrace = $true
    }
    # Requested versus enabled keywords, from the status text when it lists them.
    $enabledKeywords = $null
    $enabledStacks = $null
    $enabledProviders = $null
    $statusBufferKb = $null
    if ($null -ne $parsedStatus -and @($parsedStatus.collectors).Count -gt 0) {
        $enabledProviders = @($parsedStatus.collectors | ForEach-Object { [string]$_.name })
        $kernel = @($parsedStatus.collectors | Where-Object { [string]$_.name -eq 'NT Kernel Logger' })
        if ($kernel.Count -gt 0) {
            if (@($kernel[0].keywords).Count -gt 0) { $enabledKeywords = @($kernel[0].keywords) }
            $enabledStacks = @($kernel[0].stacks)
            $statusBufferKb = $kernel[0].buffer_size_kb
        }
        if ($null -ne $enabledKeywords -and $entry.status -eq 'observed') {
            $missing = @((Get-DpcIsrRequestedKeywords) | Where-Object { $enabledKeywords -notcontains $_ })
            if ($missing.Count -gt 0) {
                $entry.status = 'capture_failed'
                $entry.status_reason = ('requested settings were not enabled: wpr -status lists no {0} keyword for the NT Kernel Logger collector' -f ($missing -join ', '))
                $met = $false
            }
        } elseif ($null -eq $enabledKeywords -and $entry.status -eq 'observed') {
            $Notes.Add('source ' + $id + ': wpr -status listed the collector but no System Keywords, so enabled.keywords is null and the requested keywords are not verified from tool output')
        }
    }
    if ($null -ne $traceBytes -and -not $keepTrace -and (Test-Path -LiteralPath $etlPath)) {
        Remove-Item -LiteralPath $etlPath -Force
        $Log.Add('source ' + $id + ': the trace was removed because the source is ' + $entry.status + ' and the trace is not a usable record')
    }
    if ((Test-WfObservedStatus -Status $entry.status) -or $keepTrace) {
        if ($session.session_started_utc -and $session.session_stopped_utc) {
            $entry.raw_time_range = [ordered]@{ start = $session.session_started_utc; end = $session.session_stopped_utc; domain = 'system_time'; unit = 'iso_utc' }
        }
    }
    $entry.events_lost = $eventsLost
    if ($null -ne $statusBufferKb) { $entry.buffers.size_kb = $statusBufferKb }
    $entry.enabled = [ordered]@{
        providers   = $enabledProviders
        keywords    = $enabledKeywords
        stack_walk  = $enabledStacks
        counters    = @()
        options     = [ordered]@{
            dropped_events = $(if ($null -ne $parsedStatus) { $parsedStatus.dropped_events } else { $null })
            logging_mode = $(if ($null -ne $parsedStatus) { $parsedStatus.logging_mode } else { $null })
            session_started_utc = $session.session_started_utc
            session_stopped_utc = $session.session_stopped_utc
            trace_bytes = $traceBytes
            temp_bytes_seen = $session.temp_bytes_seen
            stopped_early_at_cap = $session.stopped_early_at_cap
            session_confirmed_stopped = $confirmed
        }
        verified_by = 'wpr -status profiles collectors -details, run before wpr -stop; its text is status.txt and the events lost it reports is events_lost'
    }
    $entry.exit_code = $(if ($runs.Count -gt 0) { $runs[$runs.Count - 1].exit_code } else { $null })
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = ('events lost {0}; trace {1} bytes; session confirmed stopped {2}; stopped early at cap {3}' -f $(if ($null -eq $eventsLost) { 'unknown' } else { $eventsLost }), $(if ($null -eq $traceBytes) { 'absent' } else { $traceBytes }), $(if ($null -eq $confirmed) { 'not applicable' } else { $confirmed }), $session.stopped_early_at_cap)
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/session.json')) -Object $session
    $Context['Tools'].Add((Get-WfToolRecord -Name 'wpr' -Version $null -Path $tool))
    if (((Test-WfObservedStatus -Status $entry.status) -or $keepTrace) -and (Test-Path -LiteralPath $etlPath)) {
        $Context['TraceEtl'] = $etlPath
        $Context['TraceEtlRelative'] = $relativeDir + '/trace.etl'
        $Context['TraceEventsLost'] = $eventsLost
        $Context['TraceStatus'] = $entry.status
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value $stopped
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# ---------------------------------------------------------------------------
# Source 2: the per CPU, per module report from the trace.
# ---------------------------------------------------------------------------
$invokeDpcIsrReport = {
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    $id = [string]$Source['Id']
    $xperfPath = [string]$Source['XperfPath']
    $entry = New-WfCollectorEntry -Id $id -Kind 'xperf' -Required ([bool]$Source['Required'])
    $roles = @{ 'command.json' = 'config'; 'result.json' = 'report'; 'dpcisr.txt' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $reportPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/dpcisr.txt')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $readErrorKind = ''
    $readErrorMessage = ''
    $run = $null
    $toolInfo = $null
    $pin = $null
    $arguments = @()
    $outputBytes = [int64]0
    $sectionsFound = @()
    $traceLost = $null
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $pins = Get-WfPinnedToolBuilds -Name 'xperf'
        $traceLost = $Context['TraceEventsLost']
        $hasTrace = $Context.ContainsKey('TraceEtl') -and (Test-Path -LiteralPath ([string]$Context['TraceEtl']))
        if ($hasTrace) {
            $arguments = @('-i', [string]$Context['TraceEtl'], '-a', 'dpcisr')
            if ($null -ne $traceLost -and [int64]$traceLost -gt 0) { $arguments += '-tle' }
        }
        $encoding = Get-WfConsoleOutputEncoding
        $config = [ordered]@{
            tool               = $(if ($xperfPath) { $xperfPath } else { $null })
            tool_source        = 'operator supplied (-XperfPath); xperf.exe is part of the Windows Performance Toolkit in the Windows ADK, not inbox on Windows, and runs only when its SHA-256 and version match a pinned build'
            pinned_builds      = @($pins | ForEach-Object { [ordered]@{ version = $_['Version']; sha256 = $_['Sha256']; source = $_['Source'] } })
            arguments          = @($arguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
            trace              = $(if ($hasTrace) { [string]$Context['TraceEtlRelative'] } else { $null })
            trace_events_lost  = $traceLost
            timeout_seconds    = $TimeoutSeconds
            max_artifact_bytes = $MaxArtifactBytes
            output_encoding    = [string]$encoding.WebName
            output_code_page   = [int]$encoding.CodePage
            line_endings       = 'lf'
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($(if ($xperfPath) { $xperfPath } else { 'xperf.exe' })) + @($arguments | ForEach-Object { ConvertTo-DpcIsrRecordedText -Text $_ -BundleRoot $BundleRoot })
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        $checks = New-Object 'System.Collections.Generic.List[object]'
        $checks.Add([ordered]@{ name = 'trace_present'; ok = $hasTrace; detail = $(if ($hasTrace) { [string]$Context['TraceEtlRelative'] } else { 'the wpr_trace source produced no trace' }) })
        $named = [bool]$xperfPath
        $checks.Add([ordered]@{ name = 'tool_named'; ok = $named; detail = $(if ($named) { $xperfPath } else { '-XperfPath was not given' }) })
        $exists = $false
        $pinned = $false
        if ($named) {
            $toolInfo = Get-WfExternalToolInfo -Path $xperfPath
            $exists = [bool]$toolInfo['Exists']
            $checks.Add([ordered]@{ name = 'tool_present'; ok = $exists; detail = $(if ($exists) { ('sha256 {0}, version {1}' -f $toolInfo['Sha256'], $toolInfo['Version']) } else { 'the file does not exist' }) })
            if ($exists) {
                foreach ($candidate in $pins) {
                    if ([string]$candidate['Sha256'] -eq [string]$toolInfo['Sha256'] -and [string]$candidate['Version'] -eq [string]$toolInfo['Version']) { $pin = $candidate }
                }
                $pinned = ($null -ne $pin)
                $checks.Add([ordered]@{ name = 'tool_pinned'; ok = $pinned; detail = $(if ($pinned) { 'matches the pinned build ' + [string]$pin['Version'] + ' from ' + [string]$pin['Source'] } elseif ($pins.Count -eq 0) { 'no xperf build is pinned in _common.ps1 (Get-WfPinnedToolBuilds); which Windows Performance Toolkit release goes on the PC is an open decision' } else { ('the file (sha256 {0}, version {1}) matches none of the {2} pinned builds' -f $toolInfo['Sha256'], $toolInfo['Version'], $pins.Count) }) })
            }
        }
        $preflightOk = ($hasTrace -and $named -and $exists -and $pinned)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks.ToArray()) }
        if (-not $hasTrace) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'there is no trace to report on: the wpr_trace source is ' + [string]$(if ($Context.ContainsKey('TraceStatus')) { $Context['TraceStatus'] } else { 'without a trace file' })
        } elseif (-not $named) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'xperf.exe is not inbox on Windows and -XperfPath was not given; the trace is in the bundle and the report can be produced later on a machine with the Windows Performance Toolkit (collectors/windows/README.md)'
        } elseif (-not $exists) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'the executable does not exist: ' + $xperfPath + $(if ($toolInfo['Error']) { ' (' + [string]$toolInfo['Error'] + ')' } else { '' })
        } elseif (-not $pinned) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'refused to run an unpinned tool: ' + [string]$checks[$checks.Count - 1]['detail']
        }

        if (-not $readErrorKind) {
            $Context['Tools'].Add([ordered]@{ name = 'xperf'; version = [string]$toolInfo['Version']; path = $xperfPath; sha256 = [string]$toolInfo['Sha256'] })
            $argumentText = (@($arguments | ForEach-Object { Format-DpcIsrArgument -Value $_ })) -join ' '
            $run = Invoke-WfProcess -FilePath $xperfPath -Arguments $argumentText -TimeoutSeconds $TimeoutSeconds -OutputEncoding $encoding -MaxBytes $MaxArtifactBytes
            if (-not $run['Started']) {
                $readErrorKind = 'other'; $readErrorMessage = 'the process could not be started: ' + [string]$run['Error']
            } elseif ($run['TimedOut']) {
                $readErrorKind = 'timeout'; $readErrorMessage = [string]$run['Error']
            } elseif ($run['Oversized']) {
                $readErrorKind = 'other'; $readErrorMessage = [string]$run['Error']
            } elseif ([int]$run['ExitCode'] -ne 0) {
                $readErrorKind = 'other'; $readErrorMessage = ConvertTo-DpcIsrRecordedText -Text (Get-DpcIsrRunFailure -Run $run -Tool $xperfPath) -BundleRoot $BundleRoot
            } else {
                $text = ([string]$run['StdOut']) -replace "`r`n", "`n"
                if ($text.Trim().Length -eq 0) {
                    $readErrorKind = 'other'; $readErrorMessage = 'xperf exited with code 0 and printed nothing'
                } else {
                    foreach ($section in @('DPC Info', 'Interrupt Info')) { if ($text -match ('(?m)^\s*' + $section + '\s*$')) { $sectionsFound += $section } }
                    $outputBytes = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($text.TrimEnd() + "`n")
                    if ($outputBytes -gt $MaxArtifactBytes) {
                        $readErrorKind = 'other'; $readErrorMessage = ('the report is {0} bytes, above the cap of {1}, and was not kept' -f $outputBytes, $MaxArtifactBytes)
                    } elseif ($sectionsFound.Count -lt 2) {
                        $readErrorKind = 'other'; $readErrorMessage = 'xperf exited with code 0 but the output has no DPC Info and Interrupt Info sections, so it is not the dpcisr report the decoder reads'
                    } else {
                        Write-WfTextFile -Path $reportPath -Text ($text.TrimEnd() + "`n")
                    }
                }
            }
        }
    } catch {
        $readErrorKind = 'other'
        $readErrorMessage = 'the collector raised while producing the report: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    }
    $stopped = Get-WfUtcNow
    $met = $false
    if ($readErrorKind) {
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
        if (Test-Path -LiteralPath $reportPath) { Remove-Item -LiteralPath $reportPath -Force }
    } elseif ($null -ne $traceLost -and [int64]$traceLost -gt 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the report was produced with -tle (tolerate lost events) from a trace that lost {0} events; its numbers describe the events that were recorded and not the whole window, so the report is kept with this status and never supports an absence claim' -f $traceLost)
        $Notes.Add('source ' + $id + ': the dpcisr report comes from a trace with lost events and is kept as capture_failed; read it as a lower bound, never as an absence')
    } elseif ($Context.ContainsKey('TraceStatus') -and -not (Test-WfObservedStatus -Status ([string]$Context['TraceStatus']))) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the report was produced from a trace whose source is ' + [string]$Context['TraceStatus'] + '; it inherits that status'
    } else {
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
    }
    $report = [ordered]@{
        started_utc    = ConvertTo-WfUtcString -Value $started
        stopped_utc    = ConvertTo-WfUtcString -Value $stopped
        tool_sha256    = $(if ($null -ne $toolInfo) { $toolInfo['Sha256'] } else { $null })
        tool_version   = $(if ($null -ne $toolInfo) { $toolInfo['Version'] } else { $null })
        pinned_build   = $(if ($null -ne $pin) { [ordered]@{ version = $pin['Version']; sha256 = $pin['Sha256']; source = $pin['Source'] } } else { $null })
        exit_code      = $(if ($null -ne $run) { $run['ExitCode'] } else { $null })
        timed_out      = $(if ($null -ne $run) { [bool]$run['TimedOut'] } else { $false })
        duration_ms    = $(if ($null -ne $run) { $run['DurationMs'] } else { $null })
        stdout_bytes   = $outputBytes
        stderr         = $(if ($null -ne $run) { ([string]$run['StdErr']).Trim() } else { $null })
        sections_found = @($sectionsFound)
        trace_events_lost = $traceLost
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
    if ((Test-WfObservedStatus -Status $entry.status) -or (Test-Path -LiteralPath $reportPath)) {
        if ($Context.ContainsKey('TraceEtl')) { $entry.raw_time_range = [ordered]@{ start = ConvertTo-WfUtcString -Value $started; end = ConvertTo-WfUtcString -Value $stopped; domain = 'system_time'; unit = 'iso_utc' } }
    }
    $entry.exit_code = $report.exit_code
    $entry.enabled = [ordered]@{
        providers = @(); keywords = @(); stack_walk = @(); counters = @()
        options   = [ordered]@{
            exit_code = $report.exit_code; timed_out = $report.timed_out; duration_ms = $report.duration_ms; stdout_bytes = $outputBytes
            sections_found = @($sectionsFound); tool_sha256 = $report.tool_sha256; tool_version = $report.tool_version
        }
        verified_by = 'the tool file hash and version in result.json matched the pinned build before the run; the process exit code, timing and byte count are in result.json; the report is dpcisr.txt'
    }
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = ('exit code {0}; sections {1}; trace events lost {2}' -f $report.exit_code, ($sectionsFound -join ', '), $(if ($null -eq $traceLost) { 'unknown' } else { $traceLost }))
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value $stopped
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

if ($DurationSeconds -lt 5 -or $DurationSeconds -gt 300) {
    [Console]::Error.WriteLine($collectorName + ': DurationSeconds must be between 5 and 300')
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}
if ($MaxTraceBytes -lt 16777216 -or $MaxTraceBytes -gt 17179869184) {
    [Console]::Error.WriteLine($collectorName + ': MaxTraceBytes must be between 16 MiB and 16 GiB')
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}

$definition = @{
    Name                     = $collectorName
    Version                  = '1.0.0'
    Question                 = 'Where do DPC and interrupt time land, per CPU and per module, while the PC is in use, and what ran on those CPUs?'
    RequestedDurationSeconds = $DurationSeconds
    Calibration              = @{
        status = 'not_collected'
        method = 'none in this collector: the trace timestamps are QPC (the ETW default clock) and the calibration pairs that relate them to system time come from the clock collector, which is a separate piece; until it runs alongside, the trace is unaligned to every system_time source'
    }
    Sources                  = @(
        @{
            Id              = 'wpr_trace'
            Type            = 'script'
            Required        = $true
            Invoke          = $invokeWprTrace
            DurationSeconds = $DurationSeconds
            MaxTraceBytes   = $MaxTraceBytes
            Expectation     = 'wpr starts the profile, records for the requested duration, reports zero events lost for every collector just before the stop, saves a non empty trace within the cap, and wpr -status confirms no recording remains'
        },
        @{
            Id          = 'dpcisr_report'
            Type        = 'script'
            Required    = $false
            Invoke      = $invokeDpcIsrReport
            XperfPath   = $XperfPath
            Expectation = 'a pinned xperf.exe exits 0 on "xperf -i trace.etl -a dpcisr" and prints the DPC Info and Interrupt Info sections, from a trace with zero events lost'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
