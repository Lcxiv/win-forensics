# dpcisr-trace: Where do DPC and interrupt time land, per CPU and per module, while the PC is in use?
#
# A bounded live capture. Runs under Windows PowerShell 5.1 as an elevated
# account (kernel tracing is an Administrator operation, see below), writes
# one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints one
# JSON summary line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md for the interface, the artifact formats, the
# privacy statement, the elevation note and the facts still to be verified
# on a real machine.
#
# Sources:
#
#   wpr_trace       one Windows Performance Recorder session from the profile
#                   embedded below (NT Kernel Logger: Interrupt, DPC, Loader),
#                   file mode, under its own WPR instance name, started and
#                   stopped by this script within -DurationSeconds; the
#                   profile, the wpr status text read right after the start
#                   (enabled keywords), the tracerpt summary of the saved
#                   trace (final events lost and buffers lost) and a session
#                   record are the artifacts. The trace itself never leaves
#                   the machine (see "Privacy" below).
#   dpcisr_report   the per CPU, per module DPC and ISR report of that trace,
#                   "xperf -i trace.etl -a dpcisr", which only runs on the PC
#                   when the operator names an xperf.exe (-XperfPath) whose
#                   SHA-256 and version are pinned in _common.ps1
#                   (Get-WfPinnedToolBuilds); scripts/decode_dpcisr.py turns
#                   the report into the dpcisr_module_cpu and dpcisr_interval
#                   tables
#
# Why these three keywords, and no others (Keyword (in SystemProvider),
# https://learn.microsoft.com/windows-hardware/test/wpt/keyword--in-systemprovider-):
#   Interrupt  "Interrupts are logged" (the ISR events, EVENT_TRACE_FLAG_INTERRUPT)
#   DPC        "Deferred procedure calls are logged" (EVENT_TRACE_FLAG_DPC)
#   Loader     "Kernel and user mode load and unload events are logged": the
#              Image events whose address ranges name the module behind a
#              DPC or ISR routine address ("Use the address with the Image
#              events to find which image started"; "The image events are
#              read to construct the memory regions that map to certain
#              modules", https://learn.microsoft.com/windows/win32/etw/dpc)
# The CPU of each event comes from ETW itself (the buffer context of every
# event carries the processor number,
# https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-etw_buffer_context),
# so nothing else is needed to attribute a DPC or ISR to a module and a CPU.
# Process, thread and scheduling keywords are deliberately absent: the
# kernel Process events carry every process's full command line and user
# SID (https://learn.microsoft.com/windows/win32/etw/process-typegroup1),
# which must not be recorded here. No stacks.
#
# Privacy. A kernel session also writes system configuration events on its
# own ("the kernel session automatically generates hardware configuration
# events; you do not enable these events",
# https://learn.microsoft.com/windows/win32/etw/systemconfig), and the NIC
# configuration event carries the adapter's hardware address and IP
# addresses (https://learn.microsoft.com/windows/win32/etw/systemconfig-nic).
# The flag that suppresses that rundown (EVENT_TRACE_FLAG_NO_SYSCONFIG,
# https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
# has no keyword in a WPR profile. The saved trace therefore stays on the
# PC: it is written under <OutputDirectory>\private, read there by tracerpt
# and (when pinned) xperf, and removed before the collector exits, on every
# exit path. Only its size and SHA-256 are recorded. The texts that do leave
# (the status text, the summary, the report) pass through the helper's
# hardware address pseudonyms as a second guard.
#
# WPR command line: https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options
# Profile XML: https://learn.microsoft.com/windows-hardware/test/wpt/recording-profile-xml-reference
# Loss. ETW discards an event when every buffer is full and counts it in
# EventsLost; buffers that could not be written to the log are counted in
# LogBuffersLost (EVENT_TRACE_PROPERTIES, above), and the saved trace's
# header keeps EventsLost and BuffersLost
# (https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header).
# The final figures are read after the stop from "tracerpt <trace> -summary"
# (https://learn.microsoft.com/windows-server/administration/windows-commands/tracerpt);
# a figure that is missing or not a number is null, and a null or non zero
# figure makes the trace capture_failed. The trace is never observed from a
# live snapshot alone.
#
# Elevation: "Only users running with elevated administrative privileges,
# users in the Performance Log Users group, and applications running as
# LocalSystem, LocalService or NetworkService can control event tracing
# sessions" (https://learn.microsoft.com/windows/win32/etw/controlling-event-tracing-sessions);
# for a non administrator to start a system (kernel) profiling session
# Microsoft describes granting the profile privilege and access on the
# session and provider GUIDs
# (https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session),
# none of which this collector sets up. It refuses to start a session when
# the account is not elevated and reports not_collected with that reason.
# It builds no scheduled task, service or other persistent elevation.
#
# Read only toward the machine: it changes no setting, installs nothing,
# touches no process, and the one thing it starts (the trace session, under
# a WPR instance name of its own so status, stop and cancel reach only that
# session) it stops on every exit path, cancels when the stop did not end
# it, and confirms from wpr -status; it reports when it could not confirm.
# It never cancels a recording it did not start: a WPR recording that is
# already in progress on the default instance makes the source
# not_collected. Anti-cheat note: ETW observes from the kernel, outside
# every process; nothing here opens a handle to, injects into, or changes
# the priority or affinity of any process. Easy Anti-Cheat's documentation
# does not state how it treats ETW sessions, so that is recorded as unknown
# in the README rather than asserted.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long the trace session records, in seconds (5 to 300), measured on
    # a monotonic clock from the moment wpr -start returned to the moment
    # wpr -stop is issued. The stop is issued when this elapses, when the
    # recording reaches -MaxTraceBytes, or when anything fails.
    [int]$DurationSeconds = 60,
    # Cap on the trace, in bytes (16 MiB to 16 GiB). The recording is stopped
    # early when the temporary recording reaches it; a saved trace above it
    # is not read.
    [long]$MaxTraceBytes = 2147483648,
    # Full path of xperf.exe from the Windows Performance Toolkit, when the
    # operator has one. It runs only when its SHA-256 and file version match
    # a build pinned in _common.ps1; otherwise the report is not_collected.
    [string]$XperfPath = '',
    # Cap on the size of the xperf report and of the tracerpt summary, in
    # bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for each long tool process (wpr -start, wpr -stop, tracerpt,
    # xperf), in seconds (1 to 3600). Status, profile enumeration and cancel
    # calls have their own fixed 30 second deadline. A process that does not
    # finish in time is stopped and the source is recorded as failed; the
    # trace session is then cancelled.
    [int]$TimeoutSeconds = 120
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
# and lost buffers are the check on that choice.
# ---------------------------------------------------------------------------
function Get-DpcIsrProfileName { return 'WfDpcIsrTrace' }
function Get-DpcIsrProfileFileName { return 'dpcisr-trace.wprp' }
function Get-DpcIsrRequestedKeywords { return @('Interrupt', 'DPC', 'Loader') }
function Get-DpcIsrBufferSizeKb { return 1024 }
function Get-DpcIsrBufferCount { return 64 }
function Get-DpcIsrShortTimeoutSeconds { return 30 }
function Get-DpcIsrKernelCollectorName { return 'NT Kernel Logger' }

function Get-DpcIsrProfileXml {
    $lines = @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<WindowsPerformanceRecorder Version="1.0" Author="win-forensics" Comments="dpcisr-trace 1.1.0: kernel DPC and interrupt events with the image load events needed to attribute them to a module; the CPU comes from each event itself. No process, thread or scheduling events, no stacks.">',
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
            ('    <Profile Id="{0}.Verbose.{1}" Name="{0}" DetailLevel="Verbose" LoggingMode="{1}" Description="win-forensics dpcisr-trace: DPC, interrupt and image load events, per CPU, without stacks">' -f (Get-DpcIsrProfileName), $mode),
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
# Tool text readers. Microsoft documents the shape of the wpr status text
# (Status on the WPR command line page): labelled lines "Label : value", the
# collectors listing with "Collector Name", "Buffer Size (KB)" and "Events
# Lost" per collector, bare keyword lines under a "System Keywords" header,
# and "If buffers have been lost, those buffers are listed". It documents
# that tracerpt -summary writes a summary report and nothing about its text.
# Labels are read in English; what this PC prints is a verification item in
# the README. Every figure that is missing or not a whole number is null,
# and null never becomes zero.
# ---------------------------------------------------------------------------
function ConvertTo-DpcIsrInteger {
    # The whole value must be a decimal integer; "1,234" or "n/a" is null.
    param([string]$Text)
    if ([string]$Text -match '^\s*(\d+)\s*$') { return [int64]$Matches[1] }
    return $null
}

function Get-DpcIsrStatusState {
    # active, idle or unknown, from one "wpr -status" run. Only a run that
    # exited 0 with a recognised text counts; an error, an empty or capped
    # output or a text in words the reader does not know is unknown, which
    # fails preflight and never confirms a stop.
    param($Run)
    if (-not [bool]$Run['Started'] -or [bool]$Run['TimedOut'] -or [bool]$Run['Oversized']) { return 'unknown' }
    if ($null -eq $Run['ExitCode'] -or [int]$Run['ExitCode'] -ne 0) { return 'unknown' }
    $text = ([string]$Run['StdOut'] + "`n" + [string]$Run['StdErr'])
    if ($text -match '(?i)recording is in progress') { return 'active' }
    if ($text -match '(?i)\bnot recording\b') { return 'idle' }
    return 'unknown'
}

function Read-DpcIsrWprStatus {
    param([string]$Text)
    $result = [ordered]@{
        dropped_events    = $null
        dropped_events_text = $null
        logging_mode      = $null
        time_since_start  = $null
        buffers_lost_listed = $false
        collectors        = @()
    }
    $collectors = New-Object 'System.Collections.Generic.List[object]'
    $current = $null
    $listMode = ''
    foreach ($rawLine in ([string]$Text -split "`r?`n")) {
        $line = $rawLine.TrimEnd()
        if ($line.Trim().Length -eq 0) { continue }
        if ($line -match '(?i)buffers? lost') { $result.buffers_lost_listed = $true }
        $m = [regex]::Match($line, '^\s*([^:]+?)\s*:\s*(.*)$')
        if ($m.Success -and $m.Groups[1].Value.Trim().Length -gt 0 -and $m.Groups[1].Value -notmatch '^\d{1,2}$') {
            $label = $m.Groups[1].Value.Trim()
            $value = $m.Groups[2].Value.Trim()
            $listMode = ''
            switch -Regex ($label) {
                '^Collector Name$' {
                    $current = [ordered]@{ name = $value; buffer_size_kb = $null; events_lost = $null; events_lost_text = $null; buffers_lost = $null; buffers_lost_text = $null; keywords = @(); stacks = @() }
                    $collectors.Add($current)
                }
                '^Buffer Size \(KB\)$' { if ($null -ne $current) { $current.buffer_size_kb = ConvertTo-DpcIsrInteger -Text $value } }
                '^Events Lost$' { if ($null -ne $current) { $current.events_lost = ConvertTo-DpcIsrInteger -Text $value; $current.events_lost_text = $value } }
                '^Buffers Lost$' { if ($null -ne $current) { $current.buffers_lost = ConvertTo-DpcIsrInteger -Text $value; $current.buffers_lost_text = $value } }
                '^Dropped events?$' { $result.dropped_events = ConvertTo-DpcIsrInteger -Text $value; $result.dropped_events_text = $value }
                '^Logging mode$' { $result.logging_mode = $value }
                '^Time since start$' { $result.time_since_start = $value }
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
    return $result
}

function Read-DpcIsrSummary {
    # The tracerpt summary: one figure for events lost and one for buffers
    # lost, each from a line whose label names it ("... Events Lost ..." or
    # "... Buffers Lost ...", colon or spaces before the value). Two lines
    # that disagree, a non numeric value or no line at all give null.
    param([string]$Text)
    $result = [ordered]@{ events_lost = $null; events_lost_lines = 0; buffers_lost = $null; buffers_lost_lines = 0; labelled_lines = 0 }
    $events = New-Object 'System.Collections.Generic.List[object]'
    $buffers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rawLine in ([string]$Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        # "Label : value" or "Label   value" (two or more spaces); a label may
        # itself hold runs of spaces, which are collapsed before it is read.
        $m = [regex]::Match($line, '^([A-Za-z][A-Za-z ()]*[A-Za-z)])\s*(?::\s*(.*)|\s{2,}(\S.*))$')
        if (-not $m.Success) { continue }
        $result.labelled_lines += 1
        $label = ($m.Groups[1].Value.Trim() -replace '\s+', ' ')
        $valueText = $(if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value })
        $value = ConvertTo-DpcIsrInteger -Text $valueText
        if ($label -match '(?i)^(total\s+)?events?\s+lost$') { $events.Add($value) }
        elseif ($label -match '(?i)^(total\s+)?(log\s+)?buffers?\s+lost$') { $buffers.Add($value) }
    }
    $result.events_lost_lines = $events.Count
    $result.buffers_lost_lines = $buffers.Count
    $result.events_lost = Resolve-DpcIsrSingleFigure -Values $events
    $result.buffers_lost = Resolve-DpcIsrSingleFigure -Values $buffers
    return $result
}

function Resolve-DpcIsrSingleFigure {
    # One figure from the lines that named it: null when there is none, when
    # any is not a number, or when they disagree.
    param([System.Collections.Generic.List[object]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $first = $Values[0]
    if ($null -eq $first) { return $null }
    foreach ($value in $Values) { if ($null -eq $value -or [int64]$value -ne [int64]$first) { return $null } }
    return [int64]$first
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

function Invoke-DpcIsrTool {
    # One tool call through the shared process runner, recorded for the
    # session file: tool, verb, arguments (with the bundle root as <bundle>),
    # exit code, timing, and the head of each stream. For wpr the instance
    # name, when given, is the last parameter, as Microsoft documents.
    param([string]$Tool, [string]$Verb, [string[]]$Arguments, [string]$Instance = '', [int]$TimeoutSeconds, [System.Collections.Generic.List[object]]$Runs, [System.Collections.Generic.List[string]]$Log, [string]$BundleRoot = '', [int64]$MaxBytes = 16777216)
    $parts = @()
    if ($Verb) { $parts += ('-' + $Verb) }
    $parts += @($Arguments | ForEach-Object { Format-DpcIsrArgument -Value $_ })
    if ($Instance) { $parts += @('-instancename', (Format-DpcIsrArgument -Value $Instance)) }
    $argumentText = ($parts -join ' ')
    $run = Invoke-WfProcess -FilePath $Tool -Arguments $argumentText -TimeoutSeconds $TimeoutSeconds -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes $MaxBytes
    $stdout = ConvertTo-DpcIsrRecordedText -Text ([string]$run['StdOut']) -BundleRoot $BundleRoot
    $stderr = ConvertTo-DpcIsrRecordedText -Text ([string]$run['StdErr']) -BundleRoot $BundleRoot
    $record = [ordered]@{
        tool        = ($Tool -split '[\\/]')[-1]
        verb        = $(if ($Verb) { $Verb } else { $null })
        arguments   = ConvertTo-DpcIsrRecordedText -Text $argumentText -BundleRoot $BundleRoot
        started     = [bool]$run['Started']
        exit_code   = $run['ExitCode']
        timed_out   = [bool]$run['TimedOut']
        oversized   = [bool]$run['Oversized']
        duration_ms = $run['DurationMs']
        error       = $run['Error']
        stdout_head = $(if ($stdout.Length -gt 2000) { $stdout.Substring(0, 2000) } else { $stdout })
        stderr_head = $(if ($stderr.Length -gt 2000) { $stderr.Substring(0, 2000) } else { $stderr })
    }
    $Runs.Add($record)
    $Log.Add(('{0} {1}: started {2}, exit code {3}, timed out {4}, {5} ms' -f $record.tool, $(if ($Verb) { '-' + $Verb } else { 'run' }), $record.started, $record.exit_code, $record.timed_out, $record.duration_ms))
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

function Get-DpcIsrPrivateDir {
    # Where the trace lives while the collector runs: inside the output
    # directory (a collector writes nowhere else) but outside raw/, and
    # removed before the collector exits. Nothing under it is ever listed.
    param([string]$BundleRoot)
    return [System.IO.Path]::Combine($BundleRoot, 'private')
}

$removePrivate = {
    # The definition's Cleanup: runs after the last source and on the way out
    # of a failure. The trace and WPR's temporary recording never leave the
    # machine.
    param([string]$BundleRoot, [System.Collections.Generic.List[string]]$Log)
    $privateDir = Get-DpcIsrPrivateDir -BundleRoot $BundleRoot
    if (Test-Path -LiteralPath $privateDir) {
        $bytes = Get-DpcIsrDirectoryBytes -Path $privateDir
        Remove-Item -LiteralPath $privateDir -Recurse -Force
        $Log.Add(('private directory removed ({0} bytes): the kernel trace stays on the machine' -f $bytes))
    }
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
    $short = Get-DpcIsrShortTimeoutSeconds
    $entry = New-WfCollectorEntry -Id $id -Kind 'wpr' -Required ([bool]$Source['Required'])
    $roles = @{ 'dpcisr-trace.wprp' = 'config'; 'session.json' = 'report'; 'status.txt' = 'report'; 'tracerpt-summary.txt' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $privateDir = Get-DpcIsrPrivateDir -BundleRoot $BundleRoot
    $etlPath = [System.IO.Path]::Combine($privateDir, 'trace.etl')
    $tempDir = [System.IO.Path]::Combine($privateDir, 'temp')
    $profilePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/' + (Get-DpcIsrProfileFileName))
    $summaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/tracerpt-summary.txt')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $runs = New-Object 'System.Collections.Generic.List[object]'
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $tool = Get-WfWprPath
    $tracerpt = Get-WfTracerptPath
    $instance = 'WfDpcIsrTrace-' + (ConvertTo-WfCompactUtc -Value $started)
    $profileRef = $profilePath + '!' + (Get-DpcIsrProfileName) + '.Verbose'
    $startArguments = @($profileRef, '-filemode', '-recordtempto', $tempDir)
    $stopArguments = @($etlPath, ('win-forensics ' + $collectorName + ' ' + (ConvertTo-WfCompactUtc -Value $started)), '-skipPdbGen')
    $recorded = { param([string]$Text) return (ConvertTo-DpcIsrRecordedText -Text $Text -BundleRoot $BundleRoot) }
    $worstCase = $duration + 2 * $TimeoutSeconds + 5 * $short
    $session = [ordered]@{
        tool                 = $tool
        tracerpt             = $tracerpt
        instance_name        = $instance
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
        short_timeout_seconds = $short
        worst_case_seconds   = $worstCase
        events_lost_bound    = 0
        buffers_lost_bound   = 0
        start_arguments      = @($startArguments | ForEach-Object { & $recorded $_ })
        stop_arguments       = @($stopArguments | ForEach-Object { & $recorded $_ })
        session_started_utc  = $null
        session_stop_issued_utc = $null
        recording_seconds    = $null
        stopped_early_at_cap = $false
        temp_bytes_seen      = [int64]0
        trace_bytes          = $null
        trace_sha256         = $null
        trace_kept_in_bundle = $false
        trace_removed_reason = 'the kernel trace carries system configuration events with hardware and network addresses and never leaves the machine (collectors/windows/README.md, privacy)'
        status_after_start   = $null
        settings_verified    = $null
        final                = [ordered]@{ events_lost = $null; buffers_lost = $null; source = 'tracerpt -summary of the saved trace'; events_lost_lines = 0; buffers_lost_lines = 0; labelled_lines = 0; protection = $null }
        session_state_after_stop = $null
        session_state_final  = $null
        session_confirmed_stopped = $null
        runs                 = $runs
    }
    $sessionStarted = $false
    $stopIssued = $false
    $stateAfterStop = $null
    $finalState = $null
    $readErrorKind = ''
    $readErrorMessage = ''
    $statusText = $null
    $parsedStatus = $null
    $enabledKeywords = $null
    $enabledStacks = $null
    $enabledProviders = $null
    $statusBufferKb = $null
    $earlyEventsLost = $null
    $settingsReason = $null
    $summary = $null
    $summaryRun = $null
    $traceBytes = $null
    $traceSha = $null
    $monotonicStart = $null
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        Write-WfTextFile -Path $profilePath -Text (Get-DpcIsrProfileXml)
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $profilePath) }
        $entry.command = @($tool, '-start') + @($startArguments | ForEach-Object { & $recorded $_ }) + @('-instancename', $instance)
        $entry.requested = [ordered]@{
            providers  = @(Get-DpcIsrKernelCollectorName)
            keywords   = @(Get-DpcIsrRequestedKeywords)
            stack_walk = @()
            counters   = @()
            options    = [ordered]@{
                profile_name = Get-DpcIsrProfileName; profile_id = (Get-DpcIsrProfileName) + '.Verbose.File'; logging_mode = 'file'; instance_name = $instance
                buffer_size_kb = Get-DpcIsrBufferSizeKb; buffer_count = Get-DpcIsrBufferCount
                duration_seconds = $duration; max_trace_bytes = $maxTraceBytes; events_lost_bound = 0; buffers_lost_bound = 0
                record_temp_to = '<bundle>/private/temp'; trace_path = '<bundle>/private/trace.etl'; trace_kept_in_bundle = $false
                stop_arguments = @('-stop') + @($stopArguments | ForEach-Object { & $recorded $_ }) + @('-instancename', $instance)
                tool_timeout_seconds = $TimeoutSeconds; short_timeout_seconds = $short; worst_case_seconds = $worstCase
            }
        }
        $entry.buffers = [ordered]@{ size_kb = Get-DpcIsrBufferSizeKb; count = Get-DpcIsrBufferCount; mode = 'file' }

        # Preflight: the tools, the account, no WPR recording in progress on
        # the default instance (this collector never cancels one it did not
        # start), and the profile enumerated by wpr -profiles without error.
        $account = Get-WfAccountInfo
        $present = Test-WfToolPresent -Path $tool
        $checks.Add([ordered]@{ name = 'tool_present'; ok = $present; detail = $tool })
        $tracerptPresent = Test-WfToolPresent -Path $tracerpt
        $checks.Add([ordered]@{ name = 'tracerpt_present'; ok = $tracerptPresent; detail = $tracerpt })
        $elevated = [bool]$account['elevated']
        $checks.Add([ordered]@{ name = 'account_elevated'; ok = $elevated; detail = ('{0}; starting a kernel trace session needs an elevated account (see the collector header for the citation)' -f $account['name']) })
        $idle = $false
        $accepted = $false
        if ($present -and $tracerptPresent -and $elevated) {
            $statusBefore = Invoke-DpcIsrTool -Tool $tool -Verb 'status' -Arguments @() -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
            $before = Get-DpcIsrStatusState -Run $statusBefore
            $idle = ($before -eq 'idle')
            $checks.Add([ordered]@{ name = 'no_recording_in_progress'; ok = $idle; detail = ('wpr -status (default instance) reads as {0}: {1}' -f $before, ((([string]$statusBefore['StdOut'] + ' ' + [string]$statusBefore['StdErr']) -replace '\s+', ' ').Trim())) })
            if ($idle) {
                $profiles = Invoke-DpcIsrTool -Tool $tool -Verb 'profiles' -Arguments @($profilePath) -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
                $accepted = Test-DpcIsrRunOk -Run $profiles
                $checks.Add([ordered]@{ name = 'profile_enumerated'; ok = $accepted; detail = $(if ($accepted) { 'wpr -profiles enumerated the profile file and exited 0' } else { & $recorded (Get-DpcIsrRunFailure -Run $profiles -Tool $tool) }) })
            }
        }
        $preflightOk = ($present -and $tracerptPresent -and $elevated -and $idle -and $accepted)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks.ToArray()) }
        if (-not $present) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'the executable does not exist: ' + $tool
        } elseif (-not $tracerptPresent) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'the executable does not exist: ' + $tracerpt + ' (it reads the final loss statistics of the saved trace; without it no trace could be reported as complete, so none is recorded)'
        } elseif (-not $elevated) {
            $readErrorKind = 'preflight'; $readErrorMessage = ('the account {0} is not elevated, and starting a kernel trace session is an Administrator operation; this collector never builds an elevation of its own (collectors/windows/README.md, Needs elevation)' -f $account['name'])
        } elseif (-not $idle) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'wpr -status on the default instance did not read as idle (a recording is in progress, or the text is not the one this reader knows); this collector never cancels a recording it did not start, so it refuses to start: ' + [string]$checks[$checks.Count - 1]['detail']
        } elseif (-not $accepted) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'wpr -profiles did not enumerate the recording profile: ' + [string]$checks[$checks.Count - 1]['detail']
        }

        if (-not $readErrorKind) {
            $null = New-Item -ItemType Directory -Force -Path $tempDir
            $start = Invoke-DpcIsrTool -Tool $tool -Verb 'start' -Arguments $startArguments -Instance $instance -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            $monotonicStart = Get-WfMonotonicSeconds
            if (Test-DpcIsrRunOk -Run $start) {
                $sessionStarted = $true
                $session.session_started_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
                $Log.Add(('session {0} started, recording for {1} s' -f $instance, $duration))
            } else {
                # A start that failed may still have left a session behind:
                # the finally block below checks the instance and cancels it.
                $sessionStarted = $true
                $readErrorKind = 'preflight'
                $readErrorMessage = 'wpr -start was refused: ' + (& $recorded (Get-DpcIsrRunFailure -Run $start -Tool $tool))
            }
        }

        if ($sessionStarted -and -not $readErrorKind) {
            # Requested versus enabled, from the tool's own status right after
            # the start: the kernel collector must be listed with every
            # requested keyword, and its loss figure must be readable. A
            # session whose settings cannot be verified is cancelled, not
            # recorded.
            $statusRun = Invoke-DpcIsrTool -Tool $tool -Verb 'status' -Arguments @('profiles', 'collectors', '-details') -Instance $instance -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
            $statusState = Get-DpcIsrStatusState -Run $statusRun
            if ($statusState -eq 'active') {
                $statusText = [string]$statusRun['StdOut']
                if ([string]$statusRun['StdErr']) { $statusText = $statusText + "`n" + [string]$statusRun['StdErr'] }
                $protected = Protect-WfMacAddresses -Text ($statusText -replace "`r`n", "`n") -Salt ([string]$Context['Salt'])
                Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/status.txt')) -Text (([string]$protected.Text).TrimEnd() + "`n")
                $parsedStatus = Read-DpcIsrWprStatus -Text $statusText
                $session.status_after_start = [ordered]@{
                    dropped_events = $parsedStatus.dropped_events; dropped_events_text = $parsedStatus.dropped_events_text; logging_mode = $parsedStatus.logging_mode
                    time_since_start = $parsedStatus.time_since_start; buffers_lost_listed = $parsedStatus.buffers_lost_listed
                    collectors = @($parsedStatus.collectors); mac_addresses_replaced = $protected.Count
                }
                $kernel = @($parsedStatus.collectors | Where-Object { [string]$_.name -eq (Get-DpcIsrKernelCollectorName) })
                $enabledProviders = @($parsedStatus.collectors | ForEach-Object { [string]$_.name })
                if ($kernel.Count -ne 1) {
                    $settingsReason = ('wpr -status lists {0} collector(s) named "{1}"; exactly one is expected' -f $kernel.Count, (Get-DpcIsrKernelCollectorName))
                } else {
                    $enabledKeywords = @($kernel[0].keywords)
                    $enabledStacks = @($kernel[0].stacks)
                    $statusBufferKb = $kernel[0].buffer_size_kb
                    $earlyEventsLost = $kernel[0].events_lost
                    $missing = @((Get-DpcIsrRequestedKeywords) | Where-Object { $enabledKeywords -notcontains $_ })
                    if ($enabledKeywords.Count -eq 0) {
                        $settingsReason = 'wpr -status lists no System Keywords for the kernel collector, so the requested settings are not verified from tool output'
                    } elseif ($missing.Count -gt 0) {
                        $settingsReason = ('requested settings were not enabled: wpr -status lists no {0} keyword for the kernel collector' -f ($missing -join ', '))
                    } elseif ($null -eq $earlyEventsLost) {
                        $settingsReason = ('the kernel collector''s "Events Lost" figure is missing or not a number ({0})' -f $(if ($null -eq $kernel[0].events_lost_text) { 'no line' } else { '"' + [string]$kernel[0].events_lost_text + '"' }))
                    } elseif ($parsedStatus.buffers_lost_listed) {
                        $settingsReason = 'wpr -status lists lost buffers for the session'
                    } elseif ($earlyEventsLost -gt 0) {
                        $settingsReason = ('wpr -status already reports {0} events lost right after the start' -f $earlyEventsLost)
                    }
                }
            } else {
                $settingsReason = ('wpr -status on the collector''s own instance read as {0} right after the start, so the session and its settings could not be verified: {1}' -f $statusState, (& $recorded (Get-DpcIsrRunFailure -Run $statusRun -Tool $tool)))
            }
            $session.settings_verified = ($null -eq $settingsReason)
            if ($null -ne $settingsReason) {
                $readErrorKind = 'other'
                $readErrorMessage = 'the session was cancelled without saving a trace because ' + $settingsReason
            }
        }

        if ($sessionStarted -and -not $readErrorKind) {
            # Record until the monotonic deadline or the cap, one second at a
            # time, then issue the stop at once. Nothing else runs between the
            # deadline and the stop.
            $deadline = $monotonicStart + $duration
            while ((Get-WfMonotonicSeconds) -lt $deadline) {
                Start-WfSleep -Seconds 1
                $bytes = Get-DpcIsrDirectoryBytes -Path $tempDir
                if ($bytes -gt $session.temp_bytes_seen) { $session.temp_bytes_seen = $bytes }
                if ($bytes -gt $maxTraceBytes) {
                    $session.stopped_early_at_cap = $true
                    $Log.Add(('the temporary recording reached {0} bytes, above the cap of {1}; stopping early' -f $bytes, $maxTraceBytes))
                    break
                }
            }
            $session.recording_seconds = [math]::Round((Get-WfMonotonicSeconds) - $monotonicStart, 3)
            $session.session_stop_issued_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            $stopIssued = $true
            $stop = Invoke-DpcIsrTool -Tool $tool -Verb 'stop' -Arguments $stopArguments -Instance $instance -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot
            if (-not (Test-DpcIsrRunOk -Run $stop)) {
                $readErrorKind = 'other'
                $readErrorMessage = 'wpr -stop failed, so no trace was saved: ' + (& $recorded (Get-DpcIsrRunFailure -Run $stop -Tool $tool))
            }
        }
    } catch {
        $readErrorKind = 'other'
        $readErrorMessage = 'the collector raised while running the trace session: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    } finally {
        # Every exit path ends here. The collector's own instance is checked;
        # anything but a confirmed idle state is cancelled and checked again.
        # The outcome is recorded whatever it is; an unconfirmed state is a
        # failure, never a quiet success.
        try {
            if ($sessionStarted) {
                $after = Invoke-DpcIsrTool -Tool $tool -Verb 'status' -Arguments @() -Instance $instance -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
                $stateAfterStop = Get-DpcIsrStatusState -Run $after
                $finalState = $stateAfterStop
                if ($stateAfterStop -ne 'idle') {
                    $cancel = Invoke-DpcIsrTool -Tool $tool -Verb 'cancel' -Arguments @() -Instance $instance -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
                    $Log.Add(('session {0} read as {1}; cancelled: exit code {2}' -f $instance, $stateAfterStop, [string]$cancel['ExitCode']))
                    $again = Invoke-DpcIsrTool -Tool $tool -Verb 'status' -Arguments @() -Instance $instance -TimeoutSeconds $short -Runs $runs -Log $Log -BundleRoot $BundleRoot
                    $finalState = Get-DpcIsrStatusState -Run $again
                }
            }
        } catch {
            $finalState = 'unknown'
            $Log.Add('the session state could not be confirmed: ' + $_.Exception.Message)
        }
    }
    $confirmed = $null
    if ($sessionStarted) { $confirmed = ($finalState -eq 'idle') }
    $session.session_state_after_stop = $stateAfterStop
    $session.session_state_final = $finalState
    $session.session_confirmed_stopped = $confirmed
    if ($sessionStarted -and -not $confirmed) {
        $message = ('source {0}: the trace session {1} reads as {2} after the stop and cancel; run "wpr -status -instancename {1}" on the machine and "wpr -cancel -instancename {1}" if it is still recording' -f $id, $instance, $finalState)
        $Notes.Add($message)
        $Log.Add($message)
    }

    # The saved trace: its size and hash, then its final statistics from
    # tracerpt. The file itself is removed by the definition's Cleanup.
    $traceOk = $false
    try {
        if ($stopIssued -and -not $readErrorKind -and (Test-Path -LiteralPath $etlPath)) {
            $traceBytes = [int64](Get-Item -LiteralPath $etlPath).Length
            if ($traceBytes -gt 0 -and $traceBytes -le $maxTraceBytes) {
                $traceSha = Get-WfSha256OfFile -Path $etlPath
                $traceOk = $true
            }
        }
        $session.trace_bytes = $traceBytes
        $session.trace_sha256 = $traceSha
        if ($traceOk -and $confirmed) {
            $summaryRun = Invoke-DpcIsrTool -Tool $tracerpt -Verb '' -Arguments @($etlPath, '-summary', $summaryPath, '-y') -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot -MaxBytes $MaxArtifactBytes
            if ((Test-DpcIsrRunOk -Run $summaryRun) -and (Test-Path -LiteralPath $summaryPath)) {
                $summaryBytes = [int64](Get-Item -LiteralPath $summaryPath).Length
                if ($summaryBytes -gt $MaxArtifactBytes) {
                    Remove-Item -LiteralPath $summaryPath -Force
                    $Log.Add(('the tracerpt summary is {0} bytes, above the cap of {1}, and was not kept' -f $summaryBytes, $MaxArtifactBytes))
                } else {
                    $rawSummary = [System.IO.File]::ReadAllText($summaryPath)
                    # The summary names the trace file; the bundle root in that path becomes <bundle> like every other recorded path.
                    $protectedSummary = Protect-WfMacAddresses -Text (& $recorded ($rawSummary -replace "`r`n", "`n")) -Salt ([string]$Context['Salt'])
                    Write-WfTextFile -Path $summaryPath -Text (([string]$protectedSummary.Text).TrimEnd() + "`n")
                    $summary = Read-DpcIsrSummary -Text $rawSummary
                    $session.final.events_lost = $summary.events_lost
                    $session.final.buffers_lost = $summary.buffers_lost
                    $session.final.events_lost_lines = $summary.events_lost_lines
                    $session.final.buffers_lost_lines = $summary.buffers_lost_lines
                    $session.final.labelled_lines = $summary.labelled_lines
                    $session.final.protection = [ordered]@{ mac_addresses_replaced = $protectedSummary.Count }
                }
            } elseif (Test-Path -LiteralPath $summaryPath) {
                Remove-Item -LiteralPath $summaryPath -Force
            }
        }
    } catch {
        $Log.Add('source ' + $id + ' raised while reading the saved trace: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $summaryPath) { Remove-Item -LiteralPath $summaryPath -Force }
        $summary = $null
    }
    $finalEventsLost = $(if ($null -ne $summary) { $summary.events_lost } else { $null })
    $finalBuffersLost = $(if ($null -ne $summary) { $summary.buffers_lost } else { $null })

    # Status. Observed needs every one of: a clean session, settings
    # verified, a saved trace within the cap, a confirmed idle instance, and
    # final figures that are numbers and zero. Everything else is a reason.
    $met = $false
    $stopped = Get-WfUtcNow
    if ($readErrorKind) {
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
    } elseif ($null -eq $traceBytes -or $traceBytes -le 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'wpr -stop exited 0 but the trace file is missing or empty'
    } elseif ($traceBytes -gt $maxTraceBytes) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the trace is {0} bytes, above the cap of {1}, and was not read' -f $traceBytes, $maxTraceBytes)
    } elseif (-not $confirmed) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the trace was saved but the collector''s instance reads as {0} after the stop{1}; a session whose end is not confirmed is not a complete record' -f $finalState, $(if ($stateAfterStop -ne 'idle') { ' and the cancel' } else { '' }))
    } elseif ($null -eq $summaryRun -or -not (Test-DpcIsrRunOk -Run $summaryRun) -or -not (Test-Path -LiteralPath $summaryPath)) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the final loss statistics could not be read: ' + $(if ($null -eq $summaryRun) { 'tracerpt was not run' } else { & $recorded (Get-DpcIsrRunFailure -Run $summaryRun -Tool $tracerpt) })
    } elseif ($null -eq $finalEventsLost -or $null -eq $finalBuffersLost) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the tracerpt summary gives no single whole number for {0} ({1} events lost line(s), {2} buffers lost line(s), {3} labelled lines); a trace whose loss is unknown is never a complete record. The summary text is tracerpt-summary.txt; see verification item 31' -f $(if ($null -eq $finalEventsLost -and $null -eq $finalBuffersLost) { 'events lost or buffers lost' } elseif ($null -eq $finalEventsLost) { 'events lost' } else { 'buffers lost' }), $summary.events_lost_lines, $summary.buffers_lost_lines, $summary.labelled_lines)
    } elseif ($finalEventsLost -gt 0 -or $finalBuffersLost -gt 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the saved trace lost {0} events and {1} buffers (the scenario bound is 0 for both); its report, if any, describes the events that were recorded and never the whole window. Raise the buffer count in the profile or shorten the capture' -f $finalEventsLost, $finalBuffersLost)
    } elseif ($session.stopped_early_at_cap) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the recording was stopped early because the temporary recording reached {0} bytes, above the cap of {1}; the trace is a complete record of a shorter window' -f $session.temp_bytes_seen, $maxTraceBytes)
    } else {
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
    }
    if ($session.session_started_utc -and $session.session_stop_issued_utc -and $traceOk) {
        # The window the trace covers: from the moment the start returned to
        # the moment the stop was issued, on the system clock. The trace's own
        # timestamps are QPC (docs/contracts/timestamps.md); this bracket is
        # what the collector can state about them.
        $entry.raw_time_range = [ordered]@{ start = $session.session_started_utc; end = $session.session_stop_issued_utc; domain = 'system_time'; unit = 'iso_utc' }
    }
    $entry.events_lost = $finalEventsLost
    $entry.buffers_lost = $finalBuffersLost
    if ($null -ne $statusBufferKb) { $entry.buffers.size_kb = $statusBufferKb }
    $entry.enabled = [ordered]@{
        providers   = $enabledProviders
        keywords    = $enabledKeywords
        stack_walk  = $enabledStacks
        counters    = @()
        options     = [ordered]@{
            instance_name = $instance
            dropped_events_after_start = $(if ($null -ne $parsedStatus) { $parsedStatus.dropped_events } else { $null })
            events_lost_after_start = $earlyEventsLost
            buffers_lost_listed_after_start = $(if ($null -ne $parsedStatus) { $parsedStatus.buffers_lost_listed } else { $null })
            logging_mode = $(if ($null -ne $parsedStatus) { $parsedStatus.logging_mode } else { $null })
            final_events_lost = $finalEventsLost
            final_buffers_lost = $finalBuffersLost
            session_started_utc = $session.session_started_utc
            session_stop_issued_utc = $session.session_stop_issued_utc
            recording_seconds = $session.recording_seconds
            trace_bytes = $traceBytes
            trace_sha256 = $traceSha
            trace_kept_in_bundle = $false
            temp_bytes_seen = $session.temp_bytes_seen
            stopped_early_at_cap = $session.stopped_early_at_cap
            session_state_after_stop = $stateAfterStop
            session_state_final = $finalState
            session_confirmed_stopped = $confirmed
        }
        verified_by = 'keywords and buffer size from "wpr -status profiles collectors -details -instancename <name>" right after the start (status.txt); final events lost and buffers lost from "tracerpt <trace> -summary" after the stop (tracerpt-summary.txt); the session end from "wpr -status -instancename <name>"'
    }
    $entry.exit_code = $(if ($runs.Count -gt 0) { $runs[$runs.Count - 1].exit_code } else { $null })
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = ('final events lost {0}; final buffers lost {1}; trace {2} bytes; recording {3} s of {4} requested; session {5}' -f $(if ($null -eq $finalEventsLost) { 'unknown' } else { $finalEventsLost }), $(if ($null -eq $finalBuffersLost) { 'unknown' } else { $finalBuffersLost }), $(if ($null -eq $traceBytes) { 'absent' } else { $traceBytes }), $(if ($null -eq $session.recording_seconds) { 'none' } else { $session.recording_seconds }), $duration, $(if ($null -eq $finalState) { 'not started' } else { $finalState }))
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/session.json')) -Object $session
    $Context['Tools'].Add((Get-WfToolRecord -Name 'wpr' -Version $null -Path $tool))
    if ($null -ne $summaryRun) { $Context['Tools'].Add((Get-WfToolRecord -Name 'tracerpt' -Version $null -Path $tracerpt)) }
    if ($traceOk -and $confirmed) {
        $Context['TraceEtl'] = $etlPath
        $Context['TraceEtlRecorded'] = '<bundle>/private/trace.etl'
        $Context['TraceSha256'] = $traceSha
        $Context['TraceEventsLost'] = $finalEventsLost
        $Context['TraceBuffersLost'] = $finalBuffersLost
        $Context['TraceStatus'] = $entry.status
        $Context['TraceEntry'] = $entry
        $Context['TraceRange'] = $entry.raw_time_range
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
    $recorded = { param([string]$Text) return (ConvertTo-DpcIsrRecordedText -Text $Text -BundleRoot $BundleRoot) }
    $readErrorKind = ''
    $readErrorMessage = ''
    $run = $null
    $toolInfo = $null
    $toolInfoAfter = $null
    $pin = $null
    $arguments = @()
    $outputBytes = [int64]0
    $sectionsFound = @()
    $traceLost = $null
    $traceBuffersLost = $null
    $protectedCount = 0
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $pins = Get-WfPinnedToolBuilds -Name 'xperf'
        $traceLost = $Context['TraceEventsLost']
        $traceBuffersLost = $Context['TraceBuffersLost']
        $hasTrace = $Context.ContainsKey('TraceEtl') -and (Test-Path -LiteralPath ([string]$Context['TraceEtl']))
        $lossy = (($null -ne $traceLost -and [int64]$traceLost -gt 0) -or ($null -ne $traceBuffersLost -and [int64]$traceBuffersLost -gt 0))
        if ($hasTrace) {
            $arguments = @('-i', [string]$Context['TraceEtl'], '-a', 'dpcisr')
            if ($lossy) { $arguments += '-tle' }
        }
        $encoding = Get-WfConsoleOutputEncoding
        $config = [ordered]@{
            tool               = $(if ($xperfPath) { $xperfPath } else { $null })
            tool_source        = 'operator supplied (-XperfPath); xperf.exe is part of the Windows Performance Toolkit in the Windows ADK, not inbox on Windows, and runs only when its SHA-256 and version match a pinned build, checked before and after the run'
            pinned_builds      = @($pins | ForEach-Object { [ordered]@{ version = $_['Version']; sha256 = $_['Sha256']; source = $_['Source'] } })
            arguments          = @($arguments | ForEach-Object { & $recorded $_ })
            trace              = $(if ($hasTrace) { [string]$Context['TraceEtlRecorded'] } else { $null })
            trace_sha256       = $(if ($hasTrace) { [string]$Context['TraceSha256'] } else { $null })
            trace_events_lost  = $traceLost
            trace_buffers_lost = $traceBuffersLost
            timeout_seconds    = $TimeoutSeconds
            max_artifact_bytes = $MaxArtifactBytes
            output_encoding    = [string]$encoding.WebName
            output_code_page   = [int]$encoding.CodePage
            line_endings       = 'lf'
            protection         = 'hardware addresses (six hexadecimal pairs) become mac-<12 hex> pseudonyms before the report is written'
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($(if ($xperfPath) { $xperfPath } else { 'xperf.exe' })) + @($arguments | ForEach-Object { & $recorded $_ })
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        $checks = New-Object 'System.Collections.Generic.List[object]'
        $checks.Add([ordered]@{ name = 'trace_present'; ok = $hasTrace; detail = $(if ($hasTrace) { [string]$Context['TraceEtlRecorded'] + ' (on the machine only)' } else { 'the wpr_trace source produced no readable trace' }) })
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
                $checks.Add([ordered]@{ name = 'tool_pinned'; ok = $pinned; detail = $(if ($pinned) { 'matches the pinned build ' + [string]$pin['Version'] + ' from ' + [string]$pin['Source'] } elseif (@($pins).Count -eq 0) { 'no xperf build is pinned in _common.ps1 (Get-WfPinnedToolBuilds); which Windows Performance Toolkit release goes on the PC is an open decision' } else { ('the file (sha256 {0}, version {1}) matches none of the {2} pinned builds' -f $toolInfo['Sha256'], $toolInfo['Version'], @($pins).Count) }) })
            }
        }
        $preflightOk = ($hasTrace -and $named -and $exists -and $pinned)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks.ToArray()) }
        if (-not $hasTrace) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'there is no trace to report on: the wpr_trace source is ' + [string]$(if ($Context.ContainsKey('TraceStatus')) { $Context['TraceStatus'] } else { 'without a readable trace file' })
        } elseif (-not $named) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'xperf.exe is not inbox on Windows and -XperfPath was not given; the per CPU report can only be produced on this machine, because the trace never leaves it (collectors/windows/README.md)'
        } elseif (-not $exists) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'the executable does not exist: ' + $xperfPath + $(if ($toolInfo['Error']) { ' (' + [string]$toolInfo['Error'] + ')' } else { '' })
        } elseif (-not $pinned) {
            $readErrorKind = 'preflight'; $readErrorMessage = 'refused to run an unpinned tool: ' + [string]$checks[$checks.Count - 1]['detail']
        }

        if (-not $readErrorKind) {
            $argumentText = (@($arguments | ForEach-Object { Format-DpcIsrArgument -Value $_ })) -join ' '
            $run = Invoke-WfProcess -FilePath $xperfPath -Arguments $argumentText -TimeoutSeconds $TimeoutSeconds -OutputEncoding $encoding -MaxBytes $MaxArtifactBytes
            # The file is hashed again after the run: a tool that changed
            # between the check and the run is not the pinned build.
            $toolInfoAfter = Get-WfExternalToolInfo -Path $xperfPath
            if ([string]$toolInfoAfter['Sha256'] -ne [string]$toolInfo['Sha256']) {
                $readErrorKind = 'other'; $readErrorMessage = ('the tool file changed during the run (sha256 {0} before, {1} after), so the report is not from the pinned build' -f $toolInfo['Sha256'], $toolInfoAfter['Sha256'])
            } elseif (-not $run['Started']) {
                $readErrorKind = 'other'; $readErrorMessage = 'the process could not be started: ' + [string]$run['Error']
            } elseif ($run['TimedOut']) {
                $readErrorKind = 'timeout'; $readErrorMessage = [string]$run['Error']
            } elseif ($run['Oversized']) {
                $readErrorKind = 'other'; $readErrorMessage = [string]$run['Error']
            } elseif ([int]$run['ExitCode'] -ne 0) {
                $readErrorKind = 'other'; $readErrorMessage = & $recorded (Get-DpcIsrRunFailure -Run $run -Tool $xperfPath)
                if (([string]$run['StdOut'] + ' ' + [string]$run['StdErr']) -match '(?i)lost' -and $Context.ContainsKey('TraceEntry') -and (Test-WfObservedStatus -Status ([string]$Context['TraceEntry']['status']))) {
                    # xperf refuses a trace with lost events unless told to
                    # tolerate them; a refusal that names a loss the summary
                    # did not show downgrades the trace itself.
                    $Context['TraceEntry']['status'] = 'capture_failed'
                    $Context['TraceEntry']['status_reason'] = 'xperf refused the trace naming lost events, which the tracerpt summary did not show; the trace is not accepted as complete: ' + $readErrorMessage
                    $Context['TraceEntry']['expectation']['met'] = $false
                    $Notes.Add('source wpr_trace: downgraded to capture_failed because xperf named lost events')
                }
            } else {
                $text = ([string]$run['StdOut']) -replace "`r`n", "`n"
                if ($text.Trim().Length -eq 0) {
                    $readErrorKind = 'other'; $readErrorMessage = 'xperf exited with code 0 and printed nothing'
                } else {
                    foreach ($section in @('DPC Info', 'Interrupt Info')) { if ($text -match ('(?m)^\s*' + $section + '\s*$')) { $sectionsFound += $section } }
                    $protected = Protect-WfMacAddresses -Text $text -Salt ([string]$Context['Salt'])
                    $protectedCount = $protected.Count
                    $text = [string]$protected.Text
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
            if ($null -ne $toolInfoAfter -and [string]$toolInfoAfter['Sha256'] -eq [string]$toolInfo['Sha256']) {
                $Context['Tools'].Add([ordered]@{ name = 'xperf'; version = [string]$toolInfo['Version']; path = $xperfPath; sha256 = [string]$toolInfo['Sha256'] })
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
    } elseif ($Context.ContainsKey('TraceEntry') -and -not (Test-WfObservedStatus -Status ([string]$Context['TraceEntry']['status']))) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the report was produced' + $(if ($arguments -contains '-tle') { ' with -tle (tolerate lost events)' } else { '' }) + ' from a trace whose source is capture_failed (' + [string]$Context['TraceEntry']['status_reason'] + '); it describes the events that were recorded and never the whole window, so it is kept with this status and never supports an absence claim'
        $Notes.Add('source ' + $id + ': the dpcisr report comes from a trace that is not a complete record and is kept as capture_failed; read it as a lower bound, never as an absence')
    } else {
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
    }
    $report = [ordered]@{
        started_utc    = ConvertTo-WfUtcString -Value $started
        stopped_utc    = ConvertTo-WfUtcString -Value $stopped
        tool_sha256    = $(if ($null -ne $toolInfo) { $toolInfo['Sha256'] } else { $null })
        tool_sha256_after_run = $(if ($null -ne $toolInfoAfter) { $toolInfoAfter['Sha256'] } else { $null })
        tool_version   = $(if ($null -ne $toolInfo) { $toolInfo['Version'] } else { $null })
        pinned_build   = $(if ($null -ne $pin) { [ordered]@{ version = $pin['Version']; sha256 = $pin['Sha256']; source = $pin['Source'] } } else { $null })
        exit_code      = $(if ($null -ne $run) { $run['ExitCode'] } else { $null })
        timed_out      = $(if ($null -ne $run) { [bool]$run['TimedOut'] } else { $false })
        duration_ms    = $(if ($null -ne $run) { $run['DurationMs'] } else { $null })
        stdout_bytes   = $outputBytes
        stderr         = $(if ($null -ne $run) { & $recorded (([string]$run['StdErr']).Trim()) } else { $null })
        sections_found = @($sectionsFound)
        trace_sha256   = $(if ($Context.ContainsKey('TraceSha256')) { [string]$Context['TraceSha256'] } else { $null })
        trace_events_lost = $traceLost
        trace_buffers_lost = $traceBuffersLost
        protection     = [ordered]@{ mac_addresses_replaced = $protectedCount }
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
    if ((Test-Path -LiteralPath $reportPath) -and $Context.ContainsKey('TraceRange') -and $null -ne $Context['TraceRange']) {
        # The report describes the trace, so its range is the trace's window,
        # not the moment xperf ran (that is in result.json).
        $entry.raw_time_range = [ordered]@{ start = $Context['TraceRange']['start']; end = $Context['TraceRange']['end']; domain = 'system_time'; unit = 'iso_utc' }
    }
    $entry.exit_code = $report.exit_code
    $entry.enabled = [ordered]@{
        providers = @(); keywords = @(); stack_walk = @(); counters = @()
        options   = [ordered]@{
            exit_code = $report.exit_code; timed_out = $report.timed_out; duration_ms = $report.duration_ms; stdout_bytes = $outputBytes
            sections_found = @($sectionsFound); tool_sha256 = $report.tool_sha256; tool_sha256_after_run = $report.tool_sha256_after_run; tool_version = $report.tool_version
            trace_sha256 = $report.trace_sha256; mac_addresses_replaced = $protectedCount
        }
        verified_by = 'the tool file hash and version in result.json matched the pinned build before the run and the hash again after it; the process exit code, timing and byte count are in result.json; the report is dpcisr.txt; the trace it describes is named by its SHA-256'
    }
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = ('exit code {0}; sections {1}; trace events lost {2}; trace buffers lost {3}' -f $report.exit_code, ($sectionsFound -join ', '), $(if ($null -eq $traceLost) { 'unknown' } else { $traceLost }), $(if ($null -eq $traceBuffersLost) { 'unknown' } else { $traceBuffersLost }))
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
    Version                  = '1.1.0'
    Question                 = 'Where do DPC and interrupt time land, per CPU and per module, while the PC is in use?'
    RequestedDurationSeconds = $DurationSeconds
    Calibration              = @{
        status = 'not_collected'
        method = 'none in this collector: the trace timestamps are QPC (the ETW default clock) and the calibration pairs that relate them to system time come from the clock collector, which is a separate piece; until it runs alongside, the trace is unaligned to every system_time source'
    }
    Cleanup                  = $removePrivate
    Sources                  = @(
        @{
            Id              = 'wpr_trace'
            Type            = 'script'
            Required        = $true
            Invoke          = $invokeWprTrace
            DurationSeconds = $DurationSeconds
            MaxTraceBytes   = $MaxTraceBytes
            Expectation     = 'wpr starts the profile under the collector''s own instance name, lists the kernel collector with the three requested keywords and a readable loss figure, records for the requested duration, saves a non empty trace within the cap, reads as idle after the stop, and tracerpt reports zero events lost and zero buffers lost for the saved trace'
        },
        @{
            Id          = 'dpcisr_report'
            Type        = 'script'
            Required    = $false
            Invoke      = $invokeDpcIsrReport
            XperfPath   = $XperfPath
            Expectation = 'a pinned xperf.exe, unchanged across the run, exits 0 on "xperf -i trace.etl -a dpcisr" and prints the DPC Info and Interrupt Info sections, from a trace with zero events lost and zero buffers lost'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
