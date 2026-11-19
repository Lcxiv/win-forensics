# diskio-trace: What writes to and reads from disk while the PC is in use,
# per process, per directory, per disk, in one second bins?
#
# A bounded live capture. Runs under Windows PowerShell 5.1 as an elevated
# account (kernel tracing is an Administrator operation, see below), writes
# one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints one
# JSON summary line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md ("The diskio-trace sources") for the
# interface, the artifact formats, the privacy statement, the elevation note
# and the facts still to be verified on a real machine.
#
# Sources:
#
#   wpr_trace         one Windows Performance Recorder session from the
#                     profile embedded below (NT Kernel Logger: DiskIO,
#                     Filename, HardFaults, ProcessThread), file mode, under
#                     its own WPR instance name, started and stopped by this
#                     script within -DurationSeconds. One inbox tracerpt call
#                     then reads the saved trace: it writes the summary
#                     (final events lost and buffers lost) into the bundle
#                     and the XML dump into the private folder, both named
#                     on the command line, so tracerpt writes no file under
#                     a default name anywhere else. The profile, the wpr
#                     status text read right after the start, that summary
#                     and a session record are the artifacts.
#   diskio_aggregate  the dump of an observed trace read on the PC: this
#                     script aggregates the disk, hard fault, file name, process and
#                     thread events into rows per one second bin, process,
#                     directory (fixed Windows roots and one level below them
#                     readable, everything deeper a per run salted
#                     pseudonym), disk and operation, and then deletes the
#                     trace and the dump. Only the aggregate, the rules that
#                     made it and the hashes of what it was made from leave
#                     the PC. scripts/decode_diskio.py turns the aggregate
#                     into the diskio_activity table.
#
# Events (Keyword (in SystemProvider),
# https://learn.microsoft.com/windows-hardware/test/wpt/keyword--in-systemprovider-):
#   DiskIO         "Disk I/O is logged": DiskIo Read (10) and Write (11),
#                  recorded at completion, with DiskNumber, IrpFlags,
#                  TransferSize, FileObject, HighResResponseTime ("The time
#                  between I/O initiation and completion as measured by the
#                  partition manager (in the KeQueryPerformanceCounter tick
#                  units)") and IssuingThreadId
#                  (https://learn.microsoft.com/windows/win32/etw/diskio and
#                  https://learn.microsoft.com/windows/win32/etw/diskio-typegroup1).
#   Filename       FileIo_Name: Name (0), FileCreate (32), FileDelete (35) and
#                  FileRundown (36) with FileObject and FileName, the "Full
#                  path to the file, not including the drive letter"
#                  (https://learn.microsoft.com/windows/win32/etw/fileio-name).
#                  "The disk I/O provider cannot identify which file is read
#                  or written during a disk I/O event" (DiskIo class page),
#                  so this is what names the file.
#   HardFaults     PageFault_HardFault (32) with FileObject, TThreadId and
#                  ByteCount, "Amount of data read from ReadOffset to satisfy
#                  the fault" (https://learn.microsoft.com/windows/win32/etw/pagefault-hardfault).
#   ProcessThread  Thread Start, End, DCStart and DCEnd (1 to 4) with
#                  ProcessId and TThreadId ("The DCStart and DCEnd event
#                  types enumerate the threads that are currently running at
#                  the time the kernel session starts and ends",
#                  https://learn.microsoft.com/windows/win32/etw/thread-typegroup1)
#                  and Process events with ProcessId and ImageFileName
#                  (https://learn.microsoft.com/windows/win32/etw/process-typegroup1).
#                  These map a thread id to a process from the trace alone.
#                  The Process events also carry CommandLine and UserSID:
#                  they stay in the trace and the dump on the PC and never
#                  reach the aggregate, which keeps only the image name.
# FileIO and FileIOInit (the logical file requests by the application's own
# thread) are not requested until a pilot has measured their volume; without
# them a write the system flushes later is charged to the thread that issued
# the disk request, never to a guessed process. No stacks.
#
# Privacy. File paths name the owner's profile, documents and saves, and a
# kernel session writes system configuration events with hardware and
# network addresses on its own (https://learn.microsoft.com/windows/win32/etw/systemconfig,
# https://learn.microsoft.com/windows/win32/etw/systemconfig-nic). The trace
# and its dump therefore never leave the PC: both live under
# <OutputDirectory>\private, the aggregate source deletes them as soon as it
# has read them and records that it did, and the definition's Cleanup
# removes the private folder on every exit path. Only sizes and SHA-256 of
# the two files are recorded.
#
# Concurrency. This collector runs alone. Microsoft documents "There is only
# one NT Kernel Logger session. If the session is already in use, the
# StartTrace function returns ERROR_ALREADY_EXISTS"
# (https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session),
# and whether WPR gives a second named instance its own system logger is not
# documented (README verification list). Microsoft documents no read only
# command that lists the kernel sessions in progress (the logman query page
# describes -ets only as "Sends commands to Event Trace Sessions directly
# without saving or scheduling", and its examples list Data Collector Sets,
# https://learn.microsoft.com/windows-server/administration/windows-commands/logman-query),
# so the collector does not check for another kernel session; it says so in
# the manifest, and a start that collides is refused by WPR and reported.
#
# Elevation: "Only users with administrative privileges and services running
# as LocalSystem can control an NT Kernel Logger session"
# (https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-starttracea).
# The collector refuses to start a session when the account is not elevated
# and reports not_collected with that reason. It builds no scheduled task,
# service or other persistent elevation.
#
# Read only toward the machine: it changes no setting, installs nothing,
# touches no process (ETW observes from the kernel, outside every process;
# nothing here opens a handle to, injects into, suspends, or changes the
# priority or affinity of any process), and the one thing it starts (the
# trace session, under a WPR instance name of its own) it stops on every
# exit path, cancels when the stop did not end it, and confirms from
# wpr -status; it reports when it could not confirm.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. Checked in the body, not
    # marked Mandatory, because a missing Mandatory parameter makes an
    # interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long the trace session records, in seconds (5 to 300), measured on
    # a monotonic clock from the moment wpr -start returned to the moment
    # wpr -stop is issued.
    [int]$DurationSeconds = 60,
    # Cap on the trace, in bytes (16 MiB to 16 GiB). The recording is stopped
    # early when the temporary recording reaches it; a saved trace above it
    # is not read.
    [long]$MaxTraceBytes = 2147483648,
    # Cap on the XML dump tracerpt writes from the trace, in bytes (16 MiB to
    # 16 GiB). A dump above it is not read.
    [long]$MaxDumpBytes = 4294967296,
    # Cap on the aggregate and on the tracerpt summary, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for each long step (wpr -start, wpr -stop, the tracerpt
    # read of the trace, reading the dump), in seconds (1 to 3600).
    # Status, profile enumeration and cancel calls have a fixed 30 second
    # deadline. The collector refuses to start when the worst case run time
    # exceeds the dispatcher's 900 second budget.
    [int]$TimeoutSeconds = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'diskio-trace'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $common)) {
    if (-not $OutputDirectory) { [Console]::Error.WriteLine($collectorName + ': -OutputDirectory is required') }
    else { [Console]::Error.WriteLine($collectorName + ': the shared helper is missing: ' + $common) }
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}
. $common

# ---------------------------------------------------------------------------
# The recording profile, written byte for byte into raw/wpr_trace/ and hashed
# there as the source's config_hash. Elements and attributes follow the
# recording profile XML reference
# (https://learn.microsoft.com/windows-hardware/test/wpt/recording-profile-xml-reference):
# WindowsPerformanceRecorder with Version and Author, a SystemCollector named
# "NT Kernel Logger" (https://learn.microsoft.com/windows-hardware/test/wpt/systemcollector)
# with BufferSize in KB and Buffers, a SystemProvider with its Keywords, and a
# Profile per logging mode ("A .wprp file must contain profiles for both
# memory and file logging modes",
# https://learn.microsoft.com/windows-hardware/test/wpt/logging-mode). The
# buffers are the ones dpcisr-trace uses (1024 KB, the built in General
# profile's kernel buffer size, times 64, WPR's documented default count);
# lost events and lost buffers are the check on that choice.
# ---------------------------------------------------------------------------
function Get-DiskIoProfileName { return 'WfDiskIoTrace' }
function Get-DiskIoProfileFileName { return 'diskio-trace.wprp' }
function Get-DiskIoRequestedKeywords { return @('DiskIO', 'Filename', 'HardFaults', 'ProcessThread') }
function Get-DiskIoBufferSizeKb { return 1024 }
function Get-DiskIoBufferCount { return 64 }
function Get-DiskIoShortTimeoutSeconds { return 30 }
function Get-DiskIoDispatcherBudgetSeconds { return 900 }
function Get-DiskIoKernelCollectorName { return 'NT Kernel Logger' }
function Get-DiskIoWorstCaseSeconds {
    # The longest a run can take: the recording, four long steps (wpr -start,
    # wpr -stop, the tracerpt read of the trace, reading the dump),
    # five short calls outside the recording (the default instance status,
    # the profile enumeration, the status after the stop, the cancel and the
    # final status), and the time by which the status read after the start
    # can outlast a duration below the short deadline.
    param([int]$DurationSeconds, [int]$TimeoutSeconds)
    $short = Get-DiskIoShortTimeoutSeconds
    $statusOverrun = [math]::Max(0, $short - $DurationSeconds)
    return ($DurationSeconds + $statusOverrun + 4 * $TimeoutSeconds + 5 * $short)
}

function Get-DiskIoProfileXml {
    $lines = @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<WindowsPerformanceRecorder Version="1.0" Author="win-forensics" Comments="diskio-trace 1.0.0: kernel disk I/O, file name, hard fault, process and thread events, to attribute disk activity to processes and directories on the PC. No file I/O events, no stacks.">',
        '  <Profiles>',
        '    <SystemCollector Id="WfDiskIoSystemCollector" Name="NT Kernel Logger">',
        ('      <BufferSize Value="{0}"/>' -f (Get-DiskIoBufferSizeKb)),
        ('      <Buffers Value="{0}"/>' -f (Get-DiskIoBufferCount)),
        '    </SystemCollector>',
        '    <SystemProvider Id="WfDiskIoSystemProvider">',
        '      <Keywords>'
    )
    foreach ($keyword in (Get-DiskIoRequestedKeywords)) { $lines += ('        <Keyword Value="{0}"/>' -f $keyword) }
    $lines += @(
        '      </Keywords>',
        '    </SystemProvider>'
    )
    foreach ($mode in @('File', 'Memory')) {
        $lines += @(
            ('    <Profile Id="{0}.Verbose.{1}" Name="{0}" DetailLevel="Verbose" LoggingMode="{1}" Description="win-forensics diskio-trace: disk I/O, file names, hard faults, processes and threads, without stacks">' -f (Get-DiskIoProfileName), $mode),
            '      <Collectors>',
            '        <SystemCollectorId Value="WfDiskIoSystemCollector">',
            '          <SystemProviderId Value="WfDiskIoSystemProvider"/>',
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
# Tool text readers, as in dpcisr-trace.ps1 (kept local until the scenario
# runner unifies live sessions). Microsoft documents the shape of the wpr
# status text (Status on
# https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options)
# and nothing about the tracerpt summary text. Every figure that is missing
# or not a whole number is null, and null never becomes zero.
# ---------------------------------------------------------------------------
function ConvertTo-DiskIoInteger {
    param([string]$Text)
    if ([string]$Text -match '^\s*(\d+)\s*$') { return [int64]$Matches[1] }
    return $null
}

function Get-DiskIoStatusState {
    # active, idle or unknown, from one "wpr -status" run. Only a run that
    # exited 0 with a recognised text counts; anything else is unknown, which
    # fails preflight and never confirms a stop.
    param($Run)
    if (-not [bool]$Run['Started'] -or [bool]$Run['TimedOut'] -or [bool]$Run['Oversized']) { return 'unknown' }
    if ($null -eq $Run['ExitCode'] -or [int]$Run['ExitCode'] -ne 0) { return 'unknown' }
    $text = ([string]$Run['StdOut'] + "`n" + [string]$Run['StdErr'])
    if ($text -match '(?i)recording is in progress') { return 'active' }
    if ($text -match '(?i)\bnot recording\b') { return 'idle' }
    return 'unknown'
}

function Read-DiskIoWprStatus {
    param([string]$Text)
    $result = [ordered]@{ dropped_events = $null; dropped_events_text = $null; logging_mode = $null; buffers_lost_listed = $false; collectors = @() }
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
            if ($label -eq 'Collector Name') {
                $current = [ordered]@{ name = $value; buffer_size_kb = $null; events_lost = $null; events_lost_text = $null; keywords = @(); stacks = @() }
                $collectors.Add($current)
            } elseif ($label -eq 'Buffer Size (KB)') {
                if ($null -ne $current) { $current.buffer_size_kb = ConvertTo-DiskIoInteger -Text $value }
            } elseif ($label -eq 'Events Lost') {
                if ($null -ne $current) { $current.events_lost = ConvertTo-DiskIoInteger -Text $value; $current.events_lost_text = $value }
            } elseif ($label -match '^Dropped events?$') {
                $result.dropped_events = ConvertTo-DiskIoInteger -Text $value; $result.dropped_events_text = $value
            } elseif ($label -eq 'Logging mode') {
                $result.logging_mode = $value
            }
            continue
        }
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

function Read-DiskIoSummary {
    # The tracerpt summary: one figure each for events lost, buffers lost and
    # events processed, from labelled lines ("Events Lost" or "Buffers Lost"
    # with or without a "Total" prefix, "Log Buffers Lost", and "Events
    # Processed" with or without "Total"), the value after a colon or after
    # white space as the last token on the line. Two lines that disagree, a
    # non numeric value or no line at all give null. The processed count is
    # what the dump is checked against.
    param([string]$Text)
    $result = [ordered]@{ events_lost = $null; events_lost_lines = 0; buffers_lost = $null; buffers_lost_lines = 0; events_processed = $null; events_processed_lines = 0; labelled_lines = 0 }
    $events = New-Object 'System.Collections.Generic.List[object]'
    $buffers = New-Object 'System.Collections.Generic.List[object]'
    $processed = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rawLine in ([string]$Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        $m = [regex]::Match($line, '^([A-Za-z][A-Za-z ()]*[A-Za-z)])\s*(?::\s*(.*)|\s+(\S+))$')
        if (-not $m.Success) { continue }
        $result.labelled_lines += 1
        $label = ($m.Groups[1].Value.Trim() -replace '\s+', ' ')
        $valueText = $(if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value })
        $value = ConvertTo-DiskIoInteger -Text $valueText
        if ($label -match '(?i)^(total\s+)?events\s+lost$') { $events.Add($value) }
        elseif ($label -match '(?i)^(total\s+)?(log\s+)?buffers\s+lost$') { $buffers.Add($value) }
        elseif ($label -match '(?i)^(total\s+)?events\s+processed$') { $processed.Add($value) }
    }
    $result.events_lost_lines = $events.Count
    $result.buffers_lost_lines = $buffers.Count
    $result.events_processed_lines = $processed.Count
    $result.events_lost = Resolve-DiskIoSingleFigure -Values $events
    $result.buffers_lost = Resolve-DiskIoSingleFigure -Values $buffers
    $result.events_processed = Resolve-DiskIoSingleFigure -Values $processed
    return $result
}

function Resolve-DiskIoSingleFigure {
    param([System.Collections.Generic.List[object]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $first = $Values[0]
    if ($null -eq $first) { return $null }
    foreach ($value in $Values) { if ($null -eq $value -or [int64]$value -ne [int64]$first) { return $null } }
    return [int64]$first
}

function Read-DiskIoEtlHeader {
    # The log file header of the saved trace: the clock its events carry
    # (ReservedFlags, "Specifies the clock type", WNODE_HEADER ClientContext:
    # 1 the performance counter, 2 system time, 3 the CPU cycle counter),
    # PerfFreq, StartTime, EndTime ("may be 0 if ... log file that was not
    # finalized"), EventsLost and BuffersLost
    # (https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header,
    # https://learn.microsoft.com/windows/win32/etw/wnode-header). The same
    # reader as Read-WfEtlHeader in presentmon-frames.ps1, kept local until the
    # scenario runner unifies the live captures: Microsoft documents
    # TRACE_LOGFILE_HEADER and not the buffer header and system trace header
    # before it, whose layout is the one PresentMon's regression recordings
    # show (fixtures/presentmon/gold-test_case_0.first-buffer.etl). A header
    # that does not read this way gives found false and the trace fails
    # closed.
    param([string]$Path)
    $header = [ordered]@{ found = $false; pointer_size = $null; number_of_processors = $null; events_lost = $null; buffers_lost = $null
        perf_freq_hz = $null; start_time_utc = $null; start_filetime = $null; end_time_utc = $null; reserved_flags = $null; clock_type = $null; error = $null }
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $bytes = New-Object byte[] 4096
            $read = $stream.Read($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
        if ($read -lt 1024) { $header.error = ('the file holds {0} bytes, fewer than a first buffer' -f $read); return $header }
        $headerType = [int]$bytes[0x4a]
        $hookId = [System.BitConverter]::ToUInt16($bytes, 0x4e)
        if (($headerType -ne 1 -and $headerType -ne 2) -or $hookId -ne 0) {
            $header.error = ('the first event is not a system trace header for the log file header (header type {0}, hook id {1})' -f $headerType, $hookId)
            return $header
        }
        $p = 0x48 + 0x20
        $pointerSize = [System.BitConverter]::ToUInt32($bytes, $p + 44)
        if ($pointerSize -ne 4 -and $pointerSize -ne 8) { $header.error = ('implausible PointerSize {0}' -f $pointerSize); return $header }
        $tail = $p + 56 + 2 * $pointerSize + 176
        if ($tail + 32 -gt $read) { $header.error = 'the header is cut short'; return $header }
        $perfFreq = [System.BitConverter]::ToInt64($bytes, $tail + 8)
        $startTime = [System.BitConverter]::ToInt64($bytes, $tail + 16)
        $endTime = [System.BitConverter]::ToInt64($bytes, $p + 16)
        $reserved = [System.BitConverter]::ToUInt32($bytes, $tail + 24)
        $major = [int]$bytes[$p + 4]
        $processors = [System.BitConverter]::ToUInt32($bytes, $p + 12)
        if ($reserved -lt 1 -or $reserved -gt 3 -or $perfFreq -le 0 -or $startTime -lt 125911584000000000 -or $startTime -gt 157469184000000000 -or $major -lt 5 -or $major -gt 12 -or $processors -lt 1 -or $processors -gt 4096) {
            $header.error = ('implausible header fields (ReservedFlags {0}, PerfFreq {1}, StartTime {2}, major version {3}, processors {4})' -f $reserved, $perfFreq, $startTime, $major, $processors)
            return $header
        }
        $header.found = $true
        $header.pointer_size = [int]$pointerSize
        $header.number_of_processors = [int]$processors
        $header.events_lost = [int64][System.BitConverter]::ToUInt32($bytes, $p + 48)
        $header.buffers_lost = [int64][System.BitConverter]::ToUInt32($bytes, $tail + 28)
        $header.perf_freq_hz = $perfFreq
        $header.start_filetime = $startTime
        $header.start_time_utc = ConvertTo-WfUtcString -Value ([datetime]::FromFileTimeUtc($startTime))
        if ($endTime -gt 0) { $header.end_time_utc = ConvertTo-WfUtcString -Value ([datetime]::FromFileTimeUtc($endTime)) }
        $header.reserved_flags = [int]$reserved
        $header.clock_type = @{ 1 = 'qpc'; 2 = 'system_time'; 3 = 'cpu_cycle_counter' }[[int]$reserved]
    } catch {
        $header.error = $_.Exception.Message
    }
    return $header
}

function Get-DiskIoDirectoryBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }
    $total = [int64]0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse -ErrorAction SilentlyContinue)) { $total += [int64]$file.Length }
    return $total
}

function ConvertTo-DiskIoRecordedText {
    # The bundle root becomes <bundle> (forward slashes under it), so the
    # bundle records no absolute path of its own location.
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

function Format-DiskIoArgument {
    param([string]$Value)
    if ($Value -match '[\s"]') { return ('"' + $Value.Replace('"', '\"') + '"') }
    return $Value
}

function Invoke-DiskIoTool {
    # One tool call through the helper's process runner, recorded for the
    # session file. For wpr the instance name, when given, is the last
    # parameter, as Microsoft documents ("-instancename must be last parameter").
    param([string]$Tool, [string]$Verb, [string[]]$Arguments, [string]$Instance = '', [int]$TimeoutSeconds, [System.Collections.Generic.List[object]]$Runs, [System.Collections.Generic.List[string]]$Log, [string]$BundleRoot = '', [int64]$MaxBytes = 16777216)
    $parts = @()
    if ($Verb) { $parts += ('-' + $Verb) }
    $parts += @($Arguments | ForEach-Object { Format-DiskIoArgument -Value $_ })
    if ($Instance) { $parts += @('-instancename', (Format-DiskIoArgument -Value $Instance)) }
    $argumentText = ($parts -join ' ')
    $run = Invoke-WfProcess -FilePath $Tool -Arguments $argumentText -TimeoutSeconds $TimeoutSeconds -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes $MaxBytes
    $stdout = ConvertTo-DiskIoRecordedText -Text ([string]$run['StdOut']) -BundleRoot $BundleRoot
    $stderr = ConvertTo-DiskIoRecordedText -Text ([string]$run['StdErr']) -BundleRoot $BundleRoot
    $record = [ordered]@{
        tool        = ($Tool -split '[\\/]')[-1]
        verb        = $(if ($Verb) { $Verb } else { $null })
        arguments   = ConvertTo-DiskIoRecordedText -Text $argumentText -BundleRoot $BundleRoot
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

function Test-DiskIoRunOk {
    param($Run)
    return ([bool]$Run['Started'] -and -not [bool]$Run['TimedOut'] -and -not [bool]$Run['Oversized'] -and $null -ne $Run['ExitCode'] -and [int]$Run['ExitCode'] -eq 0)
}

function Get-DiskIoRunFailure {
    param($Run, [string]$Tool)
    if (-not [bool]$Run['Started']) { return ('the process could not be started: ' + [string]$Run['Error']) }
    if ([bool]$Run['TimedOut']) { return [string]$Run['Error'] }
    if ([bool]$Run['Oversized']) { return [string]$Run['Error'] }
    $said = (([string]$Run['StdOut'] + ' ' + [string]$Run['StdErr']).Trim() -replace '\s+', ' ')
    if ($said.Length -gt 500) { $said = $said.Substring(0, 500) }
    return ('{0} exited with code {1}: {2}' -f $Tool, $Run['ExitCode'], $said)
}

function Get-DiskIoPrivateDir {
    # Where the trace and its dump live while the collector runs: inside the
    # output directory (a collector writes nowhere else) but outside raw/,
    # and removed before the collector exits. Nothing under it is listed.
    param([string]$BundleRoot)
    return [System.IO.Path]::Combine($BundleRoot, 'private')
}

function Remove-DiskIoPrivateData {
    # Deletes the private folder (the trace, WPR's temporary recording and
    # the dump) and says whether it is gone. Never throws.
    param([string]$BundleRoot)
    $privateDir = Get-DiskIoPrivateDir -BundleRoot $BundleRoot
    $result = [ordered]@{ existed = $false; bytes = [int64]0; removed = $true; error = $null }
    if (Test-Path -LiteralPath $privateDir) {
        $result.existed = $true
        $result.bytes = Get-DiskIoDirectoryBytes -Path $privateDir
        try { Remove-Item -LiteralPath $privateDir -Recurse -Force } catch { $result.error = $_.Exception.Message }
        $result.removed = -not (Test-Path -LiteralPath $privateDir)
    }
    return $result
}

$removePrivate = {
    # The definition's Cleanup: runs after the last source and on the way out
    # of a failure. The trace and the dump never leave the machine.
    param([string]$BundleRoot, [System.Collections.Generic.List[string]]$Log)
    $removal = Remove-DiskIoPrivateData -BundleRoot $BundleRoot
    if ($removal.existed) {
        if ($removal.removed) { $Log.Add(('private directory removed ({0} bytes): the trace and its dump stay on the machine' -f $removal.bytes)) }
        else { $Log.Add(('the private directory could not be removed and must be deleted by hand before the bundle leaves the PC: {0}' -f $removal.error)) }
    }
}

# ---------------------------------------------------------------------------
# Session control. Each step is its own function over one state map, so the
# scenario runner can adopt them: Start-DiskIoSession (preflight and start),
# Test-DiskIoSessionSettings (requested versus enabled from wpr -status),
# Wait-DiskIoSessionWindow (the bounded window), Stop-DiskIoSession (the
# save), Confirm-DiskIoSessionStopped (status, cancel, status).
# ---------------------------------------------------------------------------
function Start-DiskIoSession {
    # Preflight (tools, elevation, no recording in progress on the default
    # instance, the profile enumerated) and the start. Returns the checks;
    # sets State.ErrorKind and State.ErrorMessage on a refusal and
    # State.Started when a start was attempted (a refused start may still have
    # left a session behind, which Confirm-DiskIoSessionStopped checks).
    param($State)
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $tool = [string]$State.Tool
    $account = Get-WfAccountInfo
    $present = Test-WfToolPresent -Path $tool
    $checks.Add([ordered]@{ name = 'tool_present'; ok = $present; detail = $tool })
    $tracerptPresent = Test-WfToolPresent -Path ([string]$State.Tracerpt)
    $checks.Add([ordered]@{ name = 'tracerpt_present'; ok = $tracerptPresent; detail = [string]$State.Tracerpt })
    $elevated = [bool]$account['elevated']
    $checks.Add([ordered]@{ name = 'account_elevated'; ok = $elevated; detail = 'controlling an NT Kernel Logger session needs an elevated account (see the collector header for the citation)' })
    $checks.Add([ordered]@{ name = 'concurrent_kernel_session'; ok = $true; detail = 'not checked: Microsoft documents no read only command that lists the kernel trace sessions in progress; this collector is run alone, and a start that collides with another NT Kernel Logger session is refused by WPR and reported' })
    $idle = $false
    $accepted = $false
    if ($present -and $tracerptPresent -and $elevated) {
        $statusBefore = Invoke-DiskIoTool -Tool $tool -Verb 'status' -Arguments @() -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
        $before = Get-DiskIoStatusState -Run $statusBefore
        $idle = ($before -eq 'idle')
        $checks.Add([ordered]@{ name = 'no_recording_in_progress'; ok = $idle; detail = ('wpr -status (default instance) reads as {0}: {1}' -f $before, ((([string]$statusBefore['StdOut'] + ' ' + [string]$statusBefore['StdErr']) -replace '\s+', ' ').Trim())) })
        if ($idle) {
            $profiles = Invoke-DiskIoTool -Tool $tool -Verb 'profiles' -Arguments @($State.ProfilePath) -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
            $accepted = Test-DiskIoRunOk -Run $profiles
            $checks.Add([ordered]@{ name = 'profile_enumerated'; ok = $accepted; detail = $(if ($accepted) { 'wpr -profiles enumerated the profile file and exited 0' } else { ConvertTo-DiskIoRecordedText -Text (Get-DiskIoRunFailure -Run $profiles -Tool $tool) -BundleRoot $State.BundleRoot }) })
        }
    }
    $State.PreflightOk = ($present -and $tracerptPresent -and $elevated -and $idle -and $accepted)
    if (-not $present) {
        $State.ErrorKind = 'preflight'; $State.ErrorMessage = 'the executable does not exist: ' + $tool
    } elseif (-not $tracerptPresent) {
        $State.ErrorKind = 'preflight'; $State.ErrorMessage = 'the executable does not exist: ' + [string]$State.Tracerpt + ' (it reads the final loss statistics and dumps the saved trace for the aggregate; without it no trace could be reported as complete, so none is recorded)'
    } elseif (-not $elevated) {
        $State.ErrorKind = 'preflight'; $State.ErrorMessage = 'the account is not elevated, and controlling an NT Kernel Logger session is an Administrator operation; this collector never builds an elevation of its own (collectors/windows/README.md, Needs elevation)'
    } elseif (-not $idle) {
        $State.ErrorKind = 'preflight'; $State.ErrorMessage = 'wpr -status on the default instance did not read as idle (a recording is in progress, or the text is not the one this reader knows); this collector never cancels a recording it did not start, so it refuses to start: ' + [string]$checks[$checks.Count - 1]['detail']
    } elseif (-not $accepted) {
        $State.ErrorKind = 'preflight'; $State.ErrorMessage = 'wpr -profiles did not enumerate the recording profile: ' + [string]$checks[$checks.Count - 1]['detail']
    }
    if (-not $State.ErrorKind) {
        $null = New-Item -ItemType Directory -Force -Path $State.TempDir
        $start = Invoke-DiskIoTool -Tool $tool -Verb 'start' -Arguments $State.StartArguments -Instance $State.Instance -TimeoutSeconds $State.Timeout -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
        $State.MonotonicStart = Get-WfMonotonicSeconds
        $State.Started = $true
        if (Test-DiskIoRunOk -Run $start) {
            $State.Session.session_started_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            $State.Log.Add(('session {0} started, recording for {1} s' -f $State.Instance, $State.Duration))
        } else {
            $State.ErrorKind = 'preflight'
            $State.ErrorMessage = 'wpr -start was refused (another kernel trace session in progress is one documented cause: "There is only one NT Kernel Logger session"): ' + (ConvertTo-DiskIoRecordedText -Text (Get-DiskIoRunFailure -Run $start -Tool $tool) -BundleRoot $State.BundleRoot)
        }
    }
    return , $checks.ToArray()
}

function Test-DiskIoSessionSettings {
    # Requested versus enabled, from the tool's own status right after the
    # start: the kernel collector must be listed with every requested
    # keyword and a readable loss figure. A session whose settings cannot be
    # verified is cancelled, not recorded.
    param($State, [string]$Salt)
    $tool = [string]$State.Tool
    $statusRun = Invoke-DiskIoTool -Tool $tool -Verb 'status' -Arguments @('profiles', 'collectors', '-details') -Instance $State.Instance -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
    $statusState = Get-DiskIoStatusState -Run $statusRun
    $reason = $null
    if ($statusState -eq 'active') {
        $statusText = [string]$statusRun['StdOut']
        if ([string]$statusRun['StdErr']) { $statusText = $statusText + "`n" + [string]$statusRun['StdErr'] }
        $protected = Protect-WfMacAddresses -Text ($statusText -replace "`r`n", "`n") -Salt $Salt
        Write-WfTextFile -Path $State.StatusPath -Text (([string]$protected.Text).TrimEnd() + "`n")
        $parsed = Read-DiskIoWprStatus -Text $statusText
        $State.ParsedStatus = $parsed
        $State.Session.status_after_start = [ordered]@{
            dropped_events = $parsed.dropped_events; dropped_events_text = $parsed.dropped_events_text; logging_mode = $parsed.logging_mode
            buffers_lost_listed = $parsed.buffers_lost_listed; collectors = @($parsed.collectors); mac_addresses_replaced = $protected.Count
        }
        $kernel = @($parsed.collectors | Where-Object { [string]$_.name -eq (Get-DiskIoKernelCollectorName) })
        $State.EnabledProviders = @($parsed.collectors | ForEach-Object { [string]$_.name })
        if ($kernel.Count -ne 1) {
            $reason = ('wpr -status lists {0} collector(s) named "{1}"; exactly one is expected' -f $kernel.Count, (Get-DiskIoKernelCollectorName))
        } else {
            $State.EnabledKeywords = @($kernel[0].keywords)
            $State.EnabledStacks = @($kernel[0].stacks)
            $State.StatusBufferKb = $kernel[0].buffer_size_kb
            $State.EarlyEventsLost = $kernel[0].events_lost
            $missing = @((Get-DiskIoRequestedKeywords) | Where-Object { $State.EnabledKeywords -notcontains $_ })
            if ($State.EnabledKeywords.Count -eq 0) {
                $reason = 'wpr -status lists no System Keywords for the kernel collector, so the requested settings are not verified from tool output'
            } elseif ($missing.Count -gt 0) {
                $reason = ('requested settings were not enabled: wpr -status lists no {0} keyword for the kernel collector' -f ($missing -join ', '))
            } elseif ($null -eq $State.EarlyEventsLost) {
                $reason = ('the kernel collector''s "Events Lost" figure is missing or not a number ({0})' -f $(if ($null -eq $kernel[0].events_lost_text) { 'no line' } else { '"' + [string]$kernel[0].events_lost_text + '"' }))
            } elseif ($parsed.buffers_lost_listed) {
                $reason = 'wpr -status lists lost buffers for the session'
            } elseif ($State.EarlyEventsLost -gt 0) {
                $reason = ('wpr -status already reports {0} events lost right after the start' -f $State.EarlyEventsLost)
            }
        }
    } else {
        $reason = ('wpr -status on the collector''s own instance read as {0} right after the start, so the session and its settings could not be verified: {1}' -f $statusState, (ConvertTo-DiskIoRecordedText -Text (Get-DiskIoRunFailure -Run $statusRun -Tool $tool) -BundleRoot $State.BundleRoot))
    }
    $State.Session.settings_verified = ($null -eq $reason)
    if ($null -ne $reason) {
        $State.ErrorKind = 'other'
        $State.ErrorMessage = 'the session was cancelled without saving a trace because ' + $reason
    }
}

function Wait-DiskIoSessionWindow {
    # Records until the monotonic deadline or the cap, one second at a time.
    # Nothing else runs between the deadline and the stop.
    param($State)
    $deadline = [double]$State.MonotonicStart + $State.Duration
    while ((Get-WfMonotonicSeconds) -lt $deadline) {
        Start-WfSleep -Seconds 1
        $bytes = Get-DiskIoDirectoryBytes -Path $State.TempDir
        if ($bytes -gt $State.Session.temp_bytes_seen) { $State.Session.temp_bytes_seen = $bytes }
        if ($bytes -gt $State.MaxTraceBytes) {
            $State.Session.stopped_early_at_cap = $true
            $State.Log.Add(('the temporary recording reached {0} bytes, above the cap of {1}; stopping early' -f $bytes, $State.MaxTraceBytes))
            break
        }
    }
    $State.Session.recording_seconds = [math]::Round((Get-WfMonotonicSeconds) - [double]$State.MonotonicStart, 3)
}

function Stop-DiskIoSession {
    param($State)
    $State.Session.session_stop_issued_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $State.StopIssued = $true
    $stop = Invoke-DiskIoTool -Tool $State.Tool -Verb 'stop' -Arguments $State.StopArguments -Instance $State.Instance -TimeoutSeconds $State.Timeout -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
    if (-not (Test-DiskIoRunOk -Run $stop)) {
        $State.ErrorKind = 'other'
        $State.ErrorMessage = 'wpr -stop failed, so no trace was saved: ' + (ConvertTo-DiskIoRecordedText -Text (Get-DiskIoRunFailure -Run $stop -Tool $State.Tool) -BundleRoot $State.BundleRoot)
    }
}

function Confirm-DiskIoSessionStopped {
    # The collector's own instance is checked; anything but a confirmed idle
    # state is cancelled and checked again. Sets State.FinalState; never
    # throws, and an unconfirmed state is a failure, never a quiet success.
    param($State)
    try {
        $after = Invoke-DiskIoTool -Tool $State.Tool -Verb 'status' -Arguments @() -Instance $State.Instance -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
        $State.StateAfterStop = Get-DiskIoStatusState -Run $after
        $State.FinalState = $State.StateAfterStop
        if ($State.StateAfterStop -ne 'idle') {
            $cancel = Invoke-DiskIoTool -Tool $State.Tool -Verb 'cancel' -Arguments @() -Instance $State.Instance -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
            $State.Log.Add(('session {0} read as {1}; cancelled: exit code {2}' -f $State.Instance, $State.StateAfterStop, [string]$cancel['ExitCode']))
            $again = Invoke-DiskIoTool -Tool $State.Tool -Verb 'status' -Arguments @() -Instance $State.Instance -TimeoutSeconds $State.Short -Runs $State.Runs -Log $State.Log -BundleRoot $State.BundleRoot
            $State.FinalState = Get-DiskIoStatusState -Run $again
        }
    } catch {
        $State.FinalState = 'unknown'
        $State.Log.Add('the session state could not be confirmed: ' + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# The aggregate. The dump is the inbox tracerpt's XML rendering of the saved
# trace ("-of <CSV | EVTX | XML> Specifies the dump file format",
# https://learn.microsoft.com/windows-server/administration/windows-commands/tracerpt),
# one Event element per event in the documented event schema: System with
# Opcode and TimeCreated/@SystemTime ("The system time of when the event
# was logged"), and EventData with one Data element per property, named by
# its Name attribute
# (https://learn.microsoft.com/windows/win32/wes/eventschema-systempropertiestype-complextype,
# https://learn.microsoft.com/windows/win32/wes/eventschema-eventtype-complextype).
# Microsoft does not document how tracerpt renders the kernel MOF classes in
# that schema; the reader below recognises an event by its class GUID (the
# EventGuid element of ExtendedTracingInfo, the one place it is read from)
# and its event type (Opcode), both documented per class, and its fields by
# the MOF property names. That rendering is on the README's verification
# list, and every check below fails closed when the dump does not read this
# way.
# ---------------------------------------------------------------------------
function Get-DiskIoClassGuids {
    # NT Kernel Logger class GUIDs (https://learn.microsoft.com/windows/win32/etw/nt-kernel-logger-constants).
    return @{
        DiskIo    = '3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c'
        FileIo    = '90cbdc39-4a3e-11d1-84f4-0000f80464e3'
        PageFault = '3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c'
        Thread    = '3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c'
        Process   = '3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c'
    }
}

function Get-DiskIoNtfsExtendChildren {
    # The names NTFS itself keeps under \$Extend ("5.3 NTFS Reserved File
    # Names", https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/b04c3bd0-79dc-4e58-b8ed-74f19fc2ea0a).
    # The reserved names in the volume root ($Mft, $MftMirr, $LogFile,
    # $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase) are
    # files, counted under \ without their names; $Extend is the one
    # directory among them.
    return @('$Config', '$Delete', '$ObjId', '$Quota', '$Repair', '$Reparse', '$RmMetadata', '$Tops', '$Txf', '$TxfLog')
}

function Get-DiskIoKeptExtensions {
    # The file classes whose extension stays readable. The trace cannot tell
    # a directory from a file, so the text after the last dot of a name may
    # be the tail of a folder name; only these fixed classes are kept and
    # everything else is recorded as other.
    return @('bin', 'cache', 'cfg', 'dat', 'db', 'dll', 'etl', 'evtx', 'exe', 'ini', 'jpg', 'json', 'log', 'mp4', 'pak', 'pdf', 'png', 'sav', 'sys', 'tmp', 'txt', 'xml', 'zip')
}

function Get-DiskIoPseudonymRules {
    # What the aggregate keeps readable, written into command.json so the
    # bundle states the rules that made it. Decision of 2026-11-18: one
    # readable level below fixed roots, everything deeper a per run salted
    # pseudonym, the salt never written.
    return [ordered]@{
        fixed_roots           = @('\Windows', '\Program Files', '\Program Files (x86)', '\ProgramData', '\$Extend', '\Users\<profile>\AppData\Local', '\Users\<profile>\AppData\LocalLow', '\Users\<profile>\AppData\Roaming', '\Users\<profile>\Desktop', '\Users\<profile>\Documents', '\Users\<profile>\Downloads')
        readable_levels_below_root = 1
        profile_name          = 'the folder name under \Users becomes <profile>, whatever it is'
        root_files            = 'a file directly in the volume root is counted under the directory \ (pagefile.sys, swapfile.sys and hiberfil.sys are such files); its name is never kept'
        other_components      = 'every directory component that is not a fixed root or the one readable level below it becomes dir-<12 hex>, the first 12 hex digits of SHA-256 over a random salt and the lower cased path up to and including that component; the salt is made for this run and never written'
        file_names            = 'never kept; a row is per directory'
        ntfs_metadata         = 'the reserved NTFS names in the volume root ($Mft, $MftMirr, $LogFile, $Volume, $AttrDef, $Bitmap, $Boot, $BadClus, $Secure, $UpCase) are files counted under \ ; \$Extend is a fixed root, and the level below it stays readable only when it is one of the reserved names listed in ntfs_extend_children; any other name that starts with $ (the recycle bin, whose folders are named by account id, for one) is no root and becomes a pseudonym like every other directory'
        ntfs_extend_children  = @(Get-DiskIoNtfsExtendChildren)
        extension             = 'the lower cased text after the last dot of the name, with its dot, when it is one of kept_extensions; other when the name has a different one (the name may be a folder, whose tail must not be kept); null without one'
        kept_extensions       = @(Get-DiskIoKeptExtensions)
        volume                = 'the device name after \Device\ when the path starts with one and the name is 1 to 32 letters and digits (HarddiskVolume3), else a dir- pseudonym; null when the path carries no device'
        collector_files       = 'files under this bundle''s own directory (the trace being written, the temporary recording, the dump) are counted with path_class collector and no directory'
        unnamed_files         = 'a disk or hard fault event whose file object has no name event anywhere in the trace is counted with path_class unnamed and no directory'
        process_image         = 'ImageFileName of the process kept when it is 1 to 64 letters, digits, spaces and . _ ( ) + - starting with a letter or digit, else image-<12 hex> keyed like the directories; a thread with no Thread event in the trace has a null process'
        command_lines_and_user_ids = 'never read: the Process events carry them and they stay in the trace and the dump on the PC'
    }
}

function ConvertTo-DiskIoNumber {
    # A rendered integer field: decimal or 0x hexadecimal. Anything else is null.
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    $t = $Text.Trim()
    if ($t -match '^\d{1,20}$') {
        $value = [uint64]0
        if ([uint64]::TryParse($t, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value)) { return $value }
        return $null
    }
    if ($t -match '^0[xX]([0-9A-Fa-f]{1,16})$') {
        return [Convert]::ToUInt64($Matches[1], 16)
    }
    return $null
}

function ConvertTo-DiskIoPseudonymComponent {
    param([string]$PathSoFar, [string]$Salt)
    return (ConvertTo-WfPseudonym -Kind 'dir' -Value $PathSoFar.ToLowerInvariant() -Salt $Salt)
}

function ConvertTo-DiskIoPathParts {
    # One kernel file name to what the aggregate keeps of it: volume,
    # directory (with <profile> and dir- pseudonyms), extension class and
    # path class. CollectorPrefix is this bundle's own directory without its
    # drive letter, lower cased.
    param([string]$FileName, [string]$Salt, [string]$CollectorPrefix)
    $parts = [ordered]@{ volume = $null; directory = $null; extension = $null; path_class = 'named' }
    $components = @($FileName -split '\\' | Where-Object { $_ -ne '' })
    $volume = $null
    if ($FileName.StartsWith('\Device\', [System.StringComparison]::OrdinalIgnoreCase) -and $components.Count -ge 2) {
        $device = [string]$components[1]
        if ($device -match '^[A-Za-z][A-Za-z0-9]{0,31}$') { $volume = $device }
        else { $volume = ConvertTo-DiskIoPseudonymComponent -PathSoFar ('\Device\' + $device) -Salt $Salt }
        $components = @($components | Select-Object -Skip 2)
    }
    $parts.volume = $volume
    $relative = '\' + ($components -join '\')
    if ($CollectorPrefix -and ($relative.ToLowerInvariant() + '\').StartsWith($CollectorPrefix + '\', [System.StringComparison]::Ordinal)) {
        $parts.path_class = 'collector'
        return $parts
    }
    if ($components.Count -eq 0) {
        $parts.directory = '\'
        return $parts
    }
    $file = [string]$components[$components.Count - 1]
    $dirs = @()
    if ($components.Count -gt 1) { $dirs = @($components[0..($components.Count - 2)]) }
    $extension = [System.IO.Path]::GetExtension($file)
    if ($extension) {
        $class = $extension.Substring(1).ToLowerInvariant()
        if ((Get-DiskIoKeptExtensions) -ccontains $class) { $parts.extension = '.' + $class } else { $parts.extension = 'other' }
    }
    # The root: how many leading components stay readable as they are (the
    # profile name is replaced), then one readable level, then pseudonyms.
    $rootLength = 0
    $readableBelow = $true
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ($dirs.Count -gt 0) {
        $first = [string]$dirs[0]
        if (@('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData') -contains $first) {
            $rootLength = 1
        } elseif ($first -eq '$Extend') {
            $rootLength = 1
            $readableBelow = ($dirs.Count -ge 2 -and (Get-DiskIoNtfsExtendChildren) -contains [string]$dirs[1])
        } elseif ($first -eq 'Users' -and $dirs.Count -ge 2) {
            $shell = $null
            if ($dirs.Count -ge 4 -and [string]$dirs[2] -eq 'AppData' -and @('Local', 'LocalLow', 'Roaming') -contains [string]$dirs[3]) { $shell = 4 }
            elseif ($dirs.Count -ge 3 -and @('Desktop', 'Documents', 'Downloads') -contains [string]$dirs[2]) { $shell = 3 }
            if ($null -ne $shell) { $rootLength = $shell } else { $rootLength = -2 }
        } elseif ($first -eq 'Users') {
            $rootLength = 1
        }
    }
    $pathSoFar = ''
    for ($i = 0; $i -lt $dirs.Count; $i++) {
        $component = [string]$dirs[$i]
        $pathSoFar = $pathSoFar + '\' + $component
        if ($rootLength -lt 0) {
            # \Users\<profile> outside the shell folders: the profile is
            # replaced and everything below it is a pseudonym.
            if ($i -eq 0) { $out.Add($component) }
            elseif ($i -eq 1) { $out.Add('<profile>') }
            else { $out.Add((ConvertTo-DiskIoPseudonymComponent -PathSoFar $pathSoFar -Salt $Salt)) }
            continue
        }
        if ($i -lt $rootLength) {
            # The \Users\<profile> root replaces the user's folder name.
            if ($i -eq 1 -and [string]$dirs[0] -eq 'Users') { $out.Add('<profile>') } else { $out.Add($component) }
        } elseif ($rootLength -gt 0 -and $i -eq $rootLength -and $readableBelow) {
            $out.Add($component)
        } else {
            $out.Add((ConvertTo-DiskIoPseudonymComponent -PathSoFar $pathSoFar -Salt $Salt))
        }
    }
    $parts.directory = '\' + ($out.ToArray() -join '\')
    return $parts
}

function ConvertTo-DiskIoImageName {
    param([string]$Image, [string]$Salt)
    if ($null -eq $Image -or $Image.Length -eq 0) { return $null }
    if ($Image -match '^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,63}$') { return $Image }
    return (ConvertTo-WfPseudonym -Kind 'image' -Value $Image.ToLowerInvariant() -Salt $Salt)
}

function Read-DiskIoEventElement {
    # One Event element of the dump: class GUID, opcode, SystemTime and the
    # named Data values. The reader is positioned on the Event start tag.
    param([System.Xml.XmlReader]$Reader)
    $eventRecord = @{ Guid = $null; Opcode = $null; Time = $null; Data = @{} }
    $sub = $Reader.ReadSubtree()
    try {
        $null = $sub.Read()
        $section = ''
        $null = $sub.Read()
        while (-not $sub.EOF) {
            if ($sub.NodeType -ne [System.Xml.XmlNodeType]::Element) { $null = $sub.Read(); continue }
            $name = $sub.LocalName
            if ($sub.Depth -eq 1) { $section = $name }
            if ($section -eq 'System' -and $name -eq 'Opcode' -and $sub.Depth -eq 2) {
                $eventRecord.Opcode = $sub.ReadElementContentAsString()
            } elseif ($section -eq 'System' -and $name -eq 'TimeCreated') {
                $eventRecord.Time = $sub.GetAttribute('SystemTime')
                $null = $sub.Read()
            } elseif ($name -eq 'EventGuid' -and $section -ne 'System') {
                $text = $sub.ReadElementContentAsString()
                if ($text) { $eventRecord.Guid = $text.Trim().Trim('{', '}').ToLowerInvariant() }
            } elseif ($section -eq 'EventData' -and $name -eq 'Data') {
                $dataName = $sub.GetAttribute('Name')
                $value = $sub.ReadElementContentAsString()
                if ($dataName) { $eventRecord.Data[$dataName] = $value }
            } else {
                $null = $sub.Read()
            }
        }
    } finally {
        $sub.Dispose()
    }
    return $eventRecord
}

function Get-DiskIoPercentile {
    # Nearest rank on a sorted list.
    param([double[]]$Sorted, [double]$Fraction)
    if ($Sorted.Count -eq 0) { return $null }
    $rank = [int][math]::Ceiling($Fraction * $Sorted.Count)
    if ($rank -lt 1) { $rank = 1 }
    return $Sorted[$rank - 1]
}

function Add-DiskIoGroup {
    # Adds one disk or hard fault event to its group. Keys carry the process,
    # its image and the file name as known at the event's place in the trace,
    # or the raw thread and file object when they were not; the end of the
    # read resolves only those.
    param([hashtable]$Groups, [string]$Key, [hashtable]$Seed, [uint64]$Bytes, [string]$FlagsHex, $ResponseUs)
    $group = $Groups[$Key]
    if ($null -eq $group) {
        $group = $Seed
        $group['Operations'] = [int64]0
        $group['Bytes'] = [int64]0
        $group['FlagOps'] = @{}
        $group['FlagBytes'] = @{}
        $group['Response'] = New-Object 'System.Collections.Generic.List[double]'
        $Groups[$Key] = $group
    }
    $group['Operations'] += 1
    $group['Bytes'] += [int64]$Bytes
    if ($FlagsHex) {
        if ($group['FlagOps'].ContainsKey($FlagsHex)) { $group['FlagOps'][$FlagsHex] += 1; $group['FlagBytes'][$FlagsHex] += [int64]$Bytes }
        else { $group['FlagOps'][$FlagsHex] = [int64]1; $group['FlagBytes'][$FlagsHex] = [int64]$Bytes }
    }
    if ($null -ne $ResponseUs) { $group['Response'].Add([double]$ResponseUs) }
}

function Read-DiskIoDump {
    # Streams the dump once and returns the aggregate groups and the counts
    # the status rules need. Never holds the dump in memory.
    param([string]$Path, [int64]$PerfFreq, [int64]$StartFileTime, [double]$DeadlineMonotonic, [string]$Salt, [string]$CollectorPrefix)
    $guids = Get-DiskIoClassGuids
    $counts = [ordered]@{ events = [int64]0; disk_read = [int64]0; disk_write = [int64]0; hard_fault = [int64]0; file_name = [int64]0; thread = [int64]0; process = [int64]0
        other = [int64]0; malformed = [int64]0; malformed_first = $null; before_start = [int64]0; unresolved_thread = [int64]0; unnamed_file = [int64]0; timed_out = $false }
    $threads = @{}
    $firstThreads = @{}
    $processes = @{}
    $firstImages = @{}
    $names = @{}
    $groups = @{}
    $startTicks = [datetime]::FromFileTimeUtc($StartFileTime).Ticks
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.IgnoreWhitespace = $true
    $settings.IgnoreComments = $true
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = [System.Xml.XmlReader]::Create($stream, $settings)
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element -or $reader.LocalName -ne 'Event') { continue }
            $index = $counts.events
            $counts.events += 1
            if (($index % 1000) -eq 0 -and (Get-WfMonotonicSeconds) -gt $DeadlineMonotonic) { $counts.timed_out = $true; break }
            $eventRecord = Read-DiskIoEventElement -Reader $reader
            $opcode = ConvertTo-DiskIoNumber -Text ([string]$eventRecord.Opcode)
            $guid = [string]$eventRecord.Guid
            $data = $eventRecord.Data
            $kind = $null
            if ($guid -eq $guids.DiskIo -and ($opcode -eq 10 -or $opcode -eq 11)) { $kind = $(if ($opcode -eq 10) { 'read' } else { 'write' }) }
            elseif ($guid -eq $guids.PageFault -and $opcode -eq 32) { $kind = 'hard_fault' }
            elseif ($guid -eq $guids.FileIo -and @(0, 32, 35, 36) -contains [int]$(if ($null -eq $opcode) { -1 } else { $opcode })) { $kind = 'name' }
            elseif ($guid -eq $guids.Thread -and $opcode -ge 1 -and $opcode -le 4) { $kind = 'thread' }
            elseif ($guid -eq $guids.Process -and (($opcode -ge 1 -and $opcode -le 4) -or $opcode -eq 39)) { $kind = 'process' }
            if ($null -eq $kind) { $counts.other += 1; continue }
            if ($kind -eq 'name') {
                $fo = ConvertTo-DiskIoNumber -Text ([string]$data['FileObject'])
                if ($null -eq $fo -or -not $data.ContainsKey('FileName')) { $counts.malformed += 1; if ($null -eq $counts.malformed_first) { $counts.malformed_first = ('event:{0} FileIo name event without a FileObject or FileName' -f $index) }; continue }
                $names[('{0:x}' -f $fo)] = [string]$data['FileName']
                $counts.file_name += 1
                continue
            }
            if ($kind -eq 'thread') {
                $tid = ConvertTo-DiskIoNumber -Text ([string]$data['TThreadId'])
                $pidValue = ConvertTo-DiskIoNumber -Text ([string]$data['ProcessId'])
                if ($null -eq $tid -or $null -eq $pidValue) { $counts.malformed += 1; if ($null -eq $counts.malformed_first) { $counts.malformed_first = ('event:{0} Thread event without TThreadId or ProcessId' -f $index) }; continue }
                if (-not $firstThreads.ContainsKey([string]$tid)) {
                    $firstThreads[[string]$tid] = @{ Pid = $pidValue; Image = $(if ($processes.ContainsKey([string]$pidValue)) { [string]$processes[[string]$pidValue] } else { $null }) }
                }
                $threads[[string]$tid] = $pidValue
                $counts.thread += 1
                continue
            }
            if ($kind -eq 'process') {
                $pidValue = ConvertTo-DiskIoNumber -Text ([string]$data['ProcessId'])
                if ($null -eq $pidValue -or -not $data.ContainsKey('ImageFileName')) { $counts.malformed += 1; if ($null -eq $counts.malformed_first) { $counts.malformed_first = ('event:{0} Process event without ProcessId or ImageFileName' -f $index) }; continue }
                # A process id is reused: the image current at an event's place
                # is the one that owned the id then. The first image a id was
                # ever given names the requests seen before any Process event.
                if (-not $firstImages.ContainsKey([string]$pidValue)) { $firstImages[[string]$pidValue] = [string]$data['ImageFileName'] }
                $processes[[string]$pidValue] = [string]$data['ImageFileName']
                $counts.process += 1
                continue
            }
            # A disk or hard fault event: every field it is counted by must read.
            $timeText = Format-WfSystemTime -Text ([string]$eventRecord.Time)
            $fo = ConvertTo-DiskIoNumber -Text ([string]$data['FileObject'])
            if ($kind -eq 'hard_fault') {
                $tid = ConvertTo-DiskIoNumber -Text ([string]$data['TThreadId'])
                $size = ConvertTo-DiskIoNumber -Text ([string]$data['ByteCount'])
                $disk = $null; $flags = $null; $responseTicks = $null
                $ok = ($null -ne $timeText -and $null -ne $fo -and $null -ne $tid -and $null -ne $size)
            } else {
                $tid = ConvertTo-DiskIoNumber -Text ([string]$data['IssuingThreadId'])
                $size = ConvertTo-DiskIoNumber -Text ([string]$data['TransferSize'])
                $disk = ConvertTo-DiskIoNumber -Text ([string]$data['DiskNumber'])
                $flags = ConvertTo-DiskIoNumber -Text ([string]$data['IrpFlags'])
                $responseTicks = ConvertTo-DiskIoNumber -Text ([string]$data['HighResResponseTime'])
                $ok = ($null -ne $timeText -and $null -ne $fo -and $null -ne $tid -and $null -ne $size -and $null -ne $disk -and $null -ne $flags -and $null -ne $responseTicks)
            }
            if (-not $ok) {
                $counts.malformed += 1
                if ($null -eq $counts.malformed_first) { $counts.malformed_first = ('event:{0} {1} event with a field that is missing or not a number (SystemTime, FileObject, thread, size{2})' -f $index, $kind, $(if ($kind -eq 'hard_fault') { '' } else { ', DiskNumber, IrpFlags, HighResResponseTime' })) }
                continue
            }
            $ticks = (ConvertFrom-WfUtcString -Text $timeText).Ticks
            $bin = [int64][math]::Floor(($ticks - $startTicks) / 10000000.0)
            if ($bin -lt 0) { $counts.before_start += 1 }
            $counts[$(if ($kind -eq 'read') { 'disk_read' } elseif ($kind -eq 'write') { 'disk_write' } else { 'hard_fault' })] += 1
            $tidKey = [string]$tid
            $processToken = $(if ($threads.ContainsKey($tidKey)) { 'p:' + [string]$threads[$tidKey] } else { 't:' + $tidKey })
            $imageToken = 'u:'
            if ($processToken.StartsWith('p:') -and $processes.ContainsKey($processToken.Substring(2))) { $imageToken = 'i:' + [string]$processes[$processToken.Substring(2)] }
            $foKey = ('{0:x}' -f $fo)
            $fileToken = $(if ($names.ContainsKey($foKey)) { 'n:' + $names[$foKey] } else { 'f:' + $foKey })
            $flagsHex = $(if ($null -ne $flags) { ('0x{0:x}' -f $flags) } else { $null })
            $responseUs = $(if ($null -ne $responseTicks) { [double]$responseTicks * 1000000.0 / [double]$PerfFreq } else { $null })
            $key = ('{0}|{1}|{2}|{3}|{4}|{5}' -f $bin, $processToken, $imageToken, $fileToken, $(if ($null -eq $disk) { '' } else { [string]$disk }), $kind)
            Add-DiskIoGroup -Groups $groups -Key $key -Seed @{ Bin = $bin; Process = $processToken; Image = $imageToken; File = $fileToken; Disk = $disk; Operation = $kind } -Bytes $size -FlagsHex $flagsHex -ResponseUs $responseUs
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
    # Resolve what was not known at the event's place: a thread, process or
    # file object whose naming event came later in the trace (the DCEnd and
    # FileRundown at the end of the session). A process id without a Process
    # event at the request's place takes the first image the trace gives
    # that id, which is the next one after the request; a thread without a
    # Thread event takes the first process the trace gives that thread id
    # (an id cannot change hands before its End event) and the image that
    # process had then. Then build the rows.
    $final = @{}
    $partsCache = @{}
    foreach ($group in $groups.Values) {
        $pidValue = $null
        $token = [string]$group['Process']
        if ($token.StartsWith('p:')) { $pidValue = [uint64]$token.Substring(2) }
        elseif ($firstThreads.ContainsKey($token.Substring(2))) { $pidValue = [uint64]$firstThreads[$token.Substring(2)].Pid }
        else { $counts.unresolved_thread += [int64]$group['Operations'] }
        $rawImage = $null
        $imageToken = [string]$group['Image']
        if ($imageToken.StartsWith('i:')) { $rawImage = $imageToken.Substring(2) }
        elseif ($null -ne $pidValue -and $token.StartsWith('t:') -and $null -ne $firstThreads[$token.Substring(2)].Image) { $rawImage = [string]$firstThreads[$token.Substring(2)].Image }
        elseif ($null -ne $pidValue -and $firstImages.ContainsKey([string]$pidValue)) { $rawImage = [string]$firstImages[[string]$pidValue] }
        $image = $null
        if ($null -ne $rawImage) { $image = ConvertTo-DiskIoImageName -Image $rawImage -Salt $Salt }
        $fileToken = [string]$group['File']
        $fileName = $null
        if ($fileToken.StartsWith('n:')) { $fileName = $fileToken.Substring(2) }
        elseif ($names.ContainsKey($fileToken.Substring(2))) { $fileName = [string]$names[$fileToken.Substring(2)] }
        if ($null -eq $fileName) {
            $parts = [ordered]@{ volume = $null; directory = $null; extension = $null; path_class = 'unnamed' }
            $counts.unnamed_file += [int64]$group['Operations']
        } else {
            if (-not $partsCache.ContainsKey($fileName)) { $partsCache[$fileName] = ConvertTo-DiskIoPathParts -FileName $fileName -Salt $Salt -CollectorPrefix $CollectorPrefix }
            $parts = $partsCache[$fileName]
        }
        $finalKey = ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $group['Bin'], $pidValue, $image, $parts.volume, $parts.directory, $parts.extension, $parts.path_class, $group['Disk'], $group['Operation'])
        $row = $final[$finalKey]
        if ($null -eq $row) {
            $row = @{ Bin = $group['Bin']; Pid = $pidValue; Image = $image; Volume = $parts.volume; Directory = $parts.directory; Extension = $parts.extension; PathClass = $parts.path_class
                Disk = $group['Disk']; Operation = $group['Operation']; Operations = [int64]0; Bytes = [int64]0; FlagOps = @{}; FlagBytes = @{}; Response = (New-Object 'System.Collections.Generic.List[double]') }
            $final[$finalKey] = $row
        }
        $row['Operations'] += [int64]$group['Operations']
        $row['Bytes'] += [int64]$group['Bytes']
        foreach ($flag in @($group['FlagOps'].Keys)) {
            if ($row['FlagOps'].ContainsKey($flag)) { $row['FlagOps'][$flag] += $group['FlagOps'][$flag]; $row['FlagBytes'][$flag] += $group['FlagBytes'][$flag] }
            else { $row['FlagOps'][$flag] = $group['FlagOps'][$flag]; $row['FlagBytes'][$flag] = $group['FlagBytes'][$flag] }
        }
        $row['Response'].AddRange($group['Response'])
    }
    $order = @{ read = 0; write = 1; hard_fault = 2 }
    $sorted = @($final.Values | Sort-Object -Property @{ Expression = { [int64]$_['Bin'] } }, @{ Expression = { [string]$_['Image'] } }, @{ Expression = { $(if ($null -eq $_['Pid']) { [int64]-1 } else { [int64]$_['Pid'] }) } },
        @{ Expression = { [string]$_['PathClass'] } }, @{ Expression = { [string]$_['Volume'] } }, @{ Expression = { [string]$_['Directory'] } }, @{ Expression = { [string]$_['Extension'] } },
        @{ Expression = { $(if ($null -eq $_['Disk']) { [int64]-1 } else { [int64]$_['Disk'] }) } }, @{ Expression = { $order[[string]$_['Operation']] } })
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $sorted) {
        $isDisk = ([string]$row['Operation'] -ne 'hard_fault')
        $flagOps = $null
        $flagBytes = $null
        $sum = $null; $max = $null; $p50 = $null; $p95 = $null
        if ($isDisk) {
            $flagOps = [ordered]@{}
            $flagBytes = [ordered]@{}
            foreach ($flag in @($row['FlagOps'].Keys | Sort-Object)) { $flagOps[$flag] = [int64]$row['FlagOps'][$flag]; $flagBytes[$flag] = [int64]$row['FlagBytes'][$flag] }
            $values = $row['Response'].ToArray()
            [array]::Sort($values)
            $total = [double]0
            foreach ($v in $values) { $total += $v }
            $sum = [math]::Round($total, 3)
            $max = [math]::Round($values[$values.Count - 1], 3)
            $p50 = [math]::Round((Get-DiskIoPercentile -Sorted $values -Fraction 0.5), 3)
            $p95 = [math]::Round((Get-DiskIoPercentile -Sorted $values -Fraction 0.95), 3)
        }
        $rows.Add([ordered]@{
                bin_start_s          = [int64]$row['Bin']
                process_id           = $(if ($null -eq $row['Pid']) { $null } else { [int64]$row['Pid'] })
                process_image        = $row['Image']
                volume               = $row['Volume']
                directory            = $row['Directory']
                path_class           = $row['PathClass']
                extension            = $row['Extension']
                disk_number          = $(if ($null -eq $row['Disk']) { $null } else { [int64]$row['Disk'] })
                operation            = $row['Operation']
                operations           = [int64]$row['Operations']
                transferred_bytes    = [int64]$row['Bytes']
                irp_flags_operations = $flagOps
                irp_flags_bytes      = $flagBytes
                response_time_sum_us = $sum
                response_time_max_us = $max
                response_time_p50_us = $p50
                response_time_p95_us = $p95
            })
    }
    return [ordered]@{ Counts = $counts; Rows = $rows; Threads = $threads.Count; Processes = $processes.Count; Names = $names.Count }
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
    $short = Get-DiskIoShortTimeoutSeconds
    $entry = New-WfCollectorEntry -Id $id -Kind 'wpr' -Required ([bool]$Source['Required'])
    $roles = @{ 'diskio-trace.wprp' = 'config'; 'session.json' = 'report'; 'status.txt' = 'report'; 'tracerpt-summary.txt' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $privateDir = Get-DiskIoPrivateDir -BundleRoot $BundleRoot
    $etlPath = [System.IO.Path]::Combine($privateDir, 'trace.etl')
    $profilePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/' + (Get-DiskIoProfileFileName))
    $summaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/tracerpt-summary.txt')
    # One tracerpt call writes the dump and the summary, as in Microsoft's
    # example "tracerpt logfile.etl -o logdmp.xml -of XML -lr -summary
    # logdmp.txt -report logrpt.xml"
    # (https://learn.microsoft.com/windows-server/administration/windows-commands/tracerpt).
    # The -o file is named and lies in the private folder: "-o [filename]
    # ... The filename, if not specified, is dumpfile.xml" on that page, and
    # a dump of this trace must never be written under a default name.
    $readArguments = @($etlPath, '-o', [System.IO.Path]::Combine($privateDir, 'dump.xml'), '-of', 'XML', '-summary', $summaryPath, '-y')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $instance = 'WfDiskIoTrace-' + (ConvertTo-WfCompactUtc -Value $started)
    $tempDir = [System.IO.Path]::Combine($privateDir, 'temp')
    $startArguments = @(($profilePath + '!' + (Get-DiskIoProfileName) + '.Verbose'), '-filemode', '-recordtempto', $tempDir)
    $stopArguments = @($etlPath, ('win-forensics ' + $collectorName + ' ' + (ConvertTo-WfCompactUtc -Value $started)), '-skipPdbGen')
    $recorded = { param([string]$Text) return (ConvertTo-DiskIoRecordedText -Text $Text -BundleRoot $BundleRoot) }
    $worstCase = Get-DiskIoWorstCaseSeconds -DurationSeconds $duration -TimeoutSeconds $TimeoutSeconds
    $runs = New-Object 'System.Collections.Generic.List[object]'
    $session = [ordered]@{
        tool                 = Get-WfWprPath
        tracerpt             = Get-WfTracerptPath
        instance_name        = $instance
        profile_file         = $relativeDir + '/' + (Get-DiskIoProfileFileName)
        profile_name         = Get-DiskIoProfileName
        profile_id           = (Get-DiskIoProfileName) + '.Verbose.File'
        requested_keywords   = @(Get-DiskIoRequestedKeywords)
        buffer_size_kb       = Get-DiskIoBufferSizeKb
        buffer_count         = Get-DiskIoBufferCount
        logging_mode         = 'file'
        duration_seconds     = $duration
        max_trace_bytes      = $maxTraceBytes
        tool_timeout_seconds = $TimeoutSeconds
        short_timeout_seconds = $short
        worst_case_seconds   = $worstCase
        events_lost_bound    = 0
        buffers_lost_bound   = 0
        concurrent_kernel_session_check = 'not_checked'
        start_arguments      = @($startArguments | ForEach-Object { & $recorded $_ })
        stop_arguments       = @($stopArguments | ForEach-Object { & $recorded $_ })
        tracerpt_arguments   = @($readArguments | ForEach-Object { & $recorded $_ })
        session_started_utc  = $null
        session_stop_issued_utc = $null
        recording_seconds    = $null
        stopped_early_at_cap = $false
        temp_bytes_seen      = [int64]0
        trace_bytes          = $null
        trace_sha256         = $null
        trace_kept_in_bundle = $false
        trace_removed_reason = 'the trace holds full file paths, process command lines and user ids, and system configuration events with hardware and network addresses; it is read on the machine and never leaves it (collectors/windows/README.md, The diskio-trace sources)'
        header               = $null
        status_after_start   = $null
        settings_verified    = $null
        final                = [ordered]@{ events_lost = $null; buffers_lost = $null; events_processed = $null; source = 'the summary written by the one tracerpt read of the saved trace'; events_lost_lines = 0; buffers_lost_lines = 0; events_processed_lines = 0; labelled_lines = 0; protection = $null }
        session_state_after_stop = $null
        session_state_final  = $null
        session_confirmed_stopped = $null
        runs                 = $runs
    }
    $state = @{
        Tool = $session.tool; Tracerpt = $session.tracerpt; Instance = $instance; Runs = $runs; Log = $Log; BundleRoot = $BundleRoot
        Short = $short; Timeout = $TimeoutSeconds; Duration = $duration; MaxTraceBytes = $maxTraceBytes; ProfilePath = $profilePath; TempDir = $tempDir
        StatusPath = (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/status.txt'))
        StartArguments = $startArguments; StopArguments = $stopArguments; Session = $session
        Started = $false; StopIssued = $false; PreflightOk = $false; ErrorKind = ''; ErrorMessage = ''; MonotonicStart = $null
        ParsedStatus = $null; EnabledProviders = $null; EnabledKeywords = $null; EnabledStacks = $null; StatusBufferKb = $null; EarlyEventsLost = $null
        StateAfterStop = $null; FinalState = $null
    }
    $summary = $null
    $summaryRun = $null
    $traceBytes = $null
    $traceSha = $null
    $header = $null
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        Write-WfTextFile -Path $profilePath -Text (Get-DiskIoProfileXml)
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $profilePath) }
        $entry.command = @($session.tool, '-start') + @($startArguments | ForEach-Object { & $recorded $_ }) + @('-instancename', $instance)
        $entry.requested = [ordered]@{
            providers  = @(Get-DiskIoKernelCollectorName)
            keywords   = @(Get-DiskIoRequestedKeywords)
            stack_walk = @()
            counters   = @()
            options    = [ordered]@{
                profile_name = Get-DiskIoProfileName; profile_id = (Get-DiskIoProfileName) + '.Verbose.File'; logging_mode = 'file'; instance_name = $instance
                buffer_size_kb = Get-DiskIoBufferSizeKb; buffer_count = Get-DiskIoBufferCount
                duration_seconds = $duration; max_trace_bytes = $maxTraceBytes; events_lost_bound = 0; buffers_lost_bound = 0
                record_temp_to = '<bundle>/private/temp'; trace_path = '<bundle>/private/trace.etl'; trace_kept_in_bundle = $false
                stop_arguments = @('-stop') + @($stopArguments | ForEach-Object { & $recorded $_ }) + @('-instancename', $instance)
                tool_timeout_seconds = $TimeoutSeconds; short_timeout_seconds = $short; worst_case_seconds = $worstCase
                concurrent_kernel_session_check = 'not_checked'
                run_alone = 'until the PC verification of two WPR instances with system collectors recording at once has passed (README verification list), this collector is run alone and never next to dpcisr-trace'
            }
        }
        $entry.buffers = [ordered]@{ size_kb = Get-DiskIoBufferSizeKb; count = Get-DiskIoBufferCount; mode = 'file' }
        $checks = Start-DiskIoSession -State $state
        $entry.preflight = [ordered]@{ ok = [bool]$state.PreflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks) }
        if ($state.Started -and -not $state.ErrorKind) { Test-DiskIoSessionSettings -State $state -Salt ([string]$Context['Salt']) }
        if ($state.Started -and -not $state.ErrorKind) {
            Wait-DiskIoSessionWindow -State $state
            Stop-DiskIoSession -State $state
        }
    } catch {
        $state.ErrorKind = 'other'
        $state.ErrorMessage = 'the collector raised while running the trace session: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    } finally {
        if ($state.Started) { Confirm-DiskIoSessionStopped -State $state }
    }
    $confirmed = $null
    if ($state.Started) { $confirmed = ($state.FinalState -eq 'idle') }
    $session.session_state_after_stop = $state.StateAfterStop
    $session.session_state_final = $state.FinalState
    $session.session_confirmed_stopped = $confirmed
    if ($state.Started -and -not $confirmed) {
        $message = ('source {0}: the trace session {1} reads as {2} after the stop and cancel; run "wpr -status -instancename {1}" on the machine and "wpr -cancel -instancename {1}" if it is still recording' -f $id, $instance, $state.FinalState)
        $Notes.Add($message)
        $Log.Add($message)
    }

    # The saved trace: size, hash, header, then the final statistics from
    # tracerpt. The file itself is read by the aggregate source and removed.
    $traceOk = $false
    try {
        if ($state.StopIssued -and -not $state.ErrorKind -and (Test-Path -LiteralPath $etlPath)) {
            $traceBytes = [int64](Get-Item -LiteralPath $etlPath).Length
            if ($traceBytes -gt 0 -and $traceBytes -le $maxTraceBytes) {
                $traceSha = Get-WfSha256OfFile -Path $etlPath
                $header = Read-DiskIoEtlHeader -Path $etlPath
                $traceOk = $true
            }
        }
        $session.trace_bytes = $traceBytes
        $session.trace_sha256 = $traceSha
        $session.header = $header
        if ($traceOk -and $confirmed) {
            $summaryRun = Invoke-DiskIoTool -Tool $session.tracerpt -Verb '' -Arguments $readArguments -TimeoutSeconds $TimeoutSeconds -Runs $runs -Log $Log -BundleRoot $BundleRoot -MaxBytes $MaxArtifactBytes
            if ((Test-DiskIoRunOk -Run $summaryRun) -and (Test-Path -LiteralPath $summaryPath)) {
                $summaryBytes = [int64](Get-Item -LiteralPath $summaryPath).Length
                if ($summaryBytes -gt $MaxArtifactBytes) {
                    Remove-Item -LiteralPath $summaryPath -Force
                    $Log.Add(('the tracerpt summary is {0} bytes, above the cap of {1}, and was not kept' -f $summaryBytes, $MaxArtifactBytes))
                } else {
                    $rawSummary = [System.IO.File]::ReadAllText($summaryPath)
                    $protectedSummary = Protect-WfMacAddresses -Text (& $recorded ($rawSummary -replace "`r`n", "`n")) -Salt ([string]$Context['Salt'])
                    Write-WfTextFile -Path $summaryPath -Text (([string]$protectedSummary.Text).TrimEnd() + "`n")
                    $summary = Read-DiskIoSummary -Text $rawSummary
                    foreach ($key in @('events_lost', 'buffers_lost', 'events_processed', 'events_lost_lines', 'buffers_lost_lines', 'events_processed_lines', 'labelled_lines')) { $session.final[$key] = $summary[$key] }
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

    # Status, in the order the README states. A session that was started and
    # does not read as idle at the end is capture_failed whatever else
    # happened.
    $met = $false
    $stopped = Get-WfUtcNow
    if ($state.Started -and -not $confirmed) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the collector''s instance reads as {0} after {1}{2}, so the session may still be recording; a session whose end is not confirmed is not a complete record{3}' -f $state.FinalState, $(if ($state.StopIssued) { 'the stop' } else { 'the session was given up' }), $(if ($state.StateAfterStop -ne 'idle') { ' and the cancel' } else { '' }), $(if ($state.ErrorMessage) { '. Before that: ' + $state.ErrorMessage } else { '' }))
    } elseif ($state.ErrorKind) {
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $state.ErrorKind -ReadErrorMessage $state.ErrorMessage -WindowStartUtc $started
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
    } elseif ($null -eq $traceBytes -or $traceBytes -le 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'wpr -stop exited 0 but the trace file is missing or empty'
    } elseif ($traceBytes -gt $maxTraceBytes) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the trace is {0} bytes, above the cap of {1}, and was not read' -f $traceBytes, $maxTraceBytes)
    } elseif (-not [bool]$header.found) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the saved trace''s log file header could not be read ({0}), so its clock, start, end and loss are unknown' -f $header.error)
    } elseif (-not $header.end_time_utc) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the saved trace''s log file header carries no end time, so the session cannot be shown to have run until the stop; a trace without its end is never a complete record'
    } elseif ($header.clock_type -ne 'qpc') {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the saved trace is stamped with the {0} clock; the aggregate places its one second bins on the performance counter clock only' -f $header.clock_type)
    } elseif ([int64]$header.events_lost -gt 0 -or [int64]$header.buffers_lost -gt 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the saved trace''s log file header records {0} events lost and {1} buffers lost (the bound is 0 for both)' -f $header.events_lost, $header.buffers_lost)
    } elseif ($null -eq $summaryRun -or -not (Test-DiskIoRunOk -Run $summaryRun) -or -not (Test-Path -LiteralPath $summaryPath)) {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the final loss statistics could not be read: ' + $(if ($null -eq $summaryRun) { 'tracerpt was not run' } else { & $recorded (Get-DiskIoRunFailure -Run $summaryRun -Tool $session.tracerpt) })
    } elseif ($null -eq $finalEventsLost -or $null -eq $finalBuffersLost) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the tracerpt summary gives no single whole number for {0} ({1} events lost line(s), {2} buffers lost line(s), {3} labelled lines); a trace whose loss is unknown is never a complete record. The summary text is tracerpt-summary.txt' -f $(if ($null -eq $finalEventsLost -and $null -eq $finalBuffersLost) { 'events lost or buffers lost' } elseif ($null -eq $finalEventsLost) { 'events lost' } else { 'buffers lost' }), $summary.events_lost_lines, $summary.buffers_lost_lines, $summary.labelled_lines)
    } elseif ($finalEventsLost -gt 0 -or $finalBuffersLost -gt 0) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the saved trace lost {0} events and {1} buffers (the scenario bound is 0 for both); no aggregate is made from it. Raise the buffer count in the profile or shorten the capture' -f $finalEventsLost, $finalBuffersLost)
    } elseif ($session.stopped_early_at_cap) {
        $entry.status = 'capture_failed'
        $entry.status_reason = ('the recording was stopped early because the temporary recording reached {0} bytes, above the cap of {1}; the trace is a complete record of a shorter window' -f $session.temp_bytes_seen, $maxTraceBytes)
    } else {
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
    }
    if ($null -ne $header -and [bool]$header.found -and $header.end_time_utc) {
        # The window the trace covers, from its own header (system time
        # stamps of the session start and end).
        $entry.raw_time_range = [ordered]@{ start = $header.start_time_utc; end = $header.end_time_utc; domain = 'system_time'; unit = 'iso_utc' }
    } elseif ($session.session_started_utc -and $session.session_stop_issued_utc -and $traceOk) {
        $entry.raw_time_range = [ordered]@{ start = $session.session_started_utc; end = $session.session_stop_issued_utc; domain = 'system_time'; unit = 'iso_utc' }
    }
    $entry.events_lost = $finalEventsLost
    $entry.buffers_lost = $finalBuffersLost
    if ($null -ne $state.StatusBufferKb) { $entry.buffers.size_kb = $state.StatusBufferKb }
    $parsedStatus = $state.ParsedStatus
    $entry.enabled = [ordered]@{
        providers   = $state.EnabledProviders
        keywords    = $state.EnabledKeywords
        stack_walk  = $state.EnabledStacks
        counters    = @()
        options     = [ordered]@{
            instance_name = $instance
            dropped_events_after_start = $(if ($null -ne $parsedStatus) { $parsedStatus.dropped_events } else { $null })
            events_lost_after_start = $state.EarlyEventsLost
            buffers_lost_listed_after_start = $(if ($null -ne $parsedStatus) { $parsedStatus.buffers_lost_listed } else { $null })
            logging_mode = $(if ($null -ne $parsedStatus) { $parsedStatus.logging_mode } else { $null })
            final_events_lost = $finalEventsLost
            final_buffers_lost = $finalBuffersLost
            final_events_processed = $(if ($null -ne $summary) { $summary.events_processed } else { $null })
            clock_type = $(if ($null -ne $header) { $header.clock_type } else { $null })
            perf_freq_hz = $(if ($null -ne $header) { $header.perf_freq_hz } else { $null })
            header_events_lost = $(if ($null -ne $header) { $header.events_lost } else { $null })
            header_buffers_lost = $(if ($null -ne $header) { $header.buffers_lost } else { $null })
            session_started_utc = $session.session_started_utc
            session_stop_issued_utc = $session.session_stop_issued_utc
            recording_seconds = $session.recording_seconds
            trace_bytes = $traceBytes
            trace_sha256 = $traceSha
            trace_kept_in_bundle = $false
            temp_bytes_seen = $session.temp_bytes_seen
            stopped_early_at_cap = $session.stopped_early_at_cap
            concurrent_kernel_session_check = 'not_checked'
            session_state_after_stop = $state.StateAfterStop
            session_state_final = $state.FinalState
            session_confirmed_stopped = $confirmed
        }
        verified_by = 'keywords and buffer size from "wpr -status profiles collectors -details -instancename <name>" right after the start (status.txt); clock, PerfFreq, start, end and the header loss counters from the saved trace''s log file header (session.json header); final events lost and buffers lost from the summary of "tracerpt <trace> -o <private dump> -of XML -summary <file> -y" after the stop (tracerpt-summary.txt); the session end from "wpr -status -instancename <name>"'
    }
    $entry.exit_code = $(if ($runs.Count -gt 0) { $runs[$runs.Count - 1].exit_code } else { $null })
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = ('final events lost {0}; final buffers lost {1}; trace {2} bytes; clock {3}; recording {4} s of {5} requested; session {6}' -f $(if ($null -eq $finalEventsLost) { 'unknown' } else { $finalEventsLost }), $(if ($null -eq $finalBuffersLost) { 'unknown' } else { $finalBuffersLost }), $(if ($null -eq $traceBytes) { 'absent' } else { $traceBytes }), $(if ($null -ne $header -and $header.clock_type) { $header.clock_type } else { 'unknown' }), $(if ($null -eq $session.recording_seconds) { 'none' } else { $session.recording_seconds }), $duration, $(if ($null -eq $state.FinalState) { 'not started' } else { $state.FinalState }))
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/session.json')) -Object $session
    $Context['Tools'].Add((Get-WfToolRecord -Name 'wpr' -Version $null -Path $session.tool))
    if ($null -ne $summaryRun) { $Context['Tools'].Add((Get-WfToolRecord -Name 'tracerpt' -Version $null -Path $session.tracerpt)) }
    $Context['TraceEntry'] = $entry
    $Context['TraceStatus'] = $entry.status
    $Context['TraceStatusReason'] = $entry.status_reason
    if ($traceOk -and $confirmed -and $entry.status -eq 'observed') {
        $Context['TraceEtl'] = $etlPath
        $Context['TraceReadArguments'] = $readArguments
        $Context['TraceSha256'] = $traceSha
        $Context['TraceBytes'] = $traceBytes
        $Context['TraceHeader'] = $header
        $Context['TraceEventsProcessed'] = $summary.events_processed
        $Context['TraceRange'] = $entry.raw_time_range
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value $stopped
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# ---------------------------------------------------------------------------
# Source 2: the aggregate, made on the PC from the observed trace.
# ---------------------------------------------------------------------------
$invokeDiskIoAggregate = {
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
    $maxDumpBytes = [int64]$Source['MaxDumpBytes']
    $entry = New-WfCollectorEntry -Id $id -Kind 'other' -Required ([bool]$Source['Required'])
    $roles = @{ 'command.json' = 'config'; 'result.json' = 'report'; 'aggregate.jsonl' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $aggregatePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/aggregate.jsonl')
    $privateDir = Get-DiskIoPrivateDir -BundleRoot $BundleRoot
    $dumpPath = [System.IO.Path]::Combine($privateDir, 'dump.xml')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $recorded = { param([string]$Text) return (ConvertTo-DiskIoRecordedText -Text $Text -BundleRoot $BundleRoot) }
    $readErrorKind = ''
    $readErrorMessage = ''
    $tracerpt = Get-WfTracerptPath
    $hasTrace = $Context.ContainsKey('TraceEtl') -and (Test-Path -LiteralPath ([string]$Context['TraceEtl']))
    $header = $(if ($Context.ContainsKey('TraceHeader')) { $Context['TraceHeader'] } else { $null })
    $dumpArguments = @()
    if ($hasTrace) { $dumpArguments = @($Context['TraceReadArguments']) }
    # The bundle's own directory without its drive letter, lower cased: a
    # file under it is the collector's own (the trace being written).
    $collectorPrefix = ($BundleRoot -replace '^[A-Za-z]:', '').TrimEnd('\', '/').Replace('/', '\').ToLowerInvariant()
    $dumpBytes = $null
    $dumpSha = $null
    $parse = $null
    $removal = $null
    $result = [ordered]@{
        started_utc = ConvertTo-WfUtcString -Value $started; stopped_utc = $null
        trace = '<bundle>/private/trace.etl'; trace_sha256 = $(if ($hasTrace) { [string]$Context['TraceSha256'] } else { $null }); trace_bytes = $(if ($hasTrace) { $Context['TraceBytes'] } else { $null })
        trace_header = $header
        trace_events_processed = $(if ($Context.ContainsKey('TraceEventsProcessed')) { $Context['TraceEventsProcessed'] } else { $null })
        dump = '<bundle>/private/dump.xml'; dump_bytes = $null; dump_sha256 = $null; dump_events = $null
        counts = $null; threads_named = $null; processes_named = $null; file_objects_named = $null
        rows = 0; totals = $null; bin_range = $null
        recording_and_dump_removed = $null; removal_error = $null
    }
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $config = [ordered]@{
            tool                = $tracerpt
            arguments           = @($dumpArguments | ForEach-Object { & $recorded $_ })
            dump_made_by        = 'the wpr_trace source, in its one tracerpt call (raw/wpr_trace/session.json, runs); this source starts no process and reads the dump only when that source is observed'
            dump_format         = 'XML, the documented event schema (one Event element per event; ExtendedTracingInfo/EventGuid for the event class, System/Opcode, System/TimeCreated/@SystemTime, EventData/Data/@Name)'
            event_classes       = [ordered]@{
                DiskIo    = [ordered]@{ guid = (Get-DiskIoClassGuids).DiskIo; event_types = @(10, 11); fields = @('DiskNumber', 'IrpFlags', 'TransferSize', 'FileObject', 'HighResResponseTime', 'IssuingThreadId') }
                PageFault = [ordered]@{ guid = (Get-DiskIoClassGuids).PageFault; event_types = @(32); fields = @('FileObject', 'TThreadId', 'ByteCount') }
                FileIo    = [ordered]@{ guid = (Get-DiskIoClassGuids).FileIo; event_types = @(0, 32, 35, 36); fields = @('FileObject', 'FileName') }
                Thread    = [ordered]@{ guid = (Get-DiskIoClassGuids).Thread; event_types = @(1, 2, 3, 4); fields = @('ProcessId', 'TThreadId') }
                Process   = [ordered]@{ guid = (Get-DiskIoClassGuids).Process; event_types = @(1, 2, 3, 4, 39); fields = @('ProcessId', 'ImageFileName') }
            }
            bins                = 'one second, counted from the trace header''s StartTime on the trace''s own clock (the header must name the performance counter); an event is placed by its rendered SystemTime'
            response_time_unit  = 'microseconds: HighResResponseTime (KeQueryPerformanceCounter ticks) times 1000000 over the header''s PerfFreq'
            percentiles         = 'nearest rank over the response times of the row''s disk requests'
            irp_flags           = 'kept per row as the verbatim IrpFlags value (hex) with its operations and bytes; the paging share is derived from them by scripts/decode_diskio.py'
            pseudonyms          = Get-DiskIoPseudonymRules
            max_dump_bytes      = $maxDumpBytes
            max_artifact_bytes  = $MaxArtifactBytes
            timeout_seconds     = $TimeoutSeconds
            recording_kept      = $false
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($tracerpt) + @($dumpArguments | ForEach-Object { & $recorded $_ })
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{ max_dump_bytes = $maxDumpBytes; max_artifact_bytes = $MaxArtifactBytes; timeout_seconds = $TimeoutSeconds; bin_seconds = 1; readable_levels_below_root = 1; recording_kept = $false } }
        $checks = New-Object 'System.Collections.Generic.List[object]'
        $checks.Add([ordered]@{ name = 'trace_observed'; ok = $hasTrace; detail = $(if ($hasTrace) { 'the wpr_trace source is observed: zero events and buffers lost, the session confirmed stopped, a performance counter clock' } else { 'the wpr_trace source is ' + [string]$Context['TraceStatus'] + ': ' + [string]$Context['TraceStatusReason'] }) })
        $entry.preflight = [ordered]@{ ok = $hasTrace; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks.ToArray()) }
        if (-not $hasTrace) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'no complete trace to aggregate: the wpr_trace source is ' + [string]$Context['TraceStatus'] + '; an aggregate is made only from a trace with zero loss whose end is confirmed, so none is presented as complete'
        }
        if (-not $readErrorKind) {
            if (-not (Test-Path -LiteralPath $dumpPath)) {
                $readErrorKind = 'other'; $readErrorMessage = 'tracerpt exited 0 but wrote no dump'
            } else {
                $dumpBytes = [int64](Get-Item -LiteralPath $dumpPath).Length
                $result.dump_bytes = $dumpBytes
                if ($dumpBytes -gt $maxDumpBytes) {
                    $readErrorKind = 'other'; $readErrorMessage = ('the dump is {0} bytes, above the cap of {1}, and was not read' -f $dumpBytes, $maxDumpBytes)
                } else {
                    $dumpSha = Get-WfSha256OfFile -Path $dumpPath
                    $result.dump_sha256 = $dumpSha
                    $parseDeadline = (Get-WfMonotonicSeconds) + $TimeoutSeconds
                    $parse = Read-DiskIoDump -Path $dumpPath -PerfFreq ([int64]$header.perf_freq_hz) -StartFileTime ([int64]$header.start_filetime) -DeadlineMonotonic $parseDeadline -Salt ([string]$Context['Salt']) -CollectorPrefix $collectorPrefix
                }
            }
        }
    } catch {
        $readErrorKind = 'other'
        $readErrorMessage = 'the collector raised while making the aggregate: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        $parse = $null
    }
    # The trace and the dump are read; they are deleted now, whatever the
    # outcome, and the bundle records whether they are gone.
    $removal = Remove-DiskIoPrivateData -BundleRoot $BundleRoot
    $result.recording_and_dump_removed = [bool]$removal.removed
    $unremoved = $null
    if (-not $removal.removed) {
        $result.removal_error = & $recorded $(if ($removal.error) { [string]$removal.error } else { 'the removal raised no error and the folder is still there' })
        $unremoved = 'the recording under <bundle>/private (the trace, its temporary files or its dump) could not be confirmed removed and is still in the bundle directory, so this run is failed and nothing in it is presented as a result; delete <bundle>/private by hand and do not take this directory off the PC: ' + [string]$result.removal_error
        $message = 'source ' + $id + ': ' + $unremoved
        $Notes.Add($message)
        $Log.Add($message)
        # The trace source claimed a recording that never leaves the PC; that
        # claim no longer holds, so it is not observed either and the run
        # ends failed (no source observed, exit code 1).
        if ($Context.ContainsKey('TraceEntry') -and [string]$Context['TraceEntry'].status -eq 'observed') {
            $Context['TraceEntry'].status = 'capture_failed'
            $Context['TraceEntry'].status_reason = $unremoved
            $Context['TraceEntry'].expectation.met = $false
        }
    }
    $counts = $null
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lineBytes = [int64]0
    if ($null -ne $unremoved) { $parse = $null }
    if ($null -ne $parse) {
        $counts = $parse.Counts
        $result.counts = $counts
        $result.dump_events = $counts.events
        $result.threads_named = $parse.Threads
        $result.processes_named = $parse.Processes
        $result.file_objects_named = $parse.Names
        $processed = $result.trace_events_processed
        if ($counts.timed_out) {
            $readErrorKind = 'timeout'; $readErrorMessage = ('reading the dump did not finish within {0} seconds ({1} events read)' -f $TimeoutSeconds, $counts.events)
        } elseif ($null -eq $processed -or [int64]$processed -ne [int64]$counts.events) {
            $readErrorKind = 'other'; $readErrorMessage = ('the dump holds {0} events and the tracerpt summary states {1} events processed; a dump that is not the whole trace is never aggregated as complete' -f $counts.events, $(if ($null -eq $processed) { 'no single whole number of' } else { $processed }))
        } elseif ($counts.malformed -gt 0) {
            $readErrorKind = 'other'; $readErrorMessage = ('{0} events of the classes the aggregate counts could not be read (first: {1}); the dump does not render these events as this reader expects (README verification list)' -f $counts.malformed, $counts.malformed_first)
        } elseif ($counts.disk_read + $counts.disk_write -eq 0) {
            $readErrorKind = 'other'; $readErrorMessage = ('the dump holds no DiskIo Read or Write event this reader recognises ({0} events read, {1} of other classes); zero disk requests over a recording window is not accepted as a quiet window, because a dump this reader cannot read looks the same' -f $counts.events, $counts.other)
        } else {
            foreach ($row in $parse.Rows) {
                $line = ConvertTo-WfJson -Value $row
                $lines.Add($line)
                $lineBytes += [int64]$line.Length + 1
            }
            if ($lineBytes -gt $MaxArtifactBytes) {
                $readErrorKind = 'other'; $readErrorMessage = ('the aggregate is {0} bytes, above the cap of {1}, and was not kept' -f $lineBytes, $MaxArtifactBytes)
                $lines.Clear()
            }
        }
    }
    $stopped = Get-WfUtcNow
    $met = $false
    if ($null -ne $unremoved) {
        $entry.status = 'capture_failed'
        $entry.status_reason = $unremoved
    } elseif ($readErrorKind) {
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
    } else {
        Write-WfTextFile -Path $aggregatePath -Text (($lines.ToArray() -join "`n") + "`n")
        $entry.status = 'observed'
        $entry.status_reason = $null
        $met = $true
        $totals = [ordered]@{ read_operations = [int64]0; read_bytes = [int64]0; write_operations = [int64]0; write_bytes = [int64]0; hard_fault_operations = [int64]0; hard_fault_bytes = [int64]0 }
        $bins = @()
        foreach ($row in $parse.Rows) {
            $totals[[string]$row.operation + '_operations'] += [int64]$row.operations
            $totals[[string]$row.operation + '_bytes'] += [int64]$row.transferred_bytes
            $bins += [int64]$row.bin_start_s
        }
        $result.totals = $totals
        $result.rows = $lines.Count
        $result.bin_range = [ordered]@{ first_bin_start_s = ($bins | Measure-Object -Minimum).Minimum; last_bin_start_s = ($bins | Measure-Object -Maximum).Maximum }
        if ($Context.ContainsKey('TraceRange')) { $entry.raw_time_range = $Context['TraceRange'] }
    }
    $result.stopped_utc = ConvertTo-WfUtcString -Value $stopped
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $result
    $entry.exit_code = $null
    $entry.enabled = [ordered]@{
        providers = @(); keywords = @(); stack_walk = @(); counters = @()
        options   = [ordered]@{
            rows = $(if ($entry.status -eq 'observed') { $lines.Count } else { 0 })
            dump_events = $result.dump_events
            trace_events_processed = $result.trace_events_processed
            disk_read_events = $(if ($null -ne $counts) { $counts.disk_read } else { $null })
            disk_write_events = $(if ($null -ne $counts) { $counts.disk_write } else { $null })
            hard_fault_events = $(if ($null -ne $counts) { $counts.hard_fault } else { $null })
            malformed_events = $(if ($null -ne $counts) { $counts.malformed } else { $null })
            unresolved_thread_operations = $(if ($null -ne $counts) { $counts.unresolved_thread } else { $null })
            unnamed_file_operations = $(if ($null -ne $counts) { $counts.unnamed_file } else { $null })
            trace_sha256 = $result.trace_sha256
            dump_bytes = $result.dump_bytes
            dump_sha256 = $result.dump_sha256
            recording_and_dump_removed = $result.recording_and_dump_removed
            clock_type = $(if ($null -ne $header) { $header.clock_type } else { $null })
            perf_freq_hz = $(if ($null -ne $header) { $header.perf_freq_hz } else { $null })
            trace_start_utc = $(if ($null -ne $header) { $header.start_time_utc } else { $null })
        }
        verified_by = 'the dump''s event count against the tracerpt summary''s events processed, every counted event read whole, and the removal of the trace and the dump checked on disk (result.json)'
    }
    $entry.expectation = [ordered]@{
        declared = [string]$Source['Expectation']
        met      = $met
        detail   = $(if ($null -ne $counts) { ('{0} events in the dump, {1} reads, {2} writes, {3} hard faults, {4} malformed, {5} rows; trace and dump removed: {6}' -f $counts.events, $counts.disk_read, $counts.disk_write, $counts.hard_fault, $counts.malformed, $result.rows, $result.recording_and_dump_removed) } else { 'no dump was read' })
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
if ($MaxDumpBytes -lt 16777216 -or $MaxDumpBytes -gt 17179869184) {
    [Console]::Error.WriteLine($collectorName + ': MaxDumpBytes must be between 16 MiB and 16 GiB')
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}
$worstCaseSeconds = Get-DiskIoWorstCaseSeconds -DurationSeconds $DurationSeconds -TimeoutSeconds $TimeoutSeconds
if ($worstCaseSeconds -gt (Get-DiskIoDispatcherBudgetSeconds)) {
    Write-WfStderrLine -Text (('{0}: the worst case run time is {1} seconds with -DurationSeconds {2} and -TimeoutSeconds {3}, above the dispatcher budget of {4}; lower one of them' -f $collectorName, $worstCaseSeconds, $DurationSeconds, $TimeoutSeconds, (Get-DiskIoDispatcherBudgetSeconds)))
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}

$definition = @{
    Name                     = $collectorName
    Version                  = '1.0.0'
    Question                 = 'What reads from and writes to disk while the PC is in use, per process, per directory, per disk, in one second bins?'
    RequestedDurationSeconds = $DurationSeconds
    Calibration              = @{
        status = 'not_collected'
        method = 'none in this collector: the aggregate''s bins are seconds on the trace''s own performance counter clock from its header StartTime (etw_qpc_relative); the calibration pairs that relate it to system time come from the clock collector, a separate piece. Run alone: no other kernel trace session was checked for (Microsoft documents no read only listing of them)'
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
            Expectation     = 'wpr starts the profile under the collector''s own instance name, lists the kernel collector with DiskIO, Filename, HardFaults and ProcessThread and a readable loss figure, records for the requested duration, saves a non empty trace within the cap whose header names the performance counter clock, an end time and no loss, reads as idle after the stop, and the one tracerpt call that writes the dump into the private folder and the summary reports zero events lost and zero buffers lost'
        },
        @{
            Id           = 'diskio_aggregate'
            Type         = 'script'
            Required     = $true
            Invoke       = $invokeDiskIoAggregate
            MaxDumpBytes = $MaxDumpBytes
            Expectation  = 'the XML dump tracerpt made of the observed trace is there and within the cap, the dump holds exactly the events the summary says were processed, every disk, hard fault, file name, thread and process event reads whole, at least one disk request is recognised, the aggregate fits the cap, and the trace and the dump are deleted and seen gone (when they are not, both sources are capture_failed and the run is failed)'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
