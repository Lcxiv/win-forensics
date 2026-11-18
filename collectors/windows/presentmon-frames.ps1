# presentmon-frames: What did the frame pipeline do, frame by frame, during a
# bounded window: present cadence, time in the Present call, CPU and GPU busy
# and wait time, display latency, with every frame stamped in the ETW
# performance counter domain?
#
# Live capture, passive, and with no process handle anywhere. Runs under
# Windows PowerShell 5.1 as the collector account. Writes one bundle
# (docs/contracts/bundle.md) into -OutputDirectory, prints one JSON summary
# line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md for the interface, the pinned binary, every
# option with its citation, the status rules, the anti-cheat position, and
# the facts still to be verified on a real machine.
#
# Two programs run, both through the helper's one process runner:
#
#  1. Windows Performance Recorder (wpr.exe, inbox since Windows 8.1) records
#     the ETW providers PresentMon 2.6.0 enables for its default options into
#     a file inside the bundle, from a profile this script writes
#     (Get-WfPresentMonProfileXml), bounded in time (this script stops it) and
#     in size (MaximumFileSize, FileMode Sequential: "the trace stops when the
#     file size reaches the given size"). WPR is an ETW controller: it opens no
#     process. The recording is stopped on every exit path: -stop on the normal
#     path, -cancel whenever -stop did not complete, and -status afterwards to
#     confirm; whether that confirmation succeeded is in the manifest.
#     Trace loss is read from the controller (wpr -status prints "Events Lost"
#     per collector) and from the file's own header (TRACE_LOGFILE_HEADER
#     EventsLost and BuffersLost); any loss is capture_failed.
#
#  2. The operator supplied PresentMon console application, pinned by version
#     and SHA-256 (below) and verified before it runs, reads that file offline
#     with --etl_file. In that mode PresentMon opens no process: at tag v2.6.0,
#     PresentMon/OutputThread.cpp QueryProcessName() calls OpenProcess only
#     when args.mEtlFileName == nullptr (lines 294 to 319), and
#     PresentMon/MainThread.cpp enables SeDebugPrivilege only for realtime
#     analysis (lines 255 to 277, "If we are processing an ETL file we don't
#     need elevated privilege"). Process names come from the recorded
#     Microsoft-Windows-Kernel-Process events instead
#     (PresentData/PresentMonTraceConsumer.cpp HandleProcessEvent).
#
# Live PresentMon is never run by this collector, and that is deliberate:
# in its realtime mode the same function opens a PROCESS_QUERY_LIMITED_INFORMATION
# handle to every presenting process, the game included, and keeps it for the
# capture (OutputThread.cpp lines 294 to 319 and 212 to 231), and MainThread.cpp
# enables SeDebugPrivilege when it can. The accepted intent for this work is no
# handle to the game, so the recording is made by a controller that opens none
# and PresentMon only ever sees the file. tests/test_collectors_static.py
# checks that no realtime option (--timed, --session_name, --process_id,
# --terminate_after_timed, --terminate_existing_session, --stop_existing_session,
# --restart_as_admin, --hotkey) appears in this script.
#
# Nothing is downloaded or installed: when the binary is missing or its hash
# differs, nothing runs and the source is not_collected with the reason. The
# providers, keywords, levels and capture state requests in the profile are
# taken from PresentData/PresentMonTraceSession.cpp EnableProvidersListing()
# at tag v2.6.0 for the console application's default options (track display,
# GPU and input on; video, frame type, hybrid present, app timing, PC latency
# and D3D12 shader compilation off), with the same two adjustments PresentMon
# makes: the DxgKrnl Performance keyword is never used ("can have side-effects
# with negative performance impact on some versions of Windows") and the
# pre Windows 11 Dwm-Core Composition keyword is included next to Scheduling.
#
# PresentMon options passed (README-ConsoleApplication.md at v2.6.0):
#   --etl_file path       "Analyze an ETW trace log file instead of the actively running processes."
#   --output_file path    "Write CSV output to the specified path."
#   --no_console_stats    "Do not display active swap chains and frame statistics in the console."
#   --qpc_time            "Output the CPU start time as a performance counter value." (column CPUStartQPC)
#   --process_name name   "Only record processes with the specified exe name." (repeatable, optional)
# WPR options passed (WPR Command-Line Options, learn.microsoft.com):
#   -start <profile> -filemode -recordtempto <folder>, -status collectors -details, -stop <file> <description> -skipPdbGen, -cancel
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long the recording runs, in seconds (5 to 240). The other phases
    # (start, status, stop and merge, offline decode) have fixed deadlines so
    # the whole run stays inside the dispatcher's 900 seconds.
    [int]$DurationSeconds = 60,
    # Process names PresentMon keeps when it reads the recording (each becomes
    # one --process_name). Empty keeps every presenting process. Names are
    # matched against the recorded Kernel-Process events, never against a
    # live process.
    [string[]]$ProcessName = @(),
    # Where the pinned PresentMon console binary is. Empty means
    # <install root>\tools\PresentMon-2.6.0-x64.exe, two directories above
    # this script (C:\ProgramData\win-forensics\tools on the PC).
    [string]$PresentMonPath = '',
    # Cap on the recording, in bytes (1 MiB to 1 GiB): the profile's
    # MaximumFileSize in whole megabytes, at which ETW stops the session, and
    # the cap on the CSV PresentMon writes from it.
    [long]$MaxArtifactBytes = 67108864
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'presentmon-frames'
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

# --- the pin -----------------------------------------------------------------
# GitHub release v2.6.0 of GameTechDev/PresentMon, published 2026-09-21, asset
# PresentMon-2.6.0-x64.exe. The digest is the one GitHub records for the
# release asset (the release API's digest field, read 2026-11-18); the size is
# the asset size from the same record. Only these exact bytes are run.
function Get-WfPresentMonPinnedVersion { return '2.6.0' }
function Get-WfPresentMonPinnedFileName { return 'PresentMon-2.6.0-x64.exe' }
function Get-WfPresentMonPinnedSha256 { return 'b2a706bc6ad475749e3b7e3409263aa1e6906d45bdcf993f6dbc0f660188f1af' }
function Get-WfPresentMonPinnedLength { return [int64]980320 }
function Get-WfPresentMonReleaseUrl { return 'https://github.com/GameTechDev/PresentMon/releases/tag/v2.6.0' }
function Get-WfPresentMonAssetUrl { return 'https://github.com/GameTechDev/PresentMon/releases/download/v2.6.0/PresentMon-2.6.0-x64.exe' }
function Get-WfPresentMonDocumentationUrl { return 'https://github.com/GameTechDev/PresentMon/blob/v2.6.0/README-ConsoleApplication.md' }
function Get-WfPresentMonSourceUrl { return 'https://github.com/GameTechDev/PresentMon/tree/v2.6.0' }
# The WPR recording: the ETW session name and the profile name inside the
# .wprp this script writes. Only this collector uses them.
function Get-WfPresentMonSessionName { return 'wf-presentmon-frames' }
function Get-WfPresentMonProfileName { return 'WfPresentMonFrames' }
# Deadlines in seconds for the phases that are not the recording window.
function Get-WfPresentMonStartDeadline { return 60 }
function Get-WfPresentMonStatusDeadline { return 30 }
function Get-WfPresentMonStopDeadline { return 180 }
function Get-WfPresentMonDecodeDeadline { return 240 }
function Get-WfPresentMonCancelDeadline { return 60 }
# Cap on what a program may print on its two console streams.
function Get-WfPresentMonConsoleCapBytes { return [int64]1048576 }
# A process name: letters, digits, dot, underscore and hyphen, not starting
# with a hyphen, so it can never read as an option.
function Get-WfPresentMonProcessNamePattern { return '^[A-Za-z0-9._][A-Za-z0-9._-]{0,119}$' }

function Get-WfPresentMonDefaultPath {
    # <install root>\tools\<pinned file name>: the collectors live two levels
    # below the install root (remote\collectors on the PC; collectors\windows
    # in the repository, where tools\ is ignored by git).
    param([string]$ScriptRoot)
    $installRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)
    return [System.IO.Path]::Combine($installRoot, 'tools', (Get-WfPresentMonPinnedFileName))
}

function Get-WfPresentMonProviders {
    # The providers PresentMon 2.6.0 enables for the console application's
    # default options, from PresentData/PresentMonTraceSession.cpp
    # EnableProvidersListing() and the event declarations under
    # PresentData/ETW/*.h at tag v2.6.0. Keywords are the OR of the enabled
    # events' keywords (PresentMon's "any keyword" mask), levels the highest
    # event level (0 is LogAlways, which WPR treats as every level), and the
    # capture state keywords are the ones PresentMon enables a second time
    # with EVENT_CONTROL_CODE_CAPTURE_STATE. Strict marks the providers whose
    # failure makes PresentMon's own session start fail; the two that
    # PresentMon tolerates (Kernel-Process, which it allows to be access
    # denied, and the NVIDIA display driver provider, absent without that
    # driver) are not strict here either.
    return @(
        [ordered]@{ id = 'Microsoft-Windows-Kernel-Process'; guid = '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716'; keywords = '0x8000000000000010'; level = 4; capture_state = '0x8000000000000010'; strict = $false
            events = @(1, 2, 15); source = 'EnableProvidersListing: ProcessStart_Start, ProcessStop_Stop, ProcessRundown_Info, plus EVENT_CONTROL_CODE_CAPTURE_STATE for the rundown of processes already running' },
        [ordered]@{ id = 'Microsoft-Windows-DxgKrnl'; guid = '802ec45a-1e99-4b83-9920-87c98277ba9d'; keywords = '0x8000841'; level = 4; capture_state = '0x840'; strict = $true
            events = @(17, 27, 28, 29, 30, 31, 32, 116, 166, 168, 171, 172, 175, 177, 178, 180, 184, 215, 244, 252, 259, 266, 273, 382, 422, 424, 501); source = 'EnableProvidersListing: the present history, flip, blit, queue packet, VSync, context, device, hardware queue and DMA packet events for track display and track GPU; the Performance keyword (0x4000000000000000) is removed as PresentMon does; capture state for Context_DCStart and Device_DCStart' },
        [ordered]@{ id = 'Microsoft-Windows-Win32k'; guid = '8c416c79-d49b-4f01-a467-e56d3aa8234c'; keywords = '0x8400000440c01000'; level = 4; capture_state = $null; strict = $true
            events = @(63, 73, 201, 225, 301); source = 'EnableProvidersListing: TokenCompositionSurfaceObject_Info, TokenStateChanged_Info (track display), InputDeviceRead_Stop, RetrieveInputMessage_Info, OnInputXformUpdate_Info (track input)' },
        [ordered]@{ id = 'Microsoft-Windows-Dwm-Core'; guid = '9e9bba3c-2e38-40cb-99f4-9e8281425164'; keywords = '0x8000000000000081'; level = 5; capture_state = $null; strict = $true
            events = @(15, 64, 69, 70, 101, 196); source = 'EnableProvidersListing: GetPresentHistory_Info, SCHEDULE_PRESENT_Start, SCHEDULE_SURFACEUPDATE_Info, FlipChain_Pending, FlipChain_Complete, FlipChain_Dirty; Composition (0x1) is added for Windows 10, where PresentMon swaps it for Scheduling (0x80)' },
        [ordered]@{ id = 'Microsoft-Windows-Dwm-Core-Win7'; guid = '8c9dd1ad-e6e5-4b07-b455-684a9d879900'; keywords = $null; level = 5; capture_state = $null; strict = $false
            events = @(); source = 'EnableProvidersListing: EnableWithoutFiltering(Microsoft_Windows_Dwm_Core::Win7::GUID, TRACE_LEVEL_VERBOSE)' },
        [ordered]@{ id = 'Microsoft-Windows-DxgKrnl-Win7'; guid = '65cd4c8a-0848-4583-92a0-31c0fbaf00c0'; keywords = $null; level = 4; capture_state = $null; strict = $false
            events = @(); source = 'EnableProvidersListing: EnableWithoutFiltering(Microsoft_Windows_DxgKrnl::Win7::GUID, TRACE_LEVEL_INFORMATION)' },
        [ordered]@{ id = 'Microsoft-Windows-DXGI'; guid = 'ca11c036-0102-4a2d-a6ad-f03cfed5d3c9'; keywords = '0x8000000000000002'; level = 0; capture_state = $null; strict = $true
            events = @(42, 43, 55, 56); source = 'EnableProvidersListing: Present_Start, Present_Stop, PresentMultiplaneOverlay_Start, PresentMultiplaneOverlay_Stop' },
        [ordered]@{ id = 'Microsoft-Windows-D3D9'; guid = '783aca0a-790e-4d7f-8451-aa850511c6b9'; keywords = '0x8000000000000002'; level = 0; capture_state = $null; strict = $true
            events = @(1, 2); source = 'EnableProvidersListing: Present_Start, Present_Stop' },
        [ordered]@{ id = 'NVIDIA-DisplayDriver'; guid = 'ae4f8626-8265-40d1-a70b-11b64240e8e9'; keywords = '0x1000000000000000'; level = 4; capture_state = $null; strict = $false
            events = @(1); source = 'EnableProvidersListing: NvidiaDisplayDriver_Events::FlipRequest (PresentData/ETW/NV_DD.h)' }
    )
}

function Get-WfPresentMonProfileXml {
    # The WPR recording profile (Authoring Recording Profiles,
    # learn.microsoft.com/windows-hardware/test/wpt): one EventCollector named
    # after the session with PresentMon's buffer geometry (64 KB buffers, 256
    # of them: PresentMonTraceSession.cpp Start(), BufferSize 64,
    # MinimumBuffers 256) and a sequential file cap, one EventProvider per
    # provider above (Name is the GUID, Level, Keywords, CaptureStateOnStart,
    # NonPagedMemory because DxgKrnl logs from kernel mode), and one File,
    # Verbose profile whose Id is Name.DetailLevel.LoggingMode.
    param([int]$MaximumFileSizeMb)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<?xml version="1.0" encoding="utf-8"?>')
    $lines.Add('<WindowsPerformanceRecorder Version="1.0" Author="win-forensics presentmon-frames" Comments="ETW providers PresentMon 2.6.0 enables for its default options, recorded for offline analysis with --etl_file">')
    $lines.Add('  <Profiles>')
    $lines.Add(('    <EventCollector Id="EventCollector_{0}" Name="{1}" FileName="{1}.etl">' -f (Get-WfPresentMonProfileName), (Get-WfPresentMonSessionName)))
    $lines.Add('      <BufferSize Value="64"/>')
    $lines.Add('      <Buffers Value="256"/>')
    $lines.Add(('      <MaximumFileSize Value="{0}" FileMode="Sequential"/>' -f $MaximumFileSizeMb))
    $lines.Add('    </EventCollector>')
    foreach ($provider in (Get-WfPresentMonProviders)) {
        $attributes = ('Id="EventProvider_{0}" Name="{1}" NonPagedMemory="true"' -f ([string]$provider['id'] -replace '[^A-Za-z0-9]', ''), [string]$provider['guid'])
        if ([int]$provider['level'] -gt 0) { $attributes += (' Level="{0}"' -f [int]$provider['level']) }
        if ($provider['strict']) { $attributes += ' Strict="true"' }
        if ($null -eq $provider['keywords'] -and $null -eq $provider['capture_state']) {
            $lines.Add(('    <EventProvider {0}/>' -f $attributes))
            continue
        }
        $lines.Add(('    <EventProvider {0}>' -f $attributes))
        if ($null -ne $provider['keywords']) {
            $lines.Add('      <Keywords>')
            $lines.Add(('        <Keyword Value="{0}"/>' -f [string]$provider['keywords']))
            $lines.Add('      </Keywords>')
        }
        if ($null -ne $provider['capture_state']) {
            $lines.Add('      <CaptureStateOnStart>')
            $lines.Add(('        <Keyword Value="{0}"/>' -f [string]$provider['capture_state']))
            $lines.Add('      </CaptureStateOnStart>')
        }
        $lines.Add('    </EventProvider>')
    }
    $lines.Add(('    <Profile Id="{0}.Verbose.File" Name="{0}" Description="win-forensics presentmon-frames: the providers PresentMon 2.6.0 enables, recorded to a file" LoggingMode="File" DetailLevel="Verbose">' -f (Get-WfPresentMonProfileName)))
    $lines.Add('      <ProblemCategories>')
    $lines.Add('        <ProblemCategory Value="First level triage"/>')
    $lines.Add('      </ProblemCategories>')
    $lines.Add('      <Collectors>')
    $lines.Add(('        <EventCollectorId Value="EventCollector_{0}">' -f (Get-WfPresentMonProfileName)))
    $lines.Add('          <EventProviders>')
    foreach ($provider in (Get-WfPresentMonProviders)) {
        $lines.Add(('            <EventProviderId Value="EventProvider_{0}"/>' -f ([string]$provider['id'] -replace '[^A-Za-z0-9]', '')))
    }
    $lines.Add('          </EventProviders>')
    $lines.Add('        </EventCollectorId>')
    $lines.Add('      </Collectors>')
    $lines.Add('    </Profile>')
    $lines.Add('  </Profiles>')
    $lines.Add('</WindowsPerformanceRecorder>')
    return (($lines.ToArray() -join "`r`n") + "`r`n")
}

function Read-WfEtlHeader {
    # The first event of an ETW log file is the log file header
    # (TRACE_LOGFILE_HEADER, "the raw data format of the trace information
    # data in the header of an ETW log file"; EventTrace_Header MOF class).
    # It is found by the class GUID of that event, EventTraceGuid
    # {68fdd900-4a3e-11d1-84f4-0000f80464e3} (EventTraceEvent MOF class), in
    # the first 64 KiB: the size of the buffer header that precedes the event
    # is not documented, so the GUID is searched for rather than assumed at an
    # offset. The event header before the payload is the 48 byte
    # EVENT_TRACE_HEADER with the GUID at offset 24; the payload fields follow
    # the documented structure, with the pointer members at PointerSize and
    # TIME_ZONE_INFORMATION padded to 176 bytes (EventTrace_Header Max(176)).
    # Returns the fields the collector uses, or found false. The layout is
    # inferred from the documented structures and has not been checked
    # against a file from a real machine (README verification item 27).
    param([string]$Path)
    $header = [ordered]@{ found = $false; offset = $null; buffer_size_bytes = $null; os_version = $null; number_of_processors = $null; pointer_size = $null
        buffers_written = $null; events_lost = $null; buffers_lost = $null; log_file_mode = $null; maximum_file_size_mb = $null
        perf_freq_hz = $null; start_time_utc = $null; end_time_utc = $null; reserved_flags = $null; clock_type = $null; error = $null }
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $bytes = New-Object byte[] 65536
            $read = $stream.Read($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
        $guid = [byte[]](0x00, 0xd9, 0xfd, 0x68, 0x3e, 0x4a, 0xd1, 0x11, 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3)
        $at = -1
        for ($i = 24; $i -le $read - 16 - 300; $i++) {
            if ($bytes[$i] -ne 0x00 -or $bytes[$i + 1] -ne 0xd9) { continue }
            $match = $true
            for ($j = 0; $j -lt 16; $j++) { if ($bytes[$i + $j] -ne $guid[$j]) { $match = $false; break } }
            if ($match) { $at = $i; break }
        }
        if ($at -lt 0) { $header.error = 'no log file header event (EventTraceGuid) in the first 64 KiB'; return $header }
        $p = $at - 24 + 48
        $pointerSize = [System.BitConverter]::ToUInt32($bytes, $p + 44)
        if ($pointerSize -ne 4 -and $pointerSize -ne 8) { $header.error = ('implausible PointerSize {0} at offset {1}' -f $pointerSize, ($p + 44)); return $header }
        # LoggerName and LogFileName are pointers (PointerSize each) after
        # CpuSpeedInMHz; TIME_ZONE_INFORMATION (172 bytes) follows, padded to
        # 176 so that BootTime is 8 byte aligned; then BootTime, PerfFreq,
        # StartTime (8 bytes each), ReservedFlags and BuffersLost (4 each).
        $timeZone = $p + 56 + 2 * $pointerSize
        $tail = $timeZone + 176
        $perfFreq = [System.BitConverter]::ToInt64($bytes, $tail + 8)
        $startTime = [System.BitConverter]::ToInt64($bytes, $tail + 16)
        $endTime = [System.BitConverter]::ToInt64($bytes, $p + 16)
        $reserved = [System.BitConverter]::ToUInt32($bytes, $tail + 24)
        if ($reserved -lt 1 -or $reserved -gt 3 -or $startTime -le 0) { $header.error = ('implausible ReservedFlags {0} or StartTime {1}' -f $reserved, $startTime); return $header }
        $header.found = $true
        $header.offset = $p
        $header.buffer_size_bytes = [int64][System.BitConverter]::ToUInt32($bytes, $p + 0)
        $header.os_version = ('{0}.{1}.{2}' -f $bytes[$p + 4], $bytes[$p + 5], [System.BitConverter]::ToUInt32($bytes, $p + 8))
        $header.number_of_processors = [int][System.BitConverter]::ToUInt32($bytes, $p + 12)
        $header.pointer_size = [int]$pointerSize
        $header.buffers_written = [int64][System.BitConverter]::ToUInt32($bytes, $p + 36)
        $header.events_lost = [int64][System.BitConverter]::ToUInt32($bytes, $p + 48)
        $header.log_file_mode = ('0x{0:x}' -f [System.BitConverter]::ToUInt32($bytes, $p + 32))
        $header.maximum_file_size_mb = [int64][System.BitConverter]::ToUInt32($bytes, $p + 28)
        $header.buffers_lost = [int64][System.BitConverter]::ToUInt32($bytes, $tail + 28)
        $header.perf_freq_hz = $perfFreq
        $header.start_time_utc = ConvertTo-WfUtcString -Value ([datetime]::FromFileTimeUtc($startTime))
        if ($endTime -gt 0) { $header.end_time_utc = ConvertTo-WfUtcString -Value ([datetime]::FromFileTimeUtc($endTime)) }
        $header.reserved_flags = [int]$reserved
        $header.clock_type = @{ 1 = 'qpc'; 2 = 'system_time'; 3 = 'cpu_cycle_counter' }[[int]$reserved]
    } catch {
        $header.error = $_.Exception.Message
    }
    return $header
}

function Get-WfWprStatusFacts {
    # What wpr -status printed, read by the two documented lines: "WPR
    # recording is in progress..." when a recording is active, and one
    # "Events Lost : n" line per collector with "collectors" (WPR Command-Line
    # Options, Status). Events lost is the sum over the collectors listed,
    # null when no such line was printed.
    param([string]$Text)
    $facts = [ordered]@{ in_progress = ($Text -match 'WPR recording is in progress'); events_lost = $null; collectors = @() }
    $lost = [int64]0
    $seen = $false
    foreach ($m in [regex]::Matches($Text, '(?im)^\s*Events Lost\s*:\s*(\d+)')) { $lost += [int64]$m.Groups[1].Value; $seen = $true }
    if ($seen) { $facts.events_lost = $lost }
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($m in [regex]::Matches($Text, '(?im)^\s*Collector Name\s*:\s*(.+?)\s*$')) { $names.Add($m.Groups[1].Value) }
    $facts.collectors = @($names.ToArray())
    return $facts
}

function Get-WfPresentMonFlaggedLines {
    # Lines of a program's console text that look like a warning or an error,
    # kept verbatim (capped). PresentMon's realtime warnings about lost ETW
    # events (MainThread.cpp lines 448 to 462) are printed only when its own
    # session exists, which it never does in --etl_file mode, so trace loss
    # comes from the controller and the file header instead; this list is for
    # the reader.
    param([string]$Text, [int]$Limit = 20)
    $flagged = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Text -split "`r?`n")) {
        if ($flagged.Count -ge $Limit) { break }
        # wpr -status prints "Dropped event : n" and "Events Lost : n" as counters; they are read by
        # Get-WfWprStatusFacts, so only a non zero count is flagged here.
        if ($line -match '(?i)^\s*(dropped event|events lost)\s*:\s*0\s*$') { continue }
        if ($line -match '(?i)\b(warn|warning|error|fail|failed|lost|dropped|denied|unknown)\b') { $flagged.Add($line.TrimEnd()) }
    }
    # No comma: the caller wraps the result in @(), which turns no line into
    # an empty array and one line into an array of one.
    return $flagged.ToArray()
}

function Read-WfPresentMonCsvSummary {
    # Reads the CSV PresentMon wrote, line by line, and returns its header
    # columns, the number of frame rows, the frames per (Application,
    # ProcessID) pair (the first 50 pairs), and how many rows PresentMon
    # attributed to "<unknown>", its name for a process whose start or
    # rundown event is not in the recording. The file is not changed.
    param([string]$Path)
    $summary = [ordered]@{ header = @(); frames = 0; processes = @(); unknown_application_frames = 0; truncated_process_list = $false; error = $null }
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path, (New-Object System.Text.UTF8Encoding($false)), $true)
        $headerLine = $reader.ReadLine()
        if ($null -eq $headerLine) { return $summary }
        $header = @($headerLine.TrimEnd("`r") -split ',' | ForEach-Object { $_.Trim() })
        $summary.header = $header
        $applicationIndex = [array]::IndexOf($header, 'Application')
        $processIndex = [array]::IndexOf($header, 'ProcessID')
        $counts = [ordered]@{}
        $frames = 0
        $unknown = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Trim().Length -eq 0) { continue }
            $frames += 1
            if ($applicationIndex -lt 0 -or $processIndex -lt 0) { continue }
            $cells = $line -split ','
            $application = ''
            $process = ''
            if ($cells.Count -gt $applicationIndex) { $application = $cells[$applicationIndex].Trim() }
            if ($cells.Count -gt $processIndex) { $process = $cells[$processIndex].Trim() }
            if ($application -eq '<unknown>') { $unknown += 1 }
            $key = $application + "`t" + $process
            if ($counts.Contains($key)) { $counts[$key] = [int]$counts[$key] + 1 }
            elseif ($counts.Count -lt 50) { $counts[$key] = 1 }
            else { $summary.truncated_process_list = $true }
        }
        $summary.frames = $frames
        $summary.unknown_application_frames = $unknown
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($key in $counts.Keys) {
            $parts = $key -split "`t"
            $processId = $null
            $parsed = 0
            if ([int]::TryParse($parts[1], [ref]$parsed)) { $processId = $parsed }
            $list.Add([ordered]@{ application = $parts[0]; process_id = $processId; frames = [int]$counts[$key] })
        }
        $summary.processes = @($list.ToArray())
    } catch {
        $summary.error = $_.Exception.Message
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    return $summary
}

function ConvertTo-WfRunRecord {
    # The process runner's result as the manifest records it.
    param($Run, [int]$Deadline)
    if ($null -eq $Run) { return [ordered]@{ attempted = $false; started = $false; exit_code = $null; timed_out = $false; oversized = $false; duration_ms = $null; deadline_seconds = $Deadline; error = $null } }
    return [ordered]@{
        attempted        = $true
        started          = [bool]$Run['Started']
        exit_code        = $Run['ExitCode']
        timed_out        = [bool]$Run['TimedOut']
        oversized        = [bool]$Run['Oversized']
        duration_ms      = $Run['DurationMs']
        deadline_seconds = $Deadline
        error            = $Run['Error']
    }
}

function Get-WfRunText {
    # Both console streams of a run, labelled, for console.txt.
    param([string]$Label, $Run)
    if ($null -eq $Run) { return ('=== ' + $Label + ': not run' + "`n") }
    $text = '=== ' + $Label + "`n" + 'stdout:' + "`n" + [string]$Run['StdOut'] + "`n" + 'stderr:' + "`n" + [string]$Run['StdErr'] + "`n"
    if ($Run['Diagnostic']) { $text += 'diagnostic head (the run was stopped):' + "`n" + [string]$Run['Diagnostic'] + "`n" }
    if ($Run['Error']) { $text += 'runner: ' + [string]$Run['Error'] + "`n" }
    return $text
}

function Invoke-WfPresentMonFramesSource {
    # The custom source the definition below names. Verifies the pinned binary
    # and the controller, records the providers with wpr for the window, stops
    # the recording on every path, reads the file header, runs PresentMon
    # offline over the file, and writes under raw/presentmon_frames/:
    #   command.json  the binaries with the pin, every command line, the
    #                 providers with their source, the limits (role config, config_hash)
    #   profile.wprp  the WPR profile wpr was started with (role config, filter_hash)
    #   trace.etl     the recording wpr saved, untouched (role primary)
    #   frames.csv    the CSV PresentMon wrote from the recording, untouched (role report)
    #   console.txt   what wpr and PresentMon printed, verbatim (role log)
    #   result.json   the verification, every run, the file header, the CSV
    #                 summary, the cleanup (role report)
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    # The context carries the pseudonym salt the network sources share; frame
    # rows carry process names and swap chain addresses, nothing it protects.
    if ($null -eq $Context) { $Context = @{} }
    $id = [string]$Source['Id']
    $exe = [string]$Source['BinaryPath']
    $duration = [int]$Source['DurationSeconds']
    # Assigned directly, not wrapped in @(): the helper's list function
    # returns its array as one object, which @() would nest.
    $names = Get-WfList -Value $Source['ProcessNames']
    $sessionName = Get-WfPresentMonSessionName
    $consoleCap = Get-WfPresentMonConsoleCapBytes
    $entry = New-WfCollectorEntry -Id $id -Kind 'presentmon' -Required $true
    $roles = @{ 'command.json' = 'config'; 'profile.wprp' = 'config'; 'trace.etl' = 'primary'; 'frames.csv' = 'report'; 'console.txt' = 'log'; 'result.json' = 'report' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $etlPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/trace.etl')
    $outputPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/frames.csv')
    $profilePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/profile.wprp')
    $consolePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/console.txt')
    $wprTempPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/wpr-temp')
    $relativeEtl = $relativeDir + '/trace.etl'
    $relativeCsv = $relativeDir + '/frames.csv'
    $relativeProfile = $relativeDir + '/profile.wprp'
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $tools = @()
    $frames = 0
    $console = New-Object System.Text.StringBuilder
    $maximumFileSizeMb = [int][math]::Max(1, [math]::Ceiling($MaxArtifactBytes / 1048576.0))
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $wpr = Get-WfWprPath
        $encoding = Get-WfConsoleOutputEncoding
        $profileXml = Get-WfPresentMonProfileXml -MaximumFileSizeMb $maximumFileSizeMb
        Write-WfTextFile -Path $profilePath -Text $profileXml
        $entry.filter_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $profilePath) }

        # The command lines, recorded with bundle relative paths; the processes
        # receive the absolute paths of the same files, in double quotes.
        $profileArgument = $profilePath + '!' + (Get-WfPresentMonProfileName) + '.Verbose'
        $wprCommands = [ordered]@{
            probe  = @('-status')
            start  = @('-start', ($relativeProfile + '!' + (Get-WfPresentMonProfileName) + '.Verbose'), '-filemode', '-recordtempto', ($relativeDir + '/wpr-temp'))
            status = @('-status', 'collectors', '-details')
            stop   = @('-stop', $relativeEtl, 'win-forensics presentmon-frames', '-skipPdbGen')
            cancel = @('-cancel')
        }
        $startText = ('-start "{0}" -filemode -recordtempto "{1}"' -f $profileArgument, $wprTempPath)
        $stopText = ('-stop "{0}" "win-forensics presentmon-frames" -skipPdbGen' -f $etlPath)
        $decodeArguments = New-Object 'System.Collections.Generic.List[string]'
        $decodeArguments.Add('--etl_file'); $decodeArguments.Add($relativeEtl)
        $decodeArguments.Add('--output_file'); $decodeArguments.Add($relativeCsv)
        $decodeArguments.Add('--no_console_stats')
        $decodeArguments.Add('--qpc_time')
        foreach ($name in $names) { $decodeArguments.Add('--process_name'); $decodeArguments.Add([string]$name) }
        $decodeText = (@($decodeArguments.ToArray() | ForEach-Object { if ($_ -eq $relativeEtl) { '"' + $etlPath + '"' } elseif ($_ -eq $relativeCsv) { '"' + $outputPath + '"' } else { $_ } }) -join ' ')

        $account = Get-WfAccountInfo
        $binary = Get-WfBinaryInfo -Path $exe
        $pinMatched = ($binary['exists'] -and [string]$binary['sha256'] -eq (Get-WfPresentMonPinnedSha256))
        $sizeMatched = ($binary['exists'] -and [int64]$binary['length'] -eq (Get-WfPresentMonPinnedLength))
        $wprPresent = Test-WfToolPresent -Path $wpr
        $config = [ordered]@{
            tool                   = $exe
            pinned                 = [ordered]@{
                version           = Get-WfPresentMonPinnedVersion
                file_name         = Get-WfPresentMonPinnedFileName
                sha256            = Get-WfPresentMonPinnedSha256
                length            = Get-WfPresentMonPinnedLength
                release_url       = Get-WfPresentMonReleaseUrl
                asset_url         = Get-WfPresentMonAssetUrl
                documentation_url = Get-WfPresentMonDocumentationUrl
                source_url        = Get-WfPresentMonSourceUrl
                digest_source     = 'the digest GitHub records for the release asset (release API digest field), read 2026-11-18'
            }
            controller             = $wpr
            method                 = 'wpr records the providers below to a file inside the bundle for the window; PresentMon then reads that file with --etl_file. Live PresentMon is not run: in realtime mode it opens a PROCESS_QUERY_LIMITED_INFORMATION handle to every presenting process (OutputThread.cpp QueryProcessName, v2.6.0) and enables SeDebugPrivilege when it can (MainThread.cpp); with --etl_file both are skipped (the same two functions test args.mEtlFileName)'
            wpr_commands           = $wprCommands
            session_name           = $sessionName
            profile                = [ordered]@{ path = $relativeProfile; name = (Get-WfPresentMonProfileName); maximum_file_size_mb = $maximumFileSizeMb; buffer_size_kb = 64; buffers = 256; file_mode = 'Sequential' }
            providers              = @(Get-WfPresentMonProviders)
            presentmon_arguments   = @($decodeArguments.ToArray())
            output_paths_recorded_as = 'bundle relative paths; the processes received the absolute paths of the same files in this bundle, in double quotes'
            duration_seconds       = $duration
            deadlines_seconds      = [ordered]@{ start = (Get-WfPresentMonStartDeadline); status = (Get-WfPresentMonStatusDeadline); stop = (Get-WfPresentMonStopDeadline); decode = (Get-WfPresentMonDecodeDeadline); cancel = (Get-WfPresentMonCancelDeadline) }
            helper_deadline_seconds = $TimeoutSeconds
            process_names          = @($names)
            max_artifact_bytes     = $MaxArtifactBytes
            console_cap_bytes      = $consoleCap
            option_citations       = [ordered]@{
                '--etl_file'         = 'Analyze an ETW trace log file instead of the actively running processes.'
                '--output_file'      = 'Write CSV output to the specified path.'
                '--no_console_stats' = 'Do not display active swap chains and frame statistics in the console.'
                '--qpc_time'         = 'Output the CPU start time as a performance counter value.'
                '--process_name'     = 'Only record processes with the specified exe name. This argument can be repeated to capture multiple processes.'
                'wpr -start'         = 'Starts one or more profiles. -filemode: recording is done in file mode. -recordtempto: the temporary folder path that the recording is saved to.'
                'wpr -status'        = 'Displays the status of an active recording (if any). collectors: lists collector information, with Events Lost per collector.'
                'wpr -stop'          = 'Cancels and saves the recording initiated by WPR (if any) to the given file. -skipPdbGen disables dynamic generation of pdbs for .NET modules.'
                'wpr -cancel'        = 'Cancels the current recording without saving the recorded data.'
            }
            account                = [ordered]@{ elevated = $account['elevated']; performance_log_users = $account['performance_log_users'] }
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($exe) + @($decodeArguments.ToArray())
        $entry.requested = [ordered]@{ providers = @(Get-WfPresentMonProviders | ForEach-Object { [string]$_['id'] }); keywords = @(Get-WfPresentMonProviders | ForEach-Object { if ($null -ne $_['keywords']) { [string]$_['id'] + ':' + [string]$_['keywords'] } else { [string]$_['id'] + ':all' } }); stack_walk = @(); counters = @(); options = $config }
        $entry.buffers = [ordered]@{ size_kb = 64; count = 256; mode = 'file' }
        if ($names.Count -gt 0) {
            $entry.target_process = [ordered]@{ name = [string]$names[0]; pid = $null; alive_at_start = $null; alive_at_stop = $null }
        }

        # Preflight: the pin, the controller, and no other WPR recording (WPR
        # records one at a time: "An existing session is already running", WPR
        # How-to Topics; E_WPRC_RUNTIME_STATE_PROFILES_RUNNING). The probe is
        # a read of WPR's state, not a change to it.
        $probeRun = $null
        $probeFacts = [ordered]@{ in_progress = $false; events_lost = $null; collectors = @() }
        if ($wprPresent -and $pinMatched -and $sizeMatched) {
            $probeRun = Invoke-WfProcess -FilePath $wpr -Arguments '-status' -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
            $null = $console.Append((Get-WfRunText -Label 'wpr -status (before)' -Run $probeRun))
            $probeFacts = Get-WfWprStatusFacts -Text ([string]$probeRun['StdOut'] + "`n" + [string]$probeRun['StdErr'])
        }
        $otherRecording = [bool]$probeFacts['in_progress']
        $checks = @(
            [ordered]@{ name = 'binary_present'; ok = [bool]$binary['exists']; detail = $exe },
            [ordered]@{ name = 'binary_sha256_pinned'; ok = $pinMatched; detail = $(if ($binary['exists']) { 'sha256 ' + [string]$binary['sha256'] + ', pinned ' + (Get-WfPresentMonPinnedSha256) } else { 'no file' }) },
            [ordered]@{ name = 'binary_length_pinned'; ok = $sizeMatched; detail = $(if ($binary['exists']) { [string]$binary['length'] + ' bytes, pinned ' + [string](Get-WfPresentMonPinnedLength) } else { 'no file' }) },
            [ordered]@{ name = 'wpr_present'; ok = $wprPresent; detail = $wpr },
            [ordered]@{ name = 'no_other_wpr_recording'; ok = (-not $otherRecording); detail = $(if ($null -ne $probeRun) { ('wpr -status exit code {0}; in progress: {1}' -f $probeRun['ExitCode'], $otherRecording) } else { 'not probed' }) }
        )
        $preflightOk = ($binary['exists'] -and $pinMatched -and $sizeMatched -and $wprPresent -and -not $otherRecording)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = $checks }
        $toolVersion = $null
        if ($pinMatched) { $toolVersion = Get-WfPresentMonPinnedVersion } elseif ($binary['exists']) { $toolVersion = $binary['product_version'] }
        $wprInfo = Get-WfBinaryInfo -Path $wpr
        $tools = @(
            [ordered]@{ name = 'presentmon'; version = $toolVersion; path = $exe; sha256 = $binary['sha256'] },
            [ordered]@{ name = 'wpr'; version = $wprInfo['file_version']; path = $wpr; sha256 = $wprInfo['sha256'] }
        )

        if (-not $account['elevated'] -and -not $account['performance_log_users']) {
            $message = 'source ' + $id + ': the account is neither elevated nor a member of Performance Log Users (S-1-5-32-559), the two groups Microsoft documents as able to control event tracing sessions; expect the recording to be refused'
            $Notes.Add($message); $Log.Add($message)
        }

        $readErrorKind = ''
        $readErrorMessage = ''
        $keepArtifacts = $false
        $startRun = $null; $statusRun = $null; $stopRun = $null; $afterRun = $null; $cancelRun = $null; $decodeRun = $null
        $statusFacts = [ordered]@{ in_progress = $false; events_lost = $null; collectors = @() }
        $afterFacts = [ordered]@{ in_progress = $false; events_lost = $null; collectors = @() }
        $recordStart = $null
        $recordStop = $null
        $etlBytes = [int64]0
        $etlHeader = [ordered]@{ found = $false }
        $csv = [ordered]@{ header = @(); frames = 0; processes = @(); unknown_application_frames = 0; truncated_process_list = $false; error = $null }
        $qpcColumn = $false
        $eventsLost = $null
        $eventsLostSource = $null
        $buffersLost = $null

        if (-not $binary['exists']) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the PresentMon console binary is not at {0}. Download {1} from {2}, check that its SHA-256 is {3}, and place it there (or pass -PresentMonPath); the collector never downloads it' -f $exe, (Get-WfPresentMonPinnedFileName), (Get-WfPresentMonReleaseUrl), (Get-WfPresentMonPinnedSha256))
        } elseif (-not $pinMatched -or -not $sizeMatched) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the file at {0} has SHA-256 {1} ({2} bytes); the pinned PresentMon {3} console binary has {4} ({5} bytes), so nothing was run' -f $exe, [string]$binary['sha256'], [string]$binary['length'], (Get-WfPresentMonPinnedVersion), (Get-WfPresentMonPinnedSha256), [string](Get-WfPresentMonPinnedLength))
        } elseif (-not $wprPresent) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'Windows Performance Recorder is not at ' + $wpr + ' (it ships with Windows 8.1 and later); nothing was recorded'
        } elseif ($otherRecording) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'another WPR recording is in progress on this machine and WPR records one at a time; nothing was started so that recording is not disturbed (wpr -status: ' + (([string]$probeRun['StdOut']).Trim() -replace '\s+', ' ') + ')'
        } else {
            # Phase 1: start the recording.
            $Log.Add('source ' + $id + ': wpr ' + ($wprCommands['start'] -join ' '))
            $startRun = Invoke-WfProcess -FilePath $wpr -Arguments $startText -TimeoutSeconds (Get-WfPresentMonStartDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
            $null = $console.Append((Get-WfRunText -Label 'wpr -start' -Run $startRun))
            $startSaid = (([string]$startRun['StdOut'] + ' ' + [string]$startRun['StdErr'] + ' ' + [string]$startRun['Error']).Trim() -replace '\s+', ' ')
            if ($startSaid.Length -gt 500) { $startSaid = $startSaid.Substring(0, 500) }
            if (-not $startRun['Started'] -or $startRun['TimedOut'] -or $startRun['Oversized'] -or [int]$startRun['ExitCode'] -ne 0) {
                # A start that did not complete may still have left a recording
                # behind (a timed out start); cancel so nothing stays running.
                if ($startRun['Started'] -and ($startRun['TimedOut'] -or $startRun['Oversized'])) {
                    $cancelRun = Invoke-WfProcess -FilePath $wpr -Arguments '-cancel' -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                    $null = $console.Append((Get-WfRunText -Label 'wpr -cancel (after a start that did not complete)' -Run $cancelRun))
                }
                if ($startSaid -match '(?i)access (is )?denied') {
                    $readErrorKind = 'access_denied'
                    $readErrorMessage = ('wpr -start was refused (exit code {0}): "{1}". Microsoft documents that only elevated administrators, members of Performance Log Users, and the service accounts can control event tracing sessions; whether WPR itself accepts a Performance Log Users member is on the verification list' -f $startRun['ExitCode'], $startSaid)
                } else {
                    $readErrorKind = 'preflight'
                    $readErrorMessage = ('wpr -start did not complete (exit code {0}; timed out {1}): {2}; nothing was recorded' -f $startRun['ExitCode'], [bool]$startRun['TimedOut'], $startSaid)
                }
            } else {
                $recordStart = Get-WfUtcNow
                # Phase 2: the window. Nothing runs while the machine is observed.
                Wait-WfSeconds -Seconds $duration
                # Phase 3: read the controller's own counters before stopping, then stop.
                $statusRun = Invoke-WfProcess -FilePath $wpr -Arguments '-status collectors -details' -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label 'wpr -status collectors -details (before stop)' -Run $statusRun))
                $statusFacts = Get-WfWprStatusFacts -Text ([string]$statusRun['StdOut'] + "`n" + [string]$statusRun['StdErr'])
                $recordStop = Get-WfUtcNow
                $Log.Add('source ' + $id + ': wpr ' + ($wprCommands['stop'] -join ' '))
                $stopRun = Invoke-WfProcess -FilePath $wpr -Arguments $stopText -TimeoutSeconds (Get-WfPresentMonStopDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label 'wpr -stop' -Run $stopRun))
                $stopOk = ($stopRun['Started'] -and -not $stopRun['TimedOut'] -and -not $stopRun['Oversized'] -and [int]$stopRun['ExitCode'] -eq 0)
                # Phase 4: confirm nothing is still recording; cancel if it is or if the stop did not complete.
                $afterRun = Invoke-WfProcess -FilePath $wpr -Arguments '-status' -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label 'wpr -status (after)' -Run $afterRun))
                $afterFacts = Get-WfWprStatusFacts -Text ([string]$afterRun['StdOut'] + "`n" + [string]$afterRun['StdErr'])
                if (-not $stopOk -or $afterFacts['in_progress'] -or -not $afterRun['Started'] -or $afterRun['TimedOut']) {
                    $cancelRun = Invoke-WfProcess -FilePath $wpr -Arguments '-cancel' -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                    $null = $console.Append((Get-WfRunText -Label 'wpr -cancel' -Run $cancelRun))
                }
                if (Test-Path -LiteralPath $wprTempPath) { Remove-Item -LiteralPath $wprTempPath -Recurse -Force }

                $stopSaid = (([string]$stopRun['StdOut'] + ' ' + [string]$stopRun['StdErr'] + ' ' + [string]$stopRun['Error']).Trim() -replace '\s+', ' ')
                if ($stopSaid.Length -gt 500) { $stopSaid = $stopSaid.Substring(0, 500) }
                if (-not $stopOk) {
                    $readErrorKind = 'other'
                    $readErrorMessage = ('wpr -stop did not complete (exit code {0}; timed out {1}): {2}; the recording was cancelled instead and nothing was kept' -f $stopRun['ExitCode'], [bool]$stopRun['TimedOut'], $stopSaid)
                } elseif (-not (Test-Path -LiteralPath $etlPath)) {
                    $readErrorKind = 'other'
                    $readErrorMessage = 'wpr -stop exited with code 0 but no file is at ' + $relativeEtl
                } else {
                    $etlBytes = [int64](Get-Item -LiteralPath $etlPath).Length
                    $etlHeader = Read-WfEtlHeader -Path $etlPath
                    if ($null -ne $statusFacts['events_lost']) {
                        $eventsLost = [int64]$statusFacts['events_lost']
                        $eventsLostSource = 'wpr -status collectors -details, read before the stop'
                    } elseif ($etlHeader['found']) {
                        $eventsLost = [int64]$etlHeader['events_lost']
                        $eventsLostSource = 'the log file header (TRACE_LOGFILE_HEADER EventsLost)'
                    }
                    if ($etlHeader['found']) {
                        $buffersLost = [int64]$etlHeader['buffers_lost']
                        if ($null -ne $statusFacts['events_lost'] -and [int64]$etlHeader['events_lost'] -ne [int64]$statusFacts['events_lost']) {
                            $message = ('source {0}: wpr -status reported {1} events lost before the stop and the log file header records {2}; the status value is used and both are in result.json' -f $id, $statusFacts['events_lost'], $etlHeader['events_lost'])
                            $Notes.Add($message); $Log.Add($message)
                        }
                    }
                    if ($etlBytes -eq 0) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'wpr -stop exited with code 0 and left a file of zero bytes'
                    } elseif ($etlBytes -ge ($maximumFileSizeMb * 1048576)) {
                        $keepArtifacts = $true
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the recording reached its file cap of {0} MB ({1} bytes), at which a sequential ETW session stops, so it does not cover the whole window; the file is kept as a capped set' -f $maximumFileSizeMb, $etlBytes)
                    } elseif (-not $statusFacts['in_progress']) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'wpr -status at the end of the window did not report a recording in progress, so the recording did not run for the whole window: ' + ((([string]$statusRun['StdOut']).Trim() -replace '\s+', ' ')).Substring(0, [math]::Min(300, (([string]$statusRun['StdOut']).Trim() -replace '\s+', ' ').Length))
                    } elseif ($null -eq $eventsLost) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'events lost could not be read, neither from wpr -status (no Events Lost line) nor from the log file header (' + [string]$etlHeader['error'] + '), so the recording cannot be shown complete'
                    } elseif ($eventsLost -gt 0 -or ($null -ne $buffersLost -and $buffersLost -gt 0)) {
                        $keepArtifacts = $true
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the recording lost events: {0} events lost ({1}), {2} buffers lost (log file header); a recording with loss is capture_failed under docs/contracts/measurement-status.md and is kept for inspection, never as proof of absence' -f $eventsLost, $eventsLostSource, $(if ($null -ne $buffersLost) { [string]$buffersLost } else { 'unknown' }))
                    } else {
                        # Phase 5: PresentMon reads the file. No session, no process handle.
                        $Log.Add('source ' + $id + ': ' + $exe + ' ' + (@($decodeArguments.ToArray()) -join ' '))
                        $decodeRun = Invoke-WfProcess -FilePath $exe -Arguments $decodeText -TimeoutSeconds (Get-WfPresentMonDecodeDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                        $null = $console.Append((Get-WfRunText -Label 'PresentMon --etl_file' -Run $decodeRun))
                        $decodeSaid = (([string]$decodeRun['StdOut'] + ' ' + [string]$decodeRun['StdErr'] + ' ' + [string]$decodeRun['Error']).Trim() -replace '\s+', ' ')
                        if ($decodeSaid.Length -gt 500) { $decodeSaid = $decodeSaid.Substring(0, 500) }
                        if (-not $decodeRun['Started']) {
                            $readErrorKind = 'other'
                            $readErrorMessage = 'the PresentMon process could not be started: ' + [string]$decodeRun['Error']
                        } elseif ($decodeRun['TimedOut']) {
                            $readErrorKind = 'other'
                            $readErrorMessage = ('PresentMon did not finish reading the {0} byte recording within {1} seconds and was stopped' -f $etlBytes, (Get-WfPresentMonDecodeDeadline))
                        } elseif ($decodeRun['Oversized']) {
                            $readErrorKind = 'other'
                            $readErrorMessage = [string]$decodeRun['Error']
                        } elseif ([int]$decodeRun['ExitCode'] -ne 0) {
                            $readErrorKind = 'other'
                            $readErrorMessage = ('PresentMon exited with code {0} reading the recording: {1}' -f [int]$decodeRun['ExitCode'], $decodeSaid)
                        } elseif (-not (Test-Path -LiteralPath $outputPath)) {
                            # PresentMon creates its CSV at the first frame it emits
                            # (CsvOutput.cpp UpdateCsvT, v2.6.0), so no file means no
                            # frame in the recording for the processes it kept.
                            $frames = 0
                        } else {
                            $csvBytes = [int64](Get-Item -LiteralPath $outputPath).Length
                            if ($csvBytes -gt $MaxArtifactBytes) {
                                $readErrorKind = 'other'
                                $readErrorMessage = ('the CSV is {0} bytes, above the cap of {1}, and was not kept' -f $csvBytes, $MaxArtifactBytes)
                            } else {
                                $csv = Read-WfPresentMonCsvSummary -Path $outputPath
                                $qpcColumn = (@($csv['header']) -contains 'CPUStartQPC')
                                if ($csv['error']) {
                                    $readErrorKind = 'other'
                                    $readErrorMessage = 'the CSV could not be read: ' + [string]$csv['error']
                                } elseif (-not (@($csv['header']) -contains 'Application') -or -not (@($csv['header']) -contains 'ProcessID')) {
                                    $readErrorKind = 'other'
                                    $readErrorMessage = 'the CSV header is not the documented PresentMon header (no Application and ProcessID columns): ' + (@($csv['header']) -join ',')
                                } elseif (-not $qpcColumn) {
                                    $readErrorKind = 'other'
                                    $readErrorMessage = '--qpc_time was requested but the CSV header has no CPUStartQPC column, so the requested setting was not in effect: ' + (@($csv['header']) -join ',')
                                } else {
                                    $frames = [int]$csv['frames']
                                }
                            }
                        }
                    }
                }
            }
        }
        $stopped = Get-WfUtcNow
        $sessionConfirmed = ($null -ne $afterRun -and $afterRun['Started'] -and -not $afterRun['TimedOut'] -and -not $afterFacts['in_progress'])
        $cancelOk = ($null -ne $cancelRun -and $cancelRun['Started'] -and -not $cancelRun['TimedOut'] -and [int]$cancelRun['ExitCode'] -eq 0)
        if ($null -ne $startRun -and $startRun['Started'] -and [int]$startRun['ExitCode'] -eq 0 -and -not $sessionConfirmed -and -not $cancelOk) {
            $message = 'source ' + $id + ': could not confirm that the WPR recording ' + $sessionName + ' stopped (wpr -status after the stop did not say so and wpr -cancel did not complete); run "wpr -cancel" as an administrator to be sure'
            $Notes.Add($message); $Log.Add($message)
            if ($readErrorKind) { $readErrorMessage += '; the recording may still be active (see the manifest notes)' }
        }
        $consoleText = $console.ToString()
        if ($consoleText.Length -gt 0) { Write-WfTextFile -Path $consolePath -Text $consoleText }
        $flagged = @()
        if ($consoleText.Length -gt 0) { $flagged = @(Get-WfPresentMonFlaggedLines -Text $consoleText) }

        $report = [ordered]@{
            binary      = [ordered]@{
                path            = $exe
                exists          = $binary['exists']
                length          = $binary['length']
                sha256          = $binary['sha256']
                file_version    = $binary['file_version']
                product_version = $binary['product_version']
                error           = $binary['error']
                pin_matched     = $pinMatched
                length_matched  = $sizeMatched
            }
            controller  = [ordered]@{ path = $wpr; present = $wprPresent; file_version = $wprInfo['file_version']; sha256 = $wprInfo['sha256'] }
            runs        = [ordered]@{
                probe  = ConvertTo-WfRunRecord -Run $probeRun -Deadline (Get-WfPresentMonStatusDeadline)
                start  = ConvertTo-WfRunRecord -Run $startRun -Deadline (Get-WfPresentMonStartDeadline)
                status = ConvertTo-WfRunRecord -Run $statusRun -Deadline (Get-WfPresentMonStatusDeadline)
                stop   = ConvertTo-WfRunRecord -Run $stopRun -Deadline (Get-WfPresentMonStopDeadline)
                after  = ConvertTo-WfRunRecord -Run $afterRun -Deadline (Get-WfPresentMonStatusDeadline)
                cancel = ConvertTo-WfRunRecord -Run $cancelRun -Deadline (Get-WfPresentMonCancelDeadline)
                decode = ConvertTo-WfRunRecord -Run $decodeRun -Deadline (Get-WfPresentMonDecodeDeadline)
            }
            recording   = [ordered]@{
                source_started_utc       = ConvertTo-WfUtcString -Value $started
                source_stopped_utc       = ConvertTo-WfUtcString -Value $stopped
                started_utc              = $(if ($null -ne $recordStart) { ConvertTo-WfUtcString -Value $recordStart } else { $null })
                stop_requested_utc       = $(if ($null -ne $recordStop) { ConvertTo-WfUtcString -Value $recordStop } else { $null })
                duration_seconds         = $duration
                in_progress_before_stop  = [bool]$statusFacts['in_progress']
                in_progress_after_stop   = [bool]$afterFacts['in_progress']
                stop_confirmed           = $sessionConfirmed
                collectors_reported      = @($statusFacts['collectors'])
                events_lost              = $eventsLost
                events_lost_source       = $eventsLostSource
                buffers_lost             = $buffersLost
                etl_bytes                = $etlBytes
                etl_header               = $etlHeader
            }
            csv         = [ordered]@{
                path                       = $relativeCsv
                present                    = (Test-Path -LiteralPath $outputPath)
                header                     = @($csv['header'])
                qpc_time_column            = $qpcColumn
                frames                     = [int]$csv['frames']
                processes                  = @($csv['processes'])
                truncated_process_list     = [bool]$csv['truncated_process_list']
                unknown_application_frames = [int]$csv['unknown_application_frames']
            }
            console_flagged_lines = @($flagged)
            account     = $config.account
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report

        if ($readErrorKind -eq 'preflight') {
            # Nothing was recorded (docs/contracts/measurement-status.md: not started is not_collected).
            $entry.status = 'not_collected'
            $entry.status_reason = 'preflight failed: ' + $readErrorMessage
            $met = $false
        } elseif ($readErrorKind -eq 'access_denied') {
            $entry.status = 'not_collected'
            $entry.status_reason = 'preflight failed, the recording could not be started: ' + $readErrorMessage
            $met = $false
        } elseif ($readErrorKind) {
            $entry.status = 'capture_failed'
            $entry.status_reason = $readErrorMessage
            $met = $false
        } elseif ($frames -gt 0) {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        } elseif ($names.Count -eq 0) {
            # The recording ran for the whole window with no loss, and PresentMon
            # found no present in it for any process: a quiet window, proven by
            # the recording (the primary artifact), not by a CSV that PresentMon
            # never creates without a frame.
            $entry.status = 'observed_zero'
            $entry.status_reason = $null
            $met = $true
        } else {
            # Scoped to named processes and none of them presented. The status
            # contract names a target process that was not alive across the
            # window as capture_failed, and the recording cannot tell that from
            # a name that never appeared in the Kernel-Process events.
            $entry.status = 'capture_failed'
            $entry.status_reason = ('zero frames for the requested process names ({0}) in a {1} second recording that completed without loss: the process was not alive across the window, did not present, or its name was not in the recorded Kernel-Process events (PresentMon then lists it as "<unknown>" and --process_name cannot match it)' -f ($names -join ', '), $duration)
            $met = $false
            $Notes.Add('source ' + $id + ': ' + $entry.status_reason)
        }
        Remove-WfPrimaryUnlessKept -Path $etlPath -Status $entry.status -Truncated $keepArtifacts -RecordCount 1 -Log $Log -SourceId $id
        Remove-WfPrimaryUnlessKept -Path $outputPath -Status $entry.status -Truncated $keepArtifacts -RecordCount $frames -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) {
            if ($etlHeader['found'] -and $null -ne $etlHeader['end_time_utc']) {
                $entry.raw_time_range = [ordered]@{ start = $etlHeader['start_time_utc']; end = $etlHeader['end_time_utc']; domain = 'system_time'; unit = 'iso_utc' }
            } else {
                $entry.raw_time_range = New-WfTimeRange -StartUtc $recordStart -EndUtc $recordStop
            }
        }
        $entry.events_lost = $eventsLost
        $entry.enabled = [ordered]@{
            providers = @($statusFacts['collectors']); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                wpr_start_exit_code        = $(if ($null -ne $startRun) { $startRun['ExitCode'] } else { $null })
                recording_in_progress      = [bool]$statusFacts['in_progress']
                stop_confirmed             = $sessionConfirmed
                events_lost                = $eventsLost
                events_lost_source         = $eventsLostSource
                buffers_lost               = $buffersLost
                etl_bytes                  = $etlBytes
                etl_header_found           = [bool]$etlHeader['found']
                clock_type                 = $etlHeader['clock_type']
                perf_freq_hz               = $etlHeader['perf_freq_hz']
                presentmon_exit_code       = $(if ($null -ne $decodeRun) { $decodeRun['ExitCode'] } else { $null })
                csv_present                = (Test-Path -LiteralPath $outputPath)
                csv_header                 = @($csv['header'])
                qpc_time_column            = $qpcColumn
                records                    = $frames
                processes                  = @($csv['processes'])
                unknown_application_frames = [int]$csv['unknown_application_frames']
                console_flagged_lines      = @($flagged)
                elevated                   = $account['elevated']
                performance_log_users      = $account['performance_log_users']
            }
            verified_by = 'wpr -status before the stop (recording in progress, Events Lost per collector), the log file header of trace.etl (events and buffers lost, clock type, start and end), the CSV header PresentMon wrote from the file (a CPUStartQPC column proves --qpc_time), and the exit codes and console text of every run in console.txt'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('wpr start exit {0}; in progress at the end {1}; events lost {2}; file {3} bytes; PresentMon exit {4}; {5} frames from {6} processes; CPUStartQPC column {7}; stop confirmed {8}' -f $report.runs.start.exit_code, [bool]$statusFacts['in_progress'], $(if ($null -ne $eventsLost) { [string]$eventsLost } else { 'unknown' }), $etlBytes, $report.runs.decode.exit_code, $frames, @($csv['processes']).Count, $qpcColumn, $sessionConfirmed)
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while running this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        try {
            # Whatever happened, no recording may outlive the collector.
            $cancelRun = Invoke-WfProcess -FilePath (Get-WfWprPath) -Arguments '-cancel' -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes (Get-WfPresentMonConsoleCapBytes)
            $Log.Add('source ' + $id + ': wpr -cancel after the failure exited ' + [string]$cancelRun['ExitCode'])
        } catch { $Log.Add('source ' + $id + ': wpr -cancel after the failure could not run: ' + $_.Exception.Message) }
        if (Test-Path -LiteralPath $wprTempPath) { Remove-Item -LiteralPath $wprTempPath -Recurse -Force }
        if (Test-Path -LiteralPath $etlPath) { Remove-Item -LiteralPath $etlPath -Force }
        if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @(); Tools = $tools }
}

# --- parameter checks, before anything is written -----------------------------
$problems = New-Object 'System.Collections.Generic.List[string]'
if ($DurationSeconds -lt 5 -or $DurationSeconds -gt 240) { $problems.Add('DurationSeconds must be between 5 and 240') }
$names = @($ProcessName | ForEach-Object { [string]$_ } | Where-Object { $_.Length -gt 0 })
if ($names.Count -gt 8) { $problems.Add('at most 8 process names can be given') }
foreach ($name in $names) {
    if ($name -notmatch (Get-WfPresentMonProcessNamePattern)) { $problems.Add('process name does not match ' + (Get-WfPresentMonProcessNamePattern) + ': ' + $name) }
}
$binaryPath = $PresentMonPath
if (-not $binaryPath) { $binaryPath = Get-WfPresentMonDefaultPath -ScriptRoot $PSScriptRoot }
if ($problems.Count -gt 0) {
    foreach ($problem in $problems) { Write-WfStderrLine -Text ($collectorName + ': ' + $problem) }
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}

$targetProcess = $null
if ($names.Count -gt 0) { $targetProcess = [string]$names[0] }
$definition = @{
    Name                     = $collectorName
    Version                  = '2.0.0'
    Question                 = 'What did the frame pipeline do, frame by frame, during a bounded window: present cadence, time in Present, CPU and GPU busy and wait, display latency, every frame stamped in the ETW performance counter domain?'
    RequestedDurationSeconds = $DurationSeconds
    TargetProcess            = $targetProcess
    CalibrationMethod        = 'none in this collector: the recording is an ETW file whose events carry the clock the log file header names (clock_type in the manifest; QPC is the etw_qpc master domain of docs/contracts/timestamps.md), and PresentMon writes CPUStartQPC from those timestamps; the calibration pairs that relate them to system time come from the clock collector of a later runner'
    Sources                  = @(
        @{
            Id              = 'presentmon_frames'
            Type            = 'custom'
            Invoke          = 'Invoke-WfPresentMonFramesSource'
            Required        = $true
            BinaryPath      = $binaryPath
            DurationSeconds = $DurationSeconds
            ProcessNames    = @($names)
            Expectation     = 'wpr starts the profile and reports the recording in progress at the end of the window with zero events lost; wpr -stop saves the file below its cap and the log file header agrees (zero events and buffers lost); the pinned PresentMon exits with code 0 reading it with --etl_file and --qpc_time; at least one frame row was written. With no process filter, zero frames after such a recording is a quiet window (observed_zero); with a filter, zero frames is capture_failed'
        }
    )
}

# The helper's per source deadline covers every phase: start, the window,
# the status reads, the stop and merge, the offline decode and a cancel.
$timeout = (Get-WfPresentMonStartDeadline) + $DurationSeconds + 2 * (Get-WfPresentMonStatusDeadline) + (Get-WfPresentMonStopDeadline) + (Get-WfPresentMonDecodeDeadline) + (Get-WfPresentMonCancelDeadline)
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $timeout -CollectorPath $PSCommandPath)[-1]
exit $exitCode
