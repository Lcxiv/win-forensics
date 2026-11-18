# presentmon-frames: What did the frame pipeline do, frame by frame, during a
# bounded window: present cadence, time in the Present call, CPU and GPU busy
# and wait time, display latency, with every frame stamped in the ETW
# performance counter domain?
#
# Live capture, passive, and with no process handle to the game from anything
# this script runs. Runs under Windows PowerShell 5.1 as the collector account.
# Writes one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints
# one JSON summary line on stdout, and exits 0 when the bundle is complete.
# See collectors/windows/README.md for the interface, the pinned binary, every
# option with its citation, the status rules, the anti-cheat position, and the
# facts still to be verified on a real machine.
#
# Two programs run, both through the helper's one process runner:
#
#  1. Windows Performance Recorder (wpr.exe, inbox since Windows 8.1) records
#     the ETW providers PresentMon 2.6.0 enables for its default options, with
#     PresentMon's own event id filters, into a file inside the bundle, from a
#     profile this script writes (Get-WfPresentMonProfileXml). Every wpr call
#     carries -instancename wf-presentmon-frames as its last parameter, so
#     this script sees, stops and cancels only its own recording and never
#     another WPR instance's. The recording is bounded in time (this script
#     stops it) and in size (the profile's MaximumFileSize in sequential file
#     mode: "the trace stops when the file size reaches the given size").
#     Trace loss is read from the controller (wpr -status: "Dropped event" and
#     "Events Lost" per collector) and from the recording's own log file
#     header (TRACE_LOGFILE_HEADER EventsLost and BuffersLost); any loss, from
#     any source, is capture_failed.
#
#  2. The operator supplied PresentMon console application, pinned by version
#     and SHA-256 (below) and hashed again immediately before it runs, reads
#     the recording with --etl_file and prints its CSV on stdout
#     (--output_stdout), which the process runner captures under the artifact
#     cap. In that mode PresentMon opens no process: at tag v2.6.0,
#     PresentMon/OutputThread.cpp QueryProcessName() calls OpenProcess only
#     when args.mEtlFileName == nullptr (lines 294 to 319), and
#     PresentMon/MainThread.cpp enables SeDebugPrivilege only for realtime
#     analysis (lines 255 to 277). Process names come from the recorded
#     Microsoft-Windows-Kernel-Process events
#     (PresentData/PresentMonTraceConsumer.cpp HandleProcessEvent).
#
# The recording itself never leaves the PC. WPR's -stop merges the session
# file, and a merge adds machine specific information to a trace (the profile
# schema's TraceMergeProperties lists the custom events a merge can add, among
# them NetworkInterface; the ETW network configuration event SystemConfig_NIC
# carries the adapter's hardware address and IP addresses). This project keeps
# hardware and network addresses out of every bundle, so the recording is
# read on the PC for its header (loss, clock, start and end) and by
# PresentMon, then deleted; recording.json keeps its size, SHA-256 and header.
#
# Live PresentMon is never run by this collector: in its realtime mode the
# same QueryProcessName() opens a PROCESS_QUERY_LIMITED_INFORMATION handle to
# every presenting process, the game included, and keeps it for the capture
# (OutputThread.cpp lines 294 to 319 and 212 to 231), and MainThread.cpp
# enables SeDebugPrivilege when it can. tests/test_collectors_static.py checks
# that no realtime option (--timed, --session_name, --process_id,
# --terminate_after_timed, --terminate_existing_session, --stop_existing_session,
# --restart_as_admin, --hotkey, --delay) appears in this script. Whether
# wpr.exe opens a handle to a presenting process is not documented by
# Microsoft and is a verification item in the README, not a claim here.
#
# PresentMon options passed (README-ConsoleApplication.md at v2.6.0):
#   --etl_file path       "Analyze an ETW trace log file instead of the actively running processes."
#   --output_stdout       "Write CSV output to STDOUT." (CommandLine.cpp lines 556 to 557 then
#                         turn console output off, so stdout carries the CSV and nothing else;
#                         warnings and errors go to stderr, Console.cpp PrintColor line 340)
#   --qpc_time            "Output the CPU start time as a performance counter value." (column CPUStartQPC)
#   --process_name name   "Only record processes with the specified exe name." (repeatable, optional)
# WPR options passed (WPR Command-Line Options, learn.microsoft.com), each ending in -instancename:
#   -start <profile> -filemode -recordtempto <folder>, -status [collectors -details], -stop <file> <description> -skipPdbGen, -cancel
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long the recording runs, in seconds (5 to 240). The other phases
    # (probes, start, status, stop and merge, offline read, cancel) have fixed
    # deadlines, listed below.
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
    # The artifact cap, in bytes: the merged recording may not exceed it (the
    # session itself is capped at three quarters of it, in whole megabytes, by
    # the profile's MaximumFileSize, so the merge has room), and the CSV
    # PresentMon prints is captured under it by the process runner, which
    # stops PresentMon at the cap.
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
# The WPR recording: the instance name every wpr call carries (WPR
# Command-Line Options: -instancename "specifies a name to uniquely identify
# the tracing instance" and "must be the last parameter"), which is also the
# event collector's name in the profile, and the profile name inside the .wprp.
function Get-WfPresentMonInstanceName { return 'wf-presentmon-frames' }
function Get-WfPresentMonProfileName { return 'WfPresentMonFrames' }
# Deadlines in seconds for the phases that are not the recording window.
function Get-WfPresentMonStartDeadline { return 60 }
function Get-WfPresentMonStatusDeadline { return 30 }
function Get-WfPresentMonStopDeadline { return 180 }
function Get-WfPresentMonDecodeDeadline { return 240 }
function Get-WfPresentMonCancelDeadline { return 60 }
# Cap on what a program may print on a console stream that is not the CSV.
function Get-WfPresentMonConsoleCapBytes { return [int64]1048576 }
# A process name: letters, digits, dot, underscore and hyphen, not starting
# with a hyphen, so it can never read as an option.
function Get-WfPresentMonProcessNamePattern { return '^[A-Za-z0-9._][A-Za-z0-9._-]{0,119}$' }
# How far the session's own end time may precede the stop request before the
# session counts as closed early (it reached its file cap or died).
function Get-WfPresentMonEndToleranceSeconds { return 5 }

function Get-WfPresentMonDefaultPath {
    # <install root>\tools\<pinned file name>: the collectors live two levels
    # below the install root (remote\collectors on the PC; collectors\windows
    # in the repository, where tools\ is ignored by git).
    param([string]$ScriptRoot)
    $installRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)
    return [System.IO.Path]::Combine($installRoot, 'tools', (Get-WfPresentMonPinnedFileName))
}

function Get-WfPresentMonSessionCapMb {
    # The profile's MaximumFileSize: three quarters of the artifact cap in
    # whole megabytes, at least 1, so that the merged file (the session file
    # plus what WPR's -stop adds) has room to stay under the artifact cap.
    param([int64]$MaxArtifactBytes)
    return [int][math]::Max(1, [math]::Floor($MaxArtifactBytes * 0.75 / 1048576.0))
}

function Get-WfPresentMonProviders {
    # The providers PresentMon 2.6.0 enables for the console application's
    # default options, from PresentData/PresentMonTraceSession.cpp
    # EnableProvidersListing() and the event declarations under
    # PresentData/ETW/*.h at tag v2.6.0. Keywords are the OR of the enabled
    # events' keywords (PresentMon's "any keyword" mask), levels the highest
    # event level (0 is LogAlways, which WPR treats as every level), events
    # the event ids PresentMon filters in with EVENT_FILTER_TYPE_EVENT_ID (the
    # profile's EventFilters element uses the same filter type), and the
    # capture state keywords are the ones PresentMon enables a second time
    # with EVENT_CONTROL_CODE_CAPTURE_STATE. Strict marks the providers whose
    # failure makes PresentMon's own session start fail; the two it tolerates
    # (Kernel-Process, allowed to be access denied, and the NVIDIA display
    # driver provider, absent without that driver) are not strict here either.
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
    # after the instance with PresentMon's buffer geometry (64 KB buffers, 256
    # of them: PresentMonTraceSession.cpp Start(), BufferSize 64,
    # MinimumBuffers 256) and a sequential file cap, one EventProvider per
    # provider above (Name is the GUID, Level, Keywords, EventFilters with
    # FilterIn for PresentMon's event ids, CaptureStateOnStart, NonPagedMemory
    # because DxgKrnl logs from kernel mode), and one File, Verbose profile
    # whose Id is Name.DetailLevel.LoggingMode.
    param([int]$MaximumFileSizeMb)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<?xml version="1.0" encoding="utf-8"?>')
    $lines.Add('<WindowsPerformanceRecorder Version="1.0" Author="win-forensics presentmon-frames" Comments="ETW providers and event ids PresentMon 2.6.0 enables for its default options, recorded for offline analysis with --etl_file">')
    $lines.Add('  <Profiles>')
    $lines.Add(('    <EventCollector Id="EventCollector_{0}" Name="{1}" FileName="{1}.etl">' -f (Get-WfPresentMonProfileName), (Get-WfPresentMonInstanceName)))
    $lines.Add('      <BufferSize Value="64"/>')
    $lines.Add('      <Buffers Value="256"/>')
    $lines.Add(('      <MaximumFileSize Value="{0}" FileMode="Sequential"/>' -f $MaximumFileSizeMb))
    $lines.Add('    </EventCollector>')
    foreach ($provider in (Get-WfPresentMonProviders)) {
        $attributes = ('Id="EventProvider_{0}" Name="{1}" NonPagedMemory="true"' -f ([string]$provider['id'] -replace '[^A-Za-z0-9]', ''), [string]$provider['guid'])
        if ([int]$provider['level'] -gt 0) { $attributes += (' Level="{0}"' -f [int]$provider['level']) }
        if ($provider['strict']) { $attributes += ' Strict="true"' }
        # Assigned directly, not wrapped in @(): the helper's list function returns its array as one object.
        $events = Get-WfList -Value $provider['events']
        if ($null -eq $provider['keywords'] -and $null -eq $provider['capture_state'] -and $events.Count -eq 0) {
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
        if ($events.Count -gt 0) {
            $lines.Add('      <EventFilters FilterIn="true">')
            foreach ($eventId in $events) { $lines.Add(('        <EventId Value="{0}"/>' -f [int]$eventId)) }
            $lines.Add('      </EventFilters>')
        }
        $lines.Add('    </EventProvider>')
    }
    $lines.Add(('    <Profile Id="{0}.Verbose.File" Name="{0}" Description="win-forensics presentmon-frames: the providers and event ids PresentMon 2.6.0 enables, recorded to a file" LoggingMode="File" DetailLevel="Verbose">' -f (Get-WfPresentMonProfileName)))
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
    # The log file header of an ETW log file. The first buffer of the file
    # starts with a 72 byte buffer header (its first three fields are the
    # buffer's size, the saved offset and the current offset) and then the
    # log file header event: a 32 byte system trace header (version, header
    # type, flags, size, hook id, thread and process id, time stamp, kernel
    # and user time) whose hook id 0 names the EventTrace_Header class,
    # followed by TRACE_LOGFILE_HEADER ("the raw data format of the trace
    # information data in the header of an ETW log file", learn.microsoft.com).
    # Microsoft documents TRACE_LOGFILE_HEADER and not the two headers before
    # it; those two are what PresentMon's own regression recordings show
    # (Tests/Gold/test_case_0.etl to _5.etl at tag v2.6.0; the first buffer of
    # _0 is committed as fixtures/presentmon/gold-test_case_0.first-buffer.etl)
    # and what the reverse engineered descriptions of the format describe
    # (collectors/windows/README.md names them). Every field below is checked
    # for plausibility before the header counts as read. Inside
    # TRACE_LOGFILE_HEADER the offsets are Microsoft's: the two pointer members
    # take PointerSize each and TIME_ZONE_INFORMATION is padded to 176 bytes
    # (EventTrace_Header Max(176)) so BootTime is 8 byte aligned. A file whose
    # header does not read this way gives found false, and the collector then
    # treats loss and clock as unknown and fails closed.
    param([string]$Path)
    $header = [ordered]@{ found = $false; offset = $null; header_type = $null; buffer_size_bytes = $null; os_version = $null; os_build = $null; number_of_processors = $null; pointer_size = $null
        buffers_written = $null; events_lost = $null; buffers_lost = $null; log_file_mode = $null; maximum_file_size_mb = $null
        perf_freq_hz = $null; start_time_utc = $null; end_time_utc = $null; reserved_flags = $null; clock_type = $null; logger_name = $null; error = $null }
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
        # FILETIME of 2000-01-01 and 2100-01-01, the range a plausible start lies in.
        if ($reserved -lt 1 -or $reserved -gt 3 -or $perfFreq -le 0 -or $startTime -lt 125911584000000000 -or $startTime -gt 157469184000000000 -or $major -lt 5 -or $major -gt 12 -or $processors -lt 1 -or $processors -gt 4096) {
            $header.error = ('implausible header fields (ReservedFlags {0}, PerfFreq {1}, StartTime {2}, major version {3}, processors {4})' -f $reserved, $perfFreq, $startTime, $major, $processors)
            return $header
        }
        $header.found = $true
        $header.offset = $p
        $header.header_type = $headerType
        $header.buffer_size_bytes = [int64][System.BitConverter]::ToUInt32($bytes, $p + 0)
        $header.os_version = ('{0}.{1}' -f $bytes[$p + 4], $bytes[$p + 5])
        $header.os_build = [int64][System.BitConverter]::ToUInt32($bytes, $p + 8)
        $header.number_of_processors = [int]$processors
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
        # The session name is the first null terminated UTF-16 string after the structure.
        $nameStart = $tail + 32
        $nameEnd = $nameStart
        while ($nameEnd + 1 -lt $read -and -not ($bytes[$nameEnd] -eq 0 -and $bytes[$nameEnd + 1] -eq 0)) { $nameEnd += 2 }
        if ($nameEnd -gt $nameStart -and $nameEnd - $nameStart -le 512) { $header.logger_name = [System.Text.Encoding]::Unicode.GetString($bytes, $nameStart, $nameEnd - $nameStart) }
    } catch {
        $header.error = $_.Exception.Message
    }
    return $header
}

function Get-WfWprStatusFacts {
    # What wpr -status printed, read by its documented lines (WPR Command-Line
    # Options, Status): "WPR recording is in progress..." when a recording is
    # active, "Dropped event : n" ("The number of lost events since the
    # recording was started", WPR How-to Topics), and with "collectors" one
    # "Collector Name : x" block each with "Events Lost : n" and, after a
    # "Providers" line, one line per enabled provider. The provider line's
    # layout is not documented; this reads "<name or GUID>: <keywords>:
    # <level>[: ...]" with the two numbers in hex or decimal, and records
    # what it could not read as none (collectors/windows/README.md,
    # verification list). Events lost is the largest of the dropped event
    # count and the sum over the collectors listed, null when neither line
    # was printed.
    param([string]$Text)
    $facts = [ordered]@{ in_progress = ($Text -match 'WPR recording is in progress'); events_lost = $null; dropped_events = $null; collectors_events_lost = $null; collectors = @(); providers = @() }
    $m = [regex]::Match($Text, '(?im)^\s*Dropped event\s*:\s*(\d+)')
    if ($m.Success) { $facts.dropped_events = [int64]$m.Groups[1].Value }
    $lost = [int64]0
    $seen = $false
    foreach ($m in [regex]::Matches($Text, '(?im)^\s*Events Lost\s*:\s*(\d+)')) { $lost += [int64]$m.Groups[1].Value; $seen = $true }
    if ($seen) { $facts.collectors_events_lost = $lost }
    if ($seen -or $null -ne $facts.dropped_events) {
        $dropped = [int64]0
        if ($null -ne $facts.dropped_events) { $dropped = [int64]$facts.dropped_events }
        $facts.events_lost = [int64][math]::Max($lost, $dropped)
    }
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($m in [regex]::Matches($Text, '(?im)^\s*Collector Name\s*:\s*(.+?)\s*$')) { $names.Add($m.Groups[1].Value) }
    $facts.collectors = @($names.ToArray())
    $providers = New-Object 'System.Collections.Generic.List[object]'
    $inProviders = $false
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*Providers\s*$') { $inProviders = $true; continue }
        if ($line -match '^\s*(CaptureState Providers|Collector Name|System Keywords|System Stacks|Stack Walk)') { $inProviders = $false; continue }
        if (-not $inProviders) { continue }
        $pm = [regex]::Match($line, '^\s*(.+?)\s*:\s*((?:0x[0-9a-fA-F]+)|\d+)\s*:\s*((?:0x[0-9a-fA-F]+)|\d+)\s*(?::\s*(.*))?$')
        if ($pm.Success) {
            $providers.Add([ordered]@{ name = $pm.Groups[1].Value.Trim(); keywords = (ConvertTo-WfHexText -Text $pm.Groups[2].Value); level = (ConvertTo-WfInteger -Text $pm.Groups[3].Value); extra = $(if ($pm.Groups[4].Success) { $pm.Groups[4].Value.Trim() } else { $null }) })
        }
    }
    $facts.providers = @($providers.ToArray())
    return $facts
}

function ConvertTo-WfInteger {
    # A hex (0x...) or decimal number as a 64 bit integer.
    param([string]$Text)
    if ($Text -match '^0x') { return [int64][System.Convert]::ToUInt64($Text.Substring(2), 16) }
    return [int64]$Text
}

function ConvertTo-WfHexText {
    # A hex or decimal number as lower case 0x text.
    param([string]$Text)
    if ($Text -match '^0x') { return ('0x' + $Text.Substring(2).ToLowerInvariant()) }
    return ('0x{0:x}' -f [uint64]$Text)
}

function Compare-WfPresentMonEnabledProviders {
    # The requested providers against the ones wpr -status lists as enabled:
    # a strict provider must appear (by GUID or by name, case insensitive)
    # with every requested keyword bit in its mask and a level at least the
    # requested one. Returns the comparison per provider and whether every
    # strict one is satisfied.
    param($Requested, $Enabled)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $ok = $true
    foreach ($provider in @($Requested)) {
        $guid = ([string]$provider['guid']).ToLowerInvariant()
        $name = ([string]$provider['id']).ToLowerInvariant()
        $match = $null
        foreach ($candidate in @($Enabled)) {
            $candidateName = ([string]$candidate['name']).ToLowerInvariant().Trim('{', '}')
            if ($candidateName -eq $guid -or $candidateName -eq $name) { $match = $candidate; break }
        }
        $row = [ordered]@{ id = [string]$provider['id']; strict = [bool]$provider['strict']; enabled = ($null -ne $match); keywords_ok = $null; level_ok = $null; enabled_keywords = $null; enabled_level = $null }
        if ($null -ne $match) {
            $row.enabled_keywords = [string]$match['keywords']
            $row.enabled_level = [int]$match['level']
            $wanted = [uint64]0
            if ($null -ne $provider['keywords']) { $wanted = [System.Convert]::ToUInt64(([string]$provider['keywords']).Substring(2), 16) }
            $got = [System.Convert]::ToUInt64(([string]$match['keywords']).Substring(2), 16)
            # A mask of zero means every keyword for WPR ("If no keywords are specified, the default value of zero is used (which is treated by ETW as the string 0xFFFFFFFFFFFFFFFF)").
            $row.keywords_ok = ($got -eq 0 -or ($got -band $wanted) -eq $wanted)
            # A level of 0 or 0xff enables every level.
            $row.level_ok = ([int]$match['level'] -eq 0 -or [int]$match['level'] -ge [int]$provider['level'])
        }
        if ($provider['strict'] -and -not ($row.enabled -and $row.keywords_ok -and $row.level_ok)) { $ok = $false }
        $rows.Add($row)
    }
    return [ordered]@{ ok = $ok; providers = @($rows.ToArray()) }
}

function Get-WfPresentMonOutputFacts {
    # What PresentMon printed on stderr while reading the recording, read by
    # the exact wordings of MainThread.cpp at v2.6.0: "warning: %lu overflowed
    # present events detected" (lines 455 to 459, printed in every mode; the
    # count of presents the consumer threw away), "warning: %lu ETW buffers
    # were lost" and "warning: %lu ETW events were lost" (lines 449 to 454,
    # realtime counters but matched in case), and every other line that
    # starts with "warning:" or "error:" (Console.cpp PrintWarning and
    # PrintError, both to stderr).
    param([string]$Text)
    $facts = [ordered]@{ overflowed_presents = $null; etw_events_lost = $null; etw_buffers_lost = $null; warnings = @(); errors = @() }
    $m = [regex]::Match($Text, '(?im)^\s*warning:\s*(\d+)\s+overflowed present events detected')
    if ($m.Success) { $facts.overflowed_presents = [int64]$m.Groups[1].Value }
    $m = [regex]::Match($Text, '(?im)^\s*warning:\s*(\d+)\s+ETW events were lost')
    if ($m.Success) { $facts.etw_events_lost = [int64]$m.Groups[1].Value }
    $m = [regex]::Match($Text, '(?im)^\s*warning:\s*(\d+)\s+ETW buffers were lost')
    if ($m.Success) { $facts.etw_buffers_lost = [int64]$m.Groups[1].Value }
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $errors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*warning:' -and $warnings.Count -lt 20) { $warnings.Add($line.Trim()) }
        if ($line -match '^\s*error' -and $errors.Count -lt 20) { $errors.Add($line.Trim()) }
    }
    $facts.warnings = @($warnings.ToArray())
    $facts.errors = @($errors.ToArray())
    return $facts
}

function Read-WfPresentMonCsvSummary {
    # Reads the CSV PresentMon printed, line by line, and returns its header
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

function Test-WfRunCompleted {
    # A run that started, finished before its deadline, stayed under its
    # console cap and exited 0.
    param($Run)
    return ($null -ne $Run -and $Run['Started'] -and -not $Run['TimedOut'] -and -not $Run['Oversized'] -and $null -ne $Run['ExitCode'] -and [int]$Run['ExitCode'] -eq 0)
}

function Get-WfRunText {
    # Both console streams of a run, labelled, for console.txt. The CSV
    # PresentMon prints on stdout is not repeated here.
    param([string]$Label, $Run, [bool]$StdOut = $true)
    if ($null -eq $Run) { return ('=== ' + $Label + ': not run' + "`n") }
    $text = '=== ' + $Label + "`n"
    if ($StdOut) { $text += 'stdout:' + "`n" + [string]$Run['StdOut'] + "`n" } else { $text += 'stdout: the CSV (' + [string]$Run['StdOutBytes'] + ' bytes), kept as frames.csv when the source is observed' + "`n" }
    $text += 'stderr:' + "`n" + [string]$Run['StdErr'] + "`n"
    if ($Run['Diagnostic']) { $text += 'diagnostic head (the run was stopped):' + "`n" + [string]$Run['Diagnostic'] + "`n" }
    if ($Run['Error']) { $text += 'runner: ' + [string]$Run['Error'] + "`n" }
    return $text
}

function Get-WfSaid {
    # The first 500 characters of what a run printed, on one line.
    param($Run)
    if ($null -eq $Run) { return '' }
    $said = (([string]$Run['StdOut'] + ' ' + [string]$Run['StdErr'] + ' ' + [string]$Run['Error']).Trim() -replace '\s+', ' ')
    if ($said.Length -gt 500) { $said = $said.Substring(0, 500) }
    return $said
}

function New-WfWprStatusFacts {
    # An empty status reading, for a status run that did not happen.
    return [ordered]@{ in_progress = $false; events_lost = $null; dropped_events = $null; collectors_events_lost = $null; collectors = @(); providers = @() }
}

function Remove-WfPresentMonRecordingData {
    # Deletes the wpr temp folder and the recording, the two places that can
    # hold recorded events. Returns one line per path that could not be
    # deleted (a session that is still live holds its file open) and never
    # throws, so the manifest and its note are still written.
    param([string]$wprTempPath = '', [string]$etlPath = '')
    $failures = New-Object 'System.Collections.Generic.List[string]'
    if ($wprTempPath -and (Test-Path -LiteralPath $wprTempPath)) {
        try { Remove-Item -LiteralPath $wprTempPath -Recurse -Force } catch { $failures.Add($wprTempPath + ' (' + $_.Exception.Message + ')') }
    }
    if ($etlPath -and (Test-Path -LiteralPath $etlPath)) {
        try { Remove-Item -LiteralPath $etlPath -Force } catch { $failures.Add($etlPath + ' (' + $_.Exception.Message + ')') }
    }
    return @($failures.ToArray())
}

function Get-WfPresentMonLeftoverRecords {
    # The files under raw/<source id>/ that are not one of the collector's own
    # artifacts, by path and size. Nothing is opened: a session the collector
    # could not stop may still hold its file, so the sizes come from the
    # directory listing and no hash is taken.
    param([string]$BundleRoot, [string]$RelativeDir, [hashtable]$Roles)
    $records = New-Object 'System.Collections.Generic.List[object]'
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $RelativeDir
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -File -Recurse | Sort-Object -Property FullName)) {
            $tail = $file.FullName.Substring($dir.Length).TrimStart('\', '/') -replace '\\', '/'
            if (-not $Roles.ContainsKey($tail)) { $records.Add([ordered]@{ path = $RelativeDir + '/' + $tail; bytes = [int64]$file.Length }) }
        }
    } catch {
        $records.Add([ordered]@{ path = $RelativeDir; bytes = $null; error = 'the folder could not be listed: ' + $_.Exception.Message })
    }
    return @($records.ToArray())
}

function Get-WfPresentMonOwnArtifactRecords {
    # The manifest artifact list when recorded data was left behind: only the
    # files the collector wrote itself, by name, so nothing a live session
    # holds is opened for hashing.
    param([string]$BundleRoot, [string]$RelativeDir, [hashtable]$Roles)
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($tail in @($Roles.Keys | Sort-Object)) {
        $path = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($RelativeDir + '/' + $tail)
        if (Test-Path -LiteralPath $path) {
            $records.Add([ordered]@{ path = $RelativeDir + '/' + $tail; bytes = [int64](Get-Item -LiteralPath $path).Length; sha256 = Get-WfSha256OfFile -Path $path; role = $Roles[$tail] })
        }
    }
    return , $records.ToArray()
}

function Get-WfPresentMonLeftoverNote {
    param([string]$Id, [object[]]$Undeleted, [object[]]$Leftover)
    $files = @($Leftover | ForEach-Object { [string]$_['path'] + ' (' + [string]$_['bytes'] + ' bytes)' })
    return ('source ' + $Id + ': recorded data could not be deleted and is still in the bundle, which must not leave the PC until it is deleted by hand: ' + ($Undeleted -join '; ') + '; left in the bundle, not hashed and not listed as artifacts: ' + ($files -join ', '))
}

function Invoke-WfPresentMonFramesSource {
    # The custom source the definition below names. Verifies the pinned binary
    # and the controller, records the providers with wpr for the window under
    # this collector's own instance name, stops the recording on every path,
    # reads the file header and the controller's counters, runs PresentMon
    # offline over the file, deletes the file, and writes under raw/presentmon_frames/:
    #   command.json    the binaries with the pin, every command line, the
    #                   providers with their source, the limits (role config, config_hash)
    #   profile.wprp    the WPR profile wpr was started with (role config, filter_hash)
    #   frames.csv      the CSV PresentMon printed for the recording, as captured (role primary)
    #   recording.json  the recording's size, SHA-256, header, loss counts and
    #                   the settings comparison (role report)
    #   console.txt     what wpr and PresentMon printed, verbatim (role log)
    #   result.json     the verification, every run, the CSV summary, any
    #                   recorded data that could not be deleted (role report)
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
    $instance = Get-WfPresentMonInstanceName
    $consoleCap = Get-WfPresentMonConsoleCapBytes
    $entry = New-WfCollectorEntry -Id $id -Kind 'presentmon' -Required $true
    $roles = @{ 'command.json' = 'config'; 'profile.wprp' = 'config'; 'frames.csv' = 'primary'; 'recording.json' = 'report'; 'console.txt' = 'log'; 'result.json' = 'report' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $etlPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/trace.etl')
    $outputPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/frames.csv')
    $profilePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/profile.wprp')
    $consolePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/console.txt')
    $wprTempPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/wpr-temp')
    $relativeEtl = $relativeDir + '/trace.etl'
    $relativeProfile = $relativeDir + '/profile.wprp'
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $tools = @()
    $frames = 0
    $console = New-Object System.Text.StringBuilder
    $sessionCapMb = Get-WfPresentMonSessionCapMb -MaxArtifactBytes $MaxArtifactBytes
    $wpr = Get-WfWprPath
    $encoding = Get-WfConsoleOutputEncoding
    # True from the instant our -start was issued until our stop was confirmed
    # or our cancel completed: the only state in which a cancel is ours to send.
    $ownsRecording = $false
    $cancelRun = $null
    $dataLeft = $false
    $leftover = @()
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $profileXml = Get-WfPresentMonProfileXml -MaximumFileSizeMb $sessionCapMb
        Write-WfTextFile -Path $profilePath -Text $profileXml
        $entry.filter_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $profilePath) }

        # The command lines, recorded with bundle relative paths; the processes
        # receive the absolute paths of the same files, in double quotes.
        # -instancename is the last parameter of every wpr call, as documented.
        $profileArgument = $profilePath + '!' + (Get-WfPresentMonProfileName) + '.Verbose'
        $wprCommands = [ordered]@{
            probe  = @('-status', '-instancename', $instance)
            start  = @('-start', ($relativeProfile + '!' + (Get-WfPresentMonProfileName) + '.Verbose'), '-filemode', '-recordtempto', ($relativeDir + '/wpr-temp'), '-instancename', $instance)
            status = @('-status', 'collectors', '-details', '-instancename', $instance)
            stop   = @('-stop', $relativeEtl, 'win-forensics presentmon-frames', '-skipPdbGen', '-instancename', $instance)
            cancel = @('-cancel', '-instancename', $instance)
        }
        $probeText = ('-status -instancename {0}' -f $instance)
        $startText = ('-start "{0}" -filemode -recordtempto "{1}" -instancename {2}' -f $profileArgument, $wprTempPath, $instance)
        $statusText = ('-status collectors -details -instancename {0}' -f $instance)
        $stopText = ('-stop "{0}" "win-forensics presentmon-frames" -skipPdbGen -instancename {1}' -f $etlPath, $instance)
        $cancelText = ('-cancel -instancename {0}' -f $instance)
        $decodeArguments = New-Object 'System.Collections.Generic.List[string]'
        $decodeArguments.Add('--etl_file'); $decodeArguments.Add($relativeEtl)
        $decodeArguments.Add('--output_stdout')
        $decodeArguments.Add('--qpc_time')
        foreach ($name in $names) { $decodeArguments.Add('--process_name'); $decodeArguments.Add([string]$name) }
        $decodeText = (@($decodeArguments.ToArray() | ForEach-Object { if ($_ -eq $relativeEtl) { '"' + $etlPath + '"' } else { $_ } }) -join ' ')

        $account = Get-WfAccountInfo
        $binary = Get-WfBinaryInfo -Path $exe
        $pinMatched = ($binary['exists'] -and [string]$binary['sha256'] -eq (Get-WfPresentMonPinnedSha256))
        $sizeMatched = ($binary['exists'] -and [int64]$binary['length'] -eq (Get-WfPresentMonPinnedLength))
        $wprPresent = Test-WfToolPresent -Path $wpr
        $providers = @(Get-WfPresentMonProviders)
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
            method                 = 'wpr records the providers below, under the instance name, to a file inside the bundle for the window; PresentMon then reads that file with --etl_file and prints its CSV on stdout, captured under the artifact cap; the file is deleted after it was read because a WPR merged recording may carry the network adapter hardware and IP addresses. Live PresentMon is not run: in realtime mode it opens a PROCESS_QUERY_LIMITED_INFORMATION handle to every presenting process (OutputThread.cpp QueryProcessName, v2.6.0) and enables SeDebugPrivilege when it can (MainThread.cpp); with --etl_file both are skipped (the same two functions test args.mEtlFileName)'
            wpr_commands           = $wprCommands
            instance_name          = $instance
            profile                = [ordered]@{ path = $relativeProfile; name = (Get-WfPresentMonProfileName); maximum_file_size_mb = $sessionCapMb; buffer_size_kb = 64; buffers = 256; file_mode = 'Sequential'; event_id_filters = $true }
            providers              = $providers
            presentmon_arguments   = @($decodeArguments.ToArray())
            output_paths_recorded_as = 'bundle relative paths; the processes received the absolute paths of the same files in this bundle, in double quotes'
            csv_console_code_page  = $encoding.WebName
            recording_kept         = $false
            recording_deleted_because = 'a WPR merged recording may hold the network adapter hardware and IP addresses (SystemConfig_NIC through the merge''s NetworkInterface custom event); the project keeps those out of every bundle, so the recording is read on the PC and deleted. recording.json keeps its size, SHA-256 and header'
            duration_seconds       = $duration
            deadlines_seconds      = [ordered]@{ start = (Get-WfPresentMonStartDeadline); status = (Get-WfPresentMonStatusDeadline); stop = (Get-WfPresentMonStopDeadline); decode = (Get-WfPresentMonDecodeDeadline); cancel = (Get-WfPresentMonCancelDeadline) }
            helper_deadline_seconds = $TimeoutSeconds
            process_names          = @($names)
            max_artifact_bytes     = $MaxArtifactBytes
            console_cap_bytes      = $consoleCap
            disk_budget            = [ordered]@{
                session_file_max_bytes      = [int64]$sessionCapMb * 1048576
                merged_file_max_bytes       = $MaxArtifactBytes
                csv_max_bytes               = $MaxArtifactBytes
                console_max_bytes_per_stream = $consoleCap
                peak_bytes_bound            = [int64]$sessionCapMb * 1048576 + 2 * $MaxArtifactBytes + 2 * $consoleCap
                note                        = 'the session stops at session_file_max_bytes (MaximumFileSize, sequential); the merged file is checked against merged_file_max_bytes and deleted either way; the CSV is captured under csv_max_bytes by the process runner, which stops PresentMon at the cap; the merge temp folder is removed on every path. The peak is bounded by the session file plus the merged file plus the CSV plus two console streams (peak_bytes_bound), and ETW keeps 200 MB free on the system drive'
            }
            option_citations       = [ordered]@{
                '--etl_file'         = 'Analyze an ETW trace log file instead of the actively running processes.'
                '--output_stdout'    = 'Write CSV output to STDOUT.'
                '--qpc_time'         = 'Output the CPU start time as a performance counter value.'
                '--process_name'     = 'Only record processes with the specified exe name. This argument can be repeated to capture multiple processes.'
                'wpr -start'         = 'Starts one or more profiles. -filemode: recording is done in file mode. -recordtempto: the temporary folder path that the recording is saved to.'
                'wpr -status'        = 'Displays the status of an active recording (if any). collectors: lists collector information, with Events Lost per collector and the enabled providers.'
                'wpr -stop'          = 'Cancels and saves the recording initiated by WPR (if any) to the given file. -skipPdbGen disables dynamic generation of pdbs for .NET modules.'
                'wpr -cancel'        = 'Cancels the current recording without saving the recorded data.'
                '-instancename'      = 'Specifies a name to uniquely identify the tracing instance. This option can be applied to any commands that manipulate the logging session. -instancename must be the last parameter.'
            }
            account                = [ordered]@{ elevated = $account['elevated']; performance_log_users = $account['performance_log_users'] }
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($exe) + @($decodeArguments.ToArray())
        $entry.requested = [ordered]@{
            providers = @($providers | ForEach-Object { [string]$_['id'] })
            keywords  = @($providers | ForEach-Object { if ($null -ne $_['keywords']) { [string]$_['id'] + ':' + [string]$_['keywords'] } else { [string]$_['id'] + ':all' } })
            stack_walk = @(); counters = @(); options = $config
        }
        $entry.buffers = [ordered]@{ size_kb = 64; count = 256; mode = 'file' }
        if ($names.Count -gt 0) {
            $entry.target_process = [ordered]@{ name = [string]$names[0]; pid = $null; alive_at_start = $null; alive_at_stop = $null }
        }

        # Preflight: the pin, the controller, and this collector's own WPR
        # instance idle. The probe runs only after the pin matched, so a wrong
        # binary starts nothing at all. A leftover recording of this instance
        # (a run the dispatcher killed) is this collector's own and is
        # cancelled before a new one starts; any other instance is never seen.
        $probeRun = $null
        $probeFacts = New-WfWprStatusFacts
        $leftoverCancelRun = $null
        $probeIdle = $false
        $probeMessage = 'not probed'
        if ($wprPresent -and $pinMatched -and $sizeMatched) {
            $probeRun = Invoke-WfProcess -FilePath $wpr -Arguments $probeText -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
            $null = $console.Append((Get-WfRunText -Label ('wpr ' + $probeText + ' (before)') -Run $probeRun))
            $probeFacts = Get-WfWprStatusFacts -Text ([string]$probeRun['StdOut'] + "`n" + [string]$probeRun['StdErr'])
            if ((Test-WfRunCompleted -Run $probeRun) -and $probeFacts['in_progress']) {
                $message = 'source ' + $id + ': a recording of this collector''s own WPR instance (' + $instance + ') was still active, left by an earlier run that did not finish; it was cancelled before this run started'
                $Notes.Add($message); $Log.Add($message)
                $leftoverCancelRun = Invoke-WfProcess -FilePath $wpr -Arguments $cancelText -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label ('wpr ' + $cancelText + ' (leftover of an earlier run)') -Run $leftoverCancelRun))
                $probeRun = Invoke-WfProcess -FilePath $wpr -Arguments $probeText -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label ('wpr ' + $probeText + ' (after the leftover was cancelled)') -Run $probeRun))
                $probeFacts = Get-WfWprStatusFacts -Text ([string]$probeRun['StdOut'] + "`n" + [string]$probeRun['StdErr'])
            }
            $probeIdle = ((Test-WfRunCompleted -Run $probeRun) -and -not $probeFacts['in_progress'])
            $probeMessage = ('wpr -status exit code {0}; timed out {1}; in progress {2}' -f $probeRun['ExitCode'], [bool]$probeRun['TimedOut'], [bool]$probeFacts['in_progress'])
        }
        $checks = @(
            [ordered]@{ name = 'binary_present'; ok = [bool]$binary['exists']; detail = $exe },
            [ordered]@{ name = 'binary_sha256_pinned'; ok = $pinMatched; detail = $(if ($binary['exists']) { 'sha256 ' + [string]$binary['sha256'] + ', pinned ' + (Get-WfPresentMonPinnedSha256) } else { 'no file' }) },
            [ordered]@{ name = 'binary_length_pinned'; ok = $sizeMatched; detail = $(if ($binary['exists']) { [string]$binary['length'] + ' bytes, pinned ' + [string](Get-WfPresentMonPinnedLength) } else { 'no file' }) },
            [ordered]@{ name = 'wpr_present'; ok = $wprPresent; detail = $wpr },
            [ordered]@{ name = 'wpr_instance_idle'; ok = $probeIdle; detail = $probeMessage }
        )
        $preflightOk = ($binary['exists'] -and $pinMatched -and $sizeMatched -and $wprPresent -and $probeIdle)
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
        $startRun = $null; $statusRun = $null; $stopRun = $null; $afterRun = $null; $decodeRun = $null
        $statusFacts = New-WfWprStatusFacts
        $afterFacts = New-WfWprStatusFacts
        $comparison = [ordered]@{ ok = $null; providers = @() }
        $outputFacts = [ordered]@{ overflowed_presents = $null; etw_events_lost = $null; etw_buffers_lost = $null; warnings = @(); errors = @() }
        $recordStartBound = $null
        $recordStopRequested = $null
        $recordStopBound = $null
        $etlBytes = [int64]0
        $etlSha256 = $null
        $etlHeader = [ordered]@{ found = $false; error = 'not read' }
        $csv = [ordered]@{ header = @(); frames = 0; processes = @(); unknown_application_frames = 0; truncated_process_list = $false; error = $null }
        $csvBytes = [int64]0
        $qpcColumn = $false
        $eventsLost = $null
        $eventsLostSources = [ordered]@{ wpr_status_dropped_events = $null; wpr_status_collectors = $null; etl_header_events_lost = $null; etl_header_buffers_lost = $null }
        $buffersLost = $null
        $stopConfirmed = $false
        $sessionEndedEarly = $false
        $rehash = $null

        if (-not $binary['exists']) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the PresentMon console binary is not at {0}. Download {1} from {2}, check that its SHA-256 is {3}, and place it there (or pass -PresentMonPath); the collector never downloads it' -f $exe, (Get-WfPresentMonPinnedFileName), (Get-WfPresentMonReleaseUrl), (Get-WfPresentMonPinnedSha256))
        } elseif (-not $pinMatched -or -not $sizeMatched) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the file at {0} has SHA-256 {1} ({2} bytes); the pinned PresentMon {3} console binary has {4} ({5} bytes), so nothing was run' -f $exe, [string]$binary['sha256'], [string]$binary['length'], (Get-WfPresentMonPinnedVersion), (Get-WfPresentMonPinnedSha256), [string](Get-WfPresentMonPinnedLength))
        } elseif (-not $wprPresent) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'Windows Performance Recorder is not at ' + $wpr + ' (it ships with Windows 8.1 and later); nothing was recorded'
        } elseif (-not $probeIdle) {
            $readErrorKind = 'preflight'
            if ($probeFacts['in_progress']) {
                $readErrorMessage = ('a recording of this collector''s WPR instance ({0}) was active and the cancel did not clear it; nothing was started: wpr -status said "{1}"' -f $instance, (Get-WfSaid -Run $probeRun))
            } else {
                $readErrorMessage = ('the idle state of this collector''s WPR instance could not be established (wpr -status exit code {0}, timed out {1}): "{2}"; nothing was started' -f $probeRun['ExitCode'], [bool]$probeRun['TimedOut'], (Get-WfSaid -Run $probeRun))
            }
        } else {
            # Phase 1: start the recording. The time bound is taken before the
            # start is issued, so the range the source claims contains the recording.
            $recordStartBound = Get-WfUtcNow
            $Log.Add('source ' + $id + ': wpr ' + ($wprCommands['start'] -join ' '))
            $startRun = Invoke-WfProcess -FilePath $wpr -Arguments $startText -TimeoutSeconds (Get-WfPresentMonStartDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
            $null = $console.Append((Get-WfRunText -Label ('wpr ' + ($wprCommands['start'] -join ' ')) -Run $startRun))
            $startSaid = Get-WfSaid -Run $startRun
            if (-not (Test-WfRunCompleted -Run $startRun)) {
                # A start that was issued but did not complete may have left a
                # recording of our instance behind; it is ours to cancel.
                if ($startRun['Started'] -and ($startRun['TimedOut'] -or $startRun['Oversized'])) {
                    $ownsRecording = $true
                    $cancelRun = Invoke-WfProcess -FilePath $wpr -Arguments $cancelText -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                    $null = $console.Append((Get-WfRunText -Label ('wpr ' + $cancelText + ' (after a start that did not complete)') -Run $cancelRun))
                    if (Test-WfRunCompleted -Run $cancelRun) { $ownsRecording = $false }
                }
                if ($startSaid -match '(?i)access (is )?denied') {
                    $readErrorKind = 'access_denied'
                    $readErrorMessage = ('wpr -start was refused (exit code {0}): "{1}". Microsoft documents that only elevated administrators, members of Performance Log Users, and the service accounts can control event tracing sessions; whether WPR itself accepts a Performance Log Users member is on the verification list' -f $startRun['ExitCode'], $startSaid)
                } else {
                    $readErrorKind = 'preflight'
                    $readErrorMessage = ('wpr -start did not complete (exit code {0}; timed out {1}): "{2}"; nothing was recorded' -f $startRun['ExitCode'], [bool]$startRun['TimedOut'], $startSaid)
                }
            } else {
                $ownsRecording = $true
                # Phase 2: the window. Nothing runs while the machine is observed.
                Wait-WfSeconds -Seconds $duration
                # Phase 3: the controller's own counters and enabled settings, then the stop.
                $statusRun = Invoke-WfProcess -FilePath $wpr -Arguments $statusText -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label ('wpr ' + $statusText + ' (end of the window)') -Run $statusRun))
                $statusFacts = Get-WfWprStatusFacts -Text ([string]$statusRun['StdOut'] + "`n" + [string]$statusRun['StdErr'])
                $comparison = Compare-WfPresentMonEnabledProviders -Requested $providers -Enabled $statusFacts['providers']
                $recordStopRequested = Get-WfUtcNow
                $Log.Add('source ' + $id + ': wpr ' + ($wprCommands['stop'] -join ' '))
                $stopRun = Invoke-WfProcess -FilePath $wpr -Arguments $stopText -TimeoutSeconds (Get-WfPresentMonStopDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label ('wpr ' + ($wprCommands['stop'] -join ' ')) -Run $stopRun))
                $recordStopBound = Get-WfUtcNow
                $stopOk = Test-WfRunCompleted -Run $stopRun
                # Phase 4: confirm this instance is idle; cancel it if it is not or if the stop did not complete.
                $afterRun = Invoke-WfProcess -FilePath $wpr -Arguments $probeText -TimeoutSeconds (Get-WfPresentMonStatusDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $null = $console.Append((Get-WfRunText -Label ('wpr ' + $probeText + ' (after the stop)') -Run $afterRun))
                $afterFacts = Get-WfWprStatusFacts -Text ([string]$afterRun['StdOut'] + "`n" + [string]$afterRun['StdErr'])
                $stopConfirmed = ($stopOk -and (Test-WfRunCompleted -Run $afterRun) -and -not $afterFacts['in_progress'])
                if ($stopConfirmed) {
                    $ownsRecording = $false
                } else {
                    $cancelRun = Invoke-WfProcess -FilePath $wpr -Arguments $cancelText -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                    $null = $console.Append((Get-WfRunText -Label ('wpr ' + $cancelText) -Run $cancelRun))
                    if (Test-WfRunCompleted -Run $cancelRun) { $ownsRecording = $false }
                }
                foreach ($failure in @(Remove-WfPresentMonRecordingData -wprTempPath $wprTempPath)) {
                    $Log.Add('source ' + $id + ': the wpr temp folder could not be deleted after the stop and is tried again at the end: ' + $failure)
                }

                if (-not $stopConfirmed) {
                    $readErrorKind = 'other'
                    if (-not $stopOk) {
                        $readErrorMessage = ('wpr -stop did not complete (exit code {0}; timed out {1}): "{2}"; the recording was cancelled instead and nothing was kept' -f $stopRun['ExitCode'], [bool]$stopRun['TimedOut'], (Get-WfSaid -Run $stopRun))
                    } else {
                        $readErrorMessage = ('wpr -stop exited 0 but the instance could not be confirmed idle afterwards (wpr -status exit code {0}, timed out {1}, in progress {2}): "{3}"; the recording was cancelled and nothing was kept' -f $afterRun['ExitCode'], [bool]$afterRun['TimedOut'], [bool]$afterFacts['in_progress'], (Get-WfSaid -Run $afterRun))
                    }
                } elseif (-not (Test-Path -LiteralPath $etlPath)) {
                    $readErrorKind = 'other'
                    $readErrorMessage = 'wpr -stop exited with code 0 but no file is at ' + $relativeEtl
                } else {
                    $etlBytes = [int64](Get-Item -LiteralPath $etlPath).Length
                    $etlSha256 = Get-WfSha256OfFile -Path $etlPath
                    $etlHeader = Read-WfEtlHeader -Path $etlPath
                    $eventsLostSources.wpr_status_dropped_events = $statusFacts['dropped_events']
                    $eventsLostSources.wpr_status_collectors = $statusFacts['collectors_events_lost']
                    if ($etlHeader['found']) {
                        $eventsLostSources.etl_header_events_lost = $etlHeader['events_lost']
                        $eventsLostSources.etl_header_buffers_lost = $etlHeader['buffers_lost']
                        $buffersLost = [int64]$etlHeader['buffers_lost']
                    }
                    # The loss count is the largest any source reported: the
                    # controller's counters before the stop and the header the
                    # session wrote when it closed. Any loss, anywhere, fails.
                    $candidates = @()
                    if ($null -ne $statusFacts['events_lost']) { $candidates += [int64]$statusFacts['events_lost'] }
                    if ($etlHeader['found']) { $candidates += [int64]$etlHeader['events_lost'] }
                    if ($candidates.Count -gt 0) { $eventsLost = [int64]($candidates | Measure-Object -Maximum).Maximum }
                    if ($etlHeader['found'] -and $null -ne $etlHeader['end_time_utc'] -and $null -ne $recordStopRequested) {
                        $headerEnd = ConvertFrom-WfUtcString -Text ([string]$etlHeader['end_time_utc'])
                        if (($recordStopRequested - $headerEnd).TotalSeconds -gt (Get-WfPresentMonEndToleranceSeconds)) { $sessionEndedEarly = $true }
                    }
                    if (-not $statusFacts['in_progress']) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'wpr -status at the end of the window did not report a recording in progress, so the recording did not run for the whole window: "' + (Get-WfSaid -Run $statusRun) + '"'
                    } elseif (-not $etlHeader['found']) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'the recording''s log file header could not be read (' + [string]$etlHeader['error'] + '), so its loss counters, clock and bounds are unknown; the controller reported ' + $(if ($null -ne $statusFacts['events_lost']) { [string]$statusFacts['events_lost'] + ' events lost' } else { 'no loss count' }) + ', which is not enough on its own'
                    } elseif ($null -eq $statusFacts['events_lost']) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'events lost could not be read from wpr -status (no Dropped event or Events Lost line), so the controller''s count is unknown and the header''s ' + [string]$etlHeader['events_lost'] + ' cannot be cross checked'
                    } elseif ($eventsLost -gt 0 -or ($null -ne $buffersLost -and $buffersLost -gt 0)) {
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the recording lost events or buffers: {0} events lost (wpr -status: dropped {1}, collectors {2}; header {3}), {4} buffers lost (header); a recording with loss is capture_failed under docs/contracts/measurement-status.md and PresentMon was not run over it' -f $eventsLost, $eventsLostSources.wpr_status_dropped_events, $eventsLostSources.wpr_status_collectors, $eventsLostSources.etl_header_events_lost, $buffersLost)
                    } elseif ($sessionEndedEarly) {
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the session closed at {0}, before the stop was requested at {1}: it reached its file cap of {2} MB (MaximumFileSize, sequential) or stopped for another reason, so it does not cover the whole window' -f [string]$etlHeader['end_time_utc'], (ConvertTo-WfUtcString -Value $recordStopRequested), $sessionCapMb)
                    } elseif ($etlBytes -gt $MaxArtifactBytes) {
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the merged recording is {0} bytes, above the artifact cap of {1}; PresentMon was not run over it' -f $etlBytes, $MaxArtifactBytes)
                    } elseif ($comparison['ok'] -ne $true) {
                        $readErrorKind = 'other'
                        $missing = @($comparison['providers'] | Where-Object { $_['strict'] -and -not ($_['enabled'] -and $_['keywords_ok'] -and $_['level_ok']) } | ForEach-Object { [string]$_['id'] })
                        $readErrorMessage = ('the requested settings were not shown enabled by wpr -status collectors -details: ' + ($missing -join ', ') + ' (not listed, or keywords or level below the request; ' + @($statusFacts['providers']).Count + ' provider lines were read); the recording is not shown to be what PresentMon needs')
                    } else {
                        # Phase 5: PresentMon reads the file, after the binary is
                        # hashed again so the bytes that run are the bytes checked.
                        $rehash = Get-WfBinaryInfo -Path $exe
                        if (-not $rehash['exists'] -or [string]$rehash['sha256'] -ne (Get-WfPresentMonPinnedSha256) -or [int64]$rehash['length'] -ne (Get-WfPresentMonPinnedLength)) {
                            $readErrorKind = 'other'
                            $readErrorMessage = ('the PresentMon binary changed between the preflight check and the run (now SHA-256 {0}, {1} bytes); it was not run' -f [string]$rehash['sha256'], [string]$rehash['length'])
                        } else {
                            $Log.Add('source ' + $id + ': ' + $exe + ' ' + (@($decodeArguments.ToArray()) -join ' '))
                            $decodeRun = Invoke-WfProcess -FilePath $exe -Arguments $decodeText -TimeoutSeconds (Get-WfPresentMonDecodeDeadline) -OutputEncoding $encoding -MaxBytes $MaxArtifactBytes
                            $null = $console.Append((Get-WfRunText -Label 'PresentMon --etl_file (stdout is the CSV)' -Run $decodeRun -StdOut $false))
                            $outputFacts = Get-WfPresentMonOutputFacts -Text ([string]$decodeRun['StdErr'] + "`n" + [string]$decodeRun['Diagnostic'])
                            if (-not $decodeRun['Started']) {
                                $readErrorKind = 'other'
                                $readErrorMessage = 'the PresentMon process could not be started: ' + [string]$decodeRun['Error']
                            } elseif ($decodeRun['TimedOut']) {
                                $readErrorKind = 'other'
                                $readErrorMessage = ('PresentMon did not finish reading the {0} byte recording within {1} seconds and was stopped' -f $etlBytes, (Get-WfPresentMonDecodeDeadline))
                            } elseif ($decodeRun['Oversized']) {
                                $readErrorKind = 'other'
                                $readErrorMessage = ('PresentMon printed more than the artifact cap of {0} bytes of CSV and was stopped; nothing above the cap was kept' -f $MaxArtifactBytes)
                            } elseif ([int]$decodeRun['ExitCode'] -ne 0) {
                                $readErrorKind = 'other'
                                $readErrorMessage = ('PresentMon exited with code {0} reading the recording: "{1}"' -f [int]$decodeRun['ExitCode'], ((([string]$decodeRun['StdErr']).Trim() -replace '\s+', ' ')))
                            } elseif ($null -ne $outputFacts['overflowed_presents'] -and [int64]$outputFacts['overflowed_presents'] -gt 0) {
                                $readErrorKind = 'other'
                                $readErrorMessage = ('PresentMon threw away {0} presents while reading the recording ("overflowed present events detected", MainThread.cpp at v2.6.0), so the frame table would be incomplete' -f $outputFacts['overflowed_presents'])
                            } elseif (@($outputFacts['errors']).Count -gt 0 -or @($outputFacts['warnings']).Count -gt 0) {
                                $readErrorKind = 'other'
                                $readErrorMessage = 'PresentMon reported a problem reading the recording: ' + ((@($outputFacts['errors']) + @($outputFacts['warnings'])) -join ' | ')
                            } else {
                                $csvText = [string]$decodeRun['StdOut']
                                $csvBytes = [int64](New-Object System.Text.UTF8Encoding($false)).GetByteCount($csvText)
                                if ($csvText.Trim().Length -eq 0) {
                                    # No frame was emitted: PresentMon prints nothing, not
                                    # even a header, before its first frame (CsvOutput.cpp
                                    # UpdateCsvT at v2.6.0), and it discards ProcessTrace's
                                    # result (ConsumerThread.cpp lines 28 to 31), so an empty
                                    # output cannot be told from a read that stopped early.
                                    # No quiet window is claimed.
                                    $readErrorKind = 'other'
                                    if ($names.Count -gt 0) {
                                        $readErrorMessage = ('PresentMon emitted no frame for the requested process names ({0}) from a {1} second recording without loss: the process was not alive across the window, did not present, or its name was not in the recorded Kernel-Process events; and with this binary an empty output cannot be told from a read that stopped early, so no absence is claimed' -f ($names -join ', '), $duration)
                                    } else {
                                        $readErrorMessage = ('PresentMon emitted no frame from a {0} second recording without loss. With this binary an empty output cannot be told from a read that stopped early (ConsumerThread.cpp discards the result of ProcessTrace at v2.6.0), so this is not a quiet window claim; the recording''s header says {1} buffers were written' -f $duration, [string]$etlHeader['buffers_written'])
                                    }
                                } else {
                                    Write-WfTextFile -Path $outputPath -Text $csvText
                                    $csv = Read-WfPresentMonCsvSummary -Path $outputPath
                                    $qpcColumn = (@($csv['header']) -contains 'CPUStartQPC')
                                    if ($csv['error']) {
                                        $readErrorKind = 'other'
                                        $readErrorMessage = 'the CSV could not be read back: ' + [string]$csv['error']
                                    } elseif (-not (@($csv['header']) -contains 'Application') -or -not (@($csv['header']) -contains 'ProcessID')) {
                                        $readErrorKind = 'other'
                                        $readErrorMessage = 'the CSV header is not the documented PresentMon header (no Application and ProcessID columns): ' + (@($csv['header']) -join ',')
                                    } elseif (-not $qpcColumn) {
                                        $readErrorKind = 'other'
                                        $readErrorMessage = '--qpc_time was requested but the CSV header has no CPUStartQPC column, so the requested setting was not in effect: ' + (@($csv['header']) -join ',')
                                    } elseif ([int]$csv['frames'] -eq 0) {
                                        $readErrorKind = 'other'
                                        $readErrorMessage = 'PresentMon printed a CSV header and no frame row, which the pinned source never does (the header is written at the first frame); the output is not trusted'
                                    } else {
                                        $frames = [int]$csv['frames']
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        # The recording never leaves the PC (see command.json recording_deleted_because).
        $undeleted = @(Remove-WfPresentMonRecordingData -wprTempPath $wprTempPath -etlPath $etlPath)
        if ($undeleted.Count -gt 0) {
            $dataLeft = $true
            $leftover = @(Get-WfPresentMonLeftoverRecords -BundleRoot $BundleRoot -RelativeDir $relativeDir -Roles $roles)
            $message = Get-WfPresentMonLeftoverNote -Id $id -Undeleted $undeleted -Leftover $leftover
            $Notes.Add($message); $Log.Add($message)
            $frames = 0
            if ($readErrorKind) {
                $readErrorMessage = ($readErrorMessage -replace '; nothing was recorded$', '') + '; recorded data could not be deleted from the bundle (see the manifest notes)'
            } else {
                $readErrorMessage = 'recorded data could not be deleted from the bundle (see the manifest notes), so nothing is claimed from this run'
            }
            $readErrorKind = 'other'
        }
        $stopped = Get-WfUtcNow
        if ($ownsRecording) {
            $message = 'source ' + $id + ': could not confirm that the WPR recording of instance ' + $instance + ' stopped (the status after the stop did not show it idle and the cancel did not complete); run "wpr -cancel -instancename ' + $instance + '" as an administrator to be sure'
            $Notes.Add($message); $Log.Add($message)
            if ($readErrorKind) { $readErrorMessage += '; the recording may still be active (see the manifest notes)' }
        }
        $consoleText = $console.ToString()
        if ($consoleText.Length -gt 0) { Write-WfTextFile -Path $consolePath -Text $consoleText }

        $recording = [ordered]@{
            instance_name            = $instance
            session_cap_mb           = $sessionCapMb
            etl_bytes                = $etlBytes
            etl_sha256               = $etlSha256
            etl_kept                 = $false
            header                   = $etlHeader
            window_start_bound_utc   = $(if ($null -ne $recordStartBound) { ConvertTo-WfUtcString -Value $recordStartBound } else { $null })
            stop_requested_utc       = $(if ($null -ne $recordStopRequested) { ConvertTo-WfUtcString -Value $recordStopRequested } else { $null })
            window_stop_bound_utc    = $(if ($null -ne $recordStopBound) { ConvertTo-WfUtcString -Value $recordStopBound } else { $null })
            duration_seconds         = $duration
            in_progress_at_end       = [bool]$statusFacts['in_progress']
            session_ended_early      = $sessionEndedEarly
            stop_confirmed           = $stopConfirmed
            events_lost              = $eventsLost
            events_lost_sources      = $eventsLostSources
            buffers_lost             = $buffersLost
            wpr_collectors           = @($statusFacts['collectors'])
            wpr_enabled_providers    = @($statusFacts['providers'])
            settings_comparison      = $comparison
            presentmon               = $outputFacts
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/recording.json')) -Object $recording
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
        } else {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        }
        Remove-WfPrimaryUnlessKept -Path $outputPath -Status $entry.status -Truncated $false -RecordCount $frames -Log $Log -SourceId $id
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
                sha256_before_run = $(if ($null -ne $rehash) { $rehash['sha256'] } else { $null })
            }
            controller  = [ordered]@{ path = $wpr; present = $wprPresent; file_version = $wprInfo['file_version']; sha256 = $wprInfo['sha256'] }
            runs        = [ordered]@{
                probe           = ConvertTo-WfRunRecord -Run $probeRun -Deadline (Get-WfPresentMonStatusDeadline)
                leftover_cancel = ConvertTo-WfRunRecord -Run $leftoverCancelRun -Deadline (Get-WfPresentMonCancelDeadline)
                start           = ConvertTo-WfRunRecord -Run $startRun -Deadline (Get-WfPresentMonStartDeadline)
                status          = ConvertTo-WfRunRecord -Run $statusRun -Deadline (Get-WfPresentMonStatusDeadline)
                stop            = ConvertTo-WfRunRecord -Run $stopRun -Deadline (Get-WfPresentMonStopDeadline)
                after           = ConvertTo-WfRunRecord -Run $afterRun -Deadline (Get-WfPresentMonStatusDeadline)
                cancel          = ConvertTo-WfRunRecord -Run $cancelRun -Deadline (Get-WfPresentMonCancelDeadline)
                decode          = ConvertTo-WfRunRecord -Run $decodeRun -Deadline (Get-WfPresentMonDecodeDeadline)
            }
            source_started_utc = ConvertTo-WfUtcString -Value $started
            source_stopped_utc = ConvertTo-WfUtcString -Value $stopped
            csv         = [ordered]@{
                path                       = $relativeDir + '/frames.csv'
                present                    = (Test-Path -LiteralPath $outputPath)
                bytes                      = $csvBytes
                header                     = @($csv['header'])
                qpc_time_column            = $qpcColumn
                frames                     = [int]$csv['frames']
                processes                  = @($csv['processes'])
                truncated_process_list     = [bool]$csv['truncated_process_list']
                unknown_application_frames = [int]$csv['unknown_application_frames']
            }
            recorded_data_left = @($leftover)
            account     = $config.account
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if (Test-WfObservedStatus -Status $entry.status) {
            # The range the source claims contains the recording: from before
            # the start was issued to after the stop returned.
            $entry.raw_time_range = New-WfTimeRange -StartUtc $recordStartBound -EndUtc $recordStopBound
        }
        $entry.events_lost = $eventsLost
        $entry.enabled = [ordered]@{
            providers = @($comparison['providers'] | Where-Object { $_['enabled'] } | ForEach-Object { [string]$_['id'] })
            keywords  = @($comparison['providers'] | Where-Object { $_['enabled'] } | ForEach-Object { [string]$_['id'] + ':' + [string]$_['enabled_keywords'] })
            stack_walk = @(); counters = @()
            options   = [ordered]@{
                wpr_start_exit_code        = $(if ($null -ne $startRun) { $startRun['ExitCode'] } else { $null })
                recording_in_progress      = [bool]$statusFacts['in_progress']
                settings_match_request     = $comparison['ok']
                stop_confirmed             = $stopConfirmed
                session_ended_early        = $sessionEndedEarly
                events_lost                = $eventsLost
                events_lost_sources        = $eventsLostSources
                buffers_lost               = $buffersLost
                etl_bytes                  = $etlBytes
                etl_sha256                 = $etlSha256
                etl_kept                   = $false
                etl_header_found           = [bool]$etlHeader['found']
                clock_type                 = $(if ($etlHeader['found']) { $etlHeader['clock_type'] } else { $null })
                perf_freq_hz               = $(if ($etlHeader['found']) { $etlHeader['perf_freq_hz'] } else { $null })
                recording_start_utc        = $(if ($etlHeader['found']) { $etlHeader['start_time_utc'] } else { $null })
                recording_end_utc          = $(if ($etlHeader['found']) { $etlHeader['end_time_utc'] } else { $null })
                presentmon_exit_code       = $(if ($null -ne $decodeRun) { $decodeRun['ExitCode'] } else { $null })
                presentmon_overflowed_presents = $outputFacts['overflowed_presents']
                presentmon_warnings        = @($outputFacts['warnings'])
                csv_present                = (Test-Path -LiteralPath $outputPath)
                csv_bytes                  = $csvBytes
                csv_header                 = @($csv['header'])
                qpc_time_column            = $qpcColumn
                records                    = $frames
                processes                  = @($csv['processes'])
                unknown_application_frames = [int]$csv['unknown_application_frames']
                elevated                   = $account['elevated']
                performance_log_users      = $account['performance_log_users']
            }
            verified_by = 'wpr -status collectors -details at the end of the window (recording in progress, Dropped event and Events Lost counters, the enabled providers with their keywords and levels compared with the request), the log file header of the recording (events and buffers lost, clock type, start and end), the CSV PresentMon printed (a CPUStartQPC column proves --qpc_time) and its stderr (overflowed presents), and the exit codes and console text of every run in console.txt'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('wpr start exit {0}; in progress at the end {1}; settings match {2}; events lost {3}; buffers lost {4}; recording {5} bytes; session ended early {6}; stop confirmed {7}; PresentMon exit {8}; overflowed presents {9}; {10} frames from {11} processes; CPUStartQPC column {12}' -f $report.runs.start.exit_code, [bool]$statusFacts['in_progress'], $comparison['ok'], $(if ($null -ne $eventsLost) { [string]$eventsLost } else { 'unknown' }), $(if ($null -ne $buffersLost) { [string]$buffersLost } else { 'unknown' }), $etlBytes, $sessionEndedEarly, $stopConfirmed, $report.runs.decode.exit_code, $(if ($null -ne $outputFacts['overflowed_presents']) { [string]$outputFacts['overflowed_presents'] } else { 'none reported' }), $frames, @($csv['processes']).Count, $qpcColumn)
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while running this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if ($ownsRecording) {
            # Only a recording this run started is cancelled, and only by its instance name.
            try {
                $cancelRun = Invoke-WfProcess -FilePath $wpr -Arguments ('-cancel -instancename ' + $instance) -TimeoutSeconds (Get-WfPresentMonCancelDeadline) -OutputEncoding $encoding -MaxBytes $consoleCap
                $Log.Add('source ' + $id + ': wpr -cancel -instancename ' + $instance + ' after the failure exited ' + [string]$cancelRun['ExitCode'])
                if (Test-WfRunCompleted -Run $cancelRun) { $ownsRecording = $false }
            } catch { $Log.Add('source ' + $id + ': wpr -cancel after the failure could not run: ' + $_.Exception.Message) }
            if ($ownsRecording) {
                $message = 'source ' + $id + ': the collector failed while its WPR recording (instance ' + $instance + ') may still be active; run "wpr -cancel -instancename ' + $instance + '" as an administrator'
                $Notes.Add($message); $Log.Add($message)
                $entry.status_reason += '; the recording may still be active (see the manifest notes)'
            }
        }
        $undeleted = @(Remove-WfPresentMonRecordingData -wprTempPath $wprTempPath -etlPath $etlPath)
        if ($undeleted.Count -gt 0) {
            $dataLeft = $true
            $leftover = @(Get-WfPresentMonLeftoverRecords -BundleRoot $BundleRoot -RelativeDir $relativeDir -Roles $roles)
            $message = Get-WfPresentMonLeftoverNote -Id $id -Undeleted $undeleted -Leftover $leftover
            $Notes.Add($message); $Log.Add($message)
            $entry.status_reason += '; recorded data could not be deleted from the bundle (see the manifest notes)'
        }
        if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    if ($dataLeft) {
        $entry.artifacts = Get-WfPresentMonOwnArtifactRecords -BundleRoot $BundleRoot -RelativeDir $relativeDir -Roles $roles
    } else {
        $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    }
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @(); Tools = $tools }
}

# --- parameter checks, before anything is written -----------------------------
$problems = New-Object 'System.Collections.Generic.List[string]'
if ($DurationSeconds -lt 5 -or $DurationSeconds -gt 240) { $problems.Add('DurationSeconds must be between 5 and 240') }
if ($MaxArtifactBytes -lt 1048576 -or $MaxArtifactBytes -gt 1073741824) { $problems.Add('MaxArtifactBytes must be between 1 MiB and 1 GiB') }
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
    Version                  = '2.1.0'
    Question                 = 'What did the frame pipeline do, frame by frame, during a bounded window: present cadence, time in Present, CPU and GPU busy and wait, display latency, every frame stamped in the ETW performance counter domain?'
    RequestedDurationSeconds = $DurationSeconds
    TargetProcess            = $targetProcess
    CalibrationMethod        = 'none in this collector: the recording is an ETW file whose events carry the clock its log file header names (clock_type in the manifest; QPC is the etw_qpc master domain of docs/contracts/timestamps.md), and PresentMon writes CPUStartQPC from those timestamps; the calibration pairs that relate them to system time come from the clock collector of a later runner'
    Sources                  = @(
        @{
            Id              = 'presentmon_frames'
            Type            = 'custom'
            Invoke          = 'Invoke-WfPresentMonFramesSource'
            Required        = $true
            BinaryPath      = $binaryPath
            DurationSeconds = $DurationSeconds
            ProcessNames    = @($names)
            Expectation     = 'wpr starts the profile under this collector''s instance name and reports the recording in progress at the end of the window with the requested providers enabled and zero loss; wpr -stop saves the file and the instance is confirmed idle; the file''s header reads with zero events and buffers lost, a session that ran until the stop, and a size under the cap; the pinned PresentMon, hashed again, exits 0 reading it with --etl_file and --qpc_time, reports no overflowed presents, and prints at least one frame row. Zero frames is never a quiet window with this binary (an empty output cannot be told from a read that stopped early) and is capture_failed'
        }
    )
}

# The helper's per source deadline covers every phase: the probe, a leftover
# cancel and a second probe, the start, the window, the status at the end,
# the stop and merge, the status after it, a cancel, the offline read, and
# the cancel after a failure: four status runs and three cancels.
$timeout = 4 * (Get-WfPresentMonStatusDeadline) + 3 * (Get-WfPresentMonCancelDeadline) + (Get-WfPresentMonStartDeadline) + $DurationSeconds + (Get-WfPresentMonStopDeadline) + (Get-WfPresentMonDecodeDeadline)
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $timeout -CollectorPath $PSCommandPath)[-1]
exit $exitCode
