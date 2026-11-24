# session-bracket: What did the machine and each running process do between
# the baseline read at logon and the read after a play session, within one
# boot?
#
# Read only. Runs under Windows PowerShell 5.1 as the playing account, not
# elevated. Writes one bundle (docs/contracts/bundle.md), prints one JSON
# summary line on stdout, and exits 0 when the bundle is complete (status ok
# or partial). See collectors/windows/README.md, "The session-bracket
# sources", for the interface, the artifact formats, the game guard and the
# facts still to be verified on a real machine.
#
# Two phases:
#
#   -Phase baseline   the read the logon task makes (the change that
#                     registers the task lives outside collectors/, and no
#                     collector calls it; applying it is the captain's own
#                     decision at the PC). It runs the sources below and
#                     stops.
#   -Phase after      the same read, by hand or by the PC session after a
#                     play session, followed by session_delta: the newest
#                     baseline bundle next to this one is found, its
#                     artifacts are checked against the SHA-256 in its
#                     manifest, and the counters are subtracted, but only
#                     when it was taken in the same boot. Across a reboot
#                     nothing is subtracted. Processes are matched on
#                     process id plus creation time, and every row that
#                     cannot be subtracted carries a gap code (below).
#
# Sources, in order:
#
#   game_guard          Win32_Process, the Name property only, compared here
#                       with -GameProcessNames. When a game process is
#                       already running, or the guard cannot tell, every
#                       other source is recorded not_collected with that
#                       reason and nothing else is read.
#   boot                Win32_OperatingSystem LastBootUpTime, the boot
#                       identity the after phase compares
#   process_io          Win32_Process Name, ProcessId, CreationDate,
#                       WriteTransferCount, WriteOperationCount (no command
#                       line, no path). Write I/O counts file, network and
#                       device writes, never physical disk bytes.
#   disk_totals         Win32_PerfRawData_PerfDisk_PhysicalDisk, the raw
#                       cumulative read and write bytes and operations per
#                       physical disk
#   memory_paging       Win32_PerfRawData_PerfOS_Memory, the raw cumulative
#                       Pages Output, Page Writes, Pages Input, Page Reads
#   config_readback     the TDR values, the crash dump values and the
#                       Windows Error Reporting values the trial depends on,
#                       each present (with type and bytes) or absent
#   power_active_scheme powercfg /getactivescheme
#   event_counts        System and Application since boot, counted by
#                       provider, event id and level; counts only, never a
#                       message or event data
#   session_delta       (after only) the subtraction described above
#
# Gap codes of session_delta (the rung 1 codes):
#   0 matched, the delta is the difference of the two readings
#   1 exited or not seen after; its final count is unavailable
#   2 process id reused or restarted; the two instances cannot be subtracted
#   3 new or not seen before; its earlier count is unavailable
#   4 a counter is missing; no delta
#   5 identity missing or the process id is ambiguous; no delta
#   6 a counter decreased; no delta
#
# Citations:
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-process
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-perfrawdata
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-perf
# https://learn.microsoft.com/windows/win32/perfctrs/about-performance-counters
# https://learn.microsoft.com/windows/win32/wmisdk/monitoring-performance-data
# https://learn.microsoft.com/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows
# https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys
# https://learn.microsoft.com/troubleshoot/windows-server/performance/memory-dump-file-options
# https://learn.microsoft.com/windows/win32/wer/wer-settings
# https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting
# https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-icm
# https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options
# https://learn.microsoft.com/windows/win32/eventlog/eventlog-key
# https://learn.microsoft.com/dotnet/api/system.environment.specialfolder
#
# Nothing here opens a handle to, injects into, overlays, suspends, or
# changes the priority or affinity of any process: the process list is read
# through the WMI provider with the properties named above, and what the
# provider does inside the WMI host to fill them is not documented (README
# verification item 60). That is why the game guard runs first and why the
# read never runs beside a game. The registry is opened for reading, powercfg
# runs one listing verb, and the event log is read, never cleared.
[CmdletBinding()]
param(
    # The dispatcher's one parameter. Checked in the body, never Mandatory.
    [string]$OutputDirectory,
    # baseline (default) or after.
    [string]$Phase = 'baseline',
    # The logon task passes this instead of -OutputDirectory: the bundle goes
    # to <Desktop>\latency-evidence\session-<phase>-<UTC>, the Desktop folder
    # resolved through the documented known folder API (Environment.
    # SpecialFolder DesktopDirectory), never a hard coded profile path, and a
    # <bundle>.sha256 file next to it records the SHA-256 of its manifest.
    [switch]$ToEvidenceFolder,
    # Image names that count as a game for the guard, compared without
    # regard to case. The defaults are the two names seen in the captain's
    # own process lists; neither vendor documents them (README verification
    # list).
    [string[]]$GameProcessNames = @('Overwatch.exe', 'FortniteClient-Win64-Shipping.exe'),
    # Cap on records per source (1 to 100000); event_counts reads every
    # record of a channel since boot, so the default is high.
    [int]$MaxEvents = 50000,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for one source, in seconds (1 to 3600). Nine sources share the
    # dispatcher's 900 second budget.
    [int]$TimeoutSeconds = 90
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'session-bracket'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
$problem = $null
if (-not (Test-Path -LiteralPath $common)) { $problem = 'the shared helper is missing: ' + $common }
elseif ($Phase -ne 'baseline' -and $Phase -ne 'after') { $problem = '-Phase must be baseline or after' }
elseif ($ToEvidenceFolder -and $OutputDirectory) { $problem = '-ToEvidenceFolder and -OutputDirectory are exclusive; pass one' }
elseif (-not $ToEvidenceFolder -and -not $OutputDirectory) { $problem = '-OutputDirectory is required (or -ToEvidenceFolder)' }
if ($problem) {
    # No bundle can be written; the summary line is still printed so the
    # dispatcher gets its one line.
    [Console]::Error.WriteLine($collectorName + ': ' + $problem)
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}
. $common

function Get-SessionBracketGapText {
    param([int]$Code)
    switch ($Code) {
        0 { return 'matched' }
        1 { return 'exited or not seen after; final count unavailable' }
        2 { return 'process id reused or restarted; instances cannot be subtracted' }
        3 { return 'new or not seen before; earlier count unavailable' }
        4 { return 'counter missing; no delta' }
        5 { return 'identity missing or ambiguous process id; no delta' }
        6 { return 'counter decreased; no delta' }
    }
    return 'unknown'
}

function ConvertTo-SessionBracketPlain {
    # JSON read back with ConvertFrom-Json as plain maps, lists and scalars.
    # PowerShell 7 turns ISO 8601 text into DateTime and Windows PowerShell
    # 5.1 leaves it as text; both become the repository's UTC text here.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return (ConvertTo-WfUtcString -Value $Value) }
    if ($Value -is [string] -or $Value -is [System.ValueType]) { return $Value }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $map = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { $map[[string]$property.Name] = ConvertTo-SessionBracketPlain -Value $property.Value }
        return $map
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $map = [ordered]@{}
        $enumerator = $Value.GetEnumerator()
        while ($enumerator.MoveNext()) { $map[[string]$enumerator.Key] = ConvertTo-SessionBracketPlain -Value $enumerator.Value }
        return $map
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) { $items.Add((ConvertTo-SessionBracketPlain -Value $item)) }
        return , $items.ToArray()
    }
    return [string]$Value
}

function Read-SessionBracketJson {
    # One JSON file as plain values. -Array makes the top level a list:
    # PowerShell 7 enumerates a one element array to its element and an empty
    # array to nothing, Windows PowerShell 5.1 does not.
    param([string]$Path, [switch]$Array)
    $text = [System.IO.File]::ReadAllText($Path)
    $parsed = ConvertFrom-Json -InputObject $text
    $plain = ConvertTo-SessionBracketPlain -Value $parsed
    if ($Array) {
        if ($null -eq $plain) { return , @() }
        if ($plain -is [System.Collections.IDictionary]) { return , @($plain) }
        return , @($plain)
    }
    return $plain
}

function Get-SessionBracketDecimal {
    # A counter as an exact decimal, or $null when it is missing or not a
    # number. Decimal subtraction keeps UInt64 counts exact without wrap.
    param($Value)
    if ($null -eq $Value) { return $null }
    $parsed = [decimal]0
    $text = [string]$Value
    if ($Value -is [System.ValueType] -and -not ($Value -is [bool])) { $text = ([System.IConvertible]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    if ([decimal]::TryParse($text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertTo-SessionBracketCount {
    # A delta for the JSON writer, which writes decimals as doubles: an Int64
    # keeps every digit.
    param($Value)
    if ($null -eq $Value) { return $null }
    return [int64]$Value
}

function Get-SessionBracketSkipReason {
    # Why a source must not read, or $null when the guard proved no game runs.
    param([hashtable]$Context)
    $guard = $Context['SessionBracketGuard']
    if ($null -eq $guard) { return 'the game guard did not run, so whether a game is running is unknown; nothing else is read' }
    if (-not $guard['Completed']) { return ('the game guard could not read the process list (' + [string]$guard['Status'] + ': ' + [string]$guard['Reason'] + '), so whether a game is running is unknown; nothing else is read') }
    if (@($guard['Games']).Count -gt 0) { return ('a game process was already running (' + (@($guard['Games']) -join ', ') + '); this read never runs beside a game, so nothing else was read and no process was opened') }
    return $null
}

function New-SessionBracketSkippedResult {
    # The manifest entry of a source that was not read because of the guard:
    # not_collected, its reason, and one config file that says what would
    # have been read. No primary, so nothing can be read as an empty result.
    param([hashtable]$Source, [string]$BundleRoot, [string]$Reason, [System.Collections.Generic.List[string]]$Log)
    $inner = $Source['Inner']
    $id = [string]$Source['Id']
    $kind = 'other'
    if ($inner -and $inner['Kind']) { $kind = [string]$inner['Kind'] } elseif ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $relativeDir = 'raw/' + $id
    $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir)
    $now = Get-WfUtcNow
    $plan = [ordered]@{ source = $id; read = [string]$Source['Reads']; phase = [string]$Source['Phase']; skipped = $true; reason = $Reason }
    $planPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
    Write-WfJsonFile -Path $planPath -Object $plan
    $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $planPath) }
    $entry.command = @('session-bracket', 'skipped', $id)
    $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $plan }
    $entry.started_utc = ConvertTo-WfUtcString -Value $now
    $entry.preflight = [ordered]@{ ok = $false; at_utc = (ConvertTo-WfUtcString -Value $now); checks = @([ordered]@{ name = 'game_guard'; ok = $false; detail = $Reason }) }
    $entry.status = 'not_collected'
    $entry.status_reason = $Reason
    $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $false; detail = 'not read: ' + $Reason }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles @{ 'query.json' = 'config' }
    $Log.Add(('source {0}: status {1} (game guard), {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# The game guard: the process names only, compared here, so no WQL filter is
# evaluated on the provider's side and nothing but the image names is read.
$invokeGameGuard = {
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
    $entry = New-WfCollectorEntry -Id $id -Kind 'process_inventory' -Required $true
    $relativeDir = 'raw/' + $id
    $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir)
    $primaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/matches.json')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $names = [string[]]@($Source['GameNames'])
    $guard = @{ Completed = $false; Games = @(); Status = 'capture_failed'; Reason = 'the guard stopped before it read the process list' }
    $Context['SessionBracketGuard'] = $guard
    try {
        $query = [ordered]@{
            class = 'Win32_Process'; namespace = 'root/cimv2'; properties = @('Name'); filter = $null
            game_process_names = $names; comparison = 'ordinal, ignoring case, on the whole image name'
            max_records = [int]$Source['MaxRecords']; timeout_seconds = $TimeoutSeconds
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.command = @('session-bracket', 'game_guard', 'Get-CimInstance', '-ClassName', 'Win32_Process', '-Property', 'Name', '-OperationTimeoutSec', [string]$TimeoutSeconds)
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }
        $read = Get-WfCimRows -Namespace 'root/cimv2' -ClassName 'Win32_Process' -Properties @('Name') -Filter $null `
            -MaxRows ([int]$Source['MaxRecords']) -MaxBytes $MaxArtifactBytes -DeadlineUtc ($started.AddSeconds($TimeoutSeconds))
        $readAt = Get-WfUtcNow
        $rows = Get-WfList -Value $read['Rows']
        $errorKind = $null
        $errorMessage = $null
        if (-not $read['Ok']) {
            $errorKind = [string]$read['ErrorKind']
            if (-not $errorKind) { $errorKind = 'other' }
            $errorMessage = [string]$read['ErrorMessage']
        } elseif ([bool]$read['Truncated']) {
            $errorKind = 'other'
            $errorMessage = 'the process list was cut at its cap (' + [string]$read['TruncationReason'] + '), so a game could be among the rows not read'
        } elseif ($rows.Count -eq 0) {
            $errorKind = 'other'
            $errorMessage = 'the class returned no instances; the process list is never empty on a running machine'
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $errorKind)
            at_utc = ConvertTo-WfUtcString -Value $readAt
            checks = @([ordered]@{ name = 'class_readable'; ok = (-not $errorKind); detail = $(if ($errorKind) { $errorMessage } else { 'root/cimv2:Win32_Process' }) })
        }
        if ($errorKind) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $errorKind -ReadErrorMessage $errorMessage -WindowStartUtc $started
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $false; detail = $errorMessage }
            $guard['Status'] = $entry.status
            $guard['Reason'] = $entry.status_reason
        } else {
            $counts = [ordered]@{}
            foreach ($row in $rows) {
                $name = [string]$row['Name']
                foreach ($game in $names) {
                    if ([string]::Equals($name, $game, [System.StringComparison]::OrdinalIgnoreCase)) {
                        if (-not $counts.Contains($game)) { $counts[$game] = 0 }
                        $counts[$game] = [int]$counts[$game] + 1
                    }
                }
            }
            $found = New-Object 'System.Collections.Generic.List[object]'
            $enumerator = $counts.GetEnumerator()
            while ($enumerator.MoveNext()) { $found.Add([ordered]@{ name = [string]$enumerator.Key; instances = [int]$enumerator.Value }) }
            Write-WfJsonLinesFile -Path $primaryPath -Lines @($found.ToArray() | ForEach-Object { ConvertTo-WfJson -Value $_ })
            $guard['Completed'] = $true
            $guard['Games'] = @($found.ToArray() | ForEach-Object { [string]$_['name'] })
            $guard['Status'] = $(if ($found.Count -gt 0) { 'observed' } else { 'observed_zero' })
            if ($found.Count -gt 0) { $Notes.Add('game guard: ' + (@($guard['Games']) -join ', ') + ' was running, so only the guard read; run the read again when no game runs') }
            $guard['Reason'] = $null
            $entry.status = $guard['Status']
            $entry.status_reason = $null
            $entry.raw_time_range = New-WfTimeRange -StartUtc $readAt -EndUtc $readAt
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $true; detail = ('{0} processes listed; {1} game processes among them' -f $rows.Count, $found.Count) }
            $entry.enabled = [ordered]@{
                providers = @(); keywords = @(); stack_walk = @(); counters = @()
                options = [ordered]@{ processes_listed = $rows.Count; games_found = @($guard['Games']); guard_blocks_read = ($found.Count -gt 0) }
                verified_by = 'Get-CimInstance returned the whole process list without error under its operation timeout and below the cap; an empty matches.json is a read that found no game, an observation'
            }
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $guard['Status'] = $entry.status
        $guard['Reason'] = $entry.status_reason
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $primaryPath) { Remove-Item -LiteralPath $primaryPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles @{ 'query.json' = 'config'; 'matches.json' = 'primary' }
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# A built in source behind the guard: the inner definition is read by the
# helper's own source type once the guard proved no game runs.
$invokeGuarded = {
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    if (-not $Context.ContainsKey('SessionBracketStatus')) { $Context['SessionBracketStatus'] = @{} }
    $skip = Get-SessionBracketSkipReason -Context $Context
    if ($skip) {
        $result = New-SessionBracketSkippedResult -Source $Source -BundleRoot $BundleRoot -Reason $skip -Log $Log
        $Context['SessionBracketStatus'][[string]$Source['Id']] = 'not_collected'
        return $result
    }
    $inner = $Source['Inner']
    $type = [string]$inner['Type']
    $maxRecords = [int]$Source['MaxRecords']
    if ($type -eq 'cim') {
        $result = Invoke-WfCimSource -Source $inner -BundleRoot $BundleRoot -WindowDays 1 -MaxEvents $maxRecords -MaxArtifactBytes $MaxArtifactBytes `
            -TimeoutSeconds $TimeoutSeconds -Log $Log -Notes $Notes -Context $Context
    } elseif ($type -eq 'registry') {
        $result = Invoke-WfRegistrySource -Source $inner -BundleRoot $BundleRoot -MaxEvents $maxRecords -MaxArtifactBytes $MaxArtifactBytes `
            -TimeoutSeconds $TimeoutSeconds -Log $Log -Notes $Notes -Context $Context
    } elseif ($type -eq 'command') {
        $result = Invoke-WfCommandSource -Source $inner -BundleRoot $BundleRoot -MaxArtifactBytes $MaxArtifactBytes `
            -TimeoutSeconds $TimeoutSeconds -Log $Log -Notes $Notes -Context $Context
    } else {
        throw ('source ' + [string]$Source['Id'] + ' guards an unknown type: ' + $type)
    }
    $Context['SessionBracketStatus'][[string]$Source['Id']] = [string]$result['Entry']['status']
    return $result
}

function Get-SessionBracketBootUtc {
    # LastBootUpTime from this bundle's boot source, as UTC text, or $null.
    param([string]$BundleRoot)
    $path = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'raw/boot/records.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $rows = Read-SessionBracketJson -Path $path -Array
    if (@($rows).Count -ne 1) { return $null }
    $value = $rows[0]['LastBootUpTime']
    if (-not $value) { return $null }
    return [string]$value
}

# event_counts: every record of System and Application since boot, counted
# by provider, event id and level. The counts are the only thing written:
# no message, no event data, no user id. The count covers the boot only when
# the oldest record each channel still holds is at or before the boot.
$invokeEventCounts = {
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    if (-not $Context.ContainsKey('SessionBracketStatus')) { $Context['SessionBracketStatus'] = @{} }
    $skip = Get-SessionBracketSkipReason -Context $Context
    if ($skip) {
        $Context['SessionBracketStatus'][[string]$Source['Id']] = 'not_collected'
        return (New-SessionBracketSkippedResult -Source $Source -BundleRoot $BundleRoot -Reason $skip -Log $Log)
    }
    $id = [string]$Source['Id']
    $entry = New-WfCollectorEntry -Id $id -Kind 'other' -Required $true
    $relativeDir = 'raw/' + $id
    $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir)
    $primaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/counts.json')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $channels = [string[]]@($Source['Channels'])
    $maxRecords = [int]$Source['MaxRecords']
    try {
        $bootText = Get-SessionBracketBootUtc -BundleRoot $BundleRoot
        $end = ConvertTo-WfMillisecondFloor -Value (Get-WfUtcNow)
        $boot = $null
        if ($bootText) { $boot = ConvertTo-WfMillisecondFloor -Value (ConvertFrom-WfUtcString -Text $bootText) }
        $predicate = '(Level >= 0)'
        $query = [ordered]@{
            channels = $channels; predicate = $predicate; since_boot_utc = $bootText; until_utc = $(if ($null -ne $boot) { ConvertTo-WfUtcString -Value $end } else { $null })
            counted_by = @('channel', 'provider_name', 'event_id', 'level'); kept = 'counts only; no message, event data or user id is written'
            max_records_per_channel = $maxRecords; max_artifact_bytes = $MaxArtifactBytes; timeout_seconds = $TimeoutSeconds
            queries = [ordered]@{}
        }
        if ($null -ne $boot) {
            $windowMs = [int64][math]::Floor(($end - $boot).TotalMilliseconds)
            foreach ($channel in $channels) { $query.queries[$channel] = Build-WfEventQueryXml -Channel $channel -Predicates @($predicate) -EndUtc $end -WindowMilliseconds $windowMs }
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.command = @('session-bracket', 'event_counts', 'EventLogReader') + $channels
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }
        $report = [ordered]@{ channels = @() }
        $errorKind = $null
        $errorMessage = $null
        if ($null -eq $boot) {
            $errorKind = 'preflight'
            $errorMessage = 'the boot time was not read (source boot), so "since boot" has no start'
        }
        $counts = @{}
        $order = New-Object 'System.Collections.Generic.List[string]'
        $deadline = $started.AddSeconds($TimeoutSeconds)
        $channelReports = New-Object 'System.Collections.Generic.List[object]'
        if (-not $errorKind) {
            foreach ($channel in $channels) {
                $accumulator = New-WfRowAccumulator -MaxRows $maxRecords -MaxBytes ([int64]::MaxValue)
                $read = Read-WfEventRecords -Channel $channel -QueryXml ([string]$query.queries[$channel]) -DeadlineUtc $deadline -Accumulator $accumulator
                $state = Get-WfChannelState -Channel $channel -DeadlineUtc $deadline
                $oldest = $state['oldest_record_time_utc']
                $covers = ($null -ne $oldest -and (ConvertFrom-WfUtcString -Text ([string]$oldest)) -le $boot)
                $channelReports.Add([ordered]@{
                        channel = $channel; records = $accumulator.Rows.Count; truncated = [bool]$accumulator.Truncated
                        oldest_record_time_utc = $oldest; oldest_probe = $state['oldest_probe']; covers_boot = $covers
                        error = $(if ($read['Ok']) { $null } else { [string]$read['ErrorMessage'] })
                    })
                if (-not $read['Ok']) {
                    $errorKind = [string]$read['ErrorKind']
                    if ($read['Stage'] -eq 'open' -and $errorKind -ne 'access_denied' -and $errorKind -ne 'not_found') { $errorKind = 'preflight' }
                    if (-not $errorKind) { $errorKind = 'other' }
                    $errorMessage = $channel + ': ' + [string]$read['ErrorMessage']
                    break
                }
                if ($accumulator.Truncated) {
                    $errorKind = 'other'
                    $errorMessage = ('{0}: the read stopped at its cap ({1}), so the counts are not the complete set since boot' -f $channel, [string]$accumulator.Reason)
                    break
                }
                if (-not $covers) {
                    $Notes.Add(('event_counts: the {0} log no longer reaches back to the boot; a larger log size keeps a whole boot' -f $channel))
                    $errorKind = 'other'
                    $errorMessage = ('{0}: the oldest record the channel still holds ({1}) is after the boot ({2}), so records since boot may have been overwritten and the counts are not complete' -f $channel, [string]$oldest, $bootText)
                    break
                }
                foreach ($row in $accumulator.Rows) {
                    $key = $channel + '|' + [string]$row['provider_name'] + '|' + [string]$row['event_id'] + '|' + [string]$row['level']
                    if (-not $counts.ContainsKey($key)) {
                        $counts[$key] = [ordered]@{ channel = $channel; provider_name = [string]$row['provider_name']; event_id = [int]$row['event_id']; level = $row['level']; count = 0 }
                        $order.Add($key)
                    }
                    $counts[$key]['count'] = [int]$counts[$key]['count'] + 1
                }
            }
        }
        $report.channels = @($channelReports.ToArray())
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        $entry.preflight = [ordered]@{
            ok     = (-not $errorKind -or ($errorKind -ne 'preflight' -and $errorKind -ne 'access_denied' -and $errorKind -ne 'not_found'))
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @([ordered]@{ name = 'channels_readable'; ok = (-not $errorKind); detail = $(if ($errorKind) { $errorMessage } else { $channels -join ', ' }) })
        }
        if ($errorKind) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $errorKind -ReadErrorMessage $errorMessage -WindowStartUtc $started
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $false; detail = $errorMessage }
        } else {
            $sorted = @($order.ToArray() | Sort-Object)
            $lines = @(foreach ($key in $sorted) { ConvertTo-WfJson -Value $counts[$key] })
            Write-WfJsonLinesFile -Path $primaryPath -Lines $lines
            $total = 0
            foreach ($key in $sorted) { $total += [int]$counts[$key]['count'] }
            $entry.status = $(if ($total -gt 0) { 'observed' } else { 'observed_zero' })
            $entry.status_reason = $null
            $entry.raw_time_range = New-WfTimeRange -StartUtc $boot -EndUtc $end
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $true; detail = ('{0} records since boot in {1} groups; every channel holds a record at or before the boot' -f $total, $sorted.Count) }
            $entry.enabled = [ordered]@{
                providers = @(); keywords = @(); stack_walk = @(); counters = @()
                options = [ordered]@{ records = $total; groups = $sorted.Count; since_boot_utc = $bootText; until_utc = (ConvertTo-WfUtcString -Value $end) }
                verified_by = 'each channel was read to the end of the fixed interval under the deadline and below the cap, and its oldest retained record is at or before the boot (result.json)'
            }
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $primaryPath) { Remove-Item -LiteralPath $primaryPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles @{ 'query.json' = 'config'; 'counts.json' = 'primary'; 'result.json' = 'report' }
    $Context['SessionBracketStatus'][$id] = [string]$entry.status
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Get-SessionBracketBaselines {
    # Every baseline bundle in the folder that started before this run,
    # newest first. A baseline is a bundle of this collector whose boot
    # source recorded phase baseline (read or skipped by the game guard).
    param([string]$Directory, [string]$OwnBundleRoot, [datetime]$Before)
    $found = New-Object 'System.Collections.Generic.List[object]'
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory)) { return , $found.ToArray() }
    $own = [System.IO.Path]::GetFullPath($OwnBundleRoot).TrimEnd('\', '/')
    foreach ($folder in @(Get-ChildItem -LiteralPath $Directory -Directory)) {
        if ([System.IO.Path]::GetFullPath($folder.FullName).TrimEnd('\', '/') -eq $own) { continue }
        $manifestPath = Join-Path -Path $folder.FullName -ChildPath 'manifest.json'
        $phasePath = Join-WfBundlePath -BundleRoot $folder.FullName -RelativePath 'raw/boot/query.json'
        if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $phasePath)) { continue }
        try {
            $manifest = Read-SessionBracketJson -Path $manifestPath
            if ([string]$manifest['scenario']['id'] -ne 'session_bracket') { continue }
            if ([string](Read-SessionBracketJson -Path $phasePath)['phase'] -ne 'baseline') { continue }
            $start = ConvertFrom-WfUtcString -Text ([string]$manifest['capture']['start_utc'])
            if ($start -ge $Before) { continue }
            $found.Add(@{ Folder = $folder; Manifest = $manifest; Start = $start; Name = $folder.Name })
        } catch {
            continue
        }
    }
    $sorted = @($found.ToArray() | Sort-Object -Property @{ Expression = { $_['Start'] }; Descending = $true }, @{ Expression = { $_['Name'] }; Descending = $true })
    return , $sorted
}

function Test-SessionBracketBaselineIntact {
    # Every artifact the baseline manifest lists still has its recorded
    # SHA-256. Returns the first difference, or $null.
    param([string]$BundleRoot, $Manifest)
    $sidecar = $BundleRoot.TrimEnd('\', '/') + '.sha256'
    if (Test-Path -LiteralPath $sidecar) {
        $recorded = ([System.IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
        $actual = Get-WfSha256OfFile -Path (Join-Path -Path $BundleRoot -ChildPath 'manifest.json')
        if ($recorded -ne $actual) { return 'changed manifest.json (its SHA-256 differs from the .sha256 file next to the bundle)' }
    }
    foreach ($collector in @($Manifest['collectors'])) {
        foreach ($artifact in @($collector['artifacts'])) {
            $path = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ([string]$artifact['path'])
            if (-not (Test-Path -LiteralPath $path)) { return ('missing ' + [string]$artifact['path']) }
            if ((Get-WfSha256OfFile -Path $path) -ne [string]$artifact['sha256']) { return ('changed ' + [string]$artifact['path']) }
        }
    }
    return $null
}

function Get-SessionBracketSourceStatus {
    param($Manifest, [string]$Id)
    foreach ($collector in @($Manifest['collectors'])) { if ([string]$collector['id'] -eq $Id) { return [string]$collector['status'] } }
    return $null
}

function Compare-SessionBracketProcesses {
    # The rung 1 comparison: match on process id plus creation time,
    # subtract exact counts with decimal arithmetic, and name every row that
    # cannot be subtracted.
    param([object[]]$Before, [object[]]$After)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $afterByPid = @{}
    foreach ($new in $After) {
        if ($null -eq $new['ProcessId']) { continue }
        $key = [string]$new['ProcessId']
        if (-not $afterByPid.ContainsKey($key)) { $afterByPid[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $afterByPid[$key].Add($new)
    }
    $beforePids = @{}
    foreach ($old in $Before) { if ($null -ne $old['ProcessId']) { $beforePids[[string]$old['ProcessId']] = $true } }
    foreach ($old in $Before) {
        $start = $old['CreationDate']
        $new = $null
        $newStart = $null
        $bytes = $null
        $ops = $null
        $gap = 0
        $found = @()
        if ($null -ne $old['ProcessId'] -and $afterByPid.ContainsKey([string]$old['ProcessId'])) { $found = @($afterByPid[[string]$old['ProcessId']].ToArray()) }
        if ($null -eq $old['ProcessId'] -or -not $start) { $gap = 5 }
        elseif ($found.Count -eq 0) { $gap = 1 }
        elseif ($found.Count -ne 1) { $gap = 5 }
        else {
            $new = $found[0]
            $newStart = $new['CreationDate']
            $oldBytes = Get-SessionBracketDecimal -Value $old['WriteTransferCount']
            $oldOps = Get-SessionBracketDecimal -Value $old['WriteOperationCount']
            $newBytes = Get-SessionBracketDecimal -Value $new['WriteTransferCount']
            $newOps = Get-SessionBracketDecimal -Value $new['WriteOperationCount']
            if (-not $newStart) { $gap = 5 }
            elseif ([string]$newStart -ne [string]$start) { $gap = 2 }
            elseif ($null -eq $oldBytes -or $null -eq $oldOps -or $null -eq $newBytes -or $null -eq $newOps) { $gap = 4 }
            elseif ($newBytes -lt $oldBytes -or $newOps -lt $oldOps) { $gap = 6 }
            else {
                $bytes = $newBytes - $oldBytes
                $ops = $newOps - $oldOps
            }
        }
        $out.Add([ordered]@{
                name                   = $old['Name']
                after_name             = $(if ($null -ne $new) { $new['Name'] } else { $null })
                process_id             = $old['ProcessId']
                before_start_utc       = $start
                after_start_utc        = $newStart
                delta_write_bytes      = ConvertTo-SessionBracketCount -Value $bytes
                delta_write_operations = ConvertTo-SessionBracketCount -Value $ops
                gap_code               = $gap
                gap                    = Get-SessionBracketGapText -Code $gap
            })
    }
    foreach ($new in $After) {
        if ($null -ne $new['ProcessId'] -and $beforePids.ContainsKey([string]$new['ProcessId'])) { continue }
        $gap = 3
        if ($null -eq $new['ProcessId'] -or -not $new['CreationDate']) { $gap = 5 }
        $out.Add([ordered]@{
                name = $new['Name']; after_name = $new['Name']; process_id = $new['ProcessId']
                before_start_utc = $null; after_start_utc = $new['CreationDate']
                delta_write_bytes = $null; delta_write_operations = $null; gap_code = $gap; gap = Get-SessionBracketGapText -Code $gap
            })
    }
    return , $out.ToArray()
}

function Compare-SessionBracketInstances {
    # Cumulative counters keyed by instance name (a physical disk, or the one
    # Memory instance): the same gap codes, the instance name as identity.
    param([object[]]$Before, [object[]]$After, [string[]]$Counters)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $afterByName = @{}
    foreach ($new in $After) { $afterByName[[string]$new['Name']] = $new }
    $beforeNames = @{}
    foreach ($old in $Before) {
        $name = [string]$old['Name']
        $beforeNames[$name] = $true
        $row = [ordered]@{ instance = $old['Name']; gap_code = 0; gap = $null; deltas = [ordered]@{} }
        if (-not $afterByName.ContainsKey($name)) { $row.gap_code = 1 }
        else {
            $new = $afterByName[$name]
            foreach ($counter in $Counters) {
                $a = Get-SessionBracketDecimal -Value $old[$counter]
                $b = Get-SessionBracketDecimal -Value $new[$counter]
                if ($null -eq $a -or $null -eq $b) { $row.gap_code = 4; $row.deltas[$counter] = $null }
                elseif ($b -lt $a) { if ($row.gap_code -eq 0) { $row.gap_code = 6 }; $row.deltas[$counter] = $null }
                else { $row.deltas[$counter] = ConvertTo-SessionBracketCount -Value ($b - $a) }
            }
            if ($row.gap_code -ne 0) { foreach ($counter in $Counters) { $row.deltas[$counter] = $null } }
        }
        $row.gap = Get-SessionBracketGapText -Code $row.gap_code
        $out.Add($row)
    }
    foreach ($new in $After) {
        if ($beforeNames.ContainsKey([string]$new['Name'])) { continue }
        $out.Add([ordered]@{ instance = $new['Name']; gap_code = 3; gap = (Get-SessionBracketGapText -Code 3); deltas = [ordered]@{} })
    }
    return , $out.ToArray()
}

function Compare-SessionBracketEventCounts {
    param([object[]]$Before, [object[]]$After)
    $keys = New-Object 'System.Collections.Generic.List[string]'
    $old = @{}
    $new = @{}
    foreach ($row in $Before) { $key = [string]$row['channel'] + '|' + [string]$row['provider_name'] + '|' + [string]$row['event_id'] + '|' + [string]$row['level']; $old[$key] = $row; if (-not $keys.Contains($key)) { $keys.Add($key) } }
    foreach ($row in $After) { $key = [string]$row['channel'] + '|' + [string]$row['provider_name'] + '|' + [string]$row['event_id'] + '|' + [string]$row['level']; $new[$key] = $row; if (-not $keys.Contains($key)) { $keys.Add($key) } }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($key in @($keys.ToArray() | Sort-Object)) {
        $template = $(if ($new.ContainsKey($key)) { $new[$key] } else { $old[$key] })
        $a = $(if ($old.ContainsKey($key)) { [int64]$old[$key]['count'] } else { [int64]0 })
        $b = $(if ($new.ContainsKey($key)) { [int64]$new[$key]['count'] } else { [int64]0 })
        $gap = $(if ($b -lt $a) { 6 } else { 0 })
        $out.Add([ordered]@{
                channel = $template['channel']; provider_name = $template['provider_name']; event_id = $template['event_id']; level = $template['level']
                before = $a; after = $b; delta = $(if ($gap -eq 0) { $b - $a } else { $null }); gap_code = $gap
            })
    }
    return , $out.ToArray()
}

function Compare-SessionBracketConfig {
    # Each configuration value as read at the baseline and after: present,
    # type and bytes, and whether they are the same.
    param([object[]]$Before, [object[]]$After)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $index = @{}
    foreach ($key in $Before) { foreach ($value in @($key['values'])) { $index[[string]$key['path'] + '|' + [string]$value['name']] = @{ Key = $key; Value = $value } } }
    foreach ($key in $After) {
        foreach ($value in @($key['values'])) {
            $id = [string]$key['path'] + '|' + [string]$value['name']
            $old = $null
            if ($index.ContainsKey($id)) { $old = $index[$id] }
            $describe = {
                param($k, $v)
                if ($null -eq $k) { return 'not read' }
                if ($k['error_kind']) { return ('unknown (' + [string]$k['error_kind'] + ')') }
                if (-not $k['exists']) { return 'absent (key absent)' }
                if (-not $v['present']) { return 'absent' }
                return ([string]$v['kind'] + ' ' + [string]$v['bytes_hex'])
            }
            $beforeText = $(if ($null -eq $old) { 'not read' } else { & $describe $old['Key'] $old['Value'] })
            $afterText = & $describe $key $value
            $out.Add([ordered]@{ path = $key['path']; name = $value['name']; before = $beforeText; after = $afterText; same = ($beforeText -eq $afterText) })
        }
    }
    return , $out.ToArray()
}

function ConvertTo-SessionBracketCsvCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text -match '[",\r\n]') { return ('"' + $text.Replace('"', '""') + '"') }
    return $text
}

# session_delta (after phase): the subtraction against the newest baseline.
$invokeSessionDelta = {
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    if (-not $Context.ContainsKey('SessionBracketStatus')) { $Context['SessionBracketStatus'] = @{} }
    $skip = Get-SessionBracketSkipReason -Context $Context
    if ($skip) { return (New-SessionBracketSkippedResult -Source $Source -BundleRoot $BundleRoot -Reason $skip -Log $Log) }
    $id = [string]$Source['Id']
    $entry = New-WfCollectorEntry -Id $id -Kind 'other' -Required $true
    $relativeDir = 'raw/' + $id
    $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir)
    $primaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/process_delta.json')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $entry.command = @('session-bracket', 'session_delta', 'baseline', 'newest in the same folder, same boot')
    try {
        $directory = Split-Path -Parent $BundleRoot
        $plan = [ordered]@{
            baseline_folder = 'the folder that holds this bundle'
            selection = 'the newest bundle of this collector whose boot source recorded phase baseline, whose capture started before this run, and whose boot time was observed; newer baselines without an observed boot time (the game guard stopped them, or the read failed) are passed over and named'
            refuse_when = @('no usable baseline', 'a listed baseline artifact is missing or its SHA-256 differs from the baseline manifest', 'this read has no observed boot time', 'the boot times differ (a reboot between the reads)', 'the baseline or this read has no observed process list')
            process_identity = 'ProcessId plus CreationDate'
            arithmetic = 'decimal subtraction of the cumulative counts; a negative difference is gap 6, never a delta'
            gap_codes = [ordered]@{ '0' = (Get-SessionBracketGapText -Code 0); '1' = (Get-SessionBracketGapText -Code 1); '2' = (Get-SessionBracketGapText -Code 2); '3' = (Get-SessionBracketGapText -Code 3); '4' = (Get-SessionBracketGapText -Code 4); '5' = (Get-SessionBracketGapText -Code 5); '6' = (Get-SessionBracketGapText -Code 6) }
            kept = 'process names and numbers only'
            max_input_bytes = $MaxArtifactBytes
            timeout_seconds = $TimeoutSeconds
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $plan
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $plan }
        $refusal = $null
        $refusalKind = 'not_collected'
        $statuses = $Context['SessionBracketStatus']
        $currentBoot = $null
        if ($statuses['boot'] -eq 'observed') { $currentBoot = Get-SessionBracketBootUtc -BundleRoot $BundleRoot }
        $baseline = $null
        $baseRoot = $null
        $baseBoot = $null
        $passedOver = New-Object 'System.Collections.Generic.List[object]'
        foreach ($candidate in (Get-SessionBracketBaselines -Directory $directory -OwnBundleRoot $BundleRoot -Before $started)) {
            $bootStatus = Get-SessionBracketSourceStatus -Manifest $candidate['Manifest'] -Id 'boot'
            $candidateBoot = $null
            if ($bootStatus -eq 'observed') { $candidateBoot = Get-SessionBracketBootUtc -BundleRoot $candidate['Folder'].FullName }
            if (-not $candidateBoot) {
                $passedOver.Add([ordered]@{ bundle_id = [string]$candidate['Manifest']['bundle_id']; folder = $candidate['Name']; reason = ('no observed boot time (boot ' + [string]$bootStatus + ')') })
                continue
            }
            $baseline = $candidate
            $baseRoot = $candidate['Folder'].FullName
            $baseBoot = $candidateBoot
            break
        }
        if ($null -eq $baseline) {
            $refusal = ('no usable baseline bundle of this collector was found in the baseline folder before this run ({0} passed over without an observed boot time), so nothing is subtracted' -f $passedOver.Count)
        } else {
            $label = [string]$baseline['Manifest']['bundle_id']
            $altered = Test-SessionBracketBaselineIntact -BundleRoot $baseRoot -Manifest $baseline['Manifest']
            $baseProcess = Get-SessionBracketSourceStatus -Manifest $baseline['Manifest'] -Id 'process_io'
            if ($altered) {
                $refusal = 'the newest baseline (' + $label + ') no longer matches its manifest: ' + $altered
                $refusalKind = 'capture_failed'
            } elseif (-not $currentBoot) {
                $refusal = 'this read holds no observed boot time (boot ' + [string]$statuses['boot'] + '), so it cannot be placed in a boot and nothing is subtracted'
            } elseif ($baseBoot -ne $currentBoot) {
                $refusal = ('the newest baseline ({0}) was taken in another boot (last boot {1}, now {2}); the counters restart at boot, so nothing is subtracted across a reboot' -f $label, $baseBoot, $currentBoot)
            } elseif ($baseProcess -ne 'observed') {
                $refusal = 'the newest baseline (' + $label + ') holds no observed process list (process_io ' + [string]$baseProcess + '), so nothing is subtracted'
            } elseif ($statuses['process_io'] -ne 'observed') {
                $refusal = 'this read holds no observed process list (process_io ' + [string]$statuses['process_io'] + '), so nothing is subtracted'
            } else {
                foreach ($inputFile in @('raw/process_io/records.json', 'raw/disk_totals/records.json', 'raw/memory_paging/records.json', 'raw/config_readback/keys.json', 'raw/event_counts/counts.json')) {
                    $path = Join-WfBundlePath -BundleRoot $baseRoot -RelativePath $inputFile
                    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt $MaxArtifactBytes) {
                        $refusal = ('the newest baseline ({0}) holds {1} above the {2} byte cap, so it is not read' -f $label, $inputFile, $MaxArtifactBytes)
                        $refusalKind = 'capture_failed'
                        break
                    }
                }
            }
        }
        $result = [ordered]@{
            baseline_bundle_id = $(if ($null -ne $baseline) { [string]$baseline['Manifest']['bundle_id'] } else { $null })
            baseline_boot_utc  = $baseBoot
            boot_utc           = $currentBoot
            passed_over        = @($passedOver.ToArray())
            refused            = $refusal
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/selection.json')) -Object $result
        $entry.preflight = [ordered]@{
            ok     = ($null -eq $refusal)
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @(
                [ordered]@{ name = 'baseline_found'; ok = ($null -ne $baseline); detail = $(if ($null -ne $baseline) { [string]$baseline['Manifest']['bundle_id'] } else { 'none' }) },
                [ordered]@{ name = 'same_boot'; ok = ($null -ne $baseBoot -and $baseBoot -eq $currentBoot); detail = ('baseline ' + [string]$baseBoot + ', now ' + [string]$currentBoot) }
            )
        }
        if ($refusal) {
            $Notes.Add('session_delta: ' + $refusal)
            $entry.status = $refusalKind
            $entry.status_reason = $refusal
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $false; detail = $refusal }
            Write-WfStderrLine -Text ('session-bracket: no delta: ' + $refusal)
        } else {
            $beforeRows = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $baseRoot -RelativePath 'raw/process_io/records.json') -Array
            $afterRows = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'raw/process_io/records.json') -Array
            $processRows = Compare-SessionBracketProcesses -Before $beforeRows -After $afterRows
            $system = [ordered]@{
                baseline_bundle_id = [string]$baseline['Manifest']['bundle_id']
                baseline_folder    = $baseline['Folder'].Name
                baseline_start_utc = [string]$baseline['Manifest']['capture']['start_utc']
                after_start_utc    = ConvertTo-WfUtcString -Value $started
                boot_utc           = $currentBoot
                disks              = $null
                memory             = $null
                events             = $null
                config             = $null
                passed_over        = @($passedOver.ToArray())
                not_compared       = [ordered]@{}
            }
            $pairs = @(
                @{ Id = 'disk_totals'; Field = 'disks'; Counters = @('DiskWriteBytesPersec', 'DiskWritesPersec', 'DiskReadBytesPersec', 'DiskReadsPersec') },
                @{ Id = 'memory_paging'; Field = 'memory'; Counters = @('PagesOutputPersec', 'PageWritesPersec', 'PagesInputPersec', 'PageReadsPersec') }
            )
            foreach ($pair in $pairs) {
                $a = Get-SessionBracketSourceStatus -Manifest $baseline['Manifest'] -Id $pair['Id']
                $b = $statuses[$pair['Id']]
                if ($a -ne 'observed' -or $b -ne 'observed') { $system.not_compared[$pair['Id']] = ('baseline ' + [string]$a + ', after ' + [string]$b); continue }
                $old = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $baseRoot -RelativePath ('raw/' + $pair['Id'] + '/records.json')) -Array
                $new = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $pair['Id'] + '/records.json')) -Array
                $system[$pair['Field']] = Compare-SessionBracketInstances -Before $old -After $new -Counters $pair['Counters']
            }
            $a = Get-SessionBracketSourceStatus -Manifest $baseline['Manifest'] -Id 'event_counts'
            $b = $statuses['event_counts']
            if ((Test-WfObservedStatus -Status $a) -and (Test-WfObservedStatus -Status $b)) {
                $old = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $baseRoot -RelativePath 'raw/event_counts/counts.json') -Array
                $new = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'raw/event_counts/counts.json') -Array
                $system.events = Compare-SessionBracketEventCounts -Before $old -After $new
            } else { $system.not_compared['event_counts'] = ('baseline ' + [string]$a + ', after ' + [string]$b) }
            $a = Get-SessionBracketSourceStatus -Manifest $baseline['Manifest'] -Id 'config_readback'
            $b = $statuses['config_readback']
            if ($a -eq 'observed' -and $b -eq 'observed') {
                $old = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $baseRoot -RelativePath 'raw/config_readback/keys.json') -Array
                $new = Read-SessionBracketJson -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'raw/config_readback/keys.json') -Array
                $system.config = Compare-SessionBracketConfig -Before $old -After $new
            } else { $system.not_compared['config_readback'] = ('baseline ' + [string]$a + ', after ' + [string]$b) }

            # Largest writer first; rows without a delta after them, by gap.
            $ordered = @($processRows | Sort-Object -Property @{ Expression = { if ($null -eq $_['delta_write_bytes']) { [int64]-1 } else { [int64]$_['delta_write_bytes'] } }; Descending = $true }, @{ Expression = { [int]$_['gap_code'] } }, @{ Expression = { [string]$_['name'] } })
            Write-WfJsonLinesFile -Path $primaryPath -Lines @($ordered | ForEach-Object { ConvertTo-WfJson -Value $_ })
            Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/system_delta.json')) -Object $system
            $csv = New-Object 'System.Collections.Generic.List[string]'
            $csv.Add('name,process_id,before_start_utc,after_start_utc,delta_write_bytes,delta_write_operations,gap_code')
            foreach ($row in $ordered) {
                $csv.Add((@($row['name'], $row['process_id'], $row['before_start_utc'], $row['after_start_utc'], $row['delta_write_bytes'], $row['delta_write_operations'], $row['gap_code']) | ForEach-Object { ConvertTo-SessionBracketCsvCell -Value $_ }) -join ',')
            }
            Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/delta.csv')) -Text (($csv.ToArray() -join "`n") + "`n")
            # The table for whoever ran the read, on stderr: stdout carries
            # the summary line alone. Names and numbers only.
            Write-WfStderrLine -Text ('session-bracket: write I/O per process since baseline ' + [string]$baseline['Manifest']['bundle_id'] + ' (file, network and device writes, not disk bytes)')
            Write-WfStderrLine -Text ('{0,-40} {1,8} {2,14} {3,12} {4}' -f 'name', 'pid', 'write MiB', 'write ops', 'gap')
            foreach ($row in $ordered) {
                if ($row['gap_code'] -eq 0 -and [int64]$row['delta_write_bytes'] -eq 0 -and [int64]$row['delta_write_operations'] -eq 0) { continue }
                $mib = $(if ($null -eq $row['delta_write_bytes']) { '' } else { ([math]::Round([double]$row['delta_write_bytes'] / 1048576, 3)).ToString([System.Globalization.CultureInfo]::InvariantCulture) })
                Write-WfStderrLine -Text ('{0,-40} {1,8} {2,14} {3,12} {4}' -f [string]$row['name'], [string]$row['process_id'], $mib, [string]$row['delta_write_operations'], [string]$row['gap_code'])
            }
            $gaps = @($processRows | Where-Object { [int]$_['gap_code'] -ne 0 }).Count
            $entry.status = 'observed'
            $entry.status_reason = $null
            $entry.raw_time_range = New-WfTimeRange -StartUtc (ConvertFrom-WfUtcString -Text ([string]$baseline['Manifest']['capture']['start_utc'])) -EndUtc $started
            $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $true; detail = ('{0} process rows, {1} with a gap code; baseline {2}, same boot {3}' -f @($processRows).Count, $gaps, [string]$baseline['Manifest']['bundle_id'], $currentBoot) }
            $entry.enabled = [ordered]@{
                providers = @(); keywords = @(); stack_walk = @(); counters = @()
                options = [ordered]@{ baseline_bundle_id = [string]$baseline['Manifest']['bundle_id']; baseline_verified = $true; same_boot = $true; process_rows = @($processRows).Count; rows_with_gap = $gaps; baselines_passed_over = $passedOver.Count; not_compared = $system.not_compared }
                verified_by = 'the baseline artifacts match the SHA-256 in its manifest, both boot times are the same observed LastBootUpTime, and both process lists are observed'
            }
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while computing the delta: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $primaryPath) { Remove-Item -LiteralPath $primaryPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles @{ 'query.json' = 'config'; 'selection.json' = 'report'; 'process_delta.json' = 'primary'; 'system_delta.json' = 'report'; 'delta.csv' = 'report' }
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# Where the bundle goes. The logon task has no dispatcher to name a folder,
# so -ToEvidenceFolder resolves the Desktop through the documented special
# folder and makes a fresh, time stamped folder under latency-evidence. The
# collector then works from inside latency-evidence and names the bundle by
# its folder name alone, so the summary line and the log never carry the
# profile path the Desktop sits under.
$bundleTarget = $OutputDirectory
$sidecar = $null
$evidence = $null
if ($ToEvidenceFolder) {
    try {
        $desktop = Get-WfKnownFolderPath -Name 'Desktop'
        $evidence = Join-Path -Path $desktop -ChildPath 'latency-evidence'
        if (-not (Test-Path -LiteralPath $evidence)) { $null = New-Item -ItemType Directory -Path $evidence }
        $stamp = ConvertTo-WfCompactUtc -Value (Get-WfUtcNow)
        $bundleTarget = 'session-' + $Phase + '-' + $stamp
        $sidecar = Join-Path -Path $evidence -ChildPath ($bundleTarget + '.sha256')
    } catch {
        Write-WfStderrLine -Text ($collectorName + ': the evidence folder could not be resolved: ' + $_.Exception.Message)
        Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle '' -Artifacts 0)
        exit 1
    }
}

$names = @($GameProcessNames | Where-Object { $_ } | ForEach-Object { [string]$_ })
$guardNote = 'game guard: ' + ($names -join ', ')
$tdrCitation = 'https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys'
$dumpCitation = 'https://learn.microsoft.com/troubleshoot/windows-server/performance/memory-dump-file-options'
$werCitation = 'https://learn.microsoft.com/windows/win32/wer/wer-settings'
$werPolicyCitation = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting'
$pcHealthCitation = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-icm'
$werValues = @('Disabled', 'ForceQueue', 'DontSendAdditionalData', 'DontShowUI', 'LoggingDisabled')

$sources = @(
    @{
        Id          = 'game_guard'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeGameGuard
        GameNames   = $names
        MaxRecords  = $MaxEvents
        Expectation = 'the whole process list is read (image names only) and none of the game process names is running; a running game, or a list that could not be read, stops every other source'
    },
    @{
        Id          = 'boot'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Phase       = $Phase
        Reads       = 'Win32_OperatingSystem LastBootUpTime'
        Expectation = 'the one operating system instance and its last boot time'
        Inner       = @{
            Id = 'boot'; Type = 'cim'; Kind = 'config_snapshot'; Required = $true; ClassName = 'Win32_OperatingSystem'
            Properties = @('LastBootUpTime'); Options = [ordered]@{ phase = $Phase; collector = $collectorName }
        }
    },
    @{
        Id          = 'process_io'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Reads       = 'Win32_Process Name, ProcessId, CreationDate, WriteTransferCount, WriteOperationCount'
        Expectation = 'the class returns at least one instance'
        Inner       = @{
            Id = 'process_io'; Type = 'cim'; Kind = 'process_inventory'; Required = $true; ClassName = 'Win32_Process'
            Properties = @('Name', 'ProcessId', 'CreationDate', 'WriteTransferCount', 'WriteOperationCount')
            Options = [ordered]@{ phase = $Phase; command_line_requested = $false; image_path_requested = $false; meaning = 'write I/O counts file, network and device writes since the process started, never physical disk bytes' }
        }
    },
    @{
        Id          = 'disk_totals'
        Type        = 'script'
        Required    = $false
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Reads       = 'Win32_PerfRawData_PerfDisk_PhysicalDisk raw cumulative bytes and operations'
        Expectation = 'the class returns at least one instance'
        Inner       = @{
            Id = 'disk_totals'; Type = 'cim'; Kind = 'other'; Required = $false; ClassName = 'Win32_PerfRawData_PerfDisk_PhysicalDisk'
            Properties = @('Name', 'DiskWriteBytesPersec', 'DiskWritesPersec', 'DiskReadBytesPersec', 'DiskReadsPersec', 'Timestamp_Sys100NS', 'Frequency_Sys100NS')
            Options = [ordered]@{ phase = $Phase; meaning = 'raw values of cumulative count counters: the totals since the counters started, not rates' }
        }
    },
    @{
        Id          = 'memory_paging'
        Type        = 'script'
        Required    = $false
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Reads       = 'Win32_PerfRawData_PerfOS_Memory raw cumulative page counts'
        Expectation = 'the class returns at least one instance'
        Inner       = @{
            Id = 'memory_paging'; Type = 'cim'; Kind = 'other'; Required = $false; ClassName = 'Win32_PerfRawData_PerfOS_Memory'
            Properties = @('Name', 'PagesOutputPersec', 'PageWritesPersec', 'PagesInputPersec', 'PageReadsPersec', 'Timestamp_Sys100NS', 'Frequency_Sys100NS')
            Options = [ordered]@{ phase = $Phase; meaning = 'raw values of cumulative count counters: pages written to and read from disk to resolve page faults since the counters started' }
        }
    },
    @{
        Id          = 'config_readback'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Reads       = 'the TDR, crash dump and Windows Error Reporting values'
        Expectation = 'each key is opened for reading and each named value is recorded present (with type and bytes) or absent'
        Inner       = @{
            Id = 'config_readback'; Type = 'registry'; Mode = 'keys'; Kind = 'config_snapshot'; Required = $true
            Keys = @(
                @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'; Values = @('TdrLevel', 'TdrDelay'); Citation = $tdrCitation },
                @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'; Values = @('CrashDumpEnabled', 'LogEvent', 'AutoReboot'); Citation = $dumpCitation },
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'; Values = @('Disabled', 'DontSendAdditionalData', 'LoggingDisabled', 'DontShowUI'); Citation = $werPolicyCitation },
                @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'; Values = $werValues; Citation = $werCitation },
                @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'; Values = $werValues; Citation = $werCitation },
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting'; Values = @('DoReport'); Citation = $pcHealthCitation }
            )
            Citations = @($tdrCitation, $dumpCitation, $werCitation, $werPolicyCitation, $pcHealthCitation)
            Expectation = 'each key is opened for reading and each named value is recorded present (with type and bytes) or absent'
        }
    },
    @{
        Id          = 'power_active_scheme'
        Type        = 'script'
        Required    = $false
        Invoke      = $invokeGuarded
        MaxRecords  = $MaxEvents
        Reads       = 'powercfg /getactivescheme'
        Expectation = 'powercfg exits with code 0 and prints at least one line with a GUID'
        Inner       = @{
            Id = 'power_active_scheme'; Type = 'command'; Kind = 'powercfg'; Required = $false; Tool = 'powercfg'; Arguments = '/getactivescheme'
            Protect = 'generic'; Records = 'guid_lines'; ZeroRule = 'capture_failed'
            ZeroReason = 'powercfg exited with code 0 and printed no line with a GUID; the active scheme line carries one, so this output is not the listing asked for'
            RecordsMeaning = 'lines carrying a GUID (the active scheme)'; Expectation = 'powercfg exits with code 0 and prints at least one line with a GUID'
        }
    },
    @{
        Id          = 'event_counts'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeEventCounts
        MaxRecords  = $MaxEvents
        Channels    = @('System', 'Application')
        Reads       = 'System and Application since boot, counted by provider, event id and level'
        Expectation = 'every record of each channel since boot is read within the deadline and the cap, and each channel still holds a record at or before the boot'
    }
)
if ($Phase -eq 'after') {
    $sources += @{
        Id          = 'session_delta'
        Type        = 'script'
        Required    = $true
        Invoke      = $invokeSessionDelta
        Reads       = 'the newest baseline bundle of the same boot'
        Expectation = 'the newest baseline is intact and from the same boot, both process lists are observed, and every process row has a delta or a gap code'
    }
}

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = ('What did the machine and each running process do between the baseline read and the read after a play session, within one boot ({0} phase; {1})?' -f $Phase, $guardNote)
    Sources  = $sources
}

if ($null -ne $evidence) { Push-Location -LiteralPath $evidence }
try {
    $exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $bundleTarget -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
} finally {
    if ($null -ne $evidence) { Pop-Location }
}
if ($null -ne $sidecar) {
    $bundleTarget = Join-Path -Path $evidence -ChildPath $bundleTarget
    # The SHA-256 of the manifest next to the bundle; the manifest holds the
    # SHA-256 of every artifact, so this one line pins the whole bundle.
    $manifestPath = Join-Path -Path $bundleTarget -ChildPath 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            Write-WfTextFile -Path $sidecar -Text ((Get-WfSha256OfFile -Path $manifestPath) + '  ' + (Split-Path -Leaf $bundleTarget) + '/manifest.json' + "`n")
        } catch {
            Write-WfStderrLine -Text ($collectorName + ': the manifest hash file could not be written: ' + $_.Exception.Message)
        }
    }
}
exit $exitCode
