# Synthetic replacements for the Windows adapters in ../_common.ps1.
#
# Dot source ../_common.ps1 first, then this file, then run a collector: the
# helper's load once guard keeps these definitions in place. Everything here
# is invented. No value comes from a real machine, and the tests and the
# committed fixture bundles are built only from these values.
#
# The scenario lives in $global:WfSynthetic:
#   Now        first value of the clock; every Get-WfUtcNow call adds a second
#   Channels   channel name -> state map (see New-WfSyntheticChannelState)
#   Queries    list of @{ Match = <text found in the query XML>; Events = <list>;
#              ErrorKind = <optional>; ErrorMessage = <optional>; Truncated = <optional> }
#   Cim        class name -> @{ Rows = <list> } or @{ ErrorKind; ErrorMessage }
#   Providers  registered provider names, or $null when the list is unreadable
#   Evtx       'unavailable' (default) or 'placeholder' (writes a small file)
#   Stdout     list that receives what a collector prints on stdout
#   Stderr     list that receives what a collector prints on stderr

function Reset-WfSynthetic {
    param([datetime]$Now = ([datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc)))
    $global:WfSynthetic = @{
        Now       = $Now
        Ticks     = 0
        Channels  = @{}
        Queries   = New-Object 'System.Collections.Generic.List[object]'
        Cim       = @{}
        Providers = @('Microsoft-Windows-WHEA-Logger', 'Application Error', 'Application Hang', 'Windows Error Reporting', '.NET Runtime', 'Display')
        Evtx      = 'unavailable'
        Stdout    = New-Object 'System.Collections.Generic.List[string]'
        Stderr    = New-Object 'System.Collections.Generic.List[string]'
    }
}

function New-WfSyntheticChannelState {
    # OldestDaysAgo $null means the channel holds no records at all.
    param($OldestDaysAgo = 90, [int64]$RecordCount = 1000, [bool]$Found = $true, [bool]$Readable = $true, $ErrorKind = $null, $ErrorMessage = $null)
    $oldest = $null
    if ($Found -and $Readable -and $null -ne $OldestDaysAgo) { $oldest = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-1 * $OldestDaysAgo) }
    if ($null -eq $OldestDaysAgo) { $RecordCount = 0 }
    return [ordered]@{
        found = $Found; readable = $Readable; error = $ErrorMessage; error_kind = $ErrorKind
        record_count = $(if ($Readable) { $RecordCount } else { $null })
        oldest_record_number = $(if ($null -ne $oldest) { 1 } else { $null })
        oldest_record_time_utc = $oldest
        file_size_bytes = $(if ($Readable) { 1052672 } else { $null })
        is_log_full = $(if ($Readable) { $false } else { $null })
        last_write_time_utc = $null
        is_enabled = $(if ($Readable) { $true } else { $null })
        log_mode = $(if ($Readable) { 'Circular' } else { $null })
        maximum_size_bytes = $(if ($Readable) { 20971520 } else { $null })
        isolation = $(if ($Readable) { 'System' } else { $null })
        # The default System log descriptor as Microsoft documents it:
        # https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
        security_descriptor = $(if ($Readable) { 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x5;;;SO)(A;;0x1;;;IU)(A;;0x3;;;SU)(A;;0x1;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)' } else { $null })
        configuration_error = $null
    }
}

function New-WfSyntheticEvent {
    # One element of events.json, with event XML that agrees with the fields.
    param(
        [int64]$RecordId, [string]$Channel = 'System', [string]$Provider, [int]$EventId, [int]$Level = 2,
        [double]$DaysAgo, [object[]]$Properties = @(), $Message = $null, [string]$LevelDisplay = 'Error'
    )
    $when = $global:WfSynthetic.Now.AddDays(-1 * $DaysAgo)
    $time = ConvertTo-WfUtcString -Value $when
    $data = New-Object 'System.Collections.Generic.List[string]'
    foreach ($value in $Properties) { $data.Add('<Data>' + [System.Security.SecurityElement]::Escape([string]$value) + '</Data>') }
    $xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{0}'/><EventID>{1}</EventID>" +
        "<Version>0</Version><Level>{2}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords>" +
        "<TimeCreated SystemTime='{3}'/><EventRecordID>{4}</EventRecordID><Execution ProcessID='4' ThreadID='8'/>" +
        "<Channel>{5}</Channel><Computer>SYNTHETIC-PC</Computer><Security UserID='S-1-5-18'/></System><EventData>{6}</EventData></Event>") -f
        [System.Security.SecurityElement]::Escape($Provider), $EventId, $Level, $time, $RecordId, $Channel, ($data.ToArray() -join '')
    return [ordered]@{
        record_id = $RecordId; log_name = $Channel; provider_name = $Provider; event_id = $EventId; version = 0
        level = $Level; level_display = $LevelDisplay; task = 0; task_display = $null; opcode = 0
        keywords = 36028797018963968; time_created_utc = $time; machine_name = 'SYNTHETIC-PC'; user_id = 'S-1-5-18'
        process_id = 4; thread_id = 8; message = $Message
        properties = @($Properties | ForEach-Object { ConvertTo-WfScalar -Value $_ }); xml = $xml
    }
}

function Add-WfSyntheticQuery {
    param([string]$Match, $Events = @(), $ErrorKind = $null, $ErrorMessage = $null, [bool]$Truncated = $false)
    $global:WfSynthetic.Queries.Add(@{ Match = $Match; Events = @($Events); ErrorKind = $ErrorKind; ErrorMessage = $ErrorMessage; Truncated = $Truncated })
}

# --- adapter replacements ---------------------------------------------------

function Get-WfUtcNow {
    $global:WfSynthetic.Ticks += 1
    return $global:WfSynthetic.Now.AddSeconds($global:WfSynthetic.Ticks)
}

function Write-WfStdoutLine {
    param([string]$Text)
    $global:WfSynthetic.Stdout.Add($Text)
}

function Write-WfStderrLine {
    param([string]$Text)
    $global:WfSynthetic.Stderr.Add($Text)
}

function Get-WfMachineInfo {
    $ids = Get-WfShortMachineId -Seed 'synthetic-machine'
    return [ordered]@{
        machine_id_short = $ids['short']
        qpc_frequency_hz = 10000000
        boot_time_utc    = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-2)
        machine          = [ordered]@{
            machine_id   = $ids['machine_id']
            hostname     = 'SYNTHETIC-PC'
            os           = [ordered]@{ caption = 'Microsoft Windows 11 Pro'; version = '10.0.26100'; build = 26100; ubr = 1; display_version = '24H2'; architecture = '64-bit'; edition = 'Professional' }
            cpu          = [ordered]@{ name = 'Synthetic CPU'; logical_processors = 16; qpc_frequency_hz = 10000000 }
            memory_bytes = 34359738368
            gpus         = @([ordered]@{ name = 'Synthetic Display Adapter'; driver_version = '1.2.3.4'; driver_date = '2026-01-15T00:00:00.0000000Z'; device_id = 'PCI\VEN_FFFF&DEV_0001' })
            bios         = [ordered]@{ vendor = 'Synthetic Firmware'; version = 'S1.00'; release_date = '2025-11-01T00:00:00.0000000Z' }
            board        = [ordered]@{ manufacturer = 'Synthetic Boards'; product = 'SB-1' }
            drivers      = @()
            time_zone    = [ordered]@{ name = 'UTC'; utc_offset_minutes = 0; dst_active = $false }
        }
    }
}

function Get-WfAccountInfo {
    return [ordered]@{ name = 'SYNTHETIC-PC\wf-collector'; elevated = $false; event_log_readers = $true }
}

function Get-WfToolInventory {
    param([string]$CollectorName, [string]$CollectorVersion, [string]$CollectorPath)
    # Hashes are null so that the committed fixtures do not change every time
    # a script is edited; the real inventory is covered by its own test.
    $tools = @(
        [ordered]@{ name = 'powershell'; version = '5.1.26100.1'; path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; sha256 = $null },
        [ordered]@{ name = 'wevtutil'; version = $null; path = 'C:\Windows\System32\wevtutil.exe'; sha256 = $null },
        [ordered]@{ name = ('collector:' + $CollectorName); version = $CollectorVersion; path = ('<install directory>\' + $CollectorName + '.ps1'); sha256 = $null },
        [ordered]@{ name = 'collector-helper:_common.ps1'; version = (Get-WfCollectorsVersion); path = '<install directory>\_common.ps1'; sha256 = $null }
    )
    return , $tools
}

function Get-WfChannelState {
    param([string]$Channel)
    if ($global:WfSynthetic.Channels.ContainsKey($Channel)) { return $global:WfSynthetic.Channels[$Channel] }
    return (New-WfSyntheticChannelState -Found $false -Readable $false -ErrorKind 'not_found' -ErrorMessage ('synthetic backend: no channel named ' + $Channel))
}

function Get-WfRegisteredProviderNames {
    if ($null -eq $global:WfSynthetic.Providers) { return $null }
    return , @($global:WfSynthetic.Providers)
}

function Read-WfEventRecords {
    param([string]$Channel, [string]$QueryXml, [int]$MaxEvents, [int64]$MaxBytes)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Events = @(); Truncated = $false }
    foreach ($query in $global:WfSynthetic.Queries) {
        if (-not $QueryXml.Contains([string]$query['Match'])) { continue }
        if ($query['ErrorKind']) {
            $result.ErrorKind = $query['ErrorKind']
            $result.ErrorMessage = $query['ErrorMessage']
            return $result
        }
        # Newest first, like the real reader, and cut at the cap.
        $events = @(@($query['Events']) | Sort-Object -Property { $_['time_created_utc'] } -Descending)
        if ($events.Count -gt $MaxEvents) {
            $events = @($events | Select-Object -First $MaxEvents)
            $result.Truncated = $true
        }
        if ($query['Truncated']) { $result.Truncated = $true }
        $result.Ok = $true
        $result.Events = $events
        return $result
    }
    $result.Ok = $true
    return $result
}

function Export-WfEvtx {
    param([string]$QueryPath, [string]$TargetPath, [int64]$MaxBytes, [int]$TimeoutSeconds = 300)
    if ($global:WfSynthetic.Evtx -eq 'placeholder') {
        Write-WfTextFile -Path $TargetPath -Text 'synthetic placeholder, not an event log file'
        return [ordered]@{ Attempted = $true; Ok = $true; ExitCode = 0; Message = 'exported'; Command = @('wevtutil.exe', 'epl', 'query.xml', 'events.evtx', '/sq:true', '/ow:true') }
    }
    return [ordered]@{ Attempted = $true; Ok = $false; ExitCode = $null; Message = 'synthetic backend: wevtutil does not exist off Windows'; Command = $null }
}

function Get-WfCimRows {
    param([string]$Namespace, [string]$ClassName)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Rows = @() }
    if (-not $global:WfSynthetic.Cim.ContainsKey($ClassName)) {
        $result.ErrorKind = 'not_found'
        $result.ErrorMessage = 'synthetic backend: no class named ' + $ClassName
        return $result
    }
    $entry = $global:WfSynthetic.Cim[$ClassName]
    if ($entry['ErrorKind']) {
        $result.ErrorKind = $entry['ErrorKind']
        $result.ErrorMessage = $entry['ErrorMessage']
        return $result
    }
    $result.Ok = $true
    $result.Rows = @($entry['Rows'])
    return $result
}
