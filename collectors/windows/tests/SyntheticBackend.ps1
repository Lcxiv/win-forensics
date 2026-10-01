# Synthetic replacements for the Windows adapters in ../_common.ps1.
#
# Dot source ../_common.ps1 first, then this file, then run a collector: the
# helper's load once guard keeps these definitions in place. Everything here
# is invented. No value comes from a real machine, and the tests and the
# committed fixture bundles are built only from these values.
#
# Only the adapters are replaced: the reader that opens a channel
# (Open-WfEventReader), the channel configuration, the WMI producer, the
# error classifiers, the machine and tool inventories, the clock, and the
# two output streams. The bounded read loops, the caps, the status rules
# and the bundle writing run as they will on Windows.
#
# The scenario lives in $global:WfSynthetic:
#   Now        first value of the clock; every Get-WfUtcNow call adds a second
#   Channels   channel name -> New-WfSyntheticChannelState result
#   Queries    list of @{ Match = <text found in the query XML>; Events = <list>;
#              Throws = <message, the read fails after opening>;
#              Stuck = $true (the reader never returns a record before the deadline);
#              ConvertThrows = <message, every record fails to convert> }
#   Cim        class name -> @{ Rows = <list> } or @{ ErrorKind; ErrorMessage }
#              or @{ Rows; Stuck = $true } (the provider does not answer before the timeout)
#              or @{ Rows; Infinite = $true } (the provider never stops producing)
#              or @{ Rows; SecondsPerRow = <n> } (every row arrives, each n seconds after the last)
#   Providers  registered provider names, or $null when the list is unreadable
#   Evtx       'unavailable' (default) or 'placeholder' (writes a small file)
#   Commands   netsh argument string -> @{ ExitCode; StdOut; StdErr } or @{ Stuck = $true }
#              (the process never finishes); a missing key exits 1 with a message
#   NetshPresent  $false makes the netsh preflight fail
#   Files      full path -> @{ Text = <string> } or @{ ErrorKind; ErrorMessage }
#   Pnp        @{ Devices = <list of device maps, each may carry Properties = @{ DEVPKEY -> value } > }
#              or @{ ErrorKind; ErrorMessage }
#   Salt       the pseudonym salt (fixed, so fixtures are reproducible)
#   Stdout     list that receives what a collector prints on stdout
#   Stderr     list that receives what a collector prints on stderr

function Reset-WfSynthetic {
    param([datetime]$Now = ([datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc)))
    $global:WfSynthetic = @{
        Now          = $Now
        Ticks        = 0
        Channels     = @{}
        Queries      = New-Object 'System.Collections.Generic.List[object]'
        Cim          = @{}
        Providers    = @('Microsoft-Windows-WHEA-Logger', 'Application Error', 'Application Hang', 'Windows Error Reporting', '.NET Runtime', 'Display', 'Microsoft-Windows-WLAN-AutoConfig')
        Evtx         = 'unavailable'
        Commands     = @{}
        NetshPresent = $true
        Files        = @{}
        Pnp          = @{ Devices = @() }
        Processes    = New-Object 'System.Collections.Generic.List[object]'
        Salt         = 'synthetic-salt-0001'
        Stdout       = New-Object 'System.Collections.Generic.List[string]'
        Stderr       = New-Object 'System.Collections.Generic.List[string]'
    }
}

function New-WfSyntheticChannelState {
    # OldestDaysAgo $null means the channel holds no records at all.
    # Stuck 'preflight' makes the oldest record probe hang; 'main' is set on
    # the query instead (see Add-WfSyntheticQuery).
    param($OldestDaysAgo = 90, [int64]$RecordCount = 1000, [bool]$Found = $true, [bool]$Readable = $true, $ErrorKind = $null, $ErrorMessage = $null, $Stuck = $null)
    $oldest = $null
    if ($Found -and $Readable -and $null -ne $OldestDaysAgo) {
        $oldest = New-WfSyntheticEvent -RecordId 1 -Provider 'EventLog' -EventId 6009 -Level 4 -LevelDisplay 'Information' -DaysAgo $OldestDaysAgo -Properties @('oldest retained record') -Message 'oldest retained record'
    }
    if ($null -eq $OldestDaysAgo) { $RecordCount = 0 }
    $configuration = [ordered]@{
        record_count = $(if ($Readable) { $RecordCount } else { $null })
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
        configuration_error = $(if ($Readable) { $null } else { 'synthetic backend: configuration is not readable' })
    }
    return @{ Found = $Found; Readable = $Readable; ErrorKind = $ErrorKind; ErrorMessage = $ErrorMessage; Oldest = $oldest; Stuck = $Stuck; Configuration = $configuration }
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
    param([string]$Match, $Events = @(), $Throws = $null, [bool]$Stuck = $false, $ConvertThrows = $null)
    $global:WfSynthetic.Queries.Add(@{ Match = $Match; Events = @($Events); Throws = $Throws; Stuck = $Stuck; ConvertThrows = $ConvertThrows })
}

function ConvertFrom-WfSyntheticDmtf {
    # The DMTF text ConvertTo-WfDmtfDateTime writes, back to a UTC time.
    param([string]$Text)
    return [datetime]::ParseExact($Text.Substring(0, 21), 'yyyyMMddHHmmss.ffffff', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}

function New-WfSyntheticPull {
    # A ReadNext scriptblock over a list, or one that hangs until the deadline.
    param([object[]]$Items, [bool]$Stuck)
    if ($Stuck) {
        return {
            param([timespan]$Remaining)
            $global:WfSynthetic.Ticks += [int][math]::Ceiling($Remaining.TotalSeconds)
            return $null
        }
    }
    $cursor = @{ Index = 0 }
    return {
        param([timespan]$Remaining)
        if ($cursor.Index -ge $Items.Count) { return $null }
        $item = $Items[$cursor.Index]
        $cursor.Index += 1
        return $item
    }.GetNewClosure()
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

function Open-WfEventReader {
    param([string]$Channel, [string]$QueryXml, [bool]$Reverse)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; ReadNext = $null; Convert = $null; Release = $null; Dispose = $null }
    if (-not $global:WfSynthetic.Channels.ContainsKey($Channel)) {
        $result.ErrorKind = 'not_found'
        $result.ErrorMessage = 'synthetic backend: no channel named ' + $Channel
        return $result
    }
    $state = $global:WfSynthetic.Channels[$Channel]
    if (-not $state['Readable']) {
        $result.ErrorKind = $(if ($state['ErrorKind']) { $state['ErrorKind'] } else { 'access_denied' })
        $result.ErrorMessage = $(if ($state['ErrorMessage']) { $state['ErrorMessage'] } else { 'synthetic backend: the channel is not readable' })
        return $result
    }
    $result.Convert = { param($Record) return $Record }
    $result.Dispose = { }
    if ($QueryXml -eq '*') {
        $items = @()
        if ($null -ne $state['Oldest']) { $items = @($state['Oldest']) }
        $result.ReadNext = New-WfSyntheticPull -Items $items -Stuck ($state['Stuck'] -eq 'preflight')
        $result.Ok = $true
        return $result
    }
    foreach ($query in $global:WfSynthetic.Queries) {
        if (-not $QueryXml.Contains([string]$query['Match'])) { continue }
        if ($query['Throws']) {
            $message = [string]$query['Throws']
            $result.ReadNext = { param([timespan]$Remaining) throw $message }.GetNewClosure()
        } else {
            # Newest first, like the real reader in reverse direction.
            $events = @(@($query['Events']) | Sort-Object -Property { $_['time_created_utc'] } -Descending)
            $result.ReadNext = New-WfSyntheticPull -Items $events -Stuck ([bool]$query['Stuck'])
        }
        if ($query['ConvertThrows']) {
            $message = [string]$query['ConvertThrows']
            $result.Convert = { param($Record) throw $message }.GetNewClosure()
        }
        $result.Ok = $true
        return $result
    }
    $result.ReadNext = New-WfSyntheticPull -Items @() -Stuck $false
    $result.Ok = $true
    return $result
}

function Get-WfChannelConfiguration {
    param([string]$Channel)
    if ($global:WfSynthetic.Channels.ContainsKey($Channel)) { return $global:WfSynthetic.Channels[$Channel]['Configuration'] }
    return [ordered]@{ configuration_error = 'synthetic backend: no channel named ' + $Channel }
}

function Get-WfRegisteredProviderNames {
    if ($null -eq $global:WfSynthetic.Providers) { return $null }
    return , @($global:WfSynthetic.Providers)
}

function Export-WfEvtx {
    param([string]$QueryPath, [string]$TargetPath, [int64]$MaxBytes, [int]$TimeoutSeconds = 300)
    if ($global:WfSynthetic.Evtx -eq 'placeholder') {
        Write-WfTextFile -Path $TargetPath -Text 'synthetic placeholder, not an event log file'
        return [ordered]@{ Attempted = $true; Ok = $true; ExitCode = 0; Message = 'exported'; Command = @('wevtutil.exe', 'epl', 'query.xml', 'events.evtx', '/sq:true', '/ow:true') }
    }
    return [ordered]@{ Attempted = $true; Ok = $false; ExitCode = $null; Message = 'synthetic backend: wevtutil does not exist off Windows'; Command = $null }
}

function Get-WfCimErrorKind {
    # The synthetic producer throws messages of the form "synthetic:<kind>: text".
    param($Exception)
    $m = [regex]::Match([string]$Exception.Message, '^synthetic:([a-z_]+):')
    if ($m.Success) { return $m.Groups[1].Value }
    return 'other'
}

function New-WfCimProducer {
    param([string]$Namespace, [string]$ClassName, [string[]]$Properties, $Filter, [double]$TimeoutSeconds)
    $names = @($Properties)
    $convert = {
        param($Row)
        $out = [ordered]@{}
        foreach ($name in $names) { if ($Row.Contains($name)) { $out[$name] = $Row[$name] } else { $out[$name] = $null } }
        return $out
    }.GetNewClosure()
    if (-not $global:WfSynthetic.Cim.ContainsKey($ClassName)) {
        $message = 'synthetic:not_found: no class named ' + $ClassName
        return @{ Producer = { throw $message }.GetNewClosure(); Convert = $convert }
    }
    $entry = $global:WfSynthetic.Cim[$ClassName]
    if ($entry['ErrorKind']) {
        $message = 'synthetic:' + $entry['ErrorKind'] + ': ' + $entry['ErrorMessage']
        return @{ Producer = { throw $message }.GetNewClosure(); Convert = $convert }
    }
    if ($entry['Stuck']) {
        $seconds = $TimeoutSeconds
        return @{ Producer = { $global:WfSynthetic.Ticks += [int][math]::Ceiling($seconds); throw ('synthetic:timeout: the provider did not answer within ' + $seconds + ' seconds') }.GetNewClosure(); Convert = $convert }
    }
    # Emulate the WQL filter the helper builds: a window or a "before" probe.
    $rows = @($entry['Rows'])
    if ($Filter) {
        $window = [regex]::Match([string]$Filter, "^(\w+) >= '([^']+)' AND \1 <= '([^']+)'$")
        $before = [regex]::Match([string]$Filter, "^(\w+) < '([^']+)'$")
        if ($window.Success) {
            $property = $window.Groups[1].Value
            $from = ConvertFrom-WfSyntheticDmtf -Text $window.Groups[2].Value
            $to = ConvertFrom-WfSyntheticDmtf -Text $window.Groups[3].Value
            $rows = @($rows | Where-Object { $_[$property] -and (ConvertFrom-WfUtcString -Text ([string]$_[$property])) -ge $from -and (ConvertFrom-WfUtcString -Text ([string]$_[$property])) -le $to })
        } elseif ($before.Success) {
            $property = $before.Groups[1].Value
            $limit = ConvertFrom-WfSyntheticDmtf -Text $before.Groups[2].Value
            $rows = @($rows | Where-Object { $_[$property] -and (ConvertFrom-WfUtcString -Text ([string]$_[$property])) -lt $limit })
        } elseif ([string]$Filter -match "^(\w+) = '([^']*)'( OR \1 = '([^']*)')*$") {
            # A static equality filter, one property, one or more values joined by OR.
            $property = $null
            $allowed = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($term in ([string]$Filter -split ' OR ')) {
                $m = [regex]::Match($term, "^(\w+) = '([^']*)'$")
                $property = $m.Groups[1].Value
                $null = $allowed.Add($m.Groups[2].Value)
            }
            $rows = @($rows | Where-Object { $allowed.Contains([string]$_[$property]) })
        } else {
            $message = 'synthetic:other: unsupported filter ' + $Filter
            return @{ Producer = { throw $message }.GetNewClosure(); Convert = $convert }
        }
    }
    if ($entry['Infinite']) {
        $template = $rows[0]
        return @{ Producer = { while ($true) { $template } }.GetNewClosure(); Convert = $convert }
    }
    if ($entry['SecondsPerRow']) {
        $step = [int]$entry['SecondsPerRow']
        return @{ Producer = { foreach ($row in $rows) { $global:WfSynthetic.Ticks += $step; $row } }.GetNewClosure(); Convert = $convert }
    }
    return @{ Producer = { foreach ($row in $rows) { $row } }.GetNewClosure(); Convert = $convert }
}

# --- adapters for the command, file and pnp sources --------------------------

function New-WfPseudonymSalt {
    return [string]$global:WfSynthetic.Salt
}

function Get-WfNetshPath {
    return 'C:\Windows\System32\netsh.exe'
}

function Test-WfToolPresent {
    param([string]$Path)
    if ($Path -like '*netsh.exe') { return [bool]$global:WfSynthetic.NetshPresent }
    return $true
}

function Get-WfConsoleOutputEncoding {
    return (New-Object System.Text.UTF8Encoding($false))
}

function Get-WfKnownFolderPath {
    param([string]$Name)
    if ($Name -eq 'ProgramData') { return 'C:\ProgramData' }
    throw ('synthetic backend: unknown folder name ' + $Name)
}

function Invoke-WfProcess {
    # netsh only: the collector never starts anything else through this seam
    # in the test suite (the evtx export has its own replacement above).
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds, $OutputEncoding = $null, [int64]$MaxBytes = 0)
    $result = [ordered]@{ Started = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Oversized = $false; Error = $null; DurationMs = $null; StdOutBytes = [int64]0; StdErrBytes = [int64]0; Diagnostic = $null }
    $global:WfSynthetic.Processes.Add(@{ FilePath = $FilePath; Arguments = $Arguments })
    if ($TimeoutSeconds -lt 1) {
        $result.Error = 'not started: the deadline had passed'
        return $result
    }
    $result.Started = $true
    $result.DurationMs = 7
    if (-not $global:WfSynthetic.Commands.ContainsKey($Arguments)) {
        $result.ExitCode = 1
        $result.StdErr = 'synthetic backend: no output is defined for ' + $FilePath + ' ' + $Arguments
        return $result
    }
    $entry = $global:WfSynthetic.Commands[$Arguments]
    if ($entry['Stuck']) {
        $global:WfSynthetic.Ticks += $TimeoutSeconds
        $result.TimedOut = $true
        $result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
        return $result
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $result.StdOutBytes = [int64]$utf8.GetByteCount([string]$entry['StdOut'])
    $result.StdErrBytes = [int64]$utf8.GetByteCount([string]$entry['StdErr'])
    if ($MaxBytes -gt 0 -and $result.StdOutBytes -gt $MaxBytes) {
        # The real runner stops the child at the cap and keeps a 4096 character head.
        $result.Oversized = $true
        $result.Error = ('the process printed more than the cap of {0} bytes on StdOut and was stopped; nothing above the cap was kept' -f $MaxBytes)
        $head = [string]$entry['StdOut']
        if ($head.Length -gt 4096) { $head = $head.Substring(0, 4096) }
        $result.Diagnostic = 'StdOut: ' + $head
        return $result
    }
    $result.ExitCode = [int]$entry['ExitCode']
    $result.StdOut = [string]$entry['StdOut']
    $result.StdErr = [string]$entry['StdErr']
    return $result
}

function Read-WfFileBytes {
    param([string]$Path, [int64]$MaxBytes)
    $result = [ordered]@{ Exists = $false; Readable = $false; Bytes = $null; Length = $null; LastWriteUtc = $null; ErrorKind = $null; ErrorMessage = $null }
    if (-not $global:WfSynthetic.Files.ContainsKey($Path)) {
        $result.ErrorKind = 'not_found'
        $result.ErrorMessage = 'the file does not exist'
        return $result
    }
    $entry = $global:WfSynthetic.Files[$Path]
    $result.Exists = $true
    if ($entry['ErrorKind']) {
        $result.ErrorKind = [string]$entry['ErrorKind']
        $result.ErrorMessage = [string]$entry['ErrorMessage']
        return $result
    }
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$entry['Text'])
    $result.Length = [int64]$bytes.Length
    $result.LastWriteUtc = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-1)
    if ($result.Length -gt $MaxBytes) {
        $result.ErrorKind = 'too_large'
        $result.ErrorMessage = 'the file is above the cap'
        return $result
    }
    $result.Bytes = $bytes
    $result.Readable = $true
    return $result
}

function Get-WfPnpDevices {
    param([int]$TimeoutSeconds = 60)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Devices = @() }
    $entry = $global:WfSynthetic.Pnp
    if ($entry['ErrorKind']) {
        $result.ErrorKind = [string]$entry['ErrorKind']
        $result.ErrorMessage = [string]$entry['ErrorMessage']
        return $result
    }
    $devices = New-Object 'System.Collections.Generic.List[object]'
    foreach ($device in @($entry['Devices'])) {
        $row = [ordered]@{}
        foreach ($name in @('instance_id', 'class', 'class_guid', 'name', 'description', 'manufacturer', 'service', 'status', 'problem_code', 'present', 'hardware_ids', 'compatible_ids')) {
            if ($device.Contains($name)) { $row[$name] = $device[$name] } else { $row[$name] = $null }
        }
        if ($null -eq $row['hardware_ids']) { $row['hardware_ids'] = @() }
        if ($null -eq $row['compatible_ids']) { $row['compatible_ids'] = @() }
        $devices.Add($row)
    }
    $result.Devices = $devices.ToArray()
    $result.Ok = $true
    return $result
}

function Get-WfPnpDeviceProperties {
    param([string]$InstanceId, [string[]]$KeyNames)
    $result = [ordered]@{ Ok = $false; ErrorMessage = $null; Values = @{} }
    foreach ($device in @($global:WfSynthetic.Pnp['Devices'])) {
        if ([string]$device['instance_id'] -ne $InstanceId) { continue }
        if ($device.Contains('PropertyError')) {
            $result.ErrorMessage = [string]$device['PropertyError']
            return $result
        }
        if ($device.Contains('Properties')) {
            foreach ($key in $KeyNames) { if ($device['Properties'].Contains($key)) { $result.Values[$key] = $device['Properties'][$key] } }
        }
        $result.Ok = $true
        return $result
    }
    $result.ErrorMessage = 'synthetic backend: no device named ' + $InstanceId
    return $result
}
