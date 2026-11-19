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
#              Only the events whose time_created_utc lies inside the query's
#              TimeCreated bound are returned, as the real engine would.
#   Cim        class name -> @{ Rows = <list> } or @{ ErrorKind; ErrorMessage }
#              or @{ Rows; Stuck = $true } (the provider does not answer before the timeout)
#              or @{ Rows; Infinite = $true } (the provider never stops producing)
#              or @{ Rows; SecondsPerRow = <n> } (every row arrives, each n seconds after the last)
#   Providers  registered provider names, or $null when the list is unreadable
#   Evtx       'unavailable' (default) or 'placeholder' (writes a small file)
#   Commands   netsh argument string -> @{ ExitCode; StdOut; StdErr } or @{ Stuck = $true }
#              (the process never finishes); a missing key exits 1 with a message
#   Programs   list of @{ Path = <executable>; Match = <text found in the arguments>;
#              ExitCode; StdOut; StdErr; Stuck; Seconds = <how long the run takes>;
#              OutputFileArgument = <regex with one group capturing a path in the arguments>;
#              OutputText or OutputBytes = <written to that path before the process "exits"> },
#              OnCall = <scriptblock run when the program is started, for a side effect> },
#              for wpr and the PresentMon binary, matched in order after Commands; a run with
#              no match exits 1. An entry may instead carry Responses = <list of such maps>, used
#              in call order with the last repeating. Waited = seconds passed to Wait-WfSeconds, summed
#   Binaries   full path -> @{ Length; Sha256; FileVersion; ProductVersion } for Get-WfBinaryInfo;
#              a missing key is a file that does not exist
#   Account    the values Get-WfAccountInfo returns (elevated, group memberships)
#   NetshPresent  $false makes the netsh preflight fail
#   Files      full path -> @{ Text = <string> } or @{ ErrorKind; ErrorMessage }
#   Pnp        @{ Devices = <list of device maps, each may carry Properties = @{ DEVPKEY -> value } > }
#              or @{ ErrorKind; ErrorMessage }
#   Salt       the pseudonym salt (fixed, so fixtures are reproducible)
#   Elevated   whether the synthetic account is elevated (the live capture needs it)
#   Wpr        the synthetic Windows Performance Recorder (New-WfSyntheticWpr lists the knobs):
#              the default instance's State, one State per -instancename, the idle text, exit
#              codes and hangs per verb, what the status lists (keywords, buffer size, early
#              events lost, a lost buffers line), the bytes of the temporary recording and of
#              the saved trace, and whether a stop or cancel leaves the session running
#   Tracerpt   the synthetic tracerpt: Present, ExitCode, Stuck, EventsLost and BuffersLost of
#              the saved trace, Labels ('english', 'missing' or 'nonnumeric')
#   Tools      full path of an operator supplied tool -> @{ Sha256; Version } (nothing is read
#              from disk, so the fixtures stay reproducible)
#   PinnedTools  tool name -> list of @{ Version; Sha256; Source } the helper reports as pinned
#   Xperf      @{ ExitCode; StdOut; StdErr; Stuck } for the synthetic xperf report
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
        Programs     = New-Object 'System.Collections.Generic.List[object]'
        Binaries     = @{}
        NetshPresent = $true
        Files        = @{}
        Pnp          = @{ Devices = @() }
        Processes    = New-Object 'System.Collections.Generic.List[object]'
        Waited       = 0
        Salt         = 'synthetic-salt-0001'
        Elevated     = $false
        PerformanceLogUsers = $false
        Wpr          = New-WfSyntheticWpr
        Tracerpt     = @{ Present = $true; ExitCode = 0; Stuck = $false; EventsLost = 0; BuffersLost = 0; Labels = 'english' }
        Tools        = @{}
        PinnedTools  = @{}
        Xperf        = @{ ExitCode = 0; StdOut = ''; StdErr = ''; Stuck = $false }
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

function Test-WfSyntheticNumericTimediff {
    # True when the query carries timediff(@SystemTime, <number>), the form the
    # gaming PC rejected at the first read.
    param([string]$QueryXml)
    return [bool]([regex]::IsMatch($QueryXml, 'timediff\(\s*@SystemTime\s*,\s*\d'))
}

function Get-WfSyntheticQueryBound {
    # The inclusive [start, end] a Select's TimeCreated test names, read from
    # the escaped query text, or $null when the query has no such bound.
    param([string]$QueryXml)
    $m = [regex]::Match($QueryXml, "@SystemTime &gt;= '([^']+)' and @SystemTime &lt;= '([^']+)'")
    if (-not $m.Success) { $m = [regex]::Match($QueryXml, '@SystemTime &gt;= &apos;([^&]+)&apos; and @SystemTime &lt;= &apos;([^&]+)&apos;') }
    if (-not $m.Success) { return $null }
    return @{ Start = (ConvertFrom-WfUtcString -Text $m.Groups[1].Value); End = (ConvertFrom-WfUtcString -Text $m.Groups[2].Value) }
}

function Test-WfSyntheticInsideBound {
    param($Event, $Bound)
    if ($null -eq $Bound) { return $true }
    $when = ConvertFrom-WfUtcString -Text ([string]$Event['time_created_utc'])
    return ($when -ge $Bound['Start'] -and $when -le $Bound['End'])
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
    return [ordered]@{ name = 'SYNTHETIC-PC\wf-collector'; elevated = [bool]$global:WfSynthetic.Elevated; event_log_readers = $true; performance_log_users = [bool]$global:WfSynthetic.PerformanceLogUsers }
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
    if (Test-WfSyntheticNumericTimediff -QueryXml $QueryXml) {
        # What the gaming PC did on 2026-11-18 (Windows 11 Pro 25H2 build 26200,
        # Windows PowerShell 5.1.26100): EventLogQuery and EventLogReader accepted a query
        # with timediff(@SystemTime, <FILETIME number>) and the first
        # ReadEvent threw EventLogInvalidDataException, "The data is invalid",
        # before any record, on every channel. Reported by the PC session, not
        # reproduced here; collectors/windows/README.md, verification item 35.
        # Modelled so that the suite fails if a query ever carries that form again.
        $result.ReadNext = { param([timespan]$Remaining) throw 'Exception calling "ReadEvent" with "1" argument(s): "The data is invalid"' }
        $result.Ok = $true
        return $result
    }
    $bound = Get-WfSyntheticQueryBound -QueryXml $QueryXml
    if ($null -eq $bound -and $QueryXml.Contains('TimeCreated[')) {
        # A time test the stand-in cannot read must not become "every event":
        # the stand-in fails closed, like the code under test.
        $result.ReadNext = { param([timespan]$Remaining) throw 'synthetic backend: the query carries a TimeCreated test whose bound the stand-in cannot parse' }
        $result.Ok = $true
        return $result
    }
    foreach ($query in $global:WfSynthetic.Queries) {
        if (-not $QueryXml.Contains([string]$query['Match'])) { continue }
        if ($query['Throws']) {
            $message = [string]$query['Throws']
            $result.ReadNext = { param([timespan]$Remaining) throw $message }.GetNewClosure()
        } else {
            # Only the records inside the query's time bound, newest first,
            # like the real reader in reverse direction.
            $events = @(@($query['Events']) | Where-Object { Test-WfSyntheticInsideBound -Event $_ -Bound $bound } | Sort-Object -Property { $_['time_created_utc'] } -Descending)
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
    if ($Path -like '*wpr.exe') { return [bool]$global:WfSynthetic.Wpr.Present }
    if ($Path -like '*tracerpt.exe') { return [bool]$global:WfSynthetic.Tracerpt.Present }
    return $true
}

function Wait-WfSeconds {
    # The recording window passes on the synthetic clock, not in real time.
    param([int]$Seconds)
    $global:WfSynthetic.Ticks += $Seconds
    $global:WfSynthetic.Waited += $Seconds
}

function Get-WfBinaryInfo {
    param([string]$Path)
    $info = [ordered]@{ exists = $false; length = $null; sha256 = $null; file_version = $null; product_version = $null; error = $null }
    if (-not $global:WfSynthetic.Binaries.ContainsKey($Path)) { return $info }
    $entry = $global:WfSynthetic.Binaries[$Path]
    $info.exists = $true
    $info.length = [int64]$entry['Length']
    $info.sha256 = [string]$entry['Sha256']
    if ($entry.Contains('FileVersion')) { $info.file_version = $entry['FileVersion'] }
    if ($entry.Contains('ProductVersion')) { $info.product_version = $entry['ProductVersion'] }
    return $info
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
    # netsh, the synthetic wpr and the synthetic xperf: the collectors never
    # start anything else through this seam in the test suite (the evtx export
    # has its own replacement above).
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds, $OutputEncoding = $null, [int64]$MaxBytes = 0)
    $result = [ordered]@{ Started = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Oversized = $false; Error = $null; DurationMs = $null; StdOutBytes = [int64]0; StdErrBytes = [int64]0; Diagnostic = $null }
    $global:WfSynthetic.Processes.Add(@{ FilePath = $FilePath; Arguments = $Arguments })
    if ($TimeoutSeconds -lt 1) {
        $result.Error = 'not started: the deadline had passed'
        return $result
    }
    # A test that registered a Programs entry for this executable (the
    # presentmon-frames cases drive wpr through Programs) takes precedence
    # over the stateful simulators dpcisr-trace uses.
    $programForPath = $false
    foreach ($program in $global:WfSynthetic.Programs) { if ([string]$program['Path'] -eq $FilePath) { $programForPath = $true; break } }
    if ($FilePath -like '*wpr.exe' -and -not $programForPath) { return (Invoke-WfSyntheticWpr -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -Result $result) }
    if ($FilePath -like '*xperf.exe') { return (Invoke-WfSyntheticXperf -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -Result $result -MaxBytes $MaxBytes) }
    if ($FilePath -like '*tracerpt.exe') { return (Invoke-WfSyntheticTracerpt -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -Result $result) }
    $result.Started = $true
    $result.DurationMs = 7
    $entry = $null
    if ($global:WfSynthetic.Commands.ContainsKey($Arguments)) {
        $entry = $global:WfSynthetic.Commands[$Arguments]
    } else {
        foreach ($program in $global:WfSynthetic.Programs) {
            if ([string]$program['Path'] -ne $FilePath) { continue }
            if ($program['Match'] -and -not $Arguments.Contains([string]$program['Match'])) { continue }
            $entry = $program
            break
        }
    }
    if ($null -eq $entry) {
        $result.ExitCode = 1
        $result.StdErr = 'synthetic backend: no output is defined for ' + $FilePath + ' ' + $Arguments
        return $result
    }
    if ($entry.Contains('Responses')) {
        # A program whose answer changes from call to call (wpr -status before
        # and after a recording): the responses are used in order and the last
        # one repeats.
        $calls = 0
        if ($entry.Contains('Calls')) { $calls = [int]$entry['Calls'] }
        $entry['Calls'] = $calls + 1
        $responses = @($entry['Responses'])
        $entry = $responses[[math]::Min($calls, $responses.Count - 1)]
    }
    if ($entry.Contains('Seconds')) {
        $global:WfSynthetic.Ticks += [int]$entry['Seconds']
        $result.DurationMs = [int64]$entry['Seconds'] * 1000
    }
    if ($entry.Contains('OnCall')) {
        # A side effect the test wants when this program runs (the binary on
        # disk changing between the preflight hash and the run).
        & $entry['OnCall']
    }
    if ($entry.Contains('OutputFileArgument')) {
        # wpr writes its ETL to the -stop path and PresentMon its CSV to the
        # --output_file path; the synthetic program does the same before it
        # "exits", so the collector reads a file it did not write itself.
        $m = [regex]::Match($Arguments, [string]$entry['OutputFileArgument'])
        if ($m.Success) {
            $target = $m.Groups[1].Value
            $parent = Split-Path -Parent $target
            if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Force -Path $parent }
            if ($entry.Contains('OutputBytes')) { [System.IO.File]::WriteAllBytes($target, [byte[]]$entry['OutputBytes']) }
            elseif ($entry.Contains('OutputText')) { Write-WfTextFile -Path $target -Text ([string]$entry['OutputText']) }
        }
    }
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
# --- adapters for the live capture collector ---------------------------------

function New-WfSyntheticWpr {
    # The default synthetic recorder: present, idle, starts and stops cleanly,
    # loses nothing, and lists the three keywords dpcisr-trace asks for.
    # Instances holds the state of every -instancename the collector used.
    return @{
        Present             = $true
        State               = 'idle'
        Instances           = @{}
        IdleText            = "WPR is not recording`r`n"
        ProfilesExitCode    = 0
        StartExitCode       = 0
        StartStdErr         = ''
        StartStuck          = $false
        StartLeavesRunning  = $false
        StatusExitCode      = 0
        StatusStdErr        = ''
        StatusFailAfterCalls = 0
        StatusCalls         = 0
        StatusDelaySeconds  = 0
        StopExitCode        = 0
        StopStdErr          = ''
        StopStuck           = $false
        StopLeavesRunning   = $false
        CancelLeavesRunning = $false
        CollectorName       = 'NT Kernel Logger'
        EventsLost          = 0
        EventsLostText      = $null
        BuffersLostLine     = $null
        DroppedEvents       = 0
        StatusLabels        = 'english'
        Keywords            = @('Interrupt', 'DPC', 'Loader')
        BufferSizeKb        = 1024
        TempBytes           = 4096
        EtlBytes            = 4096
        TempDir             = $null
    }
}

function Split-WfSyntheticArguments {
    # The tokens of a command line as the collector built it: quoted
    # arguments may hold spaces.
    param([string]$Arguments)
    $tokens = New-Object 'System.Collections.Generic.List[string]'
    foreach ($m in [regex]::Matches([string]$Arguments, '"([^"]*)"|(\S+)')) {
        if ($m.Groups[1].Success) { $tokens.Add($m.Groups[1].Value) } else { $tokens.Add($m.Groups[2].Value) }
    }
    return , $tokens.ToArray()
}

function Get-WfSyntheticInstance {
    # The -instancename of a command line, or '' for the default instance.
    param([string[]]$Tokens)
    for ($i = 0; $i -lt $Tokens.Count - 1; $i++) { if ($Tokens[$i] -eq '-instancename') { return [string]$Tokens[$i + 1] } }
    return ''
}

function Get-WfSyntheticWprState {
    param([string]$Instance)
    $wpr = $global:WfSynthetic.Wpr
    if ($Instance -eq '') { return [string]$wpr.State }
    if ($wpr.Instances.ContainsKey($Instance)) { return [string]$wpr.Instances[$Instance] }
    return 'idle'
}

function Set-WfSyntheticWprState {
    param([string]$Instance, [string]$State)
    $wpr = $global:WfSynthetic.Wpr
    if ($Instance -eq '') { $wpr.State = $State } else { $wpr.Instances[$Instance] = $State }
}

function Write-WfSyntheticFiller {
    # A file of the requested size whose content says what it is not.
    param([string]$Path, [int64]$Bytes)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Force -Path $parent }
    $unit = [System.Text.Encoding]::ASCII.GetBytes("synthetic trace, not an event trace log`n")
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        $remaining = [int64]$Bytes
        while ($remaining -gt 0) {
            $count = [int][math]::Min($unit.Length, $remaining)
            $stream.Write($unit, 0, $count)
            $remaining -= $count
        }
    } finally { $stream.Dispose() }
}

function Get-WfSyntheticWprStatusText {
    # The shape Microsoft documents for "wpr -status" and "-status profiles
    # collectors": https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options
    param([bool]$Collectors)
    $wpr = $global:WfSynthetic.Wpr
    $nl = "`r`n"
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('WPR recording is in progress...')
    $lines.Add('')
    $lines.Add('Time since start        : 00:00:01')
    $lines.Add('')
    if ($wpr.StatusLabels -eq 'english') { $lines.Add('Dropped event           : ' + [string]$wpr.DroppedEvents) }
    else { $lines.Add('Verworfene Ereignisse   : ' + [string]$wpr.DroppedEvents) }
    $lines.Add('')
    $lines.Add('Logging mode            : File')
    if ($Collectors) {
        $lines.Add('')
        $lines.Add('Recording system activity using the following set of profiles:')
        $lines.Add('Profile                 : WfDpcIsrTrace.Verbose.File')
        $lines.Add('')
        $lines.Add('Actively recording collectors:')
        if ($wpr.CollectorName) {
            $lines.Add('Collector Name          : ' + [string]$wpr.CollectorName)
            $lines.Add('Buffer Size (KB)        : ' + [string]$wpr.BufferSizeKb)
            $lostText = $(if ($null -ne $wpr.EventsLostText) { [string]$wpr.EventsLostText } else { [string]$wpr.EventsLost })
            if ($wpr.StatusLabels -eq 'english') { $lines.Add('Events Lost             : ' + $lostText) }
            else { $lines.Add('Verlorene Ereignisse    : ' + $lostText) }
            if ($null -ne $wpr.BuffersLostLine) { $lines.Add([string]$wpr.BuffersLostLine) }
            $lines.Add('System Keywords')
            foreach ($keyword in @($wpr.Keywords)) { $lines.Add($keyword) }
            $lines.Add('System Stacks')
        }
    }
    return (($lines.ToArray() -join $nl) + $nl)
}

function Invoke-WfSyntheticWpr {
    param([string]$Arguments, [int]$TimeoutSeconds, $Result)
    $wpr = $global:WfSynthetic.Wpr
    $tokens = Split-WfSyntheticArguments -Arguments $Arguments
    $verb = $(if ($tokens.Count -gt 0) { $tokens[0] } else { '' })
    $instance = Get-WfSyntheticInstance -Tokens $tokens
    $Result.Started = $true
    $Result.DurationMs = 11
    $Result.ExitCode = 0
    switch ($verb) {
        '-status' {
            $wpr.StatusCalls = [int]$wpr.StatusCalls + 1
            if ([int]$wpr.StatusDelaySeconds -gt 0) { $global:WfSynthetic.Ticks += [int]$wpr.StatusDelaySeconds }
            if ([int]$wpr.StatusFailAfterCalls -gt 0 -and [int]$wpr.StatusCalls -gt [int]$wpr.StatusFailAfterCalls) {
                $Result.ExitCode = 5
                $Result.StdErr = "synthetic status error: access denied`r`n"
            } elseif ([int]$wpr.StatusExitCode -ne 0) {
                $Result.ExitCode = [int]$wpr.StatusExitCode
                $Result.StdErr = [string]$wpr.StatusStdErr
            } elseif ((Get-WfSyntheticWprState -Instance $instance) -eq 'recording') { $Result.StdOut = Get-WfSyntheticWprStatusText -Collectors ($tokens -contains 'collectors') }
            else { $Result.StdOut = [string]$wpr.IdleText }
        }
        '-profiles' {
            $Result.ExitCode = [int]$wpr.ProfilesExitCode
            if ($Result.ExitCode -eq 0) { $Result.StdOut = "Profile                 : WfDpcIsrTrace.Verbose.File`r`nProfile                 : WfDpcIsrTrace.Verbose.Memory`r`n" }
            else { $Result.StdErr = "synthetic wpr: the profile file is not valid`r`n" }
        }
        '-start' {
            if ((Get-WfSyntheticWprState -Instance $instance) -eq 'recording') {
                $Result.ExitCode = 1
                $Result.StdErr = "synthetic wpr: an existing session is already running`r`n"
            } elseif ($wpr.StartStuck) {
                $global:WfSynthetic.Ticks += $TimeoutSeconds
                $Result.TimedOut = $true
                $Result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
                Set-WfSyntheticWprState -Instance $instance -State 'recording'
            } elseif ([int]$wpr.StartExitCode -ne 0) {
                $Result.ExitCode = [int]$wpr.StartExitCode
                $Result.StdErr = [string]$wpr.StartStdErr
                if ($wpr.StartLeavesRunning) { Set-WfSyntheticWprState -Instance $instance -State 'recording' }
            } else {
                Set-WfSyntheticWprState -Instance $instance -State 'recording'
                for ($i = 0; $i -lt $tokens.Count - 1; $i++) {
                    if ($tokens[$i] -eq '-recordtempto') {
                        $wpr.TempDir = $tokens[$i + 1]
                        Write-WfSyntheticFiller -Path (Join-Path $wpr.TempDir 'synthetic-temporary-recording.etl') -Bytes ([int64]$wpr.TempBytes)
                    }
                }
                $Result.StdOut = "synthetic wpr: recording started`r`n"
            }
        }
        '-stop' {
            if ($wpr.StopStuck) {
                $global:WfSynthetic.Ticks += $TimeoutSeconds
                $Result.TimedOut = $true
                $Result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
            } elseif ([int]$wpr.StopExitCode -ne 0) {
                $Result.ExitCode = [int]$wpr.StopExitCode
                $Result.StdErr = [string]$wpr.StopStdErr
            } else {
                if ($tokens.Count -gt 1) { Write-WfSyntheticFiller -Path $tokens[1] -Bytes ([int64]$wpr.EtlBytes) }
                if ($wpr.TempDir -and (Test-Path -LiteralPath (Join-Path $wpr.TempDir 'synthetic-temporary-recording.etl'))) {
                    Remove-Item -LiteralPath (Join-Path $wpr.TempDir 'synthetic-temporary-recording.etl') -Force
                }
                if (-not $wpr.StopLeavesRunning) { Set-WfSyntheticWprState -Instance $instance -State 'idle' }
                $Result.StdOut = "synthetic wpr: trace saved`r`n"
            }
        }
        '-cancel' {
            if (-not $wpr.CancelLeavesRunning) { Set-WfSyntheticWprState -Instance $instance -State 'idle' }
            if ($wpr.TempDir -and (Test-Path -LiteralPath (Join-Path $wpr.TempDir 'synthetic-temporary-recording.etl'))) {
                Remove-Item -LiteralPath (Join-Path $wpr.TempDir 'synthetic-temporary-recording.etl') -Force
            }
            $Result.StdOut = "synthetic wpr: recording cancelled`r`n"
        }
        default {
            $Result.ExitCode = 1
            $Result.StdErr = 'synthetic wpr: unknown option ' + $verb
        }
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $Result.StdOutBytes = [int64]$utf8.GetByteCount([string]$Result.StdOut)
    $Result.StdErrBytes = [int64]$utf8.GetByteCount([string]$Result.StdErr)
    return $Result
}

function Invoke-WfSyntheticTracerpt {
    # "tracerpt <trace> -summary <file> -y": writes an invented summary whose
    # loss lines follow the Labels knob. The real tool's text is not
    # documented and is a verification item in the README.
    param([string]$Arguments, [int]$TimeoutSeconds, $Result)
    $tracerpt = $global:WfSynthetic.Tracerpt
    $tokens = Split-WfSyntheticArguments -Arguments $Arguments
    $Result.Started = $true
    $Result.DurationMs = 17
    if ($tracerpt['Stuck']) {
        $global:WfSynthetic.Ticks += $TimeoutSeconds
        $Result.TimedOut = $true
        $Result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
        return $Result
    }
    $trace = $(if ($tokens.Count -gt 0) { $tokens[0] } else { '' })
    $summaryPath = $null
    for ($i = 0; $i -lt $tokens.Count - 1; $i++) { if ($tokens[$i] -eq '-summary') { $summaryPath = $tokens[$i + 1] } }
    if (-not $trace -or -not (Test-Path -LiteralPath $trace)) {
        $Result.ExitCode = 1
        $Result.StdErr = 'synthetic tracerpt: the trace file does not exist'
        return $Result
    }
    $Result.ExitCode = [int]$tracerpt['ExitCode']
    if ($Result.ExitCode -ne 0) {
        $Result.StdErr = 'synthetic tracerpt: failed'
        return $Result
    }
    $nl = "`r`n"
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Files Processed:')
    $lines.Add("`t" + $trace)
    $lines.Add('Total Buffers Processed 69')
    $lines.Add('Total Events  Processed 107340')
    switch ([string]$tracerpt['Labels']) {
        'english' {
            $lines.Add('Total Events  Lost      ' + [string]$tracerpt['EventsLost'])
            $lines.Add('Total Buffers Lost      ' + [string]$tracerpt['BuffersLost'])
        }
        'nonnumeric' {
            $lines.Add('Total Events  Lost      n/a')
            $lines.Add('Total Buffers Lost      ' + [string]$tracerpt['BuffersLost'])
        }
        'events-only' {
            $lines.Add('Total Events  Lost      ' + [string]$tracerpt['EventsLost'])
        }
        default { }
    }
    $lines.Add('Start Time              2026-03-01 12:00:04')
    $lines.Add('End Time                2026-03-01 12:00:16')
    $lines.Add('Elapsed Time            10 sec')
    if ($summaryPath) { Write-WfTextFile -Path $summaryPath -Text (($lines.ToArray() -join $nl) + $nl) }
    $Result.StdOut = ''
    return $Result
}

function Invoke-WfSyntheticXperf {
    param([string]$Arguments, [int]$TimeoutSeconds, $Result, [int64]$MaxBytes)
    $xperf = $global:WfSynthetic.Xperf
    $tokens = Split-WfSyntheticArguments -Arguments $Arguments
    $Result.Started = $true
    $Result.DurationMs = 13
    if ($xperf['Stuck']) {
        $global:WfSynthetic.Ticks += $TimeoutSeconds
        $Result.TimedOut = $true
        $Result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
        return $Result
    }
    $trace = $null
    for ($i = 0; $i -lt $tokens.Count - 1; $i++) { if ($tokens[$i] -eq '-i') { $trace = $tokens[$i + 1] } }
    if (-not $trace -or -not (Test-Path -LiteralPath $trace)) {
        $Result.ExitCode = 1
        $Result.StdErr = 'synthetic xperf: the trace file does not exist'
        return $Result
    }
    $Result.ExitCode = [int]$xperf['ExitCode']
    $Result.StdOut = [string]$xperf['StdOut']
    $Result.StdErr = [string]$xperf['StdErr']
    if ($xperf.ContainsKey('ChangeHashAfterRun') -and $xperf['ChangeHashAfterRun']) {
        # The file is replaced while the tool runs: the hash read afterwards differs.
        foreach ($path in @($global:WfSynthetic.Tools.Keys)) {
            if ($path -like '*xperf.exe') { $global:WfSynthetic.Tools[$path] = @{ Sha256 = '0000000000000000000000000000000000000000000000000000000000000002'; Version = [string]$global:WfSynthetic.Tools[$path]['Version'] } }
        }
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $Result.StdOutBytes = [int64]$utf8.GetByteCount([string]$Result.StdOut)
    if ($MaxBytes -gt 0 -and $Result.StdOutBytes -gt $MaxBytes) {
        $Result.Oversized = $true
        $Result.Error = ('the process printed more than the cap of {0} bytes on StdOut and was stopped; nothing above the cap was kept' -f $MaxBytes)
        $Result.StdOut = ''
    }
    return $Result
}

function Get-WfWprPath {
    return 'C:\Windows\System32\wpr.exe'
}

function Get-WfTracerptPath {
    return 'C:\Windows\System32\tracerpt.exe'
}

function Get-WfMonotonicSeconds {
    return [double]$global:WfSynthetic.Ticks
}

function Get-WfExternalToolInfo {
    param([string]$Path)
    $info = [ordered]@{ Exists = $false; Sha256 = $null; Version = $null; Error = $null }
    if ($Path -and $global:WfSynthetic.Tools.ContainsKey($Path)) {
        $entry = $global:WfSynthetic.Tools[$Path]
        $info.Exists = $true
        $info.Sha256 = [string]$entry['Sha256']
        $info.Version = [string]$entry['Version']
    }
    return $info
}

function Get-WfPinnedToolBuilds {
    param([string]$Name)
    if ($global:WfSynthetic.PinnedTools.ContainsKey($Name)) { return , @($global:WfSynthetic.PinnedTools[$Name]) }
    return , @()
}

function Start-WfSleep {
    param([int]$Seconds)
    $global:WfSynthetic.Ticks += [math]::Max(0, $Seconds)
}
