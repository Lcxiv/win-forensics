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
#              in call order with the last repeating. Waited = seconds passed to Start-WfSleep, summed
#   Binaries   full path -> @{ Length; Sha256; FileVersion; ProductVersion } for Get-WfBinaryInfo;
#              a missing key is a file that does not exist
#   Account    the values Get-WfAccountInfo returns (elevated, group memberships)
#   NetshPresent  $false makes the netsh preflight fail
#   Files      full path -> @{ Text = <string> } or @{ ErrorKind; ErrorMessage }
#   Pnp        @{ Devices = <list of device maps, each may carry Properties = @{ DEVPKEY -> value } > }
#              or @{ ErrorKind; ErrorMessage }
#   PowercfgPresent  $false makes the powercfg preflight fail
#   Registry   key path (case insensitive) -> @{ Values = <list of @{ Name; Kind; Data }>; SubKeys = <names> }
#              or @{ ErrorKind; ErrorMessage }; a missing path does not exist (the fixed key reader)
#   DeviceKeys instance id -> the device hardware key model read by the native recorder (see below)
#   Topology   @{ Bytes = <GetLogicalProcessorInformationEx buffer> } or @{ Stage; ErrorCode; ErrorMessage }
#   Directories  folder path -> @{ Files = <list of file maps> } or @{ ErrorKind; ErrorMessage }; a missing path does not exist
#   Salt       the pseudonym salt (fixed, so fixtures are reproducible)
#   Elevated   whether the synthetic account is elevated (the live capture needs it)
#   Wpr        the synthetic Windows Performance Recorder (New-WfSyntheticWpr lists the knobs):
#              the default instance's State, one State per -instancename, the idle text, exit
#              codes and hangs per verb, what the status lists (keywords, buffer size, early
#              events lost, a lost buffers line), the bytes of the temporary recording and of
#              the saved trace, and whether a stop or cancel leaves the session running
#   Tracerpt   the synthetic tracerpt: Present, ExitCode, Stuck, EventsLost and BuffersLost of
#              the saved trace, Labels ('english', 'missing' or 'nonnumeric'), EventsProcessed
#              (the summary's processed count), and for a call that also names an XML dump
#              ("-o <file> -of XML", diskio-trace) DumpXml (the text written, none when null) and
#              OnDump (a scriptblock run once the dump is written, for a case that changes
#              the files under the collector's feet)
#   Tools      full path of an operator supplied tool -> @{ Sha256; Version } (nothing is read
#              from disk, so the fixtures stay reproducible)
#   PinnedTools  tool name -> list of @{ Version; Sha256; Source } the helper reports as pinned
#   Xperf      @{ ExitCode; StdOut; StdErr; Stuck } for the synthetic xperf report
#   Clock      the invented performance counter and system clock behind the
#              clock-calibration collector (New-WfSyntheticClock): a true
#              elapsed time that every read and every wait advances, a QPC
#              derived from it, and a system time with a quantisation step,
#              a drift and optional steps; marks fire during a wait
#   Net        the invented network behind connection-quality (New-WfSyntheticNet lists the
#              knobs): the route table and interface metrics (a change at a given second),
#              the adapters by interface index (link down windows, a read that throws), the
#              round trip time per target label and the seconds at which an echo is lost,
#              faults or makes the batch throw, the DNS answer time per server and the seconds
#              at which a query fails; every probe advances the synthetic clock by the time it
#              takes, and Sent records every address an echo or a query went to
#   Stdout     list that receives what a collector prints on stdout
#   Stderr     list that receives what a collector prints on stderr
#   ProfilePath  the account's profile folder the scenario runner refuses tool paths under
#   Host       the interpreter's edition and version (Get-WfPowerShellHost)
#   FreeBytes  free bytes on the output directory's volume, or $null when unreadable
#   Children   for the scenario runner: collector name -> @{ Case = <a case of
#              Get-WfSyntheticCases whose Setup prepares that collector's machine>;
#              StartFails = <message>; Stuck = $true (stopped at the deadline: the
#              collector never finishes, leaves Leftovers, a list of bundle relative
#              files, behind); NotReady = $true (a background collector that never
#              reports ready); Concurrent = $true (it ran alongside the runner, whose
#              clock does not advance by its run time) }. Each child runs in process at its start against a
#              fresh synthetic machine (Reset-WfSynthetic at the runner's clock, then
#              the case's Setup), and the runner's machine is restored afterwards.
#   ChildRuns  list of @{ Name; Arguments; WorkingDirectory } for every child started

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
        PowercfgPresent = $true
        Registry     = @{}
        DeviceKeys   = @{}
        NativeCalls  = New-Object 'System.Collections.Generic.List[object]'
        NativeHandles = @{}
        NativeMoreDataSeen = New-Object 'System.Collections.Generic.HashSet[string]'
        Topology     = $null
        Directories  = @{}
        Metadata     = @{}
        MissingParents = @()
        ProfileName  = 'synthetic-player'
        AccountName  = 'SYNTHETIC-PC\wf-collector'
        Files        = @{}
        Pnp          = @{ Devices = @() }
        Processes    = New-Object 'System.Collections.Generic.List[object]'
        WatchPath    = $null
        Waited       = 0
        Salt         = 'synthetic-salt-0001'
        Elevated     = $false
        PerformanceLogUsers = $false
        Wpr          = New-WfSyntheticWpr
        Tracerpt     = @{ Present = $true; ExitCode = 0; Stuck = $false; EventsLost = 0; BuffersLost = 0; Labels = 'english'; EventsProcessed = 107340; DumpXml = $null; OnDump = $null }
        Tools        = @{}
        PinnedTools  = @{}
        Xperf        = @{ ExitCode = 0; StdOut = ''; StdErr = ''; Stuck = $false }
        Clock        = $null
        Net          = $null
        Stdout       = New-Object 'System.Collections.Generic.List[string]'
        Stderr       = New-Object 'System.Collections.Generic.List[string]'
        ProfilePath  = 'C:\Users\synthetic-owner'
        Host         = [ordered]@{ edition = 'Desktop'; version = '5.1.26100.1' }
        FreeBytes    = [int64]500000000000
        Children     = @{}
        ChildRuns    = New-Object 'System.Collections.Generic.List[object]'
    }
    $global:WfSynthetic.Clock = New-WfSyntheticClock
    $global:WfSynthetic.Net = New-WfSyntheticNet
}

function New-WfSyntheticNet {
    # The invented network. Seconds are true seconds of the synthetic clock
    # (floor of Elapsed100ns / 1e7), so slot k of a session runs in second k.
    # Every address below is invented; the gateway address and the adapter's
    # hardware address are canaries the tests look for in every bundle file.
    #   Routes / InterfaceMetrics   MSFT_NetRoute rows and IPv4 interface metrics
    #   RouteChangeAtSecond / RoutesAfterChange   from that second on, the route read returns these rows
    #   RouteError        a route read throws this message (all reads)
    #   RouteErrorFromSecond  route reads at or after this second throw (0: never)
    #   Adapters          interface index (text) -> adapter values; LinkDown: @(@{ From; To }) seconds
    #                     during which the adapter reads disconnected and down at zero speed
    #   LinkError         an adapter read throws this message
    #   RttMs             label -> round trip in ms; Lost: label -> seconds whose echo times out
    #   Faulted           label -> seconds whose send faults (an exception inside the task)
    #   PingThrowAtSecond the whole batch throws in this second (0: never)
    #   DnsAvailable      whether Resolve-DnsName is there
    #   DnsMs             label -> answer time in ms; DnsFail: label -> seconds whose query fails
    #   DnsTimeoutMs      how long a failed query takes; DnsErrorId: the FullyQualifiedErrorId it carries
    return @{
        Routes               = @(
            @{ NextHop = '0.0.0.0'; InterfaceIndex = 3; RouteMetric = 0; Store = 1; AddressFamily = 2 },
            @{ NextHop = '10.213.47.1'; InterfaceIndex = 7; RouteMetric = 0; Store = 1; AddressFamily = 2 },
            @{ NextHop = '10.213.47.1'; InterfaceIndex = 7; RouteMetric = 0; Store = 0; AddressFamily = 2 },
            @{ NextHop = '10.99.0.1'; InterfaceIndex = 12; RouteMetric = 0; Store = 1; AddressFamily = 2 }
        )
        InterfaceMetrics     = @{ '3' = 5; '7' = 25; '12' = 35 }
        RouteChangeAtSecond  = $null
        RoutesAfterChange    = @()
        RouteError           = $null
        RouteErrorFromSecond = 0
        Adapters             = @{
            '7'  = @{ MediaConnectState = [uint32]1; InterfaceOperationalStatus = [uint32]1; ReceiveLinkSpeed = [uint64]1000000000; TransmitLinkSpeed = [uint64]1000000000; NdisPhysicalMedium = [uint32]14; MacAddress = '02-5E-AA-13-47-01' }
            '12' = @{ MediaConnectState = [uint32]1; InterfaceOperationalStatus = [uint32]1; ReceiveLinkSpeed = [uint64]866700000; TransmitLinkSpeed = [uint64]866700000; NdisPhysicalMedium = [uint32]9; MacAddress = '02-5E-AA-13-47-02' }
        }
        LinkDown             = @()
        LinkError            = $null
        Addresses            = @{ '10.213.47.1' = 'gateway'; '10.99.0.1' = 'gateway'; '1.1.1.1' = 'cloudflare'; '8.8.8.8' = 'google' }
        RttMs                = @{ gateway = 1; cloudflare = 12; google = 15 }
        Lost                 = @{ gateway = @(); cloudflare = @(); google = @() }
        Faulted              = @{ gateway = @(); cloudflare = @(); google = @() }
        PingThrowAtSecond    = 0
        DnsAvailable         = $true
        DnsMs                = @{ gateway = 9; cloudflare = 14 }
        DnsFail              = @{ gateway = @(); cloudflare = @() }
        DnsTimeoutMs         = 1200
        DnsErrorId           = 'ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName'
        Sent                 = New-Object 'System.Collections.Generic.List[string]'
        RouteReads           = 0
        LinkReads            = 0
    }
}

function Get-WfSyntheticSecond {
    return [int64][math]::Floor([double]$global:WfSynthetic.Clock.Elapsed100ns / 10000000.0)
}

function Add-WfSyntheticElapsedMs {
    param([int64]$Milliseconds)
    $global:WfSynthetic.Clock.Elapsed100ns += $Milliseconds * 10000
}

function New-WfSyntheticClock {
    # The invented clocks. True time is Elapsed100ns since the reset; every
    # read of either clock and every wait advances it. The counter is
    # StartQpc + Elapsed * Frequency / 1e7. The system time is StartFileTime
    # + Elapsed * (1 + DriftPpm / 1e6) + the steps whose moment has passed,
    # quantised down to a multiple of Increment100ns (the clock interrupt).
    #   -DriftPpm        the system clock runs fast (positive) or slow by this much
    #   -Increment100ns  the system timer increment (10000 is 1 ms)
    #   -Steps           @(@{ AtElapsed100ns = <n>; Delta100ns = <n> }) applied once true time passes At
    #   -Marks           @(@{ AtElapsed100ns = <n>; Label = <text> }) fired during the wait that crosses At
    #   -ThrowAtElapsed100ns  a counter read at or after this true time throws (0: never)
    #   -OvershootMs     @{ <1-based wait index> = <extra milliseconds the wait takes> }
    param(
        [int64]$Frequency = 10000000, [bool]$HighResolution = $true, [double]$DriftPpm = 0, [int64]$Increment100ns = 10000,
        $Steps = @(), $Marks = @(), [int64]$ThrowAtElapsed100ns = 0, $OvershootMs = @{}, [int64]$ReadCost100ns = 50
    )
    return @{
        Frequency       = $Frequency
        HighResolution  = $HighResolution
        StartQpc        = [int64]27345678901234
        StartFileTime   = [int64]$global:WfSynthetic.Now.ToFileTimeUtc()
        Elapsed100ns    = [int64]0
        ReadCost100ns   = $ReadCost100ns
        DriftPpm        = $DriftPpm
        Increment100ns  = $Increment100ns
        Steps           = @($Steps)
        Marks           = @($Marks)
        MarksFired      = 0
        QpcReads        = 0
        ThrowAtElapsed100ns = $ThrowAtElapsed100ns
        Waits           = 0
        OvershootMs     = $OvershootMs
        MarkDirectory   = $null
    }
}

function Get-WfSyntheticTrueQpc {
    $clock = $global:WfSynthetic.Clock
    return [int64]($clock.StartQpc + [int64][math]::Floor([double]$clock.Elapsed100ns * $clock.Frequency / 10000000.0))
}

function Get-WfSyntheticTrueFileTime {
    $clock = $global:WfSynthetic.Clock
    $value = [int64]$clock.StartFileTime + [int64]$clock.Elapsed100ns + [int64][math]::Floor([double]$clock.Elapsed100ns * $clock.DriftPpm / 1000000.0)
    foreach ($step in @($clock.Steps)) { if ($clock.Elapsed100ns -ge [int64]$step['AtElapsed100ns']) { $value += [int64]$step['Delta100ns'] } }
    if ($clock.Increment100ns -gt 1) { $value = [int64][math]::Floor([double]$value / $clock.Increment100ns) * $clock.Increment100ns }
    return $value
}

function Invoke-WfSyntheticMark {
    # Stands in for the person at the PC: runs the collector's mark mode in
    # this process against the session directory, then takes its stdout line
    # back out so the collector run still prints exactly one line.
    param([string]$Label, [string]$OutputDirectory)
    $collector = Join-Path (Split-Path -Parent $PSScriptRoot) 'clock-calibration.ps1'
    $before = $global:WfSynthetic.Stdout.Count
    & $collector -OutputDirectory $OutputDirectory -Mark $Label
    $exit = $LASTEXITCODE
    if ($global:WfSynthetic.Stdout.Count -ne $before + 1) { throw 'synthetic mark: the mark mode did not print exactly one line' }
    $line = $global:WfSynthetic.Stdout[$before]
    $global:WfSynthetic.Stdout.RemoveAt($before)
    if ($exit -ne 0) { throw ('synthetic mark failed: ' + $line) }
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
        [double]$DaysAgo, [object[]]$Properties = @(), $Message = $null, [string]$LevelDisplay = 'Error',
        # Optional names for the event data items, written as Name attributes
        # the way a manifest based provider renders them (Kernel-Power 41
        # names its first item BugcheckCode). Without them the items are bare.
        [string[]]$DataNames = @()
    )
    $when = $global:WfSynthetic.Now.AddDays(-1 * $DaysAgo)
    $time = ConvertTo-WfUtcString -Value $when
    $data = New-Object 'System.Collections.Generic.List[string]'
    $position = 0
    foreach ($value in $Properties) {
        $open = '<Data>'
        if ($position -lt @($DataNames).Count -and $DataNames[$position]) { $open = "<Data Name='" + $DataNames[$position] + "'>" }
        $data.Add($open + [System.Security.SecurityElement]::Escape([string]$value) + '</Data>')
        $position += 1
    }
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

function Get-WfQpcTimestamp {
    $clock = $global:WfSynthetic.Clock
    $clock.QpcReads += 1
    $clock.Elapsed100ns += $clock.ReadCost100ns
    if ($clock.ThrowAtElapsed100ns -gt 0 -and $clock.Elapsed100ns -ge $clock.ThrowAtElapsed100ns) { throw 'synthetic backend: the performance counter read failed' }
    return (Get-WfSyntheticTrueQpc)
}

function Get-WfQpcFrequency {
    return [int64]$global:WfSynthetic.Clock.Frequency
}

function Get-WfProcessId {
    return 4242
}

function Test-WfQpcHighResolution {
    return [bool]$global:WfSynthetic.Clock.HighResolution
}

function Get-WfSystemFileTimeUtc {
    $clock = $global:WfSynthetic.Clock
    $clock.Elapsed100ns += $clock.ReadCost100ns
    return (Get-WfSyntheticTrueFileTime)
}

function Wait-WfMilliseconds {
    # Advances true time instead of sleeping, with the configured overshoot,
    # and fires every mark whose moment falls inside the wait at exactly
    # that moment.
    param([int]$Milliseconds)
    $clock = $global:WfSynthetic.Clock
    $clock.Waits += 1
    $extra = 0
    if ($clock.OvershootMs.ContainsKey($clock.Waits)) { $extra = [int]$clock.OvershootMs[$clock.Waits] }
    $before = [int64]$clock.Elapsed100ns
    $after = $before + [int64]($Milliseconds + $extra) * 10000
    foreach ($mark in @($clock.Marks)) {
        $at = [int64]$mark['AtElapsed100ns']
        if ($at -le $before -or $at -gt $after) { continue }
        if ($clock.MarkDirectory) {
            $clock.Elapsed100ns = $at
            Invoke-WfSyntheticMark -Label ([string]$mark['Label']) -OutputDirectory $clock.MarkDirectory
            $clock.MarksFired += 1
        }
    }
    $clock.Elapsed100ns = $after
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
    return [ordered]@{ name = [string]$global:WfSynthetic.AccountName; elevated = [bool]$global:WfSynthetic.Elevated; event_log_readers = $true; performance_log_users = [bool]$global:WfSynthetic.PerformanceLogUsers }
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
        } elseif ([string]$Filter -match '^(\w+) = (TRUE|FALSE)$') {
            # A boolean literal, as WQL writes it (Present = TRUE). A row
            # without the property does not match, as WMI would not.
            $property = $Matches[1]
            $wanted = ($Matches[2] -eq 'TRUE')
            $rows = @($rows | Where-Object { $_.Contains($property) -and $_[$property] -is [bool] -and $_[$property] -eq $wanted })
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

function Get-WfToolPath {
    param([string]$Name)
    return ('C:\Windows\System32\' + $Name + '.exe')
}

function Get-WfNetshPath {
    return (Get-WfToolPath -Name 'netsh')
}

function Test-WfToolPresent {
    param([string]$Path)
    if ($Path -like '*netsh.exe') { return [bool]$global:WfSynthetic.NetshPresent }
    if ($Path -like '*powercfg.exe') { return [bool]$global:WfSynthetic.PowercfgPresent }
    if ($Path -like '*wpr.exe') { return [bool]$global:WfSynthetic.Wpr.Present }
    if ($Path -like '*tracerpt.exe') { return [bool]$global:WfSynthetic.Tracerpt.Present }
    return $true
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
    if ($Name -eq 'ProgramFiles') { return 'C:\Program Files' }
    if ($Name -eq 'Windows') { return 'C:\Windows' }
    # The two profile folders carry the invented account name, which the
    # tests check never reaches a bundle.
    if ($Name -eq 'LocalApplicationData') { return ('C:\Users\' + $global:WfSynthetic.ProfileName + '\AppData\Local') }
    if ($Name -eq 'MyDocuments') { return ('C:\Users\' + $global:WfSynthetic.ProfileName + '\Documents') }
    throw ('synthetic backend: unknown folder name ' + $Name)
}

function Get-WfFileMetadataListing {
    # The model is $global:WfSynthetic.Metadata, folder path (case insensitive) ->
    #   @{ Entries = <list of @{ Type = 'file'|'folder'; Folder; Name; Bytes; CreationTimeUtc; LastWriteTimeUtc; Entered }> }
    #   @{ ErrorKind = 'access_denied'|'other'; ErrorType = <exception type name> }
    #   @{ Entries; Stuck = $true } (the listing does not finish before the deadline)
    # A folder not in the map does not exist; its parent exists unless the
    # path is in $global:WfSynthetic.MissingParents. Entries below the depth
    # and names outside Include are dropped as the real listing drops them.
    param([string]$Path, [string]$Parent, [int]$Depth, [string[]]$Include, [int]$MaxEntries, [datetime]$DeadlineUtc)
    $result = [ordered]@{ Exists = $false; ParentExists = $true; ErrorKind = $null; ErrorType = $null; Entries = @(); Truncated = $false }
    foreach ($missing in @($global:WfSynthetic.MissingParents)) { if (([string]$missing).Equals($Path, [System.StringComparison]::OrdinalIgnoreCase)) { $result.ParentExists = $false } }
    $model = $null
    foreach ($key in $global:WfSynthetic.Metadata.Keys) {
        if (([string]$key).Equals($Path, [System.StringComparison]::OrdinalIgnoreCase)) { $model = $global:WfSynthetic.Metadata[$key]; break }
    }
    if ($null -eq $model) { return $result }
    $result.Exists = $true
    if ($model['ErrorKind']) {
        $result.ErrorKind = [string]$model['ErrorKind']
        $result.ErrorType = [string]$model['ErrorType']
        return $result
    }
    if ($model['Stuck']) {
        $global:WfSynthetic.Now = $DeadlineUtc.AddSeconds(1)
        $result.ErrorKind = 'timeout'
        $result.ErrorType = 'System.TimeoutException'
        return $result
    }
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in (Get-WfList -Value $model['Entries'])) {
        if ($item['Folder'] -and $Depth -lt 1) { continue }
        if ([string]$item['Type'] -eq 'folder' -and $Depth -lt 1) { continue }
        if ([string]$item['Type'] -eq 'file' -and -not (Test-WfNameIncluded -Name ([string]$item['Name']) -Include $Include)) { continue }
        if ($entries.Count -ge $MaxEntries) { $result.Truncated = $true; break }
        $entries.Add([ordered]@{
                Type = [string]$item['Type']; Folder = $item['Folder']; Name = [string]$item['Name']; Bytes = $item['Bytes']
                CreationTimeUtc = $item['CreationTimeUtc']; LastWriteTimeUtc = $item['LastWriteTimeUtc']
                Entered = $(if ($item.Contains('Entered')) { $item['Entered'] } else { [string]$item['Type'] -eq 'folder' })
            })
    }
    $result.Entries = $entries.ToArray()
    return $result
}

function Invoke-WfProcess {
    # netsh, powercfg, the synthetic wpr and the synthetic xperf: the collectors
    # never start anything else through this seam in the test suite (the evtx
    # export has its own replacement above).
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds, $OutputEncoding = $null, [int64]$MaxBytes = 0)
    $result = [ordered]@{ Started = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Oversized = $false; Error = $null; DurationMs = $null; StdOutBytes = [int64]0; StdErrBytes = [int64]0; Diagnostic = $null }
    $watched = $null
    if ($global:WfSynthetic.WatchPath) { $watched = (Test-Path -LiteralPath $global:WfSynthetic.WatchPath) }
    $global:WfSynthetic.Processes.Add(@{ FilePath = $FilePath; Arguments = $Arguments; WatchedPathExists = $watched })
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
        # wpr writes its ETL to the -stop path; the synthetic program does
        # the same before it "exits", so the collector reads a file it did
        # not write itself.
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
    param([string]$Path, [int64]$MaxBytes, [datetime]$DeadlineUtc = [datetime]::MaxValue)
    $result = [ordered]@{ Exists = $false; Readable = $false; Bytes = $null; Length = $null; CreationUtc = $null; LastWriteUtc = $null; ErrorKind = $null; ErrorMessage = $null }
    if (-not $global:WfSynthetic.Files.ContainsKey($Path)) {
        $result.ErrorKind = 'not_found'
        $result.ErrorMessage = 'the file does not exist'
        return $result
    }
    $entry = $global:WfSynthetic.Files[$Path]
    $result.Exists = $true
    if ($entry['SecondsToRead']) { $global:WfSynthetic.Ticks += [int]$entry['SecondsToRead'] }
    if ($entry['ErrorKind']) {
        $result.ErrorKind = [string]$entry['ErrorKind']
        $result.ErrorMessage = [string]$entry['ErrorMessage']
        return $result
    }
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$entry['Text'])
    $result.Length = [int64]$bytes.Length
    $result.CreationUtc = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-30)
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

# --- adapters for the registry and directory sources -------------------------

function Get-WfRegistryKey {
    param([string]$Path)
    $result = [ordered]@{ Exists = $false; ErrorKind = $null; ErrorMessage = $null; SubKeyNames = @(); Values = @() }
    $entry = $null
    foreach ($key in $global:WfSynthetic.Registry.Keys) {
        if ([string]$key -eq $Path -or ([string]$key).Equals($Path, [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.Registry[$key]; break }
    }
    if ($null -eq $entry) {
        $result.ErrorKind = 'not_found'
        $result.ErrorMessage = 'the key does not exist'
        return $result
    }
    if ($entry['ErrorKind']) {
        $result.Exists = ($entry['ErrorKind'] -ne 'not_found')
        $result.ErrorKind = [string]$entry['ErrorKind']
        $result.ErrorMessage = [string]$entry['ErrorMessage']
        return $result
    }
    if ($entry['SecondsToRead']) { $global:WfSynthetic.Ticks += [int]$entry['SecondsToRead'] }
    $result.Exists = $true
    $result.SubKeyNames = Get-WfList -Value $entry['SubKeys']
    $result.Values = Get-WfList -Value $entry['Values']
    return $result
}

function Get-WfDirectoryListing {
    param([string]$Path, [string]$Parent, [int]$MaxFiles, [datetime]$DeadlineUtc)
    # The synthetic machine always has the known folder itself (Program Files).
    $result = [ordered]@{ Exists = $false; Parent = $Parent; ParentExists = $true; ErrorKind = $null; ErrorMessage = $null; Files = @(); Truncated = $false }
    $entry = $null
    foreach ($key in $global:WfSynthetic.Directories.Keys) {
        if (([string]$key).Equals($Path, [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.Directories[$key]; break }
    }
    if ($null -eq $entry) { return $result }
    $result.Exists = $true
    if ($entry['ErrorKind']) {
        $result.ErrorKind = [string]$entry['ErrorKind']
        $result.ErrorMessage = [string]$entry['ErrorMessage']
        return $result
    }
    $files = New-Object 'System.Collections.Generic.List[object]'
    $listed = Get-WfList -Value $entry['Files']
    foreach ($file in $listed) {
        if ($files.Count -ge $MaxFiles) { $result.Truncated = $true; break }
        if ($entry['SecondsPerFile']) { $global:WfSynthetic.Ticks += [int]$entry['SecondsPerFile'] }
        $record = [ordered]@{}
        foreach ($name in @('name', 'bytes', 'last_write_time_utc', 'sha256', 'file_version', 'product_version', 'product_name', 'company_name', 'original_filename', 'error')) {
            if ($file.Contains($name)) { $record[$name] = $file[$name] } else { $record[$name] = $null }
        }
        $files.Add($record)
    }
    $result.Files = $files.ToArray()
    return $result
}

# --- the device key native recorder --------------------------------------------
#
# Stands in for New-WfDeviceKeyNative. The model is $global:WfSynthetic.DeviceKeys,
# instance id (case insensitive) -> @{
#   HardwareKey = 'exists' | 'missing' | 'denied' | 'error:<code>'
#   Device      = 'present' (default) | 'gone' (SetupDiOpenDeviceInfoW fails with ERROR_NO_SUCH_DEVINST)
#   Subkeys     = @{ '<relative subkey>' -> @{ Values = @(@{ Name; Type; Bytes }); Denied = $true; MoreData = $n (the
#                 first enumeration of every value answers ERROR_MORE_DATA with that size); SecondsPerValue = $n } }
#                 a subkey that is not in the map does not exist (ERROR_FILE_NOT_FOUND)
# }
# A device not in the model does not exist (ERROR_NO_SUCH_DEVINST). Every call is
# appended to $global:WfSynthetic.NativeCalls with its arguments, every handle
# handed out is tracked in $global:WfSynthetic.NativeHandles until closed, and
# $global:WfSynthetic.DeviceKeyCompile = 'fail' makes New-WfDeviceKeyNative
# report a compile failure.

function New-WfDeviceKeyNative {
    if ($global:WfSynthetic.ContainsKey('DeviceKeyCompile') -and $global:WfSynthetic.DeviceKeyCompile -eq 'fail') {
        return @{ Ok = $false; Error = 'the device key declaration could not be compiled or loaded: synthetic compiler failure'; Api = $null }
    }
    $api = New-Object psobject
    $api | Add-Member -MemberType NoteProperty -Name 'LastErrorValue' -Value 0
    $api | Add-Member -MemberType NoteProperty -Name 'NextHandle' -Value 1000
    $api | Add-Member -MemberType ScriptMethod -Name 'Record' -Value { param($name, $arguments) $global:WfSynthetic.NativeCalls.Add(@{ Call = $name; Arguments = $arguments }) }
    $api | Add-Member -MemberType ScriptMethod -Name 'Issue' -Value {
        param($kind, $target)
        $this.NextHandle += 1
        $handle = [IntPtr]$this.NextHandle
        $global:WfSynthetic.NativeHandles[[string]$this.NextHandle] = @{ Kind = $kind; Target = $target }
        return $handle
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'NewDeviceInfoData' -Value { return @{ cbSize = 32; InstanceId = $null } }
    $api | Add-Member -MemberType ScriptMethod -Name 'LastError' -Value { return [int]$this.LastErrorValue }
    $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiCreateDeviceInfoList' -Value {
        param($classGuid, $parent)
        $this.Record('SetupDiCreateDeviceInfoList', @($classGuid, $parent))
        return $this.Issue('set', $null)
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiOpenDeviceInfoW' -Value {
        param($set, $id, $parent, $flags, $data)
        $this.Record('SetupDiOpenDeviceInfoW', @($set, $id, $parent, $flags))
        $entry = $null
        foreach ($key in $global:WfSynthetic.DeviceKeys.Keys) { if (([string]$key).Equals([string]$id, [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.DeviceKeys[$key] } }
        if ($null -eq $entry -or [string]$entry['Device'] -eq 'gone' -or -not $id) {
            $this.LastErrorValue = [int](-536870389)
            return $false
        }
        $data.Value['InstanceId'] = [string]$id
        return $true
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiOpenDevRegKey' -Value {
        param($set, $data, $scope, $hwProfile, $keyType, $access)
        $id = [string]$data.Value['InstanceId']
        $this.Record('SetupDiOpenDevRegKey', @($set, $id, $scope, $hwProfile, $keyType, $access))
        $entry = $null
        foreach ($key in $global:WfSynthetic.DeviceKeys.Keys) { if (([string]$key).Equals($id, [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.DeviceKeys[$key] } }
        $state = [string]$entry['HardwareKey']
        if ($state -eq 'missing') { $this.LastErrorValue = [int](-536870396); return [IntPtr](-1) }
        if ($state -eq 'denied') { $this.LastErrorValue = 5; return [IntPtr](-1) }
        if ($state -like 'error:*') { $this.LastErrorValue = [int]($state.Substring(6)); return [IntPtr](-1) }
        return $this.Issue('hardware_key', $id)
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiDestroyDeviceInfoList' -Value {
        param($set)
        $this.Record('SetupDiDestroyDeviceInfoList', @($set))
        $global:WfSynthetic.NativeHandles.Remove([string][int64]$set)
        return $true
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'RegOpenKeyExW' -Value {
        param($key, $subkey, $options, $access, $handle)
        $this.Record('RegOpenKeyExW', @($key, $subkey, $options, $access))
        $parent = $global:WfSynthetic.NativeHandles[[string][int64]$key]
        if ($null -eq $parent -or $parent['Kind'] -ne 'hardware_key') { return 6 }
        $entry = $null
        foreach ($k in $global:WfSynthetic.DeviceKeys.Keys) { if (([string]$k).Equals([string]$parent['Target'], [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.DeviceKeys[$k] } }
        $subkeys = $entry['Subkeys']
        if ($null -eq $subkeys) { $subkeys = @{} }
        $model = $null
        foreach ($k in $subkeys.Keys) { if (([string]$k).Equals([string]$subkey, [System.StringComparison]::OrdinalIgnoreCase)) { $model = $subkeys[$k] } }
        if ($null -eq $model) {
            # The parent exists when any leaf under it exists.
            if ([string]$subkey -eq 'Interrupt Management') {
                foreach ($k in $subkeys.Keys) { if (([string]$k).StartsWith('Interrupt Management\', [System.StringComparison]::OrdinalIgnoreCase)) { $handle.Value = $this.Issue('subkey', $subkey); return 0 } }
            }
            return 2
        }
        if ($model['Denied']) { return 5 }
        $handle.Value = $this.Issue('subkey', (([string]$parent['Target']) + '|' + [string]$subkey))
        return 0
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'RegEnumValueW' -Value {
        param($key, $index, $name, $nameLength, $reserved, $type, $data, $dataLength)
        $this.Record('RegEnumValueW', @($key, $index))
        $opened = $global:WfSynthetic.NativeHandles[[string][int64]$key]
        if ($null -eq $opened -or $opened['Kind'] -ne 'subkey') { return 6 }
        $parts = ([string]$opened['Target']) -split '\|'
        $entry = $null
        foreach ($k in $global:WfSynthetic.DeviceKeys.Keys) { if (([string]$k).Equals($parts[0], [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $global:WfSynthetic.DeviceKeys[$k] } }
        $model = $null
        foreach ($k in $entry['Subkeys'].Keys) { if (([string]$k).Equals($parts[1], [System.StringComparison]::OrdinalIgnoreCase)) { $model = $entry['Subkeys'][$k] } }
        $values = @($model['Values'])
        if ([int]$index -ge $values.Count) { return 259 }
        if ($model['SecondsPerValue']) { $global:WfSynthetic.Ticks += [int]$model['SecondsPerValue'] }
        $value = $values[[int]$index]
        $bytes = [byte[]]$value['Bytes']
        if ($null -eq $bytes) { $bytes = New-Object byte[] 0 }
        if ($model['MoreData'] -and -not $global:WfSynthetic.NativeMoreDataSeen.Contains([string]$key + ':' + $index)) {
            $null = $global:WfSynthetic.NativeMoreDataSeen.Add([string]$key + ':' + $index)
            $dataLength.Value = [uint32]$model['MoreData']
            return 234
        }
        if ($bytes.Length -gt [int]$dataLength.Value) { $dataLength.Value = [uint32]$bytes.Length; return 234 }
        $null = $name.Clear()
        $null = $name.Append([string]$value['Name'])
        $nameLength.Value = [uint32]([string]$value['Name']).Length
        $type.Value = [uint32]$value['Type']
        if ($bytes.Length -gt 0) { [System.Array]::Copy($bytes, $data, $bytes.Length) }
        $dataLength.Value = [uint32]$bytes.Length
        return 0
    }
    $api | Add-Member -MemberType ScriptMethod -Name 'RegCloseKey' -Value {
        param($key)
        $this.Record('RegCloseKey', @($key))
        $global:WfSynthetic.NativeHandles.Remove([string][int64]$key)
        return 0
    }
    return @{ Ok = $true; Error = $null; Api = $api }
}

function Get-WfLogicalProcessorInformation {
    $model = $global:WfSynthetic.Topology
    $result = [ordered]@{ Ok = $false; Stage = $null; ErrorCode = $null; ErrorMessage = $null; Bytes = $null; PointerSize = 8 }
    if ($null -eq $model) { $result.Stage = 'compile'; $result.ErrorMessage = 'synthetic backend: no topology defined'; return $result }
    if ($model.ContainsKey('PointerSize')) { $result.PointerSize = [int]$model['PointerSize'] }
    if ($model['Stage']) {
        $result.Stage = [string]$model['Stage']
        $result.ErrorCode = $model['ErrorCode']
        $result.ErrorMessage = [string]$model['ErrorMessage']
        return $result
    }
    $result.Stage = 'read'
    $result.Bytes = [byte[]]$model['Bytes']
    $result.Ok = $true
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
        EtlContent          = $null
        ProfileName         = 'WfDpcIsrTrace'
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
        $lines.Add('Profile                 : ' + [string]$wpr.ProfileName + '.Verbose.File')
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
            if ($Result.ExitCode -eq 0) { $Result.StdOut = ("Profile                 : {0}.Verbose.File`r`nProfile                 : {0}.Verbose.Memory`r`n" -f [string]$wpr.ProfileName) }
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
                if ($tokens.Count -gt 1 -and $null -ne $wpr.EtlContent) {
                    # A trace whose first buffer the collector reads (diskio-trace reads its header).
                    $parent = Split-Path -Parent $tokens[1]
                    if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Force -Path $parent }
                    [System.IO.File]::WriteAllBytes($tokens[1], [byte[]]$wpr.EtlContent)
                } elseif ($tokens.Count -gt 1) { Write-WfSyntheticFiller -Path $tokens[1] -Bytes ([int64]$wpr.EtlBytes) }
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
    # "tracerpt <trace> [-o <file> -of XML] -summary <file> -y": writes an
    # invented summary whose loss lines follow the Labels knob, and the dump
    # when the call names one. The real tool's text is not
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
    $dumpPath = $null
    for ($i = 0; $i -lt $tokens.Count - 1; $i++) {
        if ($tokens[$i] -eq '-summary') { $summaryPath = $tokens[$i + 1] }
        if ($tokens[$i] -eq '-o') { $dumpPath = $tokens[$i + 1] }
    }
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
    if ($dumpPath) {
        # "-o <file> -of XML" in the same call: the dump diskio-trace reads.
        if ($null -ne $tracerpt['DumpXml']) { Write-WfTextFile -Path $dumpPath -Text ([string]$tracerpt['DumpXml']) }
        if ($tracerpt['OnDump'] -is [scriptblock]) { & $tracerpt['OnDump'] }
    }
    $nl = "`r`n"
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Files Processed:')
    $lines.Add("`t" + $trace)
    $lines.Add('Total Buffers Processed 69')
    $lines.Add('Total Events  Processed ' + [string]$tracerpt['EventsProcessed'])
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
    # The bound of a live session passes on the synthetic clock, not in real time.
    param([int]$Seconds)
    $global:WfSynthetic.Ticks += [math]::Max(0, $Seconds)
    $global:WfSynthetic.Waited += [math]::Max(0, $Seconds)
}

# --- connection-quality adapters ------------------------------------------

function Get-WfDefaultRouteHop {
    # The real adapter's selection over the invented route table, so the
    # ranking runs here as it will on Windows.
    param([int]$TimeoutSeconds = 30)
    $net = $global:WfSynthetic.Net
    $net.RouteReads += 1
    Add-WfSyntheticElapsedMs -Milliseconds 3
    $second = Get-WfSyntheticSecond
    if ($net.RouteError) { throw [System.InvalidOperationException]::new([string]$net.RouteError) }
    if ($net.RouteErrorFromSecond -gt 0 -and $second -ge $net.RouteErrorFromSecond) { throw [System.InvalidOperationException]::new('synthetic backend: the route table could not be read at 10.213.47.1') }
    $routes = $net.Routes
    if ($null -ne $net.RouteChangeAtSecond -and $second -ge $net.RouteChangeAtSecond) { $routes = $net.RoutesAfterChange }
    return (Select-WfDefaultRouteHop -Routes @($routes) -InterfaceMetrics $net.InterfaceMetrics)
}

function Get-WfNetLinkState {
    param([int]$InterfaceIndex, [int]$TimeoutSeconds = 30)
    $net = $global:WfSynthetic.Net
    $net.LinkReads += 1
    Add-WfSyntheticElapsedMs -Milliseconds 4
    if ($net.LinkError) { throw [System.UnauthorizedAccessException]::new([string]$net.LinkError) }
    $key = [string]$InterfaceIndex
    if (-not $net.Adapters.ContainsKey($key)) { return $null }
    $adapter = $net.Adapters[$key]
    $second = Get-WfSyntheticSecond
    foreach ($window in @($net.LinkDown)) {
        if ($second -ge [int64]$window['From'] -and $second -le [int64]$window['To']) {
            return @{ MediaConnectState = [uint32]2; InterfaceOperationalStatus = [uint32]7; ReceiveLinkSpeed = [uint64]0; TransmitLinkSpeed = [uint64]0; NdisPhysicalMedium = $adapter['NdisPhysicalMedium'] }
        }
    }
    # Only the requested properties: the invented hardware address stays in the model.
    return @{
        MediaConnectState          = $adapter['MediaConnectState']
        InterfaceOperationalStatus = $adapter['InterfaceOperationalStatus']
        ReceiveLinkSpeed           = $adapter['ReceiveLinkSpeed']
        TransmitLinkSpeed          = $adapter['TransmitLinkSpeed']
        NdisPhysicalMedium         = $adapter['NdisPhysicalMedium']
    }
}

function Invoke-WfPingBatch {
    # All targets at once: the batch takes as long as its slowest echo (a
    # lost echo takes the whole timeout).
    param($Targets, [int]$TimeoutMilliseconds, [System.Collections.Generic.List[object]]$Into)
    $net = $global:WfSynthetic.Net
    $second = Get-WfSyntheticSecond
    if ($net.PingThrowAtSecond -gt 0 -and $second -eq $net.PingThrowAtSecond) { throw [System.InvalidOperationException]::new('synthetic backend: the echo batch failed for 10.213.47.1') }
    $longest = 1
    foreach ($target in @($Targets)) {
        $address = [string]$target['Address']
        $net.Sent.Add('ping ' + $address)
        if (-not $net.Addresses.ContainsKey($address)) { throw ('synthetic backend: an echo went to an address the scenario does not know') }
        $label = [string]$net.Addresses[$address]
        if ($label -ne [string]$target['Label']) { throw ('synthetic backend: target ' + $target['Label'] + ' carries the address of ' + $label) }
        $outcome = @{ Label = $label; Status = 'Success'; RttMs = [int64]$net.RttMs[$label]; ErrorType = $null }
        $takes = [int64]$net.RttMs[$label]
        if (@($net.Faulted[$label]) -contains $second) {
            $outcome = @{ Label = $label; Status = 'error'; RttMs = $null; ErrorType = 'System.ComponentModel.Win32Exception' }
            $takes = 2
        } elseif (@($net.Lost[$label]) -contains $second) {
            $outcome = @{ Label = $label; Status = 'TimedOut'; RttMs = $null; ErrorType = $null }
            $takes = $TimeoutMilliseconds
        }
        if ($takes -gt $longest) { $longest = $takes }
        $Into.Add($outcome)
    }
    Add-WfSyntheticElapsedMs -Milliseconds $longest
}

function Test-WfDnsClientAvailable {
    return [bool]$global:WfSynthetic.Net.DnsAvailable
}

function Invoke-WfDnsProbe {
    param([string]$Server, [string]$Name)
    $net = $global:WfSynthetic.Net
    $net.Sent.Add('dns ' + $Server + ' ' + $Name)
    if (-not $net.Addresses.ContainsKey($Server)) { throw ('synthetic backend: a query went to a server the scenario does not know') }
    $label = [string]$net.Addresses[$Server]
    $second = Get-WfSyntheticSecond
    if (@($net.DnsFail[$label]) -contains $second) {
        Add-WfSyntheticElapsedMs -Milliseconds ([int64]$net.DnsTimeoutMs)
        return @{ Ok = $false; Records = $null; ErrorType = 'System.ComponentModel.Win32Exception'; ErrorId = $net.DnsErrorId; ErrorCode = 1460 }
    }
    Add-WfSyntheticElapsedMs -Milliseconds ([int64]$net.DnsMs[$label])
    return @{ Ok = $true; Records = 2; ErrorType = $null; ErrorId = $null; ErrorCode = $null }
}

function Get-WfUserProfilePath {
    return [string]$global:WfSynthetic.ProfilePath
}

function Get-WfPowerShellHost {
    return $global:WfSynthetic.Host
}

function Get-WfPowerShellExePath {
    return 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
}

function Get-WfVolumeFreeSpace {
    param([string]$Path)
    if ($null -eq $global:WfSynthetic.FreeBytes) { return [ordered]@{ root = 'C:\'; free_bytes = $null; error = 'synthetic: the volume could not be read' } }
    return [ordered]@{ root = 'C:\'; free_bytes = [int64]$global:WfSynthetic.FreeBytes; error = $null }
}

function Start-WfCollectorChild {
    # Runs the collector in this process, at once, against its own synthetic
    # machine, and keeps the result for Wait-WfCollectorChild. The argument
    # list is parsed back into named parameters as powershell.exe -File would.
    param([string]$ScriptPath, [string[]]$Arguments, [string]$WorkingDirectory)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    $global:WfSynthetic.ChildRuns.Add(@{ Name = $name; Arguments = @($Arguments); WorkingDirectory = $WorkingDirectory })
    $spec = $global:WfSynthetic.Children[$name]
    $result = [ordered]@{ Started = $true; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Oversized = $false; Error = $null; DurationMs = 5; StdOutBytes = [int64]0; StdErrBytes = [int64]0; Diagnostic = $null }
    $handle = @{ Name = $name; Result = $result; Ready = $true }
    if ($null -eq $spec) { throw ('synthetic backend: no child scenario for ' + $name) }
    if ($spec['StartFails']) {
        $result.Started = $false
        $result.Error = [string]$spec['StartFails']
        return $handle
    }
    if ($spec['NotReady']) { $handle.Ready = $false }
    $parameters = @{}
    for ($i = 0; $i -lt $Arguments.Count - 1; $i += 2) { $parameters[([string]$Arguments[$i]).TrimStart('-')] = [string]$Arguments[$i + 1] }
    $runner = $global:WfSynthetic
    try {
        Reset-WfSynthetic -Now (Get-WfUtcNow)
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $spec['Case'] })[0]
        & $case['Setup'] $parameters['OutputDirectory']
        if ($spec['Stuck']) {
            $null = New-Item -ItemType Directory -Force -Path $parameters['OutputDirectory']
            foreach ($relative in @($spec['Leftovers'])) {
                $path = Join-WfBundlePath -BundleRoot $parameters['OutputDirectory'] -RelativePath $relative
                $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path)
                [System.IO.File]::WriteAllText($path, 'synthetic leftover')
            }
            $result.TimedOut = $true
            $result.Error = 'the process did not finish within the deadline and was stopped'
            $global:WfSynthetic.Ticks += 600
        } else {
            & $ScriptPath @parameters
            $result.ExitCode = $LASTEXITCODE
            $result.StdOut = ((@($global:WfSynthetic.Stdout) -join "`n") + "`n")
            $result.StdErr = (@($global:WfSynthetic.Stderr) -join "`n")
        }
        $elapsed = [int]$global:WfSynthetic.Ticks
    } finally {
        $global:WfSynthetic = $runner
    }
    # A background child ran alongside the runner: its time is not the runner's.
    if (-not $spec['Concurrent']) { $global:WfSynthetic.Ticks += $elapsed }
    return $handle
}

function Wait-WfCollectorChild {
    param($Handle, [int]$TimeoutSeconds)
    $result = $Handle.Result
    $result['Waited'] = $TimeoutSeconds
    return $result
}

function Test-WfCollectorChildExited {
    param($Handle)
    return $true
}

function Test-WfCollectorChildReady {
    param($Handle, [string]$ReadyPath)
    return [bool]$Handle.Ready
}

function Get-WfScriptToolRecord {
    # As Get-WfToolInventory here: no hash and no real path, so the fixtures
    # do not change when a script is edited.
    param([string]$Name, [string]$Version, [string]$Path)
    return [ordered]@{ name = $Name; version = $Version; path = ('<install directory>\' + [System.IO.Path]::GetFileName($Path)); sha256 = $null }
}

