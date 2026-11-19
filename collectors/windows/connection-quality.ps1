# connection-quality: Does the connection from this PC drop or slow down, and where: at the PC, at the router, or beyond it?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account. Writes
# one bundle (docs/contracts/bundle.md) into -OutputDirectory, prints one JSON
# summary line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md ("The connection-quality sources") for the
# interface, the privacy rule, the status rules and the facts still to be
# verified on a real machine.
#
# A bounded session (-DurationSeconds) with one slot per second on the
# performance counter:
#   gateway_probes   an ICMP echo to the default gateway every slot and an A
#                    query for www.microsoft.com sent to it every 10 s
#   public_probes    an ICMP echo to two public resolvers (labels cloudflare
#                    and google) in the same slot, and the same A query sent
#                    to cloudflare every 10 s
#   link_state       the media connect state, operational status and link
#                    speeds of the adapter behind the default route every
#                    10 s and at the stop, with whether the preferred
#                    default route is still the one the session started on
# Every probe line carries its own counter bracket around a system time
# reading (qpc_before, filetime_utc_100ns, qpc_after, the order the timestamp
# contract fixes) and a counter reading after the probe completed (qpc_done),
# so it sits on the etw_qpc master clock beside the frame, driver delay and
# disk tables without calibration.
#
# Privacy: the gateway address is read from the route table into memory and
# never written; it is the label gateway everywhere. The two public targets
# are constants of this script, recorded by label in the samples. No local
# address, hardware address, network name, adapter name or description, DNS
# answer (address) or exception message is read into a bundle.
#
# Network traffic: the probes are packets this PC sends (one echo of 32 bytes
# per target per second, two DNS queries every 10 s). They change no setting.
# Whether the session may run while a game is being played is the owner's
# call; the collector never opens, inspects or signals any other process.
#
# https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ping.sendpingasync?view=netframework-4.8
# https://learn.microsoft.com/dotnet/api/system.net.networkinformation.pingreply.roundtriptime
# https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipstatus
# https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname
# https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netroute
# https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netipinterface
# https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
# https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # Session length in seconds (10 to 840; the dispatcher stops a collector
    # after 900).
    [int]$DurationSeconds = 300,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'connection-quality'
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

# Constants are functions (the helper's rule: no script scoped variables).
function Get-WfNetIntervalSeconds { return 1 }
function Get-WfNetDnsEverySlots { return 10 }
# An echo not answered within this many milliseconds is TimedOut. Below the
# one second slot, so a batch in which every target times out still ends
# before the next slot.
function Get-WfNetPingTimeoutMilliseconds { return 800 }
function Get-WfNetPingPayloadBytes { return 32 }
function Get-WfNetDnsName { return 'www.microsoft.com' }
function Get-WfNetCimTimeoutSeconds { return 5 }

function Get-WfNetPublicTargets {
    # The two public targets, fixed in this script: the anycast resolvers of
    # Cloudflare and Google. The samples name them by label only.
    return @(
        @{ Label = 'cloudflare'; Address = '1.1.1.1'; Dns = $true },
        @{ Label = 'google'; Address = '8.8.8.8'; Dns = $false }
    )
}

function Get-WfNetDnsErrorIdPattern {
    # The shape of a Resolve-DnsName FullyQualifiedErrorId: an error name and
    # the cmdlet's type. Anything else is withheld, never written.
    return '^[A-Za-z0-9_]{1,64},Microsoft\.DnsClient\.Commands\.ResolveDnsName$'
}

function Read-WfNetTriple {
    # Counter, system time as a file time, counter: the order the timestamp
    # contract fixes (docs/contracts/timestamps.md section 3).
    $before = Get-WfQpcTimestamp
    $fileTime = Get-WfSystemFileTimeUtc
    $after = Get-WfQpcTimestamp
    return @{ qpc_before = [int64]$before; filetime_utc_100ns = [int64]$fileTime; qpc_after = [int64]$after }
}

function ConvertTo-WfNetCount {
    # A CIM unsigned value as a JSON integer; null when it is missing or does
    # not fit (NDIS reports an unknown link speed as all ones).
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $number = [decimal]$Value } catch { return $null }
    if ($number -lt 0 -or $number -gt [decimal][int64]::MaxValue) { return $null }
    return [int64]$number
}

function ConvertTo-WfNetErrorId {
    param($Text)
    if ($null -eq $Text) { return $null }
    $value = [string]$Text
    if ($value -match (Get-WfNetDnsErrorIdPattern)) { return $value }
    return 'withheld'
}

function Get-WfNetErrorText {
    # What a session failure says: the text of a throw in this script, or
    # only the exception type for anything else, whose message is not known
    # to be free of addresses.
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    if ($exception -is [System.Management.Automation.RuntimeException] -and $exception.GetType().FullName -eq 'System.Management.Automation.RuntimeException') {
        return $exception.Message
    }
    return ('an exception of type ' + (Get-WfInnermostExceptionType -Exception $exception))
}

function New-WfNetLine {
    param([int]$Seq, [string]$Kind, $Target, [int64]$SlotQpc, $Triple, [int64]$QpcDone)
    $line = [ordered]@{ seq = $Seq; kind = $Kind }
    if ($Kind -ne 'link') { $line['target'] = $Target }
    $line['slot_qpc'] = $SlotQpc
    $line['qpc_before'] = [int64]$Triple['qpc_before']
    $line['filetime_utc_100ns'] = [int64]$Triple['filetime_utc_100ns']
    $line['qpc_after'] = [int64]$Triple['qpc_after']
    $line['qpc_done'] = $QpcDone
    return $line
}

function Add-WfNetSample {
    # One line to a samples file; returns the bytes written.
    param([string]$Path, $Line)
    $text = ConvertTo-WfJson -Value $Line
    [System.IO.File]::AppendAllText($Path, $text + "`n", (New-Object System.Text.UTF8Encoding($false)))
    return [int64]($text.Length + 1)
}

function New-WfNetTally {
    return [ordered]@{ sent = 0; ok = 0; failed = 0; unknown = 0 }
}

function Add-WfNetTally {
    param($Tally, $Ok)
    $Tally['sent'] = [int]$Tally['sent'] + 1
    if ($null -eq $Ok) { $Tally['unknown'] = [int]$Tally['unknown'] + 1 }
    elseif ($Ok) { $Tally['ok'] = [int]$Tally['ok'] + 1 }
    else { $Tally['failed'] = [int]$Tally['failed'] + 1 }
}

function Test-WfNetPingOk {
    # True for Success, false for any other IPStatus name (the echo was sent
    # and not answered as asked), null for 'error' and 'not_completed' (what
    # happened on the wire is unknown).
    param([string]$Status)
    if ($Status -eq 'Success') { return $true }
    if ($Status -eq 'error' -or $Status -eq 'not_completed') { return $null }
    return $false
}

function Invoke-WfNetQualitySessionSource {
    # The custom source: runs the bounded session and returns the three
    # manifest entries (gateway_probes, public_probes, link_state).
    param($Source, [string]$BundleRoot, [int64]$MaxArtifactBytes, [int]$TimeoutSeconds, [System.Collections.Generic.List[string]]$Log, [System.Collections.Generic.List[string]]$Notes, $MachineInfo)
    $duration = [int]$Source['DurationSeconds']
    $interval = Get-WfNetIntervalSeconds
    $dnsEvery = Get-WfNetDnsEverySlots
    $pingTimeout = Get-WfNetPingTimeoutMilliseconds
    $dnsName = Get-WfNetDnsName
    $cimTimeout = Get-WfNetCimTimeoutSeconds
    $ids = @('gateway_probes', 'public_probes', 'link_state')
    $entries = @{}
    $entries['gateway_probes'] = New-WfCollectorEntry -Id 'gateway_probes' -Kind 'other' -Required $false
    $entries['public_probes'] = New-WfCollectorEntry -Id 'public_probes' -Kind 'other' -Required $true
    $entries['link_state'] = New-WfCollectorEntry -Id 'link_state' -Kind 'other' -Required $false
    $roles = @{ 'command.json' = 'config'; 'result.json' = 'report'; 'samples.jsonl' = 'primary' }
    $paths = @{}
    foreach ($id in $ids) { $paths[$id] = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $id + '/samples.jsonl') }
    $started = Get-WfUtcNow
    foreach ($id in $ids) { $entries[$id].started_utc = ConvertTo-WfUtcString -Value $started }

    $running = @{ gateway_probes = $false; public_probes = $false; link_state = $false }
    $reasons = @{ gateway_probes = $null; public_probes = $null; link_state = $null }
    $statusOf = @{ gateway_probes = 'not_collected'; public_probes = 'not_collected'; link_state = 'not_collected' }
    $checks = @{ gateway_probes = (New-Object 'System.Collections.Generic.List[object]'); public_probes = (New-Object 'System.Collections.Generic.List[object]'); link_state = (New-Object 'System.Collections.Generic.List[object]') }
    $lineCount = @{ gateway_probes = 0; public_probes = 0; link_state = 0 }
    $probeCount = @{ gateway_probes = 0; public_probes = 0; link_state = 0 }
    $missedSeqs = @{ gateway_probes = (New-Object 'System.Collections.Generic.List[int]'); public_probes = (New-Object 'System.Collections.Generic.List[int]'); link_state = (New-Object 'System.Collections.Generic.List[int]') }
    $firstFileTime = @{ gateway_probes = $null; public_probes = $null; link_state = $null }
    $lastFileTime = @{ gateway_probes = $null; public_probes = $null; link_state = $null }
    $tallies = [ordered]@{ ping_gateway = (New-WfNetTally); dns_gateway = (New-WfNetTally); ping_cloudflare = (New-WfNetTally); ping_google = (New-WfNetTally); dns_cloudflare = (New-WfNetTally) }
    $link = [ordered]@{ readings = 0; read = 0; not_found = 0; errors = 0; down = 0; route_changed = 0; route_unknown = 0 }
    $failure = $null
    $unsupported = $false
    $frequency = $null
    $highResolution = $false
    $sessionStartQpc = $null
    $sessionStopQpc = $null
    $slotsTaken = 0
    $slotsMissed = 0
    $samplesBytes = [int64]0
    $hop = $null
    $routeReadError = $null
    $dnsAvailable = $false
    $publicTargets = @(Get-WfNetPublicTargets)
    $linkProperties = @(Get-WfNetLinkProperties)

    try {
        foreach ($id in $ids) { $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $id)) }
        $frequency = Get-WfQpcFrequency
        $highResolution = Test-WfQpcHighResolution
        if ($frequency -lt 1) { $frequency = $null }
        $dnsAvailable = Test-WfDnsClientAvailable
        try {
            $hop = Get-WfDefaultRouteHop -TimeoutSeconds $cimTimeout
        } catch {
            $routeReadError = 'the route table could not be read (' + (Get-WfInnermostExceptionType -Exception $_.Exception) + ')'
            $Log.Add('connection-quality: ' + $routeReadError)
        }
        $initialLink = $null
        $linkReadError = $null
        if ($null -ne $hop) {
            try {
                $initialLink = Get-WfNetLinkState -InterfaceIndex ([int]$hop['InterfaceIndex']) -TimeoutSeconds $cimTimeout
            } catch {
                $linkReadError = 'the adapter could not be read (' + (Get-WfInnermostExceptionType -Exception $_.Exception) + ')'
            }
        }
        $clockCheck = [ordered]@{ name = 'qpc_high_resolution'; ok = [bool]($highResolution -and $null -ne $frequency); detail = 'Stopwatch.IsHighResolution: ' + [string]$highResolution + '; Stopwatch.Frequency: ' + [string]$frequency + ' Hz' }
        $dnsCheck = [ordered]@{ name = 'resolve_dnsname_available'; ok = [bool]$dnsAvailable; detail = 'Resolve-DnsName (DnsClient module): ' + $(if ($dnsAvailable) { 'available' } else { 'not available' }) }
        $routeDetail = $routeReadError
        if ($null -eq $routeDetail) {
            if ($null -ne $hop) { $routeDetail = ('an IPv4 default route with a gateway was found ({0} candidate(s)); its next hop is kept in memory and written as the label gateway' -f [int]$hop['Candidates']) }
            else { $routeDetail = 'no active IPv4 default route (0.0.0.0/0) with a gateway address and a known interface metric' }
        }
        $routeCheck = [ordered]@{ name = 'default_route_gateway'; ok = ($null -ne $hop); detail = $routeDetail }
        foreach ($id in $ids) { $checks[$id].Add($clockCheck) }
        $checks['gateway_probes'].Add($dnsCheck)
        $checks['gateway_probes'].Add($routeCheck)
        $checks['public_probes'].Add($dnsCheck)
        $checks['link_state'].Add($routeCheck)
        $linkDetail = $linkReadError
        if ($null -eq $linkDetail) {
            if ($null -eq $hop) { $linkDetail = 'no default route interface to read' }
            elseif ($null -eq $initialLink) { $linkDetail = 'the interface of the default route has no MSFT_NetAdapter row (a virtual or tunnel interface has none)' }
            else { $linkDetail = 'MSFT_NetAdapter row of the default route interface read' }
        }
        $checks['link_state'].Add([ordered]@{ name = 'default_route_adapter'; ok = ($null -ne $initialLink); detail = $linkDetail })

        # Which sources run, and why the others do not.
        if (-not $clockCheck.ok) {
            $unsupported = $true
            foreach ($id in $ids) {
                $statusOf[$id] = 'unsupported'
                $reasons[$id] = 'Stopwatch.IsHighResolution is false or the frequency is not positive: the performance counter behind the managed timer is not the high resolution counter ETW stamps events with, so no probe could be placed on the master clock'
            }
        } else {
            if (-not $dnsAvailable) {
                foreach ($id in @('gateway_probes', 'public_probes')) { $reasons[$id] = 'preflight failed: Resolve-DnsName (the inbox DnsClient module) is not available, so the DNS probes this source declares cannot run' }
            } else {
                $running['public_probes'] = $true
                if ($null -ne $hop) { $running['gateway_probes'] = $true }
                else { $reasons['gateway_probes'] = 'preflight failed: ' + $routeDetail }
            }
            if ($null -ne $initialLink) { $running['link_state'] = $true }
            else { $reasons['link_state'] = 'preflight failed: ' + $(if ($null -eq $hop) { $routeDetail } else { $linkDetail }) }
        }

        # The configuration record of each source.
        $sessionConfig = [ordered]@{
            duration_seconds       = $duration
            interval_seconds       = $interval
            slots                  = $duration
            timeout_seconds        = $TimeoutSeconds
            max_artifact_bytes     = $MaxArtifactBytes
            qpc_frequency_hz       = $frequency
            qpc_high_resolution    = [bool]$highResolution
            slot_rule              = 'slot k is due at the session start counter plus k seconds; a slot reached more than one interval late is written as a missed line and not taken late'
            stamp                  = 'qpc_before, filetime_utc_100ns, qpc_after are read right before the probe is sent (Stopwatch.GetTimestamp, DateTime.UtcNow.ToFileTimeUtc, Stopwatch.GetTimestamp); qpc_done right after it completed'
            samples_file           = 'samples.jsonl, one JSON object per line in the order written; a decoder cites line:<n>'
            network_traffic        = 'the probes are packets this PC sends: one ICMP echo of 32 bytes per target per slot and one DNS A query per DNS target every 10 slots; no setting is read for writing or changed'
            privacy                = 'the gateway address is read from the route table into memory and written only as the label gateway; the public targets are constants of the collector; no local address, hardware address, network name, adapter name or description, DNS answer or exception message is written'
        }
        $pingSpec = [ordered]@{ api = 'System.Net.NetworkInformation.Ping.SendPingAsync(IPAddress, Int32, Byte[]), one Ping per target, all sent before any is awaited (Task.WaitAll)'; timeout_milliseconds = $pingTimeout; payload_bytes = (Get-WfNetPingPayloadBytes); kept = 'the reply Status by IPStatus name and RoundtripTime in milliseconds when Status is Success; a faulted send is error with its innermost exception type; a send still pending after the wait is not_completed' }
        $dnsSpec = [ordered]@{ api = 'Resolve-DnsName -Name <name> -Type A -Server <target> -DnsOnly -QuickTimeout -NoHostsFile'; name = $dnsName; type = 'A'; every_slots = $dnsEvery; kept = 'answered or failed, the number of records returned (never the records), and for a failure the exception type, the FullyQualifiedErrorId when it has the documented error id shape (else withheld) and the NativeErrorCode when the exception has one'; timing = 'qpc_done - qpc_after spans the cmdlet call, so it is an upper bound on the query time' }
        $configs = @{}
        $configs['gateway_probes'] = [ordered]@{ source = 'gateway_probes'; targets = @([ordered]@{ label = 'gateway'; address = 'the next hop of the preferred IPv4 default route at the session start, not written'; ping = $true; dns = $true }); ping = $pingSpec; dns = $dnsSpec; route = 'MSFT_NetRoute 0.0.0.0/0, Store 1, lowest RouteMetric plus MSFT_NetIPInterface InterfaceMetric, ties to the lowest InterfaceIndex; the gateway stays the one found at the start even when the route changes (link_state records the change)'; session = $sessionConfig }
        $publicList = New-Object 'System.Collections.Generic.List[object]'
        foreach ($target in $publicTargets) { $publicList.Add([ordered]@{ label = [string]$target['Label']; address = [string]$target['Address']; ping = $true; dns = [bool]$target['Dns'] }) }
        $configs['public_probes'] = [ordered]@{ source = 'public_probes'; targets = @($publicList.ToArray()); ping = $pingSpec; dns = $dnsSpec; session = $sessionConfig }
        $configs['link_state'] = [ordered]@{ source = 'link_state'; api = 'Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter -Filter InterfaceIndex = <the default route interface> -Property ' + ($linkProperties -join ','); every_slots = $dnsEvery; stop_reading = 'one more reading after the last slot, written with seq equal to the slot count'; route_same = 'true when the preferred IPv4 default route still has the interface and next hop the session started with, false when it changed or is gone, null when the route table could not be read; neither value is written'; values = 'MediaConnectState, InterfaceOperationalStatus and NdisPhysicalMedium as numbers, ReceiveLinkSpeed and TransmitLinkSpeed in bits per second (null when unknown)'; session = $sessionConfig }
        foreach ($id in $ids) {
            $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $id + '/command.json')
            Write-WfJsonFile -Path $configPath -Object $configs[$id]
            $entries[$id].config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
            $entries[$id].preflight = [ordered]@{ ok = [bool]$running[$id]; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = @($checks[$id].ToArray()) }
        }
        $dnsCommand = @('Resolve-DnsName', '-Name', $dnsName, '-Type', 'A', '-Server', '<target>', '-DnsOnly', '-QuickTimeout', '-NoHostsFile')
        $entries['gateway_probes'].command = @('System.Net.NetworkInformation.Ping.SendPingAsync', 'gateway') + $dnsCommand
        $entries['public_probes'].command = @('System.Net.NetworkInformation.Ping.SendPingAsync', 'cloudflare', 'google') + $dnsCommand
        $entries['link_state'].command = @('Get-CimInstance', '-Namespace', 'root/StandardCimv2', '-ClassName', 'MSFT_NetAdapter', '-Filter', 'InterfaceIndex = <default route interface>', '-Property', ($linkProperties -join ','), '-OperationTimeoutSec', [string]$cimTimeout)
        foreach ($id in @('gateway_probes', 'public_probes')) {
            $targetLabels = @($configs[$id]['targets'] | ForEach-Object { $_['label'] })
            $entries[$id].requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{
                    targets = $targetLabels; interval_seconds = $interval; dns_every_slots = $dnsEvery; ping_timeout_milliseconds = $pingTimeout
                    ping_payload_bytes = (Get-WfNetPingPayloadBytes); dns_name = $dnsName; dns_type = 'A'; duration_seconds = $duration; slots = $duration
                    timeout_seconds = $TimeoutSeconds; max_artifact_bytes = $MaxArtifactBytes
                } }
        }
        $entries['link_state'].requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{
                properties = $linkProperties; every_slots = $dnsEvery; duration_seconds = $duration; readings = ([int][math]::Ceiling($duration / [double]$dnsEvery) + 1)
                cim_timeout_seconds = $cimTimeout; time_property = $null; timeout_seconds = $TimeoutSeconds; max_artifact_bytes = $MaxArtifactBytes
            } }

        if ($running['gateway_probes'] -or $running['public_probes'] -or $running['link_state']) {
            foreach ($id in $ids) { if ($running[$id]) { [System.IO.File]::WriteAllText($paths[$id], '', (New-Object System.Text.UTF8Encoding($false))) } }
            $pingTargets = New-Object 'System.Collections.Generic.List[object]'
            $dnsTargets = New-Object 'System.Collections.Generic.List[object]'
            if ($running['gateway_probes']) {
                $pingTargets.Add(@{ Label = 'gateway'; Address = [string]$hop['NextHop']; Source = 'gateway_probes' })
                $dnsTargets.Add(@{ Label = 'gateway'; Address = [string]$hop['NextHop']; Source = 'gateway_probes' })
            }
            if ($running['public_probes']) {
                foreach ($target in $publicTargets) {
                    $pingTargets.Add(@{ Label = [string]$target['Label']; Address = [string]$target['Address']; Source = 'public_probes' })
                    if ($target['Dns']) { $dnsTargets.Add(@{ Label = [string]$target['Label']; Address = [string]$target['Address']; Source = 'public_probes' }) }
                }
            }
            $intervalTicks = [int64]$interval * $frequency
            $deadlineTicks = [int64]$TimeoutSeconds * $frequency
            $sessionStartQpc = Get-WfQpcTimestamp
            $Log.Add(('connection-quality: session start at qpc {0}, {1} slots of {2} s, ping targets {3}, DNS targets {4}, link {5}' -f $sessionStartQpc, $duration, $interval,
                    (@($pingTargets | ForEach-Object { $_['Label'] }) -join ','), (@($dnsTargets | ForEach-Object { $_['Label'] }) -join ','), $running['link_state']))

            for ($k = 0; $k -le $duration; $k++) {
                $stopReading = ($k -eq $duration)
                $slotQpc = $sessionStartQpc + [int64]$k * $intervalTicks
                $missed = $false
                $now = $null
                while ($true) {
                    $now = Get-WfQpcTimestamp
                    if (($now - $sessionStartQpc) -gt $deadlineTicks) { throw ('the session passed its deadline of ' + $TimeoutSeconds + ' s before slot ' + $k) }
                    if ($now -ge $slotQpc) {
                        if (-not $stopReading -and ($now - $slotQpc) -gt $intervalTicks) { $missed = $true }
                        break
                    }
                    $remainingMs = [int][math]::Ceiling(($slotQpc - $now) * 1000.0 / $frequency)
                    Wait-WfMilliseconds -Milliseconds ([math]::Max(1, $remainingMs))
                }
                $dnsSlot = (-not $stopReading -and ($k % $dnsEvery) -eq 0)
                if ($missed) {
                    $slotsMissed += 1
                    foreach ($id in @('gateway_probes', 'public_probes')) {
                        if (-not $running[$id]) { continue }
                        $samplesBytes += Add-WfNetSample -Path $paths[$id] -Line ([ordered]@{ seq = $k; kind = 'missed'; slot_qpc = $slotQpc; seen_qpc = [int64]$now })
                        $lineCount[$id] += 1
                        $missedSeqs[$id].Add($k)
                    }
                    if ($running['link_state'] -and $dnsSlot) {
                        $samplesBytes += Add-WfNetSample -Path $paths['link_state'] -Line ([ordered]@{ seq = $k; kind = 'missed'; slot_qpc = $slotQpc; seen_qpc = [int64]$now })
                        $lineCount['link_state'] += 1
                        $missedSeqs['link_state'].Add($k)
                    }
                    if ($samplesBytes -gt $MaxArtifactBytes) { throw ('the samples files exceeded their cap of ' + $MaxArtifactBytes + ' bytes') }
                    continue
                }

                if (-not $stopReading) {
                    $slotsTaken += 1
                    if ($pingTargets.Count -gt 0) {
                        $replies = New-Object 'System.Collections.Generic.List[object]'
                        $triple = Read-WfNetTriple
                        Invoke-WfPingBatch -Targets @($pingTargets.ToArray()) -TimeoutMilliseconds $pingTimeout -Into $replies
                        $done = Get-WfQpcTimestamp
                        for ($i = 0; $i -lt $pingTargets.Count; $i++) {
                            $target = $pingTargets[$i]
                            $reply = $replies[$i]
                            if ([string]$reply['Label'] -ne [string]$target['Label']) { throw 'the ping batch returned its replies out of order' }
                            $line = New-WfNetLine -Seq $k -Kind 'ping' -Target $target['Label'] -SlotQpc $slotQpc -Triple $triple -QpcDone $done
                            $line['status'] = [string]$reply['Status']
                            $line['rtt_ms'] = $reply['RttMs']
                            $line['error_type'] = $reply['ErrorType']
                            $id = [string]$target['Source']
                            $samplesBytes += Add-WfNetSample -Path $paths[$id] -Line $line
                            $lineCount[$id] += 1
                            $probeCount[$id] += 1
                            if ($null -eq $firstFileTime[$id]) { $firstFileTime[$id] = [int64]$triple['filetime_utc_100ns'] }
                            $lastFileTime[$id] = [int64]$triple['filetime_utc_100ns']
                            Add-WfNetTally -Tally $tallies['ping_' + [string]$target['Label']] -Ok (Test-WfNetPingOk -Status ([string]$reply['Status']))
                        }
                    }
                }
                if ($running['link_state'] -and ($dnsSlot -or $stopReading)) {
                    $triple = Read-WfNetTriple
                    $state = $null
                    $linkStatus = 'read'
                    $errorType = $null
                    try {
                        $state = Get-WfNetLinkState -InterfaceIndex ([int]$hop['InterfaceIndex']) -TimeoutSeconds $cimTimeout
                        if ($null -eq $state) { $linkStatus = 'not_found' }
                    } catch {
                        $linkStatus = 'error'
                        $errorType = Get-WfInnermostExceptionType -Exception $_.Exception
                    }
                    $routeSame = $null
                    try {
                        $currentHop = Get-WfDefaultRouteHop -TimeoutSeconds $cimTimeout
                        $routeSame = ($null -ne $currentHop -and [int]$currentHop['InterfaceIndex'] -eq [int]$hop['InterfaceIndex'] -and [string]$currentHop['NextHop'] -eq [string]$hop['NextHop'])
                        $currentHop = $null
                    } catch {
                        $routeSame = $null
                    }
                    $done = Get-WfQpcTimestamp
                    $line = New-WfNetLine -Seq $k -Kind 'link' -Target $null -SlotQpc $slotQpc -Triple $triple -QpcDone $done
                    $line['status'] = $linkStatus
                    $line['media_connect_state'] = $(if ($null -ne $state) { ConvertTo-WfNetCount -Value $state['MediaConnectState'] } else { $null })
                    $line['operational_status'] = $(if ($null -ne $state) { ConvertTo-WfNetCount -Value $state['InterfaceOperationalStatus'] } else { $null })
                    $line['receive_link_speed_bps'] = $(if ($null -ne $state) { ConvertTo-WfNetCount -Value $state['ReceiveLinkSpeed'] } else { $null })
                    $line['transmit_link_speed_bps'] = $(if ($null -ne $state) { ConvertTo-WfNetCount -Value $state['TransmitLinkSpeed'] } else { $null })
                    $line['physical_medium'] = $(if ($null -ne $state) { ConvertTo-WfNetCount -Value $state['NdisPhysicalMedium'] } else { $null })
                    $line['route_same'] = $routeSame
                    $line['error_type'] = $errorType
                    $samplesBytes += Add-WfNetSample -Path $paths['link_state'] -Line $line
                    $lineCount['link_state'] += 1
                    $probeCount['link_state'] += 1
                    if ($null -eq $firstFileTime['link_state']) { $firstFileTime['link_state'] = [int64]$triple['filetime_utc_100ns'] }
                    $lastFileTime['link_state'] = [int64]$triple['filetime_utc_100ns']
                    $link['readings'] = [int]$link['readings'] + 1
                    if ($linkStatus -eq 'read') {
                        $link['read'] = [int]$link['read'] + 1
                        if ($line['media_connect_state'] -ne 1 -or $line['operational_status'] -ne 1) { $link['down'] = [int]$link['down'] + 1 }
                    } elseif ($linkStatus -eq 'not_found') { $link['not_found'] = [int]$link['not_found'] + 1 }
                    else { $link['errors'] = [int]$link['errors'] + 1 }
                    if ($null -eq $routeSame) { $link['route_unknown'] = [int]$link['route_unknown'] + 1 }
                    elseif (-not $routeSame) { $link['route_changed'] = [int]$link['route_changed'] + 1 }
                }
                # The DNS queries come last in the slot: a query that waits for its timeout delays only what follows it.
                if ($dnsSlot) {
                    foreach ($target in $dnsTargets) {
                        $triple = Read-WfNetTriple
                        $answer = Invoke-WfDnsProbe -Server ([string]$target['Address']) -Name $dnsName
                        $done = Get-WfQpcTimestamp
                        $line = New-WfNetLine -Seq $k -Kind 'dns' -Target $target['Label'] -SlotQpc $slotQpc -Triple $triple -QpcDone $done
                        $line['status'] = $(if ($answer['Ok']) { 'answered' } else { 'failed' })
                        $line['answer_records'] = $(if ($answer['Ok']) { [int]$answer['Records'] } else { $null })
                        $line['error_type'] = $answer['ErrorType']
                        $line['error_id'] = ConvertTo-WfNetErrorId -Text $answer['ErrorId']
                        $line['error_code'] = $(if ($null -ne $answer['ErrorCode']) { [int64]$answer['ErrorCode'] } else { $null })
                        $id = [string]$target['Source']
                        $samplesBytes += Add-WfNetSample -Path $paths[$id] -Line $line
                        $lineCount[$id] += 1
                        $probeCount[$id] += 1
                        if ($null -eq $firstFileTime[$id]) { $firstFileTime[$id] = [int64]$triple['filetime_utc_100ns'] }
                        $lastFileTime[$id] = [int64]$triple['filetime_utc_100ns']
                        Add-WfNetTally -Tally $tallies['dns_' + [string]$target['Label']] -Ok ([bool]$answer['Ok'])
                    }
                }
                if ($samplesBytes -gt $MaxArtifactBytes) { throw ('the samples files exceeded their cap of ' + $MaxArtifactBytes + ' bytes') }
            }
            $sessionStopQpc = Get-WfQpcTimestamp
        }
    } catch {
        $failure = 'the session failed: ' + (Get-WfNetErrorText -ErrorRecord $_)
        $Log.Add('connection-quality raised: ' + $failure)
    }
    # The gateway address leaves memory with the session.
    $hop = $null
    $stopped = Get-WfUtcNow

    foreach ($id in $ids) {
        $entry = $entries[$id]
        $met = $false
        if ($unsupported) {
            $entry.status = 'unsupported'
            $entry.status_reason = $reasons[$id]
        } elseif (-not $running[$id]) {
            $entry.status = 'not_collected'
            $entry.status_reason = $reasons[$id]
            if ($null -ne $failure -and $null -eq $entry.status_reason) { $entry.status_reason = $failure }
        } elseif ($null -ne $failure) {
            $entry.status = 'capture_failed'
            $entry.status_reason = $failure + ('; the {0} lines written are not kept, because a session that did not reach its stop is not a complete record of the slots' -f $lineCount[$id])
        } elseif ($probeCount[$id] -eq 0) {
            $entry.status = 'capture_failed'
            $entry.status_reason = ('no probe was taken: every one of the {0} slots was reached more than one interval late' -f $duration)
        } else {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        }
        if ($entry.status -ne 'observed') {
            # A failed or skipped source leaves no primary export.
            $samplesPath = $paths[$id]
            if (Test-Path -LiteralPath $samplesPath) { Remove-Item -LiteralPath $samplesPath -Force }
        }
        $statusOf[$id] = $entry.status
        if ($entry.status -eq 'observed') {
            $firstUtc = [datetime]::FromFileTimeUtc([int64]$firstFileTime[$id])
            $lastUtc = [datetime]::FromFileTimeUtc([int64]$lastFileTime[$id])
            $entry.raw_time_range = New-WfTimeRange -StartUtc $firstUtc -EndUtc $lastUtc
        }
        $report = [ordered]@{
            started_utc        = ConvertTo-WfUtcString -Value $started
            stopped_utc        = ConvertTo-WfUtcString -Value $stopped
            status             = $entry.status
            slots              = $duration
            slots_taken        = $slotsTaken
            slots_missed       = $slotsMissed
            missed_seqs        = @($missedSeqs[$id].ToArray())
            lines              = $lineCount[$id]
            probes             = $probeCount[$id]
            session_start_qpc  = $sessionStartQpc
            session_stop_qpc   = $sessionStopQpc
            qpc_frequency_hz   = $frequency
            samples_kept       = ($entry.status -eq 'observed')
            failure            = $failure
        }
        if ($id -eq 'gateway_probes') { $report['tallies'] = [ordered]@{ ping_gateway = $tallies['ping_gateway']; dns_gateway = $tallies['dns_gateway'] } }
        elseif ($id -eq 'public_probes') { $report['tallies'] = [ordered]@{ ping_cloudflare = $tallies['ping_cloudflare']; ping_google = $tallies['ping_google']; dns_cloudflare = $tallies['dns_cloudflare'] } }
        else { $report['link'] = $link }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $id + '/result.json')) -Object $report
        $options = [ordered]@{ slots_taken = $slotsTaken; slots_missed = $slotsMissed; lines = $lineCount[$id]; probes = $probeCount[$id]; qpc_frequency_hz = $frequency; qpc_high_resolution = [bool]$highResolution; session_start_qpc = $sessionStartQpc; session_stop_qpc = $sessionStopQpc; failure = $failure }
        if ($id -ne 'link_state') {
            $options['targets'] = $(if ($entry.requested.options.Contains('targets')) { @($entry.requested.options['targets']) } else { @() })
            $options['ping_timeout_milliseconds'] = $pingTimeout
        } else {
            $options['readings'] = [int]$link['readings']
            $options['route_changed_readings'] = [int]$link['route_changed']
        }
        $entry.enabled = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $options
            verified_by = 'the probe lines themselves in samples.jsonl (one per probe and one per missed slot, in the order written); result.json carries the counts per target and the missed slots' }
        if ($id -eq 'link_state') {
            $declared = ('a reading of the default route adapter every {0} slots of the {1} s session and one at the stop, each stamped on the performance counter; a slot reached more than one interval late is written as a missed line' -f $dnsEvery, $duration)
            $detail = ('{0} readings ({1} read, {2} not found, {3} errors, {4} not connected or not up), {5} missed, route changed at {6} readings' -f $link['readings'], $link['read'], $link['not_found'], $link['errors'], $link['down'], $missedSeqs[$id].Count, $link['route_changed'])
        } else {
            $declared = ('one ICMP echo per target per 1 s slot for {0} slots and one DNS A query per DNS target every {1} slots, each stamped on the performance counter; a slot reached more than one interval late is written as a missed line, so every slot is accounted for' -f $duration, $dnsEvery)
            $detail = ('{0} probe lines, {1} missed slots of {2}' -f $probeCount[$id], $missedSeqs[$id].Count, $duration)
        }
        if ($failure) { $detail += '; ' + $failure }
        $entry.expectation = [ordered]@{ declared = $declared; met = $met; detail = $detail }
        $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
        $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
        $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    }
    if ($slotsMissed -gt 0 -and $null -eq $failure) {
        $message = ('connection-quality: {0} of {1} slots were reached more than one interval late and are written as missed lines (sampling gaps, not losses)' -f $slotsMissed, $duration)
        $Notes.Add($message)
        $Log.Add($message)
    }
    return @{
        Entries                  = @($entries['gateway_probes'], $entries['public_probes'], $entries['link_state'])
        Calibration              = $null
        RequestedDurationSeconds = $duration
    }
}

if ($DurationSeconds -lt 10 -or $DurationSeconds -gt 840) {
    [Console]::Error.WriteLine($collectorName + ': DurationSeconds must be between 10 and 840')
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    Write-WfStdoutLine -Text ('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}

$definition = @{
    Name        = $collectorName
    Version     = '1.0.0'
    Question    = 'Does the connection from this PC drop or slow down, and where: at the PC, at the router, or beyond it?'
    Calibration = @{
        status = 'not_applicable'
        method = 'none in this collector: every probe line carries its own performance counter bracket (qpc_before, qpc_after) around a system time reading, and qpc_done after the probe completed, so it sits on the etw_qpc master clock without calibration; the file time beside it is kept for the reader. Relating system_time sources to the counter is the clock-calibration collector''s job'
    }
    Sources     = @(
        @{
            Id              = 'connection_quality'
            Type            = 'custom'
            Invoke          = 'Invoke-WfNetQualitySessionSource'
            DurationSeconds = $DurationSeconds
        }
    )
}

# The helper's per source deadline covers the whole session plus a margin.
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds ($DurationSeconds + 60) -CollectorPath $PSCommandPath)[-1]
exit $exitCode
