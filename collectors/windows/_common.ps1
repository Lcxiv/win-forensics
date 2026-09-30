# Shared helper for the named read only collectors in this directory.
#
# Every collector dot sources this file. Its name starts with an underscore so
# that it can never be mistaken for a collector: collector names match
# ^[a-z][a-z0-9-]{1,40}$ and this name does not.
#
# The file has two halves. The first half is portable logic (bundle layout,
# manifest, checksums, measurement status, the one line summary) and is what
# the Pester suite exercises off Windows. The second half is a small set of
# adapter functions that touch Windows (event log, WMI, wevtutil, identity).
# The test suite replaces the adapters with synthetic ones; nothing else in
# this file calls a Windows only API.
#
# Target: Windows PowerShell 5.1 as a standard account in Event Log Readers.
# Contracts: docs/contracts/bundle.md, docs/contracts/measurement-status.md,
# schemas/manifest.schema.json. Citations for every Windows behaviour relied
# on are next to the code that relies on it and in collectors/windows/README.md.

# Load once. A collector started by powershell.exe -File loads this normally;
# the test harness loads it first, swaps the adapters, and then runs a
# collector, which must not put the real adapters back.
if (Get-Command -Name 'Invoke-WfCollectorScript' -CommandType Function -ErrorAction SilentlyContinue) { return }

# ---------------------------------------------------------------------------
# Portable helpers
# ---------------------------------------------------------------------------

# Constants are functions, not script scoped variables: a function that is
# called from another script file would look a script variable up in that
# file's scope and not find it.
function Get-WfCollectorsVersion { return '1.0.0' }
function Get-WfManifestVersion { return '1.0.0' }
function Get-WfCollectorNamePattern { return '^[a-z][a-z0-9-]{1,40}$' }

function Test-WfObservedStatus {
    param([string]$Status)
    return ($Status -eq 'observed' -or $Status -eq 'observed_zero')
}

function Test-WfCollectorName {
    param([string]$Name)
    return [bool]($Name -cmatch (Get-WfCollectorNamePattern))
}

function Get-WfList {
    # @($null) is an array holding one null. This returns an empty array for
    # a missing value and an array for anything else.
    param($Value)
    if ($null -eq $Value) { return , @() }
    return , @($Value)
}

function ConvertTo-WfIdentifier {
    # bugcheck-history -> bugcheck_history, the form the manifest schema wants
    # for scenario and collector identifiers.
    param([string]$Name)
    return ($Name -replace '-', '_')
}

function ConvertTo-WfUtcString {
    # ISO 8601 UTC with seven fractional digits, the repository's timestamp form.
    param([datetime]$Value)
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-WfCompactUtc {
    param([datetime]$Value)
    return $Value.ToUniversalTime().ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-WfUtcString {
    param([string]$Text)
    $styles = [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal'
    return [datetime]::Parse($Text, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Format-WfSystemTime {
    # The event XML carries TimeCreated/@SystemTime in UTC. Windows versions
    # differ in how many fractional digits they print, and the decoded table
    # allows at most seven, so longer fractions are cut (never rounded) and a
    # missing fraction is left alone. Returns $null for text that is not a
    # UTC timestamp.
    param($Text)
    if ($null -eq $Text) { return $null }
    $m = [regex]::Match([string]$Text, '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$')
    if (-not $m.Success) { return $null }
    $fraction = $m.Groups[2].Value
    if ($fraction.Length -gt 7) { $fraction = $fraction.Substring(0, 7) }
    if ($fraction.Length -eq 0) { return ($m.Groups[1].Value + 'Z') }
    return ($m.Groups[1].Value + '.' + $fraction + 'Z')
}

function ConvertTo-WfScalar {
    # One event data value as a JSON scalar (string, number, boolean, or null),
    # which is what schemas/decoded/eventlog_events.schema.json allows inside
    # "properties". Byte arrays become upper case hex, other collections a
    # "; " joined string, and anything else its invariant string form.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64]) { return [int64]$Value }
    if ($Value -is [uint64]) {
        if ($Value -le [uint64][int64]::MaxValue) { return [int64]$Value }
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { return $number.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        return $number
    }
    if ($Value -is [datetime]) { return (ConvertTo-WfUtcString -Value $Value) }
    if ($Value -is [byte[]]) { return ([System.BitConverter]::ToString($Value) -replace '-', '') }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $Value) {
            $scalar = ConvertTo-WfScalar -Value $item
            if ($null -eq $scalar) { $parts.Add('') } else { $parts.Add([string]$scalar) }
        }
        return ($parts.ToArray() -join '; ')
    }
    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function ConvertTo-WfJsonValue {
    # Like ConvertTo-WfScalar, but a collection stays a JSON array. Used for
    # WMI property values, which may be string arrays.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [byte[]]) { return (ConvertTo-WfScalar -Value $Value) }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) { $items.Add((ConvertTo-WfScalar -Value $item)) }
        return , $items.ToArray()
    }
    return (ConvertTo-WfScalar -Value $Value)
}

function Get-WfSha256OfText {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
        return (([System.BitConverter]::ToString($sha.ComputeHash($bytes))) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-WfSha256OfFile {
    # Get-FileHash is available in Windows PowerShell 4.0 and later and
    # defaults to SHA256:
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-WfShortMachineId {
    # The manifest wants an opaque, stable machine id. It is a SHA-256 of a
    # seed (the SMBIOS UUID when readable, else the host name), so the id is
    # stable for one machine and carries no readable hardware identifier.
    param([string]$Seed)
    $digest = Get-WfSha256OfText -Text ('wf-machine:' + $Seed)
    return [ordered]@{ machine_id = $digest.Substring(0, 32); short = $digest.Substring(0, 8) }
}

function Write-WfTextFile {
    # UTF-8 without a byte order mark. Set-Content -Encoding UTF8 writes a
    # mark in Windows PowerShell 5.1, so the .NET call is used instead.
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function ConvertTo-WfJsonString {
    # A JSON string literal in plain ASCII: everything outside the printable
    # ASCII range is written as \uXXXX, so the text survives any console or
    # file encoding between the PC and the reader.
    param([string]$Text)
    $escaped = $Text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    if ($escaped -match '[^\x20-\x7e]') {
        $builder = New-Object System.Text.StringBuilder
        foreach ($char in $escaped.ToCharArray()) {
            $code = [int]$char
            if ($code -lt 32 -or $code -gt 126) { $null = $builder.Append('\u' + $code.ToString('x4')) }
            else { $null = $builder.Append($char) }
        }
        $escaped = $builder.ToString()
    }
    return ('"' + $escaped + '"')
}

function ConvertTo-WfJson {
    # Serialises maps, lists and scalars to JSON. The collectors do not use
    # ConvertTo-Json. Its default depth is 2:
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-5.1
    # and in Windows PowerShell it writes an array that carries an invisible
    # [psobject] wrapper (output of a cmdlet, for example) as an object with
    # "value" and "Count" members, which PowerShell 6 and later no longer do:
    # https://github.com/PowerShell/PowerShell/issues/3153
    # https://github.com/PowerShell/PowerShell/issues/5579
    # That difference cannot be tested off Windows, so this writer depends on
    # no version specific behaviour.
    # -Indent -1 writes one line; -Indent 0 or more writes indented text.
    param($Value, [int]$Indent = -1)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-WfJsonString -Text $Value) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or
        $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) { return $Value.ToString($invariant) }
    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { return 'null' }
        return $number.ToString('R', $invariant)
    }
    if ($Value -is [datetime]) { return (ConvertTo-WfJsonString -Text (ConvertTo-WfUtcString -Value $Value)) }
    $pretty = ($Indent -ge 0)
    $childIndent = -1
    $open = ''
    $close = ''
    $separator = ','
    if ($pretty) {
        $childIndent = $Indent + 1
        $open = "`n" + ('  ' * $childIndent)
        $close = "`n" + ('  ' * $Indent)
        $separator = ',' + $open
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $members = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in $Value.Keys) {
            $colon = ':'
            if ($pretty) { $colon = ': ' }
            $members.Add((ConvertTo-WfJsonString -Text ([string]$key)) + $colon + (ConvertTo-WfJson -Value $Value[$key] -Indent $childIndent))
        }
        if ($members.Count -eq 0) { return '{}' }
        return ('{' + $open + ($members.ToArray() -join $separator) + $close + '}')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $Value) { $items.Add((ConvertTo-WfJson -Value $item -Indent $childIndent)) }
        if ($items.Count -eq 0) { return '[]' }
        return ('[' + $open + ($items.ToArray() -join $separator) + $close + ']')
    }
    return (ConvertTo-WfJsonString -Text ([string]$Value))
}

function Write-WfJsonFile {
    param([string]$Path, $Object)
    Write-WfTextFile -Path $Path -Text ((ConvertTo-WfJson -Value $Object -Indent 0) + "`n")
}

function Write-WfJsonArrayFile {
    # Writes a JSON array with one element per line. Each element is
    # serialised on its own so that a single element stays inside an array
    # (the pipeline would unwrap it) and so that the file has a stable shape:
    # element n of the array is what a decoder cites as index:<n>.
    param([string]$Path, $Items)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Items)) { $lines.Add((ConvertTo-WfJson -Value $item)) }
    if ($lines.Count -eq 0) {
        Write-WfTextFile -Path $Path -Text "[]`n"
    } else {
        Write-WfTextFile -Path $Path -Text ("[`n" + ($lines.ToArray() -join ",`n") + "`n]`n")
    }
}

function Build-WfEventQueryXml {
    # A structured XML query with one Select per predicate. Each predicate is
    # the inside of a System[...] test. The time bound uses timediff, which
    # Microsoft documents as the way to select "the last N milliseconds":
    # https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events
    # The same text is given to EventLogQuery and, as a file, to
    # wevtutil epl /sq:true, so both exports come from one query.
    param([string]$Channel, [string[]]$Predicates, [int64]$WindowMilliseconds)
    $channelText = [System.Security.SecurityElement]::Escape($Channel)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<QueryList>')
    $lines.Add(('  <Query Id="0" Path="{0}">' -f $channelText))
    foreach ($predicate in $Predicates) {
        $xpath = '*[System[{0} and TimeCreated[timediff(@SystemTime) <= {1}]]]' -f $predicate, $WindowMilliseconds
        $lines.Add(('    <Select Path="{0}">{1}</Select>' -f $channelText, [System.Security.SecurityElement]::Escape($xpath)))
    }
    $lines.Add('  </Query>')
    $lines.Add('</QueryList>')
    return (($lines.ToArray() -join "`n") + "`n")
}

function Resolve-WfSourceStatus {
    # The measurement status of one source, decided from what the collector
    # itself saw (docs/contracts/measurement-status.md section 2, rule 3).
    #
    # The one rule that needs care is the quiet window. Zero matching records
    # is reported as observed_zero only when the oldest record the source
    # still holds is known, because a log that wrapped or was cleared looks
    # exactly like a quiet one. The range the claim covers starts at the later
    # of the requested window start and that oldest record, and is returned
    # as CoveredStartUtc so the manifest can state it. When the oldest record
    # is unknown there is no proof of coverage and the status is
    # capture_failed. A source whose query rests on a provider name that
    # Microsoft does not document (QuietClaimVerified false) never reports
    # observed_zero either: records it finds are evidence, an empty result
    # is not.
    param(
        [string]$ReadErrorKind,
        [string]$ReadErrorMessage,
        [int]$RecordCount = 0,
        [bool]$Truncated = $false,
        $OldestRecordUtc = $null,
        $EarliestExportedUtc = $null,
        [datetime]$WindowStartUtc,
        [bool]$QuietClaimVerified = $true,
        [string]$TruncationDetail = ''
    )
    $result = [ordered]@{ Status = $null; Reason = $null; CoveredStartUtc = $null; ExpectationMet = $null }
    if ($ReadErrorKind) {
        $result.ExpectationMet = $false
        switch ($ReadErrorKind) {
            'not_found' { $result.Status = 'unsupported'; $result.Reason = 'the source does not exist on this machine: ' + $ReadErrorMessage }
            'access_denied' { $result.Status = 'not_collected'; $result.Reason = 'preflight failed, the account cannot read the source: ' + $ReadErrorMessage }
            'preflight' { $result.Status = 'not_collected'; $result.Reason = 'preflight failed, the source could not be opened: ' + $ReadErrorMessage }
            default { $result.Status = 'capture_failed'; $result.Reason = 'the read started and then failed: ' + $ReadErrorMessage }
        }
        return $result
    }
    if ($null -ne $OldestRecordUtc -and ([datetime]$OldestRecordUtc) -gt $WindowStartUtc) {
        $result.CoveredStartUtc = [datetime]$OldestRecordUtc
    } elseif ($null -ne $OldestRecordUtc) {
        $result.CoveredStartUtc = $WindowStartUtc
    } elseif ($null -ne $EarliestExportedUtc) {
        $result.CoveredStartUtc = [datetime]$EarliestExportedUtc
    }
    if ($Truncated) {
        $result.Status = 'capture_failed'
        $result.Reason = 'the export was cut at its cap, so the artifact is not the complete set of matching records: ' + $TruncationDetail
        $result.ExpectationMet = $false
        return $result
    }
    if ($RecordCount -gt 0) {
        $result.Status = 'observed'
        $result.ExpectationMet = $true
        return $result
    }
    if ($null -eq $OldestRecordUtc) {
        $result.Status = 'capture_failed'
        $result.Reason = 'zero matching records, and the oldest record the source still holds could not be established, so there is no proof that the source covers any part of the window'
        $result.ExpectationMet = $false
        return $result
    }
    if (-not $QuietClaimVerified) {
        $result.Status = 'capture_failed'
        $result.Reason = 'zero matching records, but Microsoft does not document which provider logs this signal, so an empty result is not accepted as a quiet window until the verification step in collectors/windows/README.md has been done on this machine'
        $result.ExpectationMet = $false
        return $result
    }
    $result.Status = 'observed_zero'
    $result.ExpectationMet = $true
    return $result
}

function Get-WfSummaryStatus {
    # ok: every source is observed or observed_zero.
    # partial: the bundle is complete as a container, at least one source is
    #   observed or observed_zero, and at least one is not.
    # failed: no source is observed or observed_zero.
    param([string[]]$Statuses)
    $all = @($Statuses)
    $good = @($all | Where-Object { Test-WfObservedStatus -Status $_ })
    if ($all.Count -gt 0 -and $good.Count -eq $all.Count) { return 'ok' }
    if ($good.Count -gt 0) { return 'partial' }
    return 'failed'
}

function ConvertTo-WfSummaryLine {
    # The seam with the dispatcher: exactly these four keys, one line.
    param([string]$Collector, [string]$Status, [string]$Bundle, [int]$Artifacts)
    $summary = [ordered]@{ collector = $Collector; status = $Status; bundle = $Bundle; artifacts = $Artifacts }
    return (ConvertTo-WfJson -Value $summary)
}

function Resolve-WfBundleRoot {
    # .NET file calls resolve relative paths against the process directory,
    # not the PowerShell location, so the output directory is made absolute
    # once and every file path is built from it.
    param([string]$OutputDirectory)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
}

function Join-WfBundlePath {
    # Bundle relative paths always use forward slashes (the manifest schema
    # requires ^raw/); this turns one into a file system path.
    param([string]$BundleRoot, [string]$RelativePath)
    $path = $BundleRoot
    foreach ($part in ($RelativePath -split '/')) { $path = [System.IO.Path]::Combine($path, $part) }
    return $path
}

function New-WfBundleLayout {
    # raw/ and logs/ from docs/contracts/bundle.md section 1. A directory
    # that already holds a manifest is a finished bundle and is never
    # written into again, because raw/ is immutable after capture.
    param([string]$BundleRoot)
    if (Test-Path -LiteralPath (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'manifest.json')) {
        throw ('the output directory already holds a bundle (manifest.json exists): ' + $BundleRoot)
    }
    if (Test-Path -LiteralPath (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'raw')) {
        throw ('the output directory already holds a raw directory; a collector only writes into a fresh directory: ' + $BundleRoot)
    }
    foreach ($relative in @('raw', 'logs')) {
        $null = New-Item -ItemType Directory -Force -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relative)
    }
}

function Get-WfArtifactRecords {
    # Lists every file under raw/<source id>/ with its byte count and SHA-256.
    # The list comes from the directory, not from what the code meant to
    # write, so a file under raw/ can never be missing from the manifest.
    param([string]$BundleRoot, [string]$SourceId, [hashtable]$Roles)
    $relativeDir = 'raw/' + $SourceId
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $records = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $dir)) { return , $records.ToArray() }
    $files = @(Get-ChildItem -LiteralPath $dir -File -Recurse | Sort-Object -Property FullName)
    foreach ($file in $files) {
        $tail = $file.FullName.Substring($dir.Length).TrimStart('\', '/') -replace '\\', '/'
        $role = 'other'
        if ($Roles -and $Roles.ContainsKey($tail)) { $role = $Roles[$tail] }
        $records.Add([ordered]@{
                path   = $relativeDir + '/' + $tail
                bytes  = [int64]$file.Length
                sha256 = Get-WfSha256OfFile -Path $file.FullName
                role   = $role
            })
    }
    return , $records.ToArray()
}

function New-WfCollectorEntry {
    # One manifest collectors[] entry with every required key present, so a
    # source that fails early still yields a schema valid entry.
    param([string]$Id, [string]$Kind, [bool]$Required)
    return [ordered]@{
        id             = $Id
        kind           = $Kind
        required       = $Required
        status         = 'not_collected'
        status_reason  = 'the collector stopped before this source was read'
        preflight      = $null
        command        = $null
        started_utc    = $null
        stopped_utc    = $null
        exit_code      = $null
        config_hash    = $null
        filter_hash    = $null
        requested      = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = [ordered]@{} }
        enabled        = [ordered]@{ providers = $null; keywords = $null; stack_walk = $null; counters = $null; options = $null; verified_by = $null }
        events_lost    = $null
        buffers        = $null
        artifacts      = @()
        raw_time_range = $null
        expectation    = $null
        target_process = $null
    }
}

function New-WfTimeRange {
    param($StartUtc, [datetime]$EndUtc)
    if ($null -eq $StartUtc) { return $null }
    return [ordered]@{
        start  = ConvertTo-WfUtcString -Value ([datetime]$StartUtc)
        end    = ConvertTo-WfUtcString -Value $EndUtc
        domain = 'system_time'
        unit   = 'iso_utc'
    }
}

function Invoke-WfEventSource {
    # Reads one event log channel through one structured query and writes,
    # under raw/<id>/:
    #   query.xml           the exact query (role config, hashed as config_hash)
    #   channel_state.json  what the channel held and how it is configured (role report)
    #   events.json         the structured export, oldest first (role primary)
    #   events.evtx         the binary export from wevtutil epl (role other), when it succeeds
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$WindowDays,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [bool]$SkipEvtx,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $channel = [string]$Source['Channel']
    $providers = Get-WfList -Value $Source['Providers']
    $quietVerified = $true
    if ($Source.ContainsKey('QuietClaimVerified')) { $quietVerified = [bool]$Source['QuietClaimVerified'] }
    $entry = New-WfCollectorEntry -Id $id -Kind 'eventlog' -Required ([bool]$Source['Required'])
    $roles = @{ 'query.xml' = 'config'; 'channel_state.json' = 'report'; 'events.json' = 'primary'; 'events.evtx' = 'other' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $windowMs = [int64]$WindowDays * 86400000
        $windowStart = $started.AddDays(-1 * $WindowDays)
        $queryXml = Build-WfEventQueryXml -Channel $channel -Predicates (Get-WfList -Value $Source['Predicates']) -WindowMilliseconds $windowMs
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.xml')
        Write-WfTextFile -Path $queryPath -Text $queryXml
        $queryHash = Get-WfSha256OfFile -Path $queryPath
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = $queryHash }
        $entry.command = @('System.Diagnostics.Eventing.Reader.EventLogReader', $channel, ($relativeDir + '/query.xml'))
        $entry.requested = [ordered]@{
            providers  = @($providers)
            keywords   = @()
            stack_walk = @()
            counters   = @()
            options    = [ordered]@{
                channel            = $channel
                event_ids          = Get-WfList -Value $Source['EventIds']
                window_days        = $WindowDays
                window_start_utc   = ConvertTo-WfUtcString -Value $windowStart
                max_events         = $MaxEvents
                max_artifact_bytes = $MaxArtifactBytes
                evtx_export        = (-not $SkipEvtx)
                query_sha256       = $queryHash
            }
        }

        $state = Get-WfChannelState -Channel $channel
        $registered = Get-WfRegisteredProviderNames
        $providerState = [ordered]@{}
        $enabledProviders = $null
        if ($null -ne $registered) {
            $enabledProviders = New-Object 'System.Collections.Generic.List[string]'
            foreach ($provider in $providers) {
                $isRegistered = (@($registered) -contains $provider)
                $providerState[$provider] = $isRegistered
                if ($isRegistered) { $enabledProviders.Add($provider) }
            }
            $enabledProviders = $enabledProviders.ToArray()
        }
        $stateReport = [ordered]@{
            channel              = $channel
            read_at_utc          = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            state                = $state
            providers_registered = $providerState
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/channel_state.json')) -Object $stateReport

        $found = $state['found']
        $readable = [bool]$state['readable']
        $checks = @(
            [ordered]@{ name = 'channel_found'; ok = ($found -ne $false); detail = ('channel ' + $channel) },
            [ordered]@{ name = 'channel_readable'; ok = $readable; detail = $state['error'] }
        )
        $preflightOk = ($found -ne $false) -and $readable
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = $checks }

        $oldest = $null
        if ($state['oldest_record_time_utc']) { $oldest = ConvertFrom-WfUtcString -Text ([string]$state['oldest_record_time_utc']) }
        $read = $null
        $events = @()
        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $preflightOk) {
            if ($found -eq $false) { $readErrorKind = 'not_found' } elseif ($state['error_kind'] -eq 'access_denied') { $readErrorKind = 'access_denied' } else { $readErrorKind = 'preflight' }
            $readErrorMessage = [string]$state['error']
        } else {
            $read = Read-WfEventRecords -Channel $channel -QueryXml $queryXml -MaxEvents $MaxEvents -MaxBytes $MaxArtifactBytes
            if (-not $read['Ok']) {
                $readErrorKind = [string]$read['ErrorKind']
                if (-not $readErrorKind) { $readErrorKind = 'other' }
                $readErrorMessage = [string]$read['ErrorMessage']
            } else {
                # The reader returns newest first so that a cap keeps the most
                # recent records; the file is written oldest first.
                $events = Get-WfList -Value $read['Events']
                [array]::Reverse($events)
                Write-WfJsonArrayFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/events.json')) -Items $events
            }
        }
        $queriedAt = Get-WfUtcNow

        $evtx = [ordered]@{ Attempted = $false; Ok = $false; ExitCode = $null; Message = 'not attempted'; Command = $null }
        if ($preflightOk -and -not $readErrorKind -and -not $SkipEvtx) {
            $evtxPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/events.evtx')
            $evtx = Export-WfEvtx -QueryPath $queryPath -TargetPath $evtxPath -MaxBytes $MaxArtifactBytes
            if (-not $evtx['Ok']) {
                if (Test-Path -LiteralPath $evtxPath) { Remove-Item -LiteralPath $evtxPath -Force }
                $message = ('source ' + $id + ': the binary .evtx export was not produced (' + [string]$evtx['Message'] + '); events.json carries the full XML of every record')
                $Notes.Add($message)
                $Log.Add($message)
            }
        } elseif ($SkipEvtx) {
            $evtx['Message'] = 'skipped by -SkipEvtx'
        }

        $earliest = $null
        if (@($events).Count -gt 0) { $earliest = ConvertFrom-WfUtcString -Text ([string]$events[0]['time_created_utc']) }
        $truncated = $false
        if ($null -ne $read -and $read['Ok']) { $truncated = [bool]$read['Truncated'] }
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage `
            -RecordCount (@($events).Count) -Truncated $truncated -OldestRecordUtc $oldest -EarliestExportedUtc $earliest `
            -WindowStartUtc $windowStart -QuietClaimVerified $quietVerified `
            -TruncationDetail ('cap is ' + $MaxEvents + ' records or ' + $MaxArtifactBytes + ' bytes; the newest records were kept')
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
        $covered = $resolved['CoveredStartUtc']
        $entry.raw_time_range = New-WfTimeRange -StartUtc $covered -EndUtc $queriedAt
        $coveredText = $null
        if ($null -ne $covered) { $coveredText = ConvertTo-WfUtcString -Value ([datetime]$covered) }
        $entry.enabled = [ordered]@{
            providers   = $enabledProviders
            keywords    = @()
            stack_walk  = @()
            counters    = @()
            options     = [ordered]@{
                channel           = $channel
                query_accepted    = ($preflightOk -and -not $readErrorKind)
                window_start_utc  = $coveredText
                window_end_utc    = ConvertTo-WfUtcString -Value $queriedAt
                records_exported  = @($events).Count
                truncated         = $truncated
                evtx_exported     = [bool]$evtx['Ok']
                evtx_exit_code    = $evtx['ExitCode']
                evtx_message      = $evtx['Message']
                evtx_command      = $evtx['Command']
            }
            verified_by = 'EventLogReader accepted the query in query.xml; the oldest retained record and the provider list are in channel_state.json'
        }
        $detail = ('{0} records exported; requested window starts {1}; covered range starts {2}' -f @($events).Count, (ConvertTo-WfUtcString -Value $windowStart), $coveredText)
        if ($null -ne $oldest -and $oldest -gt $windowStart) {
            $message = ('source ' + $id + ': channel ' + $channel + ' only holds records from ' + $coveredText + ', later than the requested window start; nothing is claimed before that time')
            $Notes.Add($message)
            $Log.Add($message)
        }
        $entry.expectation = [ordered]@{
            declared = 'every record matching query.xml inside the covered range is exported without truncation, and an empty export is only called a quiet window when the oldest retained record proves the range was covered'
            met      = $resolved['ExpectationMet']
            detail   = $detail
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Invoke-WfCimSource {
    # Reads every instance of one WMI class and writes, under raw/<id>/:
    #   query.json    class, namespace and window (role config, hashed as config_hash)
    #   records.json  the instances as a JSON array (role primary)
    # A source with a TimeProperty is a history: instances inside the window
    # are exported and the oldest instance bounds the covered range. A source
    # without one is a snapshot taken at collection time.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$WindowDays,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $className = [string]$Source['ClassName']
    $namespace = 'root/cimv2'
    if ($Source['Namespace']) { $namespace = [string]$Source['Namespace'] }
    $timeProperty = $null
    if ($Source['TimeProperty']) { $timeProperty = [string]$Source['TimeProperty'] }
    $kind = 'other'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'query.json' = 'config'; 'records.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $exported = @()
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $windowStart = $started.AddDays(-1 * $WindowDays)
        $query = [ordered]@{ class = $className; namespace = $namespace; time_property = $timeProperty; window_days = $null; window_start_utc = $null; max_records = $MaxEvents }
        if ($timeProperty) {
            $query.window_days = $WindowDays
            $query.window_start_utc = ConvertTo-WfUtcString -Value $windowStart
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.command = @('Get-CimInstance', '-Namespace', $namespace, '-ClassName', $className)
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }

        $read = Get-WfCimRows -Namespace $namespace -ClassName $className
        $readAt = Get-WfUtcNow
        $readErrorKind = ''
        $readErrorMessage = ''
        $rows = @()
        if (-not $read['Ok']) {
            $readErrorKind = [string]$read['ErrorKind']
            if (-not $readErrorKind) { $readErrorKind = 'other' }
            $readErrorMessage = [string]$read['ErrorMessage']
        } else {
            $rows = Get-WfList -Value $read['Rows']
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value $readAt
            checks = @([ordered]@{ name = 'class_readable'; ok = (-not $readErrorKind); detail = $(if ($readErrorKind) { $readErrorMessage } else { $namespace + ':' + $className }) })
        }

        $oldest = $null
        $truncated = $false
        if (-not $readErrorKind) {
            if ($timeProperty) {
                $inWindow = New-Object 'System.Collections.Generic.List[object]'
                $index = 0
                foreach ($row in $rows) {
                    $index += 1
                    $text = $row[$timeProperty]
                    if (-not $text) { continue }
                    $when = ConvertFrom-WfUtcString -Text ([string]$text)
                    if ($null -eq $oldest -or $when -lt $oldest) { $oldest = $when }
                    if ($when -ge $windowStart) { $inWindow.Add([pscustomobject]@{ When = $when; Index = $index; Row = $row }) }
                }
                $exported = @($inWindow.ToArray() | Sort-Object -Property When, Index | ForEach-Object { $_.Row })
            } else {
                $exported = $rows
                $oldest = $started
            }
            if (@($exported).Count -gt $MaxEvents) {
                # Keep the newest records (a history is sorted oldest first).
                $truncated = $true
                $exported = @($exported | Select-Object -Last $MaxEvents)
            }
            $recordsPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/records.json')
            Write-WfJsonArrayFile -Path $recordsPath -Items $exported
            if ((Get-Item -LiteralPath $recordsPath).Length -gt $MaxArtifactBytes) {
                $truncated = $true
                Remove-Item -LiteralPath $recordsPath -Force
                $exported = @()
                $Log.Add('source ' + $id + ': records.json exceeded the byte cap and was removed')
            }
        }

        if (-not $readErrorKind -and -not $timeProperty -and @($exported).Count -eq 0 -and -not $truncated) {
            $entry.status = 'capture_failed'
            $entry.status_reason = 'the class returned no instances; a snapshot of this class is never empty on a working machine, so this is treated as a failed read and not as an observation'
            $entry.expectation = [ordered]@{ declared = 'the class returns at least one instance'; met = $false; detail = '0 instances' }
            $entry.raw_time_range = $null
        } else {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage `
                -RecordCount (@($exported).Count) -Truncated $truncated -OldestRecordUtc $oldest `
                -WindowStartUtc $windowStart -QuietClaimVerified $true `
                -TruncationDetail ('cap is ' + $MaxEvents + ' records or ' + $MaxArtifactBytes + ' bytes; the newest records were kept')
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $covered = $resolved['CoveredStartUtc']
            if (-not $timeProperty -and -not $readErrorKind) { $covered = $readAt }
            $entry.raw_time_range = New-WfTimeRange -StartUtc $covered -EndUtc $readAt
            $coveredText = $null
            if ($null -ne $covered) { $coveredText = ConvertTo-WfUtcString -Value ([datetime]$covered) }
            if ($timeProperty) {
                $entry.expectation = [ordered]@{
                    declared = 'every instance inside the covered range is exported without truncation, and an empty export is only called a quiet window when the oldest instance proves the range was covered'
                    met      = $resolved['ExpectationMet']
                    detail   = ('{0} of {1} instances fall inside the window; covered range starts {2}' -f @($exported).Count, @($rows).Count, $coveredText)
                }
                if ($null -ne $oldest -and $oldest -gt $windowStart) {
                    $message = ('source ' + $id + ': ' + $className + ' only holds instances from ' + $coveredText + ', later than the requested window start; nothing is claimed before that time')
                    $Notes.Add($message)
                    $Log.Add($message)
                }
            } else {
                $entry.expectation = [ordered]@{ declared = 'the class returns at least one instance'; met = $resolved['ExpectationMet']; detail = ('{0} instances' -f @($exported).Count) }
            }
            $enabledOptions = [ordered]@{ class = $className; namespace = $namespace; time_property = $timeProperty; window_days = $query.window_days; window_start_utc = $null; records_exported = @($exported).Count; truncated = $truncated }
            if ($timeProperty) { $enabledOptions.window_start_utc = $coveredText }
            $entry.enabled = [ordered]@{
                providers = @(); keywords = @(); stack_walk = @(); counters = @()
                options = $enabledOptions
                verified_by = 'Get-CimInstance returned without error; the instance count and oldest instance are in the expectation detail'
            }
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        $exported = @()
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @($exported) }
}

function ConvertTo-WfMachineDrivers {
    # manifest.machine.drivers from Win32_PnPSignedDriver rows. Property names
    # are the documented ones:
    # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394354(v=vs.85)
    param($Rows, [int]$Limit = 2000)
    $drivers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in @($Rows)) {
        if ($drivers.Count -ge $Limit) { break }
        $name = $row['DeviceName']
        if (-not $name) { continue }
        $drivers.Add([ordered]@{
                name     = [string]$name
                version  = $row['DriverVersion']
                provider = $row['DriverProviderName']
                class    = $row['DeviceClass']
            })
    }
    return , $drivers.ToArray()
}

function Get-WfFallbackMachineInfo {
    # The machine section when the Windows inventory itself fails: only what
    # .NET reports about the running process, with null everywhere else. A
    # collector should still deliver its evidence when the inventory breaks.
    $hostname = [System.Environment]::MachineName
    $ids = Get-WfShortMachineId -Seed $hostname
    $version = [System.Environment]::OSVersion.Version
    $now = [datetime]::Now
    $zone = [System.TimeZoneInfo]::Local
    return [ordered]@{
        machine_id_short = $ids['short']
        qpc_frequency_hz = $null
        boot_time_utc    = $null
        machine          = [ordered]@{
            machine_id   = $ids['machine_id']
            hostname     = $hostname
            os           = [ordered]@{ caption = 'not recorded'; version = $version.ToString(); build = [int]$version.Build; ubr = $null; display_version = $null; architecture = 'not recorded'; edition = $null }
            cpu          = [ordered]@{ name = 'not recorded'; logical_processors = [int][System.Environment]::ProcessorCount; qpc_frequency_hz = $null }
            memory_bytes = $null
            gpus         = @()
            bios         = [ordered]@{ vendor = $null; version = $null; release_date = $null }
            board        = [ordered]@{ manufacturer = $null; product = $null }
            drivers      = @()
            time_zone    = [ordered]@{ name = [string]$zone.Id; utc_offset_minutes = [int]$zone.GetUtcOffset($now).TotalMinutes; dst_active = [bool]$zone.IsDaylightSavingTime($now) }
        }
    }
}

function Invoke-WfCollector {
    # Runs one collector definition and writes the whole bundle. Returns the
    # summary fields. Throws only when the bundle cannot be written at all.
    param(
        [hashtable]$Definition,
        [string]$OutputDirectory,
        [int]$WindowDays = 30,
        [int]$MaxEvents = 5000,
        [int64]$MaxArtifactBytes = 67108864,
        [bool]$SkipEvtx = $false,
        [string]$CollectorPath = ''
    )
    $name = [string]$Definition['Name']
    if (-not (Test-WfCollectorName -Name $name)) { throw ('collector name does not match ' + (Get-WfCollectorNamePattern) + ': ' + $name) }
    if ($WindowDays -lt 1 -or $WindowDays -gt 365) { throw 'WindowDays must be between 1 and 365' }
    if ($MaxEvents -lt 1 -or $MaxEvents -gt 100000) { throw 'MaxEvents must be between 1 and 100000' }
    if ($MaxArtifactBytes -lt 1048576 -or $MaxArtifactBytes -gt 1073741824) { throw 'MaxArtifactBytes must be between 1 MiB and 1 GiB' }
    $sources = Get-WfList -Value $Definition['Sources']
    if ($sources.Count -lt 1) { throw 'a collector definition needs at least one source' }

    $bundleRoot = Resolve-WfBundleRoot -OutputDirectory $OutputDirectory
    New-WfBundleLayout -BundleRoot $bundleRoot
    $log = New-Object 'System.Collections.Generic.List[string]'
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $start = Get-WfUtcNow
    $scenarioId = ConvertTo-WfIdentifier -Name $name
    # A collector made only of snapshot sources has no time window.
    $windowed = $false
    $readsEventLog = $false
    foreach ($source in $sources) {
        if ([string]$source['Type'] -eq 'eventlog') { $windowed = $true; $readsEventLog = $true }
        elseif ($source['TimeProperty']) { $windowed = $true }
    }
    $windowText = 'no time window (snapshot)'
    if ($windowed) { $windowText = ('window {0} days' -f $WindowDays) }
    $log.Add(('{0} collector {1} version {2}, helper version {3}, {4}' -f (ConvertTo-WfUtcString -Value $start), $name, [string]$Definition['Version'], (Get-WfCollectorsVersion), $windowText))

    $machineInfo = $null
    try {
        $machineInfo = Get-WfMachineInfo
    } catch {
        $message = 'the machine inventory failed and only the values .NET reports are recorded: ' + $_.Exception.Message
        $notes.Add($message)
        $log.Add($message)
        $machineInfo = Get-WfFallbackMachineInfo
    }
    $account = Get-WfAccountInfo
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $driverRows = $null
    foreach ($source in $sources) {
        $type = [string]$source['Type']
        if ($type -eq 'eventlog') {
            $result = Invoke-WfEventSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -SkipEvtx $SkipEvtx -Log $log -Notes $notes
        } elseif ($type -eq 'cim') {
            $result = Invoke-WfCimSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -Log $log -Notes $notes
            if ($source['FillsMachineDrivers']) { $driverRows = $result['Rows'] }
        } else {
            throw ('unknown source type: ' + $type)
        }
        $entries.Add($result['Entry'])
    }
    $stop = Get-WfUtcNow

    $machine = $machineInfo['machine']
    if ($null -ne $driverRows) { $machine['drivers'] = ConvertTo-WfMachineDrivers -Rows $driverRows }
    $statuses = @($entries.ToArray() | ForEach-Object { [string]$_['status'] })
    $summaryStatus = Get-WfSummaryStatus -Statuses $statuses
    $artifactCount = 0
    foreach ($entry in $entries) { $artifactCount += @($entry['artifacts']).Count }

    $tools = @()
    try {
        $tools = Get-WfToolInventory -CollectorName $name -CollectorVersion ([string]$Definition['Version']) -CollectorPath $CollectorPath
    } catch {
        $message = 'the tool inventory failed and is recorded as empty: ' + $_.Exception.Message
        $notes.Add($message)
        $log.Add($message)
    }

    $allNotes = New-Object 'System.Collections.Generic.List[string]'
    $allNotes.Add(('Read only collector {0} version {1}: {2}' -f $name, [string]$Definition['Version'], [string]$Definition['Question']))
    $allNotes.Add(('Ran as {0}; elevated: {1}; member of Event Log Readers (S-1-5-32-573): {2}.' -f $account['name'], $account['elevated'], $account['event_log_readers']))
    $allNotes.Add('The bundle directory is created and named by the dispatcher; bundle_id in this manifest is the authoritative id.')
    if ($readsEventLog) {
        $allNotes.Add('Windows are bounded with timediff, which the Event Log service evaluates when each query runs, so a window starts at most the run time of the collector later than the recorded window_start_utc.')
    }
    $allNotes.Add('This bundle holds capture output only. Decoded tables, evidence rows and a verdict are written later, off the machine.')
    foreach ($note in $notes) { $allNotes.Add($note) }

    $manifest = [ordered]@{
        manifest_version   = Get-WfManifestVersion
        bundle_id          = ('{0}_{1}_{2}' -f (ConvertTo-WfCompactUtc -Value $start), $scenarioId, $machineInfo['machine_id_short'])
        created_utc        = ConvertTo-WfUtcString -Value $stop
        scenario           = [ordered]@{
            id                   = $scenarioId
            version              = [string]$Definition['Version']
            requested_duration_s = $(if ($windowed) { [int64]$WindowDays * 86400 } else { 0 })
            target_process       = $null
            marks                = @()
        }
        capture            = [ordered]@{
            start_utc            = ConvertTo-WfUtcString -Value $start
            stop_utc             = ConvertTo-WfUtcString -Value $stop
            orchestrator         = 'wf-collector:' + $name
            orchestrator_version = Get-WfCollectorsVersion
            elevated             = $account['elevated']
            incomplete           = ($summaryStatus -ne 'ok')
        }
        machine            = $machine
        collectors         = @($entries.ToArray())
        calibration        = [ordered]@{
            status           = 'not_applicable'
            method           = 'none: this collector reads historical records that carry their own UTC system time, so there is no QPC session to calibrate'
            qpc_frequency_hz = $machineInfo['qpc_frequency_hz']
            expected_pairs   = 0
            pairs            = @()
            missing_pairs    = 0
            time_adjustment  = [ordered]@{ start = $null; stop = $null }
            boot_time_utc    = $machineInfo['boot_time_utc']
        }
        tools              = $tools
        symbols            = [ordered]@{ symbol_path = $null; cache_path = $null; dbghelp_version = $null }
        checksum_algorithm = 'sha256'
        notes              = @($allNotes.ToArray())
    }
    Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'manifest.json') -Object $manifest

    $log.Add(('{0} manifest written: bundle {1}, status {2}, {3} artifacts' -f (ConvertTo-WfUtcString -Value $stop), $manifest.bundle_id, $summaryStatus, $artifactCount))
    $summaryLine = ConvertTo-WfSummaryLine -Collector $name -Status $summaryStatus -Bundle $OutputDirectory -Artifacts $artifactCount
    Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'logs/summary.json') -Text ($summaryLine + "`n")
    Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'logs/collector.log') -Text (($log.ToArray() -join "`n") + "`n")
    foreach ($note in $notes) { Write-WfStderrLine -Text $note }
    return [ordered]@{ Status = $summaryStatus; Artifacts = $artifactCount; SummaryLine = $summaryLine; BundleId = $manifest.bundle_id }
}

function Invoke-WfCollectorScript {
    # The entry point every collector script calls. Prints exactly one JSON
    # line on stdout, sends diagnostics to stderr, and returns the exit code:
    # 0 when the bundle is complete (status ok or partial), 1 otherwise.
    param(
        [hashtable]$Definition,
        [string]$OutputDirectory,
        [int]$WindowDays = 30,
        [int]$MaxEvents = 5000,
        [int64]$MaxArtifactBytes = 67108864,
        [bool]$SkipEvtx = $false,
        [string]$CollectorPath = ''
    )
    $name = [string]$Definition['Name']
    $exitCode = 1
    $line = $null
    try {
        # Anything a callee writes to the success stream by accident is kept
        # away from stdout: only the last object, the result, is used.
        $output = @(Invoke-WfCollector -Definition $Definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays `
                -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -SkipEvtx $SkipEvtx -CollectorPath $CollectorPath)
        $result = $output[$output.Count - 1]
        $line = [string]$result['SummaryLine']
        if ($result['Status'] -ne 'failed') { $exitCode = 0 }
    } catch {
        Write-WfStderrLine -Text ('collector ' + $name + ' failed: ' + $_.Exception.Message)
        $line = ConvertTo-WfSummaryLine -Collector $name -Status 'failed' -Bundle $OutputDirectory -Artifacts 0
        $exitCode = 1
    }
    Write-WfStdoutLine -Text $line
    return $exitCode
}

# ---------------------------------------------------------------------------
# Windows adapters. Everything below touches Windows and is replaced by
# collectors/windows/tests/SyntheticBackend.ps1 in the test suite.
# ---------------------------------------------------------------------------

function Get-WfUtcNow {
    return [datetime]::UtcNow
}

function Write-WfStdoutLine {
    # [Console]::Out writes the exact text and one newline to the process
    # standard output, with no formatting or wrapping by the PowerShell host.
    param([string]$Text)
    [Console]::Out.WriteLine($Text)
}

function Write-WfStderrLine {
    param([string]$Text)
    [Console]::Error.WriteLine($Text)
}

function Get-WfCimFirst {
    # One instance of a Win32 class, or $null when the class cannot be read.
    # Local WMI read access is granted to Authenticated Users by default:
    # https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces
    param([string]$ClassName)
    try {
        return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)[0]
    } catch {
        return $null
    }
}

function Get-WfRegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

function Get-WfMachineInfo {
    # The manifest machine section. Every value that cannot be read is null;
    # the four values the schema requires as non null fall back to what .NET
    # reports about the running process.
    # Win32 classes: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
    # and https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/operating-system-classes
    $now = [datetime]::Now
    $os = Get-WfCimFirst -ClassName 'Win32_OperatingSystem'
    $system = Get-WfCimFirst -ClassName 'Win32_ComputerSystem'
    $product = Get-WfCimFirst -ClassName 'Win32_ComputerSystemProduct'
    $bios = Get-WfCimFirst -ClassName 'Win32_BIOS'
    $board = Get-WfCimFirst -ClassName 'Win32_BaseBoard'
    $processors = @()
    try { $processors = @(Get-CimInstance -ClassName 'Win32_Processor' -ErrorAction Stop) } catch { $processors = @() }
    $videoControllers = @()
    try { $videoControllers = @(Get-CimInstance -ClassName 'Win32_VideoController' -ErrorAction Stop) } catch { $videoControllers = @() }

    $hostname = [System.Environment]::MachineName
    $seed = $hostname
    if ($null -ne $product -and $product.UUID -and ($product.UUID -notmatch '^[0F-]+$')) { $seed = [string]$product.UUID }
    $ids = Get-WfShortMachineId -Seed $seed

    $osVersion = [System.Environment]::OSVersion.Version
    $caption = 'Windows'
    $version = $osVersion.ToString()
    $build = [int]$osVersion.Build
    $architecture = [string]$env:PROCESSOR_ARCHITECTURE
    if (-not $architecture) { $architecture = 'not recorded' }
    $bootTime = $null
    if ($null -ne $os) {
        if ($os.Caption) { $caption = ([string]$os.Caption).Trim() }
        if ($os.Version) { $version = [string]$os.Version }
        if ($os.BuildNumber) { $build = [int]$os.BuildNumber }
        if ($os.OSArchitecture) { $architecture = [string]$os.OSArchitecture }
        if ($os.LastBootUpTime) { $bootTime = ConvertTo-WfUtcString -Value $os.LastBootUpTime }
    }
    # UBR, DisplayVersion and EditionID are read from the registry when they
    # are present. Microsoft Learn does not document these value names, so
    # they are optional and null when absent (see README, unverified facts).
    $currentVersion = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = Get-WfRegistryValue -Path $currentVersion -Name 'UBR'
    if ($null -ne $ubr) { $ubr = [int]$ubr }

    $cpuName = 'not recorded'
    $logical = [System.Environment]::ProcessorCount
    if ($processors.Count -gt 0) {
        if ($processors[0].Name) { $cpuName = ([string]$processors[0].Name).Trim() }
        $sum = 0
        foreach ($processor in $processors) { if ($processor.NumberOfLogicalProcessors) { $sum += [int]$processor.NumberOfLogicalProcessors } }
        if ($sum -gt 0) { $logical = $sum }
    }
    $memory = $null
    if ($null -ne $system -and $system.TotalPhysicalMemory) { $memory = [int64]$system.TotalPhysicalMemory }

    $gpus = New-Object 'System.Collections.Generic.List[object]'
    foreach ($controller in $videoControllers) {
        if (-not $controller.Name) { continue }
        $driverDate = $null
        if ($controller.DriverDate) { $driverDate = ConvertTo-WfUtcString -Value $controller.DriverDate }
        $gpus.Add([ordered]@{ name = [string]$controller.Name; driver_version = $controller.DriverVersion; driver_date = $driverDate; device_id = $controller.PNPDeviceID })
    }
    $biosDate = $null
    if ($null -ne $bios -and $bios.ReleaseDate) { $biosDate = ConvertTo-WfUtcString -Value $bios.ReleaseDate }
    $zone = [System.TimeZoneInfo]::Local

    return [ordered]@{
        machine_id_short = $ids['short']
        qpc_frequency_hz = [int64][System.Diagnostics.Stopwatch]::Frequency
        boot_time_utc    = $bootTime
        machine          = [ordered]@{
            machine_id   = $ids['machine_id']
            hostname     = $hostname
            os           = [ordered]@{
                caption         = $caption
                version         = $version
                build           = $build
                ubr             = $ubr
                display_version = Get-WfRegistryValue -Path $currentVersion -Name 'DisplayVersion'
                architecture    = $architecture
                edition         = Get-WfRegistryValue -Path $currentVersion -Name 'EditionID'
            }
            cpu          = [ordered]@{ name = $cpuName; logical_processors = [int]$logical; qpc_frequency_hz = [int64][System.Diagnostics.Stopwatch]::Frequency }
            memory_bytes = $memory
            gpus         = @($gpus.ToArray())
            bios         = [ordered]@{
                vendor       = $(if ($null -ne $bios) { $bios.Manufacturer } else { $null })
                version      = $(if ($null -ne $bios) { $bios.SMBIOSBIOSVersion } else { $null })
                release_date = $biosDate
            }
            board        = [ordered]@{
                manufacturer = $(if ($null -ne $board) { $board.Manufacturer } else { $null })
                product      = $(if ($null -ne $board) { $board.Product } else { $null })
            }
            drivers      = @()
            time_zone    = [ordered]@{
                name               = [string]$zone.Id
                utc_offset_minutes = [int]$zone.GetUtcOffset($now).TotalMinutes
                dst_active         = [bool]$zone.IsDaylightSavingTime($now)
            }
        }
    }
}

function Get-WfAccountInfo {
    # Who the collector runs as. An SSH session on Windows keeps the
    # privileges of the account that authenticated:
    # https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell
    # WindowsPrincipal.IsInRole: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole
    $info = [ordered]@{ name = $null; elevated = $null; event_log_readers = $null }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $info.name = [string]$identity.Name
        $info.elevated = [bool]$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $readers = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-573')
        $info.event_log_readers = [bool]$principal.IsInRole($readers)
    } catch {
        Write-WfStderrLine -Text ('could not read the account identity: ' + $_.Exception.Message)
    }
    return $info
}

function Get-WfToolRecord {
    param([string]$Name, $Version, [string]$Path)
    $record = [ordered]@{ name = $Name; version = $Version; path = $Path; sha256 = $null }
    try {
        if ($Path -and (Test-Path -LiteralPath $Path)) { $record.sha256 = Get-WfSha256OfFile -Path $Path }
    } catch {
        $record.sha256 = $null
    }
    return $record
}

function Get-WfWevtutilPath {
    return [System.IO.Path]::Combine([string]$env:SystemRoot, 'System32', 'wevtutil.exe')
}

function Get-WfToolInventory {
    # manifest.tools: the interpreter, wevtutil, and the two script files that
    # ran, each with the SHA-256 of the exact bytes on disk.
    param([string]$CollectorName, [string]$CollectorVersion, [string]$CollectorPath)
    $tools = New-Object 'System.Collections.Generic.List[object]'
    $hostPath = $null
    try { $hostPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { $hostPath = $null }
    $tools.Add((Get-WfToolRecord -Name 'powershell' -Version $PSVersionTable.PSVersion.ToString() -Path $hostPath))
    $wevtutil = Get-WfWevtutilPath
    $wevtutilVersion = $null
    try { $wevtutilVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($wevtutil).FileVersion } catch { $wevtutilVersion = $null }
    $tools.Add((Get-WfToolRecord -Name 'wevtutil' -Version $wevtutilVersion -Path $wevtutil))
    $tools.Add((Get-WfToolRecord -Name ('collector:' + $CollectorName) -Version $CollectorVersion -Path $CollectorPath))
    $tools.Add((Get-WfToolRecord -Name 'collector-helper:_common.ps1' -Version (Get-WfCollectorsVersion) -Path ([System.IO.Path]::Combine($PSScriptRoot, '_common.ps1'))))
    return , $tools.ToArray()
}

function Get-WfEventReadErrorKind {
    # Exception classes documented under System.Diagnostics.Eventing.Reader:
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlognotfoundexception
    param($Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException]) { return 'not_found' }
        if ($current -is [System.UnauthorizedAccessException]) { return 'access_denied' }
        $current = $current.InnerException
    }
    return 'other'
}

function Get-WfChannelState {
    # What the channel holds right now. The oldest retained record is what
    # lets a later reader tell a quiet log from one that wrapped or was
    # cleared. The configuration values (log mode, maximum size, security
    # descriptor) are recorded when the account may read them and are null
    # otherwise; only the oldest record read decides found and readable.
    # EventLogSession.GetLogInformation and EventLogConfiguration:
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.getloginformation
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogconfiguration
    param([string]$Channel)
    $state = [ordered]@{
        found = $null; readable = $false; error = $null; error_kind = $null
        record_count = $null; oldest_record_number = $null; oldest_record_time_utc = $null
        file_size_bytes = $null; is_log_full = $null; last_write_time_utc = $null
        is_enabled = $null; log_mode = $null; maximum_size_bytes = $null; isolation = $null; security_descriptor = $null
        configuration_error = $null
    }
    $pathType = $null
    $reader = $null
    try {
        $pathType = [System.Diagnostics.Eventing.Reader.PathType]::LogName
        # A plain "*" query read forward returns the oldest record first.
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Channel, $pathType, '*')
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
        $record = $reader.ReadEvent()
        $state.found = $true
        $state.readable = $true
        if ($null -ne $record) {
            try {
                if ($null -ne $record.RecordId) { $state.oldest_record_number = [int64]$record.RecordId }
                if ($null -ne $record.TimeCreated) { $state.oldest_record_time_utc = ConvertTo-WfUtcString -Value $record.TimeCreated }
            } finally {
                $record.Dispose()
            }
        }
    } catch {
        $kind = Get-WfEventReadErrorKind -Exception $_.Exception
        $state.error = $_.Exception.Message
        $state.error_kind = $kind
        if ($kind -eq 'not_found') { $state.found = $false } elseif ($kind -eq 'access_denied') { $state.found = $true }
        return $state
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    try {
        $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation($Channel, $pathType)
        if ($null -ne $info.RecordCount) { $state.record_count = [int64]$info.RecordCount }
        if ($null -ne $info.FileSize) { $state.file_size_bytes = [int64]$info.FileSize }
        if ($null -ne $info.IsLogFull) { $state.is_log_full = [bool]$info.IsLogFull }
        if ($null -ne $info.LastWriteTime) { $state.last_write_time_utc = ConvertTo-WfUtcString -Value $info.LastWriteTime }
    } catch {
        $state.configuration_error = $_.Exception.Message
    }
    $configuration = $null
    try {
        $configuration = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel)
        $state.is_enabled = [bool]$configuration.IsEnabled
        $state.log_mode = [string]$configuration.LogMode
        $state.maximum_size_bytes = [int64]$configuration.MaximumSizeInBytes
        $state.isolation = [string]$configuration.LogIsolation
        $state.security_descriptor = [string]$configuration.SecurityDescriptor
    } catch {
        $state.configuration_error = $_.Exception.Message
    } finally {
        if ($null -ne $configuration) { $configuration.Dispose() }
    }
    return $state
}

function Get-WfRegisteredProviderNames {
    # Every provider registered on the machine, or $null when the list cannot
    # be read. EventLogSession.GetProviderNames:
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.getprovidernames
    try {
        return , @([System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetProviderNames())
    } catch {
        return $null
    }
}

function ConvertFrom-WfEventRecord {
    # One EventRecord as the element written to events.json. The field names
    # are the columns of schemas/decoded/eventlog_events.schema.json, plus
    # "xml", the complete event XML from EventRecord.ToXml(). The rendered
    # message and the level and task names depend on publisher metadata and
    # locale and may be unavailable, in which case they are null.
    # EventRecord: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord
    param($Record)
    $xmlText = $null
    try { $xmlText = $Record.ToXml() } catch { $xmlText = $null }
    $timeText = $null
    if ($xmlText) {
        $m = [regex]::Match($xmlText, 'TimeCreated\s+SystemTime\s*=\s*[''"]([^''"]+)[''"]')
        if ($m.Success) { $timeText = Format-WfSystemTime -Text $m.Groups[1].Value }
    }
    if (-not $timeText -and $null -ne $Record.TimeCreated) { $timeText = ConvertTo-WfUtcString -Value $Record.TimeCreated }
    $message = $null
    try { $message = $Record.FormatDescription() } catch { $message = $null }
    $levelDisplay = $null
    try { $levelDisplay = $Record.LevelDisplayName } catch { $levelDisplay = $null }
    $taskDisplay = $null
    try { $taskDisplay = $Record.TaskDisplayName } catch { $taskDisplay = $null }
    $userId = $null
    if ($null -ne $Record.UserId) { $userId = [string]$Record.UserId.Value }
    $properties = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($property in $Record.Properties) { $properties.Add((ConvertTo-WfScalar -Value $property.Value)) }
    } catch {
        $properties.Clear()
    }
    return [ordered]@{
        record_id        = $(if ($null -ne $Record.RecordId) { [int64]$Record.RecordId } else { $null })
        log_name         = [string]$Record.LogName
        provider_name    = [string]$Record.ProviderName
        event_id         = [int]$Record.Id
        version          = $(if ($null -ne $Record.Version) { [int]$Record.Version } else { $null })
        level            = $(if ($null -ne $Record.Level) { [int]$Record.Level } else { $null })
        level_display    = $levelDisplay
        task             = $(if ($null -ne $Record.Task) { [int]$Record.Task } else { $null })
        task_display     = $taskDisplay
        opcode           = $(if ($null -ne $Record.Opcode) { [int]$Record.Opcode } else { $null })
        keywords         = $(if ($null -ne $Record.Keywords) { [int64]$Record.Keywords } else { $null })
        time_created_utc = $timeText
        machine_name     = $Record.MachineName
        user_id          = $userId
        process_id       = $(if ($null -ne $Record.ProcessId) { [int]$Record.ProcessId } else { $null })
        thread_id        = $(if ($null -ne $Record.ThreadId) { [int]$Record.ThreadId } else { $null })
        message          = $message
        properties       = @($properties.ToArray())
        xml              = $xmlText
    }
}

function Read-WfEventRecords {
    # Runs the structured query and returns the records newest first, so that
    # a cap keeps the most recent ones. ReadEvent returns null when the query
    # has no more records, as in Microsoft's example:
    # https://learn.microsoft.com/en-us/previous-versions/bb671200(v=vs.90)
    # EventLogQuery.ReverseDirection:
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogquery.reversedirection
    param([string]$Channel, [string]$QueryXml, [int]$MaxEvents, [int64]$MaxBytes)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Events = @(); Truncated = $false }
    $events = New-Object 'System.Collections.Generic.List[object]'
    $reader = $null
    $approximateBytes = [int64]0
    try {
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $QueryXml)
        $query.ReverseDirection = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
        while ($true) {
            $record = $reader.ReadEvent()
            if ($null -eq $record) { break }
            try {
                if ($events.Count -ge $MaxEvents) { $result.Truncated = $true; break }
                $item = ConvertFrom-WfEventRecord -Record $record
                # The XML is the bulk of an element; twice its length is a
                # generous estimate of the element's size in events.json.
                $length = 512
                if ($item['xml']) { $length += 2 * ([string]$item['xml']).Length }
                if ($item['message']) { $length += ([string]$item['message']).Length }
                if (($approximateBytes + $length) -gt $MaxBytes) { $result.Truncated = $true; break }
                $approximateBytes += $length
                $events.Add($item)
            } finally {
                $record.Dispose()
            }
        }
        $result.Ok = $true
        $result.Events = $events.ToArray()
    } catch {
        $result.ErrorKind = Get-WfEventReadErrorKind -Exception $_.Exception
        $result.ErrorMessage = $_.Exception.Message
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    return $result
}

function Export-WfEvtx {
    # wevtutil epl <query file> <export file> /sq:true /ow:true exports the
    # records the structured query selects to a binary .evtx file:
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    # Microsoft does not say which rights the export needs beyond read access
    # to the channel, so a failure here is recorded and never fatal: the
    # structured export already holds the full XML of every record.
    # wevtutil is started directly, with no shell, and both output streams
    # are drained so the process cannot block on a full pipe.
    param([string]$QueryPath, [string]$TargetPath, [int64]$MaxBytes, [int]$TimeoutSeconds = 300)
    $wevtutil = Get-WfWevtutilPath
    $arguments = 'epl "{0}" "{1}" /sq:true /ow:true' -f $QueryPath, $TargetPath
    $result = [ordered]@{ Attempted = $true; Ok = $false; ExitCode = $null; Message = $null; Command = @($wevtutil, 'epl', $QueryPath, $TargetPath, '/sq:true', '/ow:true') }
    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $wevtutil
        $startInfo.Arguments = $arguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { $null = $_ }
            $result.Message = 'wevtutil did not finish within ' + $TimeoutSeconds + ' seconds and was stopped'
            return $result
        }
        $process.WaitForExit()
        $result.ExitCode = [int]$process.ExitCode
        $text = (([string]$stdout.Result) + ' ' + ([string]$stderr.Result)).Trim()
        if ($result.ExitCode -ne 0) {
            $result.Message = ('wevtutil exit code {0}: {1}' -f $result.ExitCode, $text)
            return $result
        }
        if (-not (Test-Path -LiteralPath $TargetPath)) {
            $result.Message = 'wevtutil exit code 0 but the export file does not exist'
            return $result
        }
        $size = (Get-Item -LiteralPath $TargetPath).Length
        if ($size -gt $MaxBytes) {
            $result.Message = ('the export is {0} bytes, above the cap of {1} bytes' -f $size, $MaxBytes)
            return $result
        }
        $result.Ok = $true
        $result.Message = 'exported'
    } catch {
        $result.Message = 'wevtutil could not be run: ' + $_.Exception.Message
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
    return $result
}

function Get-WfCimRows {
    # Every instance of a class, each as an ordered map of its properties with
    # dates as UTC text. CimException.NativeErrorCode names the failure:
    # https://learn.microsoft.com/en-us/dotnet/api/microsoft.management.infrastructure.cimexception.nativeerrorcode
    param([string]$Namespace, [string]$ClassName)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Rows = @() }
    try {
        $instances = @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop)
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($instance in $instances) {
            $row = [ordered]@{}
            foreach ($property in $instance.CimInstanceProperties) { $row[$property.Name] = ConvertTo-WfJsonValue -Value $property.Value }
            $rows.Add($row)
        }
        $result.Ok = $true
        $result.Rows = $rows.ToArray()
    } catch {
        $kind = 'other'
        $exception = $_.Exception
        if ($exception -is [Microsoft.Management.Infrastructure.CimException]) {
            $code = [string]$exception.NativeErrorCode
            if ($code -eq 'AccessDenied') { $kind = 'access_denied' }
            elseif ($code -eq 'InvalidClass' -or $code -eq 'InvalidNamespace' -or $code -eq 'NotFound') { $kind = 'not_found' }
        } elseif ($exception -is [System.UnauthorizedAccessException]) {
            $kind = 'access_denied'
        }
        $result.ErrorKind = $kind
        $result.ErrorMessage = $exception.Message
    }
    return $result
}
