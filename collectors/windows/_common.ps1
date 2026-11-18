# Shared helper for the named read only collectors in this directory.
#
# Every collector dot sources this file. Its name starts with an underscore so
# that it can never be mistaken for a collector: collector names match
# ^[a-z][a-z0-9-]{1,40}$ and this name does not.
#
# The file has two halves. The first half is portable logic (bundle layout,
# manifest, checksums, measurement status, the one line summary, the
# pseudonyms that keep other people's network names out of a bundle) and is
# what the Pester suite exercises off Windows. The second half is a small set
# of adapter functions that touch Windows (event log, WMI, wevtutil, netsh,
# one file under ProgramData, Plug and Play device properties, identity).
# The test suite replaces the adapters with synthetic ones; nothing else in
# this file calls a Windows only API.
#
# Source types a collector definition may use: eventlog, cim, command (a
# fixed netsh or powercfg query), file (one known file, summarised or copied
# read only), directory (the files of one known folder, hashed and versioned,
# never copied), registry (documented values under documented keys, read
# only, with their type and bytes; device hardware keys through the documented
# device key API), topology (the logical processor map through the documented
# API), pnp (present Plug and Play devices with their parent chain),
# unavailable (a question the collector cannot answer with a documented read
# only path, recorded as a status with its reason).
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
function Get-WfCollectorsVersion { return '1.2.0' }
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
        # Enumerated through the dictionary enumerator, not .Keys: PowerShell
        # resolves $map.Keys to an entry named "keys" when there is one.
        $members = New-Object 'System.Collections.Generic.List[string]'
        $enumerator = $Value.GetEnumerator()
        while ($enumerator.MoveNext()) {
            $colon = ':'
            if ($pretty) { $colon = ': ' }
            $members.Add((ConvertTo-WfJsonString -Text ([string]$enumerator.Key)) + $colon + (ConvertTo-WfJson -Value $enumerator.Value -Indent $childIndent))
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

function Get-WfJsonArrayBytes {
    # Size of the file Write-WfJsonLinesFile writes for these lines. The
    # writer emits plain ASCII, so one character is one byte:
    # "[\n" + lines joined by ",\n" + "\n]\n", or "[]\n" for no lines.
    param([int]$LineCount, [int64]$LineBytes)
    if ($LineCount -eq 0) { return [int64]3 }
    return [int64](5 + $LineBytes + 2 * ($LineCount - 1))
}

function Write-WfJsonLinesFile {
    # Writes a JSON array with one already serialised element per line, so
    # that element n of the array is what a decoder cites as index:<n> and a
    # single element stays inside an array.
    param([string]$Path, [string[]]$Lines)
    $all = @($Lines)
    if ($all.Count -eq 0) {
        Write-WfTextFile -Path $Path -Text "[]`n"
    } else {
        Write-WfTextFile -Path $Path -Text ("[`n" + ($all -join ",`n") + "`n]`n")
    }
}

function New-WfRowAccumulator {
    # Collects rows for one export while enforcing the two caps exactly: the
    # row count and the size of the file the rows will become. Every row is
    # serialised when it arrives, so the byte budget is the real one.
    param([int]$MaxRows, [int64]$MaxBytes)
    return @{
        MaxRows   = $MaxRows
        MaxBytes  = $MaxBytes
        Rows      = New-Object 'System.Collections.Generic.List[object]'
        Lines     = New-Object 'System.Collections.Generic.List[string]'
        LineBytes = [int64]0
        Truncated = $false
        Reason    = $null
    }
}

function Add-WfRow {
    # Returns $true when the row was kept and reading may continue, $false
    # when a cap was reached (the row is dropped and the accumulator records
    # why). The file size check counts the row's own bytes plus the separator
    # and wrapper the writer will add.
    param([hashtable]$Accumulator, $Row)
    if ($Accumulator.Rows.Count -ge $Accumulator.MaxRows) {
        $Accumulator.Truncated = $true
        $Accumulator.Reason = ('the cap of ' + $Accumulator.MaxRows + ' records was reached')
        return $false
    }
    $line = ConvertTo-WfJson -Value $Row
    $projected = Get-WfJsonArrayBytes -LineCount ($Accumulator.Lines.Count + 1) -LineBytes ($Accumulator.LineBytes + $line.Length)
    if ($projected -gt $Accumulator.MaxBytes) {
        $Accumulator.Truncated = $true
        $Accumulator.Reason = ('the export would exceed the cap of ' + $Accumulator.MaxBytes + ' bytes')
        return $false
    }
    $Accumulator.Rows.Add($Row)
    $Accumulator.Lines.Add($line)
    $Accumulator.LineBytes += $line.Length
    return $true
}

function Build-WfEventQueryXml {
    # A structured XML query with one Select per predicate. Each predicate is
    # the inside of a System[...] test. The time bound is a fixed interval
    # ending at -EndUtc: timediff(@SystemTime, <FILETIME literal>) is the
    # documented form with a literal second argument, positive when the
    # literal is the later time, so 0 <= timediff <= window selects exactly
    # [end - window, end] and a record raised after the query started cannot
    # join the result:
    # https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events
    # The same text is given to EventLogQuery and, as a file, to
    # wevtutil epl /sq:true, so both exports come from one query.
    param([string]$Channel, [string[]]$Predicates, [datetime]$EndUtc, [int64]$WindowMilliseconds)
    $channelText = [System.Security.SecurityElement]::Escape($Channel)
    $endFileTime = $EndUtc.ToUniversalTime().ToFileTimeUtc()
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<QueryList>')
    $lines.Add(('  <Query Id="0" Path="{0}">' -f $channelText))
    foreach ($predicate in $Predicates) {
        $xpath = '*[System[{0} and TimeCreated[timediff(@SystemTime, {1}) >= 0 and timediff(@SystemTime, {1}) <= {2}]]]' -f $predicate, $endFileTime, $WindowMilliseconds
        $lines.Add(('    <Select Path="{0}">{1}</Select>' -f $channelText, [System.Security.SecurityElement]::Escape($xpath)))
    }
    $lines.Add('  </Query>')
    $lines.Add('</QueryList>')
    return (($lines.ToArray() -join "`n") + "`n")
}

function ConvertTo-WfDmtfDateTime {
    # CIM DATETIME text, yyyymmddHHMMSS.mmmmmmsUTC, in UTC:
    # https://learn.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime
    param([datetime]$Value)
    return ($Value.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff', [System.Globalization.CultureInfo]::InvariantCulture) + '+000')
}

function Get-WfRemainingSeconds {
    param([datetime]$DeadlineUtc)
    $remaining = ($DeadlineUtc - (Get-WfUtcNow)).TotalSeconds
    if ($remaining -lt 0) { return [double]0 }
    return [double]$remaining
}

function Invoke-WfBoundedEventRead {
    # Pulls records from an open reader until end of stream, a cap, or the
    # deadline. Every pull carries the time left, so a reader that stalls
    # returns by the deadline. A pull that returns nothing after the deadline
    # has passed is treated as a timeout, not as end of stream, because the
    # two cannot be told apart. A record whose conversion fails stops the
    # read: an export with a hole in it is not an export.
    param([hashtable]$Reader, [datetime]$DeadlineUtc, [hashtable]$Accumulator, [hashtable]$ProtectContext = $null)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; TimedOut = $false; Count = 0 }
    try {
        while ($true) {
            $remaining = $DeadlineUtc - (Get-WfUtcNow)
            if ($remaining.TotalMilliseconds -le 0) {
                $result.TimedOut = $true
                $result.ErrorKind = 'timeout'
                $result.ErrorMessage = ('the read did not finish before the deadline ' + (ConvertTo-WfUtcString -Value $DeadlineUtc) + '; ' + $result.Count + ' records had been read')
                return $result
            }
            $record = & $Reader['ReadNext'] $remaining
            if ($null -eq $record) {
                if ((Get-WfUtcNow) -ge $DeadlineUtc) {
                    $result.TimedOut = $true
                    $result.ErrorKind = 'timeout'
                    $result.ErrorMessage = ('the reader returned nothing at the deadline ' + (ConvertTo-WfUtcString -Value $DeadlineUtc) + ', which is a timeout or an end of stream that arrived too late; ' + $result.Count + ' records had been read')
                    return $result
                }
                break
            }
            $item = $null
            try {
                $item = & $Reader['Convert'] $record
            } catch {
                $result.ErrorKind = 'incomplete'
                $result.ErrorMessage = ('record ' + ($result.Count + 1) + ' could not be converted completely: ' + $_.Exception.Message)
                return $result
            } finally {
                if ($null -ne $Reader['Release']) { & $Reader['Release'] $record }
            }
            if ($null -eq $item -or -not $item['xml']) {
                $result.ErrorKind = 'incomplete'
                $result.ErrorMessage = ('record ' + ($result.Count + 1) + ' has no event XML; the export would not be complete')
                return $result
            }
            if ($null -ne $ProtectContext) { $item = Protect-WfEventItem -Item $item -Context $ProtectContext }
            $result.Count += 1
            if (-not (Add-WfRow -Accumulator $Accumulator -Row $item)) { break }
        }
        $result.Ok = $true
    } catch {
        if ((Get-WfUtcNow) -ge $DeadlineUtc) {
            $result.TimedOut = $true
            $result.ErrorKind = 'timeout'
            $result.ErrorMessage = ('the read failed at the deadline: ' + $_.Exception.Message)
        } else {
            $result.ErrorKind = 'other'
            $result.ErrorMessage = $_.Exception.Message
        }
    }
    return $result
}

function Read-WfEventRecords {
    # Opens the query (newest first, so a cap keeps the most recent records)
    # and reads it under the deadline. Stage says where a failure happened:
    # "open" failures are preflight failures, "read" failures happened after
    # the channel was opened.
    param([string]$Channel, [string]$QueryXml, [datetime]$DeadlineUtc, [hashtable]$Accumulator, [hashtable]$ProtectContext = $null)
    $result = [ordered]@{ Ok = $false; Stage = 'open'; ErrorKind = $null; ErrorMessage = $null; TimedOut = $false; Count = 0 }
    $reader = Open-WfEventReader -Channel $Channel -QueryXml $QueryXml -Reverse $true
    if (-not $reader['Ok']) {
        $result.ErrorKind = $reader['ErrorKind']
        $result.ErrorMessage = $reader['ErrorMessage']
        return $result
    }
    $result.Stage = 'read'
    try {
        $read = Invoke-WfBoundedEventRead -Reader $reader -DeadlineUtc $DeadlineUtc -Accumulator $Accumulator -ProtectContext $ProtectContext
        $result.Ok = $read['Ok']
        $result.ErrorKind = $read['ErrorKind']
        $result.ErrorMessage = $read['ErrorMessage']
        $result.TimedOut = $read['TimedOut']
        $result.Count = $read['Count']
    } finally {
        if ($null -ne $reader['Dispose']) { & $reader['Dispose'] }
    }
    return $result
}

function Get-WfChannelState {
    # What the channel holds right now. The oldest retained record is what
    # lets a later reader tell a quiet log from one that wrapped or was
    # cleared; it is read with one bounded pull of a "*" query in forward
    # order, after the main read, so that a wrap during the main read can
    # only make the proof more conservative. The configuration values are
    # recorded when the account may read them and are null otherwise.
    param([string]$Channel, [datetime]$DeadlineUtc)
    $state = [ordered]@{
        found = $null; readable = $false; error = $null; error_kind = $null
        record_count = $null; oldest_record_number = $null; oldest_record_time_utc = $null; oldest_probe = $null
        file_size_bytes = $null; is_log_full = $null; last_write_time_utc = $null
        is_enabled = $null; log_mode = $null; maximum_size_bytes = $null; isolation = $null; security_descriptor = $null
        configuration_error = $null
    }
    $reader = Open-WfEventReader -Channel $Channel -QueryXml '*' -Reverse $false
    if (-not $reader['Ok']) {
        $state.error = $reader['ErrorMessage']
        $state.error_kind = $reader['ErrorKind']
        if ($reader['ErrorKind'] -eq 'not_found') { $state.found = $false } elseif ($reader['ErrorKind'] -eq 'access_denied') { $state.found = $true }
        return $state
    }
    $state.found = $true
    $state.readable = $true
    try {
        $remaining = $DeadlineUtc - (Get-WfUtcNow)
        if ($remaining.TotalMilliseconds -le 0) {
            $state.oldest_probe = 'not attempted: the deadline had passed'
        } else {
            $record = & $reader['ReadNext'] $remaining
            if ($null -eq $record) {
                if ((Get-WfUtcNow) -ge $DeadlineUtc) { $state.oldest_probe = 'timed out: the probe returned nothing at the deadline' }
                else { $state.oldest_probe = 'the channel holds no records' }
            } else {
                try {
                    $item = & $reader['Convert'] $record
                    $state.oldest_record_number = $item['record_id']
                    $state.oldest_record_time_utc = $item['time_created_utc']
                    $state.oldest_probe = 'read'
                } finally {
                    if ($null -ne $reader['Release']) { & $reader['Release'] $record }
                }
            }
        }
    } catch {
        $state.oldest_probe = 'failed: ' + $_.Exception.Message
    } finally {
        if ($null -ne $reader['Dispose']) { & $reader['Dispose'] }
    }
    $configuration = Get-WfChannelConfiguration -Channel $Channel
    foreach ($key in @('record_count', 'file_size_bytes', 'is_log_full', 'last_write_time_utc', 'is_enabled', 'log_mode', 'maximum_size_bytes', 'isolation', 'security_descriptor', 'configuration_error')) {
        if ($configuration.Contains($key)) { $state[$key] = $configuration[$key] }
    }
    return $state
}

function Invoke-WfStreamingRead {
    # Runs a producer pipeline and feeds every object through the converter
    # into the accumulator. The accumulator's caps and the deadline end the
    # pipeline early by a terminating error, which stops the producer as
    # well, so a producer that is unbounded or slow cannot run past either.
    param([scriptblock]$Producer, [scriptblock]$Convert, [hashtable]$Accumulator, [datetime]$DeadlineUtc)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Count = 0 }
    $stopToken = 'WF_STOP_ENUMERATION'
    $timeoutToken = 'WF_DEADLINE_PASSED'
    try {
        & $Producer | ForEach-Object {
            if ((Get-WfUtcNow) -ge $DeadlineUtc) { throw $timeoutToken }
            $row = & $Convert $_
            $result.Count += 1
            if (-not (Add-WfRow -Accumulator $Accumulator -Row $row)) { throw $stopToken }
        }
        $result.Ok = $true
    } catch {
        if ($_.Exception.Message -eq $stopToken) {
            $result.Ok = $true
        } elseif ($_.Exception.Message -eq $timeoutToken) {
            $result.ErrorKind = 'timeout'
            $result.ErrorMessage = ('the read did not finish before the deadline ' + (ConvertTo-WfUtcString -Value $DeadlineUtc) + '; ' + $result.Count + ' records had been read')
        } else {
            $result.ErrorKind = Get-WfCimErrorKind -Exception $_.Exception
            $result.ErrorMessage = $_.Exception.Message
        }
    }
    return $result
}

function Get-WfCimRows {
    # Every instance of a class that matches the filter, streamed through the
    # caps and the deadline, each as an ordered map of the requested
    # properties with dates as UTC text.
    param([string]$Namespace, [string]$ClassName, [string[]]$Properties, $Filter, [int]$MaxRows, [int64]$MaxBytes, [datetime]$DeadlineUtc)
    $accumulator = New-WfRowAccumulator -MaxRows $MaxRows -MaxBytes $MaxBytes
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Rows = @(); Lines = @(); Truncated = $false; TruncationReason = $null }
    $timeoutSeconds = Get-WfRemainingSeconds -DeadlineUtc $DeadlineUtc
    if ($timeoutSeconds -le 0) {
        $result.ErrorKind = 'timeout'
        $result.ErrorMessage = 'the deadline had passed before the class was read'
        return $result
    }
    $producer = New-WfCimProducer -Namespace $Namespace -ClassName $ClassName -Properties $Properties -Filter $Filter -TimeoutSeconds $timeoutSeconds
    $read = Invoke-WfStreamingRead -Producer $producer['Producer'] -Convert $producer['Convert'] -Accumulator $accumulator -DeadlineUtc $DeadlineUtc
    $result.Ok = $read['Ok']
    $result.ErrorKind = $read['ErrorKind']
    $result.ErrorMessage = $read['ErrorMessage']
    $result.Rows = $accumulator.Rows.ToArray()
    $result.Lines = $accumulator.Lines.ToArray()
    $result.Truncated = $accumulator.Truncated
    $result.TruncationReason = $accumulator.Reason
    return $result
}

function Resolve-WfSourceStatus {
    # The measurement status of one source, decided from what the collector
    # itself saw (docs/contracts/measurement-status.md section 2, rule 3).
    #
    # The one rule that needs care is the quiet window. Zero matching records
    # is reported as observed_zero only when a record at or before the
    # window start is known to be retained, because a log that wrapped or
    # was cleared looks exactly like a quiet one. The range the claim covers
    # starts at the later of the requested window start and that record,
    # and is returned as CoveredStartUtc so the manifest can state it. When
    # no such record is known there is no proof of coverage and the status
    # is capture_failed. A source whose query rests on a provider name that
    # Microsoft does not document (QuietClaimVerified false) never reports
    # observed_zero either: records it finds are evidence, an empty result
    # is not. A read that timed out, hit a cap, or stopped at an incomplete
    # record is capture_failed whatever it read.
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
            'timeout' { $result.Status = 'capture_failed'; $result.Reason = 'the read timed out, so the export is not the complete set of matching records: ' + $ReadErrorMessage }
            'incomplete' { $result.Status = 'capture_failed'; $result.Reason = 'the read stopped at a record it could not export completely: ' + $ReadErrorMessage }
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
        $result.Reason = 'zero matching records, and no record at or before the window start could be established, so there is no proof that the source covers any part of the window'
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

function Test-WfKeepPartialExport {
    # A source that is not observed keeps its primary export only when the
    # export is a capped, complete-as-far-as-it-goes set: the status reason
    # says so. Any other failed source leaves no primary, so nothing can be
    # read as an empty result.
    param([string]$Status, [bool]$Truncated, [int]$RecordCount)
    if (Test-WfObservedStatus -Status $Status) { return $true }
    return ($Truncated -and $RecordCount -gt 0)
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

function Remove-WfPrimaryUnlessKept {
    # Applies Test-WfKeepPartialExport to the file on disk.
    param([string]$Path, [string]$Status, [bool]$Truncated, [int]$RecordCount, [System.Collections.Generic.List[string]]$Log, [string]$SourceId)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (Test-WfKeepPartialExport -Status $Status -Truncated $Truncated -RecordCount $RecordCount) { return }
    Remove-Item -LiteralPath $Path -Force
    $Log.Add('source ' + $SourceId + ': the primary export was removed because the source is ' + $Status + ' and the export is not a capped set')
}

function Invoke-WfEventSource {
    # Reads one event log channel through one structured query and writes,
    # under raw/<id>/:
    #   query.xml           the exact query (role config, hashed as config_hash)
    #   channel_state.json  what the channel held and how it is configured (role report)
    #   events.json         the structured export, oldest first (role primary)
    #   events.evtx         the binary export from wevtutil epl (role other), when it succeeds
    # The query interval is fixed: it ends at the moment the query was built
    # and starts WindowDays earlier. Every read runs under one deadline,
    # TimeoutSeconds after the source started.
    # A source marked Protect carries network names and addresses in its
    # records (the WLAN AutoConfig channel does): every record is reduced to
    # its System section by Protect-WfEventItem before it is written (no
    # message, no string data, no rendering info), and the binary export is
    # not attempted because it would hold the full records in clear.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$WindowDays,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context = $null
    )
    $id = [string]$Source['Id']
    $channel = [string]$Source['Channel']
    $providers = Get-WfList -Value $Source['Providers']
    $quietVerified = $true
    if ($Source.ContainsKey('QuietClaimVerified')) { $quietVerified = [bool]$Source['QuietClaimVerified'] }
    $protect = $false
    if ($Source.ContainsKey('Protect') -and $null -ne $Context) { $protect = [bool]$Source['Protect'] }
    $protectContext = $null
    if ($protect) { $protectContext = $Context }
    $entry = New-WfCollectorEntry -Id $id -Kind 'eventlog' -Required ([bool]$Source['Required'])
    $roles = @{ 'query.xml' = 'config'; 'channel_state.json' = 'report'; 'events.json' = 'primary'; 'events.evtx' = 'other' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $eventsPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/events.json')
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $windowMs = [int64]$WindowDays * 86400000
        # The interval is fixed here, immediately before the query is built.
        $windowEnd = Get-WfUtcNow
        $windowStart = $windowEnd.AddMilliseconds(-1 * [double]$windowMs)
        $queryXml = Build-WfEventQueryXml -Channel $channel -Predicates (Get-WfList -Value $Source['Predicates']) -EndUtc $windowEnd -WindowMilliseconds $windowMs
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
                window_end_utc     = ConvertTo-WfUtcString -Value $windowEnd
                max_events         = $MaxEvents
                max_artifact_bytes = $MaxArtifactBytes
                timeout_seconds    = $TimeoutSeconds
                query_sha256       = $queryHash
            }
        }

        $accumulator = New-WfRowAccumulator -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes
        $read = Read-WfEventRecords -Channel $channel -QueryXml $queryXml -DeadlineUtc $deadline -Accumulator $accumulator -ProtectContext $protectContext
        $state = Get-WfChannelState -Channel $channel -DeadlineUtc $deadline
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

        $opened = ($read['Stage'] -eq 'read')
        $found = $opened -or ($read['ErrorKind'] -ne 'not_found')
        $checks = @(
            [ordered]@{ name = 'channel_found'; ok = $found; detail = ('channel ' + $channel) },
            [ordered]@{ name = 'channel_readable'; ok = $opened; detail = $(if ($opened) { $null } else { [string]$read['ErrorMessage'] }) }
        )
        $entry.preflight = [ordered]@{ ok = $opened; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = $checks }

        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $read['Ok']) {
            $readErrorKind = [string]$read['ErrorKind']
            if (-not $readErrorKind) { $readErrorKind = 'other' }
            if (-not $opened -and $readErrorKind -ne 'not_found' -and $readErrorKind -ne 'access_denied') { $readErrorKind = 'preflight' }
            $readErrorMessage = [string]$read['ErrorMessage']
        }
        $recordCount = $accumulator.Rows.Count
        $truncated = [bool]$accumulator.Truncated
        $written = $false
        if ($read['Ok']) {
            # The reader returns newest first; the file is written oldest first.
            $lines = $accumulator.Lines.ToArray()
            [array]::Reverse($lines)
            Write-WfJsonLinesFile -Path $eventsPath -Lines $lines
            $written = $true
            $size = (Get-Item -LiteralPath $eventsPath).Length
            if ($size -gt $MaxArtifactBytes) {
                # The accumulator enforces the budget exactly; this is the check of that claim.
                Remove-Item -LiteralPath $eventsPath -Force
                $written = $false
                $readErrorKind = 'other'
                $readErrorMessage = ('events.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }

        $evtx = [ordered]@{ Attempted = $false; Ok = $false; ExitCode = $null; Message = 'not attempted'; Command = $null }
        if ($protect) {
            $evtx.Message = 'not attempted: the records of this channel are reduced to their System section before they are written, and a binary export would carry the full records in clear'
        } elseif ($written -and -not $readErrorKind -and -not $truncated) {
            $evtxPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/events.evtx')
            $evtx = Export-WfEvtx -QueryPath $queryPath -TargetPath $evtxPath -MaxBytes $MaxArtifactBytes -TimeoutSeconds ([int](Get-WfRemainingSeconds -DeadlineUtc $deadline))
            if (-not $evtx['Ok']) {
                if (Test-Path -LiteralPath $evtxPath) { Remove-Item -LiteralPath $evtxPath -Force }
                $message = ('source ' + $id + ': the binary .evtx export was not produced (' + [string]$evtx['Message'] + '); events.json carries the full XML of every record')
                $Notes.Add($message)
                $Log.Add($message)
            }
        }

        $oldest = $null
        if ($state['oldest_record_time_utc']) { $oldest = ConvertFrom-WfUtcString -Text ([string]$state['oldest_record_time_utc']) }
        $earliest = $null
        if ($recordCount -gt 0) { $earliest = ConvertFrom-WfUtcString -Text ([string]$accumulator.Rows[$recordCount - 1]['time_created_utc']) }
        $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage `
            -RecordCount $recordCount -Truncated $truncated -OldestRecordUtc $oldest -EarliestExportedUtc $earliest `
            -WindowStartUtc $windowStart -QuietClaimVerified $quietVerified -TruncationDetail ([string]$accumulator.Reason + '; the newest records were kept')
        $entry.status = $resolved['Status']
        $entry.status_reason = $resolved['Reason']
        Remove-WfPrimaryUnlessKept -Path $eventsPath -Status $entry.status -Truncated $truncated -RecordCount $recordCount -Log $Log -SourceId $id
        $covered = $resolved['CoveredStartUtc']
        $entry.raw_time_range = New-WfTimeRange -StartUtc $covered -EndUtc $windowEnd
        $coveredText = $null
        if ($null -ne $covered) { $coveredText = ConvertTo-WfUtcString -Value ([datetime]$covered) }
        $entry.enabled = [ordered]@{
            providers   = $enabledProviders
            keywords    = @()
            stack_walk  = @()
            counters    = @()
            options     = [ordered]@{
                channel           = $channel
                query_accepted    = $opened
                window_start_utc  = $coveredText
                window_end_utc    = ConvertTo-WfUtcString -Value $windowEnd
                records_read      = [int]$read['Count']
                records_exported  = $(if (Test-Path -LiteralPath $eventsPath) { $recordCount } else { 0 })
                truncated         = $truncated
                timed_out         = [bool]$read['TimedOut']
                evtx_exported     = [bool]$evtx['Ok']
                evtx_exit_code    = $evtx['ExitCode']
                evtx_message      = $evtx['Message']
                evtx_command      = $evtx['Command']
            }
            verified_by = 'EventLogReader accepted the query in query.xml; the oldest retained record and the provider list are in channel_state.json'
        }
        $detail = ('{0} records read; requested window {1} to {2}; covered range starts {3}' -f $recordCount, (ConvertTo-WfUtcString -Value $windowStart), (ConvertTo-WfUtcString -Value $windowEnd), $coveredText)
        if ($null -ne $oldest -and $oldest -gt $windowStart) {
            $message = ('source ' + $id + ': channel ' + $channel + ' only holds records from ' + $coveredText + ', later than the requested window start; nothing is claimed before that time')
            $Notes.Add($message)
            $Log.Add($message)
        }
        $entry.expectation = [ordered]@{
            declared = 'every record matching query.xml inside the covered range is exported completely, within the caps and the deadline, and an empty export is only called a quiet window when the oldest retained record proves the range was covered'
            met      = $resolved['ExpectationMet']
            detail   = $detail
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $eventsPath) { Remove-Item -LiteralPath $eventsPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Invoke-WfCimSource {
    # Reads the instances of one WMI class and writes, under raw/<id>/:
    #   query.json    class, namespace, properties, filter and window (role config, hashed as config_hash)
    #   records.json  the instances as a JSON array (role primary)
    # A source with a TimeProperty is a history: the window is pushed into
    # the WQL filter, and a separate one row probe for a record at or before
    # the window start is the proof that a quiet window was covered. A source
    # without one is a snapshot taken at collection time. Both run under the
    # deadline and the caps.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$WindowDays,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context = $null
    )
    $id = [string]$Source['Id']
    $className = [string]$Source['ClassName']
    # String properties that can carry a path or free text (a command line)
    # go through Protect-WfCopiedText before anything is written.
    $protectProperties = Get-WfList -Value $Source['ProtectProperties']
    $namespace = 'root/cimv2'
    if ($Source['Namespace']) { $namespace = [string]$Source['Namespace'] }
    $timeProperty = $null
    if ($Source['TimeProperty']) { $timeProperty = [string]$Source['TimeProperty'] }
    $properties = Get-WfList -Value $Source['Properties']
    $kind = 'other'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'query.json' = 'config'; 'records.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $recordsPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/records.json')
    $exported = @()
    $sourceRowCount = $null
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $windowEnd = Get-WfUtcNow
        $windowStart = $windowEnd.AddDays(-1 * $WindowDays)
        $filter = $null
        $probeFilter = $null
        if ($timeProperty) {
            $filter = ("{0} >= '{1}' AND {0} <= '{2}'" -f $timeProperty, (ConvertTo-WfDmtfDateTime -Value $windowStart), (ConvertTo-WfDmtfDateTime -Value $windowEnd))
            $probeFilter = ("{0} < '{1}'" -f $timeProperty, (ConvertTo-WfDmtfDateTime -Value $windowStart))
        } elseif ($Source['Filter']) {
            # A snapshot narrowed by a fixed WQL predicate from the definition
            # (for example the default routes only).
            $filter = [string]$Source['Filter']
        }
        # A snapshot class that can legitimately hold no instance (a machine
        # without a default route) reports an empty result as observed_zero;
        # the proof of coverage is that the enumeration itself completed.
        $emptyIsObservation = $false
        if ($Source.ContainsKey('EmptySnapshotIsObservation')) { $emptyIsObservation = [bool]$Source['EmptySnapshotIsObservation'] }
        $query = [ordered]@{
            class = $className; namespace = $namespace; properties = @($properties); filter = $filter; time_property = $timeProperty
            window_days = $null; window_start_utc = $null; window_end_utc = $null; coverage_probe_filter = $probeFilter
            max_records = $MaxEvents; max_artifact_bytes = $MaxArtifactBytes; timeout_seconds = $TimeoutSeconds
        }
        if ($timeProperty) {
            $query.window_days = $WindowDays
            $query.window_start_utc = ConvertTo-WfUtcString -Value $windowStart
            $query.window_end_utc = ConvertTo-WfUtcString -Value $windowEnd
        }
        # Fixed options the definition wants recorded next to the query (for
        # example which snapshot of a before and after pair this read is).
        if ($Source['Options']) { foreach ($key in $Source['Options'].Keys) { $query[[string]$key] = $Source['Options'][$key] } }
        if (@($protectProperties).Count -gt 0) {
            $query['protected_properties'] = @($protectProperties)
            $query['protection'] = Get-WfCopiedTextProtectionDescription
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $command = @('Get-CimInstance', '-Namespace', $namespace, '-ClassName', $className, '-Property', (@($properties) -join ','), '-OperationTimeoutSec', [string]$TimeoutSeconds)
        if ($filter) { $command += @('-Filter', $filter) }
        $entry.command = $command
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }

        $read = Get-WfCimRows -Namespace $namespace -ClassName $className -Properties $properties -Filter $filter `
            -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes -DeadlineUtc $deadline
        $readAt = Get-WfUtcNow
        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $read['Ok']) {
            $readErrorKind = [string]$read['ErrorKind']
            if (-not $readErrorKind) { $readErrorKind = 'other' }
            $readErrorMessage = [string]$read['ErrorMessage']
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value $readAt
            checks = @([ordered]@{ name = 'class_readable'; ok = (-not $readErrorKind); detail = $(if ($readErrorKind) { $readErrorMessage } else { $namespace + ':' + $className }) })
        }

        $rows = Get-WfList -Value $read['Rows']
        $lines = Get-WfList -Value $read['Lines']
        $truncated = [bool]$read['Truncated']
        $sourceRowCount = @($rows).Count
        $protectionCounts = $null
        if (@($protectProperties).Count -gt 0 -and -not $readErrorKind) {
            if ($null -eq $Context) { throw 'a source with ProtectProperties needs the run context (the salt)' }
            # Protect at the collection boundary, then serialise again so the
            # file holds exactly the protected rows.
            $protectionCounts = [ordered]@{ user_profile_names_replaced = 0; email_addresses_replaced = 0; unc_hosts_replaced = 0; mac_addresses_replaced = 0 }
            $rebuilt = New-Object 'System.Collections.Generic.List[string]'
            foreach ($row in @($rows)) {
                foreach ($name in $protectProperties) {
                    $key = [string]$name
                    if ($row.Contains($key) -and $row[$key] -is [string]) {
                        $protected = Protect-WfCopiedText -Text ([string]$row[$key]) -Salt ([string]$Context['Salt'])
                        $row[$key] = [string]$protected['Text']
                        $protectionCounts.user_profile_names_replaced += [int]$protected['UserCount']
                        $protectionCounts.email_addresses_replaced += [int]$protected['MailCount']
                        $protectionCounts.unc_hosts_replaced += [int]$protected['HostCount']
                        $protectionCounts.mac_addresses_replaced += [int]$protected['MacCount']
                    }
                }
                $rebuilt.Add((ConvertTo-WfJson -Value $row))
            }
            $lines = $rebuilt.ToArray()
        }
        $oldest = $null
        $probe = $null
        if (-not $readErrorKind) {
            if ($timeProperty) {
                # Order oldest first by the time property, keeping arrival
                # order for equal times, and reorder the serialised lines the
                # same way so the file still costs exactly what was budgeted.
                $keyed = New-Object 'System.Collections.Generic.List[object]'
                for ($index = 0; $index -lt @($rows).Count; $index++) {
                    $text = $rows[$index][$timeProperty]
                    $when = $windowEnd
                    if ($text) { $when = ConvertFrom-WfUtcString -Text ([string]$text) }
                    $keyed.Add([pscustomobject]@{ When = $when; Index = $index })
                }
                $order = @($keyed.ToArray() | Sort-Object -Property When, Index | ForEach-Object { $_.Index })
                $exported = @($order | ForEach-Object { $rows[$_] })
                $lines = @($order | ForEach-Object { $lines[$_] })
                # The coverage proof: one bounded read for any record at or
                # before the window start. Finding one shows the source still
                # reaches back to the start; a probe that cannot complete
                # proves nothing.
                $probe = Get-WfCimRows -Namespace $namespace -ClassName $className -Properties @($timeProperty) -Filter $probeFilter `
                    -MaxRows 1 -MaxBytes 1048576 -DeadlineUtc $deadline
                if ($probe['Ok'] -and @($probe['Rows']).Count -gt 0 -and $probe['Rows'][0][$timeProperty]) {
                    $oldest = ConvertFrom-WfUtcString -Text ([string]$probe['Rows'][0][$timeProperty])
                }
            } else {
                $exported = $rows
                $oldest = $started
            }
            Write-WfJsonLinesFile -Path $recordsPath -Lines @($lines)
            $size = (Get-Item -LiteralPath $recordsPath).Length
            if ($size -gt $MaxArtifactBytes) {
                Remove-Item -LiteralPath $recordsPath -Force
                $exported = @()
                $readErrorKind = 'other'
                $readErrorMessage = ('records.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }

        $earliest = $null
        if ($timeProperty -and @($exported).Count -gt 0 -and $exported[0][$timeProperty]) { $earliest = ConvertFrom-WfUtcString -Text ([string]$exported[0][$timeProperty]) }
        if (-not $readErrorKind -and -not $timeProperty -and @($exported).Count -eq 0 -and -not $truncated -and -not $emptyIsObservation) {
            $entry.status = 'capture_failed'
            $entry.status_reason = 'the class returned no instances; a snapshot of this class is never empty on a working machine, so this is treated as a failed read and not as an observation'
            $entry.expectation = [ordered]@{ declared = 'the class returns at least one instance'; met = $false; detail = '0 instances' }
            $entry.raw_time_range = $null
            Remove-WfPrimaryUnlessKept -Path $recordsPath -Status $entry.status -Truncated $truncated -RecordCount 0 -Log $Log -SourceId $id
        } else {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage `
                -RecordCount (@($exported).Count) -Truncated $truncated -OldestRecordUtc $oldest -EarliestExportedUtc $earliest `
                -WindowStartUtc $windowStart -QuietClaimVerified $true -TruncationDetail ([string]$read['TruncationReason'] + '; the records read before the cap were kept')
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $covered = $resolved['CoveredStartUtc']
            if (-not $timeProperty -and -not $readErrorKind) { $covered = $readAt }
            $entry.raw_time_range = New-WfTimeRange -StartUtc $covered -EndUtc $(if ($timeProperty) { $windowEnd } else { $readAt })
            $coveredText = $null
            if ($null -ne $covered) { $coveredText = ConvertTo-WfUtcString -Value ([datetime]$covered) }
            if ($timeProperty) {
                $probeText = 'not run'
                if ($null -ne $probe) {
                    if ($probe['Ok']) { $probeText = ('found ' + @($probe['Rows']).Count + ' record at or before the window start') } else { $probeText = 'failed: ' + [string]$probe['ErrorMessage'] }
                }
                $entry.expectation = [ordered]@{
                    declared = 'every instance inside the window is exported completely, within the caps and the deadline, and an empty export is only called a quiet window when a record at or before the window start proves the range was covered'
                    met      = $resolved['ExpectationMet']
                    detail   = ('{0} instances inside the window; coverage probe {1}; covered range starts {2}' -f @($exported).Count, $probeText, $coveredText)
                }
                if ($null -eq $oldest -and $null -ne $earliest -and $earliest -gt $windowStart) {
                    $message = ('source ' + $id + ': ' + $className + ' holds no instance at or before the requested window start; the covered range starts at the earliest exported instance, ' + $coveredText + ', and nothing is claimed before that time')
                    $Notes.Add($message)
                    $Log.Add($message)
                }
            } elseif ($emptyIsObservation) {
                $entry.expectation = [ordered]@{ declared = 'the enumeration completes; zero instances is an observation for this class (the filter can legitimately match nothing)'; met = $resolved['ExpectationMet']; detail = ('{0} instances' -f @($exported).Count) }
            } else {
                $entry.expectation = [ordered]@{ declared = 'the class returns at least one instance'; met = $resolved['ExpectationMet']; detail = ('{0} instances' -f @($exported).Count) }
            }
            Remove-WfPrimaryUnlessKept -Path $recordsPath -Status $entry.status -Truncated $truncated -RecordCount (@($exported).Count) -Log $Log -SourceId $id
            if (-not (Test-Path -LiteralPath $recordsPath)) { $exported = @() }
            $enabledOptions = [ordered]@{
                class = $className; namespace = $namespace; properties = @($properties); filter = $filter; time_property = $timeProperty
                window_days = $query.window_days; window_start_utc = $null; window_end_utc = $query.window_end_utc
                records_read = $sourceRowCount; records_exported = @($exported).Count; truncated = $truncated
                coverage_probe = $(if ($null -ne $probe) { [bool]$probe['Ok'] } else { $null })
            }
            if ($timeProperty) { $enabledOptions.window_start_utc = $coveredText }
            if ($Source['Options']) { foreach ($key in $Source['Options'].Keys) { $enabledOptions[[string]$key] = $Source['Options'][$key] } }
            if ($null -ne $protectionCounts) { $enabledOptions['protection'] = $protectionCounts }
            $entry.enabled = [ordered]@{
                providers = @(); keywords = @(); stack_walk = @(); counters = @()
                options = $enabledOptions
                verified_by = 'Get-CimInstance returned without error under its operation timeout; the instance count and the coverage probe are in the expectation detail'
            }
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        $exported = @()
        if (Test-Path -LiteralPath $recordsPath) { Remove-Item -LiteralPath $recordsPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @($exported); SourceRowCount = $sourceRowCount }
}

# ---------------------------------------------------------------------------
# Pseudonyms. Network names (SSIDs, profile names) and hardware addresses
# (BSSIDs, the adapter's own address) belong to other people as much as to
# the owner of the PC, so a bundle never carries them in clear text. Every
# such value is replaced by <kind>-<first 12 hex of SHA-256(salt, kind,
# value)>: ssid-... for a name, mac-... for an address. The salt is random
# per run and is never written, so the same value maps to the same pseudonym
# inside one bundle (the analysis can still match the connected address
# against the scan, and a saved profile against a visible network) and to
# nothing outside it; a dictionary attack on short network names has no salt
# to work with. The rules are structural and language independent: an
# address is recognised by its shape, a network name by its place in the
# netsh output (see Protect-WfNetshText). Everything else in the text stays
# verbatim so a decoder can be fixed later against the raw output.
# ---------------------------------------------------------------------------

function Get-WfMacAddressPattern {
    # Six hexadecimal pairs separated by colons or hyphens, the forms netsh
    # and the WLAN report print, not inside a longer run of hex digits.
    return '(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])'
}

function Get-WfPseudonymPattern {
    param([string]$Kind)
    return ('^' + $Kind + '-[0-9a-f]{12}$')
}

function ConvertTo-WfPseudonym {
    param([string]$Kind, [string]$Value, [string]$Salt)
    $digest = Get-WfSha256OfText -Text ('wf-pseudonym:' + $Salt + ':' + $Kind + ':' + $Value)
    return ($Kind + '-' + $digest.Substring(0, 12))
}

function Protect-WfMacAddresses {
    # Replaces every hardware address in the text; the address is normalised
    # (lower case, colons) before hashing so both printed forms map to one
    # pseudonym. Returns the text and the number of replacements.
    param([string]$Text, [string]$Salt)
    if ($null -eq $Text) { return [ordered]@{ Text = ''; Count = 0 } }
    $found = [regex]::Matches($Text, (Get-WfMacAddressPattern))
    if ($found.Count -eq 0) { return [ordered]@{ Text = $Text; Count = 0 } }
    $builder = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($match in $found) {
        $null = $builder.Append($Text.Substring($last, $match.Index - $last))
        $normalized = ($match.Value -replace '-', ':').ToLowerInvariant()
        $null = $builder.Append((ConvertTo-WfPseudonym -Kind 'mac' -Value $normalized -Salt $Salt))
        $last = $match.Index + $match.Length
    }
    $null = $builder.Append($Text.Substring($last))
    return [ordered]@{ Text = $builder.ToString(); Count = $found.Count }
}

function Test-WfUnindentedLine {
    param([string]$Line)
    if ($Line.Length -eq 0) { return $false }
    return ($Line[0] -ne ' ' -and $Line[0] -ne "`t")
}

function Protect-WfNetshText {
    # Pseudonymises one netsh output (or, in generic mode, any text). Modes:
    #   networks    netsh wlan show networks mode=bssid. Each network block
    #               starts with an unindented "SSID n : name" line and holds
    #               indented "BSSID n : address" lines, so the name line is
    #               the nearest unindented line with a colon above each
    #               address line. That rule needs no label text, so it holds
    #               in any display language.
    #   interfaces  netsh wlan show interfaces. The name sits on the line
    #               whose label is SSID, and, as a fallback for a display
    #               language that translates that label, on the line just
    #               before the BSSID address line (netsh prints SSID, then
    #               BSSID); the Profile line repeats it, which the learned
    #               name replacement below catches.
    #   profiles    netsh wlan show profiles. Every "label : value" line with
    #               a value names a saved profile. Saved profiles are the
    #               owner's own networks, so they stay readable: the text is
    #               kept as printed and the result carries each name with its
    #               pseudonym, which is how an explicit owner selection at
    #               analysis time is matched to the pseudonymised scan. The
    #               names are still learned, so a repeat anywhere else (the
    #               interface Profile line, an event) is pseudonymised.
    #   drivers     netsh wlan show drivers. Only addresses can appear.
    #   generic     the WLAN report and stderr text: addresses, plus every
    #               name learned from the netsh outputs in this run, in its
    #               plain and HTML encoded forms.
    # Every learned name is also replaced wherever else it appears as a whole
    # token. The names themselves are returned only so the caller can carry
    # them to the next source in memory; they are never written.
    param([string]$Text, [string]$Mode, [string]$Salt, [System.Collections.Generic.List[string]]$KnownSsids)
    $result = [ordered]@{ Text = ''; MacCount = 0; SsidCount = 0; LearnedSsids = (New-Object 'System.Collections.Generic.List[string]'); Profiles = @() }
    if ($null -eq $Text) { return $result }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in (($Text -replace "`r`n", "`n") -split "`n")) { $lines.Add($line) }
    $macPattern = Get-WfMacAddressPattern
    $guidPattern = '^\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$'
    $ssidLines = New-Object 'System.Collections.Generic.HashSet[int]'
    if ($Mode -eq 'networks') {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch $macPattern) { continue }
            for ($j = $i; $j -ge 0; $j--) {
                if ((Test-WfUnindentedLine -Line $lines[$j]) -and $lines[$j].Contains(':')) { $null = $ssidLines.Add($j); break }
            }
        }
    }
    if ($Mode -eq 'interfaces') {
        # Fallback for a translated SSID label: the labelled line just before
        # an address line is the name line, unless its value is a GUID (the
        # line before the adapter's own address) or an address itself.
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch $macPattern) { continue }
            $previous = $lines[$i - 1]
            $colon = $previous.IndexOf(':')
            if ($colon -lt 0) { continue }
            $value = $previous.Substring($colon + 1).Trim()
            if ($value.Length -eq 0 -or $value -match $guidPattern -or $value -match $macPattern) { continue }
            $null = $ssidLines.Add($i - 1)
        }
    }
    $profiles = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $colon = $line.IndexOf(':')
        if ($colon -lt 0) { continue }
        $label = $line.Substring(0, $colon).Trim()
        $isName = $ssidLines.Contains($i)
        if (-not $isName -and ($Mode -eq 'interfaces' -or $Mode -eq 'networks') -and $label -match '^SSID(\s+\d+)?$') { $isName = $true }
        if (-not $isName -and $Mode -eq 'profiles' -and $label.Length -gt 0) { $isName = $true }
        if (-not $isName) { continue }
        $value = $line.Substring($colon + 1).Trim()
        if ($value.Length -eq 0 -or $value -match (Get-WfPseudonymPattern -Kind 'ssid')) { continue }
        if (-not $result.LearnedSsids.Contains($value)) { $result.LearnedSsids.Add($value) }
        $pseudonym = ConvertTo-WfPseudonym -Kind 'ssid' -Value $value -Salt $Salt
        if ($Mode -eq 'profiles') {
            # Readable by decision: the owner's own saved networks, with the
            # pseudonym the same name carries everywhere else in the bundle.
            $profiles.Add([ordered]@{ name = $value; pseudonym = $pseudonym })
            continue
        }
        $lines[$i] = $line.Substring(0, $colon + 1) + ' ' + $pseudonym
        $result.SsidCount += 1
    }
    $result.Profiles = $profiles.ToArray()
    $text = ($lines.ToArray() -join "`n")
    $names = New-Object 'System.Collections.Generic.List[string]'
    if ($Mode -ne 'profiles') { foreach ($name in $result.LearnedSsids) { $names.Add($name) } }
    if ($null -ne $KnownSsids -and $Mode -ne 'profiles') { foreach ($name in $KnownSsids) { if (-not $names.Contains($name)) { $names.Add($name) } } }
    # Longest names first, so a name that contains another is replaced whole.
    foreach ($name in @($names.ToArray() | Sort-Object -Property @{ Expression = { $_.Length }; Descending = $true }, @{ Expression = { $_ } })) {
        $pseudonym = ConvertTo-WfPseudonym -Kind 'ssid' -Value $name -Salt $Salt
        $forms = New-Object 'System.Collections.Generic.List[string]'
        $forms.Add($name)
        $encoded = [System.Net.WebUtility]::HtmlEncode($name)
        if ($encoded -ne $name) { $forms.Add($encoded) }
        foreach ($form in $forms) {
            $pattern = '(?<![A-Za-z0-9_])' + [regex]::Escape($form) + '(?![A-Za-z0-9_])'
            $found = [regex]::Matches($text, $pattern)
            if ($found.Count -gt 0) {
                $result.SsidCount += $found.Count
                $text = [regex]::Replace($text, $pattern, $pseudonym)
            }
        }
    }
    $macs = Protect-WfMacAddresses -Text $text -Salt $Salt
    $result.Text = $macs['Text']
    $result.MacCount = $macs['Count']
    return $result
}

function Get-WfBluetoothAddressPattern {
    # Twelve hexadecimal digits standing alone (a Bluetooth address as the
    # BTHENUM and BTHLE enumerators print it), not part of a GUID or a longer
    # run of hex digits.
    return '(?<![0-9A-Fa-f-])[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])'
}

function Protect-WfBluetoothAddresses {
    param([string]$Text, [string]$Salt)
    if ($null -eq $Text) { return '' }
    $found = [regex]::Matches($Text, (Get-WfBluetoothAddressPattern))
    if ($found.Count -eq 0) { return $Text }
    $builder = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($match in $found) {
        $null = $builder.Append($Text.Substring($last, $match.Index - $last))
        $hex = $match.Value.ToLowerInvariant()
        $colon = ($hex -replace '(..)(?!$)', '$1:')
        $null = $builder.Append((ConvertTo-WfPseudonym -Kind 'mac' -Value $colon -Salt $Salt))
        $last = $match.Index + $match.Length
    }
    $null = $builder.Append($Text.Substring($last))
    return $builder.ToString()
}

function Test-WfBluetoothPeerInstance {
    # A node of any Bluetooth enumerator other than the radio's own BTH\
    # (BTHENUM, BTHLE, BTHLEDEVICE, BTHHFENUM and the like enumerate a
    # remembered peer and its services, named after the peer), or a node
    # named after a Bluetooth service UUID (the Bluetooth base UUID, as a
    # peer's HID collections are).
    param([string]$InstanceId)
    if ($InstanceId -match '^BTH[^\\]+\\') { return $true }
    return ($InstanceId -match '\{[0-9A-Fa-f]{8}-0000-1000-8000-00805f9b34fb\}')
}

function Protect-WfBluetoothPeerRow {
    # A paired or remembered Bluetooth device is someone's phone, controller
    # or earbuds; its name and address identify it as a network name would.
    # The name fields become name-<12 hex> and every bare twelve digit
    # address becomes the mac- pseudonym of its colon form, in the instance
    # id, the hardware and compatible ids and the location text. Pairing or
    # connection state is not touched because it is not measured here. The
    # row is an ordered map and stays one (untyped parameter).
    param($Row, [string]$Salt)
    foreach ($field in @('name', 'description', 'bus_reported_description')) {
        $value = $Row[$field]
        if ($null -ne $value -and ([string]$value).Length -gt 0) { $Row[$field] = ConvertTo-WfPseudonym -Kind 'name' -Value ([string]$value) -Salt $Salt }
    }
    foreach ($field in @('instance_id', 'location_info', 'parent_instance_id')) {
        if ($Row[$field]) { $Row[$field] = Protect-WfBluetoothAddresses -Text ([string]$Row[$field]) -Salt $Salt }
    }
    foreach ($field in @('hardware_ids', 'compatible_ids', 'location_paths')) {
        $values = New-Object 'System.Collections.Generic.List[object]'
        foreach ($value in @($Row[$field])) { $values.Add((Protect-WfBluetoothAddresses -Text ([string]$value) -Salt $Salt)) }
        $Row[$field] = @($values.ToArray())
    }
    return $Row
}

function Protect-WfEventItem {
    # One events.json element reduced to what cannot carry a network name:
    # the System section of the record. The rendered message is dropped,
    # every string property is replaced by null (numbers and booleans, a
    # reason code or a count, stay), and the EventData, UserData and
    # RenderingInfo parts of the XML are emptied, because a name the current
    # run never learned can hide in any of them. Addresses are replaced in
    # what remains as well. The item is an ordered map and must stay one (a
    # [hashtable] parameter would copy it into an unordered one and scramble
    # the export's key order), so the parameter is untyped.
    param($Item, [hashtable]$Context)
    $Item['message'] = $null
    $values = New-Object 'System.Collections.Generic.List[object]'
    foreach ($value in @($Item['properties'])) {
        if ($value -is [string]) { $values.Add($null) } else { $values.Add($value) }
    }
    $Item['properties'] = @($values.ToArray())
    $xml = [string]$Item['xml']
    foreach ($element in @('EventData', 'UserData', 'RenderingInfo', 'ProcessingErrorData')) {
        $xml = [regex]::Replace($xml, ('(?s)<' + $element + '\b[^>]*>.*?</' + $element + '>'), ('<' + $element + '/>'))
    }
    $Item['xml'] = (Protect-WfMacAddresses -Text $xml -Salt ([string]$Context['Salt'])).Text
    return $Item
}

function ConvertTo-WfNetshFields {
    # The language independent structure of a netsh output: every line that
    # carries a colon, as line number (1-based), indentation, label and
    # value, with the index of the unindented block it belongs to. The
    # decoder classifies these by English label or by the shape of the value.
    param([string]$Text)
    $fields = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Text) { return , $fields.ToArray() }
    $block = -1
    $number = 0
    foreach ($line in (($Text -replace "`r`n", "`n") -split "`n")) {
        $number += 1
        $colon = $line.IndexOf(':')
        if ($colon -lt 0) { continue }
        $indent = $line.Length - $line.TrimStart(' ', "`t").Length
        if ($indent -eq 0) { $block += 1 }
        $fields.Add([ordered]@{
                line   = $number
                block  = $(if ($block -lt 0) { 0 } else { $block })
                indent = $indent
                label  = $line.Substring(0, $colon).Trim()
                value  = $line.Substring($colon + 1).Trim()
            })
    }
    return , $fields.ToArray()
}

function Measure-WfNetshRecords {
    # How many records a protected netsh output holds, by a language
    # independent count: interfaces by the GUID each interface prints,
    # networks by distinct address pseudonyms, profiles by name pseudonyms,
    # drivers by unindented header lines (one per interface).
    param([string]$Text, [string]$Mode)
    if ($null -eq $Text) { return 0 }
    switch ($Mode) {
        'interfaces' { return @([regex]::Matches($Text, '[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}')).Count }
        'networks' {
            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($match in [regex]::Matches($Text, 'mac-[0-9a-f]{12}')) { $null = $seen.Add($match.Value) }
            return $seen.Count
        }
        'profiles' {
            # Saved profiles stay readable, so count the valued labelled lines (the caller
            # prefers the mapping Protect-WfNetshText returns, which is the same count).
            $count = 0
            foreach ($line in (($Text -replace "`r`n", "`n") -split "`n")) {
                $colon = $line.IndexOf(':')
                if ($colon -gt 0 -and $line.Substring($colon + 1).Trim().Length -gt 0) { $count += 1 }
            }
            return $count
        }
        'drivers' {
            $count = 0
            foreach ($line in (($Text -replace "`r`n", "`n") -split "`n")) { if ((Test-WfUnindentedLine -Line $line) -and $line.Contains(':')) { $count += 1 } }
            return $count
        }
        'guid_lines' {
            # powercfg prints one GUID per scheme, subgroup, setting and alias line, in
            # every display language.
            $count = 0
            foreach ($line in (($Text -replace "`r`n", "`n") -split "`n")) { if ($line -match '[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}') { $count += 1 } }
            return $count
        }
    }
    return 0
}

function Get-WfProtectionDescription {
    param([string]$Mode)
    return [ordered]@{
        mode          = $Mode
        mac_pseudonym = 'mac-<first 12 hex of SHA-256(salt, address)>, every six pair hardware address'
        ssid_pseudonym = 'ssid-<first 12 hex of SHA-256(salt, name)>, every network and profile name found by structure, plus every learned name wherever it appears'
        salt          = 'random per run, never written; pseudonyms are consistent inside this bundle only'
    }
}

function Invoke-WfCommandSource {
    # Runs one fixed, read only netsh query and writes, under raw/<id>/:
    #   command.json  the executable, the exact arguments, the limits and the
    #                 pseudonym rules (role config, hashed as config_hash)
    #   result.json   exit code, timing, byte counts, the protected stderr,
    #                 the replacement counts and the line structure (role report)
    #   output.txt    the protected standard output, LF line endings (role primary)
    # The process is started directly with no shell and stopped at the
    # source deadline. Zero records is observed_zero or capture_failed as the
    # definition says (ZeroRule, ZeroReason): a scan that lists no network
    # cannot be told from a scan withheld by the location consent rules, so
    # the networks query treats zero as capture_failed.
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
    $arguments = [string]$Source['Arguments']
    $mode = [string]$Source['Protect']
    # Which language independent count says how many records the output
    # holds; the protection mode by default (the netsh listings), or a named
    # count (guid_lines for powercfg, whose every scheme, subgroup, setting
    # and alias line carries a GUID).
    $recordsMode = $mode
    if ($Source['Records']) { $recordsMode = [string]$Source['Records'] }
    $toolName = 'netsh'
    if ($Source['Tool']) { $toolName = [string]$Source['Tool'] }
    $zeroRule = 'observed_zero'
    if ($Source['ZeroRule']) { $zeroRule = [string]$Source['ZeroRule'] }
    $kind = 'other'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'command.json' = 'config'; 'result.json' = 'report'; 'output.txt' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $outputPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/output.txt')
    $records = 0
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $tool = Get-WfToolPath -Name $toolName
        $encoding = Get-WfConsoleOutputEncoding
        $config = [ordered]@{
            tool               = $tool
            arguments          = $arguments
            timeout_seconds    = $TimeoutSeconds
            max_artifact_bytes = $MaxArtifactBytes
            output_encoding    = [string]$encoding.WebName
            output_code_page   = [int]$encoding.CodePage
            line_endings       = 'lf'
            protection         = Get-WfProtectionDescription -Mode $mode
            zero_records_rule  = $zeroRule
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($tool) + @($arguments -split ' ')
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        $present = Test-WfToolPresent -Path $tool
        $readErrorKind = ''
        $readErrorMessage = ''
        $run = $null
        if (-not $present) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'the executable does not exist: ' + $tool
        } else {
            $remaining = Get-WfRemainingSeconds -DeadlineUtc $deadline
            if ($remaining -le 0) {
                $readErrorKind = 'timeout'
                $readErrorMessage = 'the deadline had passed before the command was started'
            } else {
                $run = Invoke-WfProcess -FilePath $tool -Arguments $arguments -TimeoutSeconds ([int][math]::Ceiling($remaining)) -OutputEncoding $encoding -MaxBytes $MaxArtifactBytes
            }
        }
        $entry.preflight = [ordered]@{
            ok     = $present
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @([ordered]@{ name = 'tool_present'; ok = $present; detail = $tool })
        }
        $protected = $null
        $stderrText = $null
        $outputBytes = 0
        if ($null -ne $run) {
            if (-not $run['Started']) {
                $readErrorKind = 'other'
                $readErrorMessage = 'the process could not be started: ' + [string]$run['Error']
            } elseif ($run['TimedOut']) {
                $readErrorKind = 'timeout'
                $readErrorMessage = [string]$run['Error']
            } elseif ($run['Oversized']) {
                $readErrorKind = 'other'
                $readErrorMessage = [string]$run['Error']
            } else {
                $protected = Protect-WfNetshText -Text ([string]$run['StdOut']) -Mode $mode -Salt ([string]$Context['Salt']) -KnownSsids $Context['Ssids']
                foreach ($name in $protected.LearnedSsids) { if (-not $Context['Ssids'].Contains($name)) { $Context['Ssids'].Add($name) } }
                $errors = Protect-WfNetshText -Text ([string]$run['StdErr']) -Mode 'generic' -Salt ([string]$Context['Salt']) -KnownSsids $Context['Ssids']
                $stderrText = ([string]$errors.Text).Trim()
                $text = [string]$protected.Text
                if ([int]$run['ExitCode'] -ne 0) {
                    $said = (($text + ' ' + $stderrText).Trim() -replace '\s+', ' ')
                    if ($said.Length -gt 500) { $said = $said.Substring(0, 500) }
                    $readErrorKind = 'other'
                    $readErrorMessage = ('{0} exited with code {1}: {2}' -f $tool, [int]$run['ExitCode'], $said)
                } elseif ($text.Trim().Length -eq 0) {
                    $readErrorKind = 'other'
                    $readErrorMessage = 'the command exited with code 0 and printed nothing'
                } else {
                    $outputBytes = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($text + "`n")
                    if ($outputBytes -gt $MaxArtifactBytes) {
                        $readErrorKind = 'other'
                        $readErrorMessage = ('the output is {0} bytes, above the cap of {1}, and was not kept' -f $outputBytes, $MaxArtifactBytes)
                    } else {
                        Write-WfTextFile -Path $outputPath -Text ($text + "`n")
                        $records = Measure-WfNetshRecords -Text $text -Mode $recordsMode
                        if ($mode -eq 'profiles') { $records = @($protected.Profiles).Count }
                    }
                }
            }
        }
        $stopped = Get-WfUtcNow
        $fields = @()
        if ($null -ne $protected -and (Test-Path -LiteralPath $outputPath)) { $fields = ConvertTo-WfNetshFields -Text ([string]$protected.Text) }
        # Assigned, not wrapped in a subexpression: $( @(...) ) unrolls a one element array into
        # a lone object and ConvertTo-WfJson would then write an object where the decoder expects a list.
        $profileMap = $null
        if ($null -ne $protected -and $mode -eq 'profiles') { $profileMap = @($protected.Profiles) }
        $report = [ordered]@{
            started_utc    = ConvertTo-WfUtcString -Value $started
            stopped_utc    = ConvertTo-WfUtcString -Value $stopped
            exit_code      = $(if ($null -ne $run) { $run['ExitCode'] } else { $null })
            timed_out      = $(if ($null -ne $run) { [bool]$run['TimedOut'] } else { $false })
            duration_ms    = $(if ($null -ne $run) { $run['DurationMs'] } else { $null })
            stdout_bytes   = $outputBytes
            stdout_bytes_read = $(if ($null -ne $run) { $run['StdOutBytes'] } else { $null })
            diagnostic     = $(if ($null -ne $run -and $run['Diagnostic']) { (Protect-WfNetshText -Text ([string]$run['Diagnostic']) -Mode $mode -Salt ([string]$Context['Salt']) -KnownSsids $Context['Ssids']).Text } else { $null })
            stderr         = $stderrText
            records        = $records
            records_meaning = [string]$Source['RecordsMeaning']
            protection     = [ordered]@{
                mac_addresses_replaced = $(if ($null -ne $protected) { $protected.MacCount } else { 0 })
                network_names_replaced = $(if ($null -ne $protected) { $protected.SsidCount } else { 0 })
            }
            profiles       = $profileMap
            fields         = @($fields)
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report

        if ($readErrorKind) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } elseif ($records -gt 0) {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        } elseif ($zeroRule -eq 'observed_zero') {
            $entry.status = 'observed_zero'
            $entry.status_reason = $null
            $met = $true
        } else {
            $entry.status = 'capture_failed'
            $entry.status_reason = 'zero records: ' + [string]$Source['ZeroReason']
            $met = $false
            $message = 'source ' + $id + ': zero records: ' + [string]$Source['ZeroReason']
            $Notes.Add($message)
            $Log.Add($message)
        }
        Remove-WfPrimaryUnlessKept -Path $outputPath -Status $entry.status -Truncated $false -RecordCount $records -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) { $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                exit_code              = $report.exit_code
                timed_out              = $report.timed_out
                duration_ms            = $report.duration_ms
                stdout_bytes           = $outputBytes
                records                = $records
                mac_addresses_replaced = $report.protection.mac_addresses_replaced
                network_names_replaced = $report.protection.network_names_replaced
                output_encoding        = $config.output_encoding
            }
            verified_by = 'the process exit code, timing and byte counts are in result.json; the protected output is output.txt'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('exit code {0}; {1} records ({2})' -f $report.exit_code, $records, [string]$Source['RecordsMeaning'])
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Invoke-WfFileSource {
    # Reads one known file read only and writes, under raw/<id>/:
    #   source.json           the path (or the candidate paths), the cap, the
    #                         mode and the protection rules (role config)
    #   result.json           whether the file existed and could be read, the
    #                         SHA-256 of the original bytes, the replacement
    #                         counts (role report)
    #   <FileName>            the primary: in summary mode the summary (size,
    #                         last write time, SHA-256, line count, how many
    #                         address shaped tokens it holds), in copy mode
    #                         the protected text of the file
    # Summary mode is for free text that can name networks the current run
    # never saw (the WLAN report embeds "netsh wlan show all"); only the
    # summary leaves the machine and the owner reads the report at the PC.
    # Copy mode is for the owner's own configuration and log files (a
    # Process Lasso INI, its action log, a Stutter Guard journal): the text
    # is kept, after Protect-WfCopiedText has replaced every Windows user
    # profile folder name, e-mail shaped token and hardware address by a
    # pseudonym, and result.json records the SHA-256 of the original bytes so
    # a copy with zero replacements can be checked to be verbatim.
    # A file that does not exist at any candidate path, or cannot be read, is
    # not_collected with the message from Windows; a file above the cap is
    # capture_failed.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds = 300,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context = $null
    )
    $id = [string]$Source['Id']
    $fileName = [string]$Source['FileName']
    $mode = 'summary'
    if ($Source['Mode']) { $mode = [string]$Source['Mode'] }
    # A copy gate: the copy is allowed only when another copied file of this
    # run (a configuration) matches a pattern, for example the vendor's switch
    # that keeps process command lines out of its log being off. When the gate
    # does not pass, or the gating file was not copied, the file is
    # summarised instead, and result.json says which.
    $gate = $Source['CopyGate']
    $gateResult = $null
    if ($mode -eq 'copy' -and $null -ne $gate) {
        $gateResult = [ordered]@{ source = [string]$gate['Source']; pattern = [string]$gate['Pattern']; passed = $false; detail = $null }
        $gatingText = $null
        if ($null -ne $Context -and $Context.ContainsKey('CopiedTexts') -and $Context['CopiedTexts'].ContainsKey([string]$gate['Source'])) { $gatingText = [string]$Context['CopiedTexts'][[string]$gate['Source']] }
        if ($null -eq $gatingText) {
            $gateResult.detail = 'the gating file ' + [string]$gate['Source'] + ' was not copied in this run, so the switch it carries is unknown'
        } elseif ($gatingText -match [string]$gate['Pattern']) {
            $gateResult.passed = $true
            $gateResult.detail = 'the gating file matches the pattern'
        } else {
            $gateResult.detail = 'the gating file does not match the pattern: ' + [string]$gate['Reason']
        }
        if (-not $gateResult.passed) { $mode = 'summary' }
    }
    $kind = 'other'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'source.json' = 'config'; 'result.json' = 'report' }
    $roles[$fileName] = 'primary'
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $primaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/' + $fileName)
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        # The candidate paths, in order: an explicit path, else the known
        # folder plus the path tail and any alternate tails (a vendor whose
        # documentation names the log file two ways).
        $candidates = New-Object 'System.Collections.Generic.List[string]'
        if ([string]$Source['Path']) {
            $candidates.Add([string]$Source['Path'])
        } else {
            $folder = Get-WfKnownFolderPath -Name ([string]$Source['Folder'])
            $candidates.Add($folder + '\' + [string]$Source['PathTail'])
            foreach ($tail in (Get-WfList -Value $Source['AlternatePathTails'])) { $candidates.Add($folder + '\' + [string]$tail) }
        }
        $protection = $null
        $why = 'the file is free text that can name networks the current run never saw, so only its size, time, hash and token counts are recorded'
        if ($null -ne $gateResult -and -not $gateResult.passed) {
            $why = 'the file was to be copied, but its copy gate did not pass (' + [string]$gateResult.detail + '), so only its size, time, hash and token counts are recorded'
        } elseif ($mode -eq 'copy') {
            $why = 'the file is the owner''s own configuration or log; its text is kept, with user profile folder names, e-mail shaped tokens, UNC host names and hardware addresses replaced by pseudonyms (see protection)'
            $protection = Get-WfCopiedTextProtectionDescription
        }
        $config = [ordered]@{
            path               = $candidates[0]
            path_candidates    = @($candidates.ToArray())
            path_documented    = [bool]$Source['PathDocumented']
            max_artifact_bytes = $MaxArtifactBytes
            timeout_seconds    = $TimeoutSeconds
            mode               = $mode
            copy_gate          = $gateResult
            why                = $why
            protection         = $protection
            sharing            = 'the file is opened for reading with writers allowed to continue; a file being appended may be read mid line, and the hash is of the bytes read'
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/source.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @('System.IO.File.ReadAllBytes') + @($candidates.ToArray())
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        # The first candidate that exists is the file; the read result of the
        # last candidate tried is what the status is decided on.
        $path = $candidates[0]
        $read = $null
        foreach ($candidate in $candidates) {
            $path = $candidate
            $read = Read-WfFileBytes -Path $candidate -MaxBytes $MaxArtifactBytes -DeadlineUtc $deadline
            if ($read['Exists']) { break }
        }
        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $read['Exists']) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'the file does not exist: ' + ($candidates.ToArray() -join ' or ') + '. ' + [string]$Source['MissingHint']
        } elseif ($read['ErrorKind'] -eq 'timeout' -or (-not $read['ErrorKind'] -and (Get-WfUtcNow) -ge $deadline)) {
            $readErrorKind = 'timeout'
            $readErrorMessage = 'the read did not finish before the deadline ' + (ConvertTo-WfUtcString -Value $deadline)
        } elseif ($read['ErrorKind'] -eq 'access_denied') {
            $readErrorKind = 'access_denied'
            $readErrorMessage = [string]$read['ErrorMessage']
        } elseif ($read['ErrorKind'] -eq 'too_large') {
            $readErrorKind = 'other'
            $readErrorMessage = ('the file is {0} bytes, above the cap of {1}, and was not read' -f $read['Length'], $MaxArtifactBytes)
        } elseif ($read['ErrorKind']) {
            $readErrorKind = 'other'
            $readErrorMessage = [string]$read['ErrorMessage']
        }
        $entry.preflight = [ordered]@{
            ok     = ([bool]$read['Exists'] -and [bool]$read['Readable'])
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @(
                [ordered]@{ name = 'file_exists'; ok = [bool]$read['Exists']; detail = $path },
                [ordered]@{ name = 'file_readable'; ok = [bool]$read['Readable']; detail = $(if ($read['Readable']) { $null } else { [string]$read['ErrorMessage'] }) }
            )
        }
        $sourceSha = $null
        $summary = $null
        $copy = $null
        if (-not $readErrorKind) {
            $bytes = [byte[]]$read['Bytes']
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $sourceSha = (([System.BitConverter]::ToString($sha.ComputeHash($bytes))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
            if ($mode -eq 'copy') {
                $decoded = ConvertFrom-WfTextBytes -Bytes $bytes
                $copy = Protect-WfCopiedText -Text ([string]$decoded['Text']) -Salt ([string]$Context['Salt'])
                $copy['Encoding'] = [string]$decoded['Encoding']
                $copy['HadByteOrderMark'] = [bool]$decoded['HadByteOrderMark']
                if ($Context.ContainsKey('CopiedTexts')) { $Context['CopiedTexts'][$id] = [string]$copy['Text'] }
                Write-WfTextFile -Path $primaryPath -Text ([string]$copy['Text'])
                $copySize = (Get-Item -LiteralPath $primaryPath).Length
                if ($copySize -gt $MaxArtifactBytes) {
                    Remove-Item -LiteralPath $primaryPath -Force
                    $readErrorKind = 'other'
                    $readErrorMessage = ('the protected copy was {0} bytes, above the cap of {1}, and was removed' -f $copySize, $MaxArtifactBytes)
                }
            } else {
                $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes)
                $summary = [ordered]@{
                    path                = $path
                    bytes               = [int64]$bytes.Length
                    last_write_time_utc = $read['LastWriteUtc']
                    sha256              = $sourceSha
                    lines               = @(($text -replace "`r`n", "`n") -split "`n").Count
                    address_tokens      = @([regex]::Matches($text, (Get-WfMacAddressPattern))).Count
                    content_kept        = $false
                }
                Write-WfJsonFile -Path $primaryPath -Object $summary
            }
        }
        $stopped = Get-WfUtcNow
        $verbatim = $null
        if ($null -ne $copy) {
            $verbatim = ((-not $copy['HadByteOrderMark']) -and $copy['Encoding'] -eq 'utf-8' -and ([int]$copy['UserCount'] + [int]$copy['MailCount'] + [int]$copy['HostCount'] + [int]$copy['MacCount']) -eq 0)
        }
        $report = [ordered]@{
            path                = $path
            path_candidates     = @($candidates.ToArray())
            exists              = [bool]$read['Exists']
            readable            = [bool]$read['Readable']
            error               = $read['ErrorMessage']
            source_bytes        = $read['Length']
            source_sha256       = $sourceSha
            last_write_time_utc = $read['LastWriteUtc']
            mode                = $mode
            copy_gate           = $gateResult
            summarised          = ($null -ne $summary)
            copied              = ($null -ne $copy -and -not $readErrorKind)
            source_encoding     = $(if ($null -ne $copy) { $copy['Encoding'] } else { $null })
            source_byte_order_mark = $(if ($null -ne $copy) { $copy['HadByteOrderMark'] } else { $null })
            copy_is_verbatim    = $verbatim
            protection          = $(if ($null -ne $copy) { [ordered]@{ user_profile_names_replaced = $copy['UserCount']; email_addresses_replaced = $copy['MailCount']; unc_hosts_replaced = $copy['HostCount']; mac_addresses_replaced = $copy['MacCount'] } } else { $null })
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if ($readErrorKind) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } else {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
            $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped
            if ($mode -eq 'copy') {
                $Notes.Add(('source {0}: the file was copied with {1} user profile folder names, {2} e-mail shaped tokens, {3} UNC host names and {4} hardware addresses replaced by pseudonyms; result.json holds the SHA-256 of the original bytes' -f $id, $copy['UserCount'], $copy['MailCount'], $copy['HostCount'], $copy['MacCount']))
            } elseif ($null -ne $gateResult) {
                $Notes.Add('source ' + $id + ': the file exists and was summarised, not copied, because its copy gate did not pass: ' + [string]$gateResult.detail)
            } else {
                $Notes.Add('source ' + $id + ': the file exists and was summarised, not copied; its text can name networks the current run never saw')
            }
        }
        Remove-WfPrimaryUnlessKept -Path $primaryPath -Status $entry.status -Truncated $false -RecordCount $(if ($met) { 1 } else { 0 }) -Log $Log -SourceId $id
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                path                = $path
                exists              = $report.exists
                readable            = $report.readable
                source_bytes        = $report.source_bytes
                source_sha256       = $sourceSha
                last_write_time_utc = $read['LastWriteUtc']
                mode                = $mode
                content_kept        = ($mode -eq 'copy' -and $met)
                copy_is_verbatim    = $verbatim
            }
            verified_by = $(if ($mode -eq 'copy') { 'the source size, time and hash are in result.json next to the replacement counts; the primary is the protected copy' } else { 'the source size, time and hash are in the summary artifact; the text itself is not in the bundle' })
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = $(if (-not $met) { $readErrorMessage } elseif ($mode -eq 'copy') { ('{0} bytes copied' -f $read['Length']) } else { ('{0} bytes summarised' -f $summary.bytes) })
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $primaryPath) { Remove-Item -LiteralPath $primaryPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Get-WfPnpDevicePropertyKeys {
    # The documented device properties read for every selected device:
    # https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-parent
    # https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-locationpaths
    return @('DEVPKEY_Device_Parent', 'DEVPKEY_Device_LocationPaths', 'DEVPKEY_Device_LocationInfo', 'DEVPKEY_Device_Address',
        'DEVPKEY_Device_ContainerId', 'DEVPKEY_Device_BusReportedDeviceDesc', 'DEVPKEY_Device_EnumeratorName')
}

function Test-WfPnpSeed {
    param([hashtable]$Device, $Classes, $InstancePrefixes)
    $class = [string]$Device['class']
    foreach ($candidate in @($Classes)) { if ($class -and $class.Equals([string]$candidate, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    $instance = [string]$Device['instance_id']
    foreach ($prefix in @($InstancePrefixes)) { if ($instance.StartsWith([string]$prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

function Invoke-WfPnpSource {
    # Lists present Plug and Play devices of the classes the definition
    # names (and, when asked, every ancestor up to the root of the device
    # tree, so a receiver can be followed to its hub and host controller) and
    # writes, under raw/<id>/:
    #   query.json    the classes, prefixes, property keys and caps (role config)
    #   result.json   how many devices were present, selected, added as
    #                 ancestors, and how many property reads failed (role report)
    #   devices.json  one element per device (role primary)
    # Zero selected devices is capture_failed unless the definition says the
    # class may be absent (ZeroIsObservation), in which case the completed
    # enumeration of the other present devices is the proof of coverage.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    $id = [string]$Source['Id']
    # Assigned, not wrapped in @(): the helper returns a wrapped array, and
    # @(<call>) would make one element of the whole list.
    $classes = Get-WfList -Value $Source['Classes']
    $prefixes = Get-WfList -Value $Source['InstancePrefixes']
    $includeAncestors = $true
    if ($Source.ContainsKey('IncludeAncestors')) { $includeAncestors = [bool]$Source['IncludeAncestors'] }
    $zeroIsObservation = $false
    if ($Source.ContainsKey('ZeroIsObservation')) { $zeroIsObservation = [bool]$Source['ZeroIsObservation'] }
    $kind = 'config_snapshot'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'query.json' = 'config'; 'result.json' = 'report'; 'devices.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $devicesPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/devices.json')
    $keys = Get-WfPnpDevicePropertyKeys
    $selected = 0
    $truncated = $false
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $query = [ordered]@{
            enumeration        = 'Win32_PnPEntity, present devices, root/cimv2'
            classes            = @($classes)
            instance_prefixes  = @($prefixes)
            include_ancestors  = $includeAncestors
            property_keys      = @($keys)
            max_records        = $MaxEvents
            max_artifact_bytes = $MaxArtifactBytes
            timeout_seconds    = $TimeoutSeconds
            zero_is_observation = $zeroIsObservation
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.command = @('Get-CimInstance', '-ClassName', 'Win32_PnPEntity', '-Filter', 'Present = TRUE', 'Get-PnpDeviceProperty', '-KeyName', (@($keys) -join ','))
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }

        $enumeration = Get-WfPnpDevices -TimeoutSeconds ([int][math]::Ceiling((Get-WfRemainingSeconds -DeadlineUtc $deadline)))
        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $enumeration['Ok']) {
            $readErrorKind = [string]$enumeration['ErrorKind']
            if (-not $readErrorKind) { $readErrorKind = 'other' }
            $readErrorMessage = [string]$enumeration['ErrorMessage']
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @([ordered]@{ name = 'devices_enumerated'; ok = (-not $readErrorKind); detail = $(if ($readErrorKind) { $readErrorMessage } else { 'Win32_PnPEntity' }) })
        }
        $all = @{}
        $present = 0
        $propertyErrors = 0
        $ancestors = 0
        $peers = 0
        $accumulator = New-WfRowAccumulator -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes
        if (-not $readErrorKind) {
            foreach ($device in @($enumeration['Devices'])) {
                $present += 1
                $key = ([string]$device['instance_id']).ToUpperInvariant()
                if (-not $all.ContainsKey($key)) { $all[$key] = $device }
            }
            if ($present -eq 0) {
                $readErrorKind = 'other'
                $readErrorMessage = 'the enumeration returned no present device at all, which never happens on a running machine'
            }
        }
        if (-not $readErrorKind) {
            $queue = New-Object 'System.Collections.Generic.Queue[object]'
            $queued = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($device in @($enumeration['Devices'])) {
                if (Test-WfPnpSeed -Device $device -Classes $classes -InstancePrefixes $prefixes) {
                    $key = ([string]$device['instance_id']).ToUpperInvariant()
                    if ($queued.Add($key)) { $queue.Enqueue(@{ Device = $device; Seed = $true }) }
                }
            }
            while ($queue.Count -gt 0) {
                if ((Get-WfUtcNow) -ge $deadline) {
                    $readErrorKind = 'timeout'
                    $readErrorMessage = ('the device properties were not all read before the deadline ' + (ConvertTo-WfUtcString -Value $deadline) + '; ' + $accumulator.Rows.Count + ' devices had been read')
                    break
                }
                $item = $queue.Dequeue()
                $device = $item['Device']
                $row = [ordered]@{}
                foreach ($name in $device.Keys) { $row[$name] = $device[$name] }
                $row['is_seed'] = [bool]$item['Seed']
                $properties = Get-WfPnpDeviceProperties -InstanceId ([string]$device['instance_id']) -KeyNames $keys
                $row['parent_instance_id'] = $null
                $row['location_paths'] = @()
                $row['location_info'] = $null
                $row['address'] = $null
                $row['container_id'] = $null
                $row['bus_reported_description'] = $null
                $row['enumerator'] = $null
                $row['property_error'] = $null
                if ($properties['Ok']) {
                    $values = $properties['Values']
                    if ($values.ContainsKey('DEVPKEY_Device_Parent')) { $row['parent_instance_id'] = $values['DEVPKEY_Device_Parent'] }
                    if ($values.ContainsKey('DEVPKEY_Device_LocationPaths')) { $row['location_paths'] = Get-WfList -Value $values['DEVPKEY_Device_LocationPaths'] }
                    if ($values.ContainsKey('DEVPKEY_Device_LocationInfo')) { $row['location_info'] = $values['DEVPKEY_Device_LocationInfo'] }
                    if ($values.ContainsKey('DEVPKEY_Device_Address')) { $row['address'] = $values['DEVPKEY_Device_Address'] }
                    if ($values.ContainsKey('DEVPKEY_Device_ContainerId')) { $row['container_id'] = $values['DEVPKEY_Device_ContainerId'] }
                    if ($values.ContainsKey('DEVPKEY_Device_BusReportedDeviceDesc')) { $row['bus_reported_description'] = $values['DEVPKEY_Device_BusReportedDeviceDesc'] }
                    if ($values.ContainsKey('DEVPKEY_Device_EnumeratorName')) { $row['enumerator'] = $values['DEVPKEY_Device_EnumeratorName'] }
                } else {
                    $propertyErrors += 1
                    $row['property_error'] = [string]$properties['ErrorMessage']
                }
                if (-not $item['Seed']) { $ancestors += 1 }
                $parent = [string]$row['parent_instance_id']
                if ((Test-WfBluetoothPeerInstance -InstanceId ([string]$row['instance_id'])) -or (Test-WfBluetoothPeerInstance -InstanceId $parent)) {
                    $peers += 1
                    $row = Protect-WfBluetoothPeerRow -Row $row -Salt ([string]$Context['Salt'])
                }
                if (-not (Add-WfRow -Accumulator $accumulator -Row $row)) { $truncated = $true; break }
                if ($includeAncestors -and $parent) {
                    $parentKey = $parent.ToUpperInvariant()
                    if ($all.ContainsKey($parentKey) -and $queued.Add($parentKey)) { $queue.Enqueue(@{ Device = $all[$parentKey]; Seed = $false }) }
                }
            }
        }
        $selected = $accumulator.Rows.Count
        if ($propertyErrors -gt 0) {
            $message = ('source {0}: the properties of {1} devices could not be read; those rows carry property_error and no parent, so their chain to the host controller is unknown' -f $id, $propertyErrors)
            $Notes.Add($message)
            $Log.Add($message)
        }
        if (-not $readErrorKind) {
            Write-WfJsonLinesFile -Path $devicesPath -Lines $accumulator.Lines.ToArray()
            $size = (Get-Item -LiteralPath $devicesPath).Length
            if ($size -gt $MaxArtifactBytes) {
                Remove-Item -LiteralPath $devicesPath -Force
                $readErrorKind = 'other'
                $readErrorMessage = ('devices.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }
        $stopped = Get-WfUtcNow
        $report = [ordered]@{
            started_utc      = ConvertTo-WfUtcString -Value $started
            stopped_utc      = ConvertTo-WfUtcString -Value $stopped
            devices_present  = $present
            devices_selected = $selected
            seeds            = ($selected - $ancestors)
            ancestors_added  = $ancestors
            peer_nodes_pseudonymised = $peers
            property_errors  = $propertyErrors
            truncated        = $truncated
            error            = $(if ($readErrorKind) { $readErrorMessage } else { $null })
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if ($readErrorKind -or $truncated) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -RecordCount $selected -Truncated $truncated `
                -OldestRecordUtc $started -WindowStartUtc $started -TruncationDetail ([string]$accumulator.Reason + '; the devices read before the cap were kept')
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } elseif ($selected -gt 0) {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        } elseif ($zeroIsObservation) {
            $entry.status = 'observed_zero'
            $entry.status_reason = $null
            $met = $true
        } else {
            $entry.status = 'capture_failed'
            $entry.status_reason = ('none of the {0} present devices matched the requested classes {1}, which never happens for these classes on a running machine, so this is treated as a failed read and not as an observation' -f $present, (@($classes) -join ', '))
            $met = $false
        }
        Remove-WfPrimaryUnlessKept -Path $devicesPath -Status $entry.status -Truncated $truncated -RecordCount $selected -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) { $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                devices_present  = $present
                devices_selected = $(if (Test-Path -LiteralPath $devicesPath) { $selected } else { 0 })
                ancestors_added  = $ancestors
                property_errors  = $propertyErrors
                truncated        = $truncated
            }
            verified_by = 'the enumeration completed without error; the device counts are in result.json'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('{0} present devices, {1} selected ({2} ancestors), {3} property reads failed' -f $present, $selected, $ancestors, $propertyErrors)
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $devicesPath) { Remove-Item -LiteralPath $devicesPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# ---------------------------------------------------------------------------
# Copied text. The owner's own configuration and log files (a Process Lasso
# INI and action log, a Stutter Guard journal) are kept readable, because
# they are what the analysis reads. Three things in them are not the owner's
# to publish or identify a person: a Windows user profile folder name in a
# path (\Users\<name>\), an e-mail shaped token, and a hardware address. Each
# is found by its shape, never by a label, and replaced by a pseudonym keyed
# with the run's salt; so is the host of a UNC path, which names a computer.
# The standard profile folders Windows documents (Public, Default, Default
# User, All Users) are not personal and stay readable:
# https://learn.microsoft.com/windows/win32/shell/knownfolderid
# ---------------------------------------------------------------------------

function Get-WfUserProfilePattern {
    # The folder name after \Users\ or /Users/, up to the next separator. A
    # separator may be doubled, as in a JSON or INI escaped path.
    return '(?<=[\\/]{1,2}[Uu][Ss][Ee][Rr][Ss][\\/]{1,2})[^\\/\r\n"''<>|:*?]+(?=[\\/]|$|["''\s,;])'
}

function Get-WfEmailPattern {
    return '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
}

function Get-WfStandardProfileFolders {
    return @('Public', 'Default', 'Default User', 'All Users')
}

function Get-WfUncHostPattern {
    # The host part of a UNC path, \\host\share, which names a computer: two
    # separators (up to four when the text is JSON escaped) at the start of a
    # token, then the host, then a separator. A separator pair inside a path
    # (an escaped C:\\Users) is not a UNC root.
    return '(?<=(?:^|[\s="''(,\[])[\\/]{2,4})[^\\/\r\n"''<>|:*?\s]+(?=[\\/])'
}

function ConvertTo-WfPseudonymisedMatches {
    # Replaces every match of the pattern by <kind>-<12 hex>, except matches
    # the Keep list names (compared without case). Returns the text and the
    # number of replacements.
    param([string]$Text, [string]$Pattern, [string]$Kind, [string]$Salt, [string[]]$Keep = @())
    if ($null -eq $Text) { return [ordered]@{ Text = ''; Count = 0 } }
    $found = [regex]::Matches($Text, $Pattern)
    if ($found.Count -eq 0) { return [ordered]@{ Text = $Text; Count = 0 } }
    $builder = New-Object System.Text.StringBuilder
    $last = 0
    $count = 0
    foreach ($match in $found) {
        $null = $builder.Append($Text.Substring($last, $match.Index - $last))
        $kept = $false
        foreach ($name in @($Keep)) { if ($match.Value.Equals([string]$name, [System.StringComparison]::OrdinalIgnoreCase)) { $kept = $true } }
        if ($kept) {
            $null = $builder.Append($match.Value)
        } else {
            $null = $builder.Append((ConvertTo-WfPseudonym -Kind $Kind -Value $match.Value.ToLowerInvariant() -Salt $Salt))
            $count += 1
        }
        $last = $match.Index + $match.Length
    }
    $null = $builder.Append($Text.Substring($last))
    return [ordered]@{ Text = $builder.ToString(); Count = $count }
}

function Protect-WfCopiedText {
    # The protection applied to every copied text: user profile folder names,
    # e-mail shaped tokens, UNC host names, hardware addresses, each found by
    # its shape. Line endings and everything else stay as they are. What has
    # no shape (an account name inside an argument) is not caught, which is
    # why vendor text that can carry command lines is kept out by a gate.
    param([string]$Text, [string]$Salt)
    $users = ConvertTo-WfPseudonymisedMatches -Text $Text -Pattern (Get-WfUserProfilePattern) -Kind 'user' -Salt $Salt -Keep (Get-WfStandardProfileFolders)
    $mails = ConvertTo-WfPseudonymisedMatches -Text ([string]$users['Text']) -Pattern (Get-WfEmailPattern) -Kind 'mail' -Salt $Salt
    $hosts = ConvertTo-WfPseudonymisedMatches -Text ([string]$mails['Text']) -Pattern (Get-WfUncHostPattern) -Kind 'host' -Salt $Salt
    $macs = Protect-WfMacAddresses -Text ([string]$hosts['Text']) -Salt $Salt
    return [ordered]@{ Text = [string]$macs['Text']; UserCount = [int]$users['Count']; MailCount = [int]$mails['Count']; HostCount = [int]$hosts['Count']; MacCount = [int]$macs['Count'] }
}

function Get-WfCopiedTextProtectionDescription {
    return [ordered]@{
        mode           = 'copy'
        user_pseudonym = 'user-<first 12 hex of SHA-256(salt, name)>, every folder name after \Users\ in a path, except the standard folders Public, Default, Default User and All Users'
        mail_pseudonym = 'mail-<first 12 hex of SHA-256(salt, address)>, every e-mail shaped token'
        host_pseudonym = 'host-<first 12 hex of SHA-256(salt, name)>, the host of every UNC path (two leading separators)'
        mac_pseudonym  = 'mac-<first 12 hex of SHA-256(salt, address)>, every six pair hardware address'
        limits         = 'a DOMAIN\\user pair, an account name in a command line argument, or a computer name standing alone has no shape of its own and is not caught; a copy gate keeps vendor text that can carry command lines out (see copy_gate)'
        salt           = 'random per run, never written; pseudonyms are consistent inside this bundle only'
        encoding       = 'the copy is UTF-8 without a byte order mark; the source encoding is recorded in result.json'
    }
}

function ConvertFrom-WfTextBytes {
    # Decodes a text file by its byte order mark (UTF-8, UTF-16 LE, UTF-16
    # BE) and as UTF-8 otherwise. Returns the text, the encoding name and
    # whether a mark was present, so result.json can say whether the copy is
    # byte for byte the source.
    param([byte[]]$Bytes)
    $result = [ordered]@{ Text = ''; Encoding = 'utf-8'; HadByteOrderMark = $false }
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $result }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $result.HadByteOrderMark = $true
        $result.Text = (New-Object System.Text.UTF8Encoding($false)).GetString($Bytes, 3, $Bytes.Length - 3)
        return $result
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        $result.HadByteOrderMark = $true
        $result.Encoding = 'utf-16le'
        $result.Text = (New-Object System.Text.UnicodeEncoding($false, $false)).GetString($Bytes, 2, $Bytes.Length - 2)
        return $result
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        $result.HadByteOrderMark = $true
        $result.Encoding = 'utf-16be'
        $result.Text = (New-Object System.Text.UnicodeEncoding($true, $false)).GetString($Bytes, 2, $Bytes.Length - 2)
        return $result
    }
    $result.Text = (New-Object System.Text.UTF8Encoding($false)).GetString($Bytes)
    return $result
}

# ---------------------------------------------------------------------------
# Registry values. A value is recorded as its name, its registry type, the
# bytes Windows holds for it, and a JSON scalar of the data, so a reader can
# decode a mask or a policy from the bytes and never has to trust the
# collector's interpretation. Types follow RegistryValueKind:
# https://learn.microsoft.com/dotnet/api/microsoft.win32.registryvaluekind
# ---------------------------------------------------------------------------

function ConvertTo-WfRegistryValueRecord {
    # One registry value as written to keys.json. Kind is the RegistryValueKind
    # name as text (DWord, QWord, Binary, String, ExpandString, MultiString,
    # None, Unknown); Data is what RegistryKey.GetValue returned. The bytes
    # are the little endian image for the numeric kinds, the bytes themselves
    # for Binary, and the UTF-16 LE text for the string kinds, which is how
    # the registry stores each of them.
    param([string]$Name, [string]$Kind, $Data)
    $record = [ordered]@{ name = $Name; kind = $Kind; data = $null; bytes_hex = $null; byte_count = $null }
    $bytes = $null
    switch ($Kind) {
        'DWord' {
            $number = [int64][int32]$Data
            if ($number -lt 0) { $number += 4294967296 }
            $record['data'] = $number
            $bytes = [System.BitConverter]::GetBytes([uint32]$number)
        }
        'QWord' {
            $signed = [int64]$Data
            $bytes = [System.BitConverter]::GetBytes($signed)
            $record['data'] = ConvertTo-WfScalar -Value ([System.BitConverter]::ToUInt64($bytes, 0))
        }
        'Binary' {
            $bytes = [byte[]]$Data
            $record['data'] = ConvertTo-WfScalar -Value $bytes
        }
        'String' { $record['data'] = [string]$Data; $bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$Data) }
        'ExpandString' { $record['data'] = [string]$Data; $bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$Data) }
        'MultiString' {
            $parts = Get-WfList -Value $Data
            $items = @(foreach ($part in $parts) { [string]$part })
            $record['data'] = $items
            $bytes = [System.Text.Encoding]::Unicode.GetBytes(($items -join "`0"))
        }
        default { $record['data'] = ConvertTo-WfScalar -Value $Data }
    }
    if ($null -ne $bytes) {
        $record['bytes_hex'] = (([System.BitConverter]::ToString([byte[]]$bytes)) -replace '-', '').ToLowerInvariant()
        $record['byte_count'] = [int]([byte[]]$bytes).Length
    }
    return $record
}

function Read-WfRegistryKeyRecord {
    # One key as written to keys.json: whether it exists, the error when it
    # could not be opened, its subkey names and every value present (or only
    # the named values, each recorded as present or absent, when ValueNames is
    # given). Nothing is created or written: a missing key is recorded as
    # absent, never fitted to a template.
    param([string]$Path, [string[]]$ValueNames = $null)
    $read = Get-WfRegistryKey -Path $Path
    $record = [ordered]@{ path = $Path; exists = [bool]$read['Exists']; error_kind = $read['ErrorKind']; error = $read['ErrorMessage']; subkeys = @(); values = @() }
    if (-not $read['Exists'] -and $read['ErrorKind'] -eq 'not_found') {
        # Absent is an observation, not an error.
        $record['error_kind'] = $null
        $record['error'] = $null
    }
    # A key that could not be opened has unknown content: nothing under it is
    # enumerated, and nothing under it is called absent.
    if ($read['ErrorKind'] -or -not $read['Exists']) { return $record }
    $subKeyNames = Get-WfList -Value $read['SubKeyNames']
    $record['subkeys'] = @(foreach ($name in $subKeyNames) { [string]$name })
    $values = New-Object 'System.Collections.Generic.List[object]'
    $present = @{}
    $found = Get-WfList -Value $read['Values']
    foreach ($value in $found) {
        $name = [string]$value['Name']
        $present[$name.ToLowerInvariant()] = $value
    }
    if ($null -eq $ValueNames) {
        foreach ($value in $found) {
            $item = ConvertTo-WfRegistryValueRecord -Name ([string]$value['Name']) -Kind ([string]$value['Kind']) -Data $value['Data']
            $item['present'] = $true
            $values.Add($item)
        }
    } else {
        foreach ($name in $ValueNames) {
            $key = ([string]$name).ToLowerInvariant()
            if ($present.ContainsKey($key)) {
                $value = $present[$key]
                $item = ConvertTo-WfRegistryValueRecord -Name ([string]$value['Name']) -Kind ([string]$value['Kind']) -Data $value['Data']
                $item['present'] = $true
            } else {
                $item = [ordered]@{ name = [string]$name; kind = $null; data = $null; bytes_hex = $null; byte_count = $null; present = $false }
            }
            $values.Add($item)
        }
    }
    $record['values'] = @($values.ToArray())
    return $record
}

# ---------------------------------------------------------------------------
# Device hardware keys. Microsoft: "You must not directly open a device's
# hardware key"; an existing one is opened with SetupDiOpenDevRegKey and
# DIREG_DEV, with minimal access:
# https://learn.microsoft.com/windows-hardware/drivers/install/opening-a-device-s-hardware-key
# https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey
# The two subkeys read under it are the ones the interrupt pages name:
# https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority
# https://learn.microsoft.com/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry
# The sequencing below is plain PowerShell over eight native calls exposed by
# New-WfDeviceKeyNative (the real one compiles one literal declaration; the
# test suite substitutes a recorder), so every branch runs under Pester: a
# missing hardware key, a missing leaf, a denied key, a device that is gone, a
# value that needs a larger buffer, a cap, a deadline. Nothing here creates,
# writes or deletes; the access asked for is KEY_READ (0x20019), which holds no
# set, create or delete right:
# https://learn.microsoft.com/windows/win32/sysinfo/registry-key-security-and-access-rights
# ---------------------------------------------------------------------------

function Get-WfDeviceKeyConstants {
    # SetupAPI flags and the error codes the sequencing tells apart. Learn
    # documents KEY_READ as 0x20019 (registry key security and access rights),
    # the two SetupAPI codes in their HRESULT form (COM error codes:
    # SPAPI_E_KEY_DOES_NOT_EXIST 0x800F0204 "the requested device registry key
    # does not exist", SPAPI_E_NO_SUCH_DEVINST 0x800F020B "the device instance
    # does not exist in the hardware tree") and that a SetupDi function's
    # GetLastError value is a setupapi.h code which HRESULT_FROM_SETUPAPI maps
    # to that form; the Win32 form the API returns (0xE0000204, 0xE000020B) and
    # the flag values come from the public SDK header setupapi.h:
    # https://learn.microsoft.com/windows/win32/sysinfo/registry-key-security-and-access-rights
    # https://learn.microsoft.com/windows/win32/com/com-error-codes-4
    # https://learn.microsoft.com/windows-hardware/drivers/install/guidelines-for-using-setupapi
    # https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/SetupAPI.h
    return @{
        DICS_FLAG_GLOBAL         = [uint32]1
        DIREG_DEV                = [uint32]1
        KEY_READ                 = [uint32]0x20019
        ERROR_SUCCESS            = 0
        ERROR_FILE_NOT_FOUND     = 2
        ERROR_ACCESS_DENIED      = 5
        ERROR_MORE_DATA          = 234
        ERROR_NO_MORE_ITEMS      = 259
        ERROR_KEY_DOES_NOT_EXIST = [int64]3758096900
        ERROR_NO_SUCH_DEVINST    = [int64]3758096907
    }
    # The last two are 0xE0000204 and 0xE000020B (APPLICATION_ERROR_MASK |
    # ERROR_SEVERITY_ERROR | 0x204 and 0x20B), written in decimal because a
    # hexadecimal literal above 0x7FFFFFFF is a negative [int32] in PowerShell.
}

function Get-WfInterruptManagementSubkeys {
    # The fixed relative subkeys, and nothing else, ever opened under a hardware key.
    return @('Interrupt Management\Affinity Policy', 'Interrupt Management\MessageSignaledInterruptProperties')
}

function ConvertTo-WfUnsignedCode {
    # GetLastWin32Error returns an int; SetupAPI codes are above 0x80000000, so
    # compare as unsigned.
    param($Code)
    if ($null -eq $Code) { return $null }
    return ([int64]$Code -band [int64]4294967295)
}

function Get-WfRegistryTypeName {
    # Registry value types: https://learn.microsoft.com/windows/win32/sysinfo/registry-value-types
    param([int64]$Type)
    switch ($Type) {
        0 { return 'REG_NONE' }
        1 { return 'REG_SZ' }
        2 { return 'REG_EXPAND_SZ' }
        3 { return 'REG_BINARY' }
        4 { return 'REG_DWORD' }
        5 { return 'REG_DWORD_BIG_ENDIAN' }
        6 { return 'REG_LINK' }
        7 { return 'REG_MULTI_SZ' }
        8 { return 'REG_RESOURCE_LIST' }
        9 { return 'REG_FULL_RESOURCE_DESCRIPTOR' }
        10 { return 'REG_RESOURCE_REQUIREMENTS_LIST' }
        11 { return 'REG_QWORD' }
    }
    return $null
}

function ConvertFrom-WfRawRegistryValue {
    # One value as the API returned it (name, numeric type, bytes) into the
    # record keys.json carries: the type code and its name, the bytes as hex,
    # and a scalar decoded from the bytes for the numeric kinds. String kinds
    # are free text that could name a person or a machine; under an interrupt
    # policy key they have no documented meaning, so their text and bytes are
    # omitted with a reason and only the name, type and size are kept.
    param([string]$Name, [int64]$Type, [byte[]]$Bytes)
    $count = 0
    if ($null -ne $Bytes) { $count = $Bytes.Length }
    $record = [ordered]@{ name = $Name; type_code = $Type; kind = (Get-WfRegistryTypeName -Type $Type); data = $null; bytes_hex = $null; byte_count = $count; present = $true; omitted_reason = $null }
    switch ($Type) {
        4 { if ($count -ge 4) { $record['data'] = [int64][System.BitConverter]::ToUInt32($Bytes, 0) } }
        5 { if ($count -ge 4) { $copy = [byte[]]$Bytes[0..3]; [System.Array]::Reverse($copy); $record['data'] = [int64][System.BitConverter]::ToUInt32($copy, 0) } }
        11 { if ($count -ge 8) { $record['data'] = ConvertTo-WfScalar -Value ([System.BitConverter]::ToUInt64($Bytes, 0)) } }
        { $_ -eq 1 -or $_ -eq 2 -or $_ -eq 7 -or $_ -eq 6 } {
            $record['omitted_reason'] = 'a string typed value is free text with no documented meaning under this key; its text and bytes are not kept'
            return $record
        }
    }
    if ($count -gt 0) { $record['bytes_hex'] = (([System.BitConverter]::ToString($Bytes)) -replace '-', '').ToLowerInvariant() } else { $record['bytes_hex'] = '' }
    if ($null -eq $record['data'] -and $Type -eq 3) { $record['data'] = $record['bytes_hex'] }
    return $record
}

function New-WfDeviceKeyLeafRecord {
    param([string]$Subkey)
    return [ordered]@{ subkey = $Subkey; exists = $null; error_code = $null; error = $null; enumeration_complete = $null; values = @() }
}

function Read-WfDeviceKeyLeaf {
    # Enumerates the values of one opened key with RegEnumValueW, growing the
    # data buffer on ERROR_MORE_DATA up to the byte cap, stopping at the value
    # cap or the deadline (both leave enumeration_complete false, so a reader
    # knows unvisited values are unknown, not absent).
    param($Api, [IntPtr]$Handle, [hashtable]$Constants, [int]$MaxValues, [int64]$MaxBytes, [datetime]$DeadlineUtc, $Record)
    $values = New-Object 'System.Collections.Generic.List[object]'
    $index = [uint32]0
    $dataSize = 4096
    $Record['enumeration_complete'] = $false
    while ($true) {
        if ((Get-WfUtcNow) -ge $DeadlineUtc) { $Record['error'] = 'the deadline passed while enumerating values; the values read so far are kept and the rest are unknown'; break }
        if ($values.Count -ge $MaxValues) { $Record['error'] = ('the cap of ' + $MaxValues + ' values was reached; the rest are unknown'); break }
        $name = New-Object System.Text.StringBuilder 16384
        $nameLength = [uint32]16383
        $type = [uint32]0
        $data = New-Object byte[] $dataSize
        $dataLength = [uint32]$dataSize
        $status = [int]$Api.RegEnumValueW($Handle, $index, $name, [ref]$nameLength, [IntPtr]::Zero, [ref]$type, $data, [ref]$dataLength)
        if ($status -eq $Constants['ERROR_NO_MORE_ITEMS']) { $Record['enumeration_complete'] = $true; break }
        if ($status -eq $Constants['ERROR_MORE_DATA']) {
            if ([int64]$dataLength -gt $MaxBytes) { $Record['error'] = ('a value needs ' + $dataLength + ' bytes, above the cap of ' + $MaxBytes + '; the values read so far are kept and the rest are unknown'); break }
            $dataSize = [int][math]::Max([int64]$dataLength, [int64]$dataSize * 2)
            if ($dataSize -gt $MaxBytes) { $dataSize = [int]$MaxBytes }
            continue
        }
        if ($status -ne $Constants['ERROR_SUCCESS']) {
            $Record['error_code'] = $status
            $Record['error'] = 'RegEnumValueW returned ' + $status + ' at index ' + $index + '; the values read so far are kept and the rest are unknown'
            break
        }
        $bytes = New-Object byte[] ([int]$dataLength)
        if ($dataLength -gt 0) { [System.Array]::Copy($data, $bytes, [int]$dataLength) }
        $values.Add((ConvertFrom-WfRawRegistryValue -Name $name.ToString() -Type ([int64]$type) -Bytes $bytes))
        $index += 1
    }
    $Record['values'] = @($values.ToArray())
    return $Record
}

function Get-WfDeviceInterruptPolicy {
    # The interrupt policy of one present device, read through the documented
    # device key API: a private device information set, the device opened by
    # its instance id (never an empty id, which would open the root device),
    # its hardware key opened with global scope, DIREG_DEV and KEY_READ, and the
    # two fixed relative subkeys opened and enumerated under that handle. Every
    # handle is closed and the set destroyed on every path.
    # The result separates stages so a reader can tell "the key is not there"
    # (the hardware key stage answered ERROR_KEY_DOES_NOT_EXIST, or a leaf
    # answered ERROR_FILE_NOT_FOUND under an opened hardware key) from "could
    # not look" (denied, device gone, native load failed, deadline): only the
    # first establishes absence; the second leaves exists null.
    param([string]$InstanceId, [int]$MaxValues = 64, [int64]$MaxBytes = 1048576, [datetime]$DeadlineUtc = [datetime]::MaxValue)
    $c = Get-WfDeviceKeyConstants
    $result = [ordered]@{
        Ok = $false; Stage = 'argument'; ErrorCode = $null; ErrorMessage = $null; DeviceOpened = $false
        HardwareKey = [ordered]@{ exists = $null; error_code = $null; error = $null }
        InterruptManagement = [ordered]@{ exists = $null; error_code = $null; error = $null }
        Leaves = @()
    }
    $leaves = New-Object 'System.Collections.Generic.List[object]'
    foreach ($subkey in (Get-WfInterruptManagementSubkeys)) { $leaves.Add((New-WfDeviceKeyLeafRecord -Subkey $subkey)) }
    $result.Leaves = @($leaves.ToArray())
    if (-not $InstanceId -or $InstanceId.Trim().Length -eq 0) {
        $result.ErrorMessage = 'the instance id is empty; an empty id would open the root device instead of the selected one'
        return $result
    }
    $result.Stage = 'compile'
    $native = New-WfDeviceKeyNative
    if (-not $native['Ok']) {
        $result.ErrorMessage = [string]$native['Error']
        return $result
    }
    $api = $native['Api']
    $invalid = [IntPtr](-1)
    $set = $invalid
    $hardwareKey = [IntPtr]::Zero
    $open = New-Object 'System.Collections.Generic.List[IntPtr]'
    try {
        $result.Stage = 'create_set'
        $set = [IntPtr]$api.SetupDiCreateDeviceInfoList([IntPtr]::Zero, [IntPtr]::Zero)
        if ($set -eq $invalid) {
            $result.ErrorCode = ConvertTo-WfUnsignedCode -Code $api.LastError()
            $result.ErrorMessage = 'SetupDiCreateDeviceInfoList failed'
            return $result
        }
        $result.Stage = 'open_device'
        $data = $api.NewDeviceInfoData()
        $opened = [bool]$api.SetupDiOpenDeviceInfoW($set, $InstanceId, [IntPtr]::Zero, [uint32]0, [ref]$data)
        if (-not $opened) {
            $result.ErrorCode = ConvertTo-WfUnsignedCode -Code $api.LastError()
            if ($result.ErrorCode -eq $c['ERROR_NO_SUCH_DEVINST']) { $result.ErrorMessage = 'SetupDiOpenDeviceInfoW: the device instance is not there (ERROR_NO_SUCH_DEVINST); its keys are unknown, not absent' }
            else { $result.ErrorMessage = 'SetupDiOpenDeviceInfoW failed' }
            return $result
        }
        $result.DeviceOpened = $true
        $result.Stage = 'open_hardware_key'
        $hardwareKey = [IntPtr]$api.SetupDiOpenDevRegKey($set, [ref]$data, $c['DICS_FLAG_GLOBAL'], [uint32]0, $c['DIREG_DEV'], $c['KEY_READ'])
        if ($hardwareKey -eq $invalid) {
            $hardwareKey = [IntPtr]::Zero
            $code = ConvertTo-WfUnsignedCode -Code $api.LastError()
            $result.HardwareKey.error_code = $code
            if ($code -eq $c['ERROR_KEY_DOES_NOT_EXIST']) {
                # Positively missing at the API resolved location: the two leaves cannot exist either.
                $result.HardwareKey.exists = $false
                $result.HardwareKey.error = 'ERROR_KEY_DOES_NOT_EXIST: the device has no hardware key under global scope'
                $result.InterruptManagement.exists = $false
                foreach ($leaf in $result.Leaves) { $leaf['exists'] = $false; $leaf['enumeration_complete'] = $true }
                $result.Stage = 'read'
                $result.Ok = $true
                return $result
            }
            $result.ErrorCode = $code
            if ($code -eq $c['ERROR_ACCESS_DENIED']) { $result.HardwareKey.error = 'ERROR_ACCESS_DENIED: the account may not open the hardware key for reading; its contents are unknown' }
            else { $result.HardwareKey.error = 'SetupDiOpenDevRegKey failed; the contents are unknown' }
            $result.ErrorMessage = [string]$result.HardwareKey.error
            return $result
        }
        $open.Add($hardwareKey)
        $result.HardwareKey.exists = $true
        $result.Stage = 'open_subkey'
        # The parent, for its existence only: nothing under it is enumerated.
        $parentHandle = [IntPtr]::Zero
        $status = [int]$api.RegOpenKeyExW($hardwareKey, 'Interrupt Management', [uint32]0, $c['KEY_READ'], [ref]$parentHandle)
        if ($status -eq $c['ERROR_SUCCESS']) {
            $open.Add($parentHandle)
            $result.InterruptManagement.exists = $true
        } elseif ($status -eq $c['ERROR_FILE_NOT_FOUND']) {
            $result.InterruptManagement.exists = $false
            foreach ($leaf in $result.Leaves) { $leaf['exists'] = $false; $leaf['enumeration_complete'] = $true }
        } else {
            $result.InterruptManagement.error_code = $status
            $result.InterruptManagement.error = 'RegOpenKeyExW on Interrupt Management returned ' + $status + '; its contents are unknown'
        }
        if ($result.InterruptManagement.exists -ne $false) {
            foreach ($leaf in $result.Leaves) {
                if ((Get-WfUtcNow) -ge $DeadlineUtc) { $result.Stage = 'timeout'; $result.ErrorMessage = 'the deadline passed before every subkey was read'; return $result }
                $leafHandle = [IntPtr]::Zero
                $status = [int]$api.RegOpenKeyExW($hardwareKey, [string]$leaf['subkey'], [uint32]0, $c['KEY_READ'], [ref]$leafHandle)
                if ($status -eq $c['ERROR_SUCCESS']) {
                    $open.Add($leafHandle)
                    $leaf['exists'] = $true
                    $result.Stage = 'enumerate'
                    $null = Read-WfDeviceKeyLeaf -Api $api -Handle $leafHandle -Constants $c -MaxValues $MaxValues -MaxBytes $MaxBytes -DeadlineUtc $DeadlineUtc -Record $leaf
                    $result.Stage = 'open_subkey'
                } elseif ($status -eq $c['ERROR_FILE_NOT_FOUND']) {
                    $leaf['exists'] = $false
                    $leaf['enumeration_complete'] = $true
                } else {
                    $leaf['error_code'] = $status
                    $leaf['error'] = 'RegOpenKeyExW returned ' + $status + '; the contents are unknown'
                }
            }
        }
        if ((Get-WfUtcNow) -ge $DeadlineUtc) { $result.Stage = 'timeout'; $result.ErrorMessage = 'the deadline passed while the subkeys were read'; return $result }
        $result.Stage = 'read'
        $result.Ok = $true
        return $result
    } catch {
        $result.ErrorMessage = 'the native call raised: ' + $_.Exception.Message
        return $result
    } finally {
        foreach ($handle in $open) { try { $null = $api.RegCloseKey($handle) } catch { $null = $_ } }
        if ($set -ne $invalid) { try { $null = $api.SetupDiDestroyDeviceInfoList($set) } catch { $null = $_ } }
    }
}

function Invoke-WfRegistrySource {
    # Reads documented registry values read only and writes, under raw/<id>/:
    #   query.json   the mode, the selection or key paths, the value names and
    #                the citations (role config, hashed as config_hash)
    #   result.json  counts: devices, keys read, keys absent, keys unknown (role report)
    #   keys.json    one element per device (Mode devices) or per key (Mode
    #                keys) (role primary)
    # Mode devices: for every present Plug and Play device the selection names
    # (instance id prefixes or setup classes), the device's hardware key is
    # opened through the documented device key API, SetupDiOpenDevRegKey with
    # global scope, DIREG_DEV and KEY_READ, and the two fixed relative subkeys
    # Interrupt Management\Affinity Policy and Interrupt Management\
    # MessageSignaledInterruptProperties are opened and enumerated under that
    # handle (Get-WfDeviceInterruptPolicy). No path under HKLM\SYSTEM\
    # CurrentControlSet\Enum is ever built or opened: Microsoft reserves that
    # tree and says applications must not open a hardware key directly:
    # https://learn.microsoft.com/windows-hardware/drivers/install/opening-a-device-s-hardware-key
    # Every value present under the two leaves is recorded with its numeric
    # type and bytes; the device's documented identity, status and problem
    # code (Win32_PnPEntity) sit next to them. A hardware key or a leaf that
    # the API says is not there is absent (an observation); a key that could
    # not be opened, a device that is gone, a declaration that did not compile
    # or a deadline that passed leave the contents unknown, never absent.
    # Mode keys: fixed, independently documented key paths (the GraphicsDrivers
    # TDR values) with the value names each may hold, each recorded present
    # (with type and bytes) or absent, read through the registry provider.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context = $null
    )
    $id = [string]$Source['Id']
    $mode = [string]$Source['Mode']
    $kind = 'config_snapshot'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'query.json' = 'config'; 'result.json' = 'report'; 'keys.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $keysPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/keys.json')
    $classes = Get-WfList -Value $Source['Classes']
    $prefixes = Get-WfList -Value $Source['InstancePrefixes']
    $fixedKeys = Get-WfList -Value $Source['Keys']
    $citations = Get-WfList -Value $Source['Citations']
    $subkeys = Get-WfInterruptManagementSubkeys
    $peers = 0
    $maxValues = 64
    if ($Source['MaxValuesPerKey']) { $maxValues = [int]$Source['MaxValuesPerKey'] }
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $query = [ordered]@{
            mode               = $mode
            classes            = @($classes)
            instance_prefixes  = @($prefixes)
            selection          = $(if ($mode -eq 'devices') { 'a present device is selected when its instance id starts with one of the prefixes or its class is one of the classes' } else { $null })
            resolver           = $(if ($mode -eq 'devices') { [ordered]@{ function = 'SetupDiOpenDevRegKey'; scope = 'DICS_FLAG_GLOBAL'; key_type = 'DIREG_DEV'; access = 'KEY_READ (0x20019)'; device = 'SetupDiOpenDeviceInfoW on the instance id, OpenFlags 0, in a private device information set'; subkeys = 'RegOpenKeyExW relative to the returned handle, options 0, KEY_READ'; values = 'RegEnumValueW on the two leaves only' } } else { 'Get-Item on the fixed key path (the registry provider)' })
            subkeys            = $(if ($mode -eq 'devices') { @($subkeys) } else { @() })
            max_values_per_key = $(if ($mode -eq 'devices') { $maxValues } else { $null })
            key_list           = @(foreach ($fixed in $fixedKeys) { $names = Get-WfList -Value $fixed['Values']; [ordered]@{ path = [string]$fixed['Path']; value_names = @($names) } })
            citations          = $citations
            protection         = $(if ($mode -eq 'devices') { 'a Bluetooth peer node (any BTH enumerator other than the radio''s own, or a Bluetooth service UUID in the id) has its name fields and twelve digit addresses replaced by name- and mac- pseudonyms before anything is written; string typed values are not kept (free text)' } else { $null })
            max_records        = $MaxEvents
            max_artifact_bytes = $MaxArtifactBytes
            timeout_seconds    = $TimeoutSeconds
            read_only          = 'keys are opened for reading only (KEY_READ); a missing key is recorded as absent and never created; a key that could not be opened is recorded as unknown'
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        if ($mode -eq 'devices') {
            $entry.command = @('Get-CimInstance', '-ClassName', 'Win32_PnPEntity', '-Filter', 'Present = TRUE', 'SetupDiOpenDevRegKey', 'DICS_FLAG_GLOBAL', 'DIREG_DEV', 'KEY_READ', 'RegOpenKeyExW', (@($subkeys) -join ';'), 'RegEnumValueW')
        } else {
            $entry.command = @('Microsoft.Win32.RegistryKey.GetValue') + @($fixedKeys | ForEach-Object { [string]$_['Path'] })
        }
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }

        $readErrorKind = ''
        $readErrorMessage = ''
        $accumulator = New-WfRowAccumulator -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes
        $present = 0
        $selected = 0
        $keysRead = 0
        $keysAbsent = 0
        $keysUnknown = 0
        $deniedCount = 0
        $devicesUnknown = 0
        $truncated = $false
        $preflightDetail = $null
        $nativeFailure = $null
        if ($mode -eq 'devices') {
            $enumeration = Get-WfPnpDevices -TimeoutSeconds ([int][math]::Ceiling((Get-WfRemainingSeconds -DeadlineUtc $deadline)))
            if (-not $enumeration['Ok']) {
                $readErrorKind = [string]$enumeration['ErrorKind']
                if (-not $readErrorKind) { $readErrorKind = 'other' }
                $readErrorMessage = [string]$enumeration['ErrorMessage']
            }
            $preflightDetail = $(if ($readErrorKind) { $readErrorMessage } else { 'Win32_PnPEntity, then SetupDiOpenDevRegKey per selected device' })
            if (-not $readErrorKind) {
                $present = @($enumeration['Devices']).Count
                if ($present -eq 0) {
                    $readErrorKind = 'other'
                    $readErrorMessage = 'the enumeration returned no present device at all, which never happens on a running machine'
                }
            }
            if (-not $readErrorKind) {
                foreach ($device in @($enumeration['Devices'])) {
                    if (-not (Test-WfPnpSeed -Device $device -Classes $classes -InstancePrefixes $prefixes)) { continue }
                    if ((Get-WfUtcNow) -ge $deadline) {
                        $readErrorKind = 'timeout'
                        $readErrorMessage = ('the device keys were not all read before the deadline ' + (ConvertTo-WfUtcString -Value $deadline) + '; ' + $accumulator.Rows.Count + ' devices had been read')
                        break
                    }
                    $selected += 1
                    $instance = [string]$device['instance_id']
                    $policy = Get-WfDeviceInterruptPolicy -InstanceId $instance -MaxValues $maxValues -MaxBytes $MaxArtifactBytes -DeadlineUtc $deadline
                    if ([string]$policy['Stage'] -eq 'compile') {
                        # The declaration did not compile or load: no device can be read in this run.
                        $nativeFailure = [string]$policy['ErrorMessage']
                        break
                    }
                    if ([string]$policy['Stage'] -eq 'timeout') {
                        $readErrorKind = 'timeout'
                        $readErrorMessage = [string]$policy['ErrorMessage']
                        break
                    }
                    $row = [ordered]@{
                        instance_id   = $instance
                        class         = $device['class']
                        name          = $device['name']
                        description   = $device['description']
                        manufacturer  = $device['manufacturer']
                        service       = $device['service']
                        status        = $device['status']
                        problem_code  = $device['problem_code']
                        hardware_ids  = (Get-WfList -Value $device['hardware_ids'])
                        device_key    = [ordered]@{ resolver = 'SetupDiOpenDevRegKey'; scope = 'DICS_FLAG_GLOBAL'; key_type = 'DIREG_DEV'; access = 'KEY_READ'; device_opened = [bool]$policy['DeviceOpened'] }
                        stage         = [string]$policy['Stage']
                        error_code    = $policy['ErrorCode']
                        registry_error = $policy['ErrorMessage']
                        hardware_key_state = $policy['HardwareKey']
                        interrupt_management = $policy['InterruptManagement']
                        interrupt_keys = @($policy['Leaves'])
                    }
                    if ($policy['Ok']) {
                        if ($policy['HardwareKey']['exists'] -eq $false) { $keysAbsent += @($subkeys).Count }
                        else {
                            foreach ($leaf in @($policy['Leaves'])) {
                                if ($leaf['exists'] -eq $true) { $keysRead += 1 }
                                elseif ($leaf['exists'] -eq $false) { $keysAbsent += 1 }
                                else { $keysUnknown += 1 }
                            }
                        }
                    } else {
                        $devicesUnknown += 1
                        $keysUnknown += @($subkeys).Count
                        if ($policy['ErrorCode'] -eq 5) { $deniedCount += 1 }
                    }
                    if ($null -ne $Context -and (Test-WfBluetoothPeerInstance -InstanceId $instance)) {
                        # A remembered Bluetooth peer is someone's device: its name and
                        # address leave as pseudonyms.
                        $peers += 1
                        $row = Protect-WfBluetoothPeerRow -Row $row -Salt ([string]$Context['Salt'])
                    }
                    if (-not (Add-WfRow -Accumulator $accumulator -Row $row)) { $truncated = $true; break }
                }
                if ($null -ne $nativeFailure) {
                    $readErrorKind = 'preflight'
                    $readErrorMessage = $nativeFailure
                } elseif (-not $readErrorKind -and $selected -eq 0) {
                    $readErrorKind = 'other'
                    $readErrorMessage = ('none of the {0} present devices matched the prefixes {1} or the classes {2}, which never happens for a PCI bus on a running machine' -f $present, (@($prefixes) -join ', '), (@($classes) -join ', '))
                } elseif (-not $readErrorKind -and $selected -gt 0 -and $devicesUnknown -ge $selected) {
                    # Not one device could be looked at: a status, with the first reason.
                    if ($deniedCount -eq $devicesUnknown) { $readErrorKind = 'access_denied' } else { $readErrorKind = 'other' }
                    $readErrorMessage = ('none of the {0} selected devices could be read; the first reason was: {1}' -f $selected, [string]$accumulator.Rows[0]['registry_error'])
                }
                if (-not $readErrorKind -and (Get-WfUtcNow) -ge $deadline) {
                    $readErrorKind = 'timeout'
                    $readErrorMessage = ('the last device key read ran past the deadline ' + (ConvertTo-WfUtcString -Value $deadline))
                }
            }
        } else {
            $preflightDetail = (@($fixedKeys | ForEach-Object { [string]$_['Path'] }) -join '; ')
            foreach ($fixed in $fixedKeys) {
                if ((Get-WfUtcNow) -ge $deadline) {
                    $readErrorKind = 'timeout'
                    $readErrorMessage = ('the keys were not all read before the deadline ' + (ConvertTo-WfUtcString -Value $deadline) + '; ' + $accumulator.Rows.Count + ' had been read')
                    break
                }
                $selected += 1
                $wanted = Get-WfList -Value $fixed['Values']
                $record = Read-WfRegistryKeyRecord -Path ([string]$fixed['Path']) -ValueNames @(foreach ($name in $wanted) { [string]$name })
                $record['citation'] = $fixed['Citation']
                if ($record['error_kind']) {
                    $keysUnknown += 1
                    if ($record['error_kind'] -eq 'access_denied') { $deniedCount += 1 }
                } elseif ($record['exists']) { $keysRead += 1 } else { $keysAbsent += 1 }
                if (-not (Add-WfRow -Accumulator $accumulator -Row $record)) { $truncated = $true; break }
            }
            if (-not $readErrorKind -and $selected -gt 0 -and $keysUnknown -ge $selected) {
                if ($deniedCount -eq $keysUnknown) { $readErrorKind = 'access_denied' } else { $readErrorKind = 'other' }
                $readErrorMessage = ('none of the {0} registry keys could be opened; the first error was: {1}' -f $selected, [string]$accumulator.Rows[0]['error'])
            }
            if (-not $readErrorKind -and (Get-WfUtcNow) -ge $deadline) {
                $readErrorKind = 'timeout'
                $readErrorMessage = ('the last key read ran past the deadline ' + (ConvertTo-WfUtcString -Value $deadline))
            }
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @([ordered]@{ name = 'keys_readable'; ok = (-not $readErrorKind); detail = $(if ($readErrorKind) { $readErrorMessage } else { $preflightDetail }) })
        }
        if (-not $readErrorKind) {
            Write-WfJsonLinesFile -Path $keysPath -Lines $accumulator.Lines.ToArray()
            $size = (Get-Item -LiteralPath $keysPath).Length
            if ($size -gt $MaxArtifactBytes) {
                Remove-Item -LiteralPath $keysPath -Force
                $readErrorKind = 'other'
                $readErrorMessage = ('keys.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }
        if ($keysUnknown -gt 0 -and -not $readErrorKind) {
            $message = ('source {0}: {1} keys could not be read; those elements carry the stage and code and their values are unknown, not absent' -f $id, $keysUnknown)
            $Notes.Add($message)
            $Log.Add($message)
        }
        $stopped = Get-WfUtcNow
        $report = [ordered]@{
            started_utc      = ConvertTo-WfUtcString -Value $started
            stopped_utc      = ConvertTo-WfUtcString -Value $stopped
            devices_present  = $(if ($mode -eq 'devices') { $present } else { $null })
            devices_selected = $(if ($mode -eq 'devices') { $selected } else { $null })
            devices_unknown  = $(if ($mode -eq 'devices') { $devicesUnknown } else { $null })
            elements         = $accumulator.Rows.Count
            keys_read        = $keysRead
            keys_absent      = $keysAbsent
            keys_unknown     = $keysUnknown
            peer_nodes_pseudonymised = $peers
            truncated        = $truncated
            error            = $(if ($readErrorKind) { $readErrorMessage } else { $null })
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if ($readErrorKind -or $truncated) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -RecordCount $accumulator.Rows.Count -Truncated $truncated `
                -OldestRecordUtc $started -WindowStartUtc $started -TruncationDetail ([string]$accumulator.Reason + '; the elements read before the cap were kept')
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } else {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        }
        Remove-WfPrimaryUnlessKept -Path $keysPath -Status $entry.status -Truncated $truncated -RecordCount $accumulator.Rows.Count -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) { $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                mode             = $mode
                devices_present  = $report.devices_present
                devices_selected = $report.devices_selected
                elements         = $(if (Test-Path -LiteralPath $keysPath) { $accumulator.Rows.Count } else { 0 })
                keys_read        = $keysRead
                keys_absent      = $keysAbsent
                keys_unknown     = $keysUnknown
                truncated        = $truncated
            }
            verified_by = $(if ($mode -eq 'devices') { 'every element records the stage each device reached, the Win32 or registry code of a failure, whether its hardware key and each leaf exists (true, false, or null for unknown), and every value with its numeric type and bytes; the counts are in result.json' } else { 'every element records whether its key exists, the error if it could not be opened, and each value with its registry type and bytes; the counts are in result.json' })
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('{0} elements; {1} keys read, {2} absent, {3} unknown' -f $accumulator.Rows.Count, $keysRead, $keysAbsent, $keysUnknown)
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $keysPath) { Remove-Item -LiteralPath $keysPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Invoke-WfDirectorySource {
    # Lists the files of one known folder (not its subfolders) read only and
    # writes, under raw/<id>/:
    #   source.json   the folder, the cap and why nothing is copied (role config)
    #   result.json   whether the folder and its parent exist, whether it could
    #                 be listed, the counts (role report; the folder level facts
    #                 a decoder cites live here)
    #   listing.json  a JSON array, one element per file: name, size, last
    #                 write time, SHA-256 and the version resource (file
    #                 version, product version, product name, company) (role primary)
    # The question is "is this program installed here, which build, which
    # components": binaries are hashed and versioned, never copied. A folder
    # that does not exist is an observation (the program is not installed at
    # this path) and is observed_zero with the listing saying so; a folder the
    # account may not list is not_collected.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $kind = 'config_snapshot'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'source.json' = 'config'; 'result.json' = 'report'; 'listing.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $listingPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/listing.json')
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $path = [string]$Source['Path']
        $parent = $null
        if ($path) {
            $parent = [System.IO.Path]::GetDirectoryName($path)
        } else {
            $parent = Get-WfKnownFolderPath -Name ([string]$Source['Folder'])
            $path = $parent + '\' + [string]$Source['PathTail']
        }
        $config = [ordered]@{
            path               = $path
            parent             = $parent
            path_documented    = [bool]$Source['PathDocumented']
            recursive          = $false
            max_files          = $MaxEvents
            max_artifact_bytes = $MaxArtifactBytes
            timeout_seconds    = $TimeoutSeconds
            mode               = 'listing'
            why_no_copy        = 'the question is whether the program is installed here and in which build; each file is named, sized, hashed and versioned, and none is copied'
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/source.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @('System.IO.Directory.GetFiles', $path, 'System.Diagnostics.FileVersionInfo.GetVersionInfo')
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        $listing = Get-WfDirectoryListing -Path $path -Parent $parent -MaxFiles $MaxEvents -DeadlineUtc $deadline
        $readErrorKind = ''
        $readErrorMessage = ''
        if ($listing['ErrorKind']) {
            $readErrorKind = [string]$listing['ErrorKind']
            $readErrorMessage = [string]$listing['ErrorMessage']
        } elseif ((Get-WfUtcNow) -ge $deadline) {
            # The adapter checks the deadline between files; this catches a last
            # file whose hash ran past it.
            $readErrorKind = 'timeout'
            $readErrorMessage = 'the listing did not finish before the deadline ' + (ConvertTo-WfUtcString -Value $deadline)
        } elseif (-not $listing['Exists'] -and -not $listing['ParentExists']) {
            # "Not installed here" is an observation only when the folder that would hold it
            # exists (Program Files always does on Windows); otherwise this is not Windows or
            # not the folder Microsoft documents, and the read fails closed.
            $readErrorKind = 'preflight'
            $readErrorMessage = 'the folder that would hold it does not exist either: ' + [string]$listing['Parent'] + '; absence cannot be told from a wrong path'
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @(
                [ordered]@{ name = 'parent_folder_exists'; ok = [bool]$listing['ParentExists']; detail = [string]$listing['Parent'] },
                [ordered]@{ name = 'folder_exists'; ok = [bool]$listing['Exists']; detail = $path },
                [ordered]@{ name = 'folder_listed'; ok = (-not $readErrorKind); detail = $(if ($readErrorKind) { $readErrorMessage } else { $null }) }
            )
        }
        $files = Get-WfList -Value $listing['Files']
        $truncated = [bool]$listing['Truncated']
        if (-not $readErrorKind) {
            # The primary is a JSON array, one element per file, so a decoded row
            # can cite index:<n>; the folder's own facts are in result.json.
            $lines = New-Object 'System.Collections.Generic.List[string]'
            foreach ($file in @($files)) { $lines.Add((ConvertTo-WfJson -Value $file)) }
            Write-WfJsonLinesFile -Path $listingPath -Lines $lines.ToArray()
            $size = (Get-Item -LiteralPath $listingPath).Length
            if ($size -gt $MaxArtifactBytes) {
                Remove-Item -LiteralPath $listingPath -Force
                $readErrorKind = 'other'
                $readErrorMessage = ('listing.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }
        $stopped = Get-WfUtcNow
        $report = [ordered]@{
            path       = $path
            parent     = $parent
            parent_exists = [bool]$listing['ParentExists']
            exists     = [bool]$listing['Exists']
            listed     = (-not $readErrorKind)
            listed_at_utc = ConvertTo-WfUtcString -Value $stopped
            error      = $(if ($readErrorKind) { $readErrorMessage } else { $null })
            file_count = $files.Count
            truncated  = $truncated
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if ($readErrorKind -or $truncated) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -RecordCount $files.Count -Truncated $truncated `
                -OldestRecordUtc $started -WindowStartUtc $started -TruncationDetail ('the cap of ' + $MaxEvents + ' files was reached; the files listed before the cap were kept')
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } elseif ($files.Count -gt 0) {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        } else {
            $entry.status = 'observed_zero'
            $entry.status_reason = $null
            $met = $true
            if (-not $listing['Exists']) { $Notes.Add('source ' + $id + ': the folder does not exist, so nothing is installed at ' + $path + '; the listing says so') }
        }
        # A listing kept despite the cap is a capped set, as for the other sources.
        Remove-WfPrimaryUnlessKept -Path $listingPath -Status $entry.status -Truncated $truncated -RecordCount $files.Count -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) { $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{ path = $path; exists = $report.exists; file_count = $(if (Test-Path -LiteralPath $listingPath) { $files.Count } else { 0 }); truncated = $truncated; content_kept = $false }
            verified_by = 'the listing completed without error; every file carries its size, time, SHA-256 and version resource'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = $(if ($met) { ('folder exists: {0}; {1} files listed' -f $report.exists, $files.Count) } else { $readErrorMessage })
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $listingPath) { Remove-Item -LiteralPath $listingPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function Invoke-WfUnavailableSource {
    # A question the scenario asks that this collector cannot answer through
    # a documented read only path reachable from Windows PowerShell 5.1
    # without compiling or installing anything. It writes, under raw/<id>/:
    #   reason.json   the reason, the documented paths that exist and why each
    #                 is not used, and the follow up (role config)
    # and records the source as not_collected with that reason, so the
    # coverage table shows the gap instead of hiding it (measurement status is
    # never adjusted to make a bundle look complete). No primary is written,
    # so nothing can be read as an empty observation.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [System.Collections.Generic.List[string]]$Log
    )
    $id = [string]$Source['Id']
    $kind = 'other'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'reason.json' = 'config' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $reason = [string]$Source['Reason']
        $config = [ordered]@{
            question         = [string]$Source['Question']
            reason           = $reason
            documented_paths = (Get-WfList -Value $Source['DocumentedPaths'])
            follow_up        = [string]$Source['FollowUp']
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/reason.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @('none')
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }
        $entry.preflight = [ordered]@{
            ok     = $false
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @([ordered]@{ name = 'read_path_available'; ok = $false; detail = $reason })
        }
        $entry.status = 'not_collected'
        $entry.status_reason = 'preflight failed, no documented read only path reachable from this collector: ' + $reason
        $entry.enabled = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $null; verified_by = $null }
        $entry.expectation = [ordered]@{ declared = [string]$Source['Expectation']; met = $false; detail = 'not attempted' }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while recording this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

# ---------------------------------------------------------------------------
# Logical processor topology. GetLogicalProcessorInformationEx returns a
# sequence of variable sized SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX records;
# the parser below walks that buffer by the documented layouts, so the raw
# bytes are the evidence and every decoded field can be checked against them:
# https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-processor_relationship
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-cache_relationship
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_relationship
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-processor_group_info
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-numa_node_relationship
# https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_affinity
# https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-logical_processor_relationship
# The layouts are the 64 bit ones (KAFFINITY is 8 bytes, GROUP_AFFINITY 16,
# PROCESSOR_GROUP_INFO 48). The collector refuses a 32 bit process: Microsoft
# documents KAFFINITY as 32 bits on 32 bit Windows (interrupt affinity page
# above), and that a 32 bit process under WOW64 sees affinity masks folded
# into 32 bits, so the function's masks can be wrong for it:
# https://learn.microsoft.com/windows/win32/winprog64/processor-affinity
# https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex#remarks
# ---------------------------------------------------------------------------

function Get-WfRelationshipName {
    param([int]$Relationship)
    switch ($Relationship) {
        0 { return 'RelationProcessorCore' }
        1 { return 'RelationNumaNode' }
        2 { return 'RelationCache' }
        3 { return 'RelationProcessorPackage' }
        4 { return 'RelationGroup' }
        5 { return 'RelationProcessorDie' }
        6 { return 'RelationNumaNodeEx' }
        7 { return 'RelationProcessorModule' }
        8 { return 'RelationProcessorSharedComputeUnit' }
    }
    return $null
}

function Get-WfCacheTypeName {
    # PROCESSOR_CACHE_TYPE: https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-processor_cache_type
    param([int]$Type)
    switch ($Type) {
        0 { return 'CacheUnified' }
        1 { return 'CacheInstruction' }
        2 { return 'CacheData' }
        3 { return 'CacheTrace' }
    }
    return $null
}

function ConvertTo-WfProcessorList {
    # The logical processor indices whose bits are set in a KAFFINITY mask.
    param([uint64]$Mask)
    $list = New-Object 'System.Collections.Generic.List[int]'
    for ($bit = 0; $bit -lt 64; $bit++) { if ((($Mask -shr $bit) -band [uint64]1) -eq [uint64]1) { $list.Add($bit) } }
    return , $list.ToArray()
}

function ConvertFrom-WfGroupAffinity {
    # One GROUP_AFFINITY (16 bytes): KAFFINITY Mask, WORD Group, WORD Reserved[3].
    param([byte[]]$Bytes, [int]$Offset)
    $mask = [System.BitConverter]::ToUInt64($Bytes, $Offset)
    $group = [int][System.BitConverter]::ToUInt16($Bytes, $Offset + 8)
    return [ordered]@{ group = $group; mask_hex = ('0x' + $mask.ToString('x')); processors = (ConvertTo-WfProcessorList -Mask $mask) }
}

function ConvertFrom-WfLogicalProcessorInformation {
    # Every record in a GetLogicalProcessorInformationEx buffer, as ordered
    # maps with the documented fields decoded and the record's offset and
    # size kept, so a reader can go back to the bytes. Throws on a buffer that
    # does not follow the documented layout (a record that runs past the end,
    # a size below the fixed part), because a half parsed topology is worse
    # than none.
    param([byte[]]$Bytes)
    $records = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Bytes) { return , $records.ToArray() }
    $offset = 0
    $index = 0
    while ($offset + 8 -le $Bytes.Length) {
        $relationship = [int][System.BitConverter]::ToUInt32($Bytes, $offset)
        $size = [int][System.BitConverter]::ToUInt32($Bytes, $offset + 4)
        if ($size -lt 8 -or $offset + $size -gt $Bytes.Length) { throw ('record ' + $index + ' at offset ' + $offset + ' has size ' + $size + ', which does not fit the buffer of ' + $Bytes.Length + ' bytes') }
        $body = $offset + 8
        $record = [ordered]@{ index = $index; offset = $offset; size = $size; relationship = $relationship; relationship_name = (Get-WfRelationshipName -Relationship $relationship) }
        switch ($relationship) {
            { $_ -eq 0 -or $_ -eq 3 -or $_ -eq 5 -or $_ -eq 7 } {
                # PROCESSOR_RELATIONSHIP: Flags, EfficiencyClass, RelativePerformance, RelativeEfficiency, Reserved[16], GroupCount at 22, GroupMask[] at 24.
                if ($size -lt 8 + 24) { throw ('record ' + $index + ' is a processor relationship of ' + $size + ' bytes, below the fixed part') }
                $flags = [int]$Bytes[$body]
                $groupCount = [int][System.BitConverter]::ToUInt16($Bytes, $body + 22)
                $masks = New-Object 'System.Collections.Generic.List[object]'
                for ($g = 0; $g -lt $groupCount; $g++) {
                    $at = $body + 24 + 16 * $g
                    if ($at + 16 -gt $offset + $size) { throw ('record ' + $index + ' declares ' + $groupCount + ' group masks but is ' + $size + ' bytes') }
                    $masks.Add((ConvertFrom-WfGroupAffinity -Bytes $Bytes -Offset $at))
                }
                $record['flags'] = $flags
                $record['smt'] = $(if ($relationship -eq 0) { (($flags -band 1) -eq 1) } else { $null })
                $record['efficiency_class'] = [int]$Bytes[$body + 1]
                $record['group_count'] = $groupCount
                $record['group_masks'] = @($masks.ToArray())
            }
            2 {
                # CACHE_RELATIONSHIP: Level, Associativity, LineSize (2), CacheSize (4), Type (4), Reserved[18], GroupCount at 30, GroupMask(s) at 32.
                if ($size -lt 8 + 32) { throw ('record ' + $index + ' is a cache relationship of ' + $size + ' bytes, below the fixed part') }
                $groupCount = [int][System.BitConverter]::ToUInt16($Bytes, $body + 30)
                # Before Windows 10 20H2 GroupCount is 0 and one GroupMask follows (Microsoft: NUMA_NODE_RELATIONSHIP notes the same rule).
                $count = $(if ($groupCount -gt 0) { $groupCount } else { 1 })
                $masks = New-Object 'System.Collections.Generic.List[object]'
                for ($g = 0; $g -lt $count; $g++) {
                    $at = $body + 32 + 16 * $g
                    if ($at + 16 -gt $offset + $size) { throw ('record ' + $index + ' declares ' + $count + ' cache group masks but is ' + $size + ' bytes') }
                    $masks.Add((ConvertFrom-WfGroupAffinity -Bytes $Bytes -Offset $at))
                }
                $type = [int][System.BitConverter]::ToUInt32($Bytes, $body + 8)
                $record['level'] = [int]$Bytes[$body]
                $record['associativity'] = [int]$Bytes[$body + 1]
                $record['line_size'] = [int][System.BitConverter]::ToUInt16($Bytes, $body + 2)
                $record['cache_size'] = [int64][System.BitConverter]::ToUInt32($Bytes, $body + 4)
                $record['cache_type'] = $type
                $record['cache_type_name'] = Get-WfCacheTypeName -Type $type
                $record['group_count'] = $groupCount
                $record['group_masks'] = @($masks.ToArray())
            }
            4 {
                # GROUP_RELATIONSHIP: MaximumGroupCount (2), ActiveGroupCount (2), Reserved[20], GroupInfo[] at 24, each 48 bytes with the mask at 40.
                if ($size -lt 8 + 24) { throw ('record ' + $index + ' is a group relationship of ' + $size + ' bytes, below the fixed part') }
                $active = [int][System.BitConverter]::ToUInt16($Bytes, $body + 2)
                $groups = New-Object 'System.Collections.Generic.List[object]'
                for ($g = 0; $g -lt $active; $g++) {
                    $at = $body + 24 + 48 * $g
                    if ($at + 48 -gt $offset + $size) { throw ('record ' + $index + ' declares ' + $active + ' groups but is ' + $size + ' bytes') }
                    $mask = [System.BitConverter]::ToUInt64($Bytes, $at + 40)
                    $groups.Add([ordered]@{ group = $g; maximum_processor_count = [int]$Bytes[$at]; active_processor_count = [int]$Bytes[$at + 1]; active_mask_hex = ('0x' + $mask.ToString('x')); processors = (ConvertTo-WfProcessorList -Mask $mask) })
                }
                $record['maximum_group_count'] = [int][System.BitConverter]::ToUInt16($Bytes, $body)
                $record['active_group_count'] = $active
                $record['groups'] = @($groups.ToArray())
            }
            { $_ -eq 1 -or $_ -eq 6 } {
                # NUMA_NODE_RELATIONSHIP: NodeNumber (4), Reserved[18], GroupCount at 22, GroupMask(s) at 24.
                if ($size -lt 8 + 24) { throw ('record ' + $index + ' is a NUMA relationship of ' + $size + ' bytes, below the fixed part') }
                $groupCount = [int][System.BitConverter]::ToUInt16($Bytes, $body + 22)
                $count = $(if ($groupCount -gt 0) { $groupCount } else { 1 })
                $masks = New-Object 'System.Collections.Generic.List[object]'
                for ($g = 0; $g -lt $count; $g++) {
                    $at = $body + 24 + 16 * $g
                    if ($at + 16 -gt $offset + $size) { throw ('record ' + $index + ' declares ' + $count + ' NUMA group masks but is ' + $size + ' bytes') }
                    $masks.Add((ConvertFrom-WfGroupAffinity -Bytes $Bytes -Offset $at))
                }
                $record['node_number'] = [int64][System.BitConverter]::ToUInt32($Bytes, $body)
                $record['group_count'] = $groupCount
                $record['group_masks'] = @($masks.ToArray())
            }
            default {
                # A relationship this parser does not lay out is kept as its bytes.
                $record['body_hex'] = (([System.BitConverter]::ToString($Bytes, $body, $size - 8)) -replace '-', '').ToLowerInvariant()
            }
        }
        $records.Add($record)
        $offset += $size
        $index += 1
    }
    if ($offset -ne $Bytes.Length) { throw ('the buffer has ' + ($Bytes.Length - $offset) + ' trailing bytes after the last record') }
    return , $records.ToArray()
}

function Invoke-WfTopologySource {
    # Reads the logical processor topology through the documented API and
    # writes, under raw/<id>/:
    #   query.json     the function, the relationship asked for (RelationAll),
    #                  the pointer size and the citations (role config)
    #   result.json    whether the call succeeded, the stage that failed, the
    #                  Win32 error code, the byte count, the record counts per
    #                  relationship, and the buffer itself as hex (role report)
    #   topology.json  one element per record, decoded by the documented
    #                  layouts (role primary)
    # The read is the one native call this collector set makes; the adapter
    # compiles its declaration once per process (see Get-WfLogicalProcessorInformation
    # and the README). A compiler that is not available is not_collected
    # (preflight); a call that fails, a buffer that does not parse, or a buffer
    # without a processor core record is capture_failed with the code or
    # message; a 32 bit host is unsupported (Microsoft documents folded masks).
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $kind = 'config_snapshot'
    if ($Source['Kind']) { $kind = [string]$Source['Kind'] }
    $entry = New-WfCollectorEntry -Id $id -Kind $kind -Required ([bool]$Source['Required'])
    $roles = @{ 'query.json' = 'config'; 'result.json' = 'report'; 'topology.json' = 'primary' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $topologyPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/topology.json')
    $records = @()
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $query = [ordered]@{
            function           = 'GetLogicalProcessorInformationEx'
            library            = 'kernel32.dll'
            relationship_type  = 'RelationAll (0xffff)'
            layout             = '64 bit: KAFFINITY 8 bytes, GROUP_AFFINITY 16 bytes, PROCESSOR_GROUP_INFO 48 bytes'
            citations          = (Get-WfList -Value $Source['Citations'])
            max_artifact_bytes = $MaxArtifactBytes
            timeout_seconds    = $TimeoutSeconds
            read_only          = 'a query of the processor topology; nothing is set'
        }
        $queryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/query.json')
        Write-WfJsonFile -Path $queryPath -Object $query
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $queryPath) }
        $entry.command = @('kernel32.dll!GetLogicalProcessorInformationEx', 'RelationAll')
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $query }

        $read = Get-WfLogicalProcessorInformation
        $readErrorKind = ''
        $readErrorMessage = ''
        $parseError = $null
        if ([int]$read['PointerSize'] -ne 8) {
            $readErrorKind = 'not_found'
            $readErrorMessage = ('the process is not 64 bit (pointer size ' + $read['PointerSize'] + '); KAFFINITY is 32 bits there and a 32 bit process under WOW64 sees folded affinity masks (Microsoft documents both), so the 64 bit layouts this parser uses do not apply and the topology is not read')
        } elseif (-not $read['Ok']) {
            if ([string]$read['Stage'] -eq 'compile') { $readErrorKind = 'preflight' } else { $readErrorKind = 'other' }
            $readErrorMessage = ('stage ' + [string]$read['Stage'] + ': ' + [string]$read['ErrorMessage'])
            if ($null -ne $read['ErrorCode']) { $readErrorMessage += (' (Win32 error ' + $read['ErrorCode'] + ')') }
        } elseif ((Get-WfUtcNow) -ge $deadline) {
            $readErrorKind = 'timeout'
            $readErrorMessage = 'the call did not return before the deadline ' + (ConvertTo-WfUtcString -Value $deadline)
        } else {
            try {
                $records = ConvertFrom-WfLogicalProcessorInformation -Bytes ([byte[]]$read['Bytes'])
            } catch {
                $parseError = $_.Exception.Message
                $readErrorKind = 'other'
                $readErrorMessage = 'the buffer does not follow the documented layout: ' + $parseError
                $records = @()
            }
        }
        $entry.preflight = [ordered]@{
            ok     = (-not $readErrorKind)
            at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
            checks = @(
                [ordered]@{ name = 'declaration_compiled'; ok = ([string]$read['Stage'] -ne 'compile'); detail = $(if ([string]$read['Stage'] -eq 'compile') { [string]$read['ErrorMessage'] } else { 'the GetLogicalProcessorInformationEx declaration is loaded' }) },
                [ordered]@{ name = 'call_succeeded'; ok = [bool]$read['Ok']; detail = $(if ($read['Ok']) { ([string]$read['Bytes'].Length + ' bytes') } else { [string]$read['ErrorMessage'] }) }
            )
        }
        $counts = [ordered]@{}
        foreach ($record in @($records)) {
            $name = [string]$record['relationship_name']
            if (-not $name) { $name = 'relationship_' + $record['relationship'] }
            if ($counts.Contains($name)) { $counts[$name] = [int]$counts[$name] + 1 } else { $counts[$name] = 1 }
        }
        $cores = 0
        if ($counts.Contains('RelationProcessorCore')) { $cores = [int]$counts['RelationProcessorCore'] }
        $undecoded = 0
        foreach ($record in @($records)) { if ($record.Contains('body_hex')) { $undecoded += 1 } }
        if ($undecoded -gt 0) { $Notes.Add(('source ' + $id + ': ' + $undecoded + ' records of a relationship type without a documented layout here are kept as bytes (body_hex) and not decoded')) }
        if (-not $readErrorKind -and $cores -eq 0) {
            $readErrorKind = 'other'
            $readErrorMessage = 'the buffer holds no RelationProcessorCore record, which the documentation promises for every active core'
        }
        if (-not $readErrorKind) {
            $lines = New-Object 'System.Collections.Generic.List[string]'
            foreach ($record in @($records)) { $lines.Add((ConvertTo-WfJson -Value $record)) }
            Write-WfJsonLinesFile -Path $topologyPath -Lines $lines.ToArray()
            $size = (Get-Item -LiteralPath $topologyPath).Length
            if ($size -gt $MaxArtifactBytes) {
                Remove-Item -LiteralPath $topologyPath -Force
                $readErrorKind = 'other'
                $readErrorMessage = ('topology.json was ' + $size + ' bytes, above the cap of ' + $MaxArtifactBytes + ', and was removed')
            }
        }
        $stopped = Get-WfUtcNow
        $bufferHex = $null
        if ($null -ne $read['Bytes']) { $bufferHex = (([System.BitConverter]::ToString([byte[]]$read['Bytes'])) -replace '-', '').ToLowerInvariant() }
        $report = [ordered]@{
            started_utc   = ConvertTo-WfUtcString -Value $started
            stopped_utc   = ConvertTo-WfUtcString -Value $stopped
            ok            = [bool]$read['Ok']
            stage         = $read['Stage']
            error_code    = $read['ErrorCode']
            error         = $(if ($readErrorKind) { $readErrorMessage } else { $null })
            pointer_size  = $read['PointerSize']
            byte_count    = $(if ($null -ne $read['Bytes']) { [int]$read['Bytes'].Length } else { $null })
            record_counts = $counts
            buffer_hex    = $bufferHex
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report
        if ($readErrorKind) {
            $resolved = Resolve-WfSourceStatus -ReadErrorKind $readErrorKind -ReadErrorMessage $readErrorMessage -WindowStartUtc $started
            $entry.status = $resolved['Status']
            $entry.status_reason = $resolved['Reason']
            $met = $false
        } else {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
            $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped
        }
        Remove-WfPrimaryUnlessKept -Path $topologyPath -Status $entry.status -Truncated $false -RecordCount @($records).Count -Log $Log -SourceId $id
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{ byte_count = $report.byte_count; records = @($records).Count; cores = $cores; record_counts = $counts; pointer_size = $report.pointer_size }
            verified_by = 'the call returned TRUE and the buffer parsed by the documented layouts; the buffer itself is in result.json as hex'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = $(if ($met) { ('{0} records, {1} processor cores' -f @($records).Count, $cores) } else { $readErrorMessage })
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $topologyPath) { Remove-Item -LiteralPath $topologyPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @() }
}

function ConvertTo-WfMachineDrivers {
    # manifest.machine.drivers from Win32_PnPSignedDriver rows. Property names
    # are the documented ones:
    # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394354(v=vs.85)
    # The list is a convenience summary with its own limit; the raw export
    # is the complete record. Returns the drivers and how many rows with a
    # device name were left out.
    param($Rows, [int]$Limit = 2000)
    $drivers = New-Object 'System.Collections.Generic.List[object]'
    $skipped = 0
    foreach ($row in @($Rows)) {
        $name = $row['DeviceName']
        if (-not $name) { continue }
        if ($drivers.Count -ge $Limit) { $skipped += 1; continue }
        $drivers.Add([ordered]@{
                name     = [string]$name
                version  = $row['DriverVersion']
                provider = $row['DriverProviderName']
                class    = $row['DeviceClass']
            })
    }
    return [ordered]@{ Drivers = $drivers.ToArray(); Skipped = $skipped; Limit = $Limit }
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
    # $State is filled as the run progresses so that the caller can still
    # write the failure logs when this function throws.
    param(
        [hashtable]$Definition,
        [string]$OutputDirectory,
        [int]$WindowDays = 30,
        [int]$MaxEvents = 5000,
        [int64]$MaxArtifactBytes = 67108864,
        [int]$TimeoutSeconds = 300,
        [string]$CollectorPath = '',
        [hashtable]$State = @{}
    )
    $name = [string]$Definition['Name']
    if (-not (Test-WfCollectorName -Name $name)) { throw ('collector name does not match ' + (Get-WfCollectorNamePattern) + ': ' + $name) }
    if ($WindowDays -lt 1 -or $WindowDays -gt 365) { throw 'WindowDays must be between 1 and 365' }
    if ($MaxEvents -lt 1 -or $MaxEvents -gt 100000) { throw 'MaxEvents must be between 1 and 100000' }
    if ($MaxArtifactBytes -lt 1048576 -or $MaxArtifactBytes -gt 1073741824) { throw 'MaxArtifactBytes must be between 1 MiB and 1 GiB' }
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3600) { throw 'TimeoutSeconds must be between 1 and 3600' }
    $sources = Get-WfList -Value $Definition['Sources']
    if ($sources.Count -lt 1) { throw 'a collector definition needs at least one source' }

    $bundleRoot = Resolve-WfBundleRoot -OutputDirectory $OutputDirectory
    New-WfBundleLayout -BundleRoot $bundleRoot
    $log = New-Object 'System.Collections.Generic.List[string]'
    $State['BundleRoot'] = $bundleRoot
    $State['Log'] = $log
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
    $log.Add(('{0} collector {1} version {2}, helper version {3}, {4}, {5} s per source' -f (ConvertTo-WfUtcString -Value $start), $name, [string]$Definition['Version'], (Get-WfCollectorsVersion), $windowText, $TimeoutSeconds))

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
    $driverResult = $null
    # Shared by the sources that pseudonymise names and addresses: one salt
    # for the run, and the network names learned so far, kept in memory only.
    $context = @{ Salt = (New-WfPseudonymSalt); Ssids = (New-Object 'System.Collections.Generic.List[string]'); CopiedTexts = @{} }
    $protects = $false
    $copies = $false
    foreach ($source in $sources) {
        $type = [string]$source['Type']
        if ($type -eq 'eventlog') {
            if ($source['Protect']) { $protects = $true }
            $result = Invoke-WfEventSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'cim') {
            if ($source['ProtectProperties']) { $copies = $true }
            $result = Invoke-WfCimSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
            if ($source['FillsMachineDrivers']) { $driverResult = $result }
        } elseif ($type -eq 'command') {
            $protects = $true
            $result = Invoke-WfCommandSource -Source $source -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes `
                -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'file') {
            if ([string]$source['Mode'] -eq 'copy') { $copies = $true } else { $protects = $true }
            $result = Invoke-WfFileSource -Source $source -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes `
                -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'pnp') {
            $protects = $true
            $result = Invoke-WfPnpSource -Source $source -BundleRoot $bundleRoot -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'directory') {
            $result = Invoke-WfDirectorySource -Source $source -BundleRoot $bundleRoot -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes
        } elseif ($type -eq 'registry') {
            if ([string]$source['Mode'] -eq 'devices') { $protects = $true }
            $result = Invoke-WfRegistrySource -Source $source -BundleRoot $bundleRoot -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'topology') {
            $result = Invoke-WfTopologySource -Source $source -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes `
                -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes
        } elseif ($type -eq 'unavailable') {
            $result = Invoke-WfUnavailableSource -Source $source -BundleRoot $bundleRoot -Log $log
        } else {
            throw ('unknown source type: ' + $type)
        }
        $entries.Add($result['Entry'])
    }
    $context['Ssids'].Clear()
    $context['CopiedTexts'].Clear()
    $stop = Get-WfUtcNow

    $machine = $machineInfo['machine']
    if ($null -ne $driverResult) {
        $summary = ConvertTo-WfMachineDrivers -Rows $driverResult['Rows']
        $machine['drivers'] = $summary['Drivers']
        if ($summary['Skipped'] -gt 0) {
            $notes.Add(('machine.drivers lists the first {0} named drivers of {1} from source {2}; {3} were left out of this summary, and the raw export is the complete record' -f $summary['Limit'], ($summary['Limit'] + $summary['Skipped']), [string]$driverResult['Entry']['id'], $summary['Skipped']))
        }
    }
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
        $allNotes.Add('Each event log query selects a fixed interval, window_end_utc minus the window to window_end_utc, so records raised while the query ran are not part of the result.')
    }
    if ($copies) {
        $allNotes.Add('Copied text (the owner''s own configuration and log files, and the command line and image path of the one named helper process) stays readable, except that every Windows user profile folder name, every e-mail shaped token, every UNC host name and every hardware address in it is a pseudonym (user-<12 hex>, mail-<12 hex>, host-<12 hex>, mac-<12 hex>) keyed with a random salt that was not stored; result.json of each copy records the SHA-256 of the original bytes and the replacement counts, so a copy with zero replacements and the same hash is verbatim.')
    }
    if ($protects) {
        $allNotes.Add('Network names, hardware addresses and Bluetooth peer names are pseudonyms (ssid-<12 hex>, mac-<12 hex>, name-<12 hex>) keyed with a random salt that was not stored: the same value maps to the same pseudonym inside this bundle and to nothing outside it. The saved Wi-Fi profiles of this PC are the exception: they are the owner''s own networks and stay readable, each with its pseudonym, so an explicit owner selection can be matched at analysis time.')
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
    $State['Written'] = $true
    foreach ($note in $notes) { Write-WfStderrLine -Text $note }
    return [ordered]@{ Status = $summaryStatus; Artifacts = $artifactCount; SummaryLine = $summaryLine; BundleId = $manifest.bundle_id }
}

function Invoke-WfCollectorScript {
    # The entry point every collector script calls. Prints exactly one JSON
    # line on stdout, sends diagnostics to stderr, and returns the exit code:
    # 0 when the bundle is complete (status ok or partial), 1 otherwise.
    # When the run fails after the bundle directory was laid out, the failed
    # summary and the log are still written under logs/ there.
    param(
        [hashtable]$Definition,
        [string]$OutputDirectory,
        [int]$WindowDays = 30,
        [int]$MaxEvents = 5000,
        [int64]$MaxArtifactBytes = 67108864,
        [int]$TimeoutSeconds = 300,
        [string]$CollectorPath = ''
    )
    $name = [string]$Definition['Name']
    $exitCode = 1
    $line = $null
    $state = @{}
    try {
        # Anything a callee writes to the success stream by accident is kept
        # away from stdout: only the last object, the result, is used.
        $output = @(Invoke-WfCollector -Definition $Definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays `
                -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds `
                -CollectorPath $CollectorPath -State $state)
        $result = $output[$output.Count - 1]
        $line = [string]$result['SummaryLine']
        if ($result['Status'] -ne 'failed') { $exitCode = 0 }
    } catch {
        $message = 'collector ' + $name + ' failed: ' + $_.Exception.Message
        Write-WfStderrLine -Text $message
        $line = ConvertTo-WfSummaryLine -Collector $name -Status 'failed' -Bundle $OutputDirectory -Artifacts 0
        $exitCode = 1
        if ($state.ContainsKey('BundleRoot') -and -not $state.ContainsKey('Written')) {
            try {
                $logs = Join-WfBundlePath -BundleRoot $state['BundleRoot'] -RelativePath 'logs'
                $null = New-Item -ItemType Directory -Force -Path $logs
                $log = New-Object 'System.Collections.Generic.List[string]'
                if ($state.ContainsKey('Log')) { foreach ($item in $state['Log']) { $log.Add($item) } }
                $log.Add((ConvertTo-WfUtcString -Value (Get-WfUtcNow)) + ' ' + $message)
                $log.Add('no manifest was written; the raw directory holds whatever was collected before the failure and is not a bundle')
                Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $state['BundleRoot'] -RelativePath 'logs/summary.json') -Text ($line + "`n")
                Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $state['BundleRoot'] -RelativePath 'logs/collector.log') -Text (($log.ToArray() -join "`n") + "`n")
            } catch {
                Write-WfStderrLine -Text ('the failure log could not be written: ' + $_.Exception.Message)
            }
        }
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
    # The operation timeout bounds a provider that does not answer:
    # https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1
    param([string]$ClassName, [int]$TimeoutSeconds = 60)
    try {
        return @(Get-CimInstance -ClassName $ClassName -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop)[0]
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
    try { $processors = @(Get-CimInstance -ClassName 'Win32_Processor' -OperationTimeoutSec 60 -ErrorAction Stop) } catch { $processors = @() }
    $videoControllers = @()
    try { $videoControllers = @(Get-CimInstance -ClassName 'Win32_VideoController' -OperationTimeoutSec 60 -ErrorAction Stop) } catch { $videoControllers = @() }

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

function Get-WfCimErrorKind {
    # CimException.NativeErrorCode names the failure:
    # https://learn.microsoft.com/en-us/dotnet/api/microsoft.management.infrastructure.cimexception.nativeerrorcode
    param($Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.UnauthorizedAccessException]) { return 'access_denied' }
        $typeName = $current.GetType().FullName
        if ($typeName -eq 'Microsoft.Management.Infrastructure.CimException') {
            $code = [string]$current.NativeErrorCode
            if ($code -eq 'AccessDenied') { return 'access_denied' }
            if ($code -eq 'InvalidClass' -or $code -eq 'InvalidNamespace' -or $code -eq 'NotFound') { return 'not_found' }
            return 'other'
        }
        $current = $current.InnerException
    }
    return 'other'
}

function ConvertFrom-WfEventRecord {
    # One EventRecord as the element written to events.json. The field names
    # are the columns of schemas/decoded/eventlog_events.schema.json, plus
    # "xml", the complete event XML from EventRecord.ToXml(). The XML is the
    # record; when it cannot be produced this throws, and the caller stops
    # the export rather than writing a record with a hole in it. The
    # rendered message and the level and task names depend on publisher
    # metadata and locale and may be unavailable, in which case they are
    # null.
    # EventRecord: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventrecord
    param($Record)
    $xmlText = $Record.ToXml()
    if (-not $xmlText) { throw 'EventRecord.ToXml() returned no text' }
    $timeText = $null
    $m = [regex]::Match($xmlText, 'TimeCreated\s+SystemTime\s*=\s*[''"]([^''"]+)[''"]')
    if ($m.Success) { $timeText = Format-WfSystemTime -Text $m.Groups[1].Value }
    if (-not $timeText -and $null -ne $Record.TimeCreated) { $timeText = ConvertTo-WfUtcString -Value $Record.TimeCreated }
    if (-not $timeText) { throw 'the record carries no creation time' }
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

function Open-WfEventReader {
    # Opens an EventLogReader over a channel and returns the pull interface
    # the portable read loop uses: ReadNext takes the time left and returns
    # the next record or null, Convert turns a record into an export element,
    # Release disposes a record, Dispose closes the reader.
    # EventLogReader.ReadEvent(TimeSpan) takes "the maximum time to allow the
    # read operation to run before canceling the operation":
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader.readevent
    # EventLogQuery.ReverseDirection:
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogquery.reversedirection
    param([string]$Channel, [string]$QueryXml, [bool]$Reverse)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; ReadNext = $null; Convert = $null; Release = $null; Dispose = $null }
    try {
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $QueryXml)
        $query.ReverseDirection = $Reverse
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
        $result.ReadNext = { param([timespan]$Remaining) return $reader.ReadEvent($Remaining) }.GetNewClosure()
        $result.Convert = { param($Record) return (ConvertFrom-WfEventRecord -Record $Record) }
        $result.Release = { param($Record) $Record.Dispose() }
        $result.Dispose = { $reader.Dispose() }.GetNewClosure()
        $result.Ok = $true
    } catch {
        $result.ErrorKind = Get-WfEventReadErrorKind -Exception $_.Exception
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
}

function Get-WfChannelConfiguration {
    # Channel configuration and log information, each null when the account
    # may not read it. Nothing here decides a status.
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.getloginformation
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogconfiguration
    param([string]$Channel)
    $state = [ordered]@{
        record_count = $null; file_size_bytes = $null; is_log_full = $null; last_write_time_utc = $null
        is_enabled = $null; log_mode = $null; maximum_size_bytes = $null; isolation = $null; security_descriptor = $null
        configuration_error = $null
    }
    try {
        $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation($Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
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
    if ($TimeoutSeconds -lt 1) {
        $result.Message = 'not started: the source deadline had passed'
        return $result
    }
    $run = Invoke-WfProcess -FilePath $wevtutil -Arguments $arguments -TimeoutSeconds $TimeoutSeconds -MaxBytes 1048576
    if (-not $run['Started']) {
        $result.Message = 'wevtutil could not be run: ' + [string]$run['Error']
        return $result
    }
    if ($run['TimedOut']) {
        $result.Message = 'wevtutil did not finish within ' + $TimeoutSeconds + ' seconds and was stopped'
        return $result
    }
    if ($run['Oversized']) {
        $result.Message = 'wevtutil printed more than 1 MiB and was stopped: ' + [string]$run['Error']
        return $result
    }
    $result.ExitCode = [int]$run['ExitCode']
    $text = (([string]$run['StdOut']) + ' ' + ([string]$run['StdErr'])).Trim()
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
    return $result
}

function Invoke-WfProcess {
    # Starts one executable directly, with no shell, drains both output
    # streams as they arrive so the process cannot block on a full pipe, and
    # stops it when the deadline passes or when a stream has delivered more
    # than MaxBytes (UTF-8 bytes) of text. Nothing above the cap is retained:
    # an oversized run keeps only the first 4096 characters of each stream as
    # a diagnostic. MaxBytes 0 means the caller enforces its own cap on what
    # it writes (wevtutil prints a line or two). The only executables started
    # through this are wevtutil (export verb) and netsh (wlan show queries).
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds, $OutputEncoding = $null, [int64]$MaxBytes = 0)
    $result = [ordered]@{ Started = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false; Oversized = $false; Error = $null; DurationMs = $null; StdOutBytes = [int64]0; StdErrBytes = [int64]0; Diagnostic = $null }
    if ($TimeoutSeconds -lt 1) {
        $result.Error = 'not started: the deadline had passed'
        return $result
    }
    $process = $null
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $diagnosticChars = 4096
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $Arguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        if ($null -ne $OutputEncoding) {
            $startInfo.StandardOutputEncoding = $OutputEncoding
            $startInfo.StandardErrorEncoding = $OutputEncoding
        }
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $null = $process.Start()
        $result.Started = $true
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
        $streams = @(
            @{ Name = 'StdOut'; Reader = $process.StandardOutput; Buffer = (New-Object char[] 4096); Text = (New-Object System.Text.StringBuilder); Bytes = [int64]0; Done = $false; Task = $null },
            @{ Name = 'StdErr'; Reader = $process.StandardError; Buffer = (New-Object char[] 4096); Text = (New-Object System.Text.StringBuilder); Bytes = [int64]0; Done = $false; Task = $null }
        )
        foreach ($stream in $streams) { $stream.Task = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length) }
        while (-not ($streams[0].Done -and $streams[1].Done)) {
            $pending = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task]'
            foreach ($stream in $streams) { if (-not $stream.Done) { $pending.Add($stream.Task) } }
            $remaining = ($deadline - [datetime]::UtcNow).TotalMilliseconds
            if ($remaining -le 0) {
                try { $process.Kill() } catch { $null = $_ }
                $result.TimedOut = $true
                $result.Error = ('the process did not finish within {0} seconds and was stopped' -f $TimeoutSeconds)
                break
            }
            $index = [System.Threading.Tasks.Task]::WaitAny($pending.ToArray(), [int][math]::Min($remaining, 1000))
            if ($index -lt 0) { continue }
            $stream = $null
            foreach ($candidate in $streams) { if ($candidate.Task -eq $pending[$index]) { $stream = $candidate } }
            $count = [int]$stream.Task.Result
            if ($count -eq 0) {
                $stream.Done = $true
                continue
            }
            $stream.Bytes += $utf8.GetByteCount($stream.Buffer, 0, $count)
            if ($MaxBytes -gt 0 -and $stream.Bytes -gt $MaxBytes) {
                # Keep the diagnostic head only, drop the rest, stop the child.
                if ($stream.Text.Length -lt $diagnosticChars) { $null = $stream.Text.Append($stream.Buffer, 0, [math]::Min($count, $diagnosticChars - $stream.Text.Length)) }
                try { $process.Kill() } catch { $null = $_ }
                $result.Oversized = $true
                $result.Error = ('the process printed more than the cap of {0} bytes on {1} and was stopped; nothing above the cap was kept' -f $MaxBytes, $stream.Name)
                break
            }
            $null = $stream.Text.Append($stream.Buffer, 0, $count)
            $stream.Task = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length)
        }
        $result.StdOutBytes = $streams[0].Bytes
        $result.StdErrBytes = $streams[1].Bytes
        if ($result.TimedOut -or $result.Oversized) {
            $head = New-Object 'System.Collections.Generic.List[string]'
            foreach ($stream in $streams) {
                $text = $stream.Text.ToString()
                if ($text.Length -gt $diagnosticChars) { $text = $text.Substring(0, $diagnosticChars) }
                if ($text.Trim().Length -gt 0) { $head.Add($stream.Name + ': ' + $text) }
            }
            $result.Diagnostic = ($head.ToArray() -join "`n")
            return $result
        }
        $process.WaitForExit()
        $result.ExitCode = [int]$process.ExitCode
        $result.StdOut = $streams[0].Text.ToString()
        $result.StdErr = $streams[1].Text.ToString()
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        $result.DurationMs = [int64]$watch.ElapsedMilliseconds
        if ($null -ne $process) { $process.Dispose() }
    }
    return $result
}

function New-WfPseudonymSalt {
    # 16 random bytes as hex, from the operating system's generator; used for
    # one run and never written anywhere.
    $bytes = New-Object byte[] 16
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return (([System.BitConverter]::ToString($bytes)) -replace '-', '').ToLowerInvariant()
}

function Get-WfNetshPath {
    return (Get-WfToolPath -Name 'netsh')
}

function Test-WfToolPresent {
    param([string]$Path)
    return [bool](Test-Path -LiteralPath $Path -PathType Leaf)
}

function Get-WfConsoleOutputEncoding {
    # A console program writes in the console output code page, which
    # defaults to the OEM code page:
    # https://learn.microsoft.com/windows/console/console-code-pages
    # What netsh does when its output is redirected is on the README's
    # verification list; the code page used to decode it is recorded.
    try { return [Console]::OutputEncoding } catch { return (New-Object System.Text.UTF8Encoding($false)) }
}

function Get-WfKnownFolderPath {
    # ProgramData through the documented special folder, never a hard coded
    # drive letter.
    param([string]$Name)
    $path = $null
    if ($Name -eq 'ProgramData') { $path = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData) }
    elseif ($Name -eq 'ProgramFiles') { $path = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles) }
    else { throw ('unknown folder name: ' + $Name) }
    # The collectors read Windows folders. A host that answers no path, or a
    # path that is not rooted at a drive (not Windows), makes a source built
    # on it fail closed instead of reading a path the documentation never
    # described.
    if (-not $path -or $path -notmatch '^[A-Za-z]:\\') { throw ('the known folder ' + $Name + ' resolved to "' + [string]$path + '", not a Windows drive path; this collector reads Windows folders only') }
    return $path
}

function Read-WfFileBytes {
    # One file, read only, or the reason it could not be read. A file above
    # the cap is not read at all. The file is opened with FileShare ReadWrite
    # and Delete, so a program that is appending to it (a vendor's action log)
    # is never refused while this reads:
    # https://learn.microsoft.com/dotnet/api/system.io.fileshare
    # The bytes are read in chunks under the source deadline; a read that
    # passes it stops and is a timeout, so one slow volume cannot hold the
    # collector.
    param([string]$Path, [int64]$MaxBytes, [datetime]$DeadlineUtc = [datetime]::MaxValue)
    $result = [ordered]@{ Exists = $false; Readable = $false; Bytes = $null; Length = $null; LastWriteUtc = $null; ErrorKind = $null; ErrorMessage = $null }
    $stream = $null
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $result.ErrorKind = 'not_found'
            $result.ErrorMessage = 'the file does not exist'
            return $result
        }
        $result.Exists = $true
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $result.Length = [int64]$item.Length
        $result.LastWriteUtc = ConvertTo-WfUtcString -Value $item.LastWriteTimeUtc
        if ($result.Length -gt $MaxBytes) {
            $result.ErrorKind = 'too_large'
            $result.ErrorMessage = 'the file is above the cap'
            return $result
        }
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $collected = New-Object System.IO.MemoryStream
        $chunk = New-Object byte[] 65536
        while ($true) {
            if ((Get-WfUtcNow) -ge $DeadlineUtc) {
                $result.ErrorKind = 'timeout'
                $result.ErrorMessage = ('the read did not finish before the deadline; ' + $collected.Length + ' bytes had been read')
                return $result
            }
            $count = $stream.Read($chunk, 0, $chunk.Length)
            if ($count -le 0) { break }
            $collected.Write($chunk, 0, $count)
            if ($collected.Length -gt $MaxBytes) {
                $result.ErrorKind = 'too_large'
                $result.ErrorMessage = 'the file grew above the cap while it was read'
                return $result
            }
        }
        $result.Bytes = $collected.ToArray()
        $result.Length = [int64]$result.Bytes.Length
        $result.Readable = $true
    } catch {
        $result.ErrorKind = Get-WfEventReadErrorKind -Exception $_.Exception
        if ($result.ErrorKind -eq 'not_found') { $result.ErrorKind = 'other' }
        $result.ErrorMessage = $_.Exception.Message
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    return $result
}

function Get-WfSha256OfFileBounded {
    # SHA-256 of a file read in chunks under a deadline, with writers allowed
    # to continue. Returns the hash, or $null when the deadline passed, in
    # which case the caller reports a timeout rather than a partial hash.
    param([string]$Path, [datetime]$DeadlineUtc)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $chunk = New-Object byte[] 1048576
        while ($true) {
            if ((Get-WfUtcNow) -ge $DeadlineUtc) { return $null }
            $count = $stream.Read($chunk, 0, $chunk.Length)
            if ($count -le 0) { break }
            $null = $sha.TransformBlock($chunk, 0, $count, $null, 0)
        }
        $null = $sha.TransformFinalBlock($chunk, 0, 0)
        return (([System.BitConverter]::ToString($sha.Hash)) -replace '-', '').ToLowerInvariant()
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Get-WfPnpDevices {
    # Every present Plug and Play device with the documented Win32_PnPEntity
    # properties the device map needs:
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity
    param([int]$TimeoutSeconds = 60)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Devices = @() }
    $seconds = $TimeoutSeconds
    if ($seconds -lt 1) { $seconds = 1 }
    $properties = @('DeviceID', 'PNPClass', 'ClassGuid', 'Name', 'Description', 'Manufacturer', 'Service', 'Status', 'ConfigManagerErrorCode', 'Present', 'HardwareID', 'CompatibleID')
    try {
        $instances = @(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_PnPEntity' -Filter 'Present = TRUE' -Property $properties -OperationTimeoutSec $seconds -ErrorAction Stop)
        $devices = New-Object 'System.Collections.Generic.List[object]'
        foreach ($instance in $instances) {
            $values = ConvertFrom-WfCimInstance -Instance $instance -Properties $properties
            $devices.Add([ordered]@{
                    instance_id    = $values['DeviceID']
                    class          = $values['PNPClass']
                    class_guid     = $values['ClassGuid']
                    name           = $values['Name']
                    description    = $values['Description']
                    manufacturer   = $values['Manufacturer']
                    service        = $values['Service']
                    status         = $values['Status']
                    problem_code   = $values['ConfigManagerErrorCode']
                    present        = $values['Present']
                    hardware_ids   = Get-WfList -Value $values['HardwareID']
                    compatible_ids = Get-WfList -Value $values['CompatibleID']
                })
        }
        $result.Devices = $devices.ToArray()
        $result.Ok = $true
    } catch {
        $result.ErrorKind = Get-WfCimErrorKind -Exception $_.Exception
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
}

function Get-WfPnpDeviceProperties {
    # The named device properties of one device through the PnpDevice module:
    # https://learn.microsoft.com/powershell/module/pnpdevice/get-pnpdeviceproperty
    # which calls the documented Win32_PnPEntity.GetDeviceProperties method.
    # The rights that method needs are not documented and are on the README's
    # verification list; a failure is recorded per device, never fatal.
    param([string]$InstanceId, [string[]]$KeyNames)
    $result = [ordered]@{ Ok = $false; ErrorMessage = $null; Values = @{} }
    try {
        $properties = @(Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $KeyNames -ErrorAction Stop)
        foreach ($property in $properties) {
            if ($null -eq $property.KeyName) { continue }
            $result.Values[[string]$property.KeyName] = ConvertTo-WfJsonValue -Value $property.Data
        }
        $result.Ok = $true
    } catch {
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
}

function ConvertFrom-WfCimInstance {
    # The requested properties of one instance as an ordered map, dates as
    # UTC text; a property the instance lacks is null.
    param($Instance, [string[]]$Properties)
    $row = [ordered]@{}
    foreach ($name in $Properties) {
        $property = $Instance.CimInstanceProperties[$name]
        if ($null -eq $property) { $row[$name] = $null } else { $row[$name] = ConvertTo-WfJsonValue -Value $property.Value }
    }
    return $row
}

function New-WfCimProducer {
    # A pipeline that streams the instances of one class, with the WQL
    # filter and the property list pushed to WMI and an operation timeout so
    # that a provider that does not answer cannot hold the collector. The
    # producer emits one instance at a time; the portable read loop stops
    # it at the caps. Get-CimInstance -Filter, -Property, -OperationTimeoutSec:
    # https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1
    param([string]$Namespace, [string]$ClassName, [string[]]$Properties, $Filter, [double]$TimeoutSeconds)
    $seconds = [int][math]::Ceiling($TimeoutSeconds)
    if ($seconds -lt 1) { $seconds = 1 }
    $parameters = @{ Namespace = $Namespace; ClassName = $ClassName; Property = @($Properties); OperationTimeoutSec = $seconds; ErrorAction = 'Stop' }
    if ($Filter) { $parameters['Filter'] = [string]$Filter }
    $names = @($Properties)
    return @{
        Producer = { Get-CimInstance @parameters }.GetNewClosure()
        Convert  = { param($Instance) return (ConvertFrom-WfCimInstance -Instance $Instance -Properties $names) }.GetNewClosure()
    }
}

function Get-WfToolPath {
    # The inbox command line tools a command source may run, by name, under
    # System32. The allowlist of what may be run is the set of fixed argument
    # strings in the collector definitions, checked by the tests.
    param([string]$Name)
    if ($Name -ne 'netsh' -and $Name -ne 'powercfg') { throw ('unknown tool name: ' + $Name) }
    return [System.IO.Path]::Combine([string]$env:SystemRoot, 'System32', $Name + '.exe')
}

function Get-WfRegistryKey {
    # One registry key, read only: whether it exists, its subkey names and
    # every value with its RegistryValueKind and data. Get-Item on the
    # registry provider returns a Microsoft.Win32.RegistryKey:
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_registry_provider
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.getvaluekind
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.getvalue
    # Environment strings are not expanded, so the bytes are what the registry
    # holds. A missing key is ErrorKind not_found and Exists false; a key the
    # account may not open is access_denied. Nothing is created or written.
    param([string]$Path)
    $result = [ordered]@{ Exists = $false; ErrorKind = $null; ErrorMessage = $null; SubKeyNames = @(); Values = @() }
    $key = $null
    try {
        # Off Windows there is no registry drive at all; that is a failed read,
        # never a machine with every key absent.
        $drive = ($Path -split ':')[0]
        if (-not (Get-PSDrive -Name $drive -ErrorAction SilentlyContinue)) {
            $result.ErrorKind = 'preflight'
            $result.ErrorMessage = 'the registry drive ' + $drive + ': is not available on this host'
            return $result
        }
        if (-not (Test-Path -LiteralPath $Path)) {
            $result.ErrorKind = 'not_found'
            $result.ErrorMessage = 'the key does not exist'
            return $result
        }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $result.Exists = $true
        $result.SubKeyNames = @($key.GetSubKeyNames())
        $values = New-Object 'System.Collections.Generic.List[object]'
        foreach ($name in @($key.GetValueNames())) {
            $values.Add(@{
                    Name = [string]$name
                    Kind = [string]$key.GetValueKind($name)
                    Data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                })
        }
        $result.Values = $values.ToArray()
    } catch {
        $current = $_.Exception
        $kind = 'other'
        while ($null -ne $current) {
            if ($current -is [System.Security.SecurityException] -or $current -is [System.UnauthorizedAccessException]) { $kind = 'access_denied'; break }
            if ($current -is [System.Management.Automation.ItemNotFoundException]) { $kind = 'not_found'; break }
            $current = $current.InnerException
        }
        # Classify the open/read exception. An unreadable key has unknown
        # contents; do not infer absence from access denial. Windows PowerShell
        # 5.1 provider behavior remains a verification item (the provider's
        # Test-Path answers true for a key the account may not open, so a
        # refused key reaches Get-Item and raises; the error says which).
        $result.Exists = ($kind -ne 'not_found')
        $result.ErrorKind = $kind
        $result.ErrorMessage = $_.Exception.Message
    } finally {
        if ($null -ne $key) { $key.Dispose() }
    }
    return $result
}

function Get-WfDirectoryListing {
    # The files directly inside one folder, each with its size, last write
    # time, SHA-256 and version resource:
    # https://learn.microsoft.com/dotnet/api/system.diagnostics.fileversioninfo.getversioninfo
    # A folder that does not exist is Exists false with no error (an
    # observation when its parent exists, which the caller checks); one the
    # account may not list is access_denied.
    param([string]$Path, [string]$Parent, [int]$MaxFiles, [datetime]$DeadlineUtc)
    $result = [ordered]@{ Exists = $false; Parent = $Parent; ParentExists = $false; ErrorKind = $null; ErrorMessage = $null; Files = @(); Truncated = $false }
    try {
        if ((Get-WfUtcNow) -ge $DeadlineUtc) { throw 'the listing did not finish before the deadline' }
        $result.ParentExists = [bool]($Parent -and (Test-Path -LiteralPath $Parent -PathType Container))
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $result }
        $result.Exists = $true
        $items = @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop | Sort-Object -Property Name)
        if ((Get-WfUtcNow) -ge $DeadlineUtc) { throw 'the listing did not finish before the deadline' }
        $files = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $items) {
            if ($files.Count -ge $MaxFiles) { $result.Truncated = $true; break }
            if ((Get-WfUtcNow) -ge $DeadlineUtc) { throw 'the listing did not finish before the deadline' }
            $record = [ordered]@{
                name                = [string]$item.Name
                bytes               = [int64]$item.Length
                last_write_time_utc = ConvertTo-WfUtcString -Value $item.LastWriteTimeUtc
                sha256              = $null
                file_version        = $null
                product_version     = $null
                product_name        = $null
                company_name        = $null
                original_filename   = $null
                error               = $null
            }
            try {
                $record.sha256 = Get-WfSha256OfFileBounded -Path $item.FullName -DeadlineUtc $DeadlineUtc
                if ($null -eq $record.sha256) { throw 'the listing did not finish before the deadline (hashing ' + $item.Name + ')' }
                $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($item.FullName)
                if ($version.FileVersion) { $record.file_version = [string]$version.FileVersion }
                if ($version.ProductVersion) { $record.product_version = [string]$version.ProductVersion }
                if ($version.ProductName) { $record.product_name = [string]$version.ProductName }
                if ($version.CompanyName) { $record.company_name = [string]$version.CompanyName }
                if ($version.OriginalFilename) { $record.original_filename = [string]$version.OriginalFilename }
            } catch {
                if ($_.Exception.Message -like '*deadline*') { throw }
                $record.error = $_.Exception.Message
            }
            $files.Add($record)
        }
        if ((Get-WfUtcNow) -ge $DeadlineUtc) { throw 'the listing did not finish before the deadline' }
        $result.Files = $files.ToArray()
    } catch {
        $result.ErrorKind = Get-WfEventReadErrorKind -Exception $_.Exception
        if ($result.ErrorKind -eq 'not_found') { $result.ErrorKind = 'other' }
        if ($_.Exception.Message -like '*deadline*') { $result.ErrorKind = 'timeout' }
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
}

function Get-WfLogicalProcessorInformation {
    # The one native call in this collector set: GetLogicalProcessorInformationEx
    # with RelationAll, which returns the processor core, cache, group, package
    # and NUMA relationships Microsoft documents:
    # https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex
    # No CIM class carries the logical processor to core map, so the
    # declaration is compiled with Add-Type, which Microsoft documents as the
    # way to make a Platform Invoke call from PowerShell:
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/add-type?view=powershell-5.1
    # Microsoft documents that Add-Type compiles the source and generates an
    # in-memory assembly that lives in this process only; whether the Windows
    # PowerShell 5.1 compiler starts a compiler process or writes temporary
    # files while it does so is not documented on Learn and is unverified
    # (README verification item 23). The declaration names one function and
    # nothing else, and the static test pins it. The call reads; it has no
    # setter.
    # The first call with a null buffer asks for the size (ERROR_INSUFFICIENT_BUFFER,
    # 122, is the documented answer); the second fills a buffer of that size.
    $result = [ordered]@{ Ok = $false; Stage = $null; ErrorCode = $null; ErrorMessage = $null; Bytes = $null; PointerSize = [System.IntPtr]::Size }
    $typeName = 'WfNative.WfSysInfo'
    try {
        $result.Stage = 'compile'
        if (-not ([System.Management.Automation.PSTypeName]$typeName).Type) {
            $declaration = '[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetLogicalProcessorInformationEx(int RelationshipType, byte[] Buffer, ref uint ReturnedLength);'
            Add-Type -MemberDefinition $declaration -Name 'WfSysInfo' -Namespace 'WfNative' -UsingNamespace 'System.Runtime.InteropServices' -ErrorAction Stop
        }
    } catch {
        $result.ErrorMessage = $_.Exception.Message
        return $result
    }
    try {
        $result.Stage = 'size'
        $length = [uint32]0
        $null = [WfNative.WfSysInfo]::GetLogicalProcessorInformationEx(0xffff, $null, [ref]$length)
        $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($length -eq 0 -or $length -gt 16777216) {
            $result.ErrorCode = $code
            $result.ErrorMessage = ('the size query returned length ' + $length + ' with Win32 error ' + $code)
            return $result
        }
        $result.Stage = 'read'
        $buffer = New-Object byte[] ([int]$length)
        $ok = [WfNative.WfSysInfo]::GetLogicalProcessorInformationEx(0xffff, $buffer, [ref]$length)
        if (-not $ok) {
            $result.ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $result.ErrorMessage = 'the call returned FALSE'
            return $result
        }
        $bytes = New-Object byte[] ([int]$length)
        [System.Array]::Copy($buffer, $bytes, [int]$length)
        $result.Bytes = $bytes
        $result.Ok = $true
    } catch {
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
}

function New-WfDeviceKeyNative {
    # The native boundary for the device hardware key reads: eight imports,
    # bound to the system directory (DefaultDllImportSearchPaths System32,
    # https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca5392),
    # compiled once per process with Add-Type from the literal below and
    # exposed as an object whose methods forward to them, so the sequencing in
    # Get-WfDeviceInterruptPolicy runs the same way over this object and over
    # the test suite's recorder. Nothing else is declared: no setter, no
    # creator, no process or device state call.
    # https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdicreatedeviceinfolist
    # https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdiopendeviceinfow
    # https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey
    # https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdidestroydeviceinfolist
    # https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regopenkeyexw
    # https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regenumvaluew
    # https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
    # https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regclosekey
    # Microsoft documents that Add-Type compiles the source and generates an
    # in-memory assembly; whether the Windows PowerShell 5.1 compiler starts a
    # compiler process or writes temporary files while it does so is not
    # documented on Learn and is unverified (README verification item 23):
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/add-type?view=powershell-5.1
    $result = @{ Ok = $false; Error = $null; Api = $null }
    $typeName = 'WfNative.WfDeviceKey'
    try {
        if (-not ([System.Management.Automation.PSTypeName]$typeName).Type) {
            $declaration = @'
[StructLayout(LayoutKind.Sequential)] public struct SP_DEVINFO_DATA { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("setupapi.dll", SetLastError = true)] public static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr ClassGuid, IntPtr hwndParent);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool SetupDiOpenDeviceInfoW(IntPtr DeviceInfoSet, string DeviceInstanceId, IntPtr hwndParent, uint OpenFlags, ref SP_DEVINFO_DATA DeviceInfoData);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("setupapi.dll", SetLastError = true)] public static extern IntPtr SetupDiOpenDevRegKey(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, uint Scope, uint HwProfile, uint KeyType, uint samDesired);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("setupapi.dll", SetLastError = true)] public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegEnumValueW(IntPtr hKey, uint dwIndex, System.Text.StringBuilder lpValueName, ref uint lpcchValueName, IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr hKey);
'@
            Add-Type -MemberDefinition $declaration -Name 'WfDeviceKey' -Namespace 'WfNative' -UsingNamespace 'System.Runtime.InteropServices' -ErrorAction Stop
        }
        $api = New-Object psobject
        $api | Add-Member -MemberType ScriptMethod -Name 'NewDeviceInfoData' -Value {
            $data = New-Object 'WfNative.WfDeviceKey+SP_DEVINFO_DATA'
            $data.cbSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($data)
            return $data
        }
        $api | Add-Member -MemberType ScriptMethod -Name 'LastError' -Value { return [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiCreateDeviceInfoList' -Value { param($classGuid, $parent) return [WfNative.WfDeviceKey]::SetupDiCreateDeviceInfoList($classGuid, $parent) }
        $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiOpenDeviceInfoW' -Value { param($set, $id, $parent, $flags, $data) return [WfNative.WfDeviceKey]::SetupDiOpenDeviceInfoW($set, $id, $parent, $flags, $data) }
        $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiOpenDevRegKey' -Value { param($set, $data, $scope, $hwProfile, $keyType, $access) return [WfNative.WfDeviceKey]::SetupDiOpenDevRegKey($set, $data, $scope, $hwProfile, $keyType, $access) }
        $api | Add-Member -MemberType ScriptMethod -Name 'SetupDiDestroyDeviceInfoList' -Value { param($set) return [WfNative.WfDeviceKey]::SetupDiDestroyDeviceInfoList($set) }
        $api | Add-Member -MemberType ScriptMethod -Name 'RegOpenKeyExW' -Value { param($key, $subkey, $options, $access, $handle) return [WfNative.WfDeviceKey]::RegOpenKeyExW($key, $subkey, $options, $access, $handle) }
        $api | Add-Member -MemberType ScriptMethod -Name 'RegEnumValueW' -Value { param($key, $index, $name, $nameLength, $reserved, $type, $data, $dataLength) return [WfNative.WfDeviceKey]::RegEnumValueW($key, $index, $name, $nameLength, $reserved, $type, $data, $dataLength) }
        $api | Add-Member -MemberType ScriptMethod -Name 'RegQueryValueExW' -Value { param($key, $name, $reserved, $type, $data, $dataLength) return [WfNative.WfDeviceKey]::RegQueryValueExW($key, $name, $reserved, $type, $data, $dataLength) }
        $api | Add-Member -MemberType ScriptMethod -Name 'RegCloseKey' -Value { param($key) return [WfNative.WfDeviceKey]::RegCloseKey($key) }
        $result.Api = $api
        $result.Ok = $true
    } catch {
        $result.Error = 'the device key declaration could not be compiled or loaded: ' + $_.Exception.Message
    }
    return $result
}
