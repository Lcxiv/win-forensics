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
# fixed netsh query), file (one known file copied read only), pnp (present
# Plug and Play devices with their parent chain).
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
function Get-WfCollectorsVersion { return '1.1.0' }
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
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $className = [string]$Source['ClassName']
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
    # A remembered peer (BTHENUM, BTHLE), one of its GATT service nodes
    # (BTHLEDEVICE), or a node named after a Bluetooth service UUID (the
    # Bluetooth base UUID, as a peer's HID collections are); each carries
    # the peer's address in its instance id.
    param([string]$InstanceId)
    foreach ($prefix in @('BTHENUM\', 'BTHLE\', 'BTHLEDEVICE\')) {
        if ($InstanceId.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
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
    $zeroRule = 'observed_zero'
    if ($Source['ZeroRule']) { $zeroRule = [string]$Source['ZeroRule'] }
    $entry = New-WfCollectorEntry -Id $id -Kind 'other' -Required ([bool]$Source['Required'])
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
        $tool = Get-WfNetshPath
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
                        $records = Measure-WfNetshRecords -Text $text -Mode $mode
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
    # Describes one known file read only, without copying it, and writes,
    # under raw/<id>/:
    #   source.json           the path, the cap and why no copy is made (role config)
    #   result.json           whether the file existed and could be read (role report)
    #   <FileName>            the summary: size, last write time, SHA-256 of
    #                         the bytes, line count, how many address shaped
    #                         tokens it holds (role primary)
    # The WLAN report is free text that embeds "netsh wlan show all", so it
    # names the neighbours' networks, and a name the current run never saw
    # cannot be recognised in free text; the summary is therefore all that
    # leaves the machine. The owner reads the report itself at the PC. A file
    # that does not exist or cannot be read is not_collected with the
    # message from Windows; a file above the cap is capture_failed.
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes
    )
    $id = [string]$Source['Id']
    $fileName = [string]$Source['FileName']
    $entry = New-WfCollectorEntry -Id $id -Kind 'other' -Required ([bool]$Source['Required'])
    $roles = @{ 'source.json' = 'config'; 'result.json' = 'report' }
    $roles[$fileName] = 'primary'
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $summaryPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/' + $fileName)
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir
        $path = [string]$Source['Path']
        if (-not $path) { $path = (Get-WfKnownFolderPath -Name ([string]$Source['Folder'])) + '\' + [string]$Source['PathTail'] }
        $config = [ordered]@{
            path               = $path
            path_documented    = [bool]$Source['PathDocumented']
            max_artifact_bytes = $MaxArtifactBytes
            mode               = 'summary'
            why_no_copy        = 'the file is free text that can name networks the current run never saw, so only its size, time, hash and token counts are recorded'
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/source.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @('System.IO.File.ReadAllBytes', $path)
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }

        $read = Read-WfFileBytes -Path $path -MaxBytes $MaxArtifactBytes
        $readErrorKind = ''
        $readErrorMessage = ''
        if (-not $read['Exists']) {
            $readErrorKind = 'preflight'
            $readErrorMessage = 'the file does not exist: ' + $path + '. ' + [string]$Source['MissingHint']
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
        $summary = $null
        if (-not $readErrorKind) {
            $bytes = [byte[]]$read['Bytes']
            $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $digest = (([System.BitConverter]::ToString($sha.ComputeHash($bytes))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
            $summary = [ordered]@{
                path                = $path
                bytes               = [int64]$bytes.Length
                last_write_time_utc = $read['LastWriteUtc']
                sha256              = $digest
                lines               = @(($text -replace "`r`n", "`n") -split "`n").Count
                address_tokens      = @([regex]::Matches($text, (Get-WfMacAddressPattern))).Count
                content_kept        = $false
            }
            Write-WfJsonFile -Path $summaryPath -Object $summary
        }
        $stopped = Get-WfUtcNow
        $report = [ordered]@{
            path         = $path
            exists       = [bool]$read['Exists']
            readable     = [bool]$read['Readable']
            error        = $read['ErrorMessage']
            source_bytes = $read['Length']
            summarised   = ($null -ne $summary)
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
            $Notes.Add('source ' + $id + ': the file exists and was summarised, not copied; its text can name networks the current run never saw')
        }
        Remove-WfPrimaryUnlessKept -Path $summaryPath -Status $entry.status -Truncated $false -RecordCount $(if ($met) { 1 } else { 0 }) -Log $Log -SourceId $id
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                exists              = $report.exists
                readable            = $report.readable
                source_bytes        = $report.source_bytes
                last_write_time_utc = $(if ($null -ne $summary) { $summary.last_write_time_utc } else { $null })
                content_kept        = $false
            }
            verified_by = 'the source size, time and hash are in the summary artifact; the text itself is not in the bundle'
        }
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = $(if ($met) { ('{0} bytes summarised' -f $summary.bytes) } else { $readErrorMessage })
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while reading this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $summaryPath) { Remove-Item -LiteralPath $summaryPath -Force }
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
    $context = @{ Salt = (New-WfPseudonymSalt); Ssids = (New-Object 'System.Collections.Generic.List[string]') }
    $protects = $false
    foreach ($source in $sources) {
        $type = [string]$source['Type']
        if ($type -eq 'eventlog') {
            if ($source['Protect']) { $protects = $true }
            $result = Invoke-WfEventSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'cim') {
            $result = Invoke-WfCimSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes
            if ($source['FillsMachineDrivers']) { $driverResult = $result }
        } elseif ($type -eq 'command') {
            $protects = $true
            $result = Invoke-WfCommandSource -Source $source -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes `
                -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } elseif ($type -eq 'file') {
            $protects = $true
            $result = Invoke-WfFileSource -Source $source -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes `
                -Log $log -Notes $notes
        } elseif ($type -eq 'pnp') {
            $protects = $true
            $result = Invoke-WfPnpSource -Source $source -BundleRoot $bundleRoot -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes -Context $context
        } else {
            throw ('unknown source type: ' + $type)
        }
        $entries.Add($result['Entry'])
    }
    $context['Ssids'].Clear()
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
    return [System.IO.Path]::Combine([string]$env:SystemRoot, 'System32', 'netsh.exe')
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
    if ($Name -eq 'ProgramData') { return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData) }
    throw ('unknown folder name: ' + $Name)
}

function Read-WfFileBytes {
    # One file, read only, or the reason it could not be read. A file above
    # the cap is not read at all.
    param([string]$Path, [int64]$MaxBytes)
    $result = [ordered]@{ Exists = $false; Readable = $false; Bytes = $null; Length = $null; LastWriteUtc = $null; ErrorKind = $null; ErrorMessage = $null }
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
        $result.Bytes = [System.IO.File]::ReadAllBytes($Path)
        $result.Readable = $true
    } catch {
        $result.ErrorKind = Get-WfEventReadErrorKind -Exception $_.Exception
        if ($result.ErrorKind -eq 'not_found') { $result.ErrorKind = 'other' }
        $result.ErrorMessage = $_.Exception.Message
    }
    return $result
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
