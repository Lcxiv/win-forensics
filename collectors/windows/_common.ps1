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
    param([hashtable]$Reader, [datetime]$DeadlineUtc, [hashtable]$Accumulator)
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
    param([string]$Channel, [string]$QueryXml, [datetime]$DeadlineUtc, [hashtable]$Accumulator)
    $result = [ordered]@{ Ok = $false; Stage = 'open'; ErrorKind = $null; ErrorMessage = $null; TimedOut = $false; Count = 0 }
    $reader = Open-WfEventReader -Channel $Channel -QueryXml $QueryXml -Reverse $true
    if (-not $reader['Ok']) {
        $result.ErrorKind = $reader['ErrorKind']
        $result.ErrorMessage = $reader['ErrorMessage']
        return $result
    }
    $result.Stage = 'read'
    try {
        $read = Invoke-WfBoundedEventRead -Reader $reader -DeadlineUtc $DeadlineUtc -Accumulator $Accumulator
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
    # into the accumulator. The accumulator's caps end the pipeline early by
    # a terminating error, which stops the producer as well, so an unbounded
    # producer cannot run past the caps.
    param([scriptblock]$Producer, [scriptblock]$Convert, [hashtable]$Accumulator)
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Count = 0 }
    $stopToken = 'WF_STOP_ENUMERATION'
    try {
        & $Producer | ForEach-Object {
            $row = & $Convert $_
            $result.Count += 1
            if (-not (Add-WfRow -Accumulator $Accumulator -Row $row)) { throw $stopToken }
        }
        $result.Ok = $true
    } catch {
        if ($_.Exception.Message -eq $stopToken) {
            $result.Ok = $true
        } else {
            $result.ErrorKind = Get-WfCimErrorKind -Exception $_.Exception
            $result.ErrorMessage = $_.Exception.Message
        }
    }
    return $result
}

function Get-WfCimRows {
    # Every instance of a class that matches the filter, streamed through the
    # caps, each as an ordered map of the requested properties with dates as
    # UTC text.
    param([string]$Namespace, [string]$ClassName, [string[]]$Properties, $Filter, [int]$MaxRows, [int64]$MaxBytes, [double]$TimeoutSeconds)
    $accumulator = New-WfRowAccumulator -MaxRows $MaxRows -MaxBytes $MaxBytes
    $result = [ordered]@{ Ok = $false; ErrorKind = $null; ErrorMessage = $null; Rows = @(); Lines = @(); Truncated = $false; TruncationReason = $null }
    if ($TimeoutSeconds -le 0) {
        $result.ErrorKind = 'timeout'
        $result.ErrorMessage = 'the deadline had passed before the class was read'
        return $result
    }
    $producer = New-WfCimProducer -Namespace $Namespace -ClassName $ClassName -Properties $Properties -Filter $Filter -TimeoutSeconds $TimeoutSeconds
    $read = Invoke-WfStreamingRead -Producer $producer['Producer'] -Convert $producer['Convert'] -Accumulator $accumulator
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
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int]$WindowDays,
        [int]$MaxEvents,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
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
                evtx_export        = (-not $SkipEvtx)
                query_sha256       = $queryHash
            }
        }

        $accumulator = New-WfRowAccumulator -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes
        $read = Read-WfEventRecords -Channel $channel -QueryXml $queryXml -DeadlineUtc $deadline -Accumulator $accumulator
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
        if ($written -and -not $readErrorKind -and -not $truncated -and -not $SkipEvtx) {
            $evtxPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/events.evtx')
            $evtx = Export-WfEvtx -QueryPath $queryPath -TargetPath $evtxPath -MaxBytes $MaxArtifactBytes -TimeoutSeconds ([int](Get-WfRemainingSeconds -DeadlineUtc $deadline))
            if (-not $evtx['Ok']) {
                if (Test-Path -LiteralPath $evtxPath) { Remove-Item -LiteralPath $evtxPath -Force }
                $message = ('source ' + $id + ': the binary .evtx export was not produced (' + [string]$evtx['Message'] + '); events.json carries the full XML of every record')
                $Notes.Add($message)
                $Log.Add($message)
            }
        } elseif ($SkipEvtx) {
            $evtx['Message'] = 'skipped by -SkipEvtx'
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
        }
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
            -MaxRows $MaxEvents -MaxBytes $MaxArtifactBytes -TimeoutSeconds (Get-WfRemainingSeconds -DeadlineUtc $deadline)
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
                    -MaxRows 1 -MaxBytes 1048576 -TimeoutSeconds (Get-WfRemainingSeconds -DeadlineUtc $deadline)
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
        if (-not $readErrorKind -and -not $timeProperty -and @($exported).Count -eq 0 -and -not $truncated) {
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
        [bool]$SkipEvtx = $false,
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
    foreach ($source in $sources) {
        $type = [string]$source['Type']
        if ($type -eq 'eventlog') {
            $result = Invoke-WfEventSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -SkipEvtx $SkipEvtx -Log $log -Notes $notes
        } elseif ($type -eq 'cim') {
            $result = Invoke-WfCimSource -Source $source -BundleRoot $bundleRoot -WindowDays $WindowDays -MaxEvents $MaxEvents `
                -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $log -Notes $notes
            if ($source['FillsMachineDrivers']) { $driverResult = $result }
        } else {
            throw ('unknown source type: ' + $type)
        }
        $entries.Add($result['Entry'])
    }
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
        [bool]$SkipEvtx = $false,
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
                -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -SkipEvtx $SkipEvtx `
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
