# Stutter Guard journal and backup readers for the change scripts in this
# directory. Dot sourced; it defines functions and changes nothing.
#
# Stutter Guard is a third party tuning tool the owner ran on 2026-11-12. It
# records the state of every value it changes in journal.json before the
# change, and exports each touched key with reg.exe into a per session backup
# folder. The undo steps restore single rows of that record, so this file
# reads both, strictly as data: nothing here runs, imports or loads anything
# Stutter Guard wrote, and no Stutter Guard binary or script is ever started.
#
# The formats come from the public source at one pinned commit, read on
# GitHub, never built or run:
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Infra/Journal.cs
#   JournalEntry: TweakId, Kind, Target, Existed, ValueKind, Data, When;
#   JournalData: Version, Originals, Applied, State; serialised by
#   System.Text.Json with default (PascalCase) names, nulls omitted, When is
#   DateTime.Now. Kind "reg" has Target "HKLM\path|ValueName" and the old
#   value in Existed, ValueKind (RegistryValueKind name) and Data.
#   RecordOriginal keeps only the first record per TweakId, Kind and Target
#   (Target compared ignoring case).
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Infra/RegistryOps.cs
#   RegValue.Serialize: DWord and QWord as invariant decimal, Binary as
#   upper case hex (Convert.ToHexString), MultiString joined on newlines.
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Infra/JournalRestorer.cs
#   RestoreReg: Existed with a kind and data writes that value back,
#   otherwise the value is deleted.
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Infra/BackupSet.cs
#   Backups\yyyyMMdd-HHmmss\<SafeName(key)>.reg, one reg export per key and
#   session, SafeName replacing every character that is not a letter, digit,
#   '-', '_' or '.' with '_' and cutting names over 150 characters to their
#   first 141 plus '-' and an FNV-1a hash of the full path.
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Infra/Paths.cs
#   Data folder %ProgramData%\Stutter Guard, journal.json in it.
#
# Later steps of the undo order (1b, 4a) call Read-WfSgJournal and
# Select-WfSgOriginalRow with their own targets; nothing here is specific to
# the GPU.
#
# Target: Windows PowerShell 5.1. Plain ASCII.

if (Get-Command -Name 'Read-WfSgJournal' -CommandType Function -ErrorAction SilentlyContinue) { return }

function Get-WfSgPinnedCommit { return '8c783a478f4b511c273b3235bf745b5d64550f49' }

function Get-WfSha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    } finally {
        $sha.Dispose()
    }
    return (ConvertTo-WfHex -Bytes $hash)
}

function ConvertTo-WfHex {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes) { return '' }
    $builder = New-Object System.Text.StringBuilder
    foreach ($b in $Bytes) { [void]$builder.Append($b.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)) }
    return $builder.ToString()
}

function ConvertFrom-WfHex {
    # Even length hexadecimal text to bytes, or $null when it is not that.
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    if (($Text.Length % 2) -ne 0) { return $null }
    if ($Text -notmatch '^[0-9A-Fa-f]*$') { return $null }
    $bytes = New-Object byte[] ($Text.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Text.Substring($i * 2, 2), 16)
    }
    return , $bytes
}

function New-WfRegValueModel {
    # One registry value as data: whether it exists, its kind (the
    # RegistryValueKind name: DWord, QWord, Binary, String, ...), and its data
    # as a number (DWord, QWord), bytes (Binary and anything else raw) or text
    # (String).
    param(
        [bool]$Exists,
        [string]$Kind = '',
        $Number = $null,
        [byte[]]$Bytes = $null,
        $Text = $null
    )
    return [pscustomobject]@{
        Exists = $Exists
        Kind   = $Kind
        Number = $Number
        Bytes  = $Bytes
        Text   = $Text
    }
}

function New-WfAbsentValue { return (New-WfRegValueModel -Exists $false) }

function ConvertFrom-WfSgRowValue {
    # The value a journal row records, decoded as RegValue.Deserialize does.
    # Returns @{ Ok; Value; Reason }. Only the kinds the change scripts can
    # restore exactly are accepted.
    param([bool]$Existed, $ValueKind, $Data)
    if (-not $Existed) {
        return [pscustomobject]@{ Ok = $true; Value = (New-WfAbsentValue); Reason = '' }
    }
    if ($ValueKind -isnot [string] -or $Data -isnot [string]) {
        return [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'the row says the value existed but carries no kind or data' }
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    switch -CaseSensitive ($ValueKind) {
        'DWord' {
            $n = [uint32]0
            if (-not [uint32]::TryParse($Data, [System.Globalization.NumberStyles]::None, $invariant, [ref]$n)) {
                return [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'DWord data is not a decimal number' }
            }
            return [pscustomobject]@{ Ok = $true; Value = (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]$n)); Reason = '' }
        }
        'QWord' {
            $n = [uint64]0
            if (-not [uint64]::TryParse($Data, [System.Globalization.NumberStyles]::None, $invariant, [ref]$n)) {
                return [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'QWord data is not a decimal number' }
            }
            return [pscustomobject]@{ Ok = $true; Value = (New-WfRegValueModel -Exists $true -Kind 'QWord' -Number $n); Reason = '' }
        }
        'Binary' {
            $bytes = ConvertFrom-WfHex -Text $Data
            if ($null -eq $bytes) {
                return [pscustomobject]@{ Ok = $false; Value = $null; Reason = 'Binary data is not hexadecimal' }
            }
            return [pscustomobject]@{ Ok = $true; Value = (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes $bytes); Reason = '' }
        }
        'String' {
            return [pscustomobject]@{ Ok = $true; Value = (New-WfRegValueModel -Exists $true -Kind 'String' -Text $Data); Reason = '' }
        }
        default {
            return [pscustomobject]@{ Ok = $false; Value = $null; Reason = ('value kind ' + $ValueKind + ' is not one this script restores') }
        }
    }
}

function Test-WfRegValueEqual {
    # Same existence, same kind (ignoring case), same data.
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    if (-not $A.Exists -and -not $B.Exists) { return $true }
    if ($A.Exists -ne $B.Exists) { return $false }
    if (-not [string]::Equals($A.Kind, $B.Kind, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    switch ($A.Kind) {
        'DWord' { return ([uint64]$A.Number -eq [uint64]$B.Number) }
        'QWord' { return ([uint64]$A.Number -eq [uint64]$B.Number) }
        'String' { return [string]::Equals([string]$A.Text, [string]$B.Text, [System.StringComparison]::Ordinal) }
        default { return ((ConvertTo-WfHex -Bytes $A.Bytes) -ceq (ConvertTo-WfHex -Bytes $B.Bytes)) }
    }
}

function Get-WfAffinityMask {
    # The KAFFINITY mask an AssignmentSetOverride value holds, or $null.
    # Learn: REG_BINARY (little endian, at most the platform's KAFFINITY
    # size), REG_DWORD or REG_QWORD:
    # https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority
    param($Value)
    if ($null -eq $Value -or -not $Value.Exists) { return $null }
    if ($Value.Kind -eq 'DWord' -or $Value.Kind -eq 'QWord') { return [uint64]$Value.Number }
    if ($Value.Kind -eq 'Binary') {
        if ($null -eq $Value.Bytes -or $Value.Bytes.Length -eq 0 -or $Value.Bytes.Length -gt 8) { return $null }
        [uint64]$mask = 0
        for ($i = 0; $i -lt $Value.Bytes.Length; $i++) { $mask = $mask -bor ([uint64]$Value.Bytes[$i] -shl (8 * $i)) }
        return $mask
    }
    return $null
}

function Format-WfCpuList {
    param($Mask)
    if ($null -eq $Mask) { return 'no mask' }
    $cpus = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 64; $i++) {
        if (([uint64]$Mask -band ([uint64]1 -shl $i)) -ne 0) { $cpus.Add([string]$i) }
    }
    if ($cpus.Count -eq 0) { return 'no CPU' }
    if ($cpus.Count -eq 1) { return ('CPU ' + $cpus[0]) }
    return ('CPUs ' + ($cpus -join ', '))
}

function Format-WfRegValue {
    param($Value)
    if ($null -eq $Value) { return 'unknown' }
    if (-not $Value.Exists) { return 'absent' }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    switch ($Value.Kind) {
        'DWord' { return ('REG_DWORD 0x' + ([uint64]$Value.Number).ToString('X8', $invariant) + ' (' + ([uint64]$Value.Number).ToString($invariant) + ')') }
        'QWord' { return ('REG_QWORD 0x' + ([uint64]$Value.Number).ToString('X16', $invariant)) }
        'Binary' {
            $pairs = @()
            foreach ($b in $Value.Bytes) { $pairs += $b.ToString('X2', $invariant) }
            return ('REG_BINARY ' + ($pairs -join ' '))
        }
        'String' { return 'REG_SZ (text not printed)' }
        default { return ('kind ' + $Value.Kind + ' (data not printed)') }
    }
}

function ConvertTo-WfWallClock {
    # A journal When as the wall clock time Stutter Guard wrote (DateTime.Now,
    # serialised with its offset), with the offset dropped: the session folder
    # names use the same local clock. $null when it is not a date.
    param($Value)
    if ($Value -is [datetime]) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Unspecified) }
    if ($Value -isnot [string]) { return $null }
    $text = $Value
    if ($text.StartsWith('wf:', [System.StringComparison]::Ordinal)) { $text = $text.Substring(3) }
    $parsed = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $null }
    return [datetime]::SpecifyKind($parsed.DateTime, [System.DateTimeKind]::Unspecified)
}

function Test-WfJsonProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    foreach ($p in $Object.PSObject.Properties) {
        if ($p.Name -ceq $Name) { return $true }
    }
    return $false
}

function Read-WfSgJournal {
    # Reads journal.json as data. Returns Status 'ok', 'missing' or
    # 'unreadable' with a Reason, the file's SHA-256 and the Originals rows.
    # Every row must have the documented shape; one malformed row makes the
    # whole journal unreadable, because a restore must never rest on a
    # record the reader only half understood.
    param([string]$Path)
    $result = [pscustomobject]@{ Status = 'unreadable'; Reason = ''; Sha256 = $null; Bytes = 0; Originals = @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $result.Status = 'missing'
        $result.Reason = 'journal.json is not in the Stutter Guard data folder'
        return $result
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        $result.Reason = 'journal.json could not be read (' + $_.Exception.GetType().Name + ')'
        return $result
    }
    $result.Bytes = $bytes.Length
    $result.Sha256 = Get-WfSha256Hex -Bytes $bytes
    try {
        $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes)
    } catch {
        $result.Reason = 'journal.json is not UTF-8 text'
        return $result
    }
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    if ($text.Trim().Length -eq 0) {
        $result.Reason = 'journal.json is empty'
        return $result
    }
    # PowerShell 7 turns date shaped strings into DateTime values during
    # ConvertFrom-Json and Windows PowerShell 5.1 does not. Marking every When
    # string first keeps both on the text Stutter Guard wrote. The marked
    # text lives in memory only.
    $guarded = [regex]::Replace($text, '("When"\s*:\s*")', '${1}wf:')
    try {
        $doc = ConvertFrom-Json -InputObject $guarded
    } catch {
        $result.Reason = 'journal.json is not valid JSON'
        return $result
    }
    if ($null -eq $doc -or $doc -is [array] -or $doc -isnot [System.Management.Automation.PSCustomObject]) {
        $result.Reason = 'journal.json is not a JSON object'
        return $result
    }
    if (-not (Test-WfJsonProperty -Object $doc -Name 'Originals')) {
        $result.Reason = 'journal.json has no Originals list'
        return $result
    }
    $originals = $doc.Originals
    if ($null -eq $originals) {
        $result.Reason = 'Originals is null'
        return $result
    }
    if ($originals -isnot [array]) {
        $result.Reason = 'Originals is not a list'
        return $result
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($entry in $originals) {
        $index++
        if ($entry -isnot [System.Management.Automation.PSCustomObject]) {
            $result.Reason = 'Originals row ' + $index + ' is not an object'
            return $result
        }
        foreach ($name in @('TweakId', 'Kind', 'Target')) {
            if (-not (Test-WfJsonProperty -Object $entry -Name $name) -or $entry.$name -isnot [string]) {
                $result.Reason = 'Originals row ' + $index + ' has no text ' + $name
                return $result
            }
        }
        if (-not (Test-WfJsonProperty -Object $entry -Name 'Existed') -or $entry.Existed -isnot [bool]) {
            $result.Reason = 'Originals row ' + $index + ' has no true or false Existed'
            return $result
        }
        $valueKind = $null
        $data = $null
        foreach ($name in @('ValueKind', 'Data')) {
            if (Test-WfJsonProperty -Object $entry -Name $name) {
                $v = $entry.$name
                if ($null -ne $v -and $v -isnot [string]) {
                    $result.Reason = 'Originals row ' + $index + ' has a ' + $name + ' that is not text'
                    return $result
                }
                if ($name -eq 'ValueKind') { $valueKind = $v } else { $data = $v }
            }
        }
        if (-not (Test-WfJsonProperty -Object $entry -Name 'When')) {
            $result.Reason = 'Originals row ' + $index + ' has no When'
            return $result
        }
        $when = ConvertTo-WfWallClock -Value $entry.When
        if ($null -eq $when) {
            $result.Reason = 'Originals row ' + $index + ' has a When that is not a date'
            return $result
        }
        $rows.Add([pscustomobject]@{
                Index     = $index
                TweakId   = $entry.TweakId
                Kind      = $entry.Kind
                Target    = $entry.Target
                Existed   = $entry.Existed
                ValueKind = $valueKind
                Data      = $data
                When      = $when
            })
    }
    $result.Status = 'ok'
    $result.Originals = $rows.ToArray()
    return $result
}

function Select-WfSgOriginalRow {
    # The single Originals row for one target. Kind is compared as Stutter
    # Guard does (ordinal), Target ignoring case. Exactly one row may match,
    # and it must belong to the expected tweak. Returns Status 'ok',
    # 'missing', 'ambiguous' or 'other_tweak', with the row and its decoded
    # value.
    param($Journal, [string]$Kind, [string]$Target, [string]$TweakId)
    $matched = @($Journal.Originals | Where-Object { $_.Kind -ceq $Kind -and [string]::Equals($_.Target, $Target, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($matched.Count -eq 0) {
        return [pscustomobject]@{ Status = 'missing'; Row = $null; Value = $null; Reason = 'no Originals row for this value' }
    }
    if ($matched.Count -gt 1) {
        $indexes = ($matched | ForEach-Object { [string]$_.Index }) -join ', '
        return [pscustomobject]@{ Status = 'ambiguous'; Row = $null; Value = $null; Reason = ('rows ' + $indexes + ' all record this value') }
    }
    $row = $matched[0]
    if (-not [string]::Equals($row.TweakId, $TweakId, [System.StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Status = 'other_tweak'; Row = $row; Value = $null; Reason = ('row ' + $row.Index + ' belongs to another tweak') }
    }
    $decoded = ConvertFrom-WfSgRowValue -Existed $row.Existed -ValueKind $row.ValueKind -Data $row.Data
    if (-not $decoded.Ok) {
        return [pscustomobject]@{ Status = 'unreadable'; Row = $row; Value = $null; Reason = ('row ' + $row.Index + ': ' + $decoded.Reason) }
    }
    return [pscustomobject]@{ Status = 'ok'; Row = $row; Value = $decoded.Value; Reason = '' }
}

function Get-WfSgSafeName {
    # BackupSet.SafeName at the pinned commit.
    param([string]$Text)
    $builder = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        if ([char]::IsLetterOrDigit($c) -or $c -eq '-' -or $c -eq '_' -or $c -eq '.') { [void]$builder.Append($c) } else { [void]$builder.Append('_') }
    }
    $name = $builder.ToString()
    if ($name.Length -le 150) { return $name }
    # FNV-1a over the UTF-16 code units, low byte then high byte.
    [uint64]$h = 2166136261
    foreach ($c in $Text.ToCharArray()) {
        $code = [int]$c
        $h = (($h -bxor [uint64]($code -band 0xFF)) * 16777619) -band [uint64]4294967295
        $h = (($h -bxor [uint64](($code -shr 8) -band 0xFF)) * 16777619) -band [uint64]4294967295
    }
    $hash = ([uint32]$h).ToString('x8', [System.Globalization.CultureInfo]::InvariantCulture)
    return ($name.Substring(0, 150 - $hash.Length - 1) + '-' + $hash)
}

function Get-WfLongHiveForm {
    # HKLM\X -> HKEY_LOCAL_MACHINE\X, the form reg.exe writes in a .reg file.
    param([string]$Path)
    if ($Path -match '^(?i)HKLM\\') { return ('HKEY_LOCAL_MACHINE' + $Path.Substring(4)) }
    return $Path
}

function Find-WfSgSessionRegFile {
    # The .reg export Stutter Guard wrote for one key in the backup session
    # that recorded a row: the latest Backups\yyyyMMdd-HHmmss folder of the
    # row's day that was created no later than the row. Returns Status 'ok'
    # with Session and Path, or 'missing' with a Reason.
    param([string]$DataDirectory, [string]$ExportedKeyPath, [datetime]$When)
    $backups = Join-Path -Path $DataDirectory -ChildPath 'Backups'
    if (-not (Test-Path -LiteralPath $backups -PathType Container)) {
        return [pscustomobject]@{ Status = 'missing'; Session = $null; Path = $null; Reason = 'there is no Backups folder' }
    }
    $best = $null
    $bestStamp = [datetime]::MinValue
    foreach ($dir in @(Get-ChildItem -LiteralPath $backups -Directory -ErrorAction Stop)) {
        if ($dir.Name -notmatch '^\d{8}-\d{6}$') { continue }
        $stamp = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($dir.Name, 'yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$stamp)) { continue }
        if ($stamp.Date -ne $When.Date) { continue }
        if ($stamp -gt $When) { continue }
        if ($stamp -gt $bestStamp) {
            $best = $dir
            $bestStamp = $stamp
        }
    }
    if ($null -eq $best) {
        return [pscustomobject]@{ Status = 'missing'; Session = $null; Path = $null; Reason = 'no backup session of that day was created before the row' }
    }
    $file = Join-Path -Path $best.FullName -ChildPath ((Get-WfSgSafeName -Text $ExportedKeyPath) + '.reg')
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        return [pscustomobject]@{ Status = 'missing'; Session = $best.Name; Path = $null; Reason = ('session ' + $best.Name + ' holds no export of the key') }
    }
    return [pscustomobject]@{ Status = 'ok'; Session = $best.Name; Path = $file; Reason = '' }
}

function ConvertFrom-WfRegHexList {
    param([string]$Text)
    $clean = ($Text -replace '\s', '')
    if ($clean.Length -eq 0) { return , (New-Object byte[] 0) }
    $parts = $clean.Split(',')
    $bytes = New-Object byte[] $parts.Length
    for ($i = 0; $i -lt $parts.Length; $i++) {
        if ($parts[$i] -notmatch '^[0-9A-Fa-f]{2}$') { return $null }
        $bytes[$i] = [Convert]::ToByte($parts[$i], 16)
    }
    return , $bytes
}

function Read-WfRegExportFile {
    # Parses a reg.exe export as text. It is never imported. Returns Status
    # 'ok' or 'unreadable' with a Reason, the file's SHA-256, and Sections:
    # key path (as written, compared ignoring case) -> value name -> model.
    # Understood data forms: dword:, hex: (REG_BINARY), hex(b): (REG_QWORD,
    # eight little endian bytes) and quoted strings; any other hex(n) form
    # is kept as raw bytes with kind 'Other'. A deletion line ("=-" or
    # "[-key]") is not something an export holds and makes the file
    # unreadable.
    param([string]$Path)
    $result = [pscustomobject]@{ Status = 'unreadable'; Reason = ''; Sha256 = $null; Sections = @{} }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        $result.Reason = 'the .reg file could not be read (' + $_.Exception.GetType().Name + ')'
        return $result
    }
    $result.Sha256 = Get-WfSha256Hex -Bytes $bytes
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    } else {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    $raw = $text -split "`r?`n"
    $lines = New-Object System.Collections.Generic.List[string]
    $pending = ''
    foreach ($line in $raw) {
        $current = $line
        if ($pending.Length -gt 0) { $current = $pending + $line.TrimStart() }
        if ($current.TrimEnd().EndsWith('\') -and $current -match '=\s*hex') {
            $pending = $current.TrimEnd()
            $pending = $pending.Substring(0, $pending.Length - 1)
            continue
        }
        $pending = ''
        $lines.Add($current)
    }
    $first = $null
    foreach ($line in $lines) { if ($line.Trim().Length -gt 0) { $first = $line.Trim(); break } }
    if ($first -cne 'Windows Registry Editor Version 5.00') {
        $result.Reason = 'the file does not start with the reg.exe export header'
        return $result
    }
    $sections = @{}
    $section = $null
    $seenHeader = $false
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if (-not $seenHeader) { $seenHeader = $true; continue }
        if ($t.StartsWith('[-')) {
            $result.Reason = 'the file holds a key deletion, which no export holds'
            return $result
        }
        if ($t.StartsWith('[') -and $t.EndsWith(']')) {
            $name = $t.Substring(1, $t.Length - 2)
            $keyLower = $name.ToLowerInvariant()
            if ($sections.ContainsKey($keyLower)) {
                $result.Reason = 'a key appears twice'
                return $result
            }
            $section = @{}
            $sections[$keyLower] = $section
            continue
        }
        if ($null -eq $section) {
            $result.Reason = 'a value appears before any key'
            return $result
        }
        $m = [regex]::Match($t, '^(?:"((?:[^"\\]|\\.)*)"|(@))=(.*)$')
        if (-not $m.Success) {
            $result.Reason = 'a line is neither a key nor a value'
            return $result
        }
        if ($m.Groups[2].Success) { $valueName = '' } else { $valueName = $m.Groups[1].Value -replace '\\(.)', '$1' }
        $dataText = $m.Groups[3].Value.Trim()
        $model = $null
        if ($dataText -ceq '-') {
            $result.Reason = 'the file holds a value deletion, which no export holds'
            return $result
        } elseif ($dataText -match '^dword:([0-9A-Fa-f]{8})$') {
            $model = New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64][Convert]::ToUInt32($Matches[1], 16))
        } elseif ($dataText -match '^hex:(.*)$') {
            $b = ConvertFrom-WfRegHexList -Text $Matches[1]
            if ($null -eq $b) { $result.Reason = 'a hex value is malformed'; return $result }
            $model = New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes $b
        } elseif ($dataText -match '^hex\(b\):(.*)$') {
            $b = ConvertFrom-WfRegHexList -Text $Matches[1]
            if ($null -eq $b -or $b.Length -ne 8) { $result.Reason = 'a hex(b) value is not eight bytes'; return $result }
            $model = New-WfRegValueModel -Exists $true -Kind 'QWord' -Number ([BitConverter]::ToUInt64($b, 0))
        } elseif ($dataText -match '^hex\(([0-9A-Fa-f]+)\):(.*)$') {
            $b = ConvertFrom-WfRegHexList -Text $Matches[2]
            if ($null -eq $b) { $result.Reason = 'a hex value is malformed'; return $result }
            $model = New-WfRegValueModel -Exists $true -Kind 'Other' -Bytes $b
        } elseif ($dataText -match '^"((?:[^"\\]|\\.)*)"$') {
            $model = New-WfRegValueModel -Exists $true -Kind 'String' -Text ($Matches[1] -replace '\\(.)', '$1')
        } else {
            $result.Reason = 'a value has data in a form this reader does not know'
            return $result
        }
        $nameLower = $valueName.ToLowerInvariant()
        if ($section.ContainsKey($nameLower)) {
            $result.Reason = 'a value appears twice in one key'
            return $result
        }
        $section[$nameLower] = $model
    }
    $result.Status = 'ok'
    $result.Sections = $sections
    return $result
}

function Get-WfRegExportValue {
    # One value from a parsed export: the model, an absent model when the key
    # is in the file without the value, or an absent model when the key is
    # not in the file but its parent (the exported key) is. $null when the
    # file cannot say (the parent is not in it either).
    param($Export, [string]$KeyPath, [string]$ParentKeyPath, [string]$ValueName)
    $key = (Get-WfLongHiveForm -Path $KeyPath).ToLowerInvariant()
    $parent = (Get-WfLongHiveForm -Path $ParentKeyPath).ToLowerInvariant()
    if ($Export.Sections.ContainsKey($key)) {
        $section = $Export.Sections[$key]
        $name = $ValueName.ToLowerInvariant()
        if ($section.ContainsKey($name)) { return $section[$name] }
        return (New-WfAbsentValue)
    }
    if ($Export.Sections.ContainsKey($parent)) { return (New-WfAbsentValue) }
    return $null
}
