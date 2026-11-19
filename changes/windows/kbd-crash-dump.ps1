# kbd-crash-dump: let the person at the PC end a hard freeze with a keyboard
# initiated stop error, so that the freeze leaves a memory dump and a stop code
# instead of only a power off.
#
# This is a change script, not a collector. -Apply and -Undo change the
# registry of the machine they run on; -Plan and -Readback only read. Nothing
# in collectors/, the scenario runner or remote-access/ may call it, and it is
# run only by hand, elevated, at the PC, on the captain's own word. The rules
# for this area are in changes/windows/README.md; the operator page is
# docs/kbd-crash-dump.md.
#
# Verbs, exactly one (-Plan when none is named):
#   -Plan      Read only. Prints the current values, exactly what -Apply would
#              change, every precondition with OK or FAIL, and refuses with the
#              reasons when one fails. Exit 0 ready, 1 refused.
#   -Apply     Prechecks, saves every affected key to a timestamped evidence
#              folder (a values CSV, reg export files and their SHA-256), reads
#              the state again, writes, and reads back with PASS or FAIL per
#              value. Exit 0 all PASS, 1 refused with nothing changed, 2 a write
#              failed or the readback failed (run -Undo).
#   -Undo      Restores exactly the before-state saved by an -Apply (the newest
#              apply folder, or -EvidenceFolder): a value that was absent is
#              deleted, a value that existed gets its saved REG_DWORD back, a
#              key the apply created is removed when it is empty again, and
#              nothing else is touched. Saves the state it is about to undo
#              first, then reads back with PASS or FAIL per value. Exit codes as
#              for -Apply.
#   -Readback  Read only. Compares the live values with what -Apply sets and
#              says whether the PC has restarted since the newest apply. Exit 0
#              all PASS, 1 otherwise.
# Options:
#   -AlternateKeys      Use Microsoft's alternate key sequence (Dump1Keys and
#                       Dump2Key under the crashdump subkeys) instead of
#                       CrashOnCtrlScroll, for a keyboard without SCROLL LOCK.
#                       The second key is fixed to Microsoft's documented
#                       example, Dump2Key 0x3d, the spacebar.
#   -Dump1Keys <n>      With -AlternateKeys only: the first key bitmap from
#                       Microsoft's table (0x01 right SHIFT, 0x02 right CTRL,
#                       0x04 right ALT, 0x10 left SHIFT, 0x20 left CTRL, 0x40
#                       left ALT, or a combination). Default 0x02.
#   -EvidenceRoot <dir> Where -Apply and -Undo save their folders and where
#                       -Undo and -Readback look for them. Default
#                       <Desktop>\wf-changes\kbd-crash-dump.
#   -EvidenceFolder <dir>  With -Undo only: the apply folder to restore from.
#
# Every Windows fact relied on, from Microsoft Learn:
#   Keys, values, the sequence, the restart, bug check 0xE2, the alternate keys
#   and their CrashOnCtrlScroll condition, the limits:
#     https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard
#   The same two keys for a freeze, and the default dump path:
#     https://learn.microsoft.com/troubleshoot/windows-client/performance/windows-based-computer-freeze-troubleshooting
#   CrashControl values (CrashDumpEnabled 0 records no dump, LogEvent,
#   AutoReboot, DumpFile):
#     https://learn.microsoft.com/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options
#   reg export syntax and exit codes (0 success, 1 failure):
#     https://learn.microsoft.com/windows-server/administration/windows-commands/reg-export
#   RegistryKey (OpenBaseKey, OpenSubKey, CreateSubKey, SetValue, DeleteValue,
#   DeleteSubKey, which refuses a key with child subkeys):
#     https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey
#   WindowsPrincipal.IsInRole:
#     https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
#   Win32_OperatingSystem LastBootUpTime:
#     https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem
# What only the PC can show is in changes/windows/README.md, "Facts to verify
# on the PC".
#
# Target: Windows PowerShell 5.1, Run as administrator for -Apply and -Undo.
# Plain ASCII. The script never prompts, never restarts anything, and starts
# no process but reg.exe with the export verb.

[CmdletBinding()]
param(
    [switch]$Plan,
    [switch]$Apply,
    [switch]$Undo,
    [switch]$Readback,
    [switch]$AlternateKeys,
    [int]$Dump1Keys = 2,
    [string]$EvidenceRoot = '',
    [string]$EvidenceFolder = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Portable logic. The Pester suite runs everything above the adapters as it
# will run on Windows.
# ---------------------------------------------------------------------------

# Constants are functions, so a function never depends on a script variable.
function Get-KcdServicesPath { return 'SYSTEM\CurrentControlSet\Services' }
# kbdhid is the USB keyboard driver service, i8042prt the PS/2 one. The
# Hyper-V keyboard (hyperkbd) is not touched: this is for a physical PC.
function Get-KcdKeyboardServices { return @('kbdhid', 'i8042prt') }
function Get-KcdCrashControlPath { return 'SYSTEM\CurrentControlSet\Control\CrashControl' }
# Microsoft's example: Dump2Key 0x3d with Dump1Keys 0x02 is the right CTRL key
# and the spacebar pressed twice.
function Get-KcdAlternateDump2Key { return 61 }
function Get-KcdLearnUrl { return 'https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard' }
function Get-KcdFolderPattern { return '^\d{8}T\d{6}Z-(apply|undo)$' }
function Get-KcdWritesBegunName { return 'writes-begun.txt' }

function Get-KcdDump1KeysNames {
    # The documented first key bitmap.
    return @(
        @{ Bit = 0x01; Name = 'right SHIFT' },
        @{ Bit = 0x02; Name = 'right CTRL' },
        @{ Bit = 0x04; Name = 'right ALT' },
        @{ Bit = 0x10; Name = 'left SHIFT' },
        @{ Bit = 0x20; Name = 'left CTRL' },
        @{ Bit = 0x40; Name = 'left ALT' }
    )
}

function Test-KcdDump1Keys {
    param([int]$Value)
    if ($Value -le 0) { return $false }
    $allowed = 0
    foreach ($entry in (Get-KcdDump1KeysNames)) { $allowed = $allowed -bor $entry.Bit }
    return (($Value -band (-bnot $allowed)) -eq 0)
}

function Get-KcdSequenceText {
    param([string]$Mode, [int]$Dump1Keys)
    if ($Mode -eq 'scroll-lock') { return 'hold the right CTRL key and press SCROLL LOCK twice' }
    $names = @()
    foreach ($entry in (Get-KcdDump1KeysNames)) { if (($Dump1Keys -band $entry.Bit) -ne 0) { $names += $entry.Name } }
    $first = $names -join ' or '
    if ($names.Count -gt 1) { $first = 'one of ' + $first }
    return ('hold ' + $first + ' and press the SPACEBAR twice')
}

function Write-KcdOut {
    # Every printed line goes through here: the profile path becomes <profile>,
    # and the line is kept for the evidence folder's log.
    param([string]$Text = '')
    $safe = Protect-KcdText -Text $Text
    $KcdLog.Add($safe)
    Write-KcdLine -Text $safe
}

function Protect-KcdText {
    param([string]$Text)
    $profilePath = ''
    try { $profilePath = [string](Get-KcdProfilePath) } catch { $profilePath = '' }
    if ($profilePath.Length -gt 3) {
        $Text = [regex]::Replace($Text, [regex]::Escape($profilePath.TrimEnd('\', '/')), '<profile>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $Text
}

function ConvertTo-KcdDataText {
    # A registry value as text: REG_DWORD and REG_QWORD as unsigned decimal,
    # REG_BINARY as hex, REG_MULTI_SZ joined with |, strings as they are.
    param([string]$Kind, $Value)
    if ($null -eq $Value) { return '' }
    if ($Kind -eq 'DWord') { return [string][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$Value), 0) }
    if ($Kind -eq 'QWord') { return [string][BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$Value), 0) }
    if ($Kind -eq 'Binary') { return ((@($Value) | ForEach-Object { ([byte]$_).ToString('x2') }) -join '') }
    if ($Kind -eq 'MultiString') { return (@($Value) -join '|') }
    return [string]$Value
}

function ConvertTo-KcdInt32 {
    # A REG_DWORD's unsigned decimal text as the Int32 RegistryKey.SetValue takes.
    param([string]$Text)
    return [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Text), 0)
}

function Get-KcdKindName {
    param([string]$Kind)
    $map = @{ DWord = 'REG_DWORD'; QWord = 'REG_QWORD'; String = 'REG_SZ'; ExpandString = 'REG_EXPAND_SZ'; MultiString = 'REG_MULTI_SZ'; Binary = 'REG_BINARY'; None = 'REG_NONE' }
    if ($map.ContainsKey($Kind)) { return $map[$Kind] }
    return ('REG_' + $Kind.ToUpperInvariant())
}

function New-KcdRow {
    param([string]$Role, [string]$Path, [string]$Name, [string]$Target)
    return [pscustomobject]@{ Role = $Role; Path = $Path; Name = $Name; Target = $Target }
}

function Get-KcdRows {
    # change: what -Apply writes and -Undo restores (Target is the REG_DWORD
    # written). guard: read, must hold, never written. context: read and
    # printed, never written.
    param([string]$Mode, [int]$Dump1Keys)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($service in (Get-KcdKeyboardServices)) {
        $parameters = (Get-KcdServicesPath) + '\' + $service + '\Parameters'
        $crashdump = (Get-KcdServicesPath) + '\' + $service + '\crashdump'
        if ($Mode -eq 'scroll-lock') {
            $rows.Add((New-KcdRow -Role 'change' -Path $parameters -Name 'CrashOnCtrlScroll' -Target '1'))
            $rows.Add((New-KcdRow -Role 'guard' -Path $crashdump -Name 'Dump1Keys' -Target ''))
            $rows.Add((New-KcdRow -Role 'guard' -Path $crashdump -Name 'Dump2Key' -Target ''))
        } else {
            $rows.Add((New-KcdRow -Role 'change' -Path $crashdump -Name 'Dump1Keys' -Target ([string]$Dump1Keys)))
            $rows.Add((New-KcdRow -Role 'change' -Path $crashdump -Name 'Dump2Key' -Target ([string](Get-KcdAlternateDump2Key))))
            $rows.Add((New-KcdRow -Role 'guard' -Path $parameters -Name 'CrashOnCtrlScroll' -Target ''))
        }
    }
    foreach ($name in @('CrashDumpEnabled', 'LogEvent', 'AutoReboot', 'DumpFile')) {
        $rows.Add((New-KcdRow -Role 'context' -Path (Get-KcdCrashControlPath) -Name $name -Target ''))
    }
    return , $rows.ToArray()
}

function Read-KcdKey {
    # One key: @{ Ok; Error; Key } where Key is $null for a key that does not exist.
    param([string]$Path)
    try {
        $key = Get-KcdRegistryKey -Path $Path
        return @{ Ok = $true; Error = ''; Key = $key }
    } catch {
        return @{ Ok = $false; Error = [string]$_.Exception.Message; Key = $null }
    }
}

function Read-KcdState {
    # The live state of every row. A key or value that could not be read is
    # Read 'failed', never absent.
    param([object[]]$Rows)
    $cache = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $Rows) {
        if (-not $cache.ContainsKey($row.Path)) { $cache[$row.Path] = Read-KcdKey -Path $row.Path }
        $entry = $cache[$row.Path]
        $state = [pscustomobject]@{
            Role = $row.Role; Path = $row.Path; Name = $row.Name; Target = $row.Target
            Read = 'ok'; Error = ''; KeyExisted = $false; ValueExisted = $false; Kind = ''; Data = ''
        }
        if (-not $entry.Ok) {
            $state.Read = 'failed'
            $state.Error = $entry.Error
        } elseif ($null -ne $entry.Key) {
            $state.KeyExisted = $true
            if ($entry.Key.Values.ContainsKey($row.Name)) {
                $value = $entry.Key.Values[$row.Name]
                $state.ValueExisted = $true
                $state.Kind = [string]$value.Kind
                $state.Data = [string]$value.Data
            }
        }
        $out.Add($state)
    }
    return , $out.ToArray()
}

function Get-KcdDwordText {
    # A REG_DWORD as the operator page writes it: decimal, with hex from 10 up.
    param([string]$Data)
    $number = [uint32]0
    if ([uint32]::TryParse($Data, [ref]$number) -and $number -ge 10) { return ($Data + ' (0x' + $number.ToString('x2') + ')') }
    return $Data
}

function Format-KcdValue {
    param($State)
    if ($State.Read -ne 'ok') { return ('unreadable (' + $State.Error + ')') }
    if (-not $State.KeyExisted) { return 'absent (the key does not exist)' }
    if (-not $State.ValueExisted) { return 'absent' }
    if ($State.Kind -eq 'DWord') { return ('REG_DWORD ' + (Get-KcdDwordText -Data $State.Data)) }
    return ((Get-KcdKindName -Kind $State.Kind) + ' ' + $State.Data)
}

function Get-KcdHivePath {
    param([string]$Path)
    return ('HKLM\' + $Path)
}

function Test-KcdIsDword {
    param($State, [string]$Data)
    return ($State.Read -eq 'ok' -and $State.ValueExisted -and $State.Kind -eq 'DWord' -and $State.Data -eq $Data)
}

function Test-KcdAbsentOrZero {
    param($State)
    if ($State.Read -ne 'ok') { return $false }
    if (-not $State.ValueExisted) { return $true }
    return (Test-KcdIsDword -State $State -Data '0')
}

function New-KcdCheck {
    param([bool]$Ok, [string]$Text)
    return [pscustomobject]@{ Ok = $Ok; Text = $Text }
}

function Get-KcdFacts {
    # Elevation, process bitness and the two service keys, each as a value or
    # an error text; an error is never read as a pass.
    $facts = @{ Elevated = $null; ElevatedError = ''; Bitness = $null; BitnessError = ''; Services = @{} }
    try { $facts.Elevated = [bool](Test-KcdElevated) } catch { $facts.ElevatedError = [string]$_.Exception.Message }
    try { $facts.Bitness = [bool](Test-KcdProcessBitness) } catch { $facts.BitnessError = [string]$_.Exception.Message }
    foreach ($service in (Get-KcdKeyboardServices)) {
        $facts.Services[$service] = Read-KcdKey -Path ((Get-KcdServicesPath) + '\' + $service)
    }
    return $facts
}

function Get-KcdAccountChecks {
    param([hashtable]$Facts)
    $checks = New-Object System.Collections.Generic.List[object]
    if ($Facts.Elevated -eq $true) {
        $checks.Add((New-KcdCheck -Ok $true -Text 'running elevated (Run as administrator)'))
    } elseif ($Facts.Elevated -eq $false) {
        $checks.Add((New-KcdCheck -Ok $false -Text 'not elevated: open Windows PowerShell with Run as administrator (HKLM writes need it)'))
    } else {
        $checks.Add((New-KcdCheck -Ok $false -Text ('elevation could not be read: ' + $Facts.ElevatedError)))
    }
    if ($Facts.Bitness -eq $true) {
        $checks.Add((New-KcdCheck -Ok $true -Text 'a 64-bit PowerShell on 64-bit Windows, or 32-bit on 32-bit'))
    } elseif ($Facts.Bitness -eq $false) {
        $checks.Add((New-KcdCheck -Ok $false -Text 'a 32-bit PowerShell on 64-bit Windows: use the 64-bit Windows PowerShell'))
    } else {
        $checks.Add((New-KcdCheck -Ok $false -Text ('process bitness could not be read: ' + $Facts.BitnessError)))
    }
    return , $checks.ToArray()
}

function Get-KcdPreconditions {
    # Every precondition of -Apply, in the order printed.
    param([string]$Mode, [int]$Dump1Keys, [object[]]$State, [hashtable]$Facts)
    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($check in (Get-KcdAccountChecks -Facts $Facts)) { $checks.Add($check) }
    foreach ($service in (Get-KcdKeyboardServices)) {
        $entry = $Facts.Services[$service]
        $label = Get-KcdHivePath -Path ((Get-KcdServicesPath) + '\' + $service)
        if (-not $entry.Ok) {
            $checks.Add((New-KcdCheck -Ok $false -Text ($label + ' could not be read: ' + $entry.Error)))
        } elseif ($null -eq $entry.Key) {
            $checks.Add((New-KcdCheck -Ok $false -Text ($label + ' does not exist; this script never creates a service key')))
        } else {
            $checks.Add((New-KcdCheck -Ok $true -Text ($label + ' exists')))
        }
    }
    $unreadable = @($State | Where-Object { $_.Read -ne 'ok' })
    if ($unreadable.Count -gt 0) {
        foreach ($s in $unreadable) { $checks.Add((New-KcdCheck -Ok $false -Text ((Get-KcdHivePath -Path $s.Path) + '\' + $s.Name + ' could not be read: ' + $s.Error))) }
    } else {
        $checks.Add((New-KcdCheck -Ok $true -Text 'every value below was read'))
    }
    foreach ($s in @($State | Where-Object { $_.Read -eq 'ok' })) {
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        if ($s.Role -eq 'change') {
            if ($Mode -eq 'scroll-lock') {
                if (Test-KcdIsDword -State $s -Data $s.Target) {
                    $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is already REG_DWORD ' + $s.Target + ': the change looks applied; run -Readback, or -Undo first')))
                } elseif (Test-KcdAbsentOrZero -State $s) {
                    $checks.Add((New-KcdCheck -Ok $true -Text ($where + ' is absent or REG_DWORD 0, as expected before the change')))
                } else {
                    $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is ' + (Format-KcdValue -State $s) + ', not absent or REG_DWORD 0: unexpected, nothing is changed')))
                }
            } else {
                if (-not $s.ValueExisted) {
                    $checks.Add((New-KcdCheck -Ok $true -Text ($where + ' is absent, as expected before the change')))
                } else {
                    $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is ' + (Format-KcdValue -State $s) + ', not absent: an alternate sequence is already set; run -Readback -AlternateKeys, or -Undo first')))
                }
            }
        } elseif ($s.Role -eq 'guard') {
            if ($Mode -eq 'scroll-lock') {
                if ($s.ValueExisted) {
                    $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is set (' + (Format-KcdValue -State $s) + '): an alternate sequence is configured; Microsoft documents it only with CrashOnCtrlScroll 0 or absent, so undo it first')))
                } else {
                    $checks.Add((New-KcdCheck -Ok $true -Text ($where + ' is absent (no alternate sequence)')))
                }
            } else {
                if (Test-KcdAbsentOrZero -State $s) {
                    $checks.Add((New-KcdCheck -Ok $true -Text ($where + ' is absent or REG_DWORD 0, as Microsoft requires for the alternate keys')))
                } else {
                    $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is ' + (Format-KcdValue -State $s) + '; Microsoft requires it to be 0 or removed for the alternate keys: undo the CrashOnCtrlScroll change first')))
                }
            }
        }
    }
    $dump = @($State | Where-Object { $_.Role -eq 'context' -and $_.Name -eq 'CrashDumpEnabled' })
    if ($dump.Count -eq 1 -and $dump[0].Read -eq 'ok') {
        if ($dump[0].ValueExisted -and $dump[0].Kind -eq 'DWord' -and $dump[0].Data -ne '0') {
            $checks.Add((New-KcdCheck -Ok $true -Text ('crash dumps are enabled (CrashDumpEnabled REG_DWORD ' + $dump[0].Data + ')')))
        } else {
            $checks.Add((New-KcdCheck -Ok $false -Text ('crash dumps are not shown enabled (CrashDumpEnabled ' + (Format-KcdValue -State $dump[0]) + '); Microsoft: a dump is written only when dump files are enabled')))
        }
    }
    if ($Mode -eq 'alternate') {
        $checks.Add((New-KcdCheck -Ok $true -Text ('-Dump1Keys 0x' + $Dump1Keys.ToString('x2') + ' is a combination of Microsoft''s documented first keys')))
    }
    return , $checks.ToArray()
}

function Show-KcdState {
    param([object[]]$State, [switch]$WithTarget)
    foreach ($s in @($State | Where-Object { $_.Role -eq 'change' })) {
        $line = '  ' + (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name + '  now: ' + (Format-KcdValue -State $s)
        if ($WithTarget) {
            $line += '  after -Apply: REG_DWORD ' + (Get-KcdDwordText -Data $s.Target)
            if ($s.Read -eq 'ok' -and -not $s.KeyExisted) { $line += ' (-Apply creates the key)' }
        }
        Write-KcdOut -Text $line
    }
    Write-KcdOut -Text 'Read and never changed:'
    foreach ($s in @($State | Where-Object { $_.Role -ne 'change' })) {
        Write-KcdOut -Text ('  ' + (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name + '  ' + (Format-KcdValue -State $s))
    }
}

function Show-KcdChecks {
    param([object[]]$Checks)
    foreach ($check in $Checks) {
        $mark = 'FAIL'
        if ($check.Ok) { $mark = 'OK  ' }
        Write-KcdOut -Text ('  ' + $mark + ' ' + $check.Text)
    }
}

function Show-KcdRestartNote {
    Write-KcdOut -Text 'Restart: Microsoft documents that this setting takes effect only after a restart. This script never restarts the PC; make your normal restart before relying on it.'
}

function Show-KcdWarning {
    param([string]$Mode, [int]$Dump1Keys)
    Write-KcdOut -Text ('WARNING: once in effect, this sequence stops Windows at once with bug check 0xE2 MANUALLY_INITIATED_CRASH, frozen or not: ' + (Get-KcdSequenceText -Mode $Mode -Dump1Keys $Dump1Keys) + '. Pressed when nothing is frozen, it crashes the PC on purpose and unsaved work is lost.')
}

function Get-KcdModeText {
    param([string]$Mode, [int]$Dump1Keys)
    if ($Mode -eq 'scroll-lock') { return 'CrashOnCtrlScroll (right CTRL + SCROLL LOCK twice), Microsoft''s documented sequence' }
    return ('alternate keys (Dump1Keys 0x' + $Dump1Keys.ToString('x2') + ', Dump2Key 0x3d): ' + (Get-KcdSequenceText -Mode $Mode -Dump1Keys $Dump1Keys))
}

function Get-KcdStamp {
    param([datetime]$Utc)
    return $Utc.ToString('yyyyMMdd''T''HHmmss''Z''', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-KcdIsoText {
    param($Utc)
    if ($null -eq $Utc) { return 'unknown' }
    return ([datetime]$Utc).ToString('yyyy-MM-dd''T''HH:mm:ss''Z''', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-KcdStamp {
    param([string]$Name)
    $stamp = $Name.Substring(0, 16)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::ParseExact($stamp, 'yyyyMMdd''T''HHmmss''Z''', [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function ConvertTo-KcdCsvField {
    # Line breaks become spaces so that every row is one line.
    param([string]$Value)
    return ('"' + (($Value -replace '[\r\n]', ' ') -replace '"', '""') + '"')
}

function Get-KcdCsvText {
    param([string]$Mode, [object[]]$State)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('"Role","Mode","Key","Name","KeyExisted","ValueExisted","Kind","Data","Target","Read"')
    foreach ($s in $State) {
        $fields = @($s.Role, $Mode, (Get-KcdHivePath -Path $s.Path), $s.Name, [string]$s.KeyExisted, [string]$s.ValueExisted, $s.Kind, $s.Data, $s.Target, $s.Read)
        $lines.Add((($fields | ForEach-Object { ConvertTo-KcdCsvField -Value (Protect-KcdText -Text ([string]$_)) }) -join ','))
    }
    return (($lines.ToArray() -join "`r`n") + "`r`n")
}

function Write-KcdTextFile {
    # ASCII content, written as UTF-8 without a byte order mark.
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-KcdSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-KcdExportTarget {
    # The key a reg export saves for a change row: the key itself when it
    # exists, otherwise its parent (the service key), which records that the
    # key was absent.
    param($State)
    if ($State.KeyExisted) { return $State.Path }
    return $State.Path.Substring(0, $State.Path.LastIndexOf('\'))
}

function Save-KcdEvidence {
    # Creates the folder, writes the values CSV, exports every affected key
    # with reg export, and writes SHA256SUMS.txt. Any failure is returned as a
    # reason; the caller then changes nothing.
    param([string]$Folder, [string]$CsvName, [string]$Mode, [object[]]$State)
    $result = @{ Ok = $false; Reason = ''; Files = @() }
    try {
        if (Test-Path -LiteralPath $Folder) { $result.Reason = 'the evidence folder already exists: ' + $Folder; return $result }
        $null = [System.IO.Directory]::CreateDirectory($Folder)
        $csvPath = Join-Path -Path $Folder -ChildPath $CsvName
        Write-KcdTextFile -Path $csvPath -Text (Get-KcdCsvText -Mode $Mode -State $State)
        $files = New-Object System.Collections.Generic.List[string]
        $files.Add($CsvName)
        $exported = @{}
        foreach ($s in @($State | Where-Object { $_.Role -eq 'change' })) {
            $target = Get-KcdExportTarget -State $s
            if ($exported.ContainsKey($target)) { continue }
            $exported[$target] = $true
            $fileName = ($target.Substring((Get-KcdServicesPath).Length + 1) -replace '\\', '-') + '.reg'
            $filePath = Join-Path -Path $Folder -ChildPath $fileName
            $code = Invoke-KcdRegExport -Key (Get-KcdHivePath -Path $target) -File $filePath
            if ($code -ne 0) { $result.Reason = 'reg export of ' + (Get-KcdHivePath -Path $target) + ' failed with exit code ' + [string]$code; return $result }
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf) -or (Get-Item -LiteralPath $filePath).Length -eq 0) {
                $result.Reason = 'reg export of ' + (Get-KcdHivePath -Path $target) + ' reported success but wrote no file'
                return $result
            }
            $files.Add($fileName)
        }
        $sums = New-Object System.Collections.Generic.List[string]
        foreach ($name in $files) { $sums.Add((Get-KcdSha256 -Path (Join-Path -Path $Folder -ChildPath $name)) + '  ' + $name) }
        Write-KcdTextFile -Path (Join-Path -Path $Folder -ChildPath 'SHA256SUMS.txt') -Text (($sums.ToArray() -join "`r`n") + "`r`n")
        $result.Files = $sums.ToArray()
        $result.Ok = $true
        return $result
    } catch {
        $result.Reason = 'saving the evidence failed: ' + [string]$_.Exception.Message
        return $result
    }
}

function Test-KcdSameState {
    # True when the change and guard rows read the same as in $Before.
    param([object[]]$Before, [object[]]$After)
    for ($i = 0; $i -lt $Before.Count; $i++) {
        $b = $Before[$i]; $a = $After[$i]
        if ($b.Role -eq 'context') { continue }
        if ($a.Read -ne 'ok' -or $b.Read -ne 'ok') { return $false }
        if ($a.KeyExisted -ne $b.KeyExisted -or $a.ValueExisted -ne $b.ValueExisted -or $a.Kind -ne $b.Kind -or $a.Data -ne $b.Data) { return $false }
    }
    return $true
}

function Show-KcdTargetReadback {
    # PASS or FAIL per value against what -Apply sets. Returns the FAIL count.
    param([string]$Mode, [object[]]$State)
    $fails = 0
    foreach ($s in @($State | Where-Object { $_.Role -eq 'change' })) {
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        if (Test-KcdIsDword -State $s -Data $s.Target) {
            Write-KcdOut -Text ('PASS ' + $where + ' = REG_DWORD ' + (Get-KcdDwordText -Data $s.Target))
        } else {
            $fails++
            Write-KcdOut -Text ('FAIL ' + $where + ' is ' + (Format-KcdValue -State $s) + ', expected REG_DWORD ' + (Get-KcdDwordText -Data $s.Target))
        }
    }
    foreach ($s in @($State | Where-Object { $_.Role -eq 'guard' })) {
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        $ok = $false
        $expected = 'absent'
        if ($Mode -eq 'scroll-lock') { $ok = ($s.Read -eq 'ok' -and -not $s.ValueExisted) } else { $ok = Test-KcdAbsentOrZero -State $s; $expected = 'absent or REG_DWORD 0' }
        if ($ok) {
            Write-KcdOut -Text ('PASS ' + $where + ' is ' + (Format-KcdValue -State $s))
        } else {
            $fails++
            Write-KcdOut -Text ('FAIL ' + $where + ' is ' + (Format-KcdValue -State $s) + ', expected ' + $expected)
        }
    }
    return $fails
}

function Get-KcdDefaultRoot {
    return (Join-Path -Path ([string](Get-KcdDesktopPath)) -ChildPath 'wf-changes\kbd-crash-dump')
}

function Get-KcdEvidenceFolders {
    # The apply folders under the root, oldest first (the names sort by time).
    param([string]$Root, [string]$Kind = 'apply')
    if (-not $Root -or -not (Test-Path -LiteralPath $Root -PathType Container)) { return , @() }
    $names = @(Get-ChildItem -LiteralPath $Root -Directory | Where-Object { $_.Name -match (Get-KcdFolderPattern) -and $_.Name.EndsWith('-' + $Kind) } | ForEach-Object { $_.Name } | Sort-Object)
    return , $names
}

function Set-KcdWritesBegun {
    # Marks an evidence folder as one whose run went on to write, so a refused
    # run's folder is never taken for a change. Returns a reason on failure.
    param([string]$Folder)
    try {
        Write-KcdTextFile -Path (Join-Path -Path $Folder -ChildPath (Get-KcdWritesBegunName)) -Text "writes began after this folder was saved`r`n"
        return ''
    } catch {
        return ('marking ' + $Folder + ' before the writes failed: ' + [string]$_.Exception.Message)
    }
}

function Show-KcdRestartStatus {
    # Compares the last boot with the newest apply or undo folder under the
    # root whose run reached its writes.
    param([string]$Root)
    Show-KcdRestartNote
    $folders = @()
    foreach ($kind in @('apply', 'undo')) {
        foreach ($name in (Get-KcdEvidenceFolders -Root $Root -Kind $kind)) {
            if (Test-Path -LiteralPath (Join-Path -Path (Join-Path -Path $Root -ChildPath $name) -ChildPath (Get-KcdWritesBegunName)) -PathType Leaf) { $folders += $name }
        }
    }
    if ($folders.Count -eq 0) {
        Write-KcdOut -Text ('No apply or undo folder that reached its writes under ' + $Root + ', so whether a restart followed a change is not known here.')
        return
    }
    $newest = @($folders | Sort-Object)[-1]
    $kindText = $newest.Substring(17)
    $changedAt = ConvertFrom-KcdStamp -Name $newest
    $boot = $null
    $bootError = ''
    try { $boot = Get-KcdLastBootUtc } catch { $bootError = [string]$_.Exception.Message }
    if ($null -eq $boot) {
        Write-KcdOut -Text ('Newest ' + $kindText + ' at ' + (Get-KcdIsoText -Utc $changedAt) + '; the last boot time could not be read (' + $bootError + '), so whether a restart followed is unknown.')
    } elseif (([datetime]$boot) -gt $changedAt) {
        Write-KcdOut -Text ('Restart done: the PC booted at ' + (Get-KcdIsoText -Utc $boot) + ', after the newest ' + $kindText + ' at ' + (Get-KcdIsoText -Utc $changedAt) + '.')
    } else {
        Write-KcdOut -Text ('RESTART PENDING: the PC last booted at ' + (Get-KcdIsoText -Utc $boot) + ', before the newest ' + $kindText + ' at ' + (Get-KcdIsoText -Utc $changedAt) + '. The values read above take effect at the next restart.')
    }
}

function Write-KcdLogFile {
    param([string]$Folder)
    try {
        if ($Folder -and (Test-Path -LiteralPath $Folder -PathType Container)) {
            Write-KcdTextFile -Path (Join-Path -Path $Folder -ChildPath 'log.txt') -Text (($KcdLog.ToArray() -join "`r`n") + "`r`n")
        }
    } catch {
        Write-KcdLine -Text ('note: the log could not be written to the evidence folder: ' + [string]$_.Exception.Message)
    }
}

function Invoke-KcdPlan {
    param([string]$Mode, [int]$Dump1Keys, [string]$Root)
    Write-KcdOut -Text 'kbd-crash-dump -Plan: read only, nothing is changed.'
    Write-KcdOut -Text ('Mode: ' + (Get-KcdModeText -Mode $Mode -Dump1Keys $Dump1Keys))
    Write-KcdOut -Text ('Source: ' + (Get-KcdLearnUrl))
    $rows = Get-KcdRows -Mode $Mode -Dump1Keys $Dump1Keys
    $state = Read-KcdState -Rows $rows
    $facts = Get-KcdFacts
    Write-KcdOut -Text 'What -Apply would change (REG_DWORD values only; nothing else):'
    Show-KcdState -State $state -WithTarget
    Write-KcdOut -Text 'Preconditions for -Apply:'
    $checks = Get-KcdPreconditions -Mode $Mode -Dump1Keys $Dump1Keys -State $state -Facts $facts
    Show-KcdChecks -Checks $checks
    Write-KcdOut -Text ('-Apply saves the before-state first, to a new folder under ' + $Root)
    Show-KcdRestartNote
    Show-KcdWarning -Mode $Mode -Dump1Keys $Dump1Keys
    $failed = @($checks | Where-Object { -not $_.Ok })
    if ($failed.Count -gt 0) {
        Write-KcdOut -Text ('REFUSED: ' + $failed.Count + ' precondition(s) failed; -Apply would change nothing.')
        return 1
    }
    Write-KcdOut -Text 'READY: every precondition holds. -Apply is a separate, explicit step.'
    return 0
}

function Invoke-KcdApply {
    param([string]$Mode, [int]$Dump1Keys, [string]$Root)
    Write-KcdOut -Text 'kbd-crash-dump -Apply'
    Write-KcdOut -Text ('Mode: ' + (Get-KcdModeText -Mode $Mode -Dump1Keys $Dump1Keys))
    $rows = Get-KcdRows -Mode $Mode -Dump1Keys $Dump1Keys
    $state = Read-KcdState -Rows $rows
    $facts = Get-KcdFacts
    Write-KcdOut -Text 'Before:'
    Show-KcdState -State $state -WithTarget
    Write-KcdOut -Text 'Preconditions:'
    $checks = Get-KcdPreconditions -Mode $Mode -Dump1Keys $Dump1Keys -State $state -Facts $facts
    Show-KcdChecks -Checks $checks
    $failed = @($checks | Where-Object { -not $_.Ok })
    if ($failed.Count -gt 0) {
        Write-KcdOut -Text ('REFUSED: ' + $failed.Count + ' precondition(s) failed. Nothing changed and nothing was saved.')
        return 1
    }

    $folder = Join-Path -Path $Root -ChildPath ((Get-KcdStamp -Utc (Get-KcdUtcNow)) + '-apply')
    $saved = Save-KcdEvidence -Folder $folder -CsvName 'before-values.csv' -Mode $Mode -State $state
    if (-not $saved.Ok) {
        Write-KcdOut -Text ('REFUSED: ' + $saved.Reason + '. Nothing changed.')
        Write-KcdLogFile -Folder $folder
        return 1
    }
    Write-KcdOut -Text ('Saved: ' + $folder)
    foreach ($line in $saved.Files) { Write-KcdOut -Text ('  SHA-256 ' + $line) }

    $again = Read-KcdState -Rows $rows
    if (-not (Test-KcdSameState -Before $state -After $again)) {
        Write-KcdOut -Text 'REFUSED: the values changed while they were being saved. Nothing changed; run -Plan again.'
        Write-KcdLogFile -Folder $folder
        return 1
    }
    $markError = Set-KcdWritesBegun -Folder $folder
    if ($markError) {
        Write-KcdOut -Text ('REFUSED: ' + $markError + '. Nothing changed.')
        Write-KcdLogFile -Folder $folder
        return 1
    }

    $writeError = ''
    foreach ($s in @($state | Where-Object { $_.Role -eq 'change' })) {
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        try {
            Set-KcdRegistryDword -Path $s.Path -Name $s.Name -Value (ConvertTo-KcdInt32 -Text $s.Target)
            Write-KcdOut -Text ('wrote ' + $where + ' = REG_DWORD ' + (Get-KcdDwordText -Data $s.Target))
        } catch {
            $writeError = $where + ': ' + [string]$_.Exception.Message
            Write-KcdOut -Text ('WRITE FAILED ' + $writeError + '; no further value is written.')
            break
        }
    }

    Write-KcdOut -Text 'Readback:'
    $after = Read-KcdState -Rows $rows
    $fails = Show-KcdTargetReadback -Mode $Mode -State $after
    Write-KcdOut -Text 'RESTART PENDING: Microsoft documents that this setting takes effect only after a restart. This script never restarts the PC.'
    Show-KcdWarning -Mode $Mode -Dump1Keys $Dump1Keys
    $code = 0
    if ($writeError -or $fails -gt 0) {
        Write-KcdOut -Text ('RESULT: FAIL. The machine may be partly changed. -Undo restores the before-state saved in ' + $folder + '.')
        $code = 2
    } else {
        Write-KcdOut -Text 'RESULT: PASS. Undo with -Undo, which restores the saved before-state.'
    }
    Write-KcdLogFile -Folder $folder
    return $code
}

function Read-KcdSums {
    param([string]$Folder)
    $map = @{}
    $path = Join-Path -Path $Folder -ChildPath 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $map }
    foreach ($line in @(Get-Content -LiteralPath $path)) {
        if ($line -match '^([0-9a-f]{64})  (\S+)$') { $map[$Matches[2]] = $Matches[1] }
    }
    return $map
}

function Get-KcdSavedChange {
    # Reads and validates the change rows of an apply folder's CSV. Returns
    # @{ Ok; Reason; Mode; Dump1Keys; Rows } where Rows are state objects in
    # the order of Get-KcdRows.
    param([string]$Folder)
    $result = @{ Ok = $false; Reason = ''; Mode = ''; Dump1Keys = 0; Rows = @() }
    $csvPath = Join-Path -Path $Folder -ChildPath 'before-values.csv'
    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) { $result.Reason = 'no before-values.csv in ' + $Folder; return $result }
    $sums = Read-KcdSums -Folder $Folder
    if (-not $sums.ContainsKey('before-values.csv')) { $result.Reason = 'SHA256SUMS.txt in ' + $Folder + ' does not list before-values.csv'; return $result }
    $actual = Get-KcdSha256 -Path $csvPath
    if ($actual -ne $sums['before-values.csv']) { $result.Reason = 'before-values.csv does not match its saved SHA-256 (saved ' + $sums['before-values.csv'] + ', now ' + $actual + ')'; return $result }
    $records = @(Get-Content -LiteralPath $csvPath | ConvertFrom-Csv)
    $changes = @($records | Where-Object { $_.Role -eq 'change' })
    if ($changes.Count -eq 0) { $result.Reason = 'the saved CSV holds no change row'; return $result }
    $modes = @($changes | ForEach-Object { $_.Mode } | Sort-Object -Unique)
    if ($modes.Count -ne 1 -or ($modes[0] -ne 'scroll-lock' -and $modes[0] -ne 'alternate')) { $result.Reason = 'the saved CSV names an unknown mode'; return $result }
    $mode = $modes[0]
    $dump1 = 2
    if ($mode -eq 'alternate') {
        $first = @($changes | Where-Object { $_.Name -eq 'Dump1Keys' } | Select-Object -First 1)
        $parsed = 0
        if ($first.Count -ne 1 -or -not [int]::TryParse([string]$first[0].Target, [ref]$parsed) -or -not (Test-KcdDump1Keys -Value $parsed)) { $result.Reason = 'the saved Dump1Keys target is not in Microsoft''s table'; return $result }
        $dump1 = $parsed
    }
    $documented = @((Get-KcdRows -Mode $mode -Dump1Keys $dump1) | Where-Object { $_.Role -eq 'change' })
    if ($documented.Count -ne $changes.Count) { $result.Reason = 'the saved CSV does not hold exactly the documented change rows'; return $result }
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $documented.Count; $i++) {
        $d = $documented[$i]
        $match = @($changes | Where-Object { $_.Key -eq (Get-KcdHivePath -Path $d.Path) -and $_.Name -eq $d.Name })
        if ($match.Count -ne 1) { $result.Reason = 'the saved CSV has no single row for ' + (Get-KcdHivePath -Path $d.Path) + '\' + $d.Name; return $result }
        $m = $match[0]
        if ($m.Target -ne $d.Target -or $m.Read -ne 'ok' -or @('True', 'False') -notcontains $m.KeyExisted -or @('True', 'False') -notcontains $m.ValueExisted) {
            $result.Reason = 'the saved row for ' + $m.Key + '\' + $m.Name + ' is not one this script wrote'
            return $result
        }
        $valueExisted = ($m.ValueExisted -eq 'True')
        $parsedData = [uint32]0
        if ($valueExisted -and ($m.Kind -ne 'DWord' -or -not [uint32]::TryParse([string]$m.Data, [ref]$parsedData))) {
            $result.Reason = 'the saved value ' + $m.Key + '\' + $m.Name + ' is not a REG_DWORD; this script restores only REG_DWORD values'
            return $result
        }
        $rows.Add([pscustomobject]@{
            Role = 'change'; Path = $d.Path; Name = $d.Name; Target = $d.Target; Read = 'ok'; Error = ''
            KeyExisted = ($m.KeyExisted -eq 'True'); ValueExisted = $valueExisted; Kind = [string]$m.Kind; Data = [string]$m.Data
        })
    }
    $result.Ok = $true
    $result.Mode = $mode
    $result.Dump1Keys = $dump1
    $result.Rows = $rows.ToArray()
    return $result
}

function Test-KcdEqualsSaved {
    param($Live, $Saved)
    if ($Live.Read -ne 'ok') { return $false }
    if (-not $Saved.ValueExisted) { return (-not $Live.ValueExisted) }
    return ($Live.ValueExisted -and $Live.Kind -eq $Saved.Kind -and $Live.Data -eq $Saved.Data)
}

function Invoke-KcdUndo {
    param([string]$Root, [string]$Folder)
    Write-KcdOut -Text 'kbd-crash-dump -Undo'
    if (-not $Folder) {
        $applies = Get-KcdEvidenceFolders -Root $Root -Kind 'apply'
        if ($applies.Count -eq 0) {
            Write-KcdOut -Text ('REFUSED: no apply folder under ' + $Root + '. Nothing changed.')
            return 1
        }
        $Folder = Join-Path -Path $Root -ChildPath $applies[$applies.Count - 1]
    }
    Write-KcdOut -Text ('Restoring from: ' + $Folder)
    $saved = Get-KcdSavedChange -Folder $Folder
    if (-not $saved.Ok) {
        Write-KcdOut -Text ('REFUSED: ' + $saved.Reason + '. Nothing changed.')
        return 1
    }
    Write-KcdOut -Text ('Mode of that apply: ' + (Get-KcdModeText -Mode $saved.Mode -Dump1Keys $saved.Dump1Keys))
    $rows = @((Get-KcdRows -Mode $saved.Mode -Dump1Keys $saved.Dump1Keys) | Where-Object { $_.Role -eq 'change' })
    $live = Read-KcdState -Rows $rows
    $facts = Get-KcdFacts
    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($check in (Get-KcdAccountChecks -Facts $facts)) { $checks.Add($check) }
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $l = $live[$i]; $s = $saved.Rows[$i]
        $where = (Get-KcdHivePath -Path $l.Path) + '\' + $l.Name
        $savedText = 'absent'
        if ($s.ValueExisted) { $savedText = (Get-KcdKindName -Kind $s.Kind) + ' ' + $s.Data }
        if ($l.Read -ne 'ok') {
            $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' could not be read: ' + $l.Error)))
        } elseif ((Test-KcdEqualsSaved -Live $l -Saved $s) -or (Test-KcdIsDword -State $l -Data $l.Target)) {
            $checks.Add((New-KcdCheck -Ok $true -Text ($where + ' now ' + (Format-KcdValue -State $l) + ', saved ' + $savedText)))
        } else {
            $checks.Add((New-KcdCheck -Ok $false -Text ($where + ' is ' + (Format-KcdValue -State $l) + ': neither the saved ' + $savedText + ' nor the applied REG_DWORD ' + $l.Target + '; something else changed it, so nothing is restored')))
        }
    }
    Write-KcdOut -Text 'Preconditions:'
    Show-KcdChecks -Checks $checks.ToArray()
    $failed = @($checks.ToArray() | Where-Object { -not $_.Ok })
    if ($failed.Count -gt 0) {
        Write-KcdOut -Text ('REFUSED: ' + $failed.Count + ' precondition(s) failed. Nothing changed.')
        return 1
    }

    $undoFolder = Join-Path -Path $Root -ChildPath ((Get-KcdStamp -Utc (Get-KcdUtcNow)) + '-undo')
    $savedNow = Save-KcdEvidence -Folder $undoFolder -CsvName 'before-undo-values.csv' -Mode $saved.Mode -State $live
    if (-not $savedNow.Ok) {
        Write-KcdOut -Text ('REFUSED: ' + $savedNow.Reason + '. Nothing changed.')
        Write-KcdLogFile -Folder $undoFolder
        return 1
    }
    Write-KcdOut -Text ('Saved the state before the undo: ' + $undoFolder)
    foreach ($line in $savedNow.Files) { Write-KcdOut -Text ('  SHA-256 ' + $line) }
    $markError = Set-KcdWritesBegun -Folder $undoFolder
    if ($markError) {
        Write-KcdOut -Text ('REFUSED: ' + $markError + '. Nothing changed.')
        Write-KcdLogFile -Folder $undoFolder
        return 1
    }

    $writeError = ''
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $s = $saved.Rows[$i]
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        if (Test-KcdEqualsSaved -Live $live[$i] -Saved $s) {
            Write-KcdOut -Text ('unchanged ' + $where + ' (already as saved)')
            continue
        }
        try {
            if ($s.ValueExisted) {
                Set-KcdRegistryDword -Path $s.Path -Name $s.Name -Value (ConvertTo-KcdInt32 -Text $s.Data)
                Write-KcdOut -Text ('restored ' + $where + ' = REG_DWORD ' + $s.Data)
            } else {
                Remove-KcdRegistryValue -Path $s.Path -Name $s.Name
                Write-KcdOut -Text ('deleted ' + $where + ' (absent before the apply)')
            }
        } catch {
            $writeError = $where + ': ' + [string]$_.Exception.Message
            Write-KcdOut -Text ('WRITE FAILED ' + $writeError + '; no further value is restored.')
            break
        }
    }
    $keyNotes = New-Object System.Collections.Generic.List[string]
    if (-not $writeError) {
        $created = @($saved.Rows | Where-Object { -not $_.KeyExisted } | ForEach-Object { $_.Path } | Sort-Object -Unique)
        foreach ($path in $created) {
            $entry = Read-KcdKey -Path $path
            if (-not $entry.Ok) {
                $keyNotes.Add('FAIL ' + (Get-KcdHivePath -Path $path) + ' could not be read to remove it: ' + $entry.Error)
            } elseif ($null -eq $entry.Key) {
                continue
            } elseif ($entry.Key.ValueCount -eq 0 -and $entry.Key.SubKeyCount -eq 0) {
                try {
                    Remove-KcdRegistryKey -Path $path
                    Write-KcdOut -Text ('deleted key ' + (Get-KcdHivePath -Path $path) + ' (absent before the apply, empty now)')
                } catch {
                    $writeError = (Get-KcdHivePath -Path $path) + ': ' + [string]$_.Exception.Message
                    $keyNotes.Add('FAIL ' + (Get-KcdHivePath -Path $path) + ' could not be removed: ' + [string]$_.Exception.Message)
                }
            } else {
                Write-KcdOut -Text ('kept key ' + (Get-KcdHivePath -Path $path) + ': absent before the apply, but it now holds values or subkeys this change did not write')
            }
        }
    }

    Write-KcdOut -Text 'Readback against the saved before-state:'
    $after = Read-KcdState -Rows $rows
    $fails = 0
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $s = $saved.Rows[$i]
        $where = (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name
        $savedText = 'absent'
        if ($s.ValueExisted) { $savedText = (Get-KcdKindName -Kind $s.Kind) + ' ' + $s.Data }
        if (Test-KcdEqualsSaved -Live $after[$i] -Saved $s) {
            Write-KcdOut -Text ('PASS ' + $where + ' is ' + (Format-KcdValue -State $after[$i]) + ', as saved')
        } else {
            $fails++
            Write-KcdOut -Text ('FAIL ' + $where + ' is ' + (Format-KcdValue -State $after[$i]) + ', saved ' + $savedText)
        }
    }
    foreach ($note in $keyNotes) { $fails++; Write-KcdOut -Text $note }
    Write-KcdOut -Text 'Restart: Microsoft documents a restart for the setting to take effect; that the restored values also take effect only after a restart is an inference. This script never restarts the PC.'
    $code = 0
    if ($writeError -or $fails -gt 0) {
        Write-KcdOut -Text 'RESULT: FAIL. Run -Undo again once the cause is fixed; the apply folder is unchanged.'
        $code = 2
    } else {
        Write-KcdOut -Text 'RESULT: PASS. The saved before-state is restored.'
    }
    Write-KcdLogFile -Folder $undoFolder
    return $code
}

function Invoke-KcdReadback {
    param([string]$Mode, [int]$Dump1Keys, [string]$Root)
    Write-KcdOut -Text 'kbd-crash-dump -Readback: read only, nothing is changed.'
    Write-KcdOut -Text ('Expected: ' + (Get-KcdModeText -Mode $Mode -Dump1Keys $Dump1Keys))
    $rows = Get-KcdRows -Mode $Mode -Dump1Keys $Dump1Keys
    $state = Read-KcdState -Rows $rows
    $fails = Show-KcdTargetReadback -Mode $Mode -State $state
    Write-KcdOut -Text 'Read and never changed:'
    foreach ($s in @($state | Where-Object { $_.Role -eq 'context' })) {
        Write-KcdOut -Text ('  ' + (Get-KcdHivePath -Path $s.Path) + '\' + $s.Name + '  ' + (Format-KcdValue -State $s))
    }
    Show-KcdRestartStatus -Root $Root
    if ($fails -gt 0) {
        Write-KcdOut -Text ('RESULT: FAIL (' + $fails + ' value(s) differ from what -Apply sets).')
        return 1
    }
    Write-KcdOut -Text 'RESULT: PASS.'
    return 0
}

function Get-KcdUsageError {
    param([hashtable]$Bound, [bool]$IsPlan, [bool]$IsApply, [bool]$IsUndo, [bool]$IsReadback, [bool]$IsAlternate, [int]$Dump1Keys)
    $verbs = @($IsPlan, $IsApply, $IsUndo, $IsReadback | Where-Object { $_ })
    if ($verbs.Count -gt 1) { return 'name exactly one of -Plan, -Apply, -Undo, -Readback' }
    if ($Bound.ContainsKey('Dump1Keys') -and -not $IsAlternate) { return '-Dump1Keys needs -AlternateKeys' }
    if ($IsAlternate -and -not (Test-KcdDump1Keys -Value $Dump1Keys)) { return ('-Dump1Keys ' + $Dump1Keys + ' is not a combination of Microsoft''s documented first keys (0x01, 0x02, 0x04, 0x10, 0x20, 0x40)') }
    if ($IsUndo -and ($IsAlternate -or $Bound.ContainsKey('Dump1Keys'))) { return '-Undo takes the mode from the saved evidence; do not pass -AlternateKeys or -Dump1Keys' }
    if ($Bound.ContainsKey('EvidenceFolder') -and -not $IsUndo) { return '-EvidenceFolder is for -Undo only' }
    return ''
}

# ---------------------------------------------------------------------------
# Windows adapters. The Pester suite defines its own versions of these first
# (changes/windows/tests/KbdCrashDump.Synthetic.ps1); when Get-KcdRegistryKey
# already exists, none of the real ones below is defined, so a test never
# reaches the real registry. Nothing above this line calls a Windows only API.
# ---------------------------------------------------------------------------

if (-not (Get-Command -Name 'Get-KcdRegistryKey' -CommandType Function -ErrorAction SilentlyContinue)) {

    function Open-KcdBaseKey {
        # HKEY_LOCAL_MACHINE in the 64-bit view.
        return [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    }

    function Get-KcdRegistryKey {
        # Opens the key read only. $null when it does not exist; throws when
        # it cannot be read.
        param([string]$Path)
        $base = Open-KcdBaseKey
        try {
            $key = $base.OpenSubKey($Path, $false)
            if ($null -eq $key) { return $null }
            try {
                $values = @{}
                foreach ($name in $key.GetValueNames()) {
                    $kind = [string]$key.GetValueKind($name)
                    $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $values[$name] = [pscustomobject]@{ Kind = $kind; Data = (ConvertTo-KcdDataText -Kind $kind -Value $raw) }
                }
                return [pscustomobject]@{ Values = $values; ValueCount = [int]$key.ValueCount; SubKeyCount = [int]$key.SubKeyCount }
            } finally {
                $key.Close()
            }
        } finally {
            $base.Close()
        }
    }

    function Open-KcdParentForWrite {
        # The parent of $Path opened for writing; it must already exist, so
        # no service key is ever created.
        param($Base, [string]$Path)
        $parentPath = $Path.Substring(0, $Path.LastIndexOf('\'))
        $parent = $Base.OpenSubKey($parentPath, $true)
        if ($null -eq $parent) { throw ('the parent key HKLM\' + $parentPath + ' does not exist') }
        return $parent
    }

    function Set-KcdRegistryDword {
        # Creates the key under its existing parent when needed, then writes
        # one REG_DWORD.
        param([string]$Path, [string]$Name, [int]$Value)
        $base = Open-KcdBaseKey
        try {
            $parent = Open-KcdParentForWrite -Base $base -Path $Path
            try {
                $key = $parent.CreateSubKey($Path.Substring($Path.LastIndexOf('\') + 1))
                if ($null -eq $key) { throw ('HKLM\' + $Path + ' could not be opened for writing') }
                try { $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $key.Close() }
            } finally {
                $parent.Close()
            }
        } finally {
            $base.Close()
        }
    }

    function Remove-KcdRegistryValue {
        param([string]$Path, [string]$Name)
        $base = Open-KcdBaseKey
        try {
            $key = $base.OpenSubKey($Path, $true)
            if ($null -eq $key) { return }
            try { $key.DeleteValue($Name, $false) } finally { $key.Close() }
        } finally {
            $base.Close()
        }
    }

    function Remove-KcdRegistryKey {
        # Deletes one key that has no subkeys (DeleteSubKey refuses one that
        # has); the caller has checked that it holds no values either.
        param([string]$Path)
        $base = Open-KcdBaseKey
        try {
            $parent = Open-KcdParentForWrite -Base $base -Path $Path
            try { $parent.DeleteSubKey($Path.Substring($Path.LastIndexOf('\') + 1), $false) } finally { $parent.Close() }
        } finally {
            $base.Close()
        }
    }

    function Invoke-KcdRegExport {
        # reg export <key> <file> /y from the system directory; returns the
        # exit code (0 success, 1 failure).
        param([string]$Key, [string]$File)
        $reg = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'reg.exe'
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $null = & $reg 'export' $Key $File '/y' 2>$null
            return [int]$LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previous
        }
    }

    function Test-KcdElevated {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return [bool]$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-KcdProcessBitness {
        return ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem)
    }

    function Get-KcdUtcNow { return [datetime]::UtcNow }

    function Get-KcdLastBootUtc {
        $os = Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop
        return ([datetime]$os.LastBootUpTime).ToUniversalTime()
    }

    function Get-KcdDesktopPath { return [Environment]::GetFolderPath('Desktop') }

    function Get-KcdProfilePath { return [Environment]::GetFolderPath('UserProfile') }

    function Write-KcdLine {
        param([string]$Text)
        [Console]::Out.WriteLine($Text)
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$KcdLog = New-Object System.Collections.Generic.List[string]
$verbName = 'Plan'
if ($Apply) { $verbName = 'Apply' } elseif ($Undo) { $verbName = 'Undo' } elseif ($Readback) { $verbName = 'Readback' }
$exitCode = 1
try {
    $usage = Get-KcdUsageError -Bound $PSBoundParameters -IsPlan $Plan.IsPresent -IsApply $Apply.IsPresent -IsUndo $Undo.IsPresent -IsReadback $Readback.IsPresent -IsAlternate $AlternateKeys.IsPresent -Dump1Keys $Dump1Keys
    if ($usage) {
        Write-KcdOut -Text ('REFUSED: ' + $usage + '. Nothing changed.')
        $exitCode = 1
    } else {
        $mode = 'scroll-lock'
        if ($AlternateKeys) { $mode = 'alternate' }
        $root = $EvidenceRoot
        if (-not $root) { $root = Get-KcdDefaultRoot }
        if ($verbName -eq 'Apply') {
            $exitCode = Invoke-KcdApply -Mode $mode -Dump1Keys $Dump1Keys -Root $root
        } elseif ($verbName -eq 'Undo') {
            $exitCode = Invoke-KcdUndo -Root $root -Folder $EvidenceFolder
        } elseif ($verbName -eq 'Readback') {
            $exitCode = Invoke-KcdReadback -Mode $mode -Dump1Keys $Dump1Keys -Root $root
        } else {
            $exitCode = Invoke-KcdPlan -Mode $mode -Dump1Keys $Dump1Keys -Root $root
        }
    }
} catch {
    $exitCode = 1
    $tail = ' Run -Readback to see the state.'
    if ($verbName -eq 'Apply' -or $verbName -eq 'Undo') { $exitCode = 2; $tail = ' If a write had started, -Readback shows the state and -Undo restores the saved before-state.' }
    Write-KcdOut -Text ('FAILED: unexpected error: ' + [string]$_.Exception.Message + '.' + $tail)
}
exit $exitCode
