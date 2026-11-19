# Synthetic Windows for gpu-affinity-1a: replaces every adapter at the bottom
# of _gpu-affinity-1a-lib.ps1 with an in memory machine held in
# $global:Wf1aSynthetic. Dot source it after the library. Nothing here reads
# or writes a real registry; the tests prove the portable logic only.
#
# The machine is invented: vendor 1234, device 5678, no real instance path.

function New-Wf1aSyntheticMachine {
    $instance = 'PCI\VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1\4&1A2B3C4D&0&0008'
    $enum = 'SYSTEM\CurrentControlSet\Enum\' + $instance
    $global:Wf1aSynthetic = @{
        InstanceId     = $instance
        Elevated       = $true
        Adapters       = @($instance)
        Registry       = @{}
        Denied         = @()
        Processes      = @('System', 'explorer', 'svchost', 'ProcessGovernor')
        Tasks          = @(
            [pscustomobject]@{ TaskPath = '\Stutter Guard\'; TaskName = 'Device power saving off'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Stutter Guard\StutterGuard.exe'; Arguments = '--agent device-power' }) },
            [pscustomobject]@{ TaskPath = '\Stutter Guard\'; TaskName = 'Timer resolution'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Stutter Guard\DpcTimerRes.exe'; Arguments = '5000' }) },
            [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Defrag\'; TaskName = 'ScheduledDefrag'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = '%windir%\system32\defrag.exe'; Arguments = '-c -h -o' }) }
        )
        TasksThrow     = $false
        Services       = @(
            [pscustomobject]@{ Name = 'ProcessGovernor'; PathName = '"C:\Program Files\Process Lasso\ProcessGovernor.exe" /service'; State = 'Running' },
            [pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; State = 'Running' }
        )
        ExportFails    = @()
        ExportEmpty    = @()
        Exports        = New-Object System.Collections.Generic.List[string]
        AfterExport    = $null
        WriteFailsOn   = @()
        WriteLies      = @()
        Writes         = New-Object System.Collections.Generic.List[string]
        Out            = New-Object System.Collections.Generic.List[string]
        NowUtc         = [datetime]::new(2026, 11, 20, 18, 0, 0, [System.DateTimeKind]::Utc)
        BootUtc        = [datetime]::new(2026, 11, 20, 9, 0, 0, [System.DateTimeKind]::Utc)
    }
    Set-Wf1aSyntheticValue -SubKey ($enum + '\Device Parameters\Interrupt Management\Affinity Policy') -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]4))
    Set-Wf1aSyntheticValue -SubKey ($enum + '\Device Parameters\Interrupt Management\Affinity Policy') -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0x40, 0, 0, 0, 0, 0, 0, 0)))
    Set-Wf1aSyntheticValue -SubKey ($enum + '\Device Parameters\Interrupt Management\Affinity Policy') -Name 'DevicePriority' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]3))
    Set-Wf1aSyntheticValue -SubKey ($enum + '\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties') -Name 'MSISupported' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]1))
    $bitsum = 'SOFTWARE\Bitsum\InterruptAffinityBackup'
    $gpuEntry = $bitsum + '\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008'
    Set-Wf1aSyntheticValue -SubKey $gpuEntry -Name 'KeysExisted' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]1))
    Set-Wf1aSyntheticValue -SubKey ($gpuEntry + '\MSI') -Name 'MSISupported' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]1))
    Set-Wf1aSyntheticValue -SubKey ($gpuEntry + '\MSI') -Name 'MessageNumberLimit' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]1))
    $nicEntry = $bitsum + '\PCI#VEN_4321&DEV_8765&SUBSYS_00000000&REV_02#4&5e6f7a8b&0&00e4'
    Set-Wf1aSyntheticValue -SubKey $nicEntry -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]4))
    Set-Wf1aSyntheticValue -SubKey $nicEntry -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0, 4, 0, 0, 0, 0, 0, 0)))
}

function Get-Wf1aSyntheticNode {
    param([string]$SubKey, [switch]$Create)
    $k = $SubKey.ToLowerInvariant()
    if (-not $global:Wf1aSynthetic.Registry.ContainsKey($k)) {
        if (-not $Create) { return $null }
        # Create the key and every parent, as a registry tree has them.
        $parts = $SubKey.Split('\')
        for ($i = 1; $i -le $parts.Length; $i++) {
            $path = ($parts[0..($i - 1)] -join '\')
            $pk = $path.ToLowerInvariant()
            if (-not $global:Wf1aSynthetic.Registry.ContainsKey($pk)) {
                $global:Wf1aSynthetic.Registry[$pk] = @{ Path = $path; Values = [ordered]@{} }
            }
        }
    }
    return $global:Wf1aSynthetic.Registry[$k]
}

function Set-Wf1aSyntheticValue {
    param([string]$SubKey, [string]$Name, $Value)
    $node = Get-Wf1aSyntheticNode -SubKey $SubKey -Create
    $existing = $null
    foreach ($entry in $node.Values.GetEnumerator()) { if ($entry.Key -ieq $Name) { $existing = $entry.Key } }
    if ($null -ne $existing) { $node.Values.Remove($existing) }
    if ($Value.Exists) { $node.Values[$Name] = $Value }
}

function Get-Wf1aSyntheticValue {
    param([string]$SubKey, [string]$Name)
    $node = Get-Wf1aSyntheticNode -SubKey $SubKey
    if ($null -eq $node) { return (New-WfAbsentValue) }
    foreach ($entry in $node.Values.GetEnumerator()) { if ($entry.Key -ieq $Name) { return $entry.Value } }
    return (New-WfAbsentValue)
}

function Remove-Wf1aSyntheticKey {
    param([string]$SubKey)
    $prefix = $SubKey.ToLowerInvariant()
    foreach ($k in @($global:Wf1aSynthetic.Registry.Keys)) {
        if ($k -eq $prefix -or $k.StartsWith($prefix + '\')) { $global:Wf1aSynthetic.Registry.Remove($k) }
    }
}

function Test-Wf1aSyntheticDenied {
    param([string]$SubKey)
    foreach ($d in $global:Wf1aSynthetic.Denied) {
        if ($SubKey -ieq $d) { throw [System.UnauthorizedAccessException]::new('denied') }
    }
}

# ---------------------------------------------------------------------------
# The adapters.
# ---------------------------------------------------------------------------

function Write-Wf1aOut {
    param([string]$Line)
    $global:Wf1aSynthetic.Out.Add($Line)
}

function Get-Wf1aNowUtc { return $global:Wf1aSynthetic.NowUtc }

function Test-Wf1aElevated { return [bool]$global:Wf1aSynthetic.Elevated }

function Get-Wf1aLastBootUtc { return $global:Wf1aSynthetic.BootUtc }

function Get-Wf1aDisplayAdapterIds { return @($global:Wf1aSynthetic.Adapters) }

function Get-Wf1aRegistryKey {
    param([string]$SubKey)
    Test-Wf1aSyntheticDenied -SubKey $SubKey
    $node = Get-Wf1aSyntheticNode -SubKey $SubKey
    if ($null -eq $node) { return $null }
    $values = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $node.Values.GetEnumerator()) { $values.Add([pscustomobject]@{ Name = $entry.Key; Value = $entry.Value }) }
    $prefix = $SubKey.ToLowerInvariant() + '\'
    $children = New-Object System.Collections.Generic.List[string]
    foreach ($k in $global:Wf1aSynthetic.Registry.Keys) {
        if ($k.StartsWith($prefix) -and $k.Substring($prefix.Length).IndexOf('\') -lt 0) {
            $path = $global:Wf1aSynthetic.Registry[$k].Path
            $children.Add($path.Substring($path.LastIndexOf('\') + 1))
        }
    }
    return [pscustomobject]@{ Values = $values.ToArray(); SubKeyNames = $children.ToArray() }
}

function Set-Wf1aRegistryValue {
    param([string]$SubKey, [string]$Name, $Value)
    $global:Wf1aSynthetic.Writes.Add('set:' + $Name)
    Test-Wf1aSyntheticDenied -SubKey $SubKey
    if ($global:Wf1aSynthetic.WriteFailsOn -contains $Name) { throw [System.IO.IOException]::new('synthetic write failure') }
    if ($null -eq (Get-Wf1aSyntheticNode -SubKey $SubKey)) { throw [System.InvalidOperationException]::new('the key does not exist') }
    if ($global:Wf1aSynthetic.WriteLies -contains $Name) { $Value = New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]99) }
    Set-Wf1aSyntheticValue -SubKey $SubKey -Name $Name -Value $Value
}

function Remove-Wf1aRegistryValue {
    param([string]$SubKey, [string]$Name)
    $global:Wf1aSynthetic.Writes.Add('remove:' + $Name)
    Test-Wf1aSyntheticDenied -SubKey $SubKey
    if ($global:Wf1aSynthetic.WriteFailsOn -contains $Name) { throw [System.IO.IOException]::new('synthetic write failure') }
    if ($null -eq (Get-Wf1aSyntheticNode -SubKey $SubKey)) { throw [System.InvalidOperationException]::new('the key does not exist') }
    if ($global:Wf1aSynthetic.WriteLies -contains $Name) {
        Set-Wf1aSyntheticValue -SubKey $SubKey -Name $Name -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]99))
        return
    }
    Set-Wf1aSyntheticValue -SubKey $SubKey -Name $Name -Value (New-WfAbsentValue)
}

function Export-Wf1aRegistryKey {
    param([string]$Key, [string]$File)
    $global:Wf1aSynthetic.Exports.Add($Key)
    $leaf = Split-Path -Leaf $File
    if ($global:Wf1aSynthetic.ExportFails -contains $leaf) { return 1 }
    if ($global:Wf1aSynthetic.ExportEmpty -contains $leaf) {
        [System.IO.File]::WriteAllBytes($File, (New-Object byte[] 0))
        return 0
    }
    [System.IO.File]::WriteAllText($File, ("Windows Registry Editor Version 5.00`r`n`r`n[" + (Get-WfLongHiveForm -Path $Key) + "]`r`n"), (New-Object System.Text.UnicodeEncoding($false, $true)))
    if ($null -ne $global:Wf1aSynthetic.AfterExport) { & $global:Wf1aSynthetic.AfterExport $leaf }
    return 0
}

function Get-Wf1aScheduledTasks {
    if ($global:Wf1aSynthetic.TasksThrow) { throw [System.UnauthorizedAccessException]::new('denied') }
    return @($global:Wf1aSynthetic.Tasks)
}

function Get-Wf1aServices { return @($global:Wf1aSynthetic.Services) }

function Get-Wf1aProcessNames { return @($global:Wf1aSynthetic.Processes) }

# ---------------------------------------------------------------------------
# Stutter Guard data on disk, invented in the shape of the pinned source.
# ---------------------------------------------------------------------------

function Get-Wf1aSyntheticJournalRow {
    param([string]$Name, [bool]$Existed = $false, [string]$ValueKind = '', [string]$Data = '', [string]$When = '2026-11-12T08:19:50.4512731+01:00', [string]$TweakId = '', [string]$Target = '')
    $instance = $global:Wf1aSynthetic.InstanceId
    if (-not $TweakId) { $TweakId = 'irq.' + $instance }
    if (-not $Target) { $Target = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $instance + '\Device Parameters\Interrupt Management\Affinity Policy|' + $Name }
    $row = [ordered]@{ TweakId = $TweakId; Kind = 'reg'; Target = $Target; Existed = $Existed }
    if ($ValueKind) { $row['ValueKind'] = $ValueKind }
    if ($Data) { $row['Data'] = $Data }
    $row['When'] = $When
    return $row
}

function ConvertTo-Wf1aSyntheticJson {
    # A small JSON writer for the test data (the library never writes JSON).
    param($Value, [int]$Indent = 0)
    $pad = ' ' * $Indent
    $inner = ' ' * ($Indent + 2)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
    if ($Value -is [string]) { return ('"' + ($Value -replace '\\', '\\' -replace '"', '\"' -replace "`n", '\n') + '"') }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($entry in $Value.GetEnumerator()) { $parts += ($inner + '"' + $entry.Key + '": ' + (ConvertTo-Wf1aSyntheticJson -Value $entry.Value -Indent ($Indent + 2))) }
        if ($parts.Count -eq 0) { return '{}' }
        return ("{`n" + ($parts -join ",`n") + "`n" + $pad + '}')
    }
    $items = @()
    foreach ($v in $Value) { $items += ($inner + (ConvertTo-Wf1aSyntheticJson -Value $v -Indent ($Indent + 2))) }
    if ($items.Count -eq 0) { return '[]' }
    return ("[`n" + ($items -join ",`n") + "`n" + $pad + ']')
}

function Write-Wf1aSyntheticJournal {
    param([string]$DataDirectory, [object[]]$Rows)
    if (-not (Test-Path -LiteralPath $DataDirectory)) { $null = New-Item -ItemType Directory -Path $DataDirectory }
    $other = [ordered]@{ TweakId = 'timer.resolution'; Kind = 'reg'; Target = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel|GlobalTimerResolutionRequests'; Existed = $false; When = '2026-11-12T08:19:49.9010000+01:00' }
    $doc = [ordered]@{ Version = 1; Originals = @(@($other) + @($Rows)); Applied = [ordered]@{}; State = [ordered]@{} }
    $text = ConvertTo-Wf1aSyntheticJson -Value $doc
    [System.IO.File]::WriteAllText((Join-Path $DataDirectory 'journal.json'), $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Write-Wf1aSyntheticSessionReg {
    # The reg export Stutter Guard makes of the Interrupt Management key,
    # UTF-16 with a byte order mark like reg.exe. -Affinity adds an Affinity
    # Policy section with the given value lines.
    param([string]$DataDirectory, [string]$Session = '20261112-081948', [string[]]$Affinity = $null, [string]$KeyPath = '')
    $instance = $global:Wf1aSynthetic.InstanceId
    $interrupt = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $instance + '\Device Parameters\Interrupt Management'
    if (-not $KeyPath) { $KeyPath = $interrupt }
    $folder = Join-Path (Join-Path $DataDirectory 'Backups') $Session
    if (-not (Test-Path -LiteralPath $folder)) { $null = New-Item -ItemType Directory -Path $folder -Force }
    $long = Get-WfLongHiveForm -Path $interrupt
    $lines = @('Windows Registry Editor Version 5.00', '', ('[' + $long + ']'), '', ('[' + $long + '\MessageSignaledInterruptProperties]'), '"MSISupported"=dword:00000001', '"MessageNumberLimit"=dword:00000010', '')
    if ($null -ne $Affinity) { $lines += @(('[' + $long + '\Affinity Policy]')) + $Affinity + @('') }
    $file = Join-Path $folder ((Get-WfSgSafeName -Text $KeyPath) + '.reg')
    [System.IO.File]::WriteAllText($file, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UnicodeEncoding($false, $true)))
    return $file
}

function Initialize-Wf1aSyntheticStutterGuard {
    # The default case: both rows say the value was absent, and the session
    # export has no Affinity Policy key, as the report expects.
    param([string]$DataDirectory)
    Write-Wf1aSyntheticJournal -DataDirectory $DataDirectory -Rows @(
        (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy'),
        (Get-Wf1aSyntheticJournalRow -Name 'AssignmentSetOverride' -When '2026-11-12T08:19:50.4598000+01:00')
    )
    $null = Write-Wf1aSyntheticSessionReg -DataDirectory $DataDirectory
    # An earlier session of the same day and a later one: neither may be
    # picked, the earlier because a later one exists before the row, the
    # later because it postdates the row.
    $null = Write-Wf1aSyntheticSessionReg -DataDirectory $DataDirectory -Session '20261112-070000' -Affinity @('"DevicePolicy"=dword:00000004')
    $null = Write-Wf1aSyntheticSessionReg -DataDirectory $DataDirectory -Session '20261112-090000' -Affinity @('"DevicePolicy"=dword:00000004')
}
