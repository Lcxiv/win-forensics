# Synthetic replacements for the Windows adapters at the bottom of
# ../kbd-crash-dump.ps1.
#
# Dot source this file, then run the script: it finds Get-KcdRegistryKey
# already defined and defines none of its real adapters, so nothing here can
# reach a real registry. Every key, value and time below is invented.
#
# The scenario lives in $global:KcdSynthetic:
#   Registry     lower case key path -> @{ Path; Entries = @{ name -> @{ Kind; Data } } }
#   ReadErrors   lower case key path -> message (reading that key throws)
#   WriteErrors  lower case 'path|name' -> message (writing or deleting that value throws)
#   KeyDeleteErrors  lower case key path -> message (deleting that key throws)
#   ExportCodes  lower case 'HKLM\path' -> exit code (default 0)
#   ExportNoFile lower case 'HKLM\path' -> $true (exit 0 but no file)
#   OnExport     scriptblock run after each export (a value changing under the script's feet)
#   AfterWrite   scriptblock run after each successful write, with the path, name and value
#   Elevated, ElevatedError, Bitness, LastBoot, LastBootError, Now (advances a second per read)
#   Desktop, Profile   the folders the default evidence root and the redaction use
#   Stdout       what the script printed
#   Calls        every registry write and export, in order, as text

function Reset-KcdSynthetic {
    param([string]$Desktop, [string]$UserProfile)
    $global:KcdSynthetic = @{
        Registry        = @{}
        ReadErrors      = @{}
        WriteErrors     = @{}
        KeyDeleteErrors = @{}
        ExportCodes     = @{}
        ExportNoFile    = @{}
        OnExport        = $null
        AfterWrite      = $null
        Elevated        = $true
        ElevatedError   = ''
        Bitness         = $true
        Now             = [datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc)
        LastBoot        = [datetime]::new(2026, 3, 1, 8, 0, 0, [System.DateTimeKind]::Utc)
        LastBootError   = ''
        Desktop         = $Desktop
        Profile         = $UserProfile
        Stdout          = New-Object System.Collections.Generic.List[string]
        Calls           = New-Object System.Collections.Generic.List[string]
    }
}

function Set-KcdSyntheticKey {
    param([string]$Path, [hashtable]$Values = @{})
    $map = @{}
    foreach ($name in $Values.Keys) {
        $value = $Values[$name]
        if ($value -is [hashtable]) { $map[$name] = @{ Kind = $value.Kind; Data = [string]$value.Data } }
        else { $map[$name] = @{ Kind = 'DWord'; Data = [string]$value } }
    }
    $global:KcdSynthetic.Registry[$Path.ToLowerInvariant()] = @{ Path = $Path; Entries = $map }
}

function Get-KcdSyntheticValue {
    # The value as stored, or $null; for test assertions.
    param([string]$Path, [string]$Name)
    $key = $global:KcdSynthetic.Registry[$Path.ToLowerInvariant()]
    if ($null -eq $key) { return $null }
    if (-not $key.Entries.ContainsKey($Name)) { return $null }
    return $key.Entries[$Name]
}

function New-KcdSyntheticMachine {
    # A plain machine: both keyboard services with a Parameters key holding
    # one unrelated value, no crashdump subkey, crash dumps enabled.
    param([string]$Desktop, [string]$UserProfile)
    Reset-KcdSynthetic -Desktop $Desktop -UserProfile $UserProfile
    $services = 'SYSTEM\CurrentControlSet\Services'
    foreach ($service in @('kbdhid', 'i8042prt')) {
        Set-KcdSyntheticKey -Path ($services + '\' + $service) -Values @{ Start = '3'; Type = '1' }
        Set-KcdSyntheticKey -Path ($services + '\' + $service + '\Parameters') -Values @{ SyntheticSetting = '7' }
    }
    Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Control\CrashControl' -Values @{
        CrashDumpEnabled = '7'; LogEvent = '1'; AutoReboot = '1'
        DumpFile         = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\MEMORY.DMP' }
    }
}

function Get-KcdRegistryKey {
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    if ($global:KcdSynthetic.ReadErrors.ContainsKey($lower)) { throw $global:KcdSynthetic.ReadErrors[$lower] }
    $key = $global:KcdSynthetic.Registry[$lower]
    if ($null -eq $key) { return $null }
    $values = @{}
    foreach ($name in $key.Entries.Keys) { $values[$name] = [pscustomobject]@{ Kind = $key.Entries[$name].Kind; Data = $key.Entries[$name].Data } }
    $prefix = $lower + '\'
    $subKeys = @($global:KcdSynthetic.Registry.Keys | Where-Object { $_.StartsWith($prefix) -and -not $_.Substring($prefix.Length).Contains('\') })
    return [pscustomobject]@{ Values = $values; ValueCount = $values.Count; SubKeyCount = $subKeys.Count }
}

function Set-KcdRegistryDword {
    param([string]$Path, [string]$Name, [int]$Value)
    $lower = $Path.ToLowerInvariant()
    $id = $lower + '|' + $Name.ToLowerInvariant()
    if ($global:KcdSynthetic.WriteErrors.ContainsKey($id)) { throw $global:KcdSynthetic.WriteErrors[$id] }
    $parent = $lower.Substring(0, $lower.LastIndexOf('\'))
    if (-not $global:KcdSynthetic.Registry.ContainsKey($parent)) { throw ('the parent key HKLM\' + $parent + ' does not exist') }
    if (-not $global:KcdSynthetic.Registry.ContainsKey($lower)) {
        $global:KcdSynthetic.Registry[$lower] = @{ Path = $Path; Entries = @{} }
        $global:KcdSynthetic.Calls.Add('create-key ' + $Path)
    }
    $data = [string][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$Value), 0)
    $global:KcdSynthetic.Registry[$lower].Entries[$Name] = @{ Kind = 'DWord'; Data = $data }
    $global:KcdSynthetic.Calls.Add('set ' + $Path + '\' + $Name + ' = ' + $data)
    if ($global:KcdSynthetic.AfterWrite) { & $global:KcdSynthetic.AfterWrite $Path $Name $Value }
}

function Remove-KcdRegistryValue {
    param([string]$Path, [string]$Name)
    $lower = $Path.ToLowerInvariant()
    $id = $lower + '|' + $Name.ToLowerInvariant()
    if ($global:KcdSynthetic.WriteErrors.ContainsKey($id)) { throw $global:KcdSynthetic.WriteErrors[$id] }
    $key = $global:KcdSynthetic.Registry[$lower]
    if ($null -eq $key) { return }
    if ($key.Entries.ContainsKey($Name)) {
        $key.Entries.Remove($Name)
        $global:KcdSynthetic.Calls.Add('delete-value ' + $Path + '\' + $Name)
    }
}

function Remove-KcdRegistryKey {
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    if ($global:KcdSynthetic.KeyDeleteErrors.ContainsKey($lower)) { throw $global:KcdSynthetic.KeyDeleteErrors[$lower] }
    $prefix = $lower + '\'
    if (@($global:KcdSynthetic.Registry.Keys | Where-Object { $_.StartsWith($prefix) }).Count -gt 0) { throw 'the key has child subkeys' }
    if ($global:KcdSynthetic.Registry.ContainsKey($lower)) {
        $global:KcdSynthetic.Registry.Remove($lower)
        $global:KcdSynthetic.Calls.Add('delete-key ' + $Path)
    }
}

function Invoke-KcdRegExport {
    param([string]$Key, [string]$File)
    $lower = $Key.ToLowerInvariant()
    $global:KcdSynthetic.Calls.Add('export ' + $Key)
    $code = 0
    if ($global:KcdSynthetic.ExportCodes.ContainsKey($lower)) { $code = [int]$global:KcdSynthetic.ExportCodes[$lower] }
    $path = $lower.Substring(5)
    $stored = $global:KcdSynthetic.Registry[$path]
    if ($null -eq $stored) { $code = 1 }
    if ($code -eq 0 -and -not $global:KcdSynthetic.ExportNoFile.ContainsKey($lower)) {
        $lines = @('Windows Registry Editor Version 5.00', '', ('[HKEY_LOCAL_MACHINE\' + $stored.Path + ']'))
        foreach ($name in ($stored.Entries.Keys | Sort-Object)) { $lines += ('"' + $name + '"=' + $stored.Entries[$name].Kind + ':' + $stored.Entries[$name].Data) }
        [System.IO.File]::WriteAllText($File, (($lines -join "`r`n") + "`r`n"))
    }
    if ($global:KcdSynthetic.OnExport) { & $global:KcdSynthetic.OnExport }
    return $code
}

function Test-KcdElevated {
    if ($global:KcdSynthetic.ElevatedError) { throw $global:KcdSynthetic.ElevatedError }
    return $global:KcdSynthetic.Elevated
}

function Test-KcdProcessBitness { return $global:KcdSynthetic.Bitness }

function Get-KcdUtcNow {
    $now = $global:KcdSynthetic.Now
    $global:KcdSynthetic.Now = $now.AddSeconds(1)
    return $now
}

function Get-KcdLastBootUtc {
    if ($global:KcdSynthetic.LastBootError) { throw $global:KcdSynthetic.LastBootError }
    return $global:KcdSynthetic.LastBoot
}

function Get-KcdDesktopPath { return $global:KcdSynthetic.Desktop }

function Get-KcdProfilePath { return $global:KcdSynthetic.Profile }

function Write-KcdLine {
    param([string]$Text)
    $global:KcdSynthetic.Stdout.Add($Text)
}
