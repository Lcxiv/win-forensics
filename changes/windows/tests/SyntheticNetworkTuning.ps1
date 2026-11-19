# Synthetic Windows for network-tuning: replaces every adapter at the bottom
# of _network-tuning-lib.ps1 with an in memory machine held in
# $global:WfNtSynthetic. Dot source it after the library. Nothing here reads
# or writes a real adapter or registry; the tests prove the portable logic
# only.
#
# The machine is invented: vendor 10EC is the PCI vendor the driver matches,
# every other identifier is made up, and the address below is a locally
# administered placeholder that must never be printed.

function New-WfNtSyntheticProperty {
    param([string]$Keyword, [string]$Value, [string]$DisplayName = '', [string[]]$Valid = @(), [string[]]$Shown = @(), [int]$Type = 1)
    $display = $Value
    for ($i = 0; $i -lt $Valid.Count; $i++) { if ($Valid[$i] -eq $Value -and $i -lt $Shown.Count) { $display = $Shown[$i] } }
    return [pscustomobject]@{
        RegistryKeyword     = $Keyword
        RegistryValue       = @($Value)
        RegistryDataType    = $Type
        DisplayName         = $DisplayName
        DisplayValue        = $display
        ValidRegistryValues = $Valid
        ValidDisplayValues  = $Shown
    }
}

function New-WfNtSyntheticMachine {
    $pnp = 'PCI\VEN_10EC&DEV_8125&SUBSYS_00001234&REV_05\4&ABCDEF0&0&00E4'
    $global:WfNtSynthetic = @{
        Elevated     = $true
        Processes    = @('System', 'explorer', 'svchost')
        Adapters     = @(
            [pscustomobject]@{ Name = 'Ethernet 2'; InterfaceDescription = 'Realtek Gaming 2.5GbE Family Controller'; DriverFileName = 'rt25cx21x64.sys'; DriverVersion = '1125.31.50.603'; PnPDeviceID = $pnp; Medium = [uint32]14; Physical = $true; Up = $true; LinkSpeed = '1 Gbps' },
            [pscustomobject]@{ Name = 'Wi-Fi'; InterfaceDescription = 'Invented Wireless Adapter'; DriverFileName = 'wifi.sys'; DriverVersion = '1.0.0.1'; PnPDeviceID = 'PCI\VEN_1234&DEV_0001&SUBSYS_00000000&REV_01\4&1111111&0&00E0'; Medium = [uint32]9; Physical = $true; Up = $false; LinkSpeed = '0 bps' }
        )
        Properties   = @{}
        DriverKeys   = @{ $pnp = '{4d36e972-e325-11ce-bfc1-08002be10318}\0001' }
        AllowTurnOff = 'Enabled'
        ExportFails  = $false
        ExportEmpty  = $false
        Exports      = New-Object System.Collections.Generic.List[string]
        AfterExport  = $null
        WriteFailsOn = @()
        WriteLies    = @()
        ReadThrows   = $false
        Writes       = New-Object System.Collections.Generic.List[string]
        Out          = New-Object System.Collections.Generic.List[string]
        NowUtc       = [datetime]::new(2026, 11, 20, 18, 0, 0, [System.DateTimeKind]::Utc)
        BootUtc      = [datetime]::new(2026, 11, 20, 9, 0, 0, [System.DateTimeKind]::Utc)
    }
    $props = New-Object System.Collections.Generic.List[object]
    $props.Add((New-WfNtSyntheticProperty -Keyword '*IdleRestriction' -Value '0' -DisplayName 'idle power down restriction' -Valid @('0', '1') -Shown @('No Restriction', 'Only idle when user not present')))
    $props.Add((New-WfNtSyntheticProperty -Keyword '*InterruptModeration' -Value '0' -DisplayName 'Interrupt Moderation' -Valid @('0', '1') -Shown @('Disabled', 'Enabled')))
    $props.Add((New-WfNtSyntheticProperty -Keyword '*FlowControl' -Value '3' -DisplayName 'Flow Control' -Valid @('0', '3') -Shown @('Disabled', 'Rx & Tx Enabled')))
    $props.Add((New-WfNtSyntheticProperty -Keyword '*UDPChecksumOffloadIPv4' -Value '3' -DisplayName 'UDP Checksum Offload (IPv4)' -Valid @('0', '1', '2', '3') -Shown @('Disabled', 'Tx Enabled', 'Rx Enabled', 'Rx & Tx Enabled')))
    $props.Add((New-WfNtSyntheticProperty -Keyword 'InventedGreenKeyword' -Value '1' -DisplayName 'Green Ethernet' -Valid @('0', '1') -Shown @('Disabled', 'Enabled')))
    $props.Add((New-WfNtSyntheticProperty -Keyword 'NetworkAddress' -Value '020000000001' -DisplayName 'Network Address' -Type 1))
    $props.Add((New-WfNtSyntheticProperty -Keyword 'InventedHiddenKeyword' -Value '0'))
    $global:WfNtSynthetic.Properties['Ethernet 2'] = $props
    $global:WfNtSynthetic.Properties['Wi-Fi'] = New-Object System.Collections.Generic.List[object]
}

function Get-WfNtSyntheticProperty {
    param([string]$Keyword, [string]$Adapter = 'Ethernet 2')
    foreach ($p in $global:WfNtSynthetic.Properties[$Adapter]) { if ($p.RegistryKeyword -ceq $Keyword) { return $p } }
    return $null
}

function Set-WfNtSyntheticLive {
    param([string]$Keyword, [string]$Value, [string]$Adapter = 'Ethernet 2')
    $p = Get-WfNtSyntheticProperty -Keyword $Keyword -Adapter $Adapter
    $p.RegistryValue = @($Value)
    $p.DisplayValue = $Value
    for ($i = 0; $i -lt @($p.ValidRegistryValues).Count; $i++) {
        if ($p.ValidRegistryValues[$i] -eq $Value -and $i -lt @($p.ValidDisplayValues).Count) { $p.DisplayValue = $p.ValidDisplayValues[$i] }
    }
}

function Get-WfNtSyntheticLive {
    param([string]$Keyword, [string]$Adapter = 'Ethernet 2')
    return [string](@((Get-WfNtSyntheticProperty -Keyword $Keyword -Adapter $Adapter).RegistryValue)[0])
}

# ---------------------------------------------------------------------------
# The adapters.
# ---------------------------------------------------------------------------

function Write-WfNtOut {
    param([string]$Line)
    $global:WfNtSynthetic.Out.Add($Line)
}

function Get-WfNtNowUtc { return $global:WfNtSynthetic.NowUtc }

function Test-WfNtElevated { return [bool]$global:WfNtSynthetic.Elevated }

function Get-WfNtLastBootUtc { return $global:WfNtSynthetic.BootUtc }

function Get-WfNtProcessNames { return @($global:WfNtSynthetic.Processes) }

function Get-WfNtEthernetAdapters { return @($global:WfNtSynthetic.Adapters) }

function Get-WfNtAdvancedProperties {
    param([string]$Name)
    if ($global:WfNtSynthetic.ReadThrows) { throw [System.UnauthorizedAccessException]::new('synthetic read failure') }
    if (-not $global:WfNtSynthetic.Properties.ContainsKey($Name)) { throw [System.ArgumentException]::new('no such adapter') }
    # Copies, as the cmdlet returns fresh objects on every call.
    return @($global:WfNtSynthetic.Properties[$Name] | ForEach-Object {
            [pscustomobject]@{
                RegistryKeyword     = $_.RegistryKeyword
                RegistryValue       = @($_.RegistryValue)
                RegistryDataType    = $_.RegistryDataType
                DisplayName         = $_.DisplayName
                DisplayValue        = $_.DisplayValue
                ValidRegistryValues = @($_.ValidRegistryValues)
                ValidDisplayValues  = @($_.ValidDisplayValues)
            }
        })
}

function Get-WfNtAllowTurnOff {
    param([string]$Name)
    if (-not $Name) { throw [System.ArgumentException]::new('no name') }
    return $global:WfNtSynthetic.AllowTurnOff
}

function Get-WfNtDriverKeyName {
    param([string]$PnPDeviceID)
    if (-not $global:WfNtSynthetic.DriverKeys.ContainsKey($PnPDeviceID)) { throw [System.ArgumentException]::new('no such device') }
    return $global:WfNtSynthetic.DriverKeys[$PnPDeviceID]
}

function Export-WfNtRegistryKey {
    param([string]$Key, [string]$File)
    $global:WfNtSynthetic.Exports.Add($Key)
    if ($global:WfNtSynthetic.ExportFails) { return 1 }
    if ($global:WfNtSynthetic.ExportEmpty) {
        [System.IO.File]::WriteAllBytes($File, (New-Object byte[] 0))
        return 0
    }
    $long = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
    [System.IO.File]::WriteAllText($File, ("Windows Registry Editor Version 5.00`r`n`r`n[" + $long + "]`r`n`"*IdleRestriction`"=`"0`"`r`n"), (New-Object System.Text.UnicodeEncoding($false, $true)))
    if ($null -ne $global:WfNtSynthetic.AfterExport) { & $global:WfNtSynthetic.AfterExport }
    return 0
}

function Set-WfNtAdvancedProperty {
    param([string]$Name, [string]$Keyword, [string]$Value)
    $global:WfNtSynthetic.Writes.Add($Name + '|' + $Keyword + '=' + $Value)
    if ($global:WfNtSynthetic.WriteFailsOn -contains $Keyword) { throw [System.IO.IOException]::new('synthetic write failure') }
    if ($null -eq (Get-WfNtSyntheticProperty -Keyword $Keyword -Adapter $Name)) { throw [System.ArgumentException]::new('no such keyword') }
    if ($global:WfNtSynthetic.WriteLies -contains $Keyword) { $Value = '7' }
    Set-WfNtSyntheticLive -Keyword $Keyword -Value $Value -Adapter $Name
}
