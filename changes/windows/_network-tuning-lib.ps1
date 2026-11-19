# Logic and Windows adapters for network-tuning.ps1: the guarded network
# tuning change for the gaming PC's one wired Realtek adapter. Dot sourced by
# the entry script and by the tests.
#
# Which settings are in the script, and why every other candidate is not, is
# argued with sources in docs/changes/network-tuning-research.md. The table in
# Get-WfNtSettings holds the settings with an include verdict there (the
# default set) and, opt in only, the reset power properties the research
# rates measure first: each runs only when named alone with -Only, as a
# guarded experiment with the same save, Undo and Readback.
#
# The file has two halves. The first half is portable logic and is what the
# Pester suite in tests/ exercises off Windows. The second half, at the
# bottom, holds the adapters that touch Windows; the tests replace them with
# tests/SyntheticNetworkTuning.ps1. Only one adapter changes anything:
# Set-WfNtAdvancedProperty, which always passes -NoRestart.
#
# Every Windows fact relied on is cited next to the code and in
# changes/windows/README.md, which also lists what is not verified yet.
#
# Target: Windows PowerShell 5.1, run by hand by the operator. Plain ASCII.

if (Get-Command -Name 'Invoke-WfNtMain' -CommandType Function -ErrorAction SilentlyContinue) { return }

# ---------------------------------------------------------------------------
# Constants. Functions, not variables: this file is dot sourced into other
# scopes.
# ---------------------------------------------------------------------------

function Get-WfNtChangeName { return 'network-tuning' }

# The settings table. Each entry is one NDIS advanced property of the
# adapter, written only as the driver exposes it (keyword, current value and
# valid values read live at Plan time). Fields:
#   Name      the -Only name.
#   Keyword   the registry keyword to match, or '' to match DisplayName.
#   Display   the driver's display name to match when Keyword is ''. The
#             Realtek names are taken from the PC's 19 Nov transcription,
#             which did not record their keywords; the live keyword is read
#             and saved, and every write uses it.
#   Proposed  the value to write, or '' for the driver's own off value: the
#             one valid value whose display text is OffDisplay, read live.
#   Default   $true: in the default set. $false: opt in, only when named
#             alone with -Only.
#   Verdict   'include' or 'measure-first' (the research document's verdict).
#
# *IdleRestriction: NetAdapterCx standardized keyword, 0 (default) "No
# restriction", 1 "Only idle when user isn't present"; it decides when the
# device's idle power down may happen.
# https://learn.microsoft.com/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management
# A device in Dx has a resume delay before it can transfer packets again
# (packet filter wake: at most 10 ms by Microsoft's guideline).
# https://learn.microsoft.com/windows-hardware/drivers/netcx/configuring-power-management
#
# The measure first entries have no cited latency case either way: Realtek
# documents none of its own properties, and *FlowControl's client default is
# Rx and Tx enabled (3).
# https://learn.microsoft.com/windows-hardware/drivers/network/enumeration-keywords
function Get-WfNtSettings {
    $research = 'docs/changes/network-tuning-research.md (measure first; no cited latency case)'
    return @(
        [pscustomobject]@{
            Name       = 'idle-restriction'
            Keyword    = '*IdleRestriction'
            Display    = ''
            Proposed   = '1'
            OffDisplay = ''
            Default    = $true
            Verdict    = 'include'
            Reason     = 'stops the adapter powering down to save energy while someone is using the PC; a powered down adapter must wake before it passes packets again (Microsoft guideline: up to 10 ms), and the driver install of 19 Nov reset this to the default 0'
            Restart    = 'adapter'
            Source     = 'https://learn.microsoft.com/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management'
        },
        [pscustomobject]@{
            Name       = 'green-ethernet'
            Keyword    = ''
            Display    = 'Green Ethernet'
            Proposed   = ''
            OffDisplay = 'Disabled'
            Default    = $false
            Verdict    = 'measure-first'
            Reason     = 'a Realtek power saving property the 19 Nov install enabled; Realtek documents no effect on latency, so this is an experiment: turn it off alone and compare'
            Restart    = 'adapter'
            Source     = $research
        },
        [pscustomobject]@{
            Name       = 'power-saving-mode'
            Keyword    = ''
            Display    = 'Power Saving Mode'
            Proposed   = ''
            OffDisplay = 'Disabled'
            Default    = $false
            Verdict    = 'measure-first'
            Reason     = 'a Realtek power saving property the 19 Nov install enabled; Realtek documents no effect on latency, so this is an experiment: turn it off alone and compare'
            Restart    = 'adapter'
            Source     = $research
        },
        [pscustomobject]@{
            Name       = 'gigabit-lite'
            Keyword    = ''
            Display    = 'Gigabit Lite'
            Proposed   = ''
            OffDisplay = 'Disabled'
            Default    = $false
            Verdict    = 'measure-first'
            Reason     = 'a Realtek property the 19 Nov install enabled; Realtek documents no effect on latency, so this is an experiment: turn it off alone and compare'
            Restart    = 'adapter'
            Source     = $research
        },
        [pscustomobject]@{
            Name       = 'ltr-obff'
            Keyword    = 'LTROBFF'
            Display    = ''
            Proposed   = ''
            OffDisplay = 'Disabled'
            Default    = $false
            Verdict    = 'measure-first'
            Reason     = 'a Realtek property the 19 Nov install moved from 0 to 4; Realtek documents neither value, so this is an experiment, and only when the driver shows it with an off value'
            Restart    = 'adapter'
            Source     = $research
        },
        [pscustomobject]@{
            Name       = 'flow-control'
            Keyword    = '*FlowControl'
            Display    = ''
            Proposed   = ''
            OffDisplay = 'Disabled'
            Default    = $false
            Verdict    = 'measure-first'
            Reason     = 'pause frames, at the Microsoft client default Rx and Tx (3); no cited latency case, so this is an experiment: turn it off alone and compare'
            Restart    = 'adapter'
            Source     = $research
        }
    )
}

function Get-WfNtSettingMatchText {
    # How a setting is found among the driver's properties, for messages.
    param($Setting)
    if ($Setting.Keyword) { return $Setting.Keyword }
    return ('the property shown as "' + $Setting.Display + '"')
}

function Get-WfNtVerdictText {
    param($Setting)
    if ($Setting.Verdict -eq 'include') { return 'include (cited case; see the research document)' }
    return 'measure first, no cited latency case (opt in: named alone with -Only)'
}

# The adapter the script may touch: the one wired Realtek adapter bound to
# the Realtek NetAdapterCx driver installed on 19 Nov (rt25cx21x64).
# *IdleRestriction is a NetAdapterCx keyword, so an NDIS driver (the inbox
# one, after a rollback) is refused.
function Get-WfNtVendorPattern { return 'Realtek' }
function Get-WfNtDriverFilePattern { return '^rt25cx21x64(\.sys)?$' }

# The game and its launcher; nothing runs while either does.
function Get-WfNtGameProcesses { return @('Overwatch', 'Battle.net') }

# The device setup class of network adapters; its driver keys are named
# {class guid}\nnnn.
# https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors
function Get-WfNtNetClassGuid { return '{4d36e972-e325-11ce-bfc1-08002be10318}' }

function Get-WfNtRestartLines {
    # https://learn.microsoft.com/powershell/module/netadapter/set-netadapteradvancedproperty
    # https://learn.microsoft.com/powershell/module/netadapter/new-netadapteradvancedproperty
    # ("Many advanced properties require restarting the network adapter
    # before the new settings take effect.")
    # https://learn.microsoft.com/powershell/module/netadapter/restart-netadapter
    return @(
        'Restart: the new value takes effect only after the adapter restarts. This script passes -NoRestart',
        '  and restarts nothing (Learn: many advanced properties require restarting the network adapter',
        '  before the new settings take effect). With the game closed, restart it by hand: Device Manager,',
        '  Network adapters, the Realtek adapter, Disable device, then Enable device (the network drops for',
        '  a few seconds), or restart the PC. Then run -Readback.'
    )
}

function Get-WfNtAttributionLines {
    return @(
        'Attribution: applying several settings in one run cannot tell which one made a difference. To judge',
        '  one setting, apply it alone with -Only <name>, play and record, and only then add the next.'
    )
}

# ---------------------------------------------------------------------------
# Output. Every line goes through Protect-WfNtText before it is written, so
# an adapter name, a device instance path, a profile folder or anything that
# looks like a hardware or network address never reaches the console.
# ---------------------------------------------------------------------------

function Protect-WfNtText {
    param([string]$Text, [string[]]$Secrets = @())
    $out = $Text
    foreach ($s in $Secrets) {
        if ($s -and $s.Length -ge 2) {
            $out = [regex]::Replace($out, [regex]::Escape($s), 'ethernet-1', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $profileRoot = [Environment]::GetEnvironmentVariable('USERPROFILE')
    if ($profileRoot -and $profileRoot.Length -ge 4) {
        $out = [regex]::Replace($out, [regex]::Escape($profileRoot), '<profile>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $out = [regex]::Replace($out, '(?i)[A-Z]:\\Users\\[^\\\s]+', '<profile>')
    $out = [regex]::Replace($out, '(?i)PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}[^\s,]*', 'ethernet-1')
    $out = [regex]::Replace($out, '(?i)\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b', '<guid>')
    $out = [regex]::Replace($out, '(?i)\b([0-9A-F]{2}[-:]){5}[0-9A-F]{2}\b', '<address>')
    $out = [regex]::Replace($out, '(?i)\b[0-9A-F]{12}\b', '<address>')
    $out = [regex]::Replace($out, '\b\d{1,3}(\.\d{1,3}){3}\b', '<address>')
    $out = [regex]::Replace($out, '[^\x20-\x7E]', '?')
    return $out
}

function Write-WfNtReport {
    param([string[]]$Lines, [string[]]$Secrets = @())
    foreach ($line in $Lines) { Write-WfNtOut -Line (Protect-WfNtText -Text $line -Secrets $Secrets) }
}

function Get-WfNtSha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('X2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Get-WfNtTextSha256 {
    param([string]$Text)
    return (Get-WfNtSha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text.ToUpperInvariant())))
}

function New-WfNtCheck {
    param([string]$Id, [bool]$Ok, [string]$Text)
    return [pscustomobject]@{ Id = $Id; Ok = $Ok; Text = $Text }
}

function Format-WfNtCheck {
    param($Check)
    $mark = 'ok    '
    if (-not $Check.Ok) { $mark = 'FAILED' }
    return ('  [' + $mark + '] ' + $Check.Id + ': ' + $Check.Text)
}

# ---------------------------------------------------------------------------
# Selecting settings and the adapter.
# ---------------------------------------------------------------------------

function Resolve-WfNtSelection {
    # -Only names, comma separated or as a list, against the settings table.
    # Returns @{ Ok; Settings; Reason }.
    param([string[]]$Only)
    $all = @(Get-WfNtSettings)
    $names = @()
    foreach ($item in @($Only)) {
        if ($null -eq $item) { continue }
        foreach ($part in ([string]$item).Split(',')) {
            $p = $part.Trim()
            if ($p) { $names += $p }
        }
    }
    if ($names.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Settings = @($all | Where-Object { $_.Default }); Reason = '' } }
    $known = @($all | ForEach-Object { $_.Name })
    $unknown = @($names | Where-Object { $known -notcontains $_ })
    if ($unknown.Count -gt 0) {
        $shown = @($unknown | ForEach-Object { Protect-WfNtText -Text $_ })
        return [pscustomobject]@{ Ok = $false; Settings = @(); Reason = ('-Only names a setting this script does not have: ' + ($shown -join ', ') + '. Known: ' + ($known -join ', ')) }
    }
    $picked = @($all | Where-Object { $names -contains $_.Name })
    $optIn = @($picked | Where-Object { -not $_.Default })
    if ($optIn.Count -gt 0 -and $picked.Count -gt 1) {
        return [pscustomobject]@{ Ok = $false; Settings = @(); Reason = ('a measure first setting runs alone, one experiment at a time: name only one of ' + (@($picked | ForEach-Object { $_.Name }) -join ', ')) }
    }
    return [pscustomobject]@{ Ok = $true; Settings = $picked; Reason = '' }
}

function Find-WfNtAdapter {
    # Exactly one physical 802.3 adapter that is Up, from the Realtek
    # NetAdapterCx driver. Returns @{ Adapter; Checks }.
    param($Adapters)
    $checks = @()
    $wired = @($Adapters | Where-Object { $_.Physical -and $_.Medium -eq 14 })
    $up = @($wired | Where-Object { $_.Up })
    if ($up.Count -ne 1) {
        $text = 'no physical Ethernet adapter is Up'
        if ($up.Count -gt 1) { $text = ([string]$up.Count + ' physical Ethernet adapters are Up; this script touches exactly one, so disconnect or disable the others first') }
        $checks += (New-WfNtCheck -Id 'adapter' -Ok $false -Text $text)
        return [pscustomobject]@{ Adapter = $null; Checks = $checks }
    }
    $a = $up[0]
    $checks += (New-WfNtCheck -Id 'adapter' -Ok $true -Text ('exactly one physical Ethernet adapter is Up (' + [string]$wired.Count + ' wired in all), linked at ' + $a.LinkSpeed))
    $vendorOk = ($a.InterfaceDescription -match (Get-WfNtVendorPattern))
    $driverOk = ([string]$a.DriverFileName -match (Get-WfNtDriverFilePattern))
    if (-not $vendorOk -or -not $driverOk) {
        $checks += (New-WfNtCheck -Id 'realtek' -Ok $false -Text ('the adapter is not the Realtek adapter on its NetAdapterCx driver (description "' + $a.InterfaceDescription + '", driver file ' + $a.DriverFileName + '); this script targets rt25cx21x64 only'))
        return [pscustomobject]@{ Adapter = $null; Checks = $checks }
    }
    $checks += (New-WfNtCheck -Id 'realtek' -Ok $true -Text ('"' + $a.InterfaceDescription + '", driver ' + $a.DriverFileName + ' ' + $a.DriverVersion))
    if ($a.Name -match '[\*\?\[\]`]' -or -not $a.Name) {
        $checks += (New-WfNtCheck -Id 'name' -Ok $false -Text 'the adapter name holds a wildcard or quoting character; rename it in Network Connections first')
        return [pscustomobject]@{ Adapter = $null; Checks = $checks }
    }
    $checks += (New-WfNtCheck -Id 'name' -Ok $true -Text 'the adapter name can be passed to the NetAdapter cmdlets literally')
    if (-not $a.PnPDeviceID) {
        $checks += (New-WfNtCheck -Id 'device' -Ok $false -Text 'the adapter reports no Plug and Play device id')
        return [pscustomobject]@{ Adapter = $null; Checks = $checks }
    }
    return [pscustomobject]@{ Adapter = $a; Checks = $checks }
}

function Test-WfNtDriverKeyName {
    # The driver key's name as DEVPKEY_Device_Driver reports it:
    # {class guid}\nnnn for the network class.
    param([string]$Name)
    if (-not $Name) { return $false }
    $pattern = '^' + [regex]::Escape((Get-WfNtNetClassGuid)) + '\\\d{4}$'
    return ($Name -match $pattern)
}

function Get-WfNtDriverKeyPath {
    param([string]$Name)
    return ('HKLM\SYSTEM\CurrentControlSet\Control\Class\' + $Name)
}

function Test-WfNtValueText {
    # An enum registry value as these properties store it: decimal digits.
    param([string]$Text)
    return ($Text -match '^[0-9]{1,10}$')
}

function Get-WfNtDisplayFor {
    # The driver's own display text for one registry value of an enum.
    param($Property, [string]$Value)
    $valid = @($Property.ValidRegistryValues)
    $shown = @($Property.ValidDisplayValues)
    for ($i = 0; $i -lt $valid.Count; $i++) {
        if ([string]$valid[$i] -eq $Value -and $i -lt $shown.Count) { return [string]$shown[$i] }
    }
    return ''
}

function Format-WfNtValue {
    param($Property, [string]$Value)
    $display = Get-WfNtDisplayFor -Property $Property -Value $Value
    if ($display) { return ($Value + ' (' + $display + ')') }
    return $Value
}

function Test-WfNtSetting {
    # Every precondition for one setting against the properties the driver
    # exposes. Returns @{ Setting; Ok; Action; Live; Keyword; Proposed;
    # Property; Checks }, Action being 'change' or 'none' (already at the
    # proposed value), Keyword the live keyword and Proposed the value to
    # write (the table's, or the driver's off value read live).
    # Property fields: MSFT_NetAdapterAdvancedPropertySettingData; displayed
    # parameters are stored as REG_SZ (RegistryDataType 1) and only they have
    # ValidRegistryValues.
    # https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapteradvancedpropertysettingdata
    param($Setting, $Properties)
    $checks = @()
    $result = [pscustomobject]@{ Setting = $Setting; Ok = $false; Action = ''; Live = ''; Keyword = ''; Proposed = ''; Property = $null; Checks = $null }
    $what = Get-WfNtSettingMatchText -Setting $Setting
    if ($Setting.Keyword) {
        $matching = @($Properties | Where-Object { $_.RegistryKeyword -ceq $Setting.Keyword })
    } else {
        $matching = @($Properties | Where-Object { $_.DisplayName -and $_.DisplayName -eq $Setting.Display })
    }
    if ($matching.Count -ne 1) {
        $text = 'the installed driver does not expose ' + $what
        if ($matching.Count -gt 1) { $text = 'the driver exposes ' + $what + ' ' + [string]$matching.Count + ' times' }
        $checks += (New-WfNtCheck -Id 'exposed' -Ok $false -Text $text)
        $result.Checks = $checks
        return $result
    }
    $p = $matching[0]
    $result.Property = $p
    $result.Keyword = [string]$p.RegistryKeyword
    if ($result.Keyword -notmatch '^\*?[A-Za-z0-9_]+$') {
        $checks += (New-WfNtCheck -Id 'exposed' -Ok $false -Text ('the driver''s keyword for ' + $what + ' is not a plain name'))
        $result.Checks = $checks
        return $result
    }
    $exposed = 'the driver exposes ' + $what
    if (-not $Setting.Keyword) { $exposed += ' as ' + $result.Keyword }
    $checks += (New-WfNtCheck -Id 'exposed' -Ok $true -Text $exposed)
    if (-not $p.DisplayName) {
        $hidden = 'it is a hidden property, so the driver lists no valid values for it'
        if (-not $Setting.Proposed) { $hidden += ' and no off value can be read' }
        $checks += (New-WfNtCheck -Id 'displayed' -Ok $false -Text $hidden)
        $result.Checks = $checks
        return $result
    }
    $checks += (New-WfNtCheck -Id 'displayed' -Ok $true -Text ('shown as "' + $p.DisplayName + '"'))
    if ([int]$p.RegistryDataType -ne 1) {
        $checks += (New-WfNtCheck -Id 'type' -Ok $false -Text ('its registry type is ' + [string]$p.RegistryDataType + ', not REG_SZ (1) as for a displayed property'))
        $result.Checks = $checks
        return $result
    }
    $checks += (New-WfNtCheck -Id 'type' -Ok $true -Text 'REG_SZ, as for every displayed property')
    $values = @($p.RegistryValue)
    if ($values.Count -ne 1 -or -not (Test-WfNtValueText -Text ([string]$values[0]))) {
        $checks += (New-WfNtCheck -Id 'value' -Ok $false -Text ('the current value is not one decimal number (' + [string]$values.Count + ' entries)'))
        $result.Checks = $checks
        return $result
    }
    $live = [string]$values[0]
    $result.Live = $live
    $checks += (New-WfNtCheck -Id 'value' -Ok $true -Text ('current value ' + (Format-WfNtValue -Property $p -Value $live)))
    $valid = @($p.ValidRegistryValues | ForEach-Object { [string]$_ })
    if ($valid.Count -eq 0) {
        $checks += (New-WfNtCheck -Id 'valid' -Ok $false -Text 'the driver lists no valid values')
        $result.Checks = $checks
        return $result
    }
    if ($valid -notcontains $live) {
        $checks += (New-WfNtCheck -Id 'valid' -Ok $false -Text ('the current value ' + $live + ' is not among the driver''s valid values (' + ($valid -join ', ') + ')'))
        $result.Checks = $checks
        return $result
    }
    $proposed = [string]$Setting.Proposed
    if (-not $proposed) {
        $off = @()
        foreach ($v in $valid) { if ((Get-WfNtDisplayFor -Property $p -Value $v) -eq $Setting.OffDisplay) { $off += $v } }
        if ($off.Count -ne 1 -or -not (Test-WfNtValueText -Text $off[0])) {
            $checks += (New-WfNtCheck -Id 'off-value' -Ok $false -Text ('the driver shows ' + [string]$off.Count + ' valid values as "' + $Setting.OffDisplay + '", not exactly one, so its off value cannot be read'))
            $result.Checks = $checks
            return $result
        }
        $proposed = $off[0]
        $checks += (New-WfNtCheck -Id 'off-value' -Ok $true -Text ('the driver''s own off value is ' + (Format-WfNtValue -Property $p -Value $proposed)))
    }
    $result.Proposed = $proposed
    if ($valid -notcontains $proposed) {
        $checks += (New-WfNtCheck -Id 'valid' -Ok $false -Text ('the proposed value ' + $proposed + ' is not among the driver''s valid values (' + ($valid -join ', ') + ')'))
        $result.Checks = $checks
        return $result
    }
    $checks += (New-WfNtCheck -Id 'valid' -Ok $true -Text ('valid values ' + ($valid -join ', ') + ' include the current and the proposed value'))
    $result.Ok = $true
    if ($live -eq $proposed) { $result.Action = 'none' } else { $result.Action = 'change' }
    $result.Checks = $checks
    return $result
}

function Get-WfNtReportedLines {
    # Every other displayed property, as the driver shows it, read only.
    # Nothing that holds an address is printed.
    param($Properties, [string[]]$Skip)
    $lines = @()
    $shown = @($Properties | Where-Object { $_.DisplayName -and ($Skip -notcontains $_.RegistryKeyword) -and $_.RegistryKeyword -notmatch '(?i)address' -and $_.DisplayName -notmatch '(?i)address' } | Sort-Object -Property DisplayName)
    foreach ($p in $shown) {
        $value = (@($p.RegistryValue) | ForEach-Object { [string]$_ }) -join ';'
        $lines += ('  ' + $p.DisplayName + ' = ' + [string]$p.DisplayValue + ' (' + $p.RegistryKeyword + ' ' + $value + ')')
    }
    return $lines
}

function Test-WfNtGameClosed {
    $running = @(Get-WfNtProcessNames)
    $found = @((Get-WfNtGameProcesses) | Where-Object { $running -contains $_ })
    if ($found.Count -gt 0) { return (New-WfNtCheck -Id 'game' -Ok $false -Text ('close ' + ($found -join ' and ') + ' first; nothing here runs while the game or its launcher runs')) }
    return (New-WfNtCheck -Id 'game' -Ok $true -Text 'neither the game nor its launcher is running')
}

# ---------------------------------------------------------------------------
# Plan: reads only.
# ---------------------------------------------------------------------------

function Invoke-WfNtPlan {
    # Reads everything live. Returns the plan object; prints nothing.
    param($Selected)
    $plan = [pscustomobject]@{
        Ready = $false; NothingToDo = $false; Adapter = $null; Checks = @(); Settings = @()
        Properties = @(); DriverKey = ''; DeviceSha256 = ''; AllowTurnOff = ''; Secrets = @()
    }
    $checks = @()
    $checks += (Test-WfNtGameClosed)
    $found = Find-WfNtAdapter -Adapters @(Get-WfNtEthernetAdapters)
    $checks += $found.Checks
    if ($null -eq $found.Adapter) { $plan.Checks = $checks; return $plan }
    $a = $found.Adapter
    $plan.Adapter = $a
    $plan.Secrets = @($a.Name, $a.PnPDeviceID)
    $plan.DeviceSha256 = Get-WfNtTextSha256 -Text $a.PnPDeviceID
    $driverKey = ''
    try { $driverKey = [string](Get-WfNtDriverKeyName -PnPDeviceID $a.PnPDeviceID) } catch { $driverKey = '' }
    if (Test-WfNtDriverKeyName -Name $driverKey) {
        $plan.DriverKey = $driverKey
        $checks += (New-WfNtCheck -Id 'driver-key' -Ok $true -Text 'the driver key name has the network class shape, so Apply can export it first')
    } else {
        $checks += (New-WfNtCheck -Id 'driver-key' -Ok $false -Text 'the adapter''s driver key could not be named, so Apply could not export it before a change')
    }
    $plan.Properties = @(Get-WfNtAdvancedProperties -Name $a.Name)
    try { $plan.AllowTurnOff = [string](Get-WfNtAllowTurnOff -Name $a.Name) } catch { $plan.AllowTurnOff = 'unknown (the read failed)' }
    $settings = @()
    foreach ($s in $Selected) { $settings += (Test-WfNtSetting -Setting $s -Properties $plan.Properties) }
    $plan.Settings = $settings
    $plan.Checks = $checks
    $allChecks = @($checks | Where-Object { -not $_.Ok }).Count -eq 0
    $allSettings = @($settings | Where-Object { -not $_.Ok }).Count -eq 0
    $toChange = @($settings | Where-Object { $_.Ok -and $_.Action -eq 'change' }).Count
    $plan.NothingToDo = ($allChecks -and $allSettings -and $toChange -eq 0)
    $plan.Ready = ($allChecks -and $allSettings -and $toChange -gt 0)
    return $plan
}

function Get-WfNtPlanLines {
    param($Plan, [bool]$Elevated)
    $lines = @()
    $lines += ((Get-WfNtChangeName) + ' Plan: reads only, nothing is changed.')
    if ($Elevated) { $lines += 'Console: elevated.' } else { $lines += 'Console: not elevated (Plan and Readback are fine; Apply and Undo need Run as administrator).' }
    $lines += 'Checks:'
    foreach ($c in $Plan.Checks) { $lines += (Format-WfNtCheck -Check $c) }
    foreach ($r in $Plan.Settings) {
        $s = $r.Setting
        $lines += ''
        $label = $r.Keyword
        if (-not $label) { $label = Get-WfNtSettingMatchText -Setting $s }
        $lines += ('Setting ' + $s.Name + ' (' + $label + ')')
        $lines += ('  verdict:  ' + (Get-WfNtVerdictText -Setting $s))
        if ($null -ne $r.Property -and $r.Live) { $lines += ('  live:     ' + (Format-WfNtValue -Property $r.Property -Value $r.Live)) } else { $lines += '  live:     unknown' }
        if ($null -ne $r.Property -and $r.Proposed) { $lines += ('  proposed: ' + (Format-WfNtValue -Property $r.Property -Value $r.Proposed)) }
        elseif ($s.Proposed) { $lines += ('  proposed: ' + $s.Proposed) }
        else { $lines += ('  proposed: the driver''s value shown as "' + $s.OffDisplay + '" (not readable, see below)') }
        $lines += ('  why:      ' + $s.Reason)
        $lines += '  restart:  adapter restart or PC restart before it takes effect (see Restart below)'
        $lines += ('  source:   ' + $s.Source)
        $lines += '  preconditions:'
        foreach ($c in $r.Checks) { $lines += ('  ' + (Format-WfNtCheck -Check $c)) }
        if (-not $r.Ok) { $lines += '  => REFUSED for this setting (above).' }
        elseif ($r.Action -eq 'none') { $lines += '  => already at the proposed value; nothing to do.' }
        else { $lines += ('  => would change ' + $r.Live + ' to ' + $r.Proposed + '.') }
    }
    if ($null -ne $Plan.Adapter) {
        $skip = @($Plan.Settings | Where-Object { $_.Keyword } | ForEach-Object { $_.Keyword })
        $lines += ''
        $lines += 'Other displayed properties, reported only in this run (the research document gives each a verdict):'
        $lines += (Get-WfNtReportedLines -Properties $Plan.Properties -Skip $skip)
        $lines += ('  Allow the computer to turn off this device = ' + $Plan.AllowTurnOff + ' (Device Manager only; not scripted)')
    }
    $selectedNames = @($Plan.Settings | ForEach-Object { $_.Setting.Name })
    $others = @((Get-WfNtSettings) | Where-Object { -not $_.Default -and $selectedNames -notcontains $_.Name } | ForEach-Object { $_.Name })
    if ($others.Count -gt 0) {
        $lines += ''
        $lines += ('Opt in experiments, measure first, no cited latency case (not selected; name one alone with -Only): ' + ($others -join ', '))
    }
    $lines += ''
    $lines += (Get-WfNtRestartLines)
    $lines += (Get-WfNtAttributionLines)
    return $lines
}

# ---------------------------------------------------------------------------
# The saved before-state.
# ---------------------------------------------------------------------------

function Get-WfNtCsvColumns {
    return @('setting', 'keyword', 'display_name', 'before_value', 'before_display', 'proposed_value', 'action', 'valid_values', 'device_sha256', 'driver_file', 'driver_version')
}

function ConvertTo-WfNtCsvField {
    param([string]$Text)
    return ('"' + (Protect-WfNtText -Text $Text).Replace('"', '""') + '"')
}

function ConvertTo-WfNtBeforeCsv {
    param($Plan)
    $rows = @(((Get-WfNtCsvColumns) | ForEach-Object { ConvertTo-WfNtCsvField -Text $_ }) -join ',')
    foreach ($r in $Plan.Settings) {
        $fields = @(
            $r.Setting.Name, $r.Keyword, [string]$r.Property.DisplayName, $r.Live,
            (Get-WfNtDisplayFor -Property $r.Property -Value $r.Live), $r.Proposed, $r.Action,
            ((@($r.Property.ValidRegistryValues) | ForEach-Object { [string]$_ }) -join ';'),
            $Plan.DeviceSha256, [string]$Plan.Adapter.DriverFileName, [string]$Plan.Adapter.DriverVersion
        )
        $rows += (($fields | ForEach-Object { ConvertTo-WfNtCsvField -Text ([string]$_) }) -join ',')
    }
    return (($rows -join "`r`n") + "`r`n")
}

function Read-WfNtBeforeCsv {
    # The saved rows, or $null when the file is not what Apply writes.
    param([string]$Path)
    try {
        $text = [System.IO.File]::ReadAllText($Path)
        $rows = @($text | ConvertFrom-Csv)
    } catch {
        return $null
    }
    if ($rows.Count -eq 0) { return $null }
    $columns = @(Get-WfNtCsvColumns)
    $out = @()
    $known = @((Get-WfNtSettings) | ForEach-Object { $_.Name })
    foreach ($row in $rows) {
        $names = @($row.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($c in $columns) { if ($names -notcontains $c) { return $null } }
        if ($known -notcontains $row.setting) { return $null }
        if (-not (Test-WfNtValueText -Text $row.before_value) -or -not (Test-WfNtValueText -Text $row.proposed_value)) { return $null }
        if ($row.action -ne 'change' -and $row.action -ne 'none') { return $null }
        if ($row.device_sha256 -notmatch '^[0-9A-F]{64}$') { return $null }
        $out += $row
    }
    return $out
}

function Write-WfNtTextFile {
    # ASCII without a byte order mark.
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.ASCIIEncoding))
}

function Get-WfNtFileSha256 {
    param([string]$Path)
    return (Get-WfNtSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path)))
}

function Get-WfNtEvidenceFiles {
    # The files the SHA256SUMS list covers; it is written last.
    return @('before-values.csv', 'adapter-driver-key.reg')
}

function Save-WfNtEvidence {
    # Saves the before-state. Returns @{ Ok; Folder; Stamp; Reason; CsvSha256 }.
    # Nothing is changed unless this returns Ok.
    param($Plan, [string]$EvidenceRoot, [datetime]$NowUtc)
    $stamp = $NowUtc.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $result = [pscustomobject]@{ Ok = $false; Folder = $null; Stamp = $stamp; Reason = ''; CsvSha256 = '' }
    try {
        if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { $null = New-Item -ItemType Directory -Path $EvidenceRoot -Force }
        $folder = Join-Path -Path $EvidenceRoot -ChildPath $stamp
        if (Test-Path -LiteralPath $folder) { $result.Reason = 'an evidence folder with this time already exists'; return $result }
        $null = New-Item -ItemType Directory -Path $folder
        $result.Folder = $folder
        $csvPath = Join-Path -Path $folder -ChildPath 'before-values.csv'
        Write-WfNtTextFile -Path $csvPath -Text (ConvertTo-WfNtBeforeCsv -Plan $Plan)
        $regPath = Join-Path -Path $folder -ChildPath 'adapter-driver-key.reg'
        $code = Export-WfNtRegistryKey -Key (Get-WfNtDriverKeyPath -Name $Plan.DriverKey) -File $regPath
        if ($code -ne 0 -or -not (Test-Path -LiteralPath $regPath -PathType Leaf) -or (Get-Item -LiteralPath $regPath).Length -eq 0) {
            $result.Reason = 'reg export of the adapter''s driver key failed (exit ' + [string]$code + ')'
            return $result
        }
        $readBack = Read-WfNtBeforeCsv -Path $csvPath
        if ($null -eq $readBack -or @($readBack).Count -ne @($Plan.Settings).Count) { $result.Reason = 'the saved values could not be read back'; return $result }
        foreach ($r in $Plan.Settings) {
            $row = @($readBack | Where-Object { $_.setting -eq $r.Setting.Name })
            if ($row.Count -ne 1 -or $row[0].before_value -ne $r.Live) { $result.Reason = ('the saved value of ' + $r.Setting.Name + ' does not read back as the live value'); return $result }
        }
        $sums = @()
        foreach ($f in (Get-WfNtEvidenceFiles)) { $sums += ((Get-WfNtFileSha256 -Path (Join-Path -Path $folder -ChildPath $f)) + '  ' + $f) }
        Write-WfNtTextFile -Path (Join-Path -Path $folder -ChildPath 'SHA256SUMS') -Text (($sums -join "`r`n") + "`r`n")
        $result.CsvSha256 = Get-WfNtFileSha256 -Path $csvPath
        $result.Ok = $true
        return $result
    } catch {
        $result.Reason = 'saving the before-state failed (' + $_.Exception.GetType().Name + ')'
        return $result
    }
}

function Test-WfNtEvidenceFolder {
    # Whether a folder holds a complete, intact before-state. Returns
    # @{ Ok; Reason; Rows }.
    param([string]$Folder)
    $sumsPath = Join-Path -Path $Folder -ChildPath 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { return [pscustomobject]@{ Ok = $false; Reason = 'no SHA256SUMS: the save did not finish'; Rows = $null } }
    $expected = @{}
    foreach ($line in ([System.IO.File]::ReadAllText($sumsPath) -split "`r`n")) {
        if ($line -match '^([0-9A-F]{64})  (\S+)$') { $expected[$Matches[2]] = $Matches[1] }
    }
    foreach ($f in (Get-WfNtEvidenceFiles)) {
        $p = Join-Path -Path $Folder -ChildPath $f
        if (-not $expected.ContainsKey($f) -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return [pscustomobject]@{ Ok = $false; Reason = ($f + ' is missing'); Rows = $null } }
        if ((Get-WfNtFileSha256 -Path $p) -cne $expected[$f]) { return [pscustomobject]@{ Ok = $false; Reason = ($f + ' does not match its SHA-256'); Rows = $null } }
    }
    $rows = Read-WfNtBeforeCsv -Path (Join-Path -Path $Folder -ChildPath 'before-values.csv')
    if ($null -eq $rows) { return [pscustomobject]@{ Ok = $false; Reason = 'before-values.csv is malformed'; Rows = $null } }
    return [pscustomobject]@{ Ok = $true; Reason = ''; Rows = @($rows) }
}

function Find-WfNtEvidenceFolder {
    # The named folder, or the newest complete one under the root.
    param([string]$EvidenceRoot, [string]$Name)
    if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { return $null }
    if ($Name) {
        if ($Name -notmatch '^\d{8}T\d{6}Z$') { return $null }
        $p = Join-Path -Path $EvidenceRoot -ChildPath $Name
        if (Test-Path -LiteralPath $p -PathType Container) { return $p }
        return $null
    }
    $dirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory | Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' } | Sort-Object -Property Name -Descending)
    foreach ($d in $dirs) {
        if (Test-Path -LiteralPath (Join-Path -Path $d.FullName -ChildPath 'SHA256SUMS') -PathType Leaf) { return $d.FullName }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Writing and reading back.
# ---------------------------------------------------------------------------

function Read-WfNtLiveValue {
    # The single current value of one keyword, or '' when it cannot be told.
    param([string]$Name, [string]$Keyword)
    $p = @(Get-WfNtAdvancedProperties -Name $Name | Where-Object { $_.RegistryKeyword -ceq $Keyword })
    if ($p.Count -ne 1) { return '' }
    $v = @($p[0].RegistryValue)
    if ($v.Count -ne 1) { return '' }
    return [string]$v[0]
}

function Get-WfNtReadbackLines {
    # PASS or FAIL per row, live against expected. $Expect is 'proposed' or
    # 'before'. Returns @{ Ok; Lines }.
    param([string]$Name, $Rows, [string]$Expect)
    $lines = @()
    $ok = $true
    foreach ($row in $Rows) {
        $want = $row.proposed_value
        if ($Expect -eq 'before') { $want = $row.before_value }
        $live = ''
        try { $live = Read-WfNtLiveValue -Name $Name -Keyword $row.keyword } catch { $live = '' }
        if (-not $live) {
            $ok = $false
            $lines += ('  FAIL ' + $row.setting + ' (' + $row.keyword + '): the live value could not be read; expected ' + $want)
        } elseif ($live -eq $want) {
            $lines += ('  PASS ' + $row.setting + ' (' + $row.keyword + '): ' + $live)
        } else {
            $ok = $false
            $lines += ('  FAIL ' + $row.setting + ' (' + $row.keyword + '): live ' + $live + ', expected ' + $want)
        }
    }
    return [pscustomobject]@{ Ok = $ok; Lines = $lines }
}

function Invoke-WfNtApply {
    param($Selected, [string]$EvidenceRoot)
    if (-not (Test-WfNtElevated)) {
        Write-WfNtReport -Lines @('REFUSED: Apply needs an elevated Windows PowerShell (Run as administrator). Nothing changed.')
        return 2
    }
    $plan = Invoke-WfNtPlan -Selected $Selected
    $secrets = @($plan.Secrets)
    Write-WfNtReport -Lines (Get-WfNtPlanLines -Plan $plan -Elevated $true) -Secrets $secrets
    if ($plan.NothingToDo) {
        Write-WfNtReport -Lines @('REFUSED: every selected setting is already at its proposed value. Nothing to change.') -Secrets $secrets
        return 2
    }
    if (-not $plan.Ready) {
        Write-WfNtReport -Lines @('REFUSED: a precondition failed (above). Nothing changed.') -Secrets $secrets
        return 2
    }
    $saved = Save-WfNtEvidence -Plan $plan -EvidenceRoot $EvidenceRoot -NowUtc (Get-WfNtNowUtc)
    if (-not $saved.Ok) {
        Write-WfNtReport -Lines @(('REFUSED: the before-state could not be saved: ' + $saved.Reason + '. Nothing changed.')) -Secrets $secrets
        return 2
    }
    Write-WfNtReport -Lines @('', ('Saved the before-state: evidence folder ' + $saved.Stamp + ' under ' + $EvidenceRoot), ('  before-values.csv SHA-256 ' + $saved.CsvSha256)) -Secrets $secrets
    $name = $plan.Adapter.Name
    # Precheck: nothing may have moved between the save and the first write.
    $moved = @()
    foreach ($r in $plan.Settings) {
        $now = ''
        try { $now = Read-WfNtLiveValue -Name $name -Keyword $r.Keyword } catch { $now = '' }
        if ($now -ne $r.Live) { $moved += ($r.Setting.Name + ' is now ' + $now + ', saved ' + $r.Live) }
    }
    if ($moved.Count -gt 0) {
        Write-WfNtReport -Lines @(('REFUSED: a value changed after it was saved (' + ($moved -join '; ') + '). Nothing changed.')) -Secrets $secrets
        return 2
    }
    $writeFailed = $false
    foreach ($r in $plan.Settings) {
        if ($r.Action -ne 'change') { continue }
        try {
            Set-WfNtAdvancedProperty -Name $name -Keyword $r.Keyword -Value $r.Proposed
            Write-WfNtReport -Lines @(('Wrote ' + $r.Setting.Name + ': ' + $r.Live + ' to ' + $r.Proposed + ' (no adapter restart).')) -Secrets $secrets
        } catch {
            $writeFailed = $true
            Write-WfNtReport -Lines @(('WRITE FAILED for ' + $r.Setting.Name + ' (' + $_.Exception.GetType().Name + '); later settings were not written.')) -Secrets $secrets
            break
        }
    }
    $rows = @(Read-WfNtBeforeCsv -Path (Join-Path -Path $saved.Folder -ChildPath 'before-values.csv'))
    $check = Get-WfNtReadbackLines -Name $name -Rows $rows -Expect 'proposed'
    Write-WfNtReport -Lines (@('', 'Readback after Apply:') + $check.Lines) -Secrets $secrets
    if ($writeFailed -or -not $check.Ok) {
        Write-WfNtReport -Lines @(('Apply did not finish cleanly. To put back exactly what was saved, run -Undo -EvidenceFolder ' + $saved.Stamp + '.')) -Secrets $secrets
        return 1
    }
    Write-WfNtReport -Lines (@('', 'Apply done.') + (Get-WfNtRestartLines)) -Secrets $secrets
    return 0
}

function Invoke-WfNtUndo {
    param([string]$EvidenceRoot, [string]$EvidenceFolder)
    if (-not (Test-WfNtElevated)) {
        Write-WfNtReport -Lines @('REFUSED: Undo needs an elevated Windows PowerShell (Run as administrator). Nothing changed.')
        return 2
    }
    $game = Test-WfNtGameClosed
    if (-not $game.Ok) {
        Write-WfNtReport -Lines @(('REFUSED: ' + $game.Text + '. Nothing changed.'))
        return 2
    }
    $found = Find-WfNtAdapter -Adapters @(Get-WfNtEthernetAdapters)
    $secrets = @()
    if ($null -ne $found.Adapter) { $secrets = @($found.Adapter.Name, $found.Adapter.PnPDeviceID) }
    if ($null -eq $found.Adapter) {
        Write-WfNtReport -Lines (@('Checks:') + @($found.Checks | ForEach-Object { Format-WfNtCheck -Check $_ }) + @('REFUSED: the adapter precondition failed (above). Nothing changed.')) -Secrets $secrets
        return 2
    }
    $folder = Find-WfNtEvidenceFolder -EvidenceRoot $EvidenceRoot -Name $EvidenceFolder
    if ($null -eq $folder) {
        Write-WfNtReport -Lines @(('REFUSED: no complete evidence folder under ' + $EvidenceRoot + '. Nothing changed.')) -Secrets $secrets
        return 2
    }
    $stamp = Split-Path -Leaf $folder
    $evidence = Test-WfNtEvidenceFolder -Folder $folder
    if (-not $evidence.Ok) {
        Write-WfNtReport -Lines @(('REFUSED: evidence folder ' + $stamp + ' cannot be used: ' + $evidence.Reason + '. Nothing changed.')) -Secrets $secrets
        return 2
    }
    $rows = @($evidence.Rows)
    $device = Get-WfNtTextSha256 -Text $found.Adapter.PnPDeviceID
    if (@($rows | Where-Object { $_.device_sha256 -ne $device }).Count -gt 0) {
        Write-WfNtReport -Lines @(('REFUSED: evidence folder ' + $stamp + ' was saved for a different adapter. Nothing changed.')) -Secrets $secrets
        return 2
    }
    $name = $found.Adapter.Name
    Write-WfNtReport -Lines @(((Get-WfNtChangeName) + ' Undo from evidence folder ' + $stamp + '.')) -Secrets $secrets
    $todo = @()
    $bad = @()
    foreach ($row in $rows) {
        $live = ''
        try { $live = Read-WfNtLiveValue -Name $name -Keyword $row.keyword } catch { $live = '' }
        if ($live -eq $row.before_value) {
            Write-WfNtReport -Lines @(('  ' + $row.setting + ': already at the saved value ' + $live + '.')) -Secrets $secrets
        } elseif ($live -and $live -eq $row.proposed_value) {
            $todo += $row
        } else {
            $bad += ($row.setting + ' is ' + $live + ', neither the saved ' + $row.before_value + ' nor the applied ' + $row.proposed_value)
        }
    }
    if ($bad.Count -gt 0) {
        Write-WfNtReport -Lines @(('REFUSED: ' + ($bad -join '; ') + '. Something else changed it; nothing changed.')) -Secrets $secrets
        return 2
    }
    $writeFailed = $false
    foreach ($row in $todo) {
        try {
            Set-WfNtAdvancedProperty -Name $name -Keyword $row.keyword -Value $row.before_value
            Write-WfNtReport -Lines @(('Wrote ' + $row.setting + ': ' + $row.proposed_value + ' back to ' + $row.before_value + ' (no adapter restart).')) -Secrets $secrets
        } catch {
            $writeFailed = $true
            Write-WfNtReport -Lines @(('WRITE FAILED for ' + $row.setting + ' (' + $_.Exception.GetType().Name + ').')) -Secrets $secrets
        }
    }
    $check = Get-WfNtReadbackLines -Name $name -Rows $rows -Expect 'before'
    Write-WfNtReport -Lines (@('', 'Readback after Undo:') + $check.Lines) -Secrets $secrets
    if ($writeFailed -or -not $check.Ok) {
        Write-WfNtReport -Lines @('Undo did not finish cleanly; the FAIL lines above name what is left. Run -Undo again or set it by hand in Device Manager.') -Secrets $secrets
        return 1
    }
    Write-WfNtReport -Lines (@('', 'Undo done.') + (Get-WfNtRestartLines)) -Secrets $secrets
    return 0
}

function Invoke-WfNtReadback {
    # Reads only: is the applied change in place? PASS when the live value is
    # the proposed one. Uses the newest complete evidence folder for the rows;
    # without one, the settings table.
    param($Selected, [string]$EvidenceRoot)
    $found = Find-WfNtAdapter -Adapters @(Get-WfNtEthernetAdapters)
    $secrets = @()
    if ($null -ne $found.Adapter) { $secrets = @($found.Adapter.Name, $found.Adapter.PnPDeviceID) }
    if ($null -eq $found.Adapter) {
        Write-WfNtReport -Lines (@('Checks:') + @($found.Checks | ForEach-Object { Format-WfNtCheck -Check $_ }) + @('REFUSED: the adapter precondition failed (above).')) -Secrets $secrets
        return 2
    }
    $lines = @(((Get-WfNtChangeName) + ' Readback: reads only, nothing is changed.'))
    $rows = @()
    $stamp = ''
    $folder = Find-WfNtEvidenceFolder -EvidenceRoot $EvidenceRoot -Name ''
    if ($null -ne $folder) {
        $evidence = Test-WfNtEvidenceFolder -Folder $folder
        if ($evidence.Ok) {
            $stamp = Split-Path -Leaf $folder
            $rows = @($evidence.Rows)
            $lines += ('Compared with evidence folder ' + $stamp + ' (PASS means the applied value is in place).')
        }
    }
    $unresolved = @()
    if ($rows.Count -eq 0) {
        $lines += 'No usable evidence folder; compared with the proposed values (PASS means the proposed value is in place).'
        $properties = @(Get-WfNtAdvancedProperties -Name $found.Adapter.Name)
        foreach ($s in $Selected) {
            $r = Test-WfNtSetting -Setting $s -Properties $properties
            if ($r.Keyword -and $r.Proposed) {
                $rows += [pscustomobject]@{ setting = $s.Name; keyword = $r.Keyword; before_value = ''; proposed_value = $r.Proposed }
            } else {
                $why = @($r.Checks | Where-Object { -not $_.Ok } | ForEach-Object { $_.Text })
                $unresolved += ('  FAIL ' + $s.Name + ': the proposed value cannot be told (' + ($why -join '; ') + ')')
            }
        }
    }
    $check = Get-WfNtReadbackLines -Name $found.Adapter.Name -Rows $rows -Expect 'proposed'
    $lines += $check.Lines
    $lines += $unresolved
    if ($stamp) {
        $applied = [datetime]::ParseExact($stamp, 'yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        $boot = Get-WfNtLastBootUtc
        if ($null -ne $boot -and $boot -lt $applied) {
            $lines += 'Note: the PC has not restarted since Apply. Unless the adapter was disabled and enabled by hand, the new value is stored but not yet in effect.'
        }
    }
    Write-WfNtReport -Lines $lines -Secrets $secrets
    if ($check.Ok -and $unresolved.Count -eq 0) { return 0 }
    return 1
}

function Invoke-WfNtMain {
    param([string]$Verb, [string[]]$Only, [string]$EvidenceRoot, [string]$EvidenceFolder)
    $selection = Resolve-WfNtSelection -Only $Only
    if (-not $selection.Ok) {
        Write-WfNtReport -Lines @(('REFUSED: ' + $selection.Reason + '. Nothing changed.'))
        return 2
    }
    $selected = @($selection.Settings)
    switch ($Verb) {
        'Apply' { return (Invoke-WfNtApply -Selected $selected -EvidenceRoot $EvidenceRoot) }
        'Undo' { return (Invoke-WfNtUndo -EvidenceRoot $EvidenceRoot -EvidenceFolder $EvidenceFolder) }
        'Readback' { return (Invoke-WfNtReadback -Selected $selected -EvidenceRoot $EvidenceRoot) }
        default {
            $plan = Invoke-WfNtPlan -Selected $selected
            Write-WfNtReport -Lines (Get-WfNtPlanLines -Plan $plan -Elevated (Test-WfNtElevated)) -Secrets @($plan.Secrets)
            if ($plan.Ready) {
                Write-WfNtReport -Lines @('', 'RESULT: READY. Apply only on the captain''s own Yes, from an elevated console, with -Apply.') -Secrets @($plan.Secrets)
                return 0
            }
            if ($plan.NothingToDo) {
                Write-WfNtReport -Lines @('', 'RESULT: NOTHING TO DO. Every selected setting is already at its proposed value.') -Secrets @($plan.Secrets)
                return 2
            }
            Write-WfNtReport -Lines @('', 'RESULT: REFUSED. A precondition failed (above); Apply would change nothing.') -Secrets @($plan.Secrets)
            return 2
        }
    }
}

# ---------------------------------------------------------------------------
# Windows adapters. Everything below touches Windows and is replaced by
# changes/windows/tests/SyntheticNetworkTuning.ps1 in the test suite. Only
# Set-WfNtAdvancedProperty changes anything.
# ---------------------------------------------------------------------------

function Write-WfNtOut {
    param([string]$Line)
    [Console]::Out.WriteLine($Line)
}

function Get-WfNtNowUtc { return [datetime]::UtcNow }

function Test-WfNtElevated {
    # https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WfNtLastBootUtc {
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem (LastBootUpTime)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
        return ([datetime]$os.LastBootUpTime).ToUniversalTime()
    } catch {
        return $null
    }
}

function Get-WfNtProcessNames {
    # Process names only.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process
    return @(Get-Process -ErrorAction Stop | ForEach-Object { [string]$_.ProcessName })
}

function Get-WfNtEthernetAdapters {
    # Physical adapters as models. NdisPhysicalMedium 14 is 802.3; Status is
    # the operational state; DriverFileName names the driver binary.
    # https://learn.microsoft.com/powershell/module/netadapter/get-netadapter (-Physical)
    # https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
    # https://learn.microsoft.com/windows-hardware/manufacture/desktop/inbox-network-drivers (DriverFileName)
    return @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name                 = [string]$_.Name
                InterfaceDescription = [string]$_.InterfaceDescription
                DriverFileName       = [string]$_.DriverFileName
                DriverVersion        = [string]$_.DriverVersion
                PnPDeviceID          = [string]$_.PnPDeviceID
                Medium               = [uint32]$_.NdisPhysicalMedium
                Physical             = [bool]$_.ConnectorPresent
                Up                   = ([string]$_.Status -eq 'Up')
                LinkSpeed            = [string]$_.LinkSpeed
            }
        })
}

function Get-WfNtAdvancedProperties {
    # Every advanced property the installed driver exposes, hidden ones
    # included, as models.
    # https://learn.microsoft.com/powershell/module/netadapter/get-netadapteradvancedproperty (-AllProperties)
    # https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapteradvancedpropertysettingdata
    param([string]$Name)
    return @(Get-NetAdapterAdvancedProperty -Name $Name -AllProperties -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                RegistryKeyword     = [string]$_.RegistryKeyword
                RegistryValue       = @($_.RegistryValue | ForEach-Object { [string]$_ })
                RegistryDataType    = [int]$_.RegistryDataType
                DisplayName         = [string]$_.DisplayName
                DisplayValue        = [string]$_.DisplayValue
                ValidRegistryValues = @($_.ValidRegistryValues | ForEach-Object { [string]$_ })
                ValidDisplayValues  = @($_.ValidDisplayValues | ForEach-Object { [string]$_ })
            }
        })
}

function Get-WfNtAllowTurnOff {
    # Read only: "Allow the computer to turn off this device to save power".
    # The property is read only (0 Unsupported, 1 Disabled, 2 Enabled) and
    # Set-NetAdapterPowerManagement has no parameter for it.
    # https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterpowermanagementsettingdata
    param([string]$Name)
    $pm = Get-NetAdapterPowerManagement -Name $Name -ErrorAction Stop
    return [string]$pm.AllowComputerToTurnOffDevice
}

function Get-WfNtDriverKeyName {
    # DEVPKEY_Device_Driver: the registry entry name of the device's driver
    # (software) key.
    # https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-driver
    # https://learn.microsoft.com/powershell/module/pnpdevice/get-pnpdeviceproperty
    param([string]$PnPDeviceID)
    $p = Get-PnpDeviceProperty -InstanceId $PnPDeviceID -KeyName 'DEVPKEY_Device_Driver' -ErrorAction Stop
    return [string]$p.Data
}

function Export-WfNtRegistryKey {
    # reg export <key> <file> /y; returns the exit code (0 success, 1 failure).
    # https://learn.microsoft.com/windows-server/administration/windows-commands/reg-export
    param([string]$Key, [string]$File)
    $reg = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'reg.exe'
    $null = & $reg export $Key $File /y 2>&1
    return [int]$LASTEXITCODE
}

function Set-WfNtAdvancedProperty {
    # The one write: one keyword of the one adapter, never restarting it.
    # Without -NoRestart the cmdlet restarts the adapter.
    # https://learn.microsoft.com/powershell/module/netadapter/set-netadapteradvancedproperty
    param([string]$Name, [string]$Keyword, [string]$Value)
    Set-NetAdapterAdvancedProperty -Name $Name -RegistryKeyword $Keyword -RegistryValue $Value -NoRestart -ErrorAction Stop
}
