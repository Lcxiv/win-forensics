#Requires -Version 5.1
<#
.SYNOPSIS
Sets up the win-forensics SSH front door on a Windows 11 PC: OpenSSH Server reachable only from
one Mac on the home network, as a standard account that can run nothing but the dispatcher.

.DESCRIPTION
Run once, elevated, at the PC, from Windows PowerShell 5.1. Safe to run again: after a Windows
feature update, to install new collectors, or with a new Mac address or key. Every step checks
its own result, and the script ends with a PASS or FAIL summary. It never displays or stores a
password, and it changes nothing about the machine's evidence (no logs cleared, nothing repaired).

The step by step instructions for the person at the PC are in remote-access/CHECKLIST.md. The
design, with the documentation each decision rests on, is in remote-access/README.md.

.PARAMETER MacIpAddress
The IP address the Mac has on the home network, for example the value "ipconfig getifaddr en0"
prints on the Mac. Inbound SSH is allowed from this address only.

.PARAMETER MacPublicKeyFile
Path of the Mac's PUBLIC key file (its name ends in .pub). Never give this script a private key.

.PARAMETER AccountName
Name of the dedicated standard account. Lower case letters and digits, 3 to 20 characters.

.PARAMETER CollectorSource
Directory holding collector scripts to install (<name>.ps1). Defaults to collectors\windows next
to the remote-access directory this script sits in. It may be missing or empty.

.PARAMETER SkipSelfTest
Skip the loopback self test (a throwaway key, a connection to 127.0.0.1, then cleanup). The run
then ends INCOMPLETE, not PASS: the self test is what proves the front door works.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\remote-access\windows\Install-FrontDoor.ps1 -MacIpAddress <MAC_LAN_ADDRESS> -MacPublicKeyFile .\mac-public-key.pub
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MacIpAddress,
    [Parameter(Mandatory = $true)][string]$MacPublicKeyFile,
    [string]$AccountName = 'wfcollector',
    [string]$CollectorSource = '',
    [switch]$SkipSelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WfCommon.ps1')
. (Join-Path $PSScriptRoot 'WfSetupLib.ps1')

# ---------------------------------------------------------------------------------------------
# Step bookkeeping
# ---------------------------------------------------------------------------------------------

$script:WfSteps = New-Object System.Collections.Generic.List[object]
$script:WfCurrentStep = $null
$script:WfAbort = $false

function Add-WfNote {
    param([Parameter(Mandatory = $true)][string]$Text)
    $script:WfCurrentStep.Details.Add($Text)
    Write-Host "      $Text"
}

function Add-WfWarning {
    param([Parameter(Mandatory = $true)][string]$Text)
    $script:WfCurrentStep.Details.Add("warning: $Text")
    if ($script:WfCurrentStep.Status -eq 'PASS') { $script:WfCurrentStep.Status = 'WARN' }
    Write-Host "      warning: $Text" -ForegroundColor Yellow
}

function Add-WfIncomplete {
    # An essential verification could not be performed. The step did not fail, but it did not
    # prove what it is there to prove, so the run cannot end in PASS (see Get-WfSummaryResult).
    param([Parameter(Mandatory = $true)][string]$Text)
    $script:WfCurrentStep.Details.Add("not verified: $Text")
    if ($script:WfCurrentStep.Status -ne 'FAIL') { $script:WfCurrentStep.Status = 'INCOMPLETE' }
    Write-Host "      not verified: $Text" -ForegroundColor Yellow
}

function Invoke-WfFailClosed {
    # Leave the machine with no SSH listener: stop sshd and keep it from starting with Windows.
    # Used when a check finds the front door cannot be made as narrow as intended.
    param([Parameter(Mandatory = $true)][string]$Reason)
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        Set-Service -Name sshd -StartupType Manual
        if ($service.Status -ne 'Stopped') { Stop-Service -Name sshd -Force }
    }
    throw "$Reason. sshd is stopped and will not start with Windows until this is fixed and the script runs again"
}

function Invoke-WfStep {
    # Run one step. A step fails by throwing; its message becomes the "what happened" line. After
    # a failure the remaining steps are not run and are reported as SKIP.
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $record = [pscustomobject]@{
        Id      = $Id
        Title   = $Title
        Status  = 'PASS'
        Details = New-Object System.Collections.Generic.List[string]
    }
    $script:WfSteps.Add($record)
    $script:WfCurrentStep = $record
    if ($script:WfAbort) {
        $record.Status = 'SKIP'
        return
    }
    Write-Host ''
    Write-Host "[$Id] $Title"
    try {
        & $Action
    } catch {
        $record.Status = 'FAIL'
        $record.Details.Add("what happened: $($_.Exception.Message)")
        Write-Host "      FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $script:WfAbort = $true
        return
    }
    if ($record.Status -eq 'PASS') { Write-Host '      ok' -ForegroundColor Green }
}

function Invoke-WfChecked {
    # Run a native tool and throw with its output when it exits non-zero.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 120,
        [Parameter(Mandatory = $true)][string]$What
    )
    $run = Invoke-WfNative -FilePath $FilePath -ArgumentList $ArgumentList -TimeoutSeconds $TimeoutSeconds
    if ($run.TimedOut) { throw "$What did not finish within $TimeoutSeconds seconds" }
    if ($run.ExitCode -ne 0) {
        $text = (($run.StdOut + ' ' + $run.StdErr) -replace '\s+', ' ').Trim()
        throw "$What failed (exit code $($run.ExitCode)): $text"
    }
    return $run
}

# ---------------------------------------------------------------------------------------------
# Small wrappers around Windows state. Kept thin so the tests can replace them.
# ---------------------------------------------------------------------------------------------

function Get-WfSidAccessRule {
    # The explicit and inherited allow rules of a file or directory as { Sid, Rights }, plus the
    # owner's SID.
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($rule in @($acl.GetAccessRules($true, $true, $sidType))) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $rules.Add(@{ Sid = $rule.IdentityReference.Value; Rights = [long][int]$rule.FileSystemRights })
    }
    return @{
        Owner     = $acl.GetOwner($sidType).Value
        Protected = $acl.AreAccessRulesProtected
        Rules     = $rules.ToArray()
    }
}

function Set-WfDirectoryAcl {
    # Replace a directory's owner and whole access list: SYSTEM and Administrators full control
    # (inherited by everything inside), plus one rule for the collector account. Inheritance from
    # the parent is switched off, so nothing granted higher up (ProgramData lets every user
    # create files) leaks in. The access list is written whole rather than edited, so entries
    # left by anything earlier do not survive.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AccountSid,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemRights]$AccountRights,
        [switch]$AccountRuleInherits
    )
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $inheritAll = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $noInherit = [System.Security.AccessControl.InheritanceFlags]::None
    $noPropagation = [System.Security.AccessControl.PropagationFlags]::None
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $account = New-Object System.Security.Principal.SecurityIdentifier($AccountSid)
    $accountInherit = $noInherit
    if ($AccountRuleInherits) { $accountInherit = $inheritAll }

    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($admins)
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $full, $inheritAll, $noPropagation, $allow)))
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $full, $inheritAll, $noPropagation, $allow)))
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($account, $AccountRights, $accountInherit, $noPropagation, $allow)))
    [System.IO.Directory]::SetAccessControl($Path, $security)
}

function Set-WfKeyFileAcl {
    # authorized_keys: SYSTEM and Administrators full control, the account read, nobody else, no
    # inheritance, owned by Administrators. Win32-OpenSSH refuses a key file that is owned by, or
    # writable by, anyone other than SYSTEM, Administrators, and the account itself; the wiki
    # words it more strictly ("should not ... provide access to any other user"), so this grants
    # no one else anything.
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-sshfileperm.c#L65-L160
    # https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AccountSid
    )
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $account = New-Object System.Security.Principal.SecurityIdentifier($AccountSid)
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($admins)
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, [System.Security.AccessControl.FileSystemRights]::FullControl, $allow)))
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, [System.Security.AccessControl.FileSystemRights]::FullControl, $allow)))
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($account, [System.Security.AccessControl.FileSystemRights]::Read, $allow)))
    [System.IO.File]::SetAccessControl($Path, $security)
}

function Assert-WfAcl {
    # Verify owner and access rules of one path, or throw naming what is wrong.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AccountSid,
        [switch]$AccountMayWrite,
        [switch]$OthersMayRead
    )
    $acl = Get-WfSidAccessRule -Path $Path
    if (@('S-1-5-32-544', 'S-1-5-18') -notcontains $acl.Owner) {
        throw "$Path is owned by $($acl.Owner), not by Administrators or SYSTEM"
    }
    $violations = @(Test-WfAclRule -Rules $acl.Rules -AccountSid $AccountSid -AccountMayWrite:$AccountMayWrite -OthersMayRead:$OthersMayRead)
    if ($violations.Count -gt 0) { throw "$Path has unsafe permissions: $($violations -join '; ')" }
}

function Get-WfLocalGroupMembership {
    # The complete membership of every local group, as { Sid; MemberSids } records, read
    # through the ADSI WinNT provider (IADsGroup::Members). The check that consumes this needs
    # every group; if any group cannot be enumerated the function throws, and the caller fails
    # rather than treating a partial list as the truth. Get-LocalGroupMember is tried second
    # because it fails on a group holding an entry for a deleted account.
    # https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsgroup-members
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1
    $groups = New-Object System.Collections.Generic.List[object]
    try {
        $computer = [ADSI]("WinNT://$env:COMPUTERNAME,computer")
        foreach ($child in @($computer.psbase.Children)) {
            if ($child.psbase.SchemaClassName -ne 'Group') { continue }
            $sidBytes = $child.psbase.InvokeGet('objectSid')
            $groupSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $members = New-Object System.Collections.Generic.List[string]
            foreach ($member in @($child.psbase.Invoke('Members'))) {
                $memberSid = $member.GetType().InvokeMember('objectSid', [System.Reflection.BindingFlags]::GetProperty, $null, $member, $null)
                $members.Add((New-Object System.Security.Principal.SecurityIdentifier($memberSid, 0)).Value)
            }
            $groups.Add(@{ Sid = $groupSid; MemberSids = $members.ToArray() })
        }
        if ($groups.Count -eq 0) { throw 'ADSI listed no local groups' }
        return $groups.ToArray()
    } catch {
        $adsiError = $_.Exception.Message
        $groups.Clear()
    }
    foreach ($group in @(Get-LocalGroup)) {
        $members = New-Object System.Collections.Generic.List[string]
        foreach ($member in @(Get-LocalGroupMember -SID $group.SID.Value -ErrorAction Stop)) {
            $members.Add([string]$member.SID.Value)
        }
        $groups.Add(@{ Sid = [string]$group.SID.Value; MemberSids = $members.ToArray() })
    }
    if ($groups.Count -eq 0) { throw "no local group could be enumerated (ADSI said: $adsiError)" }
    return $groups.ToArray()
}

function ConvertTo-WfFirewallRuleInfo {
    # Flatten one firewall rule and its port, application, service, and address filters into a
    # hashtable for Get-WfFirewallPlan. A rule whose filters are missing is marked Unclassified
    # so the planner fails closed on it rather than guessing.
    param(
        [Parameter(Mandatory = $true)]$Rule,
        [AllowNull()]$PortFilter,
        [AllowNull()]$ApplicationFilter,
        [AllowNull()]$ServiceFilter,
        [AllowNull()]$AddressFilter
    )
    $info = @{
        Name                  = [string]$Rule.Name
        DisplayName           = [string]$Rule.DisplayName
        Enabled               = ([string]$Rule.Enabled -eq 'True')
        Direction             = [string]$Rule.Direction
        Action                = [string]$Rule.Action
        Profile               = [string]$Rule.Profile
        PolicyStoreSourceType = [string]$Rule.PolicyStoreSourceType
        Protocol              = ''
        LocalPort             = [string[]]@()
        Program               = ''
        Package               = ''
        Service               = ''
        RemoteAddress         = [string[]]@()
        Unclassified          = ''
    }
    $missing = New-Object System.Collections.Generic.List[string]
    if ($null -eq $PortFilter) { $missing.Add('port filter') } else {
        $info.Protocol = [string]$PortFilter.Protocol
        $info.LocalPort = [string[]]@($PortFilter.LocalPort | ForEach-Object { [string]$_ })
    }
    if ($null -eq $ApplicationFilter) { $missing.Add('application filter') } else {
        $info.Program = [string]$ApplicationFilter.Program
        $info.Package = [string]$ApplicationFilter.Package
    }
    if ($null -eq $ServiceFilter) { $missing.Add('service filter') } else {
        $info.Service = [string]$ServiceFilter.Service
    }
    if ($null -eq $AddressFilter) { $missing.Add('address filter') } else {
        $info.RemoteAddress = [string[]]@($AddressFilter.RemoteAddress | ForEach-Object { [string]$_ })
    }
    if ($missing.Count -gt 0) { $info.Unclassified = 'missing ' + ($missing.ToArray() -join ', ') }
    return $info
}

function Get-WfInboundAllowRule {
    # The complete inventory of enabled inbound allow rules in effect (the ActiveStore, which
    # includes rules delivered by policy), each with its filters. The filters are fetched once
    # each and joined to their rule by InstanceID, which the filter objects share with the rule
    # they belong to; a rule with no matching filter is asked for its filters directly, and one
    # that still has none is reported unclassified.
    # https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True)
    $ports = @{}
    foreach ($filter in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -All)) { $ports[[string]$filter.InstanceID] = $filter }
    $applications = @{}
    foreach ($filter in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All)) { $applications[[string]$filter.InstanceID] = $filter }
    $services = @{}
    foreach ($filter in @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore -All)) { $services[[string]$filter.InstanceID] = $filter }
    $addresses = @{}
    foreach ($filter in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -All)) { $addresses[[string]$filter.InstanceID] = $filter }
    $infos = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rules) {
        $id = [string]$rule.InstanceID
        $port = $ports[$id]
        $application = $applications[$id]
        $service = $services[$id]
        $address = $addresses[$id]
        if ($null -eq $port) { $port = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)[0] }
        if ($null -eq $application) { $application = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)[0] }
        if ($null -eq $service) { $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue)[0] }
        if ($null -eq $address) { $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)[0] }
        $infos.Add((ConvertTo-WfFirewallRuleInfo -Rule $rule -PortFilter $port -ApplicationFilter $application -ServiceFilter $service -AddressFilter $address))
    }
    return $infos.ToArray()
}

function Update-WfSshdConfigFile {
    # Put new text into sshd_config safely:
    #   1. write it next to the live file and ask sshd to validate that copy (sshd -t -f);
    #      if sshd rejects it, the live file is never touched
    #   2. keep the first ever original as sshd_config.wf-original and the current file as
    #      sshd_config.wf-previous
    #   3. replace the live file, validate again, and put the previous file back if that fails
    # sshd -t: "Test mode. Only check the validity of the configuration file and sanity of the
    # keys." https://man.openbsd.org/sshd#t
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$NewText,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )
    $result = @{ Changed = $false; Restored = $false; Problem = ''; Output = '' }
    $existing = [System.IO.File]::ReadAllText($ConfigPath)
    if ($existing -ceq $NewText) {
        $live = Invoke-WfNative -FilePath $SshdExe -ArgumentList @('-t', '-f', $ConfigPath) -TimeoutSeconds 60
        if ($live.ExitCode -ne 0) {
            $result.Problem = 'sshd rejects the existing configuration'
            $result.Output = ($live.StdOut + $live.StdErr).Trim()
        }
        return $result
    }
    $candidate = $ConfigPath + '.wf-candidate'
    Write-WfTextFile -Path $candidate -Text $NewText
    try {
        $check = Invoke-WfNative -FilePath $SshdExe -ArgumentList @('-t', '-f', $candidate) -TimeoutSeconds 60
    } finally {
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
    }
    if ($check.ExitCode -ne 0) {
        $result.Problem = 'sshd rejected the new configuration; the live sshd_config was not changed'
        $result.Output = ($check.StdOut + $check.StdErr).Trim()
        return $result
    }
    $original = $ConfigPath + '.wf-original'
    if (-not (Test-Path -LiteralPath $original) -and $existing -notmatch '# BEGIN win-forensics front door') {
        Copy-Item -LiteralPath $ConfigPath -Destination $original
    }
    $previous = $ConfigPath + '.wf-previous'
    Copy-Item -LiteralPath $ConfigPath -Destination $previous -Force
    Write-WfTextFile -Path $ConfigPath -Text $NewText
    $recheck = Invoke-WfNative -FilePath $SshdExe -ArgumentList @('-t', '-f', $ConfigPath) -TimeoutSeconds 60
    if ($recheck.ExitCode -ne 0) {
        Copy-Item -LiteralPath $previous -Destination $ConfigPath -Force
        $result.Restored = $true
        $result.Problem = 'sshd rejected the configuration once it was in place; the previous sshd_config was restored'
        $result.Output = ($recheck.StdOut + $recheck.StdErr).Trim()
        return $result
    }
    $result.Changed = $true
    return $result
}

function Set-WfAuthorizedKey {
    # Write authorized_keys whole (never appended to), without a byte order mark, then lock it down.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$AccountSid
    )
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Write-WfTextFile -Path $Path -Text (($Lines -join "`n") + "`n")
    Set-WfKeyFileAcl -Path $Path -AccountSid $AccountSid
}

function Get-WfSshdLogTail {
    param([Parameter(Mandatory = $true)][string]$LogPath, [int]$Lines = 15)
    if (-not (Test-Path -LiteralPath $LogPath)) { return @() }
    return @(Get-Content -LiteralPath $LogPath -Tail $Lines -ErrorAction SilentlyContinue)
}

# ---------------------------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------------------------

function Invoke-WfPreflight {
    param([Parameter(Mandatory = $true)][hashtable]$Context)

    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'this must run in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7 (pwsh.exe). Use the exact command in the checklist'
    }
    if (-not [System.Environment]::Is64BitProcess) {
        # The LocalAccounts module "isn't available in 32-bit PowerShell on a 64-bit system".
        throw 'this is a 32 bit PowerShell. Open "Terminal (Admin)" or "Windows PowerShell" (not the x86 one) and run the command again'
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'this window is not running as Administrator. Right click the Start button, choose "Terminal (Admin)", and run the command again'
    }
    if ([System.Environment]::OSVersion.Version.Build -lt 17763) {
        throw 'this Windows is older than build 17763; the OpenSSH Server feature needs Windows 10 version 1809 or later'
    }

    # A Group Policy execution policy beats the -ExecutionPolicy value on the forced command line.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
    foreach ($scope in @('MachinePolicy', 'UserPolicy')) {
        $policy = [string](Get-ExecutionPolicy -Scope $scope)
        if (@('Restricted', 'AllSigned') -contains $policy) {
            throw "Group Policy sets the PowerShell execution policy to $policy (scope $scope), which would stop the dispatcher from running. This machine is managed in a way this script does not handle"
        }
    }

    if (-not (Test-WfAccountName -Name $Context.AccountName)) {
        throw "account name '$($Context.AccountName)' is not usable: lower case letters and digits only, starting with a letter, 3 to 20 characters"
    }
    $address = Get-WfIPv4Info -Text $Context.MacIpAddress
    if (-not $address.Valid) { throw "-MacIpAddress '$($Context.MacIpAddress)': $($address.Reason)" }
    if ($address.Warning -ne '') { Add-WfWarning "-MacIpAddress: $($address.Warning)" }

    if (-not (Test-Path -LiteralPath $Context.MacPublicKeyFile -PathType Leaf)) {
        throw "-MacPublicKeyFile '$($Context.MacPublicKeyFile)' does not exist. Give the path of the .pub file copied from the Mac"
    }
    $Context.MacKey = Read-WfPublicKey -Text ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Context.MacPublicKeyFile).Path))
    Add-WfNote "Mac public key fingerprint: $($Context.MacKey.Fingerprint) (compare with the line the Mac printed)"

    foreach ($file in @('dispatch.ps1', 'WfCommon.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Context.SourceDir $file) -PathType Leaf)) {
            throw "$file is missing next to this script; copy the whole kit folder, not single files"
        }
    }

    $own = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { [string]$_.IPAddress })
    if ($own -contains $Context.MacIpAddress) {
        throw "-MacIpAddress $($Context.MacIpAddress) is this PC's own address. It must be the Mac's address"
    }

    # The network the Mac is reached through must be set to Private: the firewall rule this
    # script creates applies to the Private profile only.
    # https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/
    $route = @(Find-NetRoute -RemoteIPAddress $Context.MacIpAddress | Select-Object -First 1)
    if ($route.Count -eq 0) { throw "this PC has no network route to $($Context.MacIpAddress). Check the address and that both machines are on the home network" }
    $interfaceIndex = $route[0].InterfaceIndex
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $interfaceIndex -ErrorAction SilentlyContinue)
    if ($profiles.Count -eq 0) { throw "the network adapter used to reach the Mac (interface $interfaceIndex) has no network profile; is it connected?" }
    $category = [string]$profiles[0].NetworkCategory
    $Context.InterfaceAlias = [string]$profiles[0].InterfaceAlias
    if ($category -ne 'Private') {
        throw "the network '$($profiles[0].Name)' on adapter '$($profiles[0].InterfaceAlias)' is set to $category, not Private. Nothing was changed. If this is your home network, set it to Private (Settings > Network & internet > your connection > Network profile type > Private network, or run: Set-NetConnectionProfile -InterfaceIndex $interfaceIndex -NetworkCategory Private) and run this script again"
    }
    Add-WfNote "network '$($profiles[0].Name)' on adapter '$($profiles[0].InterfaceAlias)' is Private"

    $firewall = Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private
    if ([string]$firewall.Enabled -ne 'True') {
        throw 'Windows Firewall is turned off for Private networks, so the rule limiting SSH to the Mac would not be enforced. Nothing was changed. Turn the firewall on (Windows Security > Firewall & network protection > Private network) and run this script again'
    }
    if ([string]$firewall.DefaultInboundAction -eq 'Allow') {
        throw 'Windows Firewall is set to allow all inbound connections on Private networks, so the rule limiting SSH to the Mac would mean nothing. Nothing was changed'
    }
}

function Install-WfOpenSshServer {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $capabilities = @(Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' })
        if ($capabilities.Count -eq 0) { throw 'Windows does not list the OpenSSH Server optional feature on this machine' }
        $capability = $capabilities[0]
        if ([string]$capability.State -ne 'Installed') {
            Add-WfNote "installing $($capability.Name) (downloads from Windows Update; this can take a few minutes)"
            $added = Add-WindowsCapability -Online -Name $capability.Name
            $Context.State.capability_installed_by_this_script = $true
            if ($added.RestartNeeded) { Add-WfWarning 'Windows says a restart is needed to finish installing OpenSSH Server. Restart, then run this script again' }
        }
        $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($null -eq $service) { throw 'the sshd service does not exist after installing OpenSSH Server. Restart Windows and run this script again' }
    } else {
        Add-WfNote 'the sshd service already exists'
    }
    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
    $pathName = [string]$wmi.PathName
    if ($pathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] } else { $exe = ($pathName.Trim() -split '\s+')[0] }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "the sshd service points at '$exe', which does not exist" }
    $Context.SshdExe = $exe
    Add-WfNote "sshd: $exe, version $((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion)"
}

function Set-WfFirewall {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # Done while sshd is not listening: the OpenSSH Server install "creates and enables a
    # firewall rule named OpenSSH-Server-In-TCP" open to every address and profile.
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
    $ownName = $Context.FirewallRuleName
    if ($null -ne (Get-NetFirewallRule -Name $ownName -ErrorAction SilentlyContinue)) {
        Remove-NetFirewallRule -Name $ownName
    }
    $ruleParams = @{
        Name          = $ownName
        DisplayName   = 'win-forensics SSH front door (Mac only)'
        Description   = 'Inbound SSH from one address on Private networks. Managed by Install-FrontDoor.ps1.'
        Group         = 'win-forensics'
        Direction     = 'Inbound'
        Action        = 'Allow'
        Protocol      = 'TCP'
        LocalPort     = 22
        RemoteAddress = $Context.MacIpAddress
        Profile       = 'Private'
        Enabled       = 'True'
    }
    [void](New-NetFirewallRule @ruleParams)

    # Every other enabled inbound allow rule that would admit TCP 22 to sshd is disabled, whatever
    # it is called. One that cannot be disabled (delivered by policy, or unreadable) means the
    # front door cannot be narrowed to the Mac, so the run fails closed.
    $plan = Get-WfFirewallPlan -Rules (Get-WfInboundAllowRule) -OwnRuleName $ownName
    foreach ($name in @($plan.Disable)) {
        Disable-NetFirewallRule -Name $name
        Add-WfNote "disabled the firewall rule '$name' (it allowed inbound SSH from more than the Mac)"
        if ($Context.State.disabled_firewall_rules -notcontains $name) { $Context.State.disabled_firewall_rules += $name }
    }
    if (@($plan.FailClosed).Count -gt 0) {
        Invoke-WfFailClosed -Reason "inbound SSH cannot be limited to the Mac: $(@($plan.FailClosed) -join '; ')"
    }

    # Verify against a fresh, complete inventory.
    $after = @(Get-WfInboundAllowRule)
    $leftover = Get-WfFirewallPlan -Rules $after -OwnRuleName $ownName
    if (@($leftover.Disable).Count -gt 0 -or @($leftover.FailClosed).Count -gt 0) {
        Invoke-WfFailClosed -Reason "these firewall rules still admit inbound SSH: $((@($leftover.Disable) + @($leftover.FailClosed)) -join '; ')"
    }
    $ownInfo = @($after | Where-Object { $_.Name -eq $ownName })
    if ($ownInfo.Count -ne 1) { Invoke-WfFailClosed -Reason "the firewall rule '$ownName' was not found after creating it" }
    $problems = @(Test-WfOwnFirewallRule -Rule $ownInfo[0] -MacAddress $Context.MacIpAddress)
    if ($problems.Count -gt 0) { Invoke-WfFailClosed -Reason "the firewall rule '$ownName' is not as intended: $($problems -join '; ')" }
    Add-WfNote "inbound TCP 22 is allowed only from $($Context.MacIpAddress), only on Private networks (rule '$ownName'); $($after.Count) enabled inbound allow rules were inspected"
}

function Start-WfSshd {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # The first start of sshd creates the host keys and the default sshd_config; that is all this
    # step wants from it. The service is then stopped again and kept from starting with Windows,
    # so that nothing listens with the stock configuration (password authentication on, every
    # account allowed) while S5 to S8 prepare the hardened one. S9 is the first start with it.
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement
    Set-Service -Name sshd -StartupType Manual
    if ((Get-Service -Name sshd).Status -ne 'Running') { Start-Service -Name sshd }
    $hostKey = Join-Path $Context.Layout.SshDir 'ssh_host_ed25519_key.pub'
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $hostKey) -and (Test-Path -LiteralPath $Context.Layout.SshdConfig)) { break }
        Start-Sleep -Milliseconds 500
    }
    $configExists = Test-Path -LiteralPath $Context.Layout.SshdConfig
    $keyExists = Test-Path -LiteralPath $hostKey
    Stop-Service -Name sshd -Force
    $service = Get-Service -Name sshd
    if ($service.Status -ne 'Stopped') { throw "the sshd service is $($service.Status) after being told to stop" }
    if (-not $configExists) { throw "sshd did not create $($Context.Layout.SshdConfig)" }
    if (-not $keyExists) { throw "sshd did not create its Ed25519 host key ($hostKey)" }
    Add-WfNote 'host keys and the default sshd_config exist; sshd is stopped until the hardened configuration is in place'
}

function Set-WfDefaultShell {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # The four values Win32-OpenSSH reads under this key: https://github.com/PowerShell/Win32-OpenSSH/wiki/DefaultShell
    $keyPath = 'HKLM:\SOFTWARE\OpenSSH'
    $names = @('DefaultShell', 'DefaultShellCommandOption', 'DefaultShellArguments', 'DefaultShellEscapeArguments')
    $current = @{}
    foreach ($name in $names) { $current[$name] = $null }
    if (Test-Path -LiteralPath $keyPath) {
        # Get-ItemProperty returns nothing for a key that has no values.
        $key = Get-ItemProperty -LiteralPath $keyPath
        if ($null -ne $key) {
            foreach ($name in $names) {
                $property = $key.PSObject.Properties[$name]
                if ($null -ne $property) { $current[$name] = [string]$property.Value }
            }
        }
    }
    $cmd = Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe'
    $decision = Get-WfDefaultShellDecision -DefaultShell $current.DefaultShell -DefaultShellCommandOption $current.DefaultShellCommandOption -SystemCmdPath $cmd
    Add-WfNote $decision.Reason
    if ($decision.Action -eq 'remove') {
        if ($null -eq $Context.State.previous_default_shell) { $Context.State.previous_default_shell = $current }
        foreach ($name in $names) {
            Remove-ItemProperty -LiteralPath $keyPath -Name $name -ErrorAction SilentlyContinue
        }
        $after = Get-ItemProperty -LiteralPath $keyPath
        if ($null -ne $after) {
            foreach ($name in $names) {
                if ($null -ne $after.PSObject.Properties[$name]) { throw "could not remove the $name registry value" }
            }
        }
        Add-WfWarning "the previous default SSH shell ('$($current.DefaultShell)') and its options were removed; their values are recorded in install-state.json"
    }
}

function Set-WfAccount {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $name = $Context.AccountName
    $marker = 'win-forensics SSH collector (key only)'
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $user) {
        # See New-WfRandomPassword for why the account has a password nobody knows.
        $password = New-WfRandomPassword
        try {
            $user = New-LocalUser -Name $name -Password $password -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires -FullName 'win-forensics collector' -Description $marker
        } finally {
            $password.Dispose()
        }
        $Context.State.account_created_by_this_script = $true
        Add-WfNote "created the standard account '$name' (its password is random and was not shown or saved)"
    } else {
        if ([string]$user.Description -ne $marker) {
            throw "an account named '$name' already exists and was not created by this script. Nothing was changed for it. Remove it, or run again with -AccountName and another name"
        }
        Set-LocalUser -Name $name -PasswordNeverExpires $true
        if (-not $user.Enabled) {
            Enable-LocalUser -Name $name
            Add-WfNote "the account '$name' was disabled and has been enabled again"
        }
    }
    $Context.AccountSid = $user.SID.Value

    # Event Log Readers, by SID because the group's name is localized. Nothing else.
    $readers = 'S-1-5-32-573'
    $groups = @(Get-WfLocalGroupMembership)
    $readersGroup = @($groups | Where-Object { $_.Sid -eq $readers })
    if ($readersGroup.Count -eq 0) { throw 'the Event Log Readers group (S-1-5-32-573) was not found among the local groups' }
    if (@($readersGroup[0].MemberSids) -notcontains $Context.AccountSid) {
        Add-LocalGroupMember -SID $readers -Member $name
        $groups = @(Get-WfLocalGroupMembership)
    }

    # Verify against the exact baseline (Test-WfAccountGroupBaseline): Event Log Readers, the
    # unavoidable Users membership through Authenticated Users, and nothing else. Any other group
    # fails the step, because the group's rights would become the account's.
    $user = Get-LocalUser -Name $name
    if (-not $user.Enabled) { throw "the account '$name' is disabled" }
    if ($null -ne $user.PasswordExpires) { throw "the account '$name' still has a password expiry date" }
    $violations = @(Test-WfAccountGroupBaseline -Groups $groups -AccountSid $Context.AccountSid)
    if ($violations.Count -gt 0) {
        throw "the account '$name' does not match the group baseline (Event Log Readers only): $($violations -join '; '). Remove it from those groups, or remove the well known members from them, and run again"
    }
    Add-WfNote "account '$name': standard, enabled, password never expires, member of Event Log Readers and of no other group ($($groups.Count) local groups checked)"
}

function Install-WfLayout {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $layout = $Context.Layout
    $sid = $Context.AccountSid
    $rights = [System.Security.AccessControl.FileSystemRights]

    foreach ($dir in @($layout.Root, $layout.Remote, $layout.Outbox)) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { [void](New-Item -ItemType Directory -Path $dir) }
    }
    # Permissions first, files second, so that nothing is ever copied into a writable directory.
    Set-WfDirectoryAcl -Path $layout.Root -AccountSid $sid -AccountRights $rights::ReadAndExecute
    Set-WfDirectoryAcl -Path $layout.Remote -AccountSid $sid -AccountRights $rights::ReadAndExecute -AccountRuleInherits
    Set-WfDirectoryAcl -Path $layout.Outbox -AccountSid $sid -AccountRights $rights::Modify -AccountRuleInherits

    # Replace the dispatcher files and mirror the collectors: the installed set is exactly what
    # this kit holds. New files inherit the directory's permissions. Unblock-File removes the
    # "downloaded from the internet" mark a file may carry, so that the RemoteSigned execution
    # policy the forced command runs under accepts it.
    foreach ($file in @('dispatch.ps1', 'WfCommon.ps1')) {
        $target = Join-Path $layout.Remote $file
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
        Copy-Item -LiteralPath (Join-Path $Context.SourceDir $file) -Destination $target
        Unblock-File -LiteralPath $target
    }
    if (Test-Path -LiteralPath $layout.Collectors) { Remove-Item -LiteralPath $layout.Collectors -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $layout.Collectors)
    # Every .ps1 directly in the source directory is installed, never its subdirectories (the
    # collectors' tests live in one). A file whose name matches the collector name pattern
    # becomes a verb; any other, such as the collectors' shared helper _common.ps1, is installed
    # next to them so they can load it, and can never be asked for by name.
    $installed = New-Object System.Collections.Generic.List[string]
    $helpers = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $Context.CollectorSource -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $Context.CollectorSource -Filter '*.ps1' -File | Sort-Object -Property Name)) {
            $target = Join-Path $layout.Collectors $file.Name
            Copy-Item -LiteralPath $file.FullName -Destination $target
            Unblock-File -LiteralPath $target
            if (Test-WfCollectorName -Name $file.BaseName) { $installed.Add($file.BaseName) } else { $helpers.Add($file.Name) }
        }
    }
    if ($installed.Count -eq 0) {
        Add-WfNote 'no collectors in this kit yet; "collect-<name>" will answer "unknown collector" until a later kit installs them'
    } else {
        Add-WfNote "collectors installed: $($installed.ToArray() -join ', ')"
    }
    if ($helpers.Count -gt 0) { Add-WfNote "helper files installed next to them (not verbs): $($helpers.ToArray() -join ', ')" }

    # Verify: nobody but SYSTEM and Administrators can change anything the forced command runs.
    Assert-WfAcl -Path $layout.Root -AccountSid $sid
    Assert-WfAcl -Path $layout.Remote -AccountSid $sid
    Assert-WfAcl -Path $layout.Collectors -AccountSid $sid
    foreach ($file in @(Get-ChildItem -LiteralPath $layout.Remote -Recurse -File)) {
        Assert-WfAcl -Path $file.FullName -AccountSid $sid
    }
    Assert-WfAcl -Path $layout.Outbox -AccountSid $sid -AccountMayWrite
    $Context.DispatcherSha256 = Get-WfFileSha256 -Path $layout.Dispatcher
    Add-WfNote "dispatcher installed at $($layout.Dispatcher)"
    Add-WfNote "dispatcher SHA-256: $($Context.DispatcherSha256)"
}

function Install-WfAuthorizedKey {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $powerShellExe = Join-Path ([System.Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) { throw "Windows PowerShell was not found at $powerShellExe" }
    $Context.ForcedCommand = Get-WfForcedCommand -PowerShellExe $powerShellExe -DispatcherPath $Context.Layout.Dispatcher
    $Context.MacKeyLine = Format-WfAuthorizedKeysLine -ForcedCommand $Context.ForcedCommand -FromAddress $Context.MacIpAddress -KeyBase64 $Context.MacKey.KeyBase64
    Set-WfAuthorizedKey -Path $Context.Layout.AuthorizedKeys -Lines @($Context.MacKeyLine) -AccountSid $Context.AccountSid

    # Verify: content read back, no byte order mark, strict permissions.
    $bytes = [System.IO.File]::ReadAllBytes($Context.Layout.AuthorizedKeys)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { throw 'authorized_keys starts with a byte order mark' }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($text -cne ($Context.MacKeyLine + "`n")) { throw 'authorized_keys does not contain exactly the one expected line' }
    Assert-WfAcl -Path $Context.Layout.AuthorizedKeys -AccountSid $Context.AccountSid
    Add-WfNote 'one key installed, limited to the dispatcher (command=), to no forwarding or terminal (restrict), and to the Mac''s address (from=)'
}

function Set-WfSshdConfig {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $configPath = $Context.Layout.SshdConfig
    $existing = [System.IO.File]::ReadAllText($configPath)
    foreach ($conflict in @(Find-WfSshdConfigConflict -Text $existing -AccountName $Context.AccountName)) { Add-WfWarning $conflict }
    $globalBlock = @(Format-WfSshdGlobalBlock -AccountName $Context.AccountName)
    $matchBlock = @(Format-WfSshdMatchBlock -AccountName $Context.AccountName -ForcedCommand $Context.ForcedCommand -AuthorizedKeysFileToken (Get-WfAuthorizedKeysFileToken))
    $newText = Merge-WfSshdConfig -Existing $existing -GlobalBlock $globalBlock -MatchBlock $matchBlock
    $update = Update-WfSshdConfigFile -ConfigPath $configPath -NewText $newText -SshdExe $Context.SshdExe
    if ($update.Problem -ne '') { throw "$($update.Problem). sshd said: $($update.Output)" }
    if ($update.Changed) { Add-WfNote 'sshd_config updated (original kept as sshd_config.wf-original)' } else { Add-WfNote 'sshd_config already up to date' }

    # What sshd itself says applies to this account when it connects from the Mac, read before
    # anything listens. sshd -T with -C: https://man.openbsd.org/sshd#C . addr and host are the
    # client's; the server side laddr and lport are optional and left out.
    $spec = 'user={0},host={1},addr={1}' -f $Context.AccountName, $Context.MacIpAddress
    $dump = Invoke-WfNative -FilePath $Context.SshdExe -ArgumentList @('-T', '-f', $configPath, '-C', $spec) -TimeoutSeconds 60
    if ($dump.ExitCode -ne 0) {
        Add-WfIncomplete "sshd -T did not report the effective configuration (exit code $($dump.ExitCode): $(($dump.StdErr + $dump.StdOut).Trim()))"
    } else {
        $effective = Test-WfSshdEffectiveConfig -Dump (ConvertFrom-WfSshdDump -Text $dump.StdOut) -AccountName $Context.AccountName -ForcedCommand $Context.ForcedCommand
        foreach ($note in @($effective.Notes)) { Add-WfWarning $note }
        if (@($effective.Problems).Count -gt 0) { throw "the effective sshd configuration for '$($Context.AccountName)' is not as intended: $(@($effective.Problems) -join '; ')" }
        Add-WfNote 'effective configuration confirmed: keys only, forced command, no terminal, no forwarding, file logging'
    }

    # The first start with the hardened configuration. Until here nothing has listened since S4.
    if ((Get-Service -Name sshd).Status -ne 'Stopped') { Stop-Service -Name sshd -Force }
    try {
        Start-Service -Name sshd
    } catch {
        if ($update.Changed) {
            Copy-Item -LiteralPath ($configPath + '.wf-previous') -Destination $configPath -Force
            throw "sshd did not start with the new configuration, so the previous sshd_config was restored and sshd is left stopped: $($_.Exception.Message)"
        }
        throw "sshd did not start and is left stopped: $($_.Exception.Message)"
    }
    if ((Get-Service -Name sshd).Status -ne 'Running') { throw 'sshd is not running after the start' }
    Set-Service -Name sshd -StartupType Automatic
    if ([string](Get-Service -Name sshd).StartType -ne 'Automatic') { throw 'the sshd service start type could not be set to Automatic' }
    Add-WfNote 'sshd started with the validated configuration and starts with Windows from now on'
}

function Set-WfPower {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # The one power change: never sleep on mains power, so the PC is reachable. Nothing else
    # about power is touched.
    # https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
    $powercfg = Join-Path ([System.Environment]::SystemDirectory) 'powercfg.exe'
    [void](Invoke-WfChecked -FilePath $powercfg -ArgumentList @('/change', 'standby-timeout-ac', '0') -What 'powercfg /change standby-timeout-ac 0')
    $query = Invoke-WfNative -FilePath $powercfg -ArgumentList @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE')
    $values = ConvertFrom-WfPowerCfgQuery -Text $query.StdOut
    if ($null -eq $values) {
        Add-WfIncomplete 'the sleep timeout could not be read back from powercfg; check Settings > System > Power says "Never" for sleep when plugged in'
    } elseif ($values.AcSeconds -ne 0) {
        throw "sleep on mains power is still $($values.AcSeconds) seconds after setting it to never"
    } else {
        Add-WfNote 'sleep on mains power: never'
    }
    $Context.State.standby_timeout_ac_set = $true
}

function Show-WfSecurityLogAccess {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # A measurement for the plan's open question about the Security log. Read only.
    $wevtutil = Join-Path ([System.Environment]::SystemDirectory) 'wevtutil.exe'
    $run = Invoke-WfNative -FilePath $wevtutil -ArgumentList @('gl', 'Security') -TimeoutSeconds 30
    if ($run.ExitCode -ne 0) {
        Add-WfWarning "wevtutil gl Security exited with code $($run.ExitCode)"
        return
    }
    $access = ''
    foreach ($line in @($run.StdOut -split "`r?`n")) {
        if ($line -match '^\s*channelAccess:\s*(\S+)\s*$') { $access = $Matches[1] }
    }
    $Context.SecurityChannelAccess = $access
    Add-WfNote "Security log channelAccess: $access"
    Add-WfNote 'the Mac side check "security-log-access" measures what the collector account itself can read'
}

function Show-WfHostKey {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $path = Join-Path $Context.Layout.SshDir 'ssh_host_ed25519_key.pub'
    $tokens = @(([System.IO.File]::ReadAllText($path)).Trim() -split '\s+')
    if ($tokens.Count -lt 2 -or $tokens[0] -cne 'ssh-ed25519') { throw "$path is not an Ed25519 public key" }
    $Context.HostKeyLine = "$($tokens[0]) $($tokens[1])"
    $Context.HostKeyFingerprint = Get-WfKeyFingerprint -KeyBase64 $tokens[1]
    Add-WfNote "host key fingerprint (public, not a secret): $($Context.HostKeyFingerprint)"
}

function Get-WfNetworkLogonRight {
    # The two user rights that decide whether a network logon (which is what an SSH key logon
    # is) is allowed at all, read with secedit. Returns @{ Allow = sids; Deny = sids } or $null.
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
    # https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants
    param([Parameter(Mandatory = $true)][string]$WorkDir)
    $secedit = Join-Path ([System.Environment]::SystemDirectory) 'secedit.exe'
    $export = Join-Path $WorkDir 'rights.inf'
    $run = Invoke-WfNative -FilePath $secedit -ArgumentList @('/export', '/cfg', $export, '/areas', 'USER_RIGHTS', '/quiet') -TimeoutSeconds 60
    if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $export)) { return $null }
    $result = @{ Allow = @(); Deny = @() }
    foreach ($line in @([System.IO.File]::ReadAllLines($export))) {
        if ($line -match '^\s*(SeNetworkLogonRight|SeDenyNetworkLogonRight)\s*=\s*(.*)$') {
            $sids = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_.Length -gt 0 })
            if ($Matches[1] -eq 'SeNetworkLogonRight') { $result.Allow = $sids } else { $result.Deny = $sids }
        }
    }
    return $result
}

function Invoke-WfSelfTest {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    # A real SSH connection to this PC from itself, as the collector account, through the same
    # forced command the Mac will use. It answers, while you are still at the PC, the questions
    # that documentation alone cannot settle: that key logon works for an account with no
    # profile, that the dispatcher starts, that a command outside the allowlist is refused, and
    # that a forced terminal request does not get a shell. It uses a throwaway key that only
    # works from 127.0.0.1 and is removed again.
    $sshDir = Split-Path -Parent $Context.SshdExe
    $ssh = Join-Path $sshDir 'ssh.exe'
    $keygen = Join-Path $sshDir 'ssh-keygen.exe'
    if (-not (Test-Path -LiteralPath $ssh) -or -not (Test-Path -LiteralPath $keygen)) {
        Add-WfIncomplete "ssh.exe or ssh-keygen.exe was not found in $sshDir (the OpenSSH Client feature), so the self test could not run. Install the OpenSSH Client feature and run this script again"
        return
    }
    $temp = Join-Path $Context.Layout.Root ('selftest-' + [System.Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $temp)
    try {
        $keyPath = Join-Path $temp 'key'
        [void](Invoke-WfChecked -FilePath $keygen -ArgumentList @('-q', '-t', 'ed25519', '-N', '', '-C', 'wf-selftest', '-f', $keyPath) -What 'creating the throwaway self test key')
        $testKey = Read-WfPublicKey -Text ([System.IO.File]::ReadAllText($keyPath + '.pub'))
        $testLine = Format-WfAuthorizedKeysLine -ForcedCommand $Context.ForcedCommand -FromAddress '127.0.0.1' -KeyBase64 $testKey.KeyBase64 -Comment 'wf-selftest'
        Set-WfAuthorizedKey -Path $Context.Layout.AuthorizedKeys -Lines @($Context.MacKeyLine, $testLine) -AccountSid $Context.AccountSid

        $knownHosts = Join-Path $temp 'known_hosts'
        Write-WfTextFile -Path $knownHosts -Text ("wf-selftest $($Context.HostKeyLine)`n")
        $clientConfig = Join-Path $temp 'config'
        Write-WfTextFile -Path $clientConfig -Text ''
        # Forward slashes in the two file options: ssh parses option values like a config file
        # line, where a backslash can act as an escape character.
        $knownHostsOption = $knownHosts.Replace('\', '/')
        $noGlobalOption = (Join-Path $temp 'none').Replace('\', '/')
        $common = @(
            '-F', $clientConfig, '-i', $keyPath, '-p', '22',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', "UserKnownHostsFile=$knownHostsOption", '-o', "GlobalKnownHostsFile=$noGlobalOption",
            '-o', 'HostKeyAlias=wf-selftest', '-o', 'PreferredAuthentications=publickey', '-o', 'ConnectTimeout=15'
        )
        $target = "$($Context.AccountName)@127.0.0.1"
        # The first logon of a new account creates its profile, which can take a while.
        $ping = Invoke-WfNative -FilePath $ssh -ArgumentList ($common + @('-T', $target, 'ping')) -TimeoutSeconds 180
        if ($ping.ExitCode -ne 0 -or $ping.StdOut -notmatch '"ok":true' -or $ping.StdOut -notmatch '"verb":"ping"') {
            $tail = @(Get-WfSshdLogTail -LogPath $Context.Layout.SshdLog) -join ' | '
            $rights = ''
            $logon = Get-WfNetworkLogonRight -WorkDir $temp
            if ($null -ne $logon) {
                $rights = " User rights: SeNetworkLogonRight = $(@($logon.Allow) -join ','); SeDenyNetworkLogonRight = $(@($logon.Deny) -join ',') (the account is $($Context.AccountSid); see the checklist, 'If a step fails', row S13)."
            }
            throw "the loopback 'ping' did not return the health JSON (exit code $($ping.ExitCode)). ssh said: $($ping.StdErr.Trim()) Output: $($ping.StdOut.Trim()) Last lines of sshd.log: $tail$rights"
        }
        Add-WfNote 'loopback "ping" returned the health JSON through the forced command'

        $refused = Invoke-WfNative -FilePath $ssh -ArgumentList ($common + @('-T', $target, 'whoami')) -TimeoutSeconds 60
        if ($refused.StdOut -notmatch '"error":"refused"') {
            throw "the loopback 'whoami' was NOT refused. Output: $($refused.StdOut.Trim()) $($refused.StdErr.Trim())"
        }
        if ($refused.ExitCode -ne 64) {
            Add-WfWarning "the loopback 'whoami' was refused, but ssh reported exit code $($refused.ExitCode) instead of 64; exit codes are not reaching the client as expected"
        } else {
            Add-WfNote 'loopback "whoami" was refused with exit code 64'
        }

        # A forced terminal request (-tt). The wiki says ForceCommand is enforced only on non-PTY
        # sessions and PermitTTY no is what blocks a terminal; this proves that setting is in
        # effect: no terminal, no shell, the dispatcher's refusal instead.
        # https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config#forcecommand
        # The client reports a refused terminal as "PTY allocation request failed on channel 0"
        # (OpenSSH clientloop.c); without that line the server granted one.
        $pty = Invoke-WfNative -FilePath $ssh -ArgumentList ($common + @('-tt', $target)) -TimeoutSeconds 60
        $ptyOutput = $pty.StdOut + $pty.StdErr
        if ($ptyOutput -match ('\\' + [regex]::Escape($Context.AccountName) + '\b') -or $ptyOutput -match '(?m)^(PS )?[A-Za-z]:\\[^\r\n]*>' -or $pty.StdOut -notmatch '"error":"refused"') {
            throw "a forced terminal request (-tt) was NOT refused by the dispatcher. Exit code $($pty.ExitCode). Output: $($ptyOutput.Trim())"
        }
        if ($pty.StdErr -notmatch 'PTY allocation request failed') {
            throw "the server granted a terminal to a forced terminal request (-tt); PermitTTY no is not in effect. Output: $($ptyOutput.Trim())"
        }
        Add-WfNote 'loopback terminal request (-tt) was refused a terminal, got no shell, and reached the dispatcher, which refused it'
    } finally {
        # Whatever happened, the throwaway key must not stay authorized.
        Set-WfAuthorizedKey -Path $Context.Layout.AuthorizedKeys -Lines @($Context.MacKeyLine) -AccountSid $Context.AccountSid
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
    $text = [System.IO.File]::ReadAllText($Context.Layout.AuthorizedKeys)
    if ($text -cne ($Context.MacKeyLine + "`n")) { throw 'authorized_keys was not restored to the single Mac key line after the self test' }
    if (Test-Path -LiteralPath $temp) { Add-WfWarning "could not delete the self test folder $temp; delete it by hand" }
}

function Save-WfState {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    if (-not (Test-Path -LiteralPath $Context.Layout.Remote -PathType Container)) { return }
    $Context.State.last_run_utc = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $Context.State.account = $Context.AccountName
    $Context.State.mac_address = $Context.MacIpAddress
    $Context.State.firewall_rule = $Context.FirewallRuleName
    Write-WfTextFile -Path $Context.Layout.State -Text ((ConvertTo-Json -InputObject $Context.State -Depth 5) + "`n")
}

function Read-WfState {
    param([Parameter(Mandatory = $true)][string]$Path)
    $state = @{
        capability_installed_by_this_script = $false
        account_created_by_this_script      = $false
        disabled_firewall_rules             = @()
        previous_default_shell              = $null
        standby_timeout_ac_set              = $false
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $saved = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path))
            foreach ($name in @('capability_installed_by_this_script', 'account_created_by_this_script', 'standby_timeout_ac_set')) {
                if ($null -ne $saved.PSObject.Properties[$name]) { $state[$name] = [bool]$saved.$name }
            }
            if ($null -ne $saved.PSObject.Properties['disabled_firewall_rules']) { $state.disabled_firewall_rules = @($saved.disabled_firewall_rules | ForEach-Object { [string]$_ }) }
            if ($null -ne $saved.PSObject.Properties['previous_default_shell'] -and $null -ne $saved.previous_default_shell) {
                $previous = @{}
                foreach ($property in $saved.previous_default_shell.PSObject.Properties) { $previous[$property.Name] = $property.Value }
                $state.previous_default_shell = $previous
            }
        } catch {
            Write-Warning "install-state.json could not be read and will be rewritten: $($_.Exception.Message)"
        }
    }
    return $state
}

function Write-WfSummary {
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $summary = Get-WfSummaryResult -Steps $script:WfSteps.ToArray()
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('')
    $lines.Add('==================== win-forensics front door: summary ====================')
    foreach ($step in $script:WfSteps) {
        $lines.Add(('[{0}] {1}  {2}' -f $step.Status, $step.Id, $step.Title))
        if ($step.Status -eq 'SKIP') {
            $lines.Add('        not run because an earlier step failed')
        } else {
            foreach ($detail in $step.Details) { $lines.Add("        $detail") }
        }
        if ($step.Status -eq 'FAIL' -or $step.Status -eq 'INCOMPLETE') {
            $lines.Add("        what to do: checklist section `"If a step fails`", row $($step.Id)")
        }
    }
    $lines.Add('')
    if ($summary.Result -eq 'PASS') {
        $lines.Add("RESULT: PASS ($($summary.Warnings) step(s) with warnings)")
        $lines.Add('')
        $lines.Add('Copy this line to the Mac (it is public, not a secret):')
        $lines.Add("    $($Context.HostKeyFingerprint)")
        $lines.Add('Then, on the Mac:')
        $lines.Add("    sh remote-access/mac/wf-pin-host-key.sh --fingerprint $($Context.HostKeyFingerprint)")
        $lines.Add('    sh remote-access/mac/wf-acceptance.sh')
    } elseif ($summary.Result -eq 'INCOMPLETE') {
        $lines.Add("RESULT: INCOMPLETE ($($summary.Incomplete) step(s) could not verify what they set up). This is not a pass. Do not continue on the Mac yet: fix what the 'not verified' lines say and run this script again.")
    } else {
        $lines.Add("RESULT: FAIL ($($summary.Failed) failed, $($summary.Skipped) not run). Fix the failed step and run this script again; it is safe to repeat.")
    }
    $lines.Add('===========================================================================')
    foreach ($line in $lines) {
        $color = 'Gray'
        if ($line.StartsWith('[FAIL]') -or $line.StartsWith('RESULT: FAIL')) { $color = 'Red' }
        elseif ($line.StartsWith('[WARN]') -or $line.StartsWith('[INCOMPLETE]') -or $line.StartsWith('RESULT: INCOMPLETE')) { $color = 'Yellow' }
        elseif ($line.StartsWith('[PASS]') -or $line.StartsWith('RESULT: PASS')) { $color = 'Green' }
        Write-Host $line -ForegroundColor $color
    }
    # A copy next to the script, so the result can be carried back to the Mac. It holds no secret:
    # step results, the Mac's LAN address, public key fingerprints, and the Security log SDDL.
    # It is a record from a real machine, so .gitignore keeps it out of the repository.
    try {
        Write-WfTextFile -Path (Join-Path $Context.SourceDir 'wf-frontdoor-report.txt') -Text (($lines.ToArray() -join "`r`n") + "`r`n")
    } catch {
        Write-Host "(could not save wf-frontdoor-report.txt next to the script: $($_.Exception.Message))"
    }
    return $summary.ExitCode
}

function Invoke-WfInstall {
    param(
        [Parameter(Mandatory = $true)][string]$MacIpAddress,
        [Parameter(Mandatory = $true)][string]$MacPublicKeyFile,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [AllowEmptyString()][string]$CollectorSource,
        [bool]$SkipSelfTest
    )
    $layout = Get-WfLayout -ProgramData $env:ProgramData
    if ([string]::IsNullOrEmpty($CollectorSource)) {
        $CollectorSource = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'collectors\windows'
    }
    $context = @{
        MacIpAddress          = $MacIpAddress.Trim()
        MacPublicKeyFile      = $MacPublicKeyFile
        AccountName           = $AccountName
        CollectorSource       = $CollectorSource
        SourceDir             = $PSScriptRoot
        Layout                = $layout
        FirewallRuleName      = 'win-forensics-ssh-in'
        State                 = Read-WfState -Path $layout.State
        MacKey                = $null
        MacKeyLine            = ''
        AccountSid            = ''
        SshdExe               = ''
        ForcedCommand         = ''
        DispatcherSha256      = ''
        HostKeyLine           = ''
        HostKeyFingerprint    = ''
        SecurityChannelAccess = ''
        InterfaceAlias        = ''
    }

    Write-Host 'win-forensics front door setup. This changes: the OpenSSH Server feature, one firewall rule,'
    Write-Host "one standard account ('$AccountName'), sshd_config, the sleep timeout on mains power, and files"
    Write-Host "under $($layout.Root). It is safe to run again."

    Invoke-WfStep -Id 'S1' -Title 'Checks before changing anything' -Action { Invoke-WfPreflight -Context $context }
    Invoke-WfStep -Id 'S2' -Title 'OpenSSH Server feature' -Action { Install-WfOpenSshServer -Context $context }
    Invoke-WfStep -Id 'S3' -Title 'Firewall: SSH from the Mac only, Private networks only' -Action { Set-WfFirewall -Context $context }
    Invoke-WfStep -Id 'S4' -Title 'sshd: host keys and default config created, then stopped' -Action { Start-WfSshd -Context $context }
    Invoke-WfStep -Id 'S5' -Title 'Default shell for sshd (cmd.exe)' -Action { Set-WfDefaultShell -Context $context }
    Invoke-WfStep -Id 'S6' -Title 'Dedicated standard account' -Action { Set-WfAccount -Context $context }
    Invoke-WfStep -Id 'S7' -Title 'Installed files and their permissions' -Action { Install-WfLayout -Context $context }
    Invoke-WfStep -Id 'S8' -Title 'The Mac''s key, pinned to the dispatcher' -Action { Install-WfAuthorizedKey -Context $context }
    Invoke-WfStep -Id 'S9' -Title 'sshd_config: validate, apply, first start, automatic start' -Action { Set-WfSshdConfig -Context $context }
    Invoke-WfStep -Id 'S10' -Title 'Power: no sleep on mains power' -Action { Set-WfPower -Context $context }
    Invoke-WfStep -Id 'S11' -Title 'Security log access (measurement only)' -Action { Show-WfSecurityLogAccess -Context $context }
    Invoke-WfStep -Id 'S12' -Title 'Host key fingerprint' -Action { Show-WfHostKey -Context $context }
    if ($SkipSelfTest) {
        Invoke-WfStep -Id 'S13' -Title 'Loopback self test' -Action { Add-WfIncomplete 'skipped because -SkipSelfTest was given; the front door has not been exercised' }
    } else {
        Invoke-WfStep -Id 'S13' -Title 'Loopback self test' -Action { Invoke-WfSelfTest -Context $context }
    }
    try { Save-WfState -Context $context } catch { Write-Host "(could not save install-state.json: $($_.Exception.Message))" }
    return (Write-WfSummary -Context $context)
}

# Run only when executed, not when the tests dot-source this file.
if ($MyInvocation.InvocationName -ne '.') {
    $results = @(Invoke-WfInstall -MacIpAddress $MacIpAddress -MacPublicKeyFile $MacPublicKeyFile -AccountName $AccountName -CollectorSource $CollectorSource -SkipSelfTest $SkipSelfTest.IsPresent)
    exit ([int]$results[$results.Count - 1])
}
