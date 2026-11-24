# Synthetic stand-ins for every Windows adapter of
# changes/windows/session-bracket-task.ps1. Dot source the script first, then
# this file: each function below replaces the adapter of the same name, so
# the tests run every verb against an invented machine and never touch Task
# Scheduler, the registry or a real Desktop.
#
# $global:SbtSynthetic holds the machine:
#   Identity       UserId, UserName, Sid, Elevated
#   Uac            Readable, EnableLua, Error
#   Desktop        a folder under the test drive, or $null (unresolvable)
#   Task           $null (absent) or the field map Task Scheduler would report
#   ListError      text: listing the tasks fails
#   RegisterError  text: Register-ScheduledTask throws (after Partial is applied)
#   RegisterPartial a field map the register call leaves behind before it throws
#   RegisterDrift  a hashtable of fields Task Scheduler reports differently from what was asked
#   UnregisterError text: Unregister-ScheduledTask throws
#   ExportError    text: Export-ScheduledTask throws
#   FailWritesUnder a path prefix under which every file write throws
#   Policies       scope -> policy name, or 'throw'
#   Processes      the process names Get-Process would report, or 'throw'
#   Zone           path -> $true / $false / 'throw'
#   Files          paths that exist besides real files (the repository files)
#   Output         every line the script printed
#   Calls          every adapter call that changes the machine

function Reset-SbtSynthetic {
    param([string]$Desktop)
    $global:SbtSynthetic = @{
        Identity        = @{ UserId = 'SYNTHETIC-PC\Synthetic Owner'; UserName = 'Synthetic Owner'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003-1001'; Elevated = $false }
        Profile         = 'C:\Users\Synthetic Owner'
        Uac             = @{ Readable = $true; EnableLua = 1; Error = $null }
        Desktop         = $Desktop
        Task            = $null
        ListError       = $null
        RegisterError   = $null
        RegisterPartial = $null
        RegisterDrift   = @{}
        UnregisterError = $null
        ExportError     = $null
        FailWritesUnder = $null
        Policies        = @{ MachinePolicy = 'Undefined'; UserPolicy = 'Undefined' }
        Processes       = @('explorer', 'svchost')
        Zone            = @{}
        Files           = @{}
        Output          = New-Object 'System.Collections.Generic.List[string]'
        Calls           = New-Object 'System.Collections.Generic.List[string]'
        Clock           = 0
        LastRunTime     = $null
        LastTaskResult  = 267011
    }
}

function Write-SbtOutput {
    param([string]$Text)
    $global:SbtSynthetic.Output.Add($Text)
}

function Get-SbtIdentity { return $global:SbtSynthetic.Identity }
function Get-SbtProfilePath { return $global:SbtSynthetic.Profile }
function Get-SbtUacState { return $global:SbtSynthetic.Uac }
function Get-SbtSystemDirectory { return 'C:\Windows\System32' }

function Get-SbtDesktopPath {
    if (-not $global:SbtSynthetic.Desktop) { throw 'synthetic: DesktopDirectory resolved to no path' }
    return $global:SbtSynthetic.Desktop
}

function Get-SbtFullPath {
    # The repository as it sits on the synthetic PC, under the owner's profile.
    param([string]$Path)
    return 'C:\Users\Synthetic Owner\win-forensics'
}

function Get-SbtLiveTask {
    $map = Get-SbtAbsent
    $map['Error'] = $null
    if ($global:SbtSynthetic.ListError) { $map['Error'] = $global:SbtSynthetic.ListError; return $map }
    if ($null -eq $global:SbtSynthetic.Task) { return $map }
    foreach ($field in (Get-SbtFields)) { $map[$field] = [string]$global:SbtSynthetic.Task[$field] }
    return $map
}

function Get-SbtTaskInfo {
    if ($global:SbtSynthetic.ContainsKey('TaskInfoError') -and $global:SbtSynthetic.TaskInfoError) { throw $global:SbtSynthetic.TaskInfoError }
    return @{ LastRunTime = $global:SbtSynthetic.LastRunTime; LastTaskResult = $global:SbtSynthetic.LastTaskResult }
}

function Export-SbtTaskXml {
    if ($global:SbtSynthetic.ExportError) { throw $global:SbtSynthetic.ExportError }
    $task = $global:SbtSynthetic.Task
    return ("<?xml version=`"1.0`" encoding=`"UTF-16`"?>`r`n<Task><Principals><Principal><UserId>{0}</UserId></Principal></Principals><Actions><Exec><Command>{1}</Command><Arguments>{2}</Arguments></Exec></Actions><Sid>{3}</Sid></Task>`r`n" -f
        $task['principal_user'], $task['execute'], [System.Security.SecurityElement]::Escape([string]$task['arguments']), $global:SbtSynthetic.Identity.Sid)
}

function Register-SbtTask {
    param($Expected, [hashtable]$Context)
    $global:SbtSynthetic.Calls.Add('register')
    if ($global:SbtSynthetic.RegisterPartial) { $global:SbtSynthetic.Task = $global:SbtSynthetic.RegisterPartial }
    if ($global:SbtSynthetic.RegisterError) { throw $global:SbtSynthetic.RegisterError }
    $task = @{}
    foreach ($field in (Get-SbtFields)) { $task[$field] = [string]$Expected[$field] }
    foreach ($key in $global:SbtSynthetic.RegisterDrift.Keys) { $task[$key] = $global:SbtSynthetic.RegisterDrift[$key] }
    $global:SbtSynthetic.Task = $task
}

function Unregister-SbtTask {
    $global:SbtSynthetic.Calls.Add('unregister')
    if ($global:SbtSynthetic.UnregisterError) { throw $global:SbtSynthetic.UnregisterError }
    $global:SbtSynthetic.Task = $null
}

function Get-SbtProcessNames {
    if ($global:SbtSynthetic.Processes -eq 'throw') { throw 'synthetic: the process list could not be read' }
    return @($global:SbtSynthetic.Processes)
}

function Get-SbtExecutionPolicy {
    param([string]$Scope)
    $policy = $global:SbtSynthetic.Policies[$Scope]
    if ($policy -eq 'throw') { throw 'synthetic: the policy could not be read' }
    return $policy
}

function Test-SbtZoneIdentifier {
    param([string]$Path)
    if (-not $global:SbtSynthetic.Zone.ContainsKey($Path)) { return $false }
    $value = $global:SbtSynthetic.Zone[$Path]
    if ($value -eq 'throw') { throw 'synthetic: the streams could not be listed' }
    return [bool]$value
}

function Test-SbtPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($global:SbtSynthetic.Files.ContainsKey($Path)) { return [bool]$global:SbtSynthetic.Files[$Path] }
    return (Test-Path -LiteralPath $Path)
}

function Get-SbtSha256 {
    param([string]$Path)
    if ($global:SbtSynthetic.Files.ContainsKey($Path)) { return [string]$global:SbtSynthetic.Files[$Path + '#sha256'] }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-SbtTextFile {
    param([string]$Path, [string]$Text)
    if ($global:SbtSynthetic.FailWritesUnder -and $Path.StartsWith($global:SbtSynthetic.FailWritesUnder)) { throw ('synthetic: access denied writing ' + (Split-Path -Leaf $Path)) }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-SbtUtcStamp {
    $global:SbtSynthetic.Clock += 1
    return ([datetime]::new(2026, 11, 19, 18, 0, 0, [System.DateTimeKind]::Utc)).AddSeconds($global:SbtSynthetic.Clock).ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Set-SbtSyntheticRepository {
    # The collector and the helper as files that exist with fixed hashes.
    param([string]$CollectorHash = ('a' * 64), [string]$HelperHash = ('b' * 64))
    $collector = 'C:\Users\Synthetic Owner\win-forensics\collectors\windows\session-bracket.ps1'
    $helper = 'C:\Users\Synthetic Owner\win-forensics\collectors\windows\_common.ps1'
    $global:SbtSynthetic.Files[$collector] = $true
    $global:SbtSynthetic.Files[$collector + '#sha256'] = $CollectorHash
    $global:SbtSynthetic.Files[$helper] = $true
    $global:SbtSynthetic.Files[$helper + '#sha256'] = $HelperHash
    $global:SbtSynthetic.Files['C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'] = $true
}
