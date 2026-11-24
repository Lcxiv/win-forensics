# session-bracket-task: register, undo and read back the logon task that
# runs the read only session-bracket baseline at the captain's logon.
#
# This is a change script, not a collector: it lives in changes/windows/,
# nothing under collectors/ or remote-access/ ever calls it, and only the
# captain runs it, at the PC, by hand (changes/windows/README.md).
#
# Verbs (exactly one; none means -Plan):
#   -Plan      read only. Prints the current state, the exact task that
#              -Apply would register, and every precondition with PASS or
#              FAIL; exits 2 with the reason when one fails.
#   -Apply     checks the preconditions, saves the before state to a new
#              evidence folder (refuses when the save fails), registers the
#              task, saves the after state, and reads back PASS or FAIL per
#              value.
#   -Undo      restores the saved before state (the task absent): removes
#              exactly this task, and only when its definition is the one
#              -Apply registered; then reads back.
#   -Readback  read only. Compares the live task with the expected
#              definition, PASS or FAIL per value, with the last run time and
#              result and whether the collector it runs changed since -Apply.
#
# Exit codes: 0 done (every readback value PASS), 1 a change or a readback
# failed (the output says which value), 2 refused before anything changed.
#
# The task (one, in the root folder of the Task Scheduler library):
#   name       win-forensics-session-bracket-baseline
#   trigger    at logon of the account that runs -Apply, nobody else
#   principal  that account, interactive logon (no password stored), run
#              level Limited: the task gets the account's standard user token
#   action     Windows PowerShell 5.1 with -NoProfile -NonInteractive
#              -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File
#              <repository>\collectors\windows\session-bracket.ps1
#              -Phase baseline -ToEvidenceFolder
#   settings   stop after 10 minutes; a second start while one runs is
#              ignored
# The collector it runs is read only and writes only its own bundle under
# <Desktop>\latency-evidence. When a game is already running at logon, the
# collector's game guard reads the process names, finds it, and reads nothing
# else (collectors/windows/README.md, "The session-bracket sources").
#
# Windows facts, each from Microsoft Learn:
# - A user who is not an administrator may register a task for their own
#   account with the interactive logon type and no password; from a process
#   that is not elevated the run level can only be the low one (LUA,
#   Limited), and a task registered there runs with low privileges:
#   https://learn.microsoft.com/windows/win32/taskschd/security-contexts-for-running-tasks
# - The same page: the run level is ignored for the built in Administrator
#   account and when UAC is turned off, so the task would run elevated; this
#   script refuses both. The built in Administrator account has RID 500
#   (0x1F4):
#   https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
#   UAC is off when EnableLUA under HKLM\SOFTWARE\Microsoft\Windows\
#   CurrentVersion\Policies\System is 0 ("Run all administrators in Admin
#   Approval Mode"):
#   https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration
# - IsInRole(Administrator) is false under UAC until the process is
#   elevated, so it tells an elevated run apart (same IsInRole page).
# - The cmdlets and their parameters:
#   https://learn.microsoft.com/powershell/module/scheduledtasks/register-scheduledtask
#   https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal
#   https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasktrigger
#   https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasksettingsset
#   https://learn.microsoft.com/powershell/module/scheduledtasks/unregister-scheduledtask
#   https://learn.microsoft.com/powershell/module/scheduledtasks/export-scheduledtask
#   https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtaskinfo
# - When the Task Scheduler service starts, logged on users are enumerated
#   and their logon tasks run, so the task can start long after logon:
#   https://learn.microsoft.com/windows/win32/taskschd/logontrigger
# - Last run results are HRESULTs; 0x41303 is "has not yet run", 0x41301
#   "currently running":
#   https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-error-and-success-constants
# - -ExecutionPolicy on the command line sets the Process scope, which Group
#   Policy (MachinePolicy, UserPolicy) overrides; RemoteSigned refuses a
#   script that carries a Zone.Identifier stream from the internet until
#   Unblock-File removes it:
#   https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies
#   https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/unblock-file
# - The Desktop folder: Environment.SpecialFolder DesktopDirectory:
#   https://learn.microsoft.com/dotnet/api/system.environment.specialfolder
# What is not on Learn is on the README's "Facts to verify on the PC" list.
#
# Privacy: the account name, its SID and the profile path never reach the
# console or the evidence folder; they are written <user>, <sid> and
# <profile>.
[CmdletBinding()]
param(
    [switch]$Plan,
    [switch]$Apply,
    [switch]$Undo,
    [switch]$Readback
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-SbtTaskName { return 'win-forensics-session-bracket-baseline' }
function Get-SbtTaskPath { return '\' }
function Get-SbtMarker { return 'win-forensics session bracket baseline (read only); undo with changes\windows\session-bracket-task.ps1 -Undo' }

function Get-SbtFields {
    # The values -Apply sets, -Readback compares and -Undo matches, in order.
    return @('present', 'description', 'execute', 'arguments', 'action_count', 'trigger', 'trigger_user', 'trigger_count',
        'principal_user', 'logon_type', 'run_level', 'execution_time_limit', 'multiple_instances')
}

function Get-SbtExpected {
    # The task definition, as the normalized values Get-SbtLiveTask returns.
    param([hashtable]$Context)
    $arguments = ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "{0}" -Phase baseline -ToEvidenceFolder' -f $Context['CollectorPath'])
    return [ordered]@{
        present              = 'True'
        description          = Get-SbtMarker
        execute              = $Context['PowerShellPath']
        arguments            = $arguments
        action_count         = '1'
        trigger              = 'MSFT_TaskLogonTrigger'
        trigger_user         = $Context['UserId']
        trigger_count        = '1'
        principal_user       = $Context['UserId']
        logon_type           = 'Interactive'
        run_level            = 'Limited'
        execution_time_limit = 'PT10M'
        multiple_instances   = 'IgnoreNew'
    }
}

function Get-SbtAbsent {
    $map = [ordered]@{}
    foreach ($field in (Get-SbtFields)) { $map[$field] = '' }
    $map['present'] = 'False'
    return $map
}

function Protect-SbtText {
    # The account name, its SID and the profile path out of any text.
    param([string]$Text, [hashtable]$Context)
    if ($null -eq $Text) { return '' }
    $out = $Text
    foreach ($pair in @(@($Context['ProfilePath'], '<profile>'), @($Context['UserId'], '<user>'), @($Context['UserSid'], '<sid>'), @($Context['UserName'], '<user>'))) {
        $find = [string]$pair[0]
        if ($find.Length -gt 0) { $out = [regex]::Replace($out, [regex]::Escape($find), [string]$pair[1], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) }
    }
    return $out
}

function Write-SbtLine {
    param([string]$Text, [hashtable]$Context)
    Write-SbtOutput -Text (Protect-SbtText -Text $Text -Context $Context)
}

function ConvertTo-SbtCsvCell {
    param([string]$Value)
    return ('"' + ([string]$Value).Replace('"', '""') + '"')
}

function ConvertTo-SbtCsv {
    # object,field,value, one row per field, values protected.
    param($Map, [hashtable]$Context)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('object,field,value')
    $object = (Get-SbtTaskPath) + (Get-SbtTaskName)
    foreach ($field in (Get-SbtFields)) {
        $lines.Add(((ConvertTo-SbtCsvCell -Value $object), (ConvertTo-SbtCsvCell -Value $field), (ConvertTo-SbtCsvCell -Value (Protect-SbtText -Text ([string]$Map[$field]) -Context $Context))) -join ',')
    }
    return (($lines.ToArray() -join "`r`n") + "`r`n")
}

function ConvertFrom-SbtCsv {
    # The field map back from a values CSV this script wrote.
    param([string]$Text)
    $map = [ordered]@{}
    foreach ($line in @($Text -split "`r?`n")) {
        $m = [regex]::Match($line, '^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$')
        if ($m.Success) { $map[$m.Groups[2].Value.Replace('""', '"')] = $m.Groups[3].Value.Replace('""', '"') }
    }
    return $map
}

function Save-SbtFile {
    # A file and its SHA-256 beside it (<name>.sha256); throws when either
    # cannot be written or does not read back with the same hash.
    param([string]$Path, [string]$Text)
    Write-SbtTextFile -Path $Path -Text $Text
    $hash = Get-SbtSha256 -Path $Path
    Write-SbtTextFile -Path ($Path + '.sha256') -Text ($hash + '  ' + (Split-Path -Leaf $Path) + "`r`n")
    if ((Get-SbtSha256 -Path $Path) -ne $hash) { throw ('the saved file did not read back with the same hash: ' + (Split-Path -Leaf $Path)) }
}

function Test-SbtSavedFile {
    # True when a file and its .sha256 exist and agree.
    param([string]$Path)
    if (-not (Test-SbtPath -Path $Path) -or -not (Test-SbtPath -Path ($Path + '.sha256'))) { return $false }
    $recorded = ((Read-SbtTextFile -Path ($Path + '.sha256')).Trim() -split '\s+')[0]
    return ($recorded -eq (Get-SbtSha256 -Path $Path))
}

function Get-SbtContext {
    # Everything the verbs read before they decide. Reads only.
    param([string]$ScriptRoot)
    $context = @{}
    $identity = Get-SbtIdentity
    $context['UserId'] = [string]$identity['UserId']
    $context['UserName'] = [string]$identity['UserName']
    $context['UserSid'] = [string]$identity['Sid']
    $context['Elevated'] = $identity['Elevated']
    $context['ProfilePath'] = [string](Get-SbtProfilePath)
    $context['Uac'] = Get-SbtUacState
    # Windows paths are joined as text: the repository and System32 are
    # Windows folders, and the tests run where no C: drive exists.
    $repo = Get-SbtFullPath -Path (([string]$ScriptRoot).TrimEnd('\') + '\..\..')
    $context['RepoPath'] = $repo
    $context['CollectorPath'] = $repo.TrimEnd('\') + '\collectors\windows\session-bracket.ps1'
    $context['HelperPath'] = $repo.TrimEnd('\') + '\collectors\windows\_common.ps1'
    $context['PowerShellPath'] = ([string](Get-SbtSystemDirectory)).TrimEnd('\') + '\WindowsPowerShell\v1.0\powershell.exe'
    $context['Desktop'] = $null
    $context['DesktopError'] = $null
    try { $context['Desktop'] = Get-SbtDesktopPath } catch { $context['DesktopError'] = $_.Exception.Message }
    $context['Task'] = Get-SbtLiveTask
    return $context
}

function Get-SbtGameNames {
    # The games and launchers nothing in the change area runs beside
    # (changes/windows/README.md, "Rules for every change script"), as
    # Get-Process reports ProcessName (no extension). Unverified on the PC:
    # README item S6.
    return @('Overwatch', 'Battle.net', 'FortniteClient-Win64-Shipping', 'EpicGamesLauncher')
}

function Get-SbtGameCheck {
    # The no_game_running check: names only, compared ignoring case; a list
    # that cannot be read fails the check, because whether a game runs is
    # then unknown.
    $names = $null
    try { $names = @(Get-SbtProcessNames) } catch { return [ordered]@{ name = 'no_game_running'; ok = $false; detail = 'the process names could not be read: ' + $_.Exception.Message } }
    $found = @()
    foreach ($game in (Get-SbtGameNames)) {
        foreach ($name in $names) { if ([string]::Equals([string]$name, $game, [System.StringComparison]::OrdinalIgnoreCase)) { $found += $game; break } }
    }
    if ($found.Count -gt 0) { return [ordered]@{ name = 'no_game_running'; ok = $false; detail = ('running: ' + ($found -join ', ') + '; close the game and its launcher first') } }
    return [ordered]@{ name = 'no_game_running'; ok = $true; detail = 'none of ' + ((Get-SbtGameNames) -join ', ') + ' runs' }
}

function Get-SbtPreconditions {
    # Every check -Apply makes before it changes anything, in order.
    param([hashtable]$Context)
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $add = { param([string]$Name, [bool]$Ok, [string]$Detail) $checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail }) }
    $sid = [string]$Context['UserSid']
    $game = Get-SbtGameCheck
    & $add $game['name'] ([bool]$game['ok']) ([string]$game['detail'])
    & $add 'not_elevated' (-not [bool]$Context['Elevated']) 'run it from a normal (not "Run as administrator") Windows PowerShell; the task must carry the standard user token'
    & $add 'not_builtin_administrator' (-not ($sid -match '^S-1-5-21-.+-500$')) 'the built in Administrator account (RID 500) runs every task elevated whatever its run level; use a normal account'
    $uac = $Context['Uac']
    $uacOk = ([bool]$uac['Readable'] -and $null -ne $uac['EnableLua'] -and [int]$uac['EnableLua'] -eq 1)
    $uacDetail = $(if (-not $uac['Readable']) { 'EnableLUA could not be read: ' + [string]$uac['Error'] } elseif ($null -eq $uac['EnableLua']) { 'EnableLUA is absent, so whether UAC is on is unknown' } else { 'EnableLUA is ' + [string]$uac['EnableLua'] + ' (1 is UAC on; with UAC off the run level is ignored and the task runs elevated)' })
    & $add 'uac_on' $uacOk $uacDetail
    $task = $Context['Task']
    $taskOk = ($null -eq $task['Error'] -and $task['present'] -eq 'False')
    $taskDetail = $(if ($task['Error']) { 'the task list could not be read: ' + [string]$task['Error'] } elseif ($task['present'] -eq 'True') { 'a task with this name already exists; read it with -Readback, remove it with -Undo' } else { 'absent' })
    & $add 'task_absent' $taskOk $taskDetail
    foreach ($pair in @(@('collector_present', $Context['CollectorPath']), @('helper_present', $Context['HelperPath']), @('powershell_present', $Context['PowerShellPath']))) {
        & $add $pair[0] (Test-SbtPath -Path $pair[1]) ([string]$pair[1])
    }
    $quoted = ([string]$Context['CollectorPath']).Contains('"')
    & $add 'path_quotable' (-not $quoted) 'the collector path holds no double quote, so it can be passed quoted to -File'
    foreach ($pair in @(@('collector_not_blocked', $Context['CollectorPath']), @('helper_not_blocked', $Context['HelperPath']))) {
        $blocked = $null
        $detail = 'no Zone.Identifier stream'
        try { $blocked = Test-SbtZoneIdentifier -Path $pair[1] } catch { $detail = 'the Zone.Identifier stream could not be read: ' + $_.Exception.Message }
        if ($blocked) { $detail = 'the file carries a Zone.Identifier stream (downloaded); RemoteSigned refuses it: review the files, then run Unblock-File on the repository files' }
        & $add $pair[0] ($blocked -eq $false) $detail
    }
    foreach ($scope in @('MachinePolicy', 'UserPolicy')) {
        $policy = $null
        $detail = $null
        try { $policy = [string](Get-SbtExecutionPolicy -Scope $scope) } catch { $detail = 'the policy could not be read: ' + $_.Exception.Message }
        $ok = ($null -ne $policy -and @('Undefined', 'RemoteSigned', 'Unrestricted', 'Bypass') -contains $policy)
        if (-not $detail) { $detail = $scope + ' is ' + $policy + $(if ($ok) { '' } else { '; Group Policy overrides -ExecutionPolicy RemoteSigned and would stop the script' }) }
        & $add ('execution_policy_' + $scope.ToLowerInvariant()) $ok $detail
    }
    $desktopOk = ($null -ne $Context['Desktop'])
    & $add 'desktop_resolved' $desktopOk $(if ($desktopOk) { [string]$Context['Desktop'] } else { 'the Desktop folder could not be resolved: ' + [string]$Context['DesktopError'] })
    return , $checks.ToArray()
}

function Write-SbtDefinition {
    param($Map, [hashtable]$Context, [string]$Title)
    Write-SbtLine -Text $Title -Context $Context
    foreach ($field in (Get-SbtFields)) { Write-SbtLine -Text ('  {0,-22} {1}' -f $field, [string]$Map[$field]) -Context $Context }
}

function Write-SbtChecks {
    param([object[]]$Checks, [hashtable]$Context)
    foreach ($check in $Checks) { Write-SbtLine -Text ('  {0,-4} {1,-34} {2}' -f $(if ($check['ok']) { 'PASS' } else { 'FAIL' }), $check['name'], $check['detail']) -Context $Context }
}

function Get-SbtComparable {
    # The account fields are compared on the name after the last backslash,
    # ignoring case: whether Task Scheduler reports the trigger and principal
    # user as COMPUTER\name or name is not documented (README verification
    # list). Every other field must match exactly.
    param([string]$Field, [string]$Value)
    if ($Field -eq 'trigger_user' -or $Field -eq 'principal_user') { return (([string]$Value) -split '\\')[-1].ToLowerInvariant() }
    return [string]$Value
}

function Compare-SbtState {
    # PASS or FAIL per field, live against expected. Returns the number of FAIL.
    param($Live, $Expected, [hashtable]$Context)
    $fails = 0
    foreach ($field in (Get-SbtFields)) {
        $same = ((Get-SbtComparable -Field $field -Value $Live[$field]) -ceq (Get-SbtComparable -Field $field -Value $Expected[$field]))
        if (-not $same) { $fails += 1 }
        Write-SbtLine -Text ('  {0,-4} {1,-22} live "{2}", expected "{3}"' -f $(if ($same) { 'PASS' } else { 'FAIL' }), $field, [string]$Live[$field], [string]$Expected[$field]) -Context $Context
    }
    return $fails
}

function Test-SbtSameDefinition {
    param($A, $B)
    foreach ($field in (Get-SbtFields)) { if ((Get-SbtComparable -Field $field -Value $A[$field]) -cne (Get-SbtComparable -Field $field -Value $B[$field])) { return $false } }
    return $true
}

function Get-SbtEvidenceRoot {
    param([hashtable]$Context)
    return (Join-Path -Path ([string]$Context['Desktop']) -ChildPath 'latency-evidence')
}

function Find-SbtSavedState {
    # The newest evidence folder of this script whose before.csv still
    # matches its hash, or $null.
    param([hashtable]$Context)
    if (-not $Context['Desktop']) { return $null }
    $root = Get-SbtEvidenceRoot -Context $Context
    $folders = Get-SbtChildFolders -Path $root -Prefix 'session-bracket-task-'
    foreach ($folder in @($folders | Sort-Object -Descending)) {
        $path = Join-Path -Path $folder -ChildPath 'before.csv'
        if (Test-SbtSavedFile -Path $path) { return $folder }
    }
    return $null
}

function Invoke-SbtPlan {
    param([hashtable]$Context)
    Write-SbtLine -Text 'session-bracket-task -Plan (read only; nothing is changed)' -Context $Context
    Write-SbtDefinition -Map $Context['Task'] -Context $Context -Title 'current state of the task:'
    Write-SbtDefinition -Map (Get-SbtExpected -Context $Context) -Context $Context -Title '-Apply would register exactly:'
    Write-SbtLine -Text '-Apply would first save the before state to <Desktop>\latency-evidence\session-bracket-task-<UTC>\ (before.csv with its SHA-256), then register, then save after.csv and task-after.xml and read back.' -Context $Context
    Write-SbtLine -Text 'preconditions:' -Context $Context
    $checks = Get-SbtPreconditions -Context $Context
    Write-SbtChecks -Checks $checks -Context $Context
    $failed = @($checks | Where-Object { -not $_['ok'] })
    if ($failed.Count -gt 0) {
        Write-SbtLine -Text ('REFUSED: ' + $failed[0]['name'] + ': ' + $failed[0]['detail']) -Context $Context
        return 2
    }
    Write-SbtLine -Text 'every precondition passes; run again with -Apply to register the task' -Context $Context
    return 0
}

function Invoke-SbtApply {
    param([hashtable]$Context)
    Write-SbtLine -Text 'session-bracket-task -Apply' -Context $Context
    $checks = Get-SbtPreconditions -Context $Context
    Write-SbtChecks -Checks $checks -Context $Context
    $failed = @($checks | Where-Object { -not $_['ok'] })
    if ($failed.Count -gt 0) {
        Write-SbtLine -Text ('REFUSED, nothing changed: ' + $failed[0]['name'] + ': ' + $failed[0]['detail']) -Context $Context
        return 2
    }
    # Save before change; refuse without it.
    $folder = $null
    try {
        $root = Get-SbtEvidenceRoot -Context $Context
        New-SbtFolder -Path $root
        $folder = Join-Path -Path $root -ChildPath ('session-bracket-task-' + (Get-SbtUtcStamp))
        New-SbtFolder -Path $folder
        Save-SbtFile -Path (Join-Path -Path $folder -ChildPath 'before.csv') -Text (ConvertTo-SbtCsv -Map $Context['Task'] -Context $Context)
        $hashes = ('collector_sha256,' + (Get-SbtSha256 -Path $Context['CollectorPath']) + "`r`nhelper_sha256," + (Get-SbtSha256 -Path $Context['HelperPath']) + "`r`n")
        Save-SbtFile -Path (Join-Path -Path $folder -ChildPath 'collector-hashes.csv') -Text $hashes
        Save-SbtFile -Path (Join-Path -Path $folder -ChildPath 'apply-started.txt') -Text ('apply started ' + (Get-SbtUtcStamp) + "`r`n")
    } catch {
        Write-SbtLine -Text ('REFUSED, nothing changed: the before state could not be saved: ' + $_.Exception.Message) -Context $Context
        return 2
    }
    Write-SbtLine -Text ('saved the before state: <Desktop>\latency-evidence\' + (Split-Path -Leaf $folder)) -Context $Context
    $expected = Get-SbtExpected -Context $Context
    $registerError = $null
    try {
        Register-SbtTask -Expected $expected -Context $Context
    } catch {
        $registerError = $_.Exception.Message
        Write-SbtLine -Text ('FAIL register: ' + $registerError) -Context $Context
    }
    $live = Get-SbtLiveTask
    try {
        Save-SbtFile -Path (Join-Path -Path $folder -ChildPath 'after.csv') -Text (ConvertTo-SbtCsv -Map $live -Context $Context)
        if ($live['present'] -eq 'True') { Save-SbtFile -Path (Join-Path -Path $folder -ChildPath 'task-after.xml') -Text (Protect-SbtText -Text (Export-SbtTaskXml) -Context $Context) }
    } catch {
        Write-SbtLine -Text ('FAIL save after state: ' + $_.Exception.Message) -Context $Context
        $registerError = $(if ($registerError) { $registerError } else { 'the after state could not be saved' })
    }
    Write-SbtLine -Text 'readback:' -Context $Context
    $fails = Compare-SbtState -Live $live -Expected $expected -Context $Context
    if ($registerError -or $fails -gt 0) {
        Write-SbtLine -Text ('FAIL: the task is not as expected ({0} values differ); -Undo removes what was registered, -Readback shows it' -f $fails) -Context $Context
        return 1
    }
    Write-SbtLine -Text 'PASS: the task is registered; it runs the read only baseline at your next logon' -Context $Context
    return 0
}

function Invoke-SbtUndo {
    param([hashtable]$Context)
    Write-SbtLine -Text 'session-bracket-task -Undo' -Context $Context
    if ($Context['Task']['Error']) {
        Write-SbtLine -Text ('REFUSED, nothing changed: the task list could not be read: ' + [string]$Context['Task']['Error']) -Context $Context
        return 2
    }
    $game = Get-SbtGameCheck
    if (-not $game['ok']) {
        Write-SbtLine -Text ('REFUSED, nothing changed: no_game_running: ' + [string]$game['detail']) -Context $Context
        return 2
    }
    $folder = Find-SbtSavedState -Context $Context
    if ($null -eq $folder) {
        Write-SbtLine -Text 'REFUSED, nothing changed: no saved before state (session-bracket-task-*\before.csv with a matching .sha256) under <Desktop>\latency-evidence' -Context $Context
        return 2
    }
    $before = ConvertFrom-SbtCsv -Text (Read-SbtTextFile -Path (Join-Path -Path $folder -ChildPath 'before.csv'))
    if ($before['present'] -ne 'False') {
        Write-SbtLine -Text 'REFUSED, nothing changed: the saved before state has the task present; this script only restores an absent task' -Context $Context
        return 2
    }
    $live = $Context['Task']
    if ($live['present'] -eq 'False') {
        Write-SbtLine -Text 'the task is already absent, as saved; nothing to remove' -Context $Context
        Write-SbtLine -Text 'readback:' -Context $Context
        $fails = Compare-SbtState -Live $live -Expected (Get-SbtAbsent) -Context $Context
        return $(if ($fails -gt 0) { 1 } else { 0 })
    }
    # Only the task -Apply registered: the expected definition, or the one
    # saved right after -Apply when that apply was partial.
    $ours = Test-SbtSameDefinition -A (ConvertTo-SbtProtectedMap -Map $live -Context $Context) -B (ConvertTo-SbtProtectedMap -Map (Get-SbtExpected -Context $Context) -Context $Context)
    $afterPath = Join-Path -Path $folder -ChildPath 'after.csv'
    if (-not $ours -and (Test-SbtSavedFile -Path $afterPath)) {
        $ours = Test-SbtSameDefinition -A (ConvertTo-SbtProtectedMap -Map $live -Context $Context) -B (ConvertFrom-SbtCsv -Text (Read-SbtTextFile -Path $afterPath))
    }
    if (-not $ours) {
        Write-SbtDefinition -Map $live -Context $Context -Title 'live task:'
        Write-SbtLine -Text 'REFUSED, nothing changed: the live task with this name is not the one -Apply registered (it changed since); remove it by hand in Task Scheduler if it is not wanted' -Context $Context
        return 2
    }
    try {
        Save-SbtFile -Path (Join-Path -Path $folder -ChildPath ('undo-before-' + (Get-SbtUtcStamp) + '.csv')) -Text (ConvertTo-SbtCsv -Map $live -Context $Context)
    } catch {
        Write-SbtLine -Text ('REFUSED, nothing changed: the state before undo could not be saved: ' + $_.Exception.Message) -Context $Context
        return 2
    }
    $removeError = $null
    try { Unregister-SbtTask } catch { $removeError = $_.Exception.Message; Write-SbtLine -Text ('FAIL unregister: ' + $removeError) -Context $Context }
    $now = Get-SbtLiveTask
    Write-SbtLine -Text 'readback:' -Context $Context
    $fails = Compare-SbtState -Live $now -Expected (Get-SbtAbsent) -Context $Context
    if ($removeError -or $fails -gt 0) { return 1 }
    Write-SbtLine -Text 'PASS: the task is removed; the before state (absent) is restored' -Context $Context
    return 0
}

function ConvertTo-SbtProtectedMap {
    param($Map, [hashtable]$Context)
    $out = [ordered]@{}
    foreach ($field in (Get-SbtFields)) { $out[$field] = Protect-SbtText -Text ([string]$Map[$field]) -Context $Context }
    return $out
}

function Get-SbtResultText {
    param($Code)
    if ($null -eq $Code) { return 'unknown' }
    $value = [int64]$Code
    $hex = '0x' + ([uint32]($value -band 0xFFFFFFFF)).ToString('X')
    switch ($value) {
        0 { return '0 (the last run ended with exit code 0)' }
        1 { return '1 (the collector exited 1: its bundle failed; read its summary)' }
        267009 { return $hex + ' (SCHED_S_TASK_RUNNING: running now)' }
        267011 { return $hex + ' (SCHED_S_TASK_HAS_NOT_RUN: not run yet)' }
        267014 { return $hex + ' (SCHED_S_TASK_TERMINATED: stopped by the user or the time limit)' }
    }
    return ($hex + ' (see the Task Scheduler error and success constants)')
}

function Invoke-SbtReadback {
    param([hashtable]$Context)
    Write-SbtLine -Text 'session-bracket-task -Readback (read only; nothing is changed)' -Context $Context
    if ($Context['Task']['Error']) {
        Write-SbtLine -Text ('FAIL: the task list could not be read: ' + [string]$Context['Task']['Error']) -Context $Context
        return 1
    }
    $live = $Context['Task']
    Write-SbtDefinition -Map $live -Context $Context -Title 'live task:'
    Write-SbtLine -Text 'compared with the definition -Apply registers:' -Context $Context
    $fails = Compare-SbtState -Live $live -Expected (Get-SbtExpected -Context $Context) -Context $Context
    if ($live['present'] -eq 'True') {
        try {
            $info = Get-SbtTaskInfo
            Write-SbtLine -Text ('last run: ' + [string]$info['LastRunTime'] + '; last result: ' + (Get-SbtResultText -Code $info['LastTaskResult'])) -Context $Context
        } catch {
            Write-SbtLine -Text ('the last run could not be read: ' + $_.Exception.Message) -Context $Context
        }
    }
    $folder = Find-SbtSavedState -Context $Context
    $hashPath = $(if ($folder) { Join-Path -Path $folder -ChildPath 'collector-hashes.csv' } else { $null })
    if ($hashPath -and (Test-SbtSavedFile -Path $hashPath)) {
        $saved = @{}
        foreach ($line in @((Read-SbtTextFile -Path $hashPath) -split "`r?`n")) { $parts = $line.Split(','); if ($parts.Count -eq 2) { $saved[$parts[0]] = $parts[1] } }
        foreach ($pair in @(@('collector_sha256', $Context['CollectorPath']), @('helper_sha256', $Context['HelperPath']))) {
            $now = $(if (Test-SbtPath -Path $pair[1]) { Get-SbtSha256 -Path $pair[1] } else { 'missing' })
            $same = ($now -eq [string]$saved[$pair[0]])
            if (-not $same) { $fails += 1 }
            Write-SbtLine -Text ('  {0,-4} {1,-22} now {2}, at -Apply {3}' -f $(if ($same) { 'PASS' } else { 'FAIL' }), $pair[0], $now, [string]$saved[$pair[0]]) -Context $Context
        }
    } else {
        Write-SbtLine -Text 'no saved -Apply record with collector hashes was found, so whether the collector changed since is not compared' -Context $Context
    }
    if ($fails -gt 0) { Write-SbtLine -Text ('FAIL: {0} values differ' -f $fails) -Context $Context; return 1 }
    Write-SbtLine -Text 'PASS: the task is as -Apply registered it' -Context $Context
    return 0
}

function Invoke-SbtMain {
    param([bool]$PlanVerb, [bool]$ApplyVerb, [bool]$UndoVerb, [bool]$ReadbackVerb, [string]$ScriptRoot)
    $named = @(@($PlanVerb, $ApplyVerb, $UndoVerb, $ReadbackVerb) | Where-Object { $_ }).Count
    if ($named -gt 1) {
        Write-SbtOutput -Text 'REFUSED, nothing changed: name one verb, exactly one of -Plan, -Apply, -Undo, -Readback'
        return 2
    }
    $context = $null
    try {
        $context = Get-SbtContext -ScriptRoot $ScriptRoot
    } catch {
        Write-SbtOutput -Text ('REFUSED, nothing changed: the current state could not be read: ' + $_.Exception.Message)
        return 2
    }
    try {
        if ($ApplyVerb) { return (Invoke-SbtApply -Context $context) }
        if ($UndoVerb) { return (Invoke-SbtUndo -Context $context) }
        if ($ReadbackVerb) { return (Invoke-SbtReadback -Context $context) }
        return (Invoke-SbtPlan -Context $context)
    } catch {
        # Not refused: a change may have been made. -Readback shows the state.
        Write-SbtLine -Text ('FAIL: the script stopped on an unexpected error: ' + $_.Exception.Message + '; run -Readback to see the state of the task') -Context $context
        return 1
    }
}

# ---------------------------------------------------------------------------
# Windows adapters. Everything that touches the machine is below this line;
# changes/windows/tests/SessionBracketTaskBackend.ps1 replaces each one, and
# the tests never run these. What they rely on that Learn does not state is
# on the README's "Facts to verify on the PC" list.

function Write-SbtOutput {
    param([string]$Text)
    [Console]::Out.WriteLine($Text)
}

function Get-SbtIdentity {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $name = [string]$identity.Name
    return @{
        UserId   = $name
        UserName = ($name -split '\\')[-1]
        Sid      = [string]$identity.User.Value
        Elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-SbtProfilePath {
    return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
}

function Get-SbtUacState {
    $state = @{ Readable = $false; EnableLua = $null; Error = $null }
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', $false)
        if ($null -eq $key) { $state.Error = 'the Policies\System key does not exist'; return $state }
        try {
            $value = $key.GetValue('EnableLUA', $null)
            $state.Readable = $true
            if ($null -ne $value) { $state.EnableLua = [int]$value }
        } finally { $key.Close() }
    } catch { $state.Error = $_.Exception.Message }
    return $state
}

function Get-SbtSystemDirectory {
    return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)
}

function Get-SbtDesktopPath {
    $path = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::DesktopDirectory)
    if (-not $path) { throw 'DesktopDirectory resolved to no path' }
    return $path
}

function Get-SbtFullPath {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function Get-SbtLiveTask {
    # The task as the normalized field map, present False when absent, or
    # Error set when the list could not be read. The root folder is listed and
    # filtered by name, so an absent task is not an error.
    $map = Get-SbtAbsent
    $map['Error'] = $null
    try {
        $task = @(Get-ScheduledTask -TaskPath (Get-SbtTaskPath) -ErrorAction Stop | Where-Object { $_.TaskName -eq (Get-SbtTaskName) })
    } catch {
        $map['Error'] = $_.Exception.Message
        return $map
    }
    if ($task.Count -eq 0) { return $map }
    $t = $task[0]
    $actions = @($t.Actions)
    $triggers = @($t.Triggers)
    $map['present'] = 'True'
    $map['description'] = [string]$t.Description
    $map['action_count'] = [string]$actions.Count
    if ($actions.Count -gt 0) { $map['execute'] = [string]$actions[0].Execute; $map['arguments'] = [string]$actions[0].Arguments }
    $map['trigger_count'] = [string]$triggers.Count
    if ($triggers.Count -gt 0) { $map['trigger'] = [string]$triggers[0].CimClass.CimClassName; $map['trigger_user'] = [string]$triggers[0].UserId }
    $map['principal_user'] = [string]$t.Principal.UserId
    $map['logon_type'] = [string]$t.Principal.LogonType
    $map['run_level'] = [string]$t.Principal.RunLevel
    $map['execution_time_limit'] = [string]$t.Settings.ExecutionTimeLimit
    $map['multiple_instances'] = [string]$t.Settings.MultipleInstances
    return $map
}

function Get-SbtTaskInfo {
    $info = Get-ScheduledTaskInfo -TaskPath (Get-SbtTaskPath) -TaskName (Get-SbtTaskName) -ErrorAction Stop
    $last = $null
    if ($null -ne $info.LastRunTime) { $last = $info.LastRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    return @{ LastRunTime = $last; LastTaskResult = $info.LastTaskResult }
}

function Export-SbtTaskXml {
    return [string](Export-ScheduledTask -TaskPath (Get-SbtTaskPath) -TaskName (Get-SbtTaskName) -ErrorAction Stop)
}

function Register-SbtTask {
    param($Expected, [hashtable]$Context)
    $action = New-ScheduledTaskAction -Execute $Expected['execute'] -Argument $Expected['arguments']
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $Context['UserId']
    $principal = New-ScheduledTaskPrincipal -UserId $Context['UserId'] -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
    $null = Register-ScheduledTask -TaskPath (Get-SbtTaskPath) -TaskName (Get-SbtTaskName) -Description $Expected['description'] -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop
}

function Unregister-SbtTask {
    Unregister-ScheduledTask -TaskPath (Get-SbtTaskPath) -TaskName (Get-SbtTaskName) -Confirm:$false -ErrorAction Stop
}

function Get-SbtExecutionPolicy {
    param([string]$Scope)
    return [string](Get-ExecutionPolicy -Scope $Scope)
}

function Get-SbtProcessNames {
    # Names only: ProcessName of each process, nothing else read from it.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process
    return @(Get-Process -ErrorAction Stop | ForEach-Object { [string]$_.ProcessName })
}

function Test-SbtZoneIdentifier {
    param([string]$Path)
    $streams = @(Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop | Where-Object { $_.Stream -eq 'Zone.Identifier' })
    return ($streams.Count -gt 0)
}

function Test-SbtPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return (Test-Path -LiteralPath $Path)
}

function Get-SbtChildFolders {
    param([string]$Path, [string]$Prefix)
    if (-not (Test-Path -LiteralPath $Path)) { return , @() }
    return , @(Get-ChildItem -LiteralPath $Path -Directory | Where-Object { $_.Name.StartsWith($Prefix) } | ForEach-Object { $_.FullName })
}

function New-SbtFolder {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path }
}

function Write-SbtTextFile {
    # UTF-8 without a byte order mark.
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Read-SbtTextFile {
    param([string]$Path)
    return [System.IO.File]::ReadAllText($Path)
}

function Get-SbtSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-SbtUtcStamp {
    return [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

# Dot sourced by the tests: define the functions and stop.
if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-SbtMain -PlanVerb ([bool]$Plan) -ApplyVerb ([bool]$Apply) -UndoVerb ([bool]$Undo) -ReadbackVerb ([bool]$Readback) -ScriptRoot $PSScriptRoot
    exit $code
}
