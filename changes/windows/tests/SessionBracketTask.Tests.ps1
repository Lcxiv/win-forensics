# Pester 5 tests for changes/windows/session-bracket-task.ps1, run off
# Windows. The script is dot sourced (its main block does not run), then
# SessionBracketTaskBackend.ps1 replaces every Windows adapter, so each verb
# runs end to end against an invented machine: the success paths and every
# failure path the change rules name (save fails, a precondition fails, the
# register call fails, the readback differs, undo after a partial apply).
# Nothing here touches Task Scheduler, the registry or a real Desktop.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'session-bracket-task.ps1'
    . $script:ScriptPath
    . (Join-Path $PSScriptRoot 'SessionBracketTaskBackend.ps1')

    function Start-Machine {
        param([string]$Name)
        $desktop = Join-Path $TestDrive $Name
        $null = New-Item -ItemType Directory -Path $desktop -Force
        Reset-SbtSynthetic -Desktop $desktop
        Set-SbtSyntheticRepository
        return $desktop
    }

    function Invoke-Verb {
        param([string]$Verb)
        $global:SbtSynthetic.Output.Clear()
        $code = Invoke-SbtMain -PlanVerb ($Verb -eq 'Plan') -ApplyVerb ($Verb -eq 'Apply') -UndoVerb ($Verb -eq 'Undo') -ReadbackVerb ($Verb -eq 'Readback') -ScriptRoot 'C:\Users\Synthetic Owner\win-forensics\changes\windows'
        return [pscustomobject]@{ Code = $code; Text = ($global:SbtSynthetic.Output.ToArray() -join "`n") }
    }

    function Get-EvidenceFolders {
        param([string]$Desktop)
        $root = Join-Path $Desktop 'latency-evidence'
        if (-not (Test-Path -LiteralPath $root)) { return , @() }
        return , @(Get-ChildItem -LiteralPath $root -Directory | Sort-Object -Property Name | ForEach-Object { $_.FullName })
    }
}

Describe 'the session bracket logon task: plan' {
    It 'prints the state, the exact task and every precondition, and changes nothing' {
        $desktop = Start-Machine -Name 'plan'
        $run = Invoke-Verb -Verb 'Plan'
        $run.Code | Should -Be 0
        $run.Text | Should -Match 'read only; nothing is changed'
        $run.Text | Should -Match ([regex]::Escape('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "<profile>\win-forensics\collectors\windows\session-bracket.ps1" -Phase baseline -ToEvidenceFolder'))
        $run.Text | Should -Match 'run_level\s+Limited'
        $run.Text | Should -Match 'logon_type\s+Interactive'
        foreach ($check in @('not_elevated', 'not_builtin_administrator', 'uac_on', 'task_absent', 'collector_present', 'helper_present', 'collector_not_blocked', 'execution_policy_machinepolicy', 'desktop_resolved', 'no_game_running')) {
            $run.Text | Should -Match ('PASS\s+' + $check)
        }
        $global:SbtSynthetic.Calls.Count | Should -Be 0
        (Get-EvidenceFolders -Desktop $desktop).Count | Should -Be 0 -Because 'the plan writes nothing'
    }

    It 'is the verb when none is named, and refuses two verbs at once' {
        $null = Start-Machine -Name 'plan-default'
        (Invoke-Verb -Verb '').Text | Should -Match '-Plan \(read only'
        $global:SbtSynthetic.Output.Clear()
        $code = Invoke-SbtMain -PlanVerb $false -ApplyVerb $true -UndoVerb $true -ReadbackVerb $false -ScriptRoot 'x'
        $code | Should -Be 2
        $global:SbtSynthetic.Output[0] | Should -Match 'exactly one'
        $global:SbtSynthetic.Calls.Count | Should -Be 0
    }

    It 'never prints the account name, its SID or the profile path' {
        $null = Start-Machine -Name 'plan-privacy'
        $global:SbtSynthetic.Task = @{}
        foreach ($field in (Get-SbtFields)) { $global:SbtSynthetic.Task[$field] = 'S-1-5-21-1000000001-1000000002-1000000003-1001 SYNTHETIC-PC\Synthetic Owner' }
        $text = (Invoke-Verb -Verb 'Plan').Text + (Invoke-Verb -Verb 'Readback').Text
        $text | Should -Not -Match 'Synthetic Owner'
        $text | Should -Not -Match 'S-1-5-21'
        $text | Should -Match '<user>'
    }
}

Describe 'the session bracket logon task: preconditions refuse before anything changes' {
    It 'refuses when <Name>' -ForEach @(
        @{ Name = 'the shell is elevated'; Check = 'not_elevated'; Setup = { $global:SbtSynthetic.Identity.Elevated = $true } },
        @{ Name = 'the account is the built in Administrator'; Check = 'not_builtin_administrator'; Setup = { $global:SbtSynthetic.Identity.Sid = 'S-1-5-21-1000000001-1000000002-1000000003-500' } },
        @{ Name = 'UAC is off'; Check = 'uac_on'; Setup = { $global:SbtSynthetic.Uac.EnableLua = 0 } },
        @{ Name = 'EnableLUA is absent'; Check = 'uac_on'; Setup = { $global:SbtSynthetic.Uac.EnableLua = $null } },
        @{ Name = 'EnableLUA cannot be read'; Check = 'uac_on'; Setup = { $global:SbtSynthetic.Uac.Readable = $false; $global:SbtSynthetic.Uac.Error = 'denied' } },
        @{ Name = 'a task with the name exists'; Check = 'task_absent'; Setup = { $global:SbtSynthetic.Task = @{ present = 'True' } } },
        @{ Name = 'the task list cannot be read'; Check = 'task_absent'; Setup = { $global:SbtSynthetic.ListError = 'the service is not running' } },
        @{ Name = 'the collector is missing'; Check = 'collector_present'; Setup = { $global:SbtSynthetic.Files['C:\Users\Synthetic Owner\win-forensics\collectors\windows\session-bracket.ps1'] = $false } },
        @{ Name = 'the helper carries a Zone.Identifier stream'; Check = 'helper_not_blocked'; Setup = { $global:SbtSynthetic.Zone['C:\Users\Synthetic Owner\win-forensics\collectors\windows\_common.ps1'] = $true } },
        @{ Name = 'the streams cannot be listed'; Check = 'collector_not_blocked'; Setup = { $global:SbtSynthetic.Zone['C:\Users\Synthetic Owner\win-forensics\collectors\windows\session-bracket.ps1'] = 'throw' } },
        @{ Name = 'Group Policy sets AllSigned'; Check = 'execution_policy_machinepolicy'; Setup = { $global:SbtSynthetic.Policies['MachinePolicy'] = 'AllSigned' } },
        @{ Name = 'the user policy cannot be read'; Check = 'execution_policy_userpolicy'; Setup = { $global:SbtSynthetic.Policies['UserPolicy'] = 'throw' } },
        @{ Name = 'the Desktop cannot be resolved'; Check = 'desktop_resolved'; Setup = { $global:SbtSynthetic.Desktop = $null } },
        @{ Name = 'a game runs'; Check = 'no_game_running'; Setup = { $global:SbtSynthetic.Processes = @('explorer', 'overwatch') } },
        @{ Name = 'a launcher runs'; Check = 'no_game_running'; Setup = { $global:SbtSynthetic.Processes = @('Battle.net') } },
        @{ Name = 'the process list cannot be read'; Check = 'no_game_running'; Setup = { $global:SbtSynthetic.Processes = 'throw' } }
    ) {
        $desktop = Start-Machine -Name ('refuse-' + $Check + '-' + $Name.Length)
        & $Setup
        $plan = Invoke-Verb -Verb 'Plan'
        $plan.Code | Should -Be 2
        $plan.Text | Should -Match ('FAIL\s+' + $Check)
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 2
        $apply.Text | Should -Match 'REFUSED, nothing changed'
        $global:SbtSynthetic.Calls.Count | Should -Be 0
        if ($global:SbtSynthetic.Desktop) { (Get-EvidenceFolders -Desktop $desktop).Count | Should -Be 0 -Because 'a refused apply saves nothing' }
    }
}

Describe 'the session bracket logon task: apply, readback and undo' {
    It 'saves the before state, registers the task, reads back PASS, and undo removes it and reads back absent' {
        $desktop = Start-Machine -Name 'round-trip'
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 0
        $apply.Text | Should -Match 'PASS: the task is registered'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
        $folder = (Get-EvidenceFolders -Desktop $desktop)[0]
        foreach ($file in @('before.csv', 'collector-hashes.csv', 'apply-started.txt', 'after.csv', 'task-after.xml')) {
            Test-SbtSavedFile -Path (Join-Path $folder $file) | Should -BeTrue -Because $file
        }
        $before = ConvertFrom-SbtCsv -Text (Get-Content -LiteralPath (Join-Path $folder 'before.csv') -Raw)
        $before['present'] | Should -BeExactly 'False'
        $saved = (Get-Content -LiteralPath (Join-Path $folder 'after.csv') -Raw) + (Get-Content -LiteralPath (Join-Path $folder 'task-after.xml') -Raw)
        $saved | Should -Not -Match 'Synthetic Owner'
        $saved | Should -Not -Match 'S-1-5-21'

        $readback = Invoke-Verb -Verb 'Readback'
        $readback.Code | Should -Be 0
        $readback.Text | Should -Match 'SCHED_S_TASK_HAS_NOT_RUN'
        $readback.Text | Should -Match 'PASS\s+collector_sha256'

        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 0
        $undo.Text | Should -Match 'PASS: the task is removed'
        @($global:SbtSynthetic.Calls) | Should -Be @('register', 'unregister')
        $global:SbtSynthetic.Task | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $folder -Filter 'undo-before-*.csv').Count | Should -Be 1 -Because 'undo saves what it removes first'

        $again = Invoke-Verb -Verb 'Undo'
        $again.Code | Should -Be 0
        $again.Text | Should -Match 'already absent'
        @($global:SbtSynthetic.Calls).Count | Should -Be 2 -Because 'a second undo touches nothing'
    }

    It 'refuses to apply when the before state cannot be saved, and registers nothing' {
        $desktop = Start-Machine -Name 'save-fails'
        $global:SbtSynthetic.FailWritesUnder = Join-Path $desktop 'latency-evidence'
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 2
        $apply.Text | Should -Match 'the before state could not be saved'
        $global:SbtSynthetic.Calls.Count | Should -Be 0
    }

    It 'reports FAIL when the register call fails, and undo cleans up what the partial apply left' {
        $desktop = Start-Machine -Name 'partial'
        $partial = @{}
        foreach ($field in (Get-SbtFields)) { $partial[$field] = '' }
        $partial['present'] = 'True'
        $partial['description'] = Get-SbtMarker
        $partial['execute'] = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $global:SbtSynthetic.RegisterPartial = $partial
        $global:SbtSynthetic.RegisterError = 'synthetic: the task was created but the trigger could not be set'
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 1
        $apply.Text | Should -Match 'FAIL register'
        $apply.Text | Should -Match 'FAIL\s+trigger\b'

        $global:SbtSynthetic.RegisterError = $null
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 0 -Because 'the live task is the one saved right after the partial apply'
        $global:SbtSynthetic.Task | Should -BeNullOrEmpty
    }

    It 'reports FAIL when the after state cannot be saved, and undo still removes the task' {
        $desktop = Start-Machine -Name 'export-fails'
        $global:SbtSynthetic.ExportError = 'synthetic: the task XML could not be exported'
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 1
        $apply.Text | Should -Match 'FAIL save after state: synthetic: the task XML could not be exported'
        $apply.Text | Should -Match 'FAIL: the task is not as expected'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
        $folder = (Get-EvidenceFolders -Desktop $desktop)[0]
        Test-Path -LiteralPath (Join-Path $folder 'task-after.xml') | Should -BeFalse

        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 0
        $undo.Text | Should -Match 'PASS: the task is removed'
        @($global:SbtSynthetic.Calls) | Should -Be @('register', 'unregister')
        $global:SbtSynthetic.Task | Should -BeNullOrEmpty
    }

    It 'reports FAIL per value when Task Scheduler holds something other than what was asked' {
        $null = Start-Machine -Name 'drift'
        $global:SbtSynthetic.RegisterDrift = @{ run_level = 'Highest' }
        $apply = Invoke-Verb -Verb 'Apply'
        $apply.Code | Should -Be 1
        $apply.Text | Should -Match 'FAIL\s+run_level\s+live "Highest", expected "Limited"'
        $apply.Text | Should -Match 'PASS\s+logon_type'
        (Invoke-Verb -Verb 'Readback').Code | Should -Be 1
    }

    It 'accepts the account written with or without the computer name' {
        $null = Start-Machine -Name 'account-form'
        $global:SbtSynthetic.RegisterDrift = @{ trigger_user = 'Synthetic Owner'; principal_user = 'synthetic owner' }
        (Invoke-Verb -Verb 'Apply').Code | Should -Be 0
    }

    It 'flags a collector that changed since apply' {
        $null = Start-Machine -Name 'collector-changed'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.Files['C:\Users\Synthetic Owner\win-forensics\collectors\windows\session-bracket.ps1#sha256'] = 'c' * 64
        $readback = Invoke-Verb -Verb 'Readback'
        $readback.Code | Should -Be 1
        $readback.Text | Should -Match 'FAIL\s+collector_sha256'
    }

    It 'still compares every value when the last run cannot be read' {
        $null = Start-Machine -Name 'info-fails'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.TaskInfoError = 'synthetic: the task info could not be read'
        $readback = Invoke-Verb -Verb 'Readback'
        $readback.Code | Should -Be 0
        $readback.Text | Should -Match 'the last run could not be read'
        $readback.Text | Should -Match 'PASS: the task is as -Apply registered it'
    }

    It 'refuses to undo while a game runs, and removes nothing' {
        $null = Start-Machine -Name 'undo-game'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.Processes = @('FortniteClient-Win64-Shipping')
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 2
        $undo.Text | Should -Match 'no_game_running: running: FortniteClient-Win64-Shipping'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
    }

    It 'refuses to undo a task with this name that is not the one apply registered' {
        $null = Start-Machine -Name 'foreign'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.Task['arguments'] = '-File C:\elsewhere\other.ps1'
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 2
        $undo.Text | Should -Match 'not the one -Apply registered'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
    }

    It 'refuses to undo without a saved before state, or with one whose hash no longer matches' {
        $desktop = Start-Machine -Name 'no-saved'
        $global:SbtSynthetic.Task = @{ present = 'True' }
        (Invoke-Verb -Verb 'Undo').Text | Should -Match 'no saved before state'
        $global:SbtSynthetic.Task = $null
        $null = Invoke-Verb -Verb 'Apply'
        $before = Join-Path (Get-EvidenceFolders -Desktop $desktop)[0] 'before.csv'
        Add-Content -LiteralPath $before -Value 'tampered'
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 2
        $undo.Text | Should -Match 'no saved before state'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
    }

    It 'refuses to undo when the state before undo cannot be saved' {
        $desktop = Start-Machine -Name 'undo-save-fails'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.FailWritesUnder = Join-Path $desktop 'latency-evidence'
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 2
        $undo.Text | Should -Match 'state before undo could not be saved'
        @($global:SbtSynthetic.Calls) | Should -Be @('register')
    }

    It 'reports FAIL when the unregister call fails and the task is still there' {
        $null = Start-Machine -Name 'unregister-fails'
        $null = Invoke-Verb -Verb 'Apply'
        $global:SbtSynthetic.UnregisterError = 'synthetic: access denied'
        $undo = Invoke-Verb -Verb 'Undo'
        $undo.Code | Should -Be 1
        $undo.Text | Should -Match 'FAIL unregister'
        $undo.Text | Should -Match 'FAIL\s+present'
    }
}

Describe 'the session bracket logon task script' {
    It 'is plain ASCII, has no Mandatory parameter, and names each verb as a switch' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 126 }).Count | Should -Be 0
        $command = Get-Command -Name $script:ScriptPath
        foreach ($verb in @('Plan', 'Apply', 'Undo', 'Readback')) { $command.Parameters[$verb].ParameterType | Should -Be ([switch]) }
        @($command.Parameters.Values | Where-Object { @($_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count -gt 0 }).Count | Should -Be 0
    }

    It 'registers the task through Task Scheduler with exactly the expected definition' {
        $null = Start-Machine -Name 'adapter-register'
        $context = Get-SbtContext -ScriptRoot 'C:\Users\Synthetic Owner\win-forensics\changes\windows'
        $expected = Get-SbtExpected -Context $context
        $recorded = @{}
        . $script:ScriptPath
        function New-ScheduledTaskAction { [CmdletBinding()] param($Execute, $Argument, $WorkingDirectory, $Id) $recorded['action'] = @{} + $PSBoundParameters; return 'action' }
        function New-ScheduledTaskTrigger { [CmdletBinding()] param([switch]$AtLogOn, [switch]$AtStartup, [switch]$Once, [switch]$Daily, [switch]$Weekly, $At, $User, $RandomDelay) $recorded['trigger'] = @{} + $PSBoundParameters; return 'trigger' }
        function New-ScheduledTaskPrincipal { [CmdletBinding()] param($UserId, $GroupId, $LogonType, $RunLevel, $ProcessTokenSidType, $RequiredPrivilege, $Id) $recorded['principal'] = @{} + $PSBoundParameters; return 'principal' }
        function New-ScheduledTaskSettingsSet { [CmdletBinding()] param($ExecutionTimeLimit, $MultipleInstances, [switch]$Hidden, [switch]$RunOnlyIfIdle, [switch]$AllowStartIfOnBatteries, $Priority) $recorded['settings'] = @{} + $PSBoundParameters; return 'settings' }
        function Register-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName, $Description, $Action, $Trigger, $Principal, $Settings, $RunLevel, $Xml, $InputObject, [switch]$Force) $recorded['register'] = @{} + $PSBoundParameters; return 'task' }
        Register-SbtTask -Expected $expected -Context $context

        $recorded['action'].Keys | Sort-Object | Should -Be @('Argument', 'Execute')
        $recorded['action']['Execute'] | Should -BeExactly 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $recorded['action']['Argument'] | Should -BeExactly '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "C:\Users\Synthetic Owner\win-forensics\collectors\windows\session-bracket.ps1" -Phase baseline -ToEvidenceFolder'
        $recorded['trigger'].Keys | Sort-Object | Should -Be @('AtLogOn', 'User')
        [bool]$recorded['trigger']['AtLogOn'] | Should -BeTrue
        $recorded['trigger']['User'] | Should -BeExactly 'SYNTHETIC-PC\Synthetic Owner'
        $recorded['principal'].Keys | Sort-Object | Should -Be @('LogonType', 'RunLevel', 'UserId')
        $recorded['principal']['UserId'] | Should -BeExactly 'SYNTHETIC-PC\Synthetic Owner'
        [string]$recorded['principal']['LogonType'] | Should -BeExactly 'Interactive'
        [string]$recorded['principal']['RunLevel'] | Should -BeExactly 'Limited'
        $recorded['settings'].Keys | Sort-Object | Should -Be @('ExecutionTimeLimit', 'MultipleInstances')
        $recorded['settings']['ExecutionTimeLimit'] | Should -Be ([timespan]::FromMinutes(10))
        [string]$recorded['settings']['MultipleInstances'] | Should -BeExactly 'IgnoreNew'
        $recorded['register'].Keys | Sort-Object | Should -Be @('Action', 'Description', 'ErrorAction', 'Principal', 'Settings', 'TaskName', 'TaskPath', 'Trigger')
        $recorded['register']['TaskPath'] | Should -BeExactly '\'
        $recorded['register']['TaskName'] | Should -BeExactly 'win-forensics-session-bracket-baseline'
        $recorded['register']['Description'] | Should -BeExactly (Get-SbtMarker)
        $recorded['register']['Action'] | Should -Be 'action'
        $recorded['register']['Trigger'] | Should -Be 'trigger'
        $recorded['register']['Principal'] | Should -Be 'principal'
        $recorded['register']['Settings'] | Should -Be 'settings'
    }

    It 'unregisters exactly the fixed task through Task Scheduler, without a prompt' {
        $recorded = @{}
        . $script:ScriptPath
        function Unregister-ScheduledTask { [CmdletBinding()] param($TaskPath, $TaskName, $InputObject, $CimSession, [switch]$Confirm) $recorded['unregister'] = @{} + $PSBoundParameters }
        Unregister-SbtTask
        $recorded['unregister'].Keys | Sort-Object | Should -Be @('Confirm', 'ErrorAction', 'TaskName', 'TaskPath')
        $recorded['unregister']['TaskPath'] | Should -BeExactly '\'
        $recorded['unregister']['TaskName'] | Should -BeExactly 'win-forensics-session-bracket-baseline'
        [bool]$recorded['unregister']['Confirm'] | Should -BeFalse
    }
}
