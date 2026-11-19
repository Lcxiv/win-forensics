# Pester 5 tests for ../kbd-crash-dump.ps1, run off Windows.
#
# The Windows adapters are replaced by KbdCrashDump.Synthetic.ps1, so these
# tests prove the portable logic (verbs, preconditions, save before change,
# apply, readback, undo and every failure path) against an invented registry,
# and nothing about Windows itself. The evidence folders are real files in
# the test drive. What only the PC can show is listed in
# changes/windows/README.md.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:ChangeScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'kbd-crash-dump.ps1'
    . (Join-Path $PSScriptRoot 'KbdCrashDump.Synthetic.ps1')

    $script:Services = 'SYSTEM\CurrentControlSet\Services'
    $script:KbdParameters = $script:Services + '\kbdhid\Parameters'
    $script:Ps2Parameters = $script:Services + '\i8042prt\Parameters'
    $script:KbdCrashdump = $script:Services + '\kbdhid\crashdump'
    $script:Ps2Crashdump = $script:Services + '\i8042prt\crashdump'

    function Start-KcdCase {
        # A fresh invented machine under a fresh profile folder in the test drive.
        $profilePath = Join-Path $TestDrive ('Users\' + [guid]::NewGuid().ToString('n').Substring(0, 8) + '\someone')
        $desktop = Join-Path $profilePath 'Desktop'
        $null = New-Item -ItemType Directory -Path $desktop -Force
        New-KcdSyntheticMachine -Desktop $desktop -UserProfile $profilePath
        return (Join-Path $desktop 'wf-changes\kbd-crash-dump')
    }

    function Invoke-Kcd {
        param([hashtable]$Arguments = @{})
        $global:KcdSynthetic.Stdout.Clear()
        $global:KcdSynthetic.Calls.Clear()
        $pipeline = @(& $script:ChangeScript @Arguments)
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Pipeline = $pipeline
            Lines    = @($global:KcdSynthetic.Stdout.ToArray())
            Text     = ($global:KcdSynthetic.Stdout.ToArray() -join "`n")
            Calls    = @($global:KcdSynthetic.Calls.ToArray())
            Writes   = @($global:KcdSynthetic.Calls.ToArray() | Where-Object { $_ -notlike 'export *' })
        }
    }

    function Get-KcdFolders {
        param([string]$Root)
        # Callers wrap the result in @(): one folder comes back as a single string.
        if (-not (Test-Path -LiteralPath $Root)) { return }
        Get-ChildItem -LiteralPath $Root -Directory | ForEach-Object { $_.Name } | Sort-Object
    }

    function Get-KcdValueText {
        param([string]$Path, [string]$Name)
        $value = Get-KcdSyntheticValue -Path $Path -Name $Name
        if ($null -eq $value) { return 'absent' }
        return ($value.Kind + ' ' + $value.Data)
    }

    function Get-KcdSnapshot {
        # Every key and value of the invented registry as sorted text, to
        # prove that an undo restores the machine exactly.
        $lines = @()
        foreach ($path in ($global:KcdSynthetic.Registry.Keys | Sort-Object)) {
            $key = $global:KcdSynthetic.Registry[$path]
            $lines += ('[' + $path + ']')
            foreach ($name in ($key.Entries.Keys | Sort-Object)) { $lines += ($name + '=' + $key.Entries[$name].Kind + ':' + $key.Entries[$name].Data) }
        }
        return ($lines -join "`n")
    }
}

Describe 'verbs and usage' {
    It 'runs -Plan when no verb is named, reads only and saves nothing' {
        $root = Start-KcdCase
        $before = Get-KcdSnapshot
        $run = Invoke-Kcd
        $run.ExitCode | Should -Be 0
        $run.Lines[0] | Should -BeExactly 'kbd-crash-dump -Plan: read only, nothing is changed.'
        $run.Writes | Should -BeNullOrEmpty
        $run.Calls | Should -BeNullOrEmpty
        $run.Pipeline | Should -BeNullOrEmpty
        Get-KcdSnapshot | Should -BeExactly $before
        Test-Path -LiteralPath $root | Should -BeFalse
    }

    It 'refuses two verbs at once and changes nothing' {
        $null = Start-KcdCase
        $run = Invoke-Kcd -Arguments @{ Plan = $true; Apply = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: name exactly one of -Plan, -Apply, -Undo, -Readback'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses -Dump1Keys without -AlternateKeys, an undocumented bitmap, and mode options on -Undo' {
        $null = Start-KcdCase
        (Invoke-Kcd -Arguments @{ Dump1Keys = 0x20 }).Text | Should -Match '-Dump1Keys needs -AlternateKeys'
        foreach ($bad in @(0, 0x08, 0x80, 0x102, -1)) {
            $run = Invoke-Kcd -Arguments @{ Apply = $true; AlternateKeys = $true; Dump1Keys = $bad }
            $run.ExitCode | Should -Be 1
            $run.Text | Should -Match 'not a combination of Microsoft''s documented first keys'
            $run.Calls | Should -BeNullOrEmpty
        }
        (Invoke-Kcd -Arguments @{ Undo = $true; AlternateKeys = $true }).Text | Should -Match '-Undo takes the mode from the saved evidence'
        (Invoke-Kcd -Arguments @{ Apply = $true; EvidenceFolder = 'x' }).Text | Should -Match '-EvidenceFolder is for -Undo only'
    }

    It 'never declares a mandatory parameter, so it can never prompt' {
        $command = Get-Command -Name $script:ChangeScript
        $mandatory = @($command.Parameters.Values | Where-Object { @($_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count -gt 0 })
        $mandatory | Should -BeNullOrEmpty
    }
}

Describe '-Plan' {
    It 'prints the current state, what would change, every precondition, the restart and the warning' {
        $root = Start-KcdCase
        $run = Invoke-Kcd -Arguments @{ Plan = $true }
        $run.ExitCode | Should -Be 0
        $run.Text | Should -Match ([regex]::Escape('HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll  now: absent  after -Apply: REG_DWORD 1'))
        $run.Text | Should -Match ([regex]::Escape('HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\CrashOnCtrlScroll  now: absent  after -Apply: REG_DWORD 1'))
        $run.Text | Should -Match 'OK   running elevated'
        $run.Text | Should -Match 'OK   crash dumps are enabled \(CrashDumpEnabled REG_DWORD 7\)'
        $run.Text | Should -Match 'takes effect only after a restart'
        $run.Text | Should -Match 'hold the right CTRL key and press SCROLL LOCK twice'
        $run.Text | Should -Match 'crashes the PC on purpose'
        $run.Text | Should -Match 'READY'
        $run.Text | Should -Match ([regex]::Escape('https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard'))
        Test-Path -LiteralPath $root | Should -BeFalse
    }

    It 'says when -Apply would create a missing Parameters key' {
        $null = Start-KcdCase
        $global:KcdSynthetic.Registry.Remove($script:KbdParameters.ToLowerInvariant())
        $run = Invoke-Kcd
        $run.ExitCode | Should -Be 0
        $run.Text | Should -Match ([regex]::Escape('kbdhid\Parameters\CrashOnCtrlScroll  now: absent (the key does not exist)  after -Apply: REG_DWORD 1 (-Apply creates the key)'))
    }

    It 'refuses with a reason for each failed precondition, and still changes nothing' -TestCases @(
        @{ Case = 'not elevated'; Setup = { $global:KcdSynthetic.Elevated = $false }; Reason = 'FAIL not elevated: open Windows PowerShell with Run as administrator' }
        @{ Case = 'elevation unknown'; Setup = { $global:KcdSynthetic.ElevatedError = 'no identity here' }; Reason = 'FAIL elevation could not be read: no identity here' }
        @{ Case = '32-bit on 64-bit'; Setup = { $global:KcdSynthetic.Bitness = $false }; Reason = 'FAIL a 32-bit PowerShell on 64-bit Windows' }
        @{ Case = 'no PS/2 service'; Setup = { $global:KcdSynthetic.Registry.Remove('system\currentcontrolset\services\i8042prt\parameters'); $global:KcdSynthetic.Registry.Remove('system\currentcontrolset\services\i8042prt') }; Reason = 'i8042prt does not exist; this script never creates a service key' }
        @{ Case = 'unreadable key'; Setup = { $global:KcdSynthetic.ReadErrors['system\currentcontrolset\services\kbdhid\parameters'] = 'Requested registry access is not allowed.' }; Reason = 'kbdhid\\Parameters\\CrashOnCtrlScroll could not be read: Requested registry access is not allowed.' }
        @{ Case = 'string value'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -Values @{ CrashOnCtrlScroll = @{ Kind = 'String'; Data = '1' } } }; Reason = 'is REG_SZ 1, not absent or REG_DWORD 0: unexpected' }
        @{ Case = 'unexpected dword'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -Values @{ CrashOnCtrlScroll = '5' } }; Reason = 'is REG_DWORD 5, not absent or REG_DWORD 0' }
        @{ Case = 'already applied'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Services\i8042prt\Parameters' -Values @{ CrashOnCtrlScroll = '1' } }; Reason = 'is already REG_DWORD 1: the change looks applied' }
        @{ Case = 'alternate keys set'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Services\kbdhid\crashdump' -Values @{ Dump1Keys = '2'; Dump2Key = '61' } }; Reason = 'an alternate sequence is configured' }
        @{ Case = 'dumps off'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Control\CrashControl' -Values @{ CrashDumpEnabled = '0' } }; Reason = 'crash dumps are not shown enabled \(CrashDumpEnabled REG_DWORD 0\)' }
        @{ Case = 'dumps unknown'; Setup = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Control\CrashControl' -Values @{ LogEvent = '1' } }; Reason = 'crash dumps are not shown enabled \(CrashDumpEnabled absent\)' }
    ) {
        param($Case, $Setup, $Reason)
        $root = Start-KcdCase
        & $Setup
        $before = Get-KcdSnapshot
        $plan = Invoke-Kcd -Arguments @{ Plan = $true }
        $plan.ExitCode | Should -Be 1 -Because $Case
        $plan.Text | Should -Match $Reason
        $plan.Text | Should -Match 'REFUSED: \d+ precondition\(s\) failed; -Apply would change nothing.'
        $apply = Invoke-Kcd -Arguments @{ Apply = $true }
        $apply.ExitCode | Should -Be 1 -Because $Case
        $apply.Text | Should -Match 'Nothing changed and nothing was saved.'
        $apply.Calls | Should -BeNullOrEmpty
        Get-KcdSnapshot | Should -BeExactly $before
        Test-Path -LiteralPath $root | Should -BeFalse
    }

    It 'accepts CrashOnCtrlScroll already at REG_DWORD 0' {
        $null = Start-KcdCase
        Set-KcdSyntheticKey -Path $script:KbdParameters -Values @{ CrashOnCtrlScroll = '0'; SyntheticSetting = '7' }
        $run = Invoke-Kcd
        $run.ExitCode | Should -Be 0
        $run.Text | Should -Match 'kbdhid\\Parameters\\CrashOnCtrlScroll  now: REG_DWORD 0  after -Apply: REG_DWORD 1'
    }

    It 'never prints the profile path' {
        $root = Start-KcdCase
        $run = Invoke-Kcd
        $run.Text | Should -Not -Match ([regex]::Escape($global:KcdSynthetic.Profile))
        $run.Text | Should -Match ([regex]::Escape('-Apply saves the before-state first, to a new folder under <profile>'))
        $root | Should -Not -BeNullOrEmpty
    }

    It 'keeps the profile path out of the output, the saved CSV and the log, even inside a value' {
        $root = Start-KcdCase
        Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Control\CrashControl' -Values @{
            CrashDumpEnabled = '7'; LogEvent = '1'; AutoReboot = '1'
            DumpFile         = @{ Kind = 'ExpandString'; Data = ($global:KcdSynthetic.Profile + '\dumps\MEMORY.DMP') }
        }
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 0
        $run.Text | Should -Match ([regex]::Escape('DumpFile  REG_EXPAND_SZ <profile>\dumps\MEMORY.DMP'))
        $folder = Join-Path $root @(Get-KcdFolders -Root $root)[0]
        foreach ($name in @('before-values.csv', 'log.txt')) {
            $text = [System.IO.File]::ReadAllText((Join-Path $folder $name))
            $text | Should -Not -Match ([regex]::Escape($global:KcdSynthetic.Profile))
            $text | Should -Match ([regex]::Escape('<profile>\dumps\MEMORY.DMP'))
        }
        $run.Text | Should -Not -Match ([regex]::Escape($global:KcdSynthetic.Profile))
    }
}

Describe '-Apply' {
    It 'saves, writes both documented values, reads back PASS and says a restart is needed' {
        $root = Start-KcdCase
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 0
        $run.Calls | Should -Be @(
            'export HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters',
            'export HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters',
            'set SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll = 1',
            'set SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\CrashOnCtrlScroll = 1')
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'DWord 1'
        Get-KcdValueText -Path $script:Ps2Parameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'DWord 1'
        Get-KcdValueText -Path $script:KbdParameters -Name 'SyntheticSetting' | Should -BeExactly 'DWord 7'
        $run.Text | Should -Match 'PASS HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll = REG_DWORD 1'
        $run.Text | Should -Match 'PASS HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters\\CrashOnCtrlScroll = REG_DWORD 1'
        $run.Text | Should -Match 'RESTART PENDING: Microsoft documents that this setting takes effect only after a restart. This script never restarts the PC.'
        $run.Text | Should -Match 'RESULT: PASS'
        $run.Text | Should -Not -Match ([regex]::Escape($global:KcdSynthetic.Profile))

        $folders = @(Get-KcdFolders -Root $root)
        $folders | Should -Be @('20260301T120000Z-apply')
        $folder = Join-Path $root $folders[0]
        @(Get-ChildItem -LiteralPath $folder | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('before-values.csv', 'i8042prt-Parameters.reg', 'kbdhid-Parameters.reg', 'log.txt', 'SHA256SUMS.txt', 'writes-begun.txt')
        $sums = @(Get-Content -LiteralPath (Join-Path $folder 'SHA256SUMS.txt'))
        $sums.Count | Should -Be 3
        foreach ($line in $sums) {
            $hash, $name = $line -split '  ', 2
            (Get-FileHash -LiteralPath (Join-Path $folder $name) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $hash
            $run.Text | Should -Match ([regex]::Escape('SHA-256 ' + $line))
        }
        $rows = @(Get-Content -LiteralPath (Join-Path $folder 'before-values.csv') | ConvertFrom-Csv)
        $change = @($rows | Where-Object { $_.Role -eq 'change' })
        $change.Count | Should -Be 2
        foreach ($row in $change) {
            $row.Mode | Should -BeExactly 'scroll-lock'
            $row.Name | Should -BeExactly 'CrashOnCtrlScroll'
            $row.KeyExisted | Should -BeExactly 'True'
            $row.ValueExisted | Should -BeExactly 'False'
            $row.Target | Should -BeExactly '1'
        }
        @($rows | Where-Object { $_.Role -eq 'context' -and $_.Name -eq 'DumpFile' })[0].Data | Should -BeExactly '%SystemRoot%\MEMORY.DMP'
        $log = Get-Content -LiteralPath (Join-Path $folder 'log.txt') -Raw
        $log | Should -Match 'RESULT: PASS'
        $log | Should -Not -Match ([regex]::Escape($global:KcdSynthetic.Profile))
        [System.IO.File]::ReadAllBytes((Join-Path $folder 'before-values.csv'))[0] | Should -Be ([byte][char]'"')
    }

    It 'creates a missing Parameters key under its existing service key, records that, and exports the service key' {
        $root = Start-KcdCase
        $global:KcdSynthetic.Registry.Remove($script:Ps2Parameters.ToLowerInvariant())
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 0
        $run.Calls | Should -Contain 'export HKLM\SYSTEM\CurrentControlSet\Services\i8042prt'
        $run.Calls | Should -Contain ('create-key ' + $script:Ps2Parameters)
        $folder = Join-Path $root @(Get-KcdFolders -Root $root)[0]
        Test-Path -LiteralPath (Join-Path $folder 'i8042prt.reg') | Should -BeTrue
        $row = @(Get-Content -LiteralPath (Join-Path $folder 'before-values.csv') | ConvertFrom-Csv | Where-Object { $_.Role -eq 'change' -and $_.Key -like '*i8042prt*' })[0]
        $row.KeyExisted | Should -BeExactly 'False'
    }

    It 'refuses when a reg export fails, writing nothing' {
        $root = Start-KcdCase
        $global:KcdSynthetic.ExportCodes['hklm\system\currentcontrolset\services\i8042prt\parameters'] = 1
        $before = Get-KcdSnapshot
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: reg export of HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters failed with exit code 1. Nothing changed.'
        $run.Writes | Should -BeNullOrEmpty
        Get-KcdSnapshot | Should -BeExactly $before
        # The partial folder holds no SHA256SUMS.txt, so -Undo can never restore from it.
        $folder = Join-Path $root @(Get-KcdFolders -Root $root)[0]
        Test-Path -LiteralPath (Join-Path $folder 'SHA256SUMS.txt') | Should -BeFalse
        $undo = Invoke-Kcd -Arguments @{ Undo = $true }
        $undo.ExitCode | Should -Be 1
        $undo.Writes | Should -BeNullOrEmpty
    }

    It 'refuses when a reg export reports success but writes no file' {
        $null = Start-KcdCase
        $global:KcdSynthetic.ExportNoFile['hklm\system\currentcontrolset\services\kbdhid\parameters'] = $true
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'reported success but wrote no file'
        $run.Writes | Should -BeNullOrEmpty
    }

    It 'refuses when the evidence folder cannot be created' {
        $null = Start-KcdCase
        $blocker = Join-Path $TestDrive ('blocker-' + [guid]::NewGuid().ToString('n'))
        Set-Content -LiteralPath $blocker -Value 'a file where the folder should go'
        $run = Invoke-Kcd -Arguments @{ Apply = $true; EvidenceRoot = (Join-Path $blocker 'sub') }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: saving the evidence failed'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses when a value changes between the precheck and the save' {
        $null = Start-KcdCase
        $global:KcdSynthetic.OnExport = { Set-KcdSyntheticKey -Path 'SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -Values @{ CrashOnCtrlScroll = '0' } }
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: the values changed while they were being saved'
        $run.Writes | Should -BeNullOrEmpty
    }

    It 'stops at a failed write, reports FAIL with exit 2, and -Undo then restores the exact before-state' {
        $root = Start-KcdCase
        $global:KcdSynthetic.Registry.Remove($script:Ps2Parameters.ToLowerInvariant())
        $before = Get-KcdSnapshot
        $global:KcdSynthetic.WriteErrors['system\currentcontrolset\services\i8042prt\parameters|crashonctrlscroll'] = 'Access to the registry key is denied.'
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 2
        $run.Text | Should -Match 'WRITE FAILED HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters\\CrashOnCtrlScroll: Access to the registry key is denied.'
        $run.Text | Should -Match 'PASS HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll = REG_DWORD 1'
        $run.Text | Should -Match 'FAIL HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters\\CrashOnCtrlScroll is absent \(the key does not exist\), expected REG_DWORD 1'
        $run.Text | Should -Match 'RESULT: FAIL. The machine may be partly changed. -Undo restores'
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'DWord 1'

        # A second apply refuses: the half applied value is not the expected before-state.
        $again = Invoke-Kcd -Arguments @{ Apply = $true }
        $again.ExitCode | Should -Be 1
        $again.Writes | Should -BeNullOrEmpty

        $global:KcdSynthetic.WriteErrors.Clear()
        $undo = Invoke-Kcd -Arguments @{ Undo = $true }
        $undo.ExitCode | Should -Be 0
        $undo.Writes | Should -Be @('delete-value SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll')
        $undo.Text | Should -Match 'unchanged HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters\\CrashOnCtrlScroll \(already as saved\)'
        $undo.Text | Should -Match 'RESULT: PASS'
        Get-KcdSnapshot | Should -BeExactly $before
        @(Get-KcdFolders -Root $root | Where-Object { $_ -like '*-undo' }).Count | Should -Be 1
    }

    It 'reports a readback mismatch as FAIL with exit 2' {
        $null = Start-KcdCase
        $global:KcdSynthetic.AfterWrite = {
            param($Path, $Name, $Value)
            $null = $Value
            if ($Path -like '*i8042prt*') { $global:KcdSynthetic.Registry[$Path.ToLowerInvariant()].Entries[$Name] = @{ Kind = 'DWord'; Data = '0' } }
        }
        $run = Invoke-Kcd -Arguments @{ Apply = $true }
        $run.ExitCode | Should -Be 2
        $run.Text | Should -Match 'FAIL HKLM\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters\\CrashOnCtrlScroll is REG_DWORD 0, expected REG_DWORD 1'
        $run.Text | Should -Match 'RESULT: FAIL'
    }
}

Describe '-Readback' {
    It 'fails before any apply, passes after it, and says whether a restart followed' {
        $null = Start-KcdCase
        $first = Invoke-Kcd -Arguments @{ Readback = $true }
        $first.ExitCode | Should -Be 1
        $first.Text | Should -Match 'FAIL HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll is absent, expected REG_DWORD 1'
        $first.Text | Should -Match 'No apply or undo folder that reached its writes under'
        $first.Calls | Should -BeNullOrEmpty

        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $pending = Invoke-Kcd -Arguments @{ Readback = $true }
        $pending.ExitCode | Should -Be 0
        $pending.Calls | Should -BeNullOrEmpty
        $pending.Text | Should -Match 'takes effect only after a restart'
        $pending.Text | Should -Match 'RESTART PENDING: the PC last booted at 2026-03-01T08:00:00Z, before the newest apply at 2026-03-01T12:00:00Z'
        $pending.Text | Should -Match 'RESULT: PASS'

        $global:KcdSynthetic.LastBoot = [datetime]::new(2026, 3, 1, 13, 0, 0, [System.DateTimeKind]::Utc)
        $done = Invoke-Kcd -Arguments @{ Readback = $true }
        $done.Text | Should -Match 'Restart done: the PC booted at 2026-03-01T13:00:00Z, after the newest apply at 2026-03-01T12:00:00Z'

        $global:KcdSynthetic.LastBootError = 'no CIM here'
        (Invoke-Kcd -Arguments @{ Readback = $true }).Text | Should -Match 'the last boot time could not be read \(no CIM here\), so whether a restart followed is unknown'
    }

    It 'never counts a refused -Apply or -Undo folder as the newest change' {
        $root = Start-KcdCase
        $global:KcdSynthetic.ExportCodes['hklm\system\currentcontrolset\services\i8042prt\parameters'] = 1
        $refusedApply = Invoke-Kcd -Arguments @{ Apply = $true }
        $refusedApply.ExitCode | Should -Be 1
        @(Get-KcdFolders -Root $root).Count | Should -Be 1
        (Invoke-Kcd -Arguments @{ Readback = $true }).Text | Should -Match 'No apply or undo folder that reached its writes under'

        $global:KcdSynthetic.ExportCodes.Clear()
        (Invoke-Kcd -Arguments @{ Apply = $true }).ExitCode | Should -Be 0
        $global:KcdSynthetic.LastBoot = [datetime]::new(2026, 3, 2, 8, 0, 0, [System.DateTimeKind]::Utc)
        $global:KcdSynthetic.Now = [datetime]::new(2026, 3, 2, 12, 0, 0, [System.DateTimeKind]::Utc)
        $global:KcdSynthetic.ExportCodes['hklm\system\currentcontrolset\services\kbdhid\parameters'] = 1
        $refusedUndo = Invoke-Kcd -Arguments @{ Undo = $true }
        $refusedUndo.ExitCode | Should -Be 1
        $refusedUndo.Writes | Should -BeNullOrEmpty
        @(Get-KcdFolders -Root $root | Where-Object { $_ -like '*-undo' }).Count | Should -Be 1

        $readback = Invoke-Kcd -Arguments @{ Readback = $true }
        $readback.ExitCode | Should -Be 0
        $readback.Text | Should -Match 'Restart done: the PC booted at 2026-03-02T08:00:00Z, after the newest apply at'
        $readback.Text | Should -Not -Match 'RESTART PENDING: the PC last booted'
    }

    It 'treats an unreadable value as FAIL, never as absent' {
        $null = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $global:KcdSynthetic.ReadErrors['system\currentcontrolset\services\kbdhid\parameters'] = 'denied'
        $run = Invoke-Kcd -Arguments @{ Readback = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'FAIL HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll is unreadable \(denied\)'
    }
}

Describe '-Undo' {
    It 'restores absent values by deleting them and touches nothing else' {
        $root = Start-KcdCase
        $before = Get-KcdSnapshot
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 0
        $run.Calls | Should -Be @(
            'export HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters',
            'export HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters',
            'delete-value SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll',
            'delete-value SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\CrashOnCtrlScroll')
        $run.Text | Should -Match 'PASS HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll is absent, as saved'
        $run.Text | Should -Match 'RESULT: PASS'
        Get-KcdSnapshot | Should -BeExactly $before
        $undoName = @(Get-KcdFolders -Root $root | Where-Object { $_ -like '*-undo' })[0]
        $undoFolder = Join-Path $root $undoName
        @(Get-ChildItem -LiteralPath $undoFolder | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('before-undo-values.csv', 'i8042prt-Parameters.reg', 'kbdhid-Parameters.reg', 'log.txt', 'SHA256SUMS.txt', 'writes-begun.txt')
    }

    It 'restores a value that existed as REG_DWORD 0 to REG_DWORD 0' {
        $null = Start-KcdCase
        Set-KcdSyntheticKey -Path $script:KbdParameters -Values @{ CrashOnCtrlScroll = '0'; SyntheticSetting = '7' }
        $before = Get-KcdSnapshot
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 0
        $run.Writes | Should -Contain 'set SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll = 0'
        Get-KcdSnapshot | Should -BeExactly $before
    }

    It 'removes a key the apply created once it is empty, and keeps it when something else wrote to it' {
        $null = Start-KcdCase
        $global:KcdSynthetic.Registry.Remove($script:KbdParameters.ToLowerInvariant())
        $before = Get-KcdSnapshot
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 0
        $run.Writes | Should -Contain ('delete-key ' + $script:KbdParameters)
        Get-KcdSnapshot | Should -BeExactly $before

        $null = Start-KcdCase
        $global:KcdSynthetic.Registry.Remove($script:KbdParameters.ToLowerInvariant())
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $global:KcdSynthetic.Registry[$script:KbdParameters.ToLowerInvariant()].Entries['WrittenByWindows'] = @{ Kind = 'DWord'; Data = '3' }
        $kept = Invoke-Kcd -Arguments @{ Undo = $true }
        $kept.ExitCode | Should -Be 0
        $kept.Writes | Should -Not -Contain ('delete-key ' + $script:KbdParameters)
        $kept.Text | Should -Match 'kept key HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters: absent before the apply, but it now holds values'
        Get-KcdValueText -Path $script:KbdParameters -Name 'WrittenByWindows' | Should -BeExactly 'DWord 3'
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'absent'
    }

    It 'uses the newest apply folder, or the one named with -EvidenceFolder' {
        $root = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $null = Invoke-Kcd -Arguments @{ Undo = $true }
        Set-KcdSyntheticKey -Path $script:KbdParameters -Values @{ CrashOnCtrlScroll = '0'; SyntheticSetting = '7' }
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $applies = @(Get-KcdFolders -Root $root | Where-Object { $_ -like '*-apply' })
        $applies.Count | Should -Be 2
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.Text | Should -Match ([regex]::Escape($applies[1]))
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'DWord 0'

        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $named = Invoke-Kcd -Arguments @{ Undo = $true; EvidenceFolder = (Join-Path $root $applies[1]) }
        $named.ExitCode | Should -Be 0
        $named.Text | Should -Match ([regex]::Escape('Restoring from: ' + '<profile>'))
    }

    It 'refuses without an apply folder' {
        $null = Start-KcdCase
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: no apply folder under'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses a CSV that does not match its saved SHA-256' {
        $root = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $csv = Join-Path (Join-Path $root @(Get-KcdFolders -Root $root)[0]) 'before-values.csv'
        $text = [System.IO.File]::ReadAllText($csv) -replace '"False","","",', '"True","DWord","9",'
        [System.IO.File]::WriteAllText($csv, $text)
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: before-values.csv does not match its saved SHA-256'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses a CSV that names a key this script never writes, even with a matching hash' {
        $root = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $folder = Join-Path $root @(Get-KcdFolders -Root $root)[0]
        $csv = Join-Path $folder 'before-values.csv'
        $text = [System.IO.File]::ReadAllText($csv) -replace 'Services\\kbdhid\\Parameters","CrashOnCtrlScroll"', 'Services\\Other\\Parameters","CrashOnCtrlScroll"'
        [System.IO.File]::WriteAllText($csv, $text)
        $hash = (Get-FileHash -LiteralPath $csv -Algorithm SHA256).Hash.ToLowerInvariant()
        $sums = @(Get-Content -LiteralPath (Join-Path $folder 'SHA256SUMS.txt') | ForEach-Object { if ($_ -like '*before-values.csv') { $hash + '  before-values.csv' } else { $_ } })
        [System.IO.File]::WriteAllText((Join-Path $folder 'SHA256SUMS.txt'), (($sums -join "`r`n") + "`r`n"))
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: the saved CSV has no single row for HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses when something else changed a value since the apply' {
        $null = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        Set-KcdSyntheticKey -Path $script:Ps2Parameters -Values @{ CrashOnCtrlScroll = '4'; SyntheticSetting = '7' }
        $before = Get-KcdSnapshot
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'is REG_DWORD 4: neither the saved absent nor the applied REG_DWORD 1; something else changed it'
        $run.Calls | Should -BeNullOrEmpty
        Get-KcdSnapshot | Should -BeExactly $before
    }

    It 'refuses when not elevated' {
        $null = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $global:KcdSynthetic.Elevated = $false
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'FAIL not elevated'
        $run.Calls | Should -BeNullOrEmpty
    }

    It 'refuses when saving the state before the undo fails' {
        $null = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $global:KcdSynthetic.ExportCodes['hklm\system\currentcontrolset\services\kbdhid\parameters'] = 1
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'REFUSED: reg export of HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters failed with exit code 1. Nothing changed.'
        $run.Writes | Should -BeNullOrEmpty
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'DWord 1'
    }

    It 'reports a failed restore with exit 2 and succeeds when run again' {
        $null = Start-KcdCase
        $before = Get-KcdSnapshot
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $global:KcdSynthetic.WriteErrors['system\currentcontrolset\services\kbdhid\parameters|crashonctrlscroll'] = 'denied'
        $run = Invoke-Kcd -Arguments @{ Undo = $true }
        $run.ExitCode | Should -Be 2
        $run.Text | Should -Match 'WRITE FAILED HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters\\CrashOnCtrlScroll: denied'
        $run.Text | Should -Match 'RESULT: FAIL'
        $global:KcdSynthetic.WriteErrors.Clear()
        $again = Invoke-Kcd -Arguments @{ Undo = $true }
        $again.ExitCode | Should -Be 0
        Get-KcdSnapshot | Should -BeExactly $before
    }
}

Describe '-AlternateKeys' {
    It 'plans, applies Microsoft''s example under both crashdump keys, reads back, and undoes to the exact before-state' {
        $root = Start-KcdCase
        $before = Get-KcdSnapshot
        $plan = Invoke-Kcd -Arguments @{ AlternateKeys = $true }
        $plan.ExitCode | Should -Be 0
        $plan.Text | Should -Match 'hold right CTRL and press the SPACEBAR twice'
        $plan.Text | Should -Match 'kbdhid\\crashdump\\Dump2Key  now: absent \(the key does not exist\)  after -Apply: REG_DWORD 61 \(0x3d\) \(-Apply creates the key\)'
        $plan.Text | Should -Match 'CrashOnCtrlScroll is absent or REG_DWORD 0, as Microsoft requires for the alternate keys'

        $apply = Invoke-Kcd -Arguments @{ Apply = $true; AlternateKeys = $true }
        $apply.ExitCode | Should -Be 0
        $apply.Calls | Should -Be @(
            'export HKLM\SYSTEM\CurrentControlSet\Services\kbdhid',
            'export HKLM\SYSTEM\CurrentControlSet\Services\i8042prt',
            ('create-key ' + $script:KbdCrashdump),
            'set SYSTEM\CurrentControlSet\Services\kbdhid\crashdump\Dump1Keys = 2',
            'set SYSTEM\CurrentControlSet\Services\kbdhid\crashdump\Dump2Key = 61',
            ('create-key ' + $script:Ps2Crashdump),
            'set SYSTEM\CurrentControlSet\Services\i8042prt\crashdump\Dump1Keys = 2',
            'set SYSTEM\CurrentControlSet\Services\i8042prt\crashdump\Dump2Key = 61')
        Get-KcdValueText -Path $script:KbdParameters -Name 'CrashOnCtrlScroll' | Should -BeExactly 'absent'

        $readback = Invoke-Kcd -Arguments @{ Readback = $true; AlternateKeys = $true }
        $readback.ExitCode | Should -Be 0
        (Invoke-Kcd -Arguments @{ Readback = $true }).ExitCode | Should -Be 1

        $undo = Invoke-Kcd -Arguments @{ Undo = $true }
        $undo.ExitCode | Should -Be 0
        $undo.Text | Should -Match 'Mode of that apply: alternate keys'
        $undo.Writes | Should -Contain ('delete-key ' + $script:KbdCrashdump)
        $undo.Writes | Should -Contain ('delete-key ' + $script:Ps2Crashdump)
        Get-KcdSnapshot | Should -BeExactly $before
        $root | Should -Not -BeNullOrEmpty
    }

    It 'takes a documented -Dump1Keys combination and names every first key it allows' {
        $null = Start-KcdCase
        $run = Invoke-Kcd -Arguments @{ Apply = $true; AlternateKeys = $true; Dump1Keys = 0x11 }
        $run.ExitCode | Should -Be 0
        $run.Text | Should -Match 'hold one of right SHIFT or left SHIFT and press the SPACEBAR twice'
        Get-KcdValueText -Path $script:KbdCrashdump -Name 'Dump1Keys' | Should -BeExactly 'DWord 17'
        (Invoke-Kcd -Arguments @{ Readback = $true; AlternateKeys = $true }).ExitCode | Should -Be 1
        (Invoke-Kcd -Arguments @{ Readback = $true; AlternateKeys = $true; Dump1Keys = 0x11 }).ExitCode | Should -Be 0
        $undo = Invoke-Kcd -Arguments @{ Undo = $true }
        $undo.ExitCode | Should -Be 0
    }

    It 'refuses while CrashOnCtrlScroll is 1, as Microsoft requires it 0 or removed' {
        $null = Start-KcdCase
        $null = Invoke-Kcd -Arguments @{ Apply = $true }
        $run = Invoke-Kcd -Arguments @{ Apply = $true; AlternateKeys = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'Microsoft requires it to be 0 or removed for the alternate keys'
        $run.Writes | Should -BeNullOrEmpty
    }

    It 'refuses when alternate values already exist' {
        $null = Start-KcdCase
        Set-KcdSyntheticKey -Path $script:Ps2Crashdump -Values @{ Dump2Key = '61' }
        $run = Invoke-Kcd -Arguments @{ Apply = $true; AlternateKeys = $true }
        $run.ExitCode | Should -Be 1
        $run.Text | Should -Match 'an alternate sequence is already set'
    }
}
