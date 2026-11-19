# Pester 5 tests for gpu-affinity-1a.ps1 and the Stutter Guard journal
# reader, run off Windows against SyntheticGpuAffinity1a.ps1. They prove the
# portable logic (selection, cross-checks, refusals, the saved before-state,
# the write order, undo, readback) and nothing about Windows itself; what
# only the PC can show is listed in changes/windows/README.md.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:ChangeRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:ChangeRoot '_gpu-affinity-1a-lib.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticGpuAffinity1a.ps1')

    function Invoke-Test1a {
        # Runs the real entry script in this process against the synthetic
        # machine and returns its exit code and output lines.
        param([string[]]$Verb = @(), [hashtable]$Extra = @{})
        $global:Wf1aSynthetic.Out.Clear()
        $all = @{ StutterGuardDataDirectory = $script:SgDir; EvidenceRoot = $script:EvidenceRoot }
        foreach ($v in $Verb) { $all[$v] = $true }
        foreach ($k in $Extra.Keys) { $all[$k] = $Extra[$k] }
        & (Join-Path $script:ChangeRoot 'gpu-affinity-1a.ps1') @all
        $code = $LASTEXITCODE
        return [pscustomobject]@{ ExitCode = $code; Lines = @($global:Wf1aSynthetic.Out.ToArray()); Text = ($global:Wf1aSynthetic.Out.ToArray() -join "`n") }
    }

    function Get-TestAffinityKey {
        return ('SYSTEM\CurrentControlSet\Enum\' + $global:Wf1aSynthetic.InstanceId + '\Device Parameters\Interrupt Management\Affinity Policy')
    }

    function Get-TestLive {
        param([string]$Name)
        return (Get-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name $Name)
    }

    function Get-TestEvidenceFolders {
        if (-not (Test-Path -LiteralPath $script:EvidenceRoot)) { return @() }
        return @(Get-ChildItem -LiteralPath $script:EvidenceRoot -Directory)
    }
}

Describe 'gpu-affinity-1a' {
    BeforeEach {
        New-Wf1aSyntheticMachine
        $script:SgDir = Join-Path $TestDrive ('sg-' + [guid]::NewGuid().ToString('N'))
        $script:EvidenceRoot = Join-Path $TestDrive ('evidence-' + [guid]::NewGuid().ToString('N'))
        Initialize-Wf1aSyntheticStutterGuard -DataDirectory $script:SgDir
    }

    Describe 'Stutter Guard journal reader' {
        It 'reads the Originals rows as data and hashes the file' {
            $j = Read-WfSgJournal -Path (Join-Path $script:SgDir 'journal.json')
            $j.Status | Should -Be 'ok'
            $j.Originals.Count | Should -Be 3
            $j.Sha256 | Should -Match '^[0-9A-F]{64}$'
            $j.Originals[1].When | Should -Be ([datetime]::new(2026, 11, 12, 8, 19, 50).AddTicks(4512731))
            $j.Originals[1].Existed | Should -BeFalse
            $j.Originals[1].ValueKind | Should -BeNullOrEmpty
        }

        It 'reports a missing journal as missing' {
            (Read-WfSgJournal -Path (Join-Path $TestDrive 'nowhere.json')).Status | Should -Be 'missing'
        }

        It 'refuses <Case>' -ForEach @(
            @{ Case = 'an empty file'; Text = ''; Reason = 'empty' }
            @{ Case = 'text that is not JSON'; Text = '{ "Originals": [ '; Reason = 'not valid JSON' }
            @{ Case = 'a top level list'; Text = '[ 1, 2 ]'; Reason = 'not a JSON object' }
            @{ Case = 'no Originals'; Text = '{ "Version": 1 }'; Reason = 'no Originals' }
            @{ Case = 'a null Originals'; Text = '{ "Originals": null }'; Reason = 'Originals is null' }
            @{ Case = 'an Originals object'; Text = '{ "Originals": { "a": 1 } }'; Reason = 'not a list' }
            @{ Case = 'a row without TweakId'; Text = '{ "Originals": [ { "Kind": "reg", "Target": "x", "Existed": false, "When": "2026-11-12T08:00:00+01:00" } ] }'; Reason = 'no text TweakId' }
            @{ Case = 'a text Existed'; Text = '{ "Originals": [ { "TweakId": "t", "Kind": "reg", "Target": "x", "Existed": "false", "When": "2026-11-12T08:00:00+01:00" } ] }'; Reason = 'Existed' }
            @{ Case = 'a numeric Data'; Text = '{ "Originals": [ { "TweakId": "t", "Kind": "reg", "Target": "x", "Existed": true, "ValueKind": "DWord", "Data": 4, "When": "2026-11-12T08:00:00+01:00" } ] }'; Reason = 'Data that is not text' }
            @{ Case = 'a When that is not a date'; Text = '{ "Originals": [ { "TweakId": "t", "Kind": "reg", "Target": "x", "Existed": false, "When": "yesterday" } ] }'; Reason = 'not a date' }
            @{ Case = 'a row without When'; Text = '{ "Originals": [ { "TweakId": "t", "Kind": "reg", "Target": "x", "Existed": false } ] }'; Reason = 'no When' }
        ) {
            $p = Join-Path $TestDrive 'bad.json'
            [System.IO.File]::WriteAllText($p, $Text, (New-Object System.Text.UTF8Encoding($false)))
            $j = Read-WfSgJournal -Path $p
            $j.Status | Should -Be 'unreadable'
            $j.Reason | Should -Match ([regex]::Escape($Reason))
        }

        It 'refuses bytes that are not UTF-8' {
            $p = Join-Path $TestDrive 'latin.json'
            [System.IO.File]::WriteAllBytes($p, [byte[]](0x7B, 0xE9, 0xFF, 0x7D))
            (Read-WfSgJournal -Path $p).Reason | Should -Match 'not UTF-8'
        }

        It 'selects one row by kind and target, target ignoring case' {
            $j = Read-WfSgJournal -Path (Join-Path $script:SgDir 'journal.json')
            $keys = Get-Wf1aDeviceKeys -InstanceId $global:Wf1aSynthetic.InstanceId
            $target = (Get-Wf1aJournalTarget -Keys $keys -ValueName 'DevicePolicy').ToLowerInvariant()
            $s = Select-WfSgOriginalRow -Journal $j -Kind 'reg' -Target $target -TweakId $keys.TweakId
            $s.Status | Should -Be 'ok'
            $s.Value.Exists | Should -BeFalse
            (Select-WfSgOriginalRow -Journal $j -Kind 'REG' -Target $target -TweakId $keys.TweakId).Status | Should -Be 'missing'
            (Select-WfSgOriginalRow -Journal $j -Kind 'reg' -Target $target -TweakId 'irq.other').Status | Should -Be 'other_tweak'
        }

        It 'calls two rows for one target ambiguous' {
            Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @(
                (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy'),
                (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy' -Target ('HKLM\SYSTEM\CURRENTCONTROLSET\ENUM\' + $global:Wf1aSynthetic.InstanceId + '\Device Parameters\Interrupt Management\Affinity Policy|devicepolicy'))
            )
            $j = Read-WfSgJournal -Path (Join-Path $script:SgDir 'journal.json')
            $keys = Get-Wf1aDeviceKeys -InstanceId $global:Wf1aSynthetic.InstanceId
            (Select-WfSgOriginalRow -Journal $j -Kind 'reg' -Target (Get-Wf1aJournalTarget -Keys $keys -ValueName 'DevicePolicy') -TweakId $keys.TweakId).Status | Should -Be 'ambiguous'
        }

        It 'decodes <Kind> data as RegValue.Serialize wrote it' -ForEach @(
            @{ Kind = 'DWord'; Data = '4'; Expect = 'REG_DWORD 0x00000004 (4)' }
            @{ Kind = 'QWord'; Data = '64'; Expect = 'REG_QWORD 0x0000000000000040' }
            @{ Kind = 'Binary'; Data = '4000000000000000'; Expect = 'REG_BINARY 40 00 00 00 00 00 00 00' }
            @{ Kind = 'String'; Data = 'x'; Expect = 'REG_SZ (text not printed)' }
        ) {
            $d = ConvertFrom-WfSgRowValue -Existed $true -ValueKind $Kind -Data $Data
            $d.Ok | Should -BeTrue
            Format-WfRegValue -Value $d.Value | Should -BeExactly $Expect
        }

        It 'refuses data it cannot restore exactly' -ForEach @(
            @{ Kind = 'DWord'; Data = '-1' }
            @{ Kind = 'DWord'; Data = '0x4' }
            @{ Kind = 'Binary'; Data = '4G' }
            @{ Kind = 'MultiString'; Data = 'a' }
            @{ Kind = $null; Data = $null }
        ) {
            (ConvertFrom-WfSgRowValue -Existed $true -ValueKind $Kind -Data $Data).Ok | Should -BeFalse
        }

        It 'names backup files as BackupSet.SafeName does' {
            $k = 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1\4&1a2b3c4d&0&0008\Device Parameters\Interrupt Management'
            Get-WfSgSafeName -Text $k | Should -BeExactly 'HKLM_SYSTEM_CurrentControlSet_Enum_PCI_VEN_1234_DEV_5678_SUBSYS_9ABC1234_REV_A1_4_1a2b3c4d_0_0008_Device_Parameters_Interrupt_Management'
            # Over 150 characters: cut and hashed (oracle computed separately from
            # the C# algorithm at the pinned commit).
            Get-WfSgSafeName -Text ($k + '\MessageSignaledInterruptProperties\Extra\Deeper\AndDeeper') | Should -BeExactly 'HKLM_SYSTEM_CurrentControlSet_Enum_PCI_VEN_1234_DEV_5678_SUBSYS_9ABC1234_REV_A1_4_1a2b3c4d_0_0008_Device_Parameters_Interrupt_Management_Mess-74462525'
        }

        It 'picks the latest session of the row''s day created before the row' {
            $keys = Get-Wf1aDeviceKeys -InstanceId $global:Wf1aSynthetic.InstanceId
            $f = Find-WfSgSessionRegFile -DataDirectory $script:SgDir -ExportedKeyPath ('HKLM\' + $keys.Interrupt) -When ([datetime]::new(2026, 11, 12, 8, 19, 50))
            $f.Status | Should -Be 'ok'
            $f.Session | Should -Be '20261112-081948'
            (Find-WfSgSessionRegFile -DataDirectory $script:SgDir -ExportedKeyPath ('HKLM\' + $keys.Interrupt) -When ([datetime]::new(2026, 11, 13, 8, 0, 0))).Status | Should -Be 'missing'
        }
    }

    Describe 'reg export parser' {
        It 'reads UTF-16 exports with continuation lines, dword, hex and hex(b)' {
            $p = Join-Path $TestDrive 'a.reg'
            $text = "Windows Registry Editor Version 5.00`r`n`r`n[HKEY_LOCAL_MACHINE\SOFTWARE\X]`r`n`"D`"=dword:0000000a`r`n`"B`"=hex:40,00,00,00,\`r`n  00,00,00,00`r`n`"Q`"=hex(b):40,00,00,00,00,00,00,00`r`n`"S`"=`"a\`"b`"`r`n@=`"default`"`r`n"
            [System.IO.File]::WriteAllText($p, $text, (New-Object System.Text.UnicodeEncoding($false, $true)))
            $r = Read-WfRegExportFile -Path $p
            $r.Status | Should -Be 'ok'
            $s = $r.Sections['hkey_local_machine\software\x']
            $s['d'].Number | Should -Be 10
            (ConvertTo-WfHex -Bytes $s['b'].Bytes) | Should -BeExactly '4000000000000000'
            $s['q'].Kind | Should -Be 'QWord'
            $s['q'].Number | Should -Be 64
            $s['s'].Text | Should -BeExactly 'a"b'
            $s[''].Text | Should -BeExactly 'default'
        }

        It 'refuses <Case>' -ForEach @(
            @{ Case = 'a missing header'; Text = "[HKEY_LOCAL_MACHINE\X]`r`n" }
            @{ Case = 'a value deletion'; Text = "Windows Registry Editor Version 5.00`r`n[HKEY_LOCAL_MACHINE\X]`r`n`"A`"=-`r`n" }
            @{ Case = 'a key deletion'; Text = "Windows Registry Editor Version 5.00`r`n[-HKEY_LOCAL_MACHINE\X]`r`n" }
            @{ Case = 'a duplicate value'; Text = "Windows Registry Editor Version 5.00`r`n[HKEY_LOCAL_MACHINE\X]`r`n`"A`"=dword:00000001`r`n`"a`"=dword:00000002`r`n" }
            @{ Case = 'a value before any key'; Text = "Windows Registry Editor Version 5.00`r`n`"A`"=dword:00000001`r`n" }
            @{ Case = 'a short hex(b)'; Text = "Windows Registry Editor Version 5.00`r`n[HKEY_LOCAL_MACHINE\X]`r`n`"A`"=hex(b):01,02`r`n" }
        ) {
            $p = Join-Path $TestDrive 'bad.reg'
            [System.IO.File]::WriteAllText($p, $Text, (New-Object System.Text.UnicodeEncoding($false, $true)))
            (Read-WfRegExportFile -Path $p).Status | Should -Be 'unreadable'
        }
    }

    Describe 'Plan' {
        It 'is the default verb, reads only and is ready on the expected machine' {
            $r = Invoke-Test1a
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Verb: Plan'
            $r.Text | Should -Match 'READY'
            $r.Text | Should -Match 'DevicePolicy: REG_DWORD 0x00000004 \(4\) -> delete the value'
            $r.Text | Should -Match 'AssignmentSetOverride: REG_BINARY 40 00 00 00 00 00 00 00 \(CPU 6\) -> delete the value'
            $r.Text | Should -Match 'DevicePriority: .* left as it is'
            $r.Text | Should -Match 'Session 20261112-081948 export'
            $r.Text | Should -Match 'no mask recorded'
            $r.Text | Should -Match 'Restart: needed'
            $r.Text | Should -Match 'Stutter Guard task "Device power saving off"'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
            $global:Wf1aSynthetic.Exports.Count | Should -Be 0
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'never prints the instance path' {
            $r = Invoke-Test1a
            $r.Text | Should -Not -Match 'VEN_'
            $r.Text | Should -Not -Match '1A2B3C4D'
            $r.Text | Should -Match 'display-adapter-1'
        }

        It 'plans without elevation and says Apply needs it' {
            $global:Wf1aSynthetic.Elevated = $false
            $r = Invoke-Test1a -Verb 'Plan'
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Elevated: false'
        }

        It 'refuses when <Case>' -ForEach @(
            @{ Case = 'no display adapter is present'; Setup = { $global:Wf1aSynthetic.Adapters = @() }; Expect = 'No present PCI display adapter' }
            @{ Case = 'two display adapters match'; Setup = { $global:Wf1aSynthetic.Adapters = @($global:Wf1aSynthetic.InstanceId, 'PCI\VEN_1234&DEV_9999&SUBSYS_00000000&REV_01\4&FFFF&0&0010') }; Expect = '2 present PCI display adapters' }
            @{ Case = 'the game is running'; Setup = { $global:Wf1aSynthetic.Processes += 'Overwatch' }; Expect = 'Close the game' }
            @{ Case = 'Stutter Guard is running'; Setup = { $global:Wf1aSynthetic.Processes += 'StutterGuard' }; Expect = 'StutterGuard is running' }
            @{ Case = 'the Bitsum tool is running'; Setup = { $global:Wf1aSynthetic.Processes += 'IRQControl' }; Expect = 'IRQControl is running' }
            @{ Case = 'a Stutter Guard task has an unreviewed action'; Setup = { $global:Wf1aSynthetic.Tasks += [pscustomobject]@{ TaskPath = '\Stutter Guard\'; TaskName = 'Heal'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Stutter Guard\StutterGuard.exe'; Arguments = '--agent heal' }) } }; Expect = 'task-3: an action this step has not reviewed' }
            @{ Case = 'a task elsewhere runs the Bitsum tool'; Setup = { $global:Wf1aSynthetic.Tasks += [pscustomobject]@{ TaskPath = '\'; TaskName = 'irq'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Process Lasso\IRQControl.exe'; Arguments = '' }) } }; Expect = 'not reviewed' }
            @{ Case = 'a service runs a writer'; Setup = { $global:Wf1aSynthetic.Services += [pscustomobject]@{ Name = 'x'; PathName = 'C:\x\IRQControl.exe /svc'; State = 'Running' } }; Expect = 'service-1 runs irqcontrol.exe' }
            @{ Case = 'tasks cannot be listed'; Setup = { $global:Wf1aSynthetic.TasksThrow = $true }; Expect = 'cannot be ruled out' }
            @{ Case = 'the live mask is another CPU'; Setup = { Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0, 1, 0, 0, 0, 0, 0, 0))) }; Expect = 'Found: DevicePolicy REG_DWORD 0x00000004 \(4\), AssignmentSetOverride REG_BINARY 00 01 00 00 00 00 00 00 \(CPU 8\)' }
            @{ Case = 'the live policy is absent'; Setup = { Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'DevicePolicy' -Value (New-WfAbsentValue) }; Expect = 'Found: DevicePolicy absent' }
            @{ Case = 'the live key cannot be read'; Setup = { $global:Wf1aSynthetic.Denied = @((Get-TestAffinityKey)) }; Expect = 'unknown, not absent' }
            @{ Case = 'the journal is missing'; Setup = { Remove-Item -LiteralPath (Join-Path $script:SgDir 'journal.json') }; Expect = 'journal missing' }
            @{ Case = 'the journal is unreadable'; Setup = { [System.IO.File]::WriteAllText((Join-Path $script:SgDir 'journal.json'), '{ broken') }; Expect = 'journal unreadable' }
            @{ Case = 'the AssignmentSetOverride row is missing'; Setup = { Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @((Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy')) }; Expect = 'row for AssignmentSetOverride is missing' }
            @{ Case = 'two rows record DevicePolicy'; Setup = { Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @((Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy'), (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy'), (Get-Wf1aSyntheticJournalRow -Name 'AssignmentSetOverride')) }; Expect = 'DevicePolicy is ambiguous' }
            @{ Case = 'the row is not from 12 Nov'; Setup = { Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @((Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy' -When '2026-11-14T10:00:00+01:00'), (Get-Wf1aSyntheticJournalRow -Name 'AssignmentSetOverride')) }; Expect = 'not in the 12 Nov session' }
            @{ Case = 'the session export is missing'; Setup = { Remove-Item -LiteralPath (Join-Path (Join-Path $script:SgDir 'Backups') '20261112-081948') -Recurse; Remove-Item -LiteralPath (Join-Path (Join-Path $script:SgDir 'Backups') '20261112-070000') -Recurse }; Expect = 'session export of the key was not found' }
            @{ Case = 'the session export disagrees'; Setup = { $null = Write-Wf1aSyntheticSessionReg -DataDirectory $script:SgDir -Affinity @('"DevicePolicy"=dword:00000004') }; Expect = 'Sources disagree, session 20261112-081948 export against the journal: DevicePolicy' }
            @{ Case = 'the Bitsum backup recorded a mask'; Setup = { Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008' -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](1, 0, 0, 0, 0, 0, 0, 0))) }; Expect = 'Bitsum recorded an affinity mask' }
            @{ Case = 'the Bitsum backup recorded a DevicePolicy'; Setup = { Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008\Affinity' -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]0)) }; Expect = 'Bitsum recorded a DevicePolicy' }
            @{ Case = 'the Bitsum backup key is absent'; Setup = { Remove-Wf1aSyntheticKey -SubKey 'SOFTWARE\Bitsum' }; Expect = 'InterruptAffinityBackup key is not present' }
            @{ Case = 'the Bitsum backup has two entries for the device'; Setup = { Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&99&0&0010' -Name 'KeysExisted' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]1)) }; Expect = 'holds 2 entries' }
            @{ Case = 'the live values already are the rows'; Setup = { Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'DevicePolicy' -Value (New-WfAbsentValue); Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfAbsentValue) }; Expect = 'nothing to change' }
        ) {
            & $Setup
            $r = Invoke-Test1a
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'REFUSED'
            $r.Text | Should -Match $Expect
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
            $global:Wf1aSynthetic.Exports.Count | Should -Be 0
        }

        It 'ignores a display adapter that is not on PCI' {
            $global:Wf1aSynthetic.Adapters = @('ROOT\BasicDisplay\0000', $global:Wf1aSynthetic.InstanceId)
            (Invoke-Test1a).ExitCode | Should -Be 0
        }
    }

    Describe 'Apply' {
        It 'refuses without elevation' {
            $global:Wf1aSynthetic.Elevated = $false
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'needs an elevated'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'saves the before-state, deletes both values in order and reads back PASS' {
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'APPLIED'
            $r.Text | Should -Match 'PASS DevicePolicy: absent'
            $r.Text | Should -Match 'PASS AssignmentSetOverride: absent'
            $r.Text | Should -Match 'Restart: needed'
            @($global:Wf1aSynthetic.Writes) | Should -Be @('remove:DevicePolicy', 'remove:AssignmentSetOverride')
            (Get-TestLive -Name 'DevicePolicy').Exists | Should -BeFalse
            (Get-TestLive -Name 'AssignmentSetOverride').Exists | Should -BeFalse
            (Get-TestLive -Name 'DevicePriority').Number | Should -Be 3
            $folders = @(Get-TestEvidenceFolders)
            $folders.Count | Should -Be 1
            $folders[0].Name | Should -Be '20261120T180000Z'
            $names = @(Get-ChildItem -LiteralPath $folders[0].FullName -File | ForEach-Object { $_.Name } | Sort-Object)
            $names | Should -Be @('affinity-policy.reg', 'apply-result.txt', 'before-values.csv', 'bitsum-backup.reg', 'evidence.txt', 'msi-properties.reg', 'SHA256SUMS')
            $csv = Get-Content -LiteralPath (Join-Path $folders[0].FullName 'before-values.csv')
            $csv[0] | Should -BeExactly 'role,value,exists,kind,data,target_exists,target_kind,target_data,device_sha256'
            $csv[1] | Should -Match '^change,DevicePolicy,true,DWord,4,false,,,[0-9A-F]{64}$'
            $csv[2] | Should -Match '^change,AssignmentSetOverride,true,Binary,4000000000000000,false,,,'
            $csv[3] | Should -Match '^watch,DevicePriority,true,DWord,3,,,,'
            (Get-Content -LiteralPath (Join-Path $folders[0].FullName 'evidence.txt') -Raw) | Should -Match 'journal_sha256=[0-9A-F]{64}'
            (Get-Content -LiteralPath (Join-Path $folders[0].FullName 'apply-result.txt') -Raw) | Should -Match 'readback=PASS'
            $global:Wf1aSynthetic.Exports.Count | Should -Be 3
            $r.Text | Should -Not -Match 'VEN_'
        }

        It 'refuses and changes nothing when the export of <File> fails' -ForEach @(
            @{ File = 'affinity-policy.reg'; Mode = 'fail' }
            @{ File = 'msi-properties.reg'; Mode = 'fail' }
            @{ File = 'bitsum-backup.reg'; Mode = 'fail' }
            @{ File = 'bitsum-backup.reg'; Mode = 'empty' }
        ) {
            if ($Mode -eq 'fail') { $global:Wf1aSynthetic.ExportFails = @($File) } else { $global:Wf1aSynthetic.ExportEmpty = @($File) }
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match ('reg export of ' + [regex]::Escape($File) + ' failed')
            $r.Text | Should -Match 'Nothing changed'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
            $folders = @(Get-TestEvidenceFolders)
            Test-Path -LiteralPath (Join-Path $folders[0].FullName 'SHA256SUMS') | Should -BeFalse
        }

        It 'stops on the precheck and saves nothing when the live value is unexpected' {
            Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0, 1, 0, 0, 0, 0, 0, 0)))
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'CPU 8'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
            $global:Wf1aSynthetic.Exports.Count | Should -Be 0
        }

        It 'refuses when a value changes between the save and the write' {
            $global:Wf1aSynthetic.AfterExport = { param($leaf) if ($leaf -eq 'bitsum-backup.reg') { Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'DevicePriority' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]2)) } }
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'DevicePriority changed after it was saved'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'stops on a write failure, says not to restart, and Undo restores the partial apply' {
            $global:Wf1aSynthetic.WriteFailsOn = @('AssignmentSetOverride')
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAILED: AssignmentSetOverride could not be written'
            $r.Text | Should -Match 'Written before the failure: DevicePolicy'
            $r.Text | Should -Match 'Do not restart'
            $r.Text | Should -Match '-Undo'
            (Get-TestLive -Name 'DevicePolicy').Exists | Should -BeFalse
            $global:Wf1aSynthetic.WriteFailsOn = @()
            $global:Wf1aSynthetic.Writes.Clear()
            $u = Invoke-Test1a -Verb 'Undo'
            $u.ExitCode | Should -Be 0
            $u.Text | Should -Match 'AssignmentSetOverride: already REG_BINARY'
            @($global:Wf1aSynthetic.Writes) | Should -Be @('set:DevicePolicy')
            (Get-TestLive -Name 'DevicePolicy').Number | Should -Be 4
            $u.Text | Should -Match 'UNDONE'
        }

        It 'fails when the readback does not match what was written' {
            $global:Wf1aSynthetic.WriteLies = @('AssignmentSetOverride')
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAIL AssignmentSetOverride: live REG_DWORD 0x00000063'
            $r.Text | Should -Match 'Do not restart'
            (Get-Content -LiteralPath (Join-Path (Get-TestEvidenceFolders)[0].FullName 'apply-result.txt') -Raw) | Should -Match 'readback=FAIL'
        }

        It 'writes the recorded kind and data when the rows say the values existed' {
            Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @(
                (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy' -Existed $true -ValueKind 'DWord' -Data '4'),
                (Get-Wf1aSyntheticJournalRow -Name 'AssignmentSetOverride' -Existed $true -ValueKind 'Binary' -Data '0100000000000000')
            )
            $null = Write-Wf1aSyntheticSessionReg -DataDirectory $script:SgDir -Affinity @('"DevicePolicy"=dword:00000004', '"AssignmentSetOverride"=hex:01,00,00,00,00,00,00,00')
            Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008\Affinity' -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](1, 0, 0, 0, 0, 0, 0, 0)))
            Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008\Affinity' -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]4))
            $r = Invoke-Test1a -Verb 'Apply'
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'set REG_BINARY 01 00 00 00 00 00 00 00 \(CPU 0\)'
            @($global:Wf1aSynthetic.Writes) | Should -Be @('set:DevicePolicy', 'set:AssignmentSetOverride')
            (Get-TestLive -Name 'AssignmentSetOverride').Kind | Should -Be 'Binary'
            (ConvertTo-WfHex -Bytes (Get-TestLive -Name 'AssignmentSetOverride').Bytes) | Should -BeExactly '0100000000000000'
            (Get-TestLive -Name 'DevicePolicy').Number | Should -Be 4
        }
    }

    Describe 'Undo' {
        It 'restores the saved before-state exactly, mask first' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.Writes.Clear()
            $global:Wf1aSynthetic.NowUtc = $global:Wf1aSynthetic.NowUtc.AddHours(1)
            $u = Invoke-Test1a -Verb 'Undo'
            $u.ExitCode | Should -Be 0
            @($global:Wf1aSynthetic.Writes) | Should -Be @('set:AssignmentSetOverride', 'set:DevicePolicy')
            (Get-TestLive -Name 'DevicePolicy').Number | Should -Be 4
            (ConvertTo-WfHex -Bytes (Get-TestLive -Name 'AssignmentSetOverride').Bytes) | Should -BeExactly '4000000000000000'
            (Get-TestLive -Name 'AssignmentSetOverride').Kind | Should -Be 'Binary'
            $u.Text | Should -Match 'PASS DevicePolicy: REG_DWORD 0x00000004'
            @(Get-ChildItem -LiteralPath (Get-TestEvidenceFolders)[0].FullName -Filter 'undo-result-*.txt').Count | Should -Be 1
        }

        It 'puts back the saved kind as well as the data' {
            Write-Wf1aSyntheticJournal -DataDirectory $script:SgDir -Rows @(
                (Get-Wf1aSyntheticJournalRow -Name 'DevicePolicy' -Existed $true -ValueKind 'DWord' -Data '4'),
                (Get-Wf1aSyntheticJournalRow -Name 'AssignmentSetOverride' -Existed $true -ValueKind 'Binary' -Data '0100000000000000')
            )
            $null = Write-Wf1aSyntheticSessionReg -DataDirectory $script:SgDir -Affinity @('"DevicePolicy"=dword:00000004', '"AssignmentSetOverride"=hex:01,00,00,00,00,00,00,00')
            Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008' -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](1, 0, 0, 0, 0, 0, 0, 0)))
            Set-Wf1aSyntheticValue -SubKey 'SOFTWARE\Bitsum\InterruptAffinityBackup\PCI#VEN_1234&DEV_5678&SUBSYS_9ABC1234&REV_A1#4&1a2b3c4d&0&0008' -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]4))
            # The live mask is a QWORD here, to show Undo puts back the kind too.
            Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'QWord' -Number ([uint64]0x40))
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            (Get-TestLive -Name 'AssignmentSetOverride').Kind | Should -Be 'Binary'
            $global:Wf1aSynthetic.NowUtc = $global:Wf1aSynthetic.NowUtc.AddHours(1)
            (Invoke-Test1a -Verb 'Undo').ExitCode | Should -Be 0
            (Get-TestLive -Name 'AssignmentSetOverride').Kind | Should -Be 'QWord'
            (Get-TestLive -Name 'AssignmentSetOverride').Number | Should -Be 64
            (Get-TestLive -Name 'DevicePriority').Number | Should -Be 3
        }

        It 'deletes again a value the saved before-state did not have' {
            # Apply always starts from both values present (the live check), so
            # this saved state is made by hand, with its hashes, to exercise the
            # delete branch of Undo.
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $folder = (@(Get-TestEvidenceFolders))[0].FullName
            $csvPath = Join-Path $folder 'before-values.csv'
            $lines = @(Get-Content -LiteralPath $csvPath)
            $lines[1] = $lines[1] -replace '^change,DevicePolicy,true,DWord,4,false,,,', 'change,DevicePolicy,false,,,true,DWord,4,'
            Write-Wf1aTextFile -Path $csvPath -Text (($lines -join "`r`n") + "`r`n")
            $sums = @()
            foreach ($f in (Get-Wf1aEvidenceFiles)) { $sums += ((Get-Wf1aFileSha256 -Path (Join-Path $folder $f)) + '  ' + $f) }
            Write-Wf1aTextFile -Path (Join-Path $folder 'SHA256SUMS') -Text (($sums -join "`r`n") + "`r`n")
            Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'DevicePolicy' -Value (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64]4))
            $global:Wf1aSynthetic.Writes.Clear()
            $global:Wf1aSynthetic.NowUtc = $global:Wf1aSynthetic.NowUtc.AddHours(1)
            $u = Invoke-Test1a -Verb 'Undo'
            $u.ExitCode | Should -Be 0
            @($global:Wf1aSynthetic.Writes) | Should -Be @('set:AssignmentSetOverride', 'remove:DevicePolicy')
            (Get-TestLive -Name 'DevicePolicy').Exists | Should -BeFalse
        }

        It 'refuses without a saved before-state' {
            $r = Invoke-Test1a -Verb 'Undo'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'no complete evidence folder'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses without elevation' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.Elevated = $false
            $global:Wf1aSynthetic.Writes.Clear()
            (Invoke-Test1a -Verb 'Undo').ExitCode | Should -Be 2
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a folder whose files do not match their hashes' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $csv = Join-Path (Get-TestEvidenceFolders)[0].FullName 'before-values.csv'
            [System.IO.File]::AppendAllText($csv, "change,DevicePolicy,false,,,false,,,x`r`n")
            $global:Wf1aSynthetic.Writes.Clear()
            $r = Invoke-Test1a -Verb 'Undo'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'does not match its SHA-256'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'skips a save that did not finish and refuses it by name' {
            $global:Wf1aSynthetic.ExportFails = @('bitsum-backup.reg')
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 2
            $name = (Get-TestEvidenceFolders)[0].Name
            (Invoke-Test1a -Verb 'Undo').Text | Should -Match 'no complete evidence folder'
            $r = Invoke-Test1a -Verb 'Undo' -Extra @{ EvidenceFolder = $name }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'no SHA256SUMS'
        }

        It 'refuses when a value is neither saved nor applied' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0, 1, 0, 0, 0, 0, 0, 0)))
            $global:Wf1aSynthetic.Writes.Clear()
            $r = Invoke-Test1a -Verb 'Undo'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'something else changed it'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a folder saved for another display adapter' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.Adapters = @('PCI\VEN_1234&DEV_9999&SUBSYS_00000000&REV_01\4&FFFF&0&0010')
            $r = Invoke-Test1a -Verb 'Undo'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'another display adapter'
        }

        It 'reports a write failure during Undo' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.WriteFailsOn = @('DevicePolicy')
            $r = Invoke-Test1a -Verb 'Undo'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAILED: DevicePolicy could not be written'
            $r.Text | Should -Match 'FAIL DevicePolicy'
        }
    }

    Describe 'Readback' {
        It 'passes after Apply and a restart' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.BootUtc = $global:Wf1aSynthetic.NowUtc.AddMinutes(5)
            $r = Invoke-Test1a -Verb 'Readback'
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'PASS DevicePolicy: absent'
            $r.Text | Should -Match 'Restart: done since Apply'
            $r.Text | Should -Match 'info DevicePriority'
            $r.Text | Should -Match 'READBACK PASS'
        }

        It 'says when the restart has not happened yet' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            (Invoke-Test1a -Verb 'Readback').Text | Should -Match 'Restart: NOT done since Apply'
        }

        It 'catches a value put back after the restart' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.BootUtc = $global:Wf1aSynthetic.NowUtc.AddMinutes(5)
            Set-Wf1aSyntheticValue -SubKey (Get-TestAffinityKey) -Name 'AssignmentSetOverride' -Value (New-WfRegValueModel -Exists $true -Kind 'Binary' -Bytes ([byte[]](0x40, 0, 0, 0, 0, 0, 0, 0)))
            $r = Invoke-Test1a -Verb 'Readback'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAIL AssignmentSetOverride: live REG_BINARY 40 00 00 00 00 00 00 00 \(CPU 6\), expected absent'
            $r.Text | Should -Match 'do not re-apply in a loop'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 2
        }

        It 'says when Undo ran after Apply' {
            (Invoke-Test1a -Verb 'Apply').ExitCode | Should -Be 0
            $global:Wf1aSynthetic.NowUtc = $global:Wf1aSynthetic.NowUtc.AddHours(1)
            (Invoke-Test1a -Verb 'Undo').ExitCode | Should -Be 0
            $r = Invoke-Test1a -Verb 'Readback'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'Undo ran after Apply \(evidence folder 20261120T180000Z\)'
        }

        It 'names a mechanism found next to a FAIL' {
            $global:Wf1aSynthetic.Processes += 'IRQControl'
            $r = Invoke-Test1a -Verb 'Readback'
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'warning: IRQControl is running'
        }

        It 'cannot tell without usable journal rows' {
            Remove-Item -LiteralPath (Join-Path $script:SgDir 'journal.json')
            $r = Invoke-Test1a -Verb 'Readback'
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'CANNOT READ BACK'
        }
    }

    Describe 'entry script' {
        It 'refuses two verbs' {
            $r = Invoke-Test1a -Verb @('Apply', 'Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'name one verb'
            $global:Wf1aSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses -EvidenceFolder without -Undo' {
            $r = Invoke-Test1a -Extra @{ EvidenceFolder = '20261120T180000Z' }
            $r.ExitCode | Should -Be 2
        }

        It 'masks the instance path and the profile folder in any line' {
            $line = Protect-Wf1aText -Text 'a PCI\VEN_1234&DEV_5678&SUBSYS_1\4&2 b C:\Users\someone\x' -Secrets @()
            $line | Should -BeExactly 'a display-adapter-1 b <profile>\x'
            Protect-Wf1aText -Text 'k=pci\ven_1234&dev_5678\abc' -Secrets @('PCI\VEN_1234&DEV_5678\ABC') | Should -BeExactly 'k=display-adapter-1'
        }
    }
}
