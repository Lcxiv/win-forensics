# Pester 5 tests for network-tuning.ps1, run off Windows against
# SyntheticNetworkTuning.ps1. They prove the portable logic (adapter
# selection, per setting preconditions, -Only, the saved before-state, the
# precheck, the write, undo and readback, every failure path) and nothing
# about Windows itself; what only the PC can show is listed in
# changes/windows/README.md.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:ChangeRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:ChangeRoot '_network-tuning-lib.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticNetworkTuning.ps1')

    function Invoke-TestNt {
        # Runs the real entry script in this process against the synthetic
        # machine and returns its exit code and output lines.
        param([string[]]$Verb = @(), [hashtable]$Extra = @{})
        $global:WfNtSynthetic.Out.Clear()
        $all = @{ EvidenceRoot = $script:EvidenceRoot }
        foreach ($v in $Verb) { $all[$v] = $true }
        foreach ($k in $Extra.Keys) { $all[$k] = $Extra[$k] }
        & (Join-Path $script:ChangeRoot 'network-tuning.ps1') @all
        $code = $LASTEXITCODE
        return [pscustomobject]@{ ExitCode = $code; Lines = @($global:WfNtSynthetic.Out.ToArray()); Text = ($global:WfNtSynthetic.Out.ToArray() -join "`n") }
    }

    function Get-TestEvidenceFolders {
        if (-not (Test-Path -LiteralPath $script:EvidenceRoot)) { return @() }
        return @(Get-ChildItem -LiteralPath $script:EvidenceRoot -Directory)
    }

    function New-TestPlantedFolder {
        # An evidence folder written by something other than Apply, with a
        # matching SHA256SUMS. Each row is 'setting|keyword|display|before|proposed'
        # or, with a sixth field, that driver file.
        param([string]$Stamp, [string[]]$Rows)
        $folder = Join-Path $script:EvidenceRoot $Stamp
        $null = New-Item -ItemType Directory -Path $folder -Force
        $device = Get-WfNtTextSha256 -Text $global:WfNtSynthetic.Adapters[0].PnPDeviceID
        $lines = @(((Get-WfNtCsvColumns) | ForEach-Object { '"' + $_ + '"' }) -join ',')
        foreach ($r in $Rows) {
            $f = $r.Split('|')
            $driver = 'rt25cx21x64.sys'
            if ($f.Count -gt 5) { $driver = $f[5] }
            $lines += ((@($f[0], $f[1], $f[2], $f[3], '', $f[4], 'change', '', $device, $driver, '1') | ForEach-Object { '"' + $_ + '"' }) -join ',')
        }
        Write-WfNtTextFile -Path (Join-Path $folder 'before-values.csv') -Text (($lines -join "`r`n") + "`r`n")
        Write-WfNtTextFile -Path (Join-Path $folder 'adapter-driver-key.reg') -Text "Windows Registry Editor Version 5.00`r`n"
        $sums = @((Get-WfNtEvidenceFiles) | ForEach-Object { (Get-WfNtFileSha256 -Path (Join-Path $folder $_)) + '  ' + $_ })
        Write-WfNtTextFile -Path (Join-Path $folder 'SHA256SUMS') -Text (($sums -join "`r`n") + "`r`n")
    }

    function Assert-TestPrivate {
        # Nothing that identifies the adapter or the network leaves.
        param([string]$Text)
        $Text | Should -Not -Match 'Ethernet 2'
        $Text | Should -Not -Match 'VEN_10EC'
        $Text | Should -Not -Match '020000000001'
        $Text | Should -Not -Match 'ABCDEF0'
        $Text | Should -Not -Match '4d36e972'
    }
}

Describe 'network-tuning' {
    BeforeEach {
        New-WfNtSyntheticMachine
        $script:EvidenceRoot = Join-Path $TestDrive ('evidence-' + [guid]::NewGuid().ToString('N'))
    }

    Describe 'the settings table' {
        It 'holds the include verdicts as the default set, each with a keyword, a value, a reason and a Learn source' {
            $s = @(Get-WfNtSettings | Where-Object { $_.Default })
            @($s | ForEach-Object { $_.Name }) | Should -Be @('idle-restriction')
            foreach ($x in $s) {
                $x.Verdict | Should -Be 'include'
                $x.Keyword | Should -Match '^\*?[A-Za-z]+$'
                $x.Proposed | Should -Match '^[0-9]+$'
                $x.Reason | Should -Not -BeNullOrEmpty
                $x.Source | Should -Match '^https://learn\.microsoft\.com/'
            }
        }

        It 'holds the measure first entries as opt in, each proposing the driver''s off value read live' {
            $s = @(Get-WfNtSettings | Where-Object { -not $_.Default })
            @($s | ForEach-Object { $_.Name }) | Should -Be @('green-ethernet', 'power-saving-mode', 'gigabit-lite', 'ltr-obff', 'flow-control')
            foreach ($x in $s) {
                $x.Verdict | Should -Be 'measure-first'
                $x.Proposed | Should -BeNullOrEmpty
                $x.OffDisplay | Should -Be 'Disabled'
                ($x.Keyword -or $x.Display) | Should -BeTrue
                $x.Reason | Should -Not -BeNullOrEmpty
                $x.Source | Should -Match 'network-tuning-research\.md'
            }
        }
    }

    Describe 'Plan' {
        It 'prints the live and proposed value, the reason, the restart and every precondition, and changes nothing' {
            $r = Invoke-TestNt
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Setting idle-restriction \(\*IdleRestriction\)'
            $r.Text | Should -Match 'verdict:  include \(cited case'
            $r.Text | Should -Match 'Opt in experiments, measure first, no cited latency case \(not selected; name one alone with -Only\): green-ethernet, power-saving-mode, gigabit-lite, ltr-obff, flow-control'
            $r.Text | Should -Not -Match 'Setting green-ethernet'
            $r.Text | Should -Match 'live:     0 \(No Restriction\)'
            $r.Text | Should -Match 'proposed: 1 \(Only idle when user not present\)'
            $r.Text | Should -Match 'why:      stops the adapter powering down'
            $r.Text | Should -Match 'restart:  adapter restart or PC restart'
            $r.Text | Should -Match '\[ok    \] valid: valid values 0, 1 include the current and the proposed value'
            $r.Text | Should -Match 'would change 0 to 1'
            $r.Text | Should -Match 'passes -NoRestart'
            $r.Text | Should -Match 'cannot tell which one made a difference'
            $r.Text | Should -Match 'RESULT: READY'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            $global:WfNtSynthetic.Exports.Count | Should -Be 0
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'reports the other displayed properties read only, and never an address' {
            $r = Invoke-TestNt
            $r.Text | Should -Match 'Green Ethernet = Enabled \(InventedGreenKeyword 1\)'
            $r.Text | Should -Match 'Flow Control = Rx & Tx Enabled \(\*FlowControl 3\)'
            $r.Text | Should -Match 'Allow the computer to turn off this device = Enabled'
            $r.Text | Should -Not -Match 'Network Address'
            $r.Text | Should -Not -Match 'InventedHiddenKeyword'
            Assert-TestPrivate -Text $r.Text
        }

        It 'runs unelevated' {
            $global:WfNtSynthetic.Elevated = $false
            $r = Invoke-TestNt
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'not elevated'
        }

        It 'reports nothing to do when the value is already proposed' {
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1'
            $r = Invoke-TestNt
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'already at the proposed value'
            $r.Text | Should -Match 'RESULT: NOTHING TO DO'
        }

        It 'refuses <Case>' -ForEach @(
            @{ Case = 'with no wired adapter Up'; Setup = { $global:WfNtSynthetic.Adapters[0].Up = $false }; Expect = 'no physical Ethernet adapter is Up' }
            @{ Case = 'with two wired adapters Up'; Setup = { $global:WfNtSynthetic.Adapters += [pscustomobject]@{ Name = 'Ethernet 3'; InterfaceDescription = 'Realtek Gaming 2.5GbE Family Controller #2'; DriverFileName = 'rt25cx21x64.sys'; DriverVersion = '1'; PnPDeviceID = 'PCI\VEN_10EC&DEV_8125&SUBSYS_00001234&REV_05\4&FFFFFF0&0&00E8'; Medium = [uint32]14; Physical = $true; Up = $true; LinkSpeed = '1 Gbps' } }; Expect = '2 physical Ethernet adapters are Up' }
            @{ Case = 'for an adapter that is not Realtek'; Setup = { $global:WfNtSynthetic.Adapters[0].InterfaceDescription = 'Invented Other Controller' }; Expect = 'not the Realtek adapter' }
            @{ Case = 'for the Realtek adapter on another driver'; Setup = { $global:WfNtSynthetic.Adapters[0].DriverFileName = 'rt640x64.sys' }; Expect = 'targets rt25cx21x64 only' }
            @{ Case = 'for a name with a wildcard'; Setup = { $global:WfNtSynthetic.Properties['Ether*'] = $global:WfNtSynthetic.Properties['Ethernet 2']; $global:WfNtSynthetic.Adapters[0].Name = 'Ether*' }; Expect = 'wildcard' }
            @{ Case = 'when the keyword is not exposed'; Setup = { $p = Get-WfNtSyntheticProperty -Keyword '*IdleRestriction'; $p.RegistryKeyword = '*Other' }; Expect = 'does not expose \*IdleRestriction' }
            @{ Case = 'when the keyword is hidden'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').DisplayName = '' }; Expect = 'hidden property' }
            @{ Case = 'for a value type other than REG_SZ'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').RegistryDataType = 4 }; Expect = 'registry type is 4' }
            @{ Case = 'for two current values'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').RegistryValue = @('0', '1') }; Expect = 'not one decimal number \(2 entries\)' }
            @{ Case = 'for a value that is not a number'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').RegistryValue = @('abc') }; Expect = 'not one decimal number' }
            @{ Case = 'when the current value is not valid'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').RegistryValue = @('5') }; Expect = 'current value 5 is not among' }
            @{ Case = 'when the proposed value is not valid'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').ValidRegistryValues = @('0', '2') }; Expect = 'proposed value 1 is not among' }
            @{ Case = 'when the driver lists no valid values'; Setup = { (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').ValidRegistryValues = @() }; Expect = 'lists no valid values' }
            @{ Case = 'when the driver key cannot be named'; Setup = { $global:WfNtSynthetic.DriverKeys[$global:WfNtSynthetic.Adapters[0].PnPDeviceID] = 'SOMETHING\ELSE' }; Expect = 'driver key could not be named' }
            @{ Case = 'while the game runs'; Setup = { $global:WfNtSynthetic.Processes += 'Overwatch' }; Expect = 'close Overwatch first' }
        ) {
            & $Setup
            $r = Invoke-TestNt
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match $Expect
            $r.Text | Should -Match 'RESULT: REFUSED'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            Assert-TestPrivate -Text $r.Text
        }

        It 'stops when the properties cannot be read' {
            $global:WfNtSynthetic.ReadThrows = $true
            $r = Invoke-TestNt
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'STOPPED: an unexpected error \(UnauthorizedAccessException\)'
        }
    }

    Describe 'verbs and -Only' {
        It 'refuses two verbs' {
            $r = Invoke-TestNt -Verb @('Apply', 'Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'name one verb, not Apply and Undo'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses -EvidenceFolder without -Undo' {
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ EvidenceFolder = '20261120T180000Z' }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'goes with -Undo only'
        }

        It 'refuses -Only with -Undo' {
            $r = Invoke-TestNt -Verb @('Undo') -Extra @{ Only = @('idle-restriction') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'name the run with -EvidenceFolder'
        }

        It 'refuses an unknown -Only name and lists the known ones' {
            $r = Invoke-TestNt -Extra @{ Only = @('idle-restriction,no-such-setting') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'does not have: no-such-setting\. Known: idle-restriction, green-ethernet, power-saving-mode, gigabit-lite, ltr-obff, flow-control'
        }

        It 'accepts -Only as one comma separated string' {
            $r = Invoke-TestNt -Extra @{ Only = @(' idle-restriction ,') }
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Setting idle-restriction'
        }
    }

    Describe 'Apply' {
        It 'refuses without elevation and changes nothing' {
            $global:WfNtSynthetic.Elevated = $false
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'Apply needs an elevated'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'saves, writes once, reads back PASS and names the restart' {
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|*IdleRestriction=1')
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '1'
            $r.Text | Should -Match 'Saved the before-state: evidence folder 20261120T180000Z'
            $r.Text | Should -Match 'PASS idle-restriction \(\*IdleRestriction\): 1'
            $r.Text | Should -Match 'Apply done'
            $r.Text | Should -Match 'Disable device, then Enable device'
            Assert-TestPrivate -Text $r.Text
            $folder = @(Get-TestEvidenceFolders)
            $folder.Count | Should -Be 1
            $names = @(Get-ChildItem -LiteralPath $folder[0].FullName | ForEach-Object { $_.Name } | Sort-Object)
            $names | Should -Be @('adapter-driver-key.reg', 'before-values.csv', 'SHA256SUMS')
            @($global:WfNtSynthetic.Exports) | Should -Be @('HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001')
            $csv = [System.IO.File]::ReadAllText((Join-Path $folder[0].FullName 'before-values.csv'))
            $csv | Should -Match '"idle-restriction","\*IdleRestriction","idle power down restriction","0","No Restriction","1","change","0;1","[0-9A-F]{64}","rt25cx21x64.sys","1125.31.50.603"'
            Assert-TestPrivate -Text $csv
            (Test-WfNtEvidenceFolder -Folder $folder[0].FullName).Ok | Should -BeTrue
        }

        It 'refuses when every setting is already at its proposed value' {
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1'
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'Nothing to change'
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'refuses on a failed precondition before saving anything' {
            $global:WfNtSynthetic.Processes += 'Battle.net'
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'a precondition failed'
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'refuses when the export fails, without writing or a SHA256SUMS' {
            $global:WfNtSynthetic.ExportFails = $true
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'reg export of the adapter''s driver key failed \(exit 1\)\. Nothing changed'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            $folder = @(Get-TestEvidenceFolders)
            Test-Path -LiteralPath (Join-Path $folder[0].FullName 'SHA256SUMS') | Should -BeFalse
        }

        It 'refuses when the export is empty' {
            $global:WfNtSynthetic.ExportEmpty = $true
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'export of the adapter''s driver key failed'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses when the value moves between the save and the write' {
            $global:WfNtSynthetic.AfterExport = { Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1' }
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'a value changed after it was saved \(idle-restriction is now 1, saved 0\)'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'reports a failed write, reads back FAIL and points to Undo' {
            $global:WfNtSynthetic.WriteFailsOn = @('*IdleRestriction')
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'WRITE FAILED for idle-restriction \(IOException\)'
            $r.Text | Should -Match 'FAIL idle-restriction \(\*IdleRestriction\): live 0, expected 1'
            $r.Text | Should -Match 'run -Undo -EvidenceFolder 20261120T180000Z'
        }

        It 'reports a readback mismatch' {
            $global:WfNtSynthetic.WriteLies = @('*IdleRestriction')
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAIL idle-restriction \(\*IdleRestriction\): live 7, expected 1'
        }

        It 'refuses when an evidence folder for this second already exists' {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:EvidenceRoot '20261120T180000Z') -Force
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'already exists'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }
    }

    Describe 'Undo' {
        It 'restores the saved value and reads back PASS' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|*IdleRestriction=0')
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '0'
            $r.Text | Should -Match 'Undo from evidence folder 20261120T180000Z'
            $r.Text | Should -Match 'PASS idle-restriction \(\*IdleRestriction\): 0'
            $r.Text | Should -Match 'Undo done'
            Assert-TestPrivate -Text $r.Text
        }

        It 'writes nothing when the value is already back' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '0'
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 0
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            $r.Text | Should -Match 'already at the saved value 0'
        }

        It 'refuses without elevation' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.Elevated = $false
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses while the game runs' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.Processes += 'Overwatch'
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'close Overwatch first'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses without an evidence folder' {
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'no complete evidence folder'
        }

        It 'skips an incomplete save and refuses one named explicitly' {
            $global:WfNtSynthetic.ExportFails = $true
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 2
            $r = Invoke-TestNt -Verb @('Undo')
            $r.Text | Should -Match 'no complete evidence folder'
            $r = Invoke-TestNt -Verb @('Undo') -Extra @{ EvidenceFolder = '20261120T180000Z' }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'no SHA256SUMS'
        }

        It 'refuses a before-state that no longer matches its SHA-256' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $csv = Join-Path (@(Get-TestEvidenceFolders)[0].FullName) 'before-values.csv'
            [System.IO.File]::WriteAllText($csv, ([System.IO.File]::ReadAllText($csv) -replace '"0","No Restriction"', '"1","No Restriction"'))
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'before-values.csv does not match its SHA-256'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a value something else changed' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            (Get-WfNtSyntheticProperty -Keyword '*IdleRestriction').ValidRegistryValues = @('0', '1', '2')
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '2'
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'idle-restriction is 2, neither the saved 0 nor the applied 1'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a save made for another adapter' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $old = $global:WfNtSynthetic.Adapters[0].PnPDeviceID
            $new = 'PCI\VEN_10EC&DEV_8125&SUBSYS_00001234&REV_05\4&9999999&0&00E4'
            $global:WfNtSynthetic.Adapters[0].PnPDeviceID = $new
            $global:WfNtSynthetic.DriverKeys[$new] = $global:WfNtSynthetic.DriverKeys[$old]
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'saved for a different adapter'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'reports a failed undo write' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.WriteFailsOn = @('*IdleRestriction')
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'WRITE FAILED for idle-restriction'
            $r.Text | Should -Match 'FAIL idle-restriction \(\*IdleRestriction\): live 1, expected 0'
        }

        It 'undoes a well formed folder that Apply did not write, so the refusals below come from the row checks' {
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1'
            New-TestPlantedFolder -Stamp '20261121T000000Z' -Rows @('idle-restriction|*IdleRestriction|idle power down restriction|0|1')
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|*IdleRestriction=0')
        }

        It 'refuses a planted folder whose row <Case>' -ForEach @(
            @{ Case = 'names a keyword that is not its setting''s own'; Rows = @('idle-restriction|*FlowControl|Flow Control|0|3') }
            @{ Case = 'names its setting''s keyword in another case'; Rows = @('idle-restriction|*idlerestriction|idle power down restriction|1|0') }
            @{ Case = 'gives a display matched setting a keyword that is not a plain name'; Rows = @('green-ethernet|Invented Green;x|Green Ethernet|0|1') }
            @{ Case = 'gives a display matched setting another display name'; Rows = @('green-ethernet|*FlowControl|Flow Control|0|3') }
            @{ Case = 'repeats a setting'; Rows = @('idle-restriction|*IdleRestriction|idle power down restriction|0|1', 'idle-restriction|*IdleRestriction|idle power down restriction|0|1') }
            @{ Case = 'names another driver file'; Rows = @('idle-restriction|*IdleRestriction|idle power down restriction|0|1|rt640x64.sys') }
        ) {
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1'
            New-TestPlantedFolder -Stamp '20261121T000000Z' -Rows $Rows
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'before-values.csv is malformed'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a planted display matched row whose live keyword shows another name' {
            New-TestPlantedFolder -Stamp '20261121T000000Z' -Rows @('green-ethernet|*FlowControl|Green Ethernet|0|3')
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'does not fit this adapter''s settings \(green-ethernet: \*FlowControl is not shown as "Green Ethernet"\)'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            Get-WfNtSyntheticLive -Keyword '*FlowControl' | Should -Be '3'
        }

        It 'refuses a planted row whose keyword the adapter does not show once' {
            New-TestPlantedFolder -Stamp '20261121T000000Z' -Rows @('green-ethernet|InventedMissingKeyword|Green Ethernet|0|1')
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'does not expose InventedMissingKeyword exactly once'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses a planted row whose saved value is not among the live valid values' {
            Set-WfNtSyntheticLive -Keyword '*IdleRestriction' -Value '1'
            New-TestPlantedFolder -Stamp '20261121T000000Z' -Rows @('idle-restriction|*IdleRestriction|idle power down restriction|5|1')
            $r = Invoke-TestNt -Verb @('Undo')
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'idle-restriction: the saved 5 or the applied 1 is not among the driver''s valid values \(0, 1\)'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '1'
        }

        It 'uses the named evidence folder' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $r = Invoke-TestNt -Verb @('Undo') -Extra @{ EvidenceFolder = '20261120T180000Z' }
            $r.ExitCode | Should -Be 0
            $r = Invoke-TestNt -Verb @('Undo') -Extra @{ EvidenceFolder = '..\elsewhere' }
            $r.ExitCode | Should -Be 2
        }
    }

    Describe 'Readback' {
        It 'passes after Apply and notes the missing restart' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Readback')
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Compared with evidence folder 20261120T180000Z'
            $r.Text | Should -Match 'PASS idle-restriction'
            $r.Text | Should -Match 'has not restarted since Apply'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'drops the restart note after a later boot' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.BootUtc = [datetime]::new(2026, 11, 20, 19, 0, 0, [System.DateTimeKind]::Utc)
            $r = Invoke-TestNt -Verb @('Readback')
            $r.Text | Should -Not -Match 'has not restarted'
        }

        It 'fails before any Apply, against the proposed values' {
            $r = Invoke-TestNt -Verb @('Readback')
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'No usable evidence folder'
            $r.Text | Should -Match 'FAIL idle-restriction \(\*IdleRestriction\): live 0, expected 1'
        }

        It 'refuses without the adapter' {
            $global:WfNtSynthetic.Adapters[0].Up = $false
            $r = Invoke-TestNt -Verb @('Readback')
            $r.ExitCode | Should -Be 2
        }
    }

    Describe 'several settings (an invented second setting)' {
        BeforeEach {
            # The real default set has one setting; this invented second one proves
            # -Only, the write order and undo after a partial apply.
            function Get-WfNtSettings {
                return @(
                    [pscustomobject]@{ Name = 'idle-restriction'; Keyword = '*IdleRestriction'; Display = ''; Proposed = '1'; OffDisplay = ''; Default = $true; Verdict = 'include'; Reason = 'test'; Restart = 'adapter'; Source = 'https://learn.microsoft.com/x' },
                    [pscustomobject]@{ Name = 'flow-control'; Keyword = '*FlowControl'; Display = ''; Proposed = '0'; OffDisplay = ''; Default = $true; Verdict = 'include'; Reason = 'test'; Restart = 'adapter'; Source = 'https://learn.microsoft.com/y' }
                )
            }
        }

        It 'applies only the setting named with -Only' {
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('flow-control') }
            $r.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|*FlowControl=0')
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '0'
            $csv = [System.IO.File]::ReadAllText((Join-Path (@(Get-TestEvidenceFolders)[0].FullName) 'before-values.csv'))
            $csv | Should -Not -Match 'idle-restriction'
        }

        It 'stops at the first failed write and Undo puts back only what was written' {
            $global:WfNtSynthetic.WriteFailsOn = @('*FlowControl')
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 1
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '1'
            Get-WfNtSyntheticLive -Keyword '*FlowControl' | Should -Be '3'
            $r.Text | Should -Match 'PASS idle-restriction'
            $r.Text | Should -Match 'FAIL flow-control \(\*FlowControl\): live 3, expected 0'
            $global:WfNtSynthetic.WriteFailsOn = @()
            $global:WfNtSynthetic.Writes.Clear()
            $u = Invoke-TestNt -Verb @('Undo')
            $u.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|*IdleRestriction=0')
            $u.Text | Should -Match 'flow-control: already at the saved value 3'
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '0'
        }

        It 'refuses the whole run when one selected setting fails its precondition' {
            (Get-WfNtSyntheticProperty -Keyword '*FlowControl').ValidRegistryValues = @('3')
            $r = Invoke-TestNt -Verb @('Apply')
            $r.ExitCode | Should -Be 2
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('idle-restriction') }
            $r.ExitCode | Should -Be 0
        }
    }

    Describe 'opt in measure first experiments' {
        It 'plans one named alone, labelled measure first, proposing the driver''s off value' {
            $r = Invoke-TestNt -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Setting green-ethernet \(InventedGreenKeyword\)'
            $r.Text | Should -Match 'verdict:  measure first, no cited latency case'
            $r.Text | Should -Match 'live:     1 \(Enabled\)'
            $r.Text | Should -Match 'proposed: 0 \(Disabled\)'
            $r.Text | Should -Match '\[ok    \] off-value: the driver''s own off value is 0 \(Disabled\)'
            $r.Text | Should -Match 'would change 1 to 0'
            $r.Text | Should -Not -Match 'Setting idle-restriction'
            $r.Text | Should -Not -Match 'Green Ethernet = '
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'applies, reads back, undoes and reads back <Name> with the live keyword' -ForEach @(
            @{ Name = 'green-ethernet'; Keyword = 'InventedGreenKeyword'; Before = '1'; Off = '0' }
            @{ Name = 'power-saving-mode'; Keyword = 'InventedPowerSavingKeyword'; Before = '1'; Off = '0' }
            @{ Name = 'gigabit-lite'; Keyword = 'InventedGigaLiteKeyword'; Before = '1'; Off = '0' }
            @{ Name = 'flow-control'; Keyword = '*FlowControl'; Before = '3'; Off = '0' }
        ) {
            $a = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @($Name) }
            $a.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @(('Ethernet 2|' + $Keyword + '=' + $Off))
            Get-WfNtSyntheticLive -Keyword '*IdleRestriction' | Should -Be '0'
            $csv = [System.IO.File]::ReadAllText((Join-Path (@(Get-TestEvidenceFolders)[0].FullName) 'before-values.csv'))
            $csv | Should -Match ('"' + $Name + '","' + [regex]::Escape($Keyword) + '",')
            $csv | Should -Not -Match 'idle-restriction'
            $b = Invoke-TestNt -Verb @('Readback')
            $b.ExitCode | Should -Be 0
            $b.Text | Should -Match ('PASS ' + $Name)
            $global:WfNtSynthetic.Writes.Clear()
            $u = Invoke-TestNt -Verb @('Undo')
            $u.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @(('Ethernet 2|' + $Keyword + '=' + $Before))
            Get-WfNtSyntheticLive -Keyword $Keyword | Should -Be $Before
            Assert-TestPrivate -Text ($a.Text + $b.Text + $u.Text)
        }

        It 'refuses ltr-obff while the driver hides it, so no off value can be read' {
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('ltr-obff') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'hidden property, so the driver lists no valid values for it and no off value can be read'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
            Test-Path -LiteralPath $script:EvidenceRoot | Should -BeFalse
        }

        It 'refuses when the driver shows no value as Disabled' {
            (Get-WfNtSyntheticProperty -Keyword 'InventedGreenKeyword').ValidDisplayValues = @('Off', 'On')
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'shows 0 valid values as "Disabled", not exactly one, so its off value cannot be read'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'refuses when two values are shown as Disabled' {
            $p = Get-WfNtSyntheticProperty -Keyword '*FlowControl'
            $p.ValidRegistryValues = @('0', '1', '3')
            $p.ValidDisplayValues = @('Disabled', 'Disabled', 'Rx & Tx Enabled')
            $r = Invoke-TestNt -Extra @{ Only = @('flow-control') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'shows 2 valid values as "Disabled"'
        }

        It 'refuses when the display name matches twice' {
            (Get-WfNtSyntheticProperty -Keyword 'InventedPowerSavingKeyword').DisplayName = 'Green Ethernet'
            $r = Invoke-TestNt -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'exposes the property shown as "Green Ethernet" 2 times'
        }

        It 'refuses when the driver does not show the property' {
            (Get-WfNtSyntheticProperty -Keyword 'InventedGigaLiteKeyword').DisplayName = 'Something Else'
            $r = Invoke-TestNt -Extra @{ Only = @('gigabit-lite') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'does not expose the property shown as "Gigabit Lite"'
        }

        It 'reports nothing to do when it is already off' {
            Set-WfNtSyntheticLive -Keyword 'InventedGreenKeyword' -Value '0'
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'Nothing to change'
        }

        It 'refuses <Case>' -ForEach @(
            @{ Case = 'two experiments in one run'; Only = @('green-ethernet,flow-control') }
            @{ Case = 'an experiment together with the default setting'; Only = @('idle-restriction', 'gigabit-lite') }
        ) {
            $r = Invoke-TestNt -Verb @('Apply') -Extra @{ Only = $Only }
            $r.ExitCode | Should -Be 2
            $r.Text | Should -Match 'a measure first setting runs alone, one experiment at a time'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'reads back an experiment against the live off value when nothing was applied' {
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAIL green-ethernet \(InventedGreenKeyword\): live 1, expected 0'
        }

        It 'reads back FAIL when the proposed value cannot be told' {
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('ltr-obff') }
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'FAIL ltr-obff: the proposed value cannot be told \(it is a hidden property'
        }

        It 'reads back each setting named with -Only from the newest folder that holds it' {
            (Invoke-TestNt -Verb @('Apply')).ExitCode | Should -Be 0
            $global:WfNtSynthetic.NowUtc = $global:WfNtSynthetic.NowUtc.AddDays(1)
            (Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('green-ethernet') }).ExitCode | Should -Be 0
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('idle-restriction') }
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'Compared idle-restriction with evidence folder 20261120T180000Z'
            $r.Text | Should -Match 'PASS idle-restriction \(\*IdleRestriction\): 1'
            $r.Text | Should -Match 'has not restarted since Apply \(evidence folder 20261120T180000Z\)'
            $r.Text | Should -Not -Match 'green-ethernet'
            $r.Text | Should -Not -Match '20261121T180000Z'
            (Invoke-TestNt -Verb @('Undo')).ExitCode | Should -Be 0
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('idle-restriction') }
            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'PASS idle-restriction'
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('green-ethernet') }
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'Compared green-ethernet with evidence folder 20261121T180000Z'
            $r.Text | Should -Match 'FAIL green-ethernet \(InventedGreenKeyword\): live 1, expected 0'
            $global:WfNtSynthetic.Writes.Clear()
            $r = Invoke-TestNt -Verb @('Readback') -Extra @{ Only = @('flow-control') }
            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'No usable evidence folder holds flow-control; compared with the proposed values'
            $r.Text | Should -Match 'FAIL flow-control \(\*FlowControl\): live 3, expected 0'
            $global:WfNtSynthetic.Writes.Count | Should -Be 0
        }

        It 'undoes an earlier experiment kept in place, by its folder' {
            (Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('green-ethernet') }).ExitCode | Should -Be 0
            $first = @(Get-TestEvidenceFolders)[0].Name
            $global:WfNtSynthetic.NowUtc = $global:WfNtSynthetic.NowUtc.AddDays(3)
            (Invoke-TestNt -Verb @('Apply') -Extra @{ Only = @('flow-control') }).ExitCode | Should -Be 0
            $global:WfNtSynthetic.Writes.Clear()
            $u = Invoke-TestNt -Verb @('Undo') -Extra @{ EvidenceFolder = $first }
            $u.ExitCode | Should -Be 0
            @($global:WfNtSynthetic.Writes) | Should -Be @('Ethernet 2|InventedGreenKeyword=1')
            Get-WfNtSyntheticLive -Keyword '*FlowControl' | Should -Be '0'
        }
    }

    Describe 'output protection' {
        It 'masks names, device paths, addresses and profile folders' {
            $t = Protect-WfNtText -Text 'Ethernet 2 at PCI\VEN_10EC&DEV_8125&X\Y mac 02-00-00-00-00-01 or 020000000001 ip 192.168.0.1 C:\Users\someone\x {12345678-1234-1234-1234-123456789ABC}' -Secrets @('Ethernet 2')
            $t | Should -BeExactly 'ethernet-1 at ethernet-1 mac <address> or <address> ip <address> <profile>\x {<guid>}'
        }

        It 'keeps driver versions and plain numbers' {
            Protect-WfNtText -Text 'driver 1125.31.50.603 value 1024' | Should -BeExactly 'driver 1125.31.50.603 value 1024'
        }
    }
}
