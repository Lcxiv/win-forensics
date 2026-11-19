# Pester 5 tests for the shared live session path (Invoke-WfLiveSession), the
# portable JSON reader, and the local scenario runner (_run-scenario.ps1 with
# _scenarios.ps1), run off Windows against the synthetic backend. Each runner
# test starts the real collector scripts as synthetic children, in process.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:CollectorRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:CollectorRoot '_common.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticBackend.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticScenarios.ps1')
    . (Join-Path $script:CollectorRoot '_scenarios.ps1')

    function Invoke-TestRun {
        # Runs the scenario runner in this process and returns what a caller sees.
        param([string]$OutputDirectory, [hashtable]$Arguments = @{})
        $global:WfSynthetic.Stdout.Clear()
        $global:WfSynthetic.Stderr.Clear()
        $all = @{ OutputDirectory = $OutputDirectory; PresentMonPath = (Get-WfSyntheticPresentMonPath); XperfPath = 'C:\Tools\WindowsPerformanceToolkit\xperf.exe' }
        foreach ($key in $Arguments.Keys) { $all[$key] = $Arguments[$key] }
        $null = & (Join-Path $script:CollectorRoot '_run-scenario.ps1') @all
        $exit = $LASTEXITCODE
        $manifestPath = Join-Path $OutputDirectory 'manifest.json'
        $manifest = $null
        if (Test-Path -LiteralPath $manifestPath) { $manifest = Read-WfJsonFile -Path $manifestPath }
        return [pscustomobject]@{
            ExitCode = $exit
            Stdout   = @($global:WfSynthetic.Stdout.ToArray())
            Stderr   = @($global:WfSynthetic.Stderr.ToArray())
            Manifest = $manifest
            Children = @($global:WfSynthetic.ChildRuns | ForEach-Object { $_['Name'] })
        }
    }

    function Get-TestEntry {
        param($Manifest, [string]$Id)
        return @($Manifest['collectors'] | Where-Object { $_['id'] -eq $Id })[0]
    }

    function Get-TestStep {
        param($Manifest, [string]$Step)
        return @($Manifest['run']['steps'] | Where-Object { $_['step'] -eq $Step })[0]
    }

    function Get-TestCheck {
        param($Manifest, [string]$Name)
        return @($Manifest['preflight']['checks'] | Where-Object { $_['name'] -eq $Name })[0]
    }
}

Describe 'the shared live session path' {
    BeforeEach {
        Reset-WfSynthetic
        $script:calls = New-Object 'System.Collections.Generic.List[string]'
        $script:hooks = @{
            Start   = { param($S) $S.Calls.Add('start'); return @{ Ok = $S.StartOk; MayRemain = $true } }
            Stop    = { param($S) $S.Calls.Add('stop'); return $S.StopOk }
            Confirm = { param($S, $Moment) $S.Calls.Add('confirm:' + $Moment); $read = $S.Reads[0]; if ($S.Reads.Count -gt 1) { $S.Reads.RemoveAt(0) }; if ($read -eq 'throw') { throw 'status could not run' }; return $read }
            Cancel  = { param($S, $Read) $S.Calls.Add('cancel:' + $Read); return $true }
        }
        $script:state = @{ Calls = $script:calls; StartOk = $true; StopOk = $true; Reads = (New-Object 'System.Collections.Generic.List[string]') }
    }

    It 'bounds the session on the monotonic clock, stops it, and confirms it idle without a cancel' {
        $script:state.Reads.Add('idle')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        @($script:calls) | Should -Be @('start', 'stop', 'confirm:after_stop')
        $record.bound_seconds | Should -Be 5
        $record.stop_ok | Should -BeTrue
        $record.cancel_issued | Should -BeFalse
        $record.confirmed | Should -BeTrue
        $global:WfSynthetic.Waited | Should -Be 5
    }

    It 'cancels a start that did not complete even when the instance reads idle, and reads it again' {
        $script:state.StartOk = $false
        $script:state.Reads.Add('idle')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        @($script:calls) | Should -Be @('start', 'confirm:after_stop', 'cancel:idle', 'confirm:after_cancel')
        $record.stop_issued | Should -BeFalse
        $record.confirmed | Should -BeTrue
    }

    It 'cancels after a stop that failed and reports the state the second read gives' {
        $script:state.StopOk = $false
        $script:state.Reads.Add('active'); $script:state.Reads.Add('active')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        @($script:calls) | Should -Be @('start', 'stop', 'confirm:after_stop', 'cancel:active', 'confirm:after_cancel')
        $record.state_final | Should -BeExactly 'active'
        $record.confirmed | Should -BeFalse
    }

    It 'ends the session when the start raises, as a timed out start does' {
        $script:hooks['Start'] = { param($S) $S.Calls.Add('start'); throw 'wpr -start did not finish within 60 seconds' }
        $script:state.Reads.Add('active'); $script:state.Reads.Add('idle')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        $record.error | Should -Match 'did not finish'
        @($script:calls) | Should -Be @('start', 'confirm:after_stop', 'cancel:active', 'confirm:after_cancel')
        $record.confirmed | Should -BeTrue
    }

    It 'reports unknown, never idle, when the state cannot be read' {
        $script:state.Reads.Add('throw')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        $record.state_final | Should -BeExactly 'unknown'
        $record.confirmed | Should -BeFalse
        $record.end_error | Should -Match 'could not run'
    }

    It 'stops early when the watch says so' {
        $script:hooks['Watch'] = { param($S) return ((Get-WfMonotonicSeconds) -ge 2) }
        $script:state.Reads.Add('idle')
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 30
        $record.stopped_early | Should -BeTrue
        $record.bound_seconds | Should -BeLessThan 30
    }

    It 'never runs the end check for a session that cannot remain' {
        $script:hooks['Start'] = { param($S) $S.Calls.Add('start'); return @{ Ok = $false; MayRemain = $false } }
        $record = Invoke-WfLiveSession -LiveHooks $script:hooks -LiveState $script:state -LiveSeconds 5
        @($script:calls) | Should -Be @('start')
        $record.confirmed | Should -BeNullOrEmpty
    }
}

Describe 'the portable JSON reader' {
    It 'reads what the writer writes, keeping key order, integers and text dates' {
        $text = '{"b":1,"a":[],"c":{"d":"2026-03-01T12:00:00Z","e":-1.5e2,"f":12345678901234,"g":null,"h":true,"i":[[],[{}]]},"j":"q\"\\\u00e9\n"}'
        $value = ConvertFrom-WfJson -Text $text
        @($value.Keys) | Should -Be @('b', 'a', 'c', 'j')
        $value['a'].GetType().IsArray | Should -BeTrue
        $value['a'].Count | Should -Be 0
        $value['c']['d'] | Should -BeOfType [string]
        $value['c']['f'] | Should -BeOfType [int64]
        $value['c']['e'] | Should -Be -150
        $value['c']['g'] | Should -BeNullOrEmpty
        $value['j'] | Should -BeExactly ("q`"\" + [char]0xe9 + "`n")
        ConvertTo-WfJson -Value $value | Should -BeExactly '{"b":1,"a":[],"c":{"d":"2026-03-01T12:00:00Z","e":-150,"f":12345678901234,"g":null,"h":true,"i":[[],[{}]]},"j":"q\"\\\u00e9\n"}'
    }

    It 'reads every committed collector manifest back to the same bytes' {
        foreach ($bundle in @(Get-ChildItem -LiteralPath (Join-Path $script:CollectorRoot '../../fixtures/collector-bundles') -Directory)) {
            $path = Join-Path $bundle.FullName 'manifest.json'
            $text = [System.IO.File]::ReadAllText($path)
            ((ConvertTo-WfJson -Value (Read-WfJsonFile -Path $path) -Indent 0) + "`n") | Should -BeExactly $text -Because $bundle.Name
        }
    }

    It 'refuses text that is not one JSON value' {
        foreach ($bad in @('', '{', '[1,]', '{"a" 1}', '"open', '1 2', 'nul', '{"a":1}x')) {
            { ConvertFrom-WfJson -Text $bad } | Should -Throw -Because $bad
        }
    }
}

Describe 'runner helpers' {
    It 'quotes a process argument the way the C runtime parses it' {
        Format-WfProcessArgument -Value 'plain' | Should -BeExactly 'plain'
        Format-WfProcessArgument -Value 'C:\Program Files\x' | Should -BeExactly '"C:\Program Files\x"'
        Format-WfProcessArgument -Value 'C:\dir with space\' | Should -BeExactly '"C:\dir with space\\"'
        Format-WfProcessArgument -Value 'say "hi"' | Should -BeExactly '"say \"hi\""'
        Format-WfProcessArgument -Value '' | Should -BeExactly '""'
    }

    It 'writes the profile, account and bundle placeholders in plain, JSON escaped and forward slash spellings' {
        $redactions = New-WfRunnerRedactions -BundleRoot 'C:\Users\Someone\runs\b1' -ProfilePath 'C:\Users\Someone' -AccountName 'PC\Someone'
        Protect-WfRunnerText -Text 'C:\Users\Someone\runs\b1\x and c:\\users\\someone\\tools and C:/Users/Someone/y as PC\Someone' -Redactions $redactions |
            Should -BeExactly '<bundle>\x and <profile>\\tools and <profile>/y as <account>'
    }

    It 'knows a path under the profile folder, ignoring case and slashes' {
        Test-WfPathUnder -Path 'c:/users/someone/Downloads/x.exe' -ProfilePath 'C:\Users\Someone' | Should -BeTrue
        Test-WfPathUnder -Path 'C:\Users\Someone2\x.exe' -ProfilePath 'C:\Users\Someone' | Should -BeFalse
        Test-WfPathUnder -Path 'C:\ProgramData\win-forensics\tools\x.exe' -ProfilePath 'C:\Users\Someone' | Should -BeFalse
    }

    It 'declares every registered source as the committed collector bundles show it' {
        $fixtures = Join-Path $script:CollectorRoot '../../fixtures/collector-bundles'
        foreach ($entry in @(Get-WfCollectorRegistry)) {
            $bundle = @(Get-ChildItem -LiteralPath $fixtures -Directory | Where-Object { $_.Name -eq $entry['Name'] -or $_.Name -like ($entry['Name'] + '-*') } | Sort-Object Name)
            if ($entry['Name'] -eq 'config-snapshot') { @($entry['Sources']).Count | Should -Be 0; continue }
            $manifest = Read-WfJsonFile -Path (Join-Path $bundle[0].FullName 'manifest.json')
            $declared = @($entry['Sources'] | ForEach-Object { '{0}|{1}|{2}' -f $_['Id'], $_['Kind'], $_['Required'] })
            $written = @($manifest['collectors'] | ForEach-Object { '{0}|{1}|{2}' -f $_['id'], $_['kind'], $_['required'] })
            $declared | Should -Be $written -Because $entry['Name']
            Test-Path -LiteralPath (Join-Path $script:CollectorRoot ($entry['Name'] + '.ps1')) | Should -BeTrue
        }
    }

    It 'gives every source of every scenario one id in the merged manifest' {
        foreach ($id in @(Get-WfScenarioIds)) {
            $seen = @{}
            foreach ($step in @((Get-WfScenarioDefinition -Id $id -DurationSeconds 60 -ProcessName '')['Steps'])) {
                foreach ($source in @((Get-WfRegistryEntry -Name $step['Collector'])['Sources'])) {
                    $name = $step['Prefix'] + $source['Id']
                    $seen.ContainsKey($name) | Should -BeFalse -Because $name
                    $seen[$name] = $true
                }
            }
        }
    }
}

Describe 'the scenario runner' {
    BeforeEach {
        Reset-WfSynthetic
        Set-WfSyntheticScenarioMachine
        $script:out = Join-Path $TestDrive ('run-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'runs S1 in its fixed order, merges every source, and closes a valid manifest last' {
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 0
        $run.Stdout.Count | Should -Be 1
        $summary = ConvertFrom-WfJson -Text $run.Stdout[0]
        $summary['collector'] | Should -BeExactly 'scenario-runner'
        $summary['status'] | Should -BeExactly 'partial'
        $run.Children | Should -Be @('clock-calibration', 'dpcisr-trace', 'presentmon-frames', 'bugcheck-history', 'whea-errors', 'application-errors', 'tdr-events', 'reliability-records', 'driver-inventory')
        $m = $run.Manifest
        $m['manifest_version'] | Should -BeExactly '1.2.0'
        $m['capture']['orchestrator'] | Should -BeExactly 'wf-runner:s1'
        $m['preflight']['ok'] | Should -BeTrue
        @($m['run']['steps'] | ForEach-Object { $_['step'] }) | Should -Be @('state_before', 'clock', 'dpcisr', 'frames', 'bugchecks', 'whea', 'app_errors', 'tdr', 'reliability', 'drivers', 'state_after')
        (Get-TestStep $m 'state_before')['outcome'] | Should -BeExactly 'absent'
        (Get-TestStep $m 'clock')['ready'] | Should -BeTrue
        $m['run']['clock_brackets_live'] | Should -BeTrue
        (Get-TestEntry $m 'presentmon_frames')['status'] | Should -BeExactly 'observed'
        (Get-TestEntry $m 'wpr_trace')['required'] | Should -BeTrue
        (Get-TestEntry $m 'system_restart_events')['required'] | Should -BeFalse
        @($m['calibration']['pairs']).Count | Should -BeGreaterThan 2
        @($m['scenario']['marks']).Count | Should -Be 2
        @($m['machine']['drivers']).Count | Should -BeGreaterThan 0
        # The clock runs across both captures; each capture gets the runner's window.
        $clock = $global:WfSynthetic.ChildRuns[0]
        $clockArguments = @($clock['Arguments'])
        $at = -1
        for ($i = 0; $i -lt $clockArguments.Count; $i++) { if ($clockArguments[$i] -eq '-DurationSeconds') { $at = $i } }
        $clockArguments[$at + 1] | Should -BeExactly '300'
        foreach ($child in $global:WfSynthetic.ChildRuns) {
            $child['Arguments'][1] | Should -BeExactly (Join-WfBundlePath -BundleRoot (Resolve-WfBundleRoot -OutputDirectory $script:out) -RelativePath ('logs/steps/' + @($m['run']['steps'] | Where-Object { $_['collector'] -eq $child['Name'] })[0]['step']))
        }
        # Every artifact is in place and hashes to what the manifest says.
        foreach ($entry in @($m['collectors'])) {
            foreach ($artifact in @($entry['artifacts'])) {
                $path = Join-WfBundlePath -BundleRoot $script:out -RelativePath $artifact['path']
                (Get-WfSha256OfFile -Path $path) | Should -BeExactly $artifact['sha256']
            }
        }
        @(Get-ChildItem -LiteralPath (Join-Path $script:out 'logs/steps') -Recurse -Directory | Where-Object { $_.Name -eq 'raw' -or $_.Name -eq 'private' }).Count | Should -Be 0
    }

    It 'refuses an output directory that already holds a bundle' {
        (Invoke-TestRun -OutputDirectory $script:out).ExitCode | Should -Be 0
        $before = [System.IO.File]::ReadAllText((Join-Path $script:out 'manifest.json'))
        $global:WfSynthetic.ChildRuns.Clear()
        $again = Invoke-TestRun -OutputDirectory $script:out
        $again.ExitCode | Should -Be 1
        $again.Children.Count | Should -Be 0
        [System.IO.File]::ReadAllText((Join-Path $script:out 'manifest.json')) | Should -BeExactly $before
    }

    It 'refuses to start without elevation, runs nothing, and lists every source as not_collected' {
        $global:WfSynthetic.Elevated = $false
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        $run.Children.Count | Should -Be 0
        $m = $run.Manifest
        $m['preflight']['ok'] | Should -BeFalse
        (Get-TestCheck $m 'rights:dpcisr')['ok'] | Should -BeFalse
        foreach ($entry in @($m['collectors'])) {
            $entry['status'] | Should -BeExactly 'not_collected'
            $entry['status_reason'] | Should -Match 'refused to start'
            @($entry['artifacts']).Count | Should -Be 0
        }
        @($m['collectors']).Count | Should -Be 14
        @($m['run']['steps'] | Where-Object { $_['outcome'] -ne 'absent' } | ForEach-Object { $_['outcome'] } | Select-Object -Unique) | Should -Be @('not_started')
        $m['calibration']['status'] | Should -BeExactly 'not_collected'
        @(Get-ChildItem -LiteralPath (Join-Path $script:out 'raw')).Count | Should -Be 0
    }

    It 'refuses when the PresentMon binary is absent, never downloading it' {
        $global:WfSynthetic.Binaries.Remove((Get-WfSyntheticPresentMonPath))
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        $run.Children.Count | Should -Be 0
        (Get-TestCheck $run.Manifest 'tool:presentmon')['detail'] | Should -Match 'does not exist; the runner never downloads it'
    }

    It 'refuses a PresentMon binary whose hash is not the pin' {
        $global:WfSynthetic.Binaries[(Get-WfSyntheticPresentMonPath)]['Sha256'] = ('0' * 64)
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        (Get-TestCheck $run.Manifest 'tool:presentmon')['ok'] | Should -BeFalse
        $run.Manifest['preflight']['ok'] | Should -BeFalse
    }

    It 'refuses a tool path under the profile folder and never writes that folder' {
        $global:WfSynthetic.ProfilePath = 'C:\Users\synthetic-owner'
        $path = 'C:\Users\synthetic-owner\Downloads\PresentMon-2.6.0-x64.exe'
        $global:WfSynthetic.Binaries[$path] = $global:WfSynthetic.Binaries[(Get-WfSyntheticPresentMonPath)]
        $run = Invoke-TestRun -OutputDirectory $script:out -Arguments @{ PresentMonPath = $path }
        $run.ExitCode | Should -Be 1
        (Get-TestCheck $run.Manifest 'tool:presentmon')['detail'] | Should -Match 'under the profile folder'
        foreach ($file in @(Get-ChildItem -LiteralPath $script:out -Recurse -File)) {
            [System.IO.File]::ReadAllText($file.FullName) | Should -Not -Match 'synthetic-owner' -Because $file.Name
        }
    }

    It 'goes on without the optional xperf, which leaves the per CPU report not_collected' {
        $run = Invoke-TestRun -OutputDirectory $script:out -Arguments @{ XperfPath = '' }
        $run.ExitCode | Should -Be 0
        (Get-TestCheck $run.Manifest 'tool:xperf')['ok'] | Should -BeFalse
        $run.Manifest['preflight']['required'] | Should -Not -Contain 'tool:xperf'
        (Get-TestEntry $run.Manifest 'dpcisr_report')['status'] | Should -BeExactly 'not_collected'
    }

    It 'accepts an xperf whose hash and version are a pinned build' {
        $run = Invoke-TestRun -OutputDirectory $script:out
        $check = Get-TestCheck $run.Manifest 'tool:xperf'
        $check['ok'] | Should -BeTrue
        $check['detail'] | Should -Match 'match a pinned build'
        (Get-TestEntry $run.Manifest 'dpcisr_report')['status'] | Should -BeExactly 'observed'
    }

    It 'says no xperf build is pinned yet when none is' {
        $global:WfSynthetic.PinnedTools['xperf'] = @()
        $run = Invoke-TestRun -OutputDirectory $script:out
        $check = Get-TestCheck $run.Manifest 'tool:xperf'
        $check['ok'] | Should -BeFalse
        $check['detail'] | Should -Match 'no xperf build is pinned yet'
    }

    It 'refuses an xperf whose hash is not a pinned build' {
        $global:WfSynthetic.PinnedTools['xperf'] = @(@{ Version = '10.0.26100.1 (synthetic)'; Sha256 = ('0' * 63) + '9'; Source = 'another build' })
        $run = Invoke-TestRun -OutputDirectory $script:out
        $check = Get-TestCheck $run.Manifest 'tool:xperf'
        $check['ok'] | Should -BeFalse
        $check['detail'] | Should -Match 'matches no pinned build'
    }

    It 'refuses when the volume has less free space than the scenario needs, or cannot be read' {
        $global:WfSynthetic.FreeBytes = [int64]1000000
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        (Get-TestCheck $run.Manifest 'free_space')['detail'] | Should -Match 'needs at least \d+'
        $run.Manifest['run']['minimum_free_bytes'] | Should -BeGreaterThan 2147483648
        Reset-WfSynthetic; Set-WfSyntheticScenarioMachine
        $global:WfSynthetic.FreeBytes = $null
        $second = Invoke-TestRun -OutputDirectory ($script:out + '-b')
        $second.ExitCode | Should -Be 1
        (Get-TestCheck $second.Manifest 'free_space')['detail'] | Should -Match 'could not be read'
    }

    It 'refuses under an interpreter other than Windows PowerShell 5.1' {
        $global:WfSynthetic.Host = [ordered]@{ edition = 'Core'; version = '7.4.6' }
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        (Get-TestCheck $run.Manifest 'interpreter')['ok'] | Should -BeFalse
    }

    It 'records a collector that could not start and fails the run when it was required' {
        $global:WfSynthetic.Children['presentmon-frames'] = @{ Case = 'presentmon-frames'; StartFails = 'synthetic: the process could not be created' }
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        (Get-TestStep $run.Manifest 'frames')['outcome'] | Should -BeExactly 'start_failed'
        (Get-TestEntry $run.Manifest 'presentmon_frames')['status'] | Should -BeExactly 'not_collected'
        (Get-TestEntry $run.Manifest 'presentmon_frames')['status_reason'] | Should -Match 'could not be created'
        # The steps after it still ran.
        $run.Children | Should -Contain 'driver-inventory'
    }

    It 'stops a frame recording collector at its deadline, cancels its named recording, and only then removes what it left' {
        $global:WfSynthetic.Children['presentmon-frames'] = @{ Case = 'presentmon-frames'; Stuck = $true; Leftovers = @('raw/presentmon_frames/trace.etl', 'raw/presentmon_frames/wpr-temp/a.etl') }
        Set-WfSyntheticWprState -Instance (Get-WfPresentMonInstanceName) -State 'recording'
        $global:WfSynthetic.Processes.Clear()
        $global:WfSynthetic.WatchPath = Join-Path $script:out 'logs/steps/frames/raw'
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        $step = Get-TestStep $run.Manifest 'frames'
        $step['outcome'] | Should -BeExactly 'timed_out'
        $step['private_removed'] | Should -BeTrue
        $step['session_end']['checked'] | Should -BeTrue
        $step['session_end']['cancel_issued'] | Should -BeTrue
        $step['session_end']['confirmed'] | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:out 'logs/steps/frames/raw') | Should -BeFalse
        $calls = @($global:WfSynthetic.Processes | ForEach-Object { $_['Arguments'] })
        $calls | Should -Be @('-status -instancename wf-presentmon-frames', '-cancel -instancename wf-presentmon-frames', '-status -instancename wf-presentmon-frames')
        # A recording still being written cannot be deleted, so the folder is still there at every wpr call.
        @($global:WfSynthetic.Processes | ForEach-Object { $_['WatchedPathExists'] }) | Should -Be @($true, $true, $true)
        (Get-TestEntry $run.Manifest 'presentmon_frames')['status_reason'] | Should -Match 'timed_out'
    }

    It 'says so when the session of a stopped collector cannot be confirmed' {
        $global:WfSynthetic.Children['presentmon-frames'] = @{ Case = 'presentmon-frames'; Stuck = $true; Leftovers = @() }
        Set-WfSyntheticWprState -Instance (Get-WfPresentMonInstanceName) -State 'recording'
        $global:WfSynthetic.Wpr.CancelLeavesRunning = $true
        $run = Invoke-TestRun -OutputDirectory $script:out
        $end = (Get-TestStep $run.Manifest 'frames')['session_end']
        $end['confirmed'] | Should -BeFalse
        $end['state_final'] | Should -BeExactly 'active'
        $end['detail'] | Should -Match 'wpr -status -instancename wf-presentmon-frames'
    }

    It 'removes the private kernel trace of a stopped trace collector and reports the instance it cannot name' {
        $global:WfSynthetic.Children['dpcisr-trace'] = @{ Case = 'dpcisr-trace'; Stuck = $true; Leftovers = @('private/trace.etl', 'raw/wpr_trace/status.txt') }
        $global:WfSynthetic.Processes.Clear()
        $run = Invoke-TestRun -OutputDirectory $script:out
        $step = Get-TestStep $run.Manifest 'dpcisr'
        $step['outcome'] | Should -BeExactly 'timed_out'
        $step['private_removed'] | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:out 'logs/steps/dpcisr/private') | Should -BeFalse
        $step['session_end']['checked'] | Should -BeFalse
        $step['session_end']['detail'] | Should -Match 'WfDpcIsrTrace-'
        @($global:WfSynthetic.Processes | Where-Object { $_['FilePath'] -like '*wpr.exe' }).Count | Should -Be 0
    }

    It 'removes the raw and private folders of a finished step whose manifest cannot be read' {
        $stepRoot = Join-Path $TestDrive 'unreadable/logs/steps/frames'
        foreach ($relative in @('raw/presentmon_frames/frames.csv', 'private/trace.etl')) {
            $path = Join-Path $stepRoot $relative
            $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path)
            [System.IO.File]::WriteAllText($path, 'synthetic leftover')
        }
        [System.IO.File]::WriteAllText((Join-Path $stepRoot 'manifest.json'), '{ "collectors": [')
        $step = @{ Step = 'frames'; Collector = 'presentmon-frames'; Prefix = ''; Required = $true; StepRoot = $stepRoot; Entry = (Get-WfRegistryEntry -Name 'presentmon-frames') }
        $record = [ordered]@{ outcome = 'completed'; detail = $null; private_removed = $null }
        $entries = New-Object 'System.Collections.Generic.List[object]'
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $log = New-Object 'System.Collections.Generic.List[string]'
        Merge-WfScenarioStep -Step $step -Record $record -BundleRoot (Join-Path $TestDrive 'unreadable') -Entries $entries -Seen $seen -Log $log
        $record.outcome | Should -BeExactly 'no_manifest'
        $record.private_removed | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $stepRoot 'raw') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $stepRoot 'private') | Should -BeFalse
        $entries.Count | Should -Be 1
        $entries[0].status | Should -BeExactly 'not_collected'
        $entries[0].status_reason | Should -Match 'manifest could not be read'
    }

    It 'holds the frame recording step to the peak the collector states for itself' {
        $extra = & (Get-WfRegistryEntry -Name 'presentmon-frames')['DiskExtra'] ([int64]67108864)
        (2 * [int64]67108864 + $extra) | Should -Be (Get-WfPresentMonPeakBytesBound -MaxArtifactBytes 67108864)
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.Manifest['run']['minimum_free_bytes'] | Should -Be 3542089728
    }

    It 'fails the run when a required capture lost events, and keeps what the collector said' {
        $global:WfSynthetic.Children['presentmon-frames'] = @{ Case = 'presentmon-frames-lost-events' }
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 1
        (ConvertFrom-WfJson -Text $run.Stdout[0])['status'] | Should -BeExactly 'failed'
        (Get-TestEntry $run.Manifest 'presentmon_frames')['status'] | Should -BeExactly 'capture_failed'
        (Get-TestStep $run.Manifest 'frames')['outcome'] | Should -BeExactly 'completed'
    }

    It 'records a clock session that never became ready and still runs the captures' {
        $global:WfSynthetic.Children['clock-calibration'] = @{ Case = 'clock-calibration'; Concurrent = $true; NotReady = $true }
        $run = Invoke-TestRun -OutputDirectory $script:out
        (Get-TestStep $run.Manifest 'clock')['ready'] | Should -BeFalse
        $run.Children | Should -Contain 'presentmon-frames'
    }

    It 'says whether the clock pairs bracket the live captures' {
        $start = [datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc)
        $calibration = @{ pairs = @(@{ filetime_utc_100ns = $start.ToFileTimeUtc() }, @{ filetime_utc_100ns = $start.AddSeconds(300).ToFileTimeUtc() }) }
        $inside = @([ordered]@{ phase = 'live'; background = $false; started_utc = '2026-03-01T12:00:10Z'; stopped_utc = '2026-03-01T12:04:00Z' })
        $after = @([ordered]@{ phase = 'live'; background = $false; started_utc = '2026-03-01T12:00:10Z'; stopped_utc = '2026-03-01T12:06:00Z' })
        Test-WfClockBracketsLive -Calibration $calibration -Records $inside | Should -BeTrue
        Test-WfClockBracketsLive -Calibration $calibration -Records $after | Should -BeFalse
        Test-WfClockBracketsLive -Calibration @{ pairs = @() } -Records $inside | Should -BeNullOrEmpty
    }

    It 'writes no profile folder, account name or output directory in clear' {
        $global:WfSynthetic.ProfilePath = $TestDrive
        $run = Invoke-TestRun -OutputDirectory $script:out
        $run.ExitCode | Should -Be 0
        $resolved = Resolve-WfBundleRoot -OutputDirectory $script:out
        foreach ($file in @(Get-ChildItem -LiteralPath $script:out -Recurse -File)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            $text.Contains($TestDrive) | Should -BeFalse -Because $file.FullName
            $text.Contains($resolved) | Should -BeFalse -Because $file.FullName
            $text.Contains('SYNTHETIC-PC\wf-collector') | Should -BeFalse -Because $file.FullName
            $text.Contains('SYNTHETIC-PC\\wf-collector') | Should -BeFalse -Because $file.FullName
        }
        [System.IO.File]::ReadAllText((Join-Path $script:out 'logs/steps/clock/logs/summary.json')) | Should -Match '<bundle>'
    }

    It 'prints the mark command for the running clock session on stderr' {
        $run = Invoke-TestRun -OutputDirectory $script:out
        @($run.Stderr | Where-Object { $_ -match 'Mark "<what you noticed>"' }).Count | Should -Be 1
    }

    It 'refuses its own bad parameters with one failed line and no directory' {
        $global:WfSynthetic.Stdout.Clear()
        $null = & (Join-Path $script:CollectorRoot '_run-scenario.ps1') -OutputDirectory $script:out -DurationSeconds 5
        $LASTEXITCODE | Should -Be 1
        Test-Path -LiteralPath $script:out | Should -BeFalse
    }
}
