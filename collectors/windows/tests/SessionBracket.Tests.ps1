# Pester 5 tests for the session-bracket collector, run off Windows against
# the synthetic backend. The fixture cases (SyntheticScenarios.ps1) cover
# every status; these tests cover what a single bundle cannot show: the
# logon task's evidence folder flow end to end, the guard leaving every other
# reader untouched, a baseline that changed after it was written, and the
# arguments the collector refuses.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:CollectorRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:CollectorRoot '_common.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticBackend.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticScenarios.ps1')
    $script:Collector = Join-Path $script:CollectorRoot 'session-bracket.ps1'

    function Invoke-Bracket {
        param([hashtable]$Arguments)
        $global:WfSynthetic.Stdout.Clear()
        $global:WfSynthetic.Stderr.Clear()
        $null = @(& $script:Collector @Arguments)
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Stdout   = @($global:WfSynthetic.Stdout.ToArray())
            Stderr   = @($global:WfSynthetic.Stderr.ToArray())
        }
    }

    function Read-Manifest {
        param([string]$Bundle)
        return (Get-Content -LiteralPath (Join-Path $Bundle 'manifest.json') -Raw | ConvertFrom-Json)
    }

    function Get-Source {
        param($Manifest, [string]$Id)
        return @($Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
    }

    function Start-Stage {
        # A fresh synthetic machine at the given stage, its Desktop in the test drive.
        param([string]$Stage, [string]$Desktop, [switch]$GameRunning)
        Reset-WfSynthetic
        $global:WfSynthetic.Desktop = $Desktop
        New-WfSyntheticBracketMachine -Stage $Stage -GameRunning:$GameRunning
    }
}

Describe 'session-bracket from the logon task to the after read' {
    It 'writes the baseline under Desktop\latency-evidence with the manifest hash beside it, and the after read finds it there' {
        $desktop = Join-Path $TestDrive 'desktop-flow'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop
        $baseline = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true }
        $baseline.ExitCode | Should -Be 0
        $baseline.Stdout.Count | Should -Be 1
        $evidence = Join-Path $desktop 'latency-evidence'
        $folders = @(Get-ChildItem -LiteralPath $evidence -Directory)
        $folders.Count | Should -Be 1
        $folders[0].Name | Should -Match '^session-baseline-\d{8}T\d{6}Z$'
        ($baseline.Stdout[0] | ConvertFrom-Json).bundle | Should -BeExactly $folders[0].Name -Because 'the summary names the folder alone, never the profile path the Desktop sits under'
        Get-ChildItem -LiteralPath $folders[0].FullName -Recurse -File | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) | Should -Not -Match ([regex]::Escape($desktop)) -Because $_.Name }
        $sidecar = $folders[0].FullName + '.sha256'
        Test-Path -LiteralPath $sidecar | Should -BeTrue
        $recorded = ([System.IO.File]::ReadAllText($sidecar) -split '\s+')[0]
        $recorded | Should -BeExactly ((Get-FileHash -LiteralPath (Join-Path $folders[0].FullName 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant())

        Start-Stage -Stage 'after' -Desktop $desktop
        $after = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true; Phase = 'after' }
        $after.ExitCode | Should -Be 0
        $after.Stdout.Count | Should -Be 1 -Because 'the delta table goes to stderr; stdout carries the summary line alone'
        ($after.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        $afterFolder = @(Get-ChildItem -LiteralPath $evidence -Directory | Where-Object { $_.Name -like 'session-after-*' })[0]
        $delta = Get-Source -Manifest (Read-Manifest -Bundle $afterFolder.FullName) -Id 'session_delta'
        $delta.status | Should -BeExactly 'observed'
        $delta.enabled.options.baseline_bundle_id | Should -BeExactly (Read-Manifest -Bundle $folders[0].FullName).bundle_id
        ($after.Stderr -join "`n") | Should -Match 'example-launcher\.exe'
        ($after.Stderr -join "`n") | Should -Not -Match 'svchost\.exe' -Because 'a matched process with no write is left out of the printed table'
    }

    It 'refuses a baseline whose files changed after it was written' {
        $desktop = Join-Path $TestDrive 'desktop-tamper'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop
        $null = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true }
        $baselineFolder = @(Get-ChildItem -LiteralPath (Join-Path $desktop 'latency-evidence') -Directory)[0]
        $records = Join-Path $baselineFolder.FullName 'raw/process_io/records.json'
        [System.IO.File]::WriteAllText($records, [System.IO.File]::ReadAllText($records).Replace('4100000000', '4000000000'))

        Start-Stage -Stage 'after' -Desktop $desktop
        $after = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true; Phase = 'after' }
        $afterFolder = @(Get-ChildItem -LiteralPath (Join-Path $desktop 'latency-evidence') -Directory | Where-Object { $_.Name -like 'session-after-*' })[0]
        $delta = Get-Source -Manifest (Read-Manifest -Bundle $afterFolder.FullName) -Id 'session_delta'
        $delta.status | Should -BeExactly 'capture_failed'
        $delta.status_reason | Should -Match 'no longer matches its manifest: changed raw/process_io/records\.json'
        Test-Path -LiteralPath (Join-Path $afterFolder.FullName 'raw/session_delta/process_delta.json') | Should -BeFalse
        ($after.Stderr -join "`n") | Should -Match 'no delta'
    }

    It 'refuses a baseline whose manifest no longer matches the hash file beside it' {
        $desktop = Join-Path $TestDrive 'desktop-sidecar'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop
        $null = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true }
        $baselineFolder = @(Get-ChildItem -LiteralPath (Join-Path $desktop 'latency-evidence') -Directory)[0]
        [System.IO.File]::WriteAllText($baselineFolder.FullName + '.sha256', ('0' * 64) + "  manifest.json`n")

        Start-Stage -Stage 'after' -Desktop $desktop
        $null = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true; Phase = 'after' }
        $afterFolder = @(Get-ChildItem -LiteralPath (Join-Path $desktop 'latency-evidence') -Directory | Where-Object { $_.Name -like 'session-after-*' })[0]
        $delta = Get-Source -Manifest (Read-Manifest -Bundle $afterFolder.FullName) -Id 'session_delta'
        $delta.status | Should -BeExactly 'capture_failed'
        $delta.status_reason | Should -Match 'changed manifest\.json'
    }
}

Describe 'the session-bracket game guard' {
    It 'reads nothing but the process names when a game runs: no registry key, no event log, no process started' {
        $desktop = Join-Path $TestDrive 'desktop-game'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop -GameRunning
        # Readers that would fail the test if anything behind the guard touched them.
        $global:WfSynthetic.Registry = @{}
        $global:WfSynthetic.Channels = @{}
        $global:WfSynthetic.Queries.Clear()
        $run = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true }
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $global:WfSynthetic.Processes.Count | Should -Be 0 -Because 'powercfg is behind the guard'
        $bundle = @(Get-ChildItem -LiteralPath (Join-Path $desktop 'latency-evidence') -Directory)[0].FullName
        $manifest = Read-Manifest -Bundle $bundle
        (Get-Source -Manifest $manifest -Id 'game_guard').status | Should -BeExactly 'observed'
        foreach ($source in @($manifest.collectors | Where-Object { $_.id -ne 'game_guard' })) {
            $source.status | Should -BeExactly 'not_collected'
            @(Get-ChildItem -LiteralPath (Join-Path $bundle ('raw/' + $source.id))).Name | Should -Be @('query.json')
        }
        @($manifest.notes) -join ' ' | Should -Match 'FortniteClient-Win64-Shipping\.exe'
    }

    It 'matches a game name without regard to case and only on the whole image name' {
        $desktop = Join-Path $TestDrive 'desktop-case'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop
        $rows = @($global:WfSynthetic.Cim['Win32_Process']['Rows']) + @([ordered]@{ Name = 'overwatch.EXE'; ProcessId = 4100; CreationDate = '2026-03-01T11:58:00.0000000Z'; WriteTransferCount = 1; WriteOperationCount = 1 })
        $global:WfSynthetic.Cim['Win32_Process'] = @{ Rows = $rows }
        $run = Invoke-Bracket -Arguments @{ OutputDirectory = (Join-Path $TestDrive 'case-bundle') }
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $guard = Get-Source -Manifest (Read-Manifest -Bundle (Join-Path $TestDrive 'case-bundle')) -Id 'game_guard'
        @($guard.enabled.options.games_found) | Should -Be @('Overwatch.exe')

        Start-Stage -Stage 'baseline' -Desktop $desktop
        $rows = @($global:WfSynthetic.Cim['Win32_Process']['Rows']) + @([ordered]@{ Name = 'Overwatch.exe.bak'; ProcessId = 4100; CreationDate = '2026-03-01T11:58:00.0000000Z'; WriteTransferCount = 1; WriteOperationCount = 1 })
        $global:WfSynthetic.Cim['Win32_Process'] = @{ Rows = $rows }
        $run = Invoke-Bracket -Arguments @{ OutputDirectory = (Join-Path $TestDrive 'prefix-bundle') }
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
    }

    It 'treats a process list cut at its cap as unknown, never as no game' {
        $desktop = Join-Path $TestDrive 'desktop-cap'
        $null = New-Item -ItemType Directory -Path $desktop
        Start-Stage -Stage 'baseline' -Desktop $desktop
        $run = Invoke-Bracket -Arguments @{ OutputDirectory = (Join-Path $TestDrive 'cap-bundle'); MaxEvents = 3 }
        $run.ExitCode | Should -Be 1
        $manifest = Read-Manifest -Bundle (Join-Path $TestDrive 'cap-bundle')
        (Get-Source -Manifest $manifest -Id 'game_guard').status | Should -BeExactly 'capture_failed'
        (Get-Source -Manifest $manifest -Id 'process_io').status_reason | Should -Match 'whether a game is running is unknown'
    }
}

Describe 'session-bracket arguments' {
    It 'refuses <Name> without writing a bundle' -ForEach @(
        @{ Name = 'an unknown phase'; Arguments = @{ Phase = 'during' } },
        @{ Name = 'both destinations'; Arguments = @{ ToEvidenceFolder = $true } }
    ) {
        Reset-WfSynthetic
        $target = Join-Path $TestDrive ('refused-' + $Name.Replace(' ', '-'))
        $all = @{ OutputDirectory = $target }
        foreach ($key in $Arguments.Keys) { $all[$key] = $Arguments[$key] }
        $null = & $script:Collector @all 2>$null
        $LASTEXITCODE | Should -Be 1
        Test-Path -LiteralPath $target | Should -BeFalse
    }

    It 'fails closed with one line when the Desktop folder cannot be resolved' {
        Reset-WfSynthetic
        $global:WfSynthetic.Desktop = $null
        $run = Invoke-Bracket -Arguments @{ ToEvidenceFolder = $true }
        $run.ExitCode | Should -Be 1
        $run.Stdout.Count | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        ($run.Stderr -join "`n") | Should -Match 'evidence folder could not be resolved'
    }
}
