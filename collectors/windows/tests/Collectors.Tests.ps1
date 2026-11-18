# Pester 5 tests for the collector helper and the collectors, run off Windows.
#
# The Windows adapters are replaced by SyntheticBackend.ps1, so these tests
# prove the portable logic (layout, manifest, checksums, measurement status,
# the summary line, the exit code) and nothing about Windows itself. What
# only a real machine can show is listed in collectors/windows/README.md.

BeforeAll {
    Set-StrictMode -Version 2.0
    $script:CollectorRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:CollectorRoot '_common.ps1')
    # The real process runner, kept before the synthetic backend replaces it,
    # so one test can run it against a real child process on this host.
    $script:RealInvokeProcess = ${function:Invoke-WfProcess}
    . (Join-Path $PSScriptRoot 'SyntheticBackend.ps1')
    . (Join-Path $PSScriptRoot 'SyntheticScenarios.ps1')

    function Invoke-TestCollector {
        # Runs a real collector script in this process against the synthetic
        # backend and returns what a caller of the script would see.
        param([string]$Collector, [string]$OutputDirectory, [hashtable]$Arguments = @{})
        $global:WfSynthetic.Stdout.Clear()
        $global:WfSynthetic.Stderr.Clear()
        $all = @{ OutputDirectory = $OutputDirectory }
        foreach ($key in $Arguments.Keys) { $all[$key] = $Arguments[$key] }
        $pipeline = @(& (Join-Path $script:CollectorRoot ($Collector + '.ps1')) @all)
        $manifestPath = Join-Path $OutputDirectory 'manifest.json'
        $manifest = $null
        if (Test-Path -LiteralPath $manifestPath) { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Pipeline = $pipeline
            Stdout   = @($global:WfSynthetic.Stdout.ToArray())
            Stderr   = @($global:WfSynthetic.Stderr.ToArray())
            Manifest = $manifest
        }
    }

    function Get-TestUtcText {
        # ConvertFrom-Json in PowerShell 7 turns ISO 8601 text into DateTime;
        # Windows PowerShell 5.1 leaves it as text. This gives the text back.
        param($Value)
        if ($Value -is [datetime]) { return (ConvertTo-WfUtcString -Value $Value) }
        return [string]$Value
    }

    function Get-TestSha256 {
        param([string]$Path)
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

Describe 'time and value conversion' {
    It 'writes UTC with seven fractional digits' {
        $value = [datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc).AddTicks(1234567)
        ConvertTo-WfUtcString -Value $value | Should -BeExactly '2026-03-01T12:00:00.1234567Z'
        ConvertTo-WfCompactUtc -Value $value | Should -BeExactly '20260301T120000Z'
    }

    It 'round trips its own UTC text' {
        $text = '2026-02-26T06:00:00.0000001Z'
        ConvertTo-WfUtcString -Value (ConvertFrom-WfUtcString -Text $text) | Should -BeExactly $text
    }

    It 'cuts a SystemTime fraction to seven digits without rounding' {
        Format-WfSystemTime -Text '2024-11-25T16:59:52.684557999Z' | Should -BeExactly '2024-11-25T16:59:52.6845579Z'
        Format-WfSystemTime -Text '2024-11-25T16:59:52.684Z' | Should -BeExactly '2024-11-25T16:59:52.684Z'
        Format-WfSystemTime -Text '2024-11-25T16:59:52Z' | Should -BeExactly '2024-11-25T16:59:52Z'
    }

    It 'returns null for text that is not a UTC timestamp' {
        Format-WfSystemTime -Text '11/25/2024 4:59 PM' | Should -BeNullOrEmpty
        Format-WfSystemTime -Text $null | Should -BeNullOrEmpty
    }

    It 'turns event data values into JSON scalars' {
        ConvertTo-WfScalar -Value $null | Should -BeNullOrEmpty
        ConvertTo-WfScalar -Value 'text' | Should -BeExactly 'text'
        ConvertTo-WfScalar -Value $true | Should -BeTrue
        ConvertTo-WfScalar -Value ([uint32]159) | Should -Be 159
        (ConvertTo-WfScalar -Value ([uint32]159)) | Should -BeOfType [int64]
        ConvertTo-WfScalar -Value ([byte[]](0x43, 0x50, 0x45, 0x52)) | Should -BeExactly '43504552'
        ConvertTo-WfScalar -Value ([uint64]::MaxValue) | Should -BeExactly '18446744073709551615'
        ConvertTo-WfScalar -Value ([string[]]('a', 'b')) | Should -BeExactly 'a; b'
        ConvertTo-WfScalar -Value ([guid]'00000000-0000-0000-0000-000000000001') | Should -BeExactly '00000000-0000-0000-0000-000000000001'
        ConvertTo-WfScalar -Value ([datetime]::new(2026, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc)) | Should -BeExactly '2026-01-02T03:04:05.0000000Z'
    }

    It 'keeps a WMI string array as an array, even with one element' {
        $value = ConvertTo-WfJsonValue -Value ([string[]]@('only'))
        , $value | Should -BeOfType [object[]]
        (ConvertTo-WfJson -Value ([ordered]@{ v = $value })) | Should -BeExactly '{"v":["only"]}'
    }

    It 'returns an empty list for a missing value and never a list holding null' {
        $none = Get-WfList -Value $null
        $one = Get-WfList -Value 'x'
        $two = Get-WfList -Value @(1, 2)
        , $none | Should -BeOfType [object[]]
        @($none).Count | Should -Be 0
        @($one).Count | Should -Be 1
        @($two).Count | Should -Be 2
    }
}

Describe 'JSON writer' {
    It 'writes scalars, maps and lists that a JSON parser reads back' {
        $value = [ordered]@{
            text = 'a "quoted" \ path'; none = $null; yes = $true; no = $false; whole = [int64]9007199254740993
            byte = [byte]7; real = 9.5; when = [datetime]::new(2026, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc)
            empty_list = @(); empty_map = [ordered]@{}; one = @('only'); nested = @([ordered]@{ a = @(1, 2) })
        }
        $compact = ConvertTo-WfJson -Value $value
        $compact | Should -Not -Match "`n"
        $compact | Should -BeExactly '{"text":"a \"quoted\" \\ path","none":null,"yes":true,"no":false,"whole":9007199254740993,"byte":7,"real":9.5,"when":"2026-01-02T03:04:05.0000000Z","empty_list":[],"empty_map":{},"one":["only"],"nested":[{"a":[1,2]}]}'
        $pretty = ConvertTo-WfJson -Value $value -Indent 0
        ($pretty -replace '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)', '') | Should -BeExactly ($compact -replace '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)', '')
        $parsed = $pretty | ConvertFrom-Json
        $parsed.text | Should -BeExactly 'a "quoted" \ path'
        $parsed.none | Should -BeNullOrEmpty
        @($parsed.one).Count | Should -Be 1
        $parsed.nested[0].a | Should -Be @(1, 2)
    }

    It 'keeps text in plain ASCII by escaping control and non ASCII characters' {
        $text = "line one`r`nline two`ttab " + [char]0x07 + ' caf' + [char]0xE9 + ' ' + [char]0xD83D + [char]0xDE00
        $json = ConvertTo-WfJsonString -Text $text
        $bs = [string][char]92
        $expected = '"line one\r\nline two\ttab ' + $bs + 'u0007 caf' + $bs + 'u00e9 ' + $bs + 'ud83d' + $bs + 'ude00"'
        $json | Should -BeExactly $expected
        $json | Should -Match '^[\x20-\x7e]+$'
        ($json | ConvertFrom-Json) | Should -BeExactly $text
    }

    It 'writes an array that carries a psobject wrapper as an array' {
        # Windows PowerShell's ConvertTo-Json writes such an array as an object
        # with value and Count members (PowerShell/PowerShell issue 3153).
        $wrapped = Write-Output -NoEnumerate @(1, 2)
        ConvertTo-WfJson -Value ([ordered]@{ list = $wrapped }) | Should -BeExactly '{"list":[1,2]}'
        $returned = Get-WfList -Value @('a')
        ConvertTo-WfJson -Value ([ordered]@{ list = $returned }) | Should -BeExactly '{"list":["a"]}'
    }

    It 'writes numbers that are not finite as null' {
        ConvertTo-WfJson -Value ([double]::NaN) | Should -BeExactly 'null'
        ConvertTo-WfJson -Value ([double]::PositiveInfinity) | Should -BeExactly 'null'
    }
}

Describe 'collector names' {
    It 'accepts the names the seam allows' {
        foreach ($name in @('bugcheck-history', 'whea-errors', 'ab', 'a1-b2')) { Test-WfCollectorName -Name $name | Should -BeTrue -Because $name }
    }

    It 'rejects names the dispatcher must never map' {
        foreach ($name in @('_common', 'Bugcheck', 'a', 'x_y', '-x', '1abc', 'a.b', ('a' * 42))) { Test-WfCollectorName -Name $name | Should -BeFalse -Because $name }
    }

    It 'gives every script in the collector directory a valid name, except the helper' {
        $scripts = @(Get-ChildItem -LiteralPath $script:CollectorRoot -Filter '*.ps1' -File)
        $scripts.Count | Should -BeGreaterThan 1
        foreach ($file in $scripts) {
            if ($file.Name -ceq '_common.ps1') { Test-WfCollectorName -Name $file.BaseName | Should -BeFalse }
            else { Test-WfCollectorName -Name $file.BaseName | Should -BeTrue -Because $file.Name }
        }
    }

    It 'derives schema identifiers and an opaque machine id' {
        ConvertTo-WfIdentifier -Name 'bugcheck-history' | Should -BeExactly 'bugcheck_history'
        $a = Get-WfShortMachineId -Seed 'seed-one'
        $b = Get-WfShortMachineId -Seed 'seed-one'
        $c = Get-WfShortMachineId -Seed 'seed-two'
        $a['machine_id'] | Should -BeExactly $b['machine_id']
        $a['machine_id'] | Should -Not -Be $c['machine_id']
        $a['short'] | Should -Match '^[0-9a-f]{8}$'
        $a['machine_id'] | Should -Not -Match 'seed'
    }
}

Describe 'event query' {
    It 'builds a structured query with one Select per predicate and a fixed interval' {
        $end = [datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc)
        $text = Build-WfEventQueryXml -Channel 'Application' -Predicates @("Provider[@Name='Application Error'] and (EventID=1000)", '(EventID=1002)') -EndUtc $end -WindowMilliseconds 2592000000
        $xml = [xml]$text
        $xml.QueryList.Query.Path | Should -BeExactly 'Application'
        $selects = @($xml.QueryList.Query.Select)
        $selects.Count | Should -Be 2
        $selects[0].Path | Should -BeExactly 'Application'
        $fileTime = $end.ToFileTimeUtc()
        $fileTime | Should -Be ($end - [datetime]::new(1601, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).Ticks
        $selects[0].InnerText | Should -BeExactly "*[System[Provider[@Name='Application Error'] and (EventID=1000) and TimeCreated[timediff(@SystemTime, $fileTime) >= 0 and timediff(@SystemTime, $fileTime) <= 2592000000]]]"
        $selects[1].InnerText | Should -BeExactly "*[System[(EventID=1002) and TimeCreated[timediff(@SystemTime, $fileTime) >= 0 and timediff(@SystemTime, $fileTime) <= 2592000000]]]"
    }

    It 'writes CIM DATETIME text in UTC for the WQL filter' {
        $value = [datetime]::new(2026, 1, 30, 12, 0, 5, [System.DateTimeKind]::Utc).AddTicks(1234560)
        ConvertTo-WfDmtfDateTime -Value $value | Should -BeExactly '20260130120005.123456+000'
    }
}

Describe 'measurement status of one source' {
    BeforeAll {
        $script:WindowStart = [datetime]::new(2026, 2, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
        $script:Older = $script:WindowStart.AddDays(-30)
        $script:Newer = $script:WindowStart.AddDays(10)
    }

    It 'is observed when records were exported' {
        $r = Resolve-WfSourceStatus -RecordCount 3 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly 'observed'
        $r['Reason'] | Should -BeNullOrEmpty
        $r['CoveredStartUtc'] | Should -Be $script:WindowStart
    }

    It 'is observed_zero only when the oldest retained record is known' {
        $r = Resolve-WfSourceStatus -RecordCount 0 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly 'observed_zero'
        $r['CoveredStartUtc'] | Should -Be $script:WindowStart
    }

    It 'narrows the covered range when the source is younger than the window' {
        $r = Resolve-WfSourceStatus -RecordCount 0 -OldestRecordUtc $script:Newer -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly 'observed_zero'
        $r['CoveredStartUtc'] | Should -Be $script:Newer
    }

    It 'refuses a quiet window when the oldest retained record is unknown' {
        $r = Resolve-WfSourceStatus -RecordCount 0 -OldestRecordUtc $null -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly 'capture_failed'
        $r['Reason'] | Should -Match 'no proof'
        $r['CoveredStartUtc'] | Should -BeNullOrEmpty
    }

    It 'refuses a quiet window for a provider Microsoft does not document' {
        $r = Resolve-WfSourceStatus -RecordCount 0 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart -QuietClaimVerified $false
        $r['Status'] | Should -BeExactly 'capture_failed'
        $r['Reason'] | Should -Match 'verification step'
    }

    It 'still reports records from an undocumented provider as observed' {
        $r = Resolve-WfSourceStatus -RecordCount 1 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart -QuietClaimVerified $false
        $r['Status'] | Should -BeExactly 'observed'
    }

    It 'is capture_failed when the export hit its cap' {
        $r = Resolve-WfSourceStatus -RecordCount 5000 -Truncated $true -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart -TruncationDetail 'cap is 5000'
        $r['Status'] | Should -BeExactly 'capture_failed'
        $r['Reason'] | Should -Match 'cap is 5000'
    }

    It 'maps read failures to <Status>' -ForEach @(
        @{ Kind = 'access_denied'; Status = 'not_collected' }
        @{ Kind = 'preflight'; Status = 'not_collected' }
        @{ Kind = 'not_found'; Status = 'unsupported' }
        @{ Kind = 'timeout'; Status = 'capture_failed' }
        @{ Kind = 'incomplete'; Status = 'capture_failed' }
        @{ Kind = 'other'; Status = 'capture_failed' }
    ) {
        $r = Resolve-WfSourceStatus -ReadErrorKind $Kind -ReadErrorMessage 'the tool said no' -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly $Status
        $r['Reason'] | Should -Match 'the tool said no'
    }

    It 'never reports an unreadable source as observed_zero, whatever else is passed' {
        $r = Resolve-WfSourceStatus -ReadErrorKind 'access_denied' -ReadErrorMessage 'denied' -RecordCount 0 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -Not -Be 'observed_zero'
        $r['Status'] | Should -Not -Be 'observed'
    }

    It 'never reports a timed out read as observed, whatever it read' {
        $r = Resolve-WfSourceStatus -ReadErrorKind 'timeout' -ReadErrorMessage 'deadline' -RecordCount 40 -OldestRecordUtc $script:Older -WindowStartUtc $script:WindowStart
        $r['Status'] | Should -BeExactly 'capture_failed'
        $r['Reason'] | Should -Match 'timed out'
    }

    It 'keeps a partial export only for a capped source' {
        Test-WfKeepPartialExport -Status 'capture_failed' -Truncated $true -RecordCount 5 | Should -BeTrue
        Test-WfKeepPartialExport -Status 'capture_failed' -Truncated $true -RecordCount 0 | Should -BeFalse
        Test-WfKeepPartialExport -Status 'capture_failed' -Truncated $false -RecordCount 5 | Should -BeFalse
        Test-WfKeepPartialExport -Status 'not_collected' -Truncated $false -RecordCount 0 | Should -BeFalse
        Test-WfKeepPartialExport -Status 'observed_zero' -Truncated $false -RecordCount 0 | Should -BeTrue
    }
}

Describe 'bounded reads' {
    BeforeAll {
        function New-ListReader {
            param([object[]]$Items, [scriptblock]$Convert = { param($r) $r })
            return @{ ReadNext = (New-WfSyntheticPull -Items $Items -Stuck $false); Convert = $Convert; Release = $null; Dispose = { } }
        }
        function New-Element {
            param([int]$Id, [string]$Xml = '<Event/>')
            return [ordered]@{ record_id = $Id; time_created_utc = '2026-02-20T00:00:00.0000000Z'; xml = $Xml }
        }
    }

    It 'reads to the end of the stream within the deadline' {
        Reset-WfSynthetic
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1), (New-Element -Id 2))) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $result['Ok'] | Should -BeTrue
        $result['Count'] | Should -Be 2
        $accumulator.Rows.Count | Should -Be 2
    }

    It 'gives up at the deadline when the reader never returns a record' {
        Reset-WfSynthetic
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $reader = @{ ReadNext = (New-WfSyntheticPull -Items @() -Stuck $true); Convert = { param($r) $r }; Release = $null; Dispose = { } }
        $result = Invoke-WfBoundedEventRead -Reader $reader -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(5) -Accumulator $accumulator
        $result['Ok'] | Should -BeFalse
        $result['TimedOut'] | Should -BeTrue
        $result['ErrorKind'] | Should -BeExactly 'timeout'
        $accumulator.Rows.Count | Should -Be 0
    }

    It 'gives up when the deadline has already passed' {
        Reset-WfSynthetic
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1))) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(-1) -Accumulator $accumulator
        $result['ErrorKind'] | Should -BeExactly 'timeout'
        $accumulator.Rows.Count | Should -Be 0
    }

    It 'stops at a record whose conversion fails or that has no XML' {
        Reset-WfSynthetic
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1)) -Convert { param($r) throw 'ToXml failed' }) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $result['ErrorKind'] | Should -BeExactly 'incomplete'
        $result['ErrorMessage'] | Should -Match 'ToXml failed'
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1), (New-Element -Id 2 -Xml ''))) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $result['ErrorKind'] | Should -BeExactly 'incomplete'
        $result['ErrorMessage'] | Should -Match 'record 2 has no event XML'
        $accumulator.Rows.Count | Should -Be 1
    }

    It 'enforces the row cap and the exact byte budget of the file it will write' {
        Reset-WfSynthetic
        $accumulator = New-WfRowAccumulator -MaxRows 2 -MaxBytes 1048576
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1), (New-Element -Id 2), (New-Element -Id 3))) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $result['Ok'] | Should -BeTrue
        $accumulator.Truncated | Should -BeTrue
        $accumulator.Rows.Count | Should -Be 2
        $accumulator.Reason | Should -Match 'cap of 2 records'

        $one = ConvertTo-WfJson -Value (New-Element -Id 1)
        $budget = Get-WfJsonArrayBytes -LineCount 2 -LineBytes (2 * $one.Length)
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes $budget
        $result = Invoke-WfBoundedEventRead -Reader (New-ListReader -Items @((New-Element -Id 1), (New-Element -Id 2), (New-Element -Id 3))) -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $accumulator.Truncated | Should -BeTrue
        $accumulator.Rows.Count | Should -Be 2
        $accumulator.Reason | Should -Match 'exceed the cap of'
        $path = Join-Path $TestDrive 'budget.json'
        Write-WfJsonLinesFile -Path $path -Lines $accumulator.Lines.ToArray()
        (Get-Item -LiteralPath $path).Length | Should -Be $budget
        $empty = Join-Path $TestDrive 'empty.json'
        Write-WfJsonLinesFile -Path $empty -Lines @()
        (Get-Item -LiteralPath $empty).Length | Should -Be (Get-WfJsonArrayBytes -LineCount 0 -LineBytes 0)
    }

    It 'stops an unbounded producer at the caps and classifies producer failures' {
        Reset-WfSynthetic
        $deadline = $global:WfSynthetic.Now.AddSeconds(100)
        $accumulator = New-WfRowAccumulator -MaxRows 3 -MaxBytes 1048576
        $result = Invoke-WfStreamingRead -Producer { while ($true) { [ordered]@{ a = 1 } } } -Convert { param($r) $r } -Accumulator $accumulator -DeadlineUtc $deadline
        $result['Ok'] | Should -BeTrue
        $accumulator.Rows.Count | Should -Be 3
        $accumulator.Truncated | Should -BeTrue
        $accumulator = New-WfRowAccumulator -MaxRows 3 -MaxBytes 1048576
        $result = Invoke-WfStreamingRead -Producer { [ordered]@{ a = 1 }; throw 'synthetic:access_denied: no' } -Convert { param($r) $r } -Accumulator $accumulator -DeadlineUtc $deadline
        $result['Ok'] | Should -BeFalse
        $result['ErrorKind'] | Should -BeExactly 'access_denied'
        $result['Count'] | Should -Be 1
    }

    It 'stops a producer that keeps answering but runs past the deadline' {
        Reset-WfSynthetic
        $deadline = $global:WfSynthetic.Now.AddSeconds(30)
        $accumulator = New-WfRowAccumulator -MaxRows 1000 -MaxBytes 1048576
        $result = Invoke-WfStreamingRead -Producer { foreach ($i in 1..20) { $global:WfSynthetic.Ticks += 5; [ordered]@{ a = $i } } } -Convert { param($r) $r } -Accumulator $accumulator -DeadlineUtc $deadline
        $result['Ok'] | Should -BeFalse
        $result['ErrorKind'] | Should -BeExactly 'timeout'
        $result['ErrorMessage'] | Should -Match 'did not finish before the deadline'
        $result['Count'] | Should -BeLessThan 20
        $accumulator.Truncated | Should -BeFalse
    }
}

Describe 'summary line' {
    It 'derives ok, partial and failed from the source statuses' {
        Get-WfSummaryStatus -Statuses @('observed', 'observed_zero') | Should -BeExactly 'ok'
        Get-WfSummaryStatus -Statuses @('observed', 'capture_failed') | Should -BeExactly 'partial'
        Get-WfSummaryStatus -Statuses @('not_collected', 'unsupported') | Should -BeExactly 'failed'
        Get-WfSummaryStatus -Statuses @('not_collected') | Should -BeExactly 'failed'
    }

    It 'is one line with exactly the four seam keys in order' {
        $line = ConvertTo-WfSummaryLine -Collector 'bugcheck-history' -Status 'ok' -Bundle 'C:\ProgramData\wf\out\b 1' -Artifacts 3
        $line | Should -Not -Match "`n"
        $line | Should -BeExactly '{"collector":"bugcheck-history","status":"ok","bundle":"C:\\ProgramData\\wf\\out\\b 1","artifacts":3}'
        $parsed = $line | ConvertFrom-Json
        $parsed.bundle | Should -BeExactly 'C:\ProgramData\wf\out\b 1'
        $parsed.artifacts | Should -Be 3
    }
}

Describe 'bundle files' {
    It 'creates raw and logs and refuses a directory that already holds a bundle' {
        $root = Join-Path $TestDrive 'layout'
        New-WfBundleLayout -BundleRoot $root
        Test-Path -LiteralPath (Join-Path $root 'raw') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $root 'logs') | Should -BeTrue
        { New-WfBundleLayout -BundleRoot $root } | Should -Throw '*raw directory*'
        $second = Join-Path $TestDrive 'layout2'
        $null = New-Item -ItemType Directory -Path $second
        Set-Content -LiteralPath (Join-Path $second 'manifest.json') -Value '{}'
        { New-WfBundleLayout -BundleRoot $second } | Should -Throw '*manifest.json exists*'
    }

    It 'writes text as UTF-8 without a byte order mark' {
        $path = Join-Path $TestDrive 'plain.txt'
        Write-WfTextFile -Path $path -Text "caf$([char]0xE9)`n"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0] | Should -Be 0x63
        $bytes.Length | Should -Be 6
    }

    It 'writes a JSON array that stays an array for zero and for one element' {
        $empty = Join-Path $TestDrive 'empty.json'
        Write-WfJsonLinesFile -Path $empty -Lines @()
        [System.IO.File]::ReadAllText($empty) | Should -BeExactly "[]`n"
        $one = Join-Path $TestDrive 'one.json'
        Write-WfJsonLinesFile -Path $one -Lines @((ConvertTo-WfJson -Value ([ordered]@{ a = 1; b = @('x') })))
        [System.IO.File]::ReadAllText($one) | Should -BeExactly "[`n{`"a`":1,`"b`":[`"x`"]}`n]`n"
    }

    It 'lists every file under a source directory with its size, hash and role' {
        $root = Join-Path $TestDrive 'artifacts'
        $dir = Join-Path (Join-Path $root 'raw') 'src_a'
        $null = New-Item -ItemType Directory -Force -Path $dir
        Write-WfTextFile -Path (Join-Path $dir 'events.json') -Text "[]`n"
        Write-WfTextFile -Path (Join-Path $dir 'stray.bin') -Text 'left behind'
        $records = Get-WfArtifactRecords -BundleRoot $root -SourceId 'src_a' -Roles @{ 'events.json' = 'primary' }
        @($records).Count | Should -Be 2
        $events = @($records | Where-Object { $_['path'] -eq 'raw/src_a/events.json' })[0]
        $events['role'] | Should -BeExactly 'primary'
        $events['bytes'] | Should -Be 3
        $events['sha256'] | Should -BeExactly (Get-TestSha256 -Path (Join-Path $dir 'events.json'))
        $stray = @($records | Where-Object { $_['path'] -eq 'raw/src_a/stray.bin' })[0]
        $stray['role'] | Should -BeExactly 'other'
        $none = Get-WfArtifactRecords -BundleRoot $root -SourceId 'absent' -Roles @{}
        @($none).Count | Should -Be 0
    }

    It 'hashes a tool file and leaves the hash null when the file is missing' {
        $path = Join-Path $TestDrive 'tool.bin'
        Write-WfTextFile -Path $path -Text 'tool'
        (Get-WfToolRecord -Name 't' -Version '1.0.0' -Path $path)['sha256'] | Should -BeExactly (Get-TestSha256 -Path $path)
        (Get-WfToolRecord -Name 't' -Version $null -Path (Join-Path $TestDrive 'missing.bin'))['sha256'] | Should -BeNullOrEmpty
    }
}

Describe 'event record conversion' {
    BeforeAll {
        function New-FakeRecord {
            param([string]$SystemTime, [scriptblock]$Describe = { 'rendered message' })
            $record = [pscustomobject]@{
                RecordId = [int64]77; LogName = 'System'; ProviderName = 'Example-Provider'; Id = 41; Version = [byte]8
                Level = [byte]1; Task = 63; Opcode = [int16]0; Keywords = [int64]-9223372036854775806
                TimeCreated = [datetime]::new(2026, 2, 26, 6, 0, 0, [System.DateTimeKind]::Utc)
                MachineName = 'SYNTHETIC-PC'; UserId = [pscustomobject]@{ Value = 'S-1-5-18' }; ProcessId = 4; ThreadId = 8
                LevelDisplayName = 'Critical'; TaskDisplayName = $null
                Properties = @([pscustomobject]@{ Value = [uint32]159 }, [pscustomobject]@{ Value = [byte[]](1, 2) }, [pscustomobject]@{ Value = 'text' })
            }
            $xml = "<Event><System><TimeCreated SystemTime='$SystemTime'/></System></Event>"
            $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $xml }.GetNewClosure()
            $record | Add-Member -MemberType ScriptMethod -Name FormatDescription -Value $Describe
            return $record
        }
    }

    It 'takes the time from the event XML and keeps the data values as scalars' {
        $item = ConvertFrom-WfEventRecord -Record (New-FakeRecord -SystemTime '2026-02-26T06:00:00.123456789Z')
        $item['time_created_utc'] | Should -BeExactly '2026-02-26T06:00:00.1234567Z'
        $item['record_id'] | Should -Be 77
        $item['event_id'] | Should -Be 41
        $item['user_id'] | Should -BeExactly 'S-1-5-18'
        $item['keywords'] | Should -Be -9223372036854775806
        $item['message'] | Should -BeExactly 'rendered message'
        $item['properties'][0] | Should -Be 159
        $item['properties'][1] | Should -BeExactly '0102'
        $item['properties'][2] | Should -BeExactly 'text'
        $item['xml'] | Should -Match 'SystemTime'
    }

    It 'leaves the message null when the publisher metadata cannot render it' {
        $item = ConvertFrom-WfEventRecord -Record (New-FakeRecord -SystemTime '2026-02-26T06:00:00Z' -Describe { throw 'no metadata' })
        $item['message'] | Should -BeNullOrEmpty
        $item['time_created_utc'] | Should -BeExactly '2026-02-26T06:00:00Z'
    }

    It 'throws when the record has no XML, so the source can never be observed from it' {
        $record = New-FakeRecord -SystemTime '2026-02-26T06:00:00Z'
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { throw 'rendering failed' } -Force
        { ConvertFrom-WfEventRecord -Record $record } | Should -Throw '*rendering failed*'
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '' } -Force
        { ConvertFrom-WfEventRecord -Record $record } | Should -Throw '*no text*'
    }

    It 'falls back to TimeCreated when the XML has no usable SystemTime' {
        $item = ConvertFrom-WfEventRecord -Record (New-FakeRecord -SystemTime 'garbage')
        $item['time_created_utc'] | Should -BeExactly '2026-02-26T06:00:00.0000000Z'
    }

    It 'classifies read failures by exception type' {
        Get-WfEventReadErrorKind -Exception (New-Object System.UnauthorizedAccessException('no')) | Should -BeExactly 'access_denied'
        Get-WfEventReadErrorKind -Exception (New-Object System.Exception('outer', (New-Object System.UnauthorizedAccessException('inner')))) | Should -BeExactly 'access_denied'
        Get-WfEventReadErrorKind -Exception (New-Object System.InvalidOperationException('x')) | Should -BeExactly 'other'
    }
}

Describe 'collectors, end to end against the synthetic backend' {
    It 'case <Case> exits <ExitCode> with one summary line and a complete container' -ForEach (& {
            . (Join-Path (Split-Path -Parent $PSScriptRoot) '_common.ps1')
            . (Join-Path $PSScriptRoot 'SyntheticBackend.ps1')
            . (Join-Path $PSScriptRoot 'SyntheticScenarios.ps1')
            Get-WfSyntheticCases
        }) {
        Reset-WfSynthetic
        & $Setup
        $out = Join-Path $TestDrive ('case-' + $Case)
        $run = Invoke-TestCollector -Collector $Collector -OutputDirectory $out -Arguments $Arguments
        $run.ExitCode | Should -Be $ExitCode
        $run.Pipeline.Count | Should -Be 0 -Because 'nothing but the summary line may reach stdout'
        $run.Stdout.Count | Should -Be 1
        $summary = $run.Stdout[0] | ConvertFrom-Json
        @($summary.PSObject.Properties.Name) | Should -Be @('collector', 'status', 'bundle', 'artifacts')
        $summary.collector | Should -BeExactly $Collector
        $summary.bundle | Should -BeExactly $out
        $summary.status | Should -BeIn @('ok', 'partial', 'failed')
        if ($ExitCode -eq 0) { $summary.status | Should -BeIn @('ok', 'partial') } else { $summary.status | Should -BeExactly 'failed' }

        $run.Manifest | Should -Not -BeNullOrEmpty
        $run.Manifest.bundle_id | Should -Match '^[0-9]{8}T[0-9]{6}Z_[a-z0-9_]+_[a-z0-9]+$'
        $run.Manifest.checksum_algorithm | Should -BeExactly 'sha256'
        $listed = @{}
        foreach ($collector in $run.Manifest.collectors) {
            if ($collector.status -in @('observed', 'observed_zero')) { $collector.status_reason | Should -BeNullOrEmpty }
            else { $collector.status_reason | Should -Not -BeNullOrEmpty }
            foreach ($artifact in $collector.artifacts) {
                $file = Join-Path $out $artifact.path
                Test-Path -LiteralPath $file | Should -BeTrue
                (Get-Item -LiteralPath $file).Length | Should -Be $artifact.bytes
                Get-TestSha256 -Path $file | Should -BeExactly $artifact.sha256
                $listed[$artifact.path] = $true
            }
        }
        $listed.Count | Should -Be $summary.artifacts
        $onDisk = @(Get-ChildItem -LiteralPath (Join-Path $out 'raw') -File -Recurse | ForEach-Object { 'raw/' + ($_.FullName.Substring((Join-Path $out 'raw').Length).TrimStart('\', '/') -replace '\\', '/') })
        @($onDisk | Sort-Object) | Should -Be @($listed.Keys | Sort-Object)

        # A collector writes capture output only: no evidence, no verdict, no decoded tables.
        foreach ($name in @('evidence.jsonl', 'verdict.json', 'validation.json', 'decoded')) { Test-Path -LiteralPath (Join-Path $out $name) | Should -BeFalse -Because $name }
        (Get-Content -LiteralPath (Join-Path (Join-Path $out 'logs') 'summary.json') -Raw).Trim() | Should -BeExactly $run.Stdout[0]
    }

    It 'records a channel the account cannot read as not_collected and writes no event export' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -Readable $false -ErrorKind 'access_denied' -ErrorMessage 'Attempted to perform an unauthorized operation.'
        $out = Join-Path $TestDrive 'denied'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'not_collected'
        $source.status_reason | Should -Match 'unauthorized operation'
        $source.preflight.ok | Should -BeFalse
        $source.raw_time_range | Should -BeNullOrEmpty
        @($source.artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $out 'raw/system_whea_events/events.json') | Should -BeFalse
        $run.Manifest.capture.incomplete | Should -BeTrue
    }

    It 'records a channel that does not exist as unsupported' {
        Reset-WfSynthetic
        $out = Join-Path $TestDrive 'missing-channel'
        $run = Invoke-TestCollector -Collector 'application-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $run.Manifest.collectors[0].status | Should -BeExactly 'unsupported'
        $run.Manifest.collectors[0].status_reason | Should -Match 'no channel named Application'
    }

    It 'does not call an empty channel a quiet window' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo $null
        $out = Join-Path $TestDrive 'empty-channel'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $run.Manifest.collectors[0].status | Should -BeExactly 'capture_failed'
        $run.Manifest.collectors[0].status_reason | Should -Match 'no proof'
    }

    It 'bounds a quiet window by the oldest retained record and says so' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 9
        $out = Join-Path $TestDrive 'young-log'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'observed_zero'
        $oldest = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-9)
        Get-TestUtcText -Value $source.raw_time_range.start | Should -BeExactly $oldest
        Get-TestUtcText -Value $source.enabled.options.window_start_utc | Should -BeExactly $oldest
        Get-TestUtcText -Value $source.requested.options.window_start_utc | Should -Not -Be $oldest
        @($run.Manifest.notes | Where-Object { $_ -match 'only holds records from' }).Count | Should -Be 1
        @($run.Stderr | Where-Object { $_ -match 'only holds records from' }).Count | Should -Be 1
    }

    It 'marks a capped export capture_failed and keeps the newest records' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'WHEA-Logger' -Events @(
            (New-WfSyntheticEvent -RecordId 1 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 8),
            (New-WfSyntheticEvent -RecordId 2 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 6),
            (New-WfSyntheticEvent -RecordId 3 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 4),
            (New-WfSyntheticEvent -RecordId 4 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 2)
        )
        $out = Join-Path $TestDrive 'capped'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out -Arguments @{ MaxEvents = 2 }
        $run.ExitCode | Should -Be 1
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'cap of 2 records'
        $source.expectation.met | Should -BeFalse
        $source.enabled.options.records_exported | Should -Be 2
        $events = Get-Content -LiteralPath (Join-Path $out 'raw/system_whea_events/events.json') -Raw | ConvertFrom-Json
        @($events | ForEach-Object { $_.record_id }) | Should -Be @(3, 4)
    }

    It 'lists the binary export when wevtutil succeeds' {
        Reset-WfSynthetic
        $global:WfSynthetic.Evtx = 'placeholder'
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'with-evtx'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $source = $run.Manifest.collectors[0]
        $source.enabled.options.evtx_exported | Should -BeTrue
        @($source.artifacts | Where-Object { $_.path -eq 'raw/system_whea_events/events.evtx' -and $_.role -eq 'other' }).Count | Should -Be 1
    }

    It 'keeps the collector usable when the binary export fails' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'no-evtx'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        $run.Manifest.collectors[0].status | Should -BeExactly 'observed_zero'
        $run.Manifest.collectors[0].enabled.options.evtx_exported | Should -BeFalse
        @($run.Manifest.notes | Where-Object { $_ -match 'binary .evtx export was not produced' }).Count | Should -Be 1
    }

    It 'never writes into a directory that already holds a bundle' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'twice'
        $first = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $first.ExitCode | Should -Be 0
        $before = Get-TestSha256 -Path (Join-Path $out 'manifest.json')
        $second = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $second.ExitCode | Should -Be 1
        ($second.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        ($second.Stdout[0] | ConvertFrom-Json).artifacts | Should -Be 0
        @($second.Stderr | Where-Object { $_ -match 'already holds a bundle' }).Count | Should -Be 1
        Get-TestSha256 -Path (Join-Path $out 'manifest.json') | Should -BeExactly $before
    }

    It 'rejects a window or cap outside its range with a failed summary' {
        Reset-WfSynthetic
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory (Join-Path $TestDrive 'bad-window') -Arguments @{ WindowDays = 0 }
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        Test-Path -LiteralPath (Join-Path $TestDrive 'bad-window') | Should -BeFalse
    }

    It 'reports partial when the documented TDR source is quiet and the undocumented one is empty' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $run = Invoke-TestCollector -Collector 'tdr-events' -OutputDirectory (Join-Path $TestDrive 'tdr-quiet')
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $display = @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_display_events' })[0]
        $display.status | Should -BeExactly 'capture_failed'
        $display.required | Should -BeFalse
        $bugchecks = @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_bugcheck_events' })[0]
        $bugchecks.status | Should -BeExactly 'observed_zero'
    }

    It 'reports Display records as observed when they exist' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match "Provider[@Name=&apos;Display&apos;]" -Events @(
            (New-WfSyntheticEvent -RecordId 900 -Provider 'Display' -EventId 4101 -Level 3 -LevelDisplay 'Warning' -DaysAgo 2 -Properties @('exampledrv') -Message 'Display driver exampledrv stopped responding and has successfully recovered.')
        )
        $run = Invoke-TestCollector -Collector 'tdr-events' -OutputDirectory (Join-Path $TestDrive 'tdr-seen')
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_display_events' })[0].status | Should -BeExactly 'observed'
    }

    It 'records providers that are not registered on the machine' {
        Reset-WfSynthetic
        $global:WfSynthetic.Providers = @('Application Error')
        $global:WfSynthetic.Channels['Application'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'providers'
        $run = Invoke-TestCollector -Collector 'application-errors' -OutputDirectory $out
        $source = $run.Manifest.collectors[0]
        @($source.requested.providers).Count | Should -Be 4
        @($source.enabled.providers) | Should -Be @('Application Error')
        $state = Get-Content -LiteralPath (Join-Path $out 'raw/application_error_events/channel_state.json') -Raw | ConvertFrom-Json
        $state.providers_registered.'Application Hang' | Should -BeFalse
        $state.providers_registered.'Application Error' | Should -BeTrue
    }

    It 'maps WMI failures to not_collected and unsupported' {
        Reset-WfSynthetic
        $global:WfSynthetic.Cim['Win32_ReliabilityRecords'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
        $run = Invoke-TestCollector -Collector 'reliability-records' -OutputDirectory (Join-Path $TestDrive 'cim-denied')
        $run.ExitCode | Should -Be 1
        $records = @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_records' })[0]
        $records.status | Should -BeExactly 'not_collected'
        $records.status_reason | Should -Match 'Access denied'
        @($records.artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 0
        @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_stability_metrics' })[0].status | Should -BeExactly 'unsupported'
    }

    It 'exports only reliability records inside the window, oldest first' {
        Reset-WfSynthetic
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'reliability-records' })[0]
        & $case['Setup']
        $out = Join-Path $TestDrive 'reliability'
        $run = Invoke-TestCollector -Collector 'reliability-records' -OutputDirectory $out
        $rows = Get-Content -LiteralPath (Join-Path $out 'raw/reliability_records/records.json') -Raw | ConvertFrom-Json
        @($rows | ForEach-Object { $_.RecordNumber }) | Should -Be @(4800, 5120)
        $rows[0].InsertionStrings | Should -Be @('Example Application', '1.0.0.0')
        $entry = @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_records' })[0]
        $entry.expectation.detail | Should -Match '2 instances inside the window; coverage probe found 1 record'
        $entry.enabled.options.filter | Should -Match "^TimeGenerated >= '\d{14}\.\d{6}\+000' AND TimeGenerated <= '\d{14}\.\d{6}\+000'$"
        $entry.command | Should -Contain '-Filter'
        $entry.raw_time_range.start | Should -Not -BeNullOrEmpty
    }

    It 'treats an empty driver snapshot as a failed read, not as an observation' {
        Reset-WfSynthetic
        $global:WfSynthetic.Cim['Win32_PnPSignedDriver'] = @{ Rows = @() }
        $global:WfSynthetic.Cim['Win32_SystemDriver'] = @{ Rows = @([ordered]@{ Name = 'ACPI'; State = 'Running' }) }
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory (Join-Path $TestDrive 'no-drivers')
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        @($run.Manifest.collectors | Where-Object { $_.id -eq 'pnp_signed_drivers' })[0].status | Should -BeExactly 'capture_failed'
        @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_drivers' })[0].status | Should -BeExactly 'observed'
    }

    It 'fills machine.drivers from the driver snapshot and skips rows without a device name' {
        Reset-WfSynthetic
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'driver-inventory' })[0]
        & $case['Setup']
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory (Join-Path $TestDrive 'drivers')
        @($run.Manifest.machine.drivers).Count | Should -Be 2
        $run.Manifest.machine.drivers[0].name | Should -BeExactly 'Synthetic Display Adapter'
        $run.Manifest.machine.drivers[0].version | Should -BeExactly '1.2.3.4'
        $run.Manifest.machine.drivers[0].provider | Should -BeExactly 'Synthetic Graphics'
        $run.Manifest.machine.drivers[0].class | Should -BeExactly 'DISPLAY'
    }

    It 'still delivers the bundle when the machine or tool inventory fails' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $realMachine = ${function:Get-WfMachineInfo}
        $realTools = ${function:Get-WfToolInventory}
        try {
            function Get-WfMachineInfo { throw 'inventory broke' }
            function Get-WfToolInventory { throw 'tools broke' }
            $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory (Join-Path $TestDrive 'no-inventory')
        } finally {
            Set-Item -Path function:Get-WfMachineInfo -Value $realMachine
            Set-Item -Path function:Get-WfToolInventory -Value $realTools
        }
        $run.ExitCode | Should -Be 0
        $run.Manifest.collectors[0].status | Should -BeExactly 'observed_zero'
        $run.Manifest.machine.os.caption | Should -BeExactly 'not recorded'
        $run.Manifest.machine.cpu.logical_processors | Should -BeGreaterThan 0
        $run.Manifest.machine.machine_id | Should -Match '^[0-9a-f]{32}$'
        @($run.Manifest.tools).Count | Should -Be 0
        @($run.Manifest.notes | Where-Object { $_ -match 'inventory broke' }).Count | Should -Be 1
        @($run.Manifest.notes | Where-Object { $_ -match 'tools broke' }).Count | Should -Be 1
    }

    It 'records no time window for a snapshot collector' {
        Reset-WfSynthetic
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'driver-inventory' })[0]
        & $case['Setup']
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory (Join-Path $TestDrive 'snapshot')
        $run.Manifest.scenario.requested_duration_s | Should -Be 0
        @($run.Manifest.notes | Where-Object { $_ -match 'timediff' }).Count | Should -Be 0
        $source = $run.Manifest.collectors[0]
        $source.requested.options.window_days | Should -BeNullOrEmpty
        $source.raw_time_range.start | Should -Be $source.raw_time_range.end
    }

    It 'stops a source at a record without XML and leaves no export behind' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'EventID=41 or EventID=1001' -Events @((New-WfSyntheticEvent -RecordId 7 -Provider 'EventLog' -EventId 1001 -DaysAgo 1), [ordered]@{ record_id = 1; time_created_utc = '2026-02-20T00:00:00.0000000Z'; xml = $null })
        $out = Join-Path $TestDrive 'no-xml'
        $run = Invoke-TestCollector -Collector 'tdr-events' -OutputDirectory $out
        $bugchecks = @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_bugcheck_events' })[0]
        $bugchecks.status | Should -BeExactly 'capture_failed'
        $bugchecks.status_reason | Should -Match 'no event XML'
        Test-Path -LiteralPath (Join-Path $out 'raw/system_bugcheck_events/events.json') | Should -BeFalse
        $run.Stdout.Count | Should -Be 1
    }

    It 'stops a source whose records cannot be converted' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'WHEA-Logger' -Events @((New-WfSyntheticEvent -RecordId 7 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 1)) -ConvertThrows 'ToXml failed'
        $out = Join-Path $TestDrive 'convert-throws'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $run.Manifest.collectors[0].status | Should -BeExactly 'capture_failed'
        $run.Manifest.collectors[0].status_reason | Should -Match 'ToXml failed'
        Test-Path -LiteralPath (Join-Path $out 'raw/system_whea_events/events.json') | Should -BeFalse
    }

    It 'fails the source when the main read never finishes, and keeps no export' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'WHEA-Logger' -Stuck $true
        $out = Join-Path $TestDrive 'stuck-main'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 30 }
        $run.ExitCode | Should -Be 1
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'timed out'
        $source.preflight.ok | Should -BeTrue
        $source.enabled.options.timed_out | Should -BeTrue
        $source.requested.options.timeout_seconds | Should -Be 30
        Test-Path -LiteralPath (Join-Path $out 'raw/system_whea_events/events.json') | Should -BeFalse
        # The synthetic clock advanced by the deadline, not further: the collector did not wait longer than it was told.
        $global:WfSynthetic.Ticks | Should -BeLessThan 60
    }

    It 'does not claim a quiet window when the oldest record probe never finishes' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -Stuck 'preflight'
        $out = Join-Path $TestDrive 'stuck-probe'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 30 }
        $run.ExitCode | Should -Be 1
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'no proof'
        $state = Get-Content -LiteralPath (Join-Path $out 'raw/system_whea_events/channel_state.json') -Raw | ConvertFrom-Json
        $state.state.oldest_probe | Should -Match 'timed out|deadline'
        $state.state.oldest_record_time_utc | Should -BeNullOrEmpty
    }

    It 'still reports records as observed when only the probe fails, covering from the earliest record' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -Stuck 'preflight'
        Add-WfSyntheticQuery -Match 'WHEA-Logger' -Events @((New-WfSyntheticEvent -RecordId 7 -Provider 'Microsoft-Windows-WHEA-Logger' -EventId 17 -DaysAgo 3))
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory (Join-Path $TestDrive 'probe-fails-with-events') -Arguments @{ TimeoutSeconds = 30 }
        $run.ExitCode | Should -Be 0
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'observed'
        Get-TestUtcText -Value $source.raw_time_range.start | Should -BeExactly (ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-3))
    }

    It 'fixes the query interval before the read and reports it as the range end' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'interval'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $source = $run.Manifest.collectors[0]
        $endText = Get-TestUtcText -Value $source.requested.options.window_end_utc
        $startText = Get-TestUtcText -Value $source.requested.options.window_start_utc
        ((ConvertFrom-WfUtcString -Text $endText) - (ConvertFrom-WfUtcString -Text $startText)).TotalDays | Should -Be 30
        Get-TestUtcText -Value $source.raw_time_range.end | Should -BeExactly $endText
        Get-TestUtcText -Value $source.raw_time_range.start | Should -BeExactly $startText
        $query = [System.IO.File]::ReadAllText((Join-Path $out 'raw/system_whea_events/query.xml'))
        $query | Should -Match ('timediff\(@SystemTime, ' + (ConvertFrom-WfUtcString -Text $endText).ToFileTimeUtc() + '\) &gt;= 0')
        $query | Should -Not -Match 'timediff\(@SystemTime\)'
    }

    It 'never writes events.json larger than the cap and records the exact size' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['Application'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $big = ('caf' + [char]0xE9 + ' ') * 20000
        $events = @()
        for ($i = 1; $i -le 6; $i++) {
            $events += New-WfSyntheticEvent -RecordId (100 + $i) -Channel 'Application' -Provider 'Application Error' -EventId 1000 -DaysAgo (7 - $i) -Properties @('example.exe', $big) -Message ('crash ' + $i)
        }
        Add-WfSyntheticQuery -Match 'Application Error' -Events $events
        $out = Join-Path $TestDrive 'byte-cap'
        $cap = 1048576
        $run = Invoke-TestCollector -Collector 'application-errors' -OutputDirectory $out -Arguments @{ MaxArtifactBytes = $cap }
        $run.ExitCode | Should -Be 1
        $source = $run.Manifest.collectors[0]
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'exceed the cap of 1048576 bytes'
        $file = Join-Path $out 'raw/application_error_events/events.json'
        Test-Path -LiteralPath $file | Should -BeTrue
        $size = (Get-Item -LiteralPath $file).Length
        $size | Should -BeLessOrEqual $cap
        $written = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        # One more record (the next older one) would not have fit, and what was written is the newest records, oldest first.
        $written.Count | Should -BeGreaterThan 1
        $written.Count | Should -BeLessThan 6
        $oneMore = (ConvertTo-WfJson -Value $events[6 - $written.Count - 1]).Length
        ($size + 2 + $oneMore) | Should -BeGreaterThan $cap
        @($written | ForEach-Object { $_.record_id }) | Should -Be @((100 + 6 - $written.Count + 1)..106)
        [System.IO.File]::ReadAllText($file) | Should -Match '^[\x20-\x7e\n]+$'
        $artifact = @($source.artifacts | Where-Object { $_.path -eq 'raw/application_error_events/events.json' })[0]
        $artifact.bytes | Should -Be $size
        @($source.artifacts).Count | Should -Be 3
    }

    It 'leaves no primary export for a failed source that was not capped' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'display-empty'
        $run = Invoke-TestCollector -Collector 'tdr-events' -OutputDirectory $out
        $display = @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_display_events' })[0]
        $display.status | Should -BeExactly 'capture_failed'
        Test-Path -LiteralPath (Join-Path $out 'raw/system_display_events/events.json') | Should -BeFalse
        @($display.artifacts | ForEach-Object { $_.role }) | Should -Not -Contain 'primary'
        $display.enabled.options.records_exported | Should -Be 0
        $global:WfSynthetic.Cim['Win32_PnPSignedDriver'] = @{ Rows = @() }
        $global:WfSynthetic.Cim['Win32_SystemDriver'] = @{ Rows = @([ordered]@{ Name = 'ACPI'; State = 'Running' }) }
        $out2 = Join-Path $TestDrive 'pnp-empty'
        $run2 = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory $out2
        Test-Path -LiteralPath (Join-Path $out2 'raw/pnp_signed_drivers/records.json') | Should -BeFalse
        @(@($run2.Manifest.collectors | Where-Object { $_.id -eq 'pnp_signed_drivers' })[0].artifacts).Count | Should -Be 1
    }

    It 'fails closed when a WMI provider does not answer or never stops' {
        Reset-WfSynthetic
        $global:WfSynthetic.Cim['Win32_ReliabilityRecords'] = @{ Rows = @(); Stuck = $true }
        $global:WfSynthetic.Cim['Win32_ReliabilityStabilityMetrics'] = @{ Rows = @([ordered]@{ SystemStabilityIndex = 5.0; TimeGenerated = (ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-1)) }); Infinite = $true }
        $out = Join-Path $TestDrive 'wmi-stuck'
        $run = Invoke-TestCollector -Collector 'reliability-records' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 100; MaxEvents = 50 }
        $run.ExitCode | Should -Be 1
        $records = @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_records' })[0]
        $records.status | Should -BeExactly 'capture_failed'
        $records.status_reason | Should -Match 'timed out'
        Test-Path -LiteralPath (Join-Path $out 'raw/reliability_records/records.json') | Should -BeFalse
        $metrics = @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_stability_metrics' })[0]
        $metrics.status | Should -BeExactly 'capture_failed'
        $metrics.status_reason | Should -Match 'cap of 50 records'
        $metrics.enabled.options.records_exported | Should -Be 50
        $rows = Get-Content -LiteralPath (Join-Path $out 'raw/reliability_stability_metrics/records.json') -Raw | ConvertFrom-Json
        @($rows).Count | Should -Be 50
        $global:WfSynthetic.Ticks | Should -BeLessThan 400
    }

    It 'fails closed when a WMI provider keeps answering but the enumeration outlasts the deadline' {
        Reset-WfSynthetic
        $rows = @()
        for ($i = 1; $i -le 10; $i++) {
            $rows += [ordered]@{ ProductName = 'Synthetic'; SourceName = 'Application Error'; EventIdentifier = 1000; Message = ('slow ' + $i); TimeGenerated = (ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-1 * $i)) }
        }
        $global:WfSynthetic.Cim['Win32_ReliabilityRecords'] = @{ Rows = $rows; SecondsPerRow = 10 }
        $global:WfSynthetic.Cim['Win32_ReliabilityStabilityMetrics'] = @{ Rows = @([ordered]@{ SystemStabilityIndex = 5.0; TimeGenerated = (ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-1)) }) }
        $out = Join-Path $TestDrive 'wmi-slow'
        $run = Invoke-TestCollector -Collector 'reliability-records' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 30 }
        $records = @($run.Manifest.collectors | Where-Object { $_.id -eq 'reliability_records' })[0]
        $records.status | Should -BeExactly 'capture_failed'
        $records.status_reason | Should -Match 'timed out'
        $records.expectation.met | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $out 'raw/reliability_records/records.json') | Should -BeFalse
        @($records.artifacts | ForEach-Object { $_.role }) | Should -Not -Contain 'primary'
    }

    It 'requests only the documented properties and gets nulls for the rest' {
        Reset-WfSynthetic
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'driver-inventory' })[0]
        & $case['Setup']
        $out = Join-Path $TestDrive 'properties'
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory $out
        $rows = Get-Content -LiteralPath (Join-Path $out 'raw/system_drivers/records.json') -Raw | ConvertFrom-Json
        @($rows[0].PSObject.Properties.Name) | Should -Be @('Name', 'DisplayName', 'Description', 'PathName', 'ServiceType', 'StartMode', 'State', 'Started', 'Status', 'ErrorControl', 'ExitCode', 'AcceptStop', 'TagId')
        $entry = @($run.Manifest.collectors | Where-Object { $_.id -eq 'system_drivers' })[0]
        $entry.command | Should -Contain '-OperationTimeoutSec'
        $entry.command | Should -Contain '-Property'
        @($entry.requested.options.properties).Count | Should -Be 13
    }

    It 'says in the manifest when machine.drivers was cut at its limit' {
        Reset-WfSynthetic
        $rows = @()
        for ($i = 1; $i -le 2003; $i++) {
            $rows += [ordered]@{ DeviceID = ('SYN\DEV' + $i); DeviceName = ('Synthetic device ' + $i); DeviceClass = 'SYSTEM'; DriverProviderName = 'Synthetic'; DriverVersion = '1.0.0.' + $i }
        }
        $global:WfSynthetic.Cim['Win32_PnPSignedDriver'] = @{ Rows = $rows }
        $global:WfSynthetic.Cim['Win32_SystemDriver'] = @{ Rows = @([ordered]@{ Name = 'ACPI'; State = 'Running' }) }
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory (Join-Path $TestDrive 'many-drivers') -Arguments @{ MaxEvents = 5000; TimeoutSeconds = 3600 }
        $run.ExitCode | Should -Be 0
        @($run.Manifest.machine.drivers).Count | Should -Be 2000
        @($run.Manifest.notes | Where-Object { $_ -match 'machine.drivers lists the first 2000 named drivers of 2003 from source pnp_signed_drivers; 3 were left out' }).Count | Should -Be 1
        @($run.Manifest.collectors | Where-Object { $_.id -eq 'pnp_signed_drivers' })[0].enabled.options.records_exported | Should -Be 2003
    }

    It 'writes the failed summary and log under logs when the run fails after the layout exists' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $realAccount = ${function:Get-WfAccountInfo}
        $out = Join-Path $TestDrive 'late-failure'
        try {
            function Get-WfAccountInfo { throw 'identity broke' }
            $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        } finally {
            Set-Item -Path function:Get-WfAccountInfo -Value $realAccount
        }
        $run.ExitCode | Should -Be 1
        $run.Manifest | Should -BeNullOrEmpty
        (Get-Content -LiteralPath (Join-Path $out 'logs/summary.json') -Raw).Trim() | Should -BeExactly $run.Stdout[0]
        $log = [System.IO.File]::ReadAllText((Join-Path $out 'logs/collector.log'))
        $log | Should -Match 'identity broke'
        $log | Should -Match 'no manifest was written'
        # A refused directory gets nothing at all.
        $refused = Join-Path $TestDrive 'refused'
        $null = New-Item -ItemType Directory -Path $refused
        Set-Content -LiteralPath (Join-Path $refused 'manifest.json') -Value '{}'
        $run2 = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $refused
        $run2.ExitCode | Should -Be 1
        Test-Path -LiteralPath (Join-Path $refused 'logs') | Should -BeFalse
    }
}

Describe 'pseudonyms for network names and addresses' {
    BeforeAll {
        $script:Salt = 'test-salt'
    }

    It 'maps both printed forms of an address to one pseudonym and leaves GUIDs alone' {
        $text = 'a 02:AA:bb:CC:dd:01 and 02-aa-BB-cc-DD-01 but not 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c or 0123456789AB'
        $r = Protect-WfMacAddresses -Text $text -Salt $script:Salt
        $r['Count'] | Should -Be 2
        $expected = ConvertTo-WfPseudonym -Kind 'mac' -Value '02:aa:bb:cc:dd:01' -Salt $script:Salt
        $r['Text'] | Should -BeExactly ('a ' + $expected + ' and ' + $expected + ' but not 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c or 0123456789AB')
        $expected | Should -Match '^mac-[0-9a-f]{12}$'
    }

    It 'finds the network name by structure in a scan, whatever the labels say' {
        $text = "Nom : WLAN`r`nIl y a 2 reseaux visibles.`r`n`r`nSSID 1 : Chez Moi`r`n    Type : Infrastructure`r`n    Chiffrement : CCMP`r`n    BSSID 1 : 02:aa:bb:cc:dd:01`r`n         Signal : 80%`r`n`r`nSSID 2 : `r`n    Type : Infrastructure`r`n    BSSID 1 : 02:aa:bb:cc:dd:02`r`n"
        $r = Protect-WfNetshText -Text $text -Mode 'networks' -Salt $script:Salt -KnownSsids $null
        $r.Text | Should -Not -Match 'Chez Moi'
        $r.Text | Should -Match "`nSSID 1 : ssid-[0-9a-f]{12}`n"
        $r.Text | Should -Match "`nSSID 2 : `n"
        $r.Text | Should -Match 'Chiffrement : CCMP'
        $r.Text | Should -Match 'Nom : WLAN'
        $r.Text | Should -Not -Match '02:aa:bb'
        $r.MacCount | Should -Be 2
        $r.SsidCount | Should -Be 1
        @($r.LearnedSsids) | Should -Be @('Chez Moi')
    }

    It 'replaces the SSID line and its repeat on the profile line of an interface listing' {
        $text = "    SSID                   : Home Net`r`n    BSSID                  : 02:aa:bb:cc:dd:01`r`n    Channel                : 6`r`n    Profile                : Home Net`r`n"
        $r = Protect-WfNetshText -Text $text -Mode 'interfaces' -Salt $script:Salt -KnownSsids $null
        $pseudonym = ConvertTo-WfPseudonym -Kind 'ssid' -Value 'Home Net' -Salt $script:Salt
        $r.Text | Should -Not -Match 'Home Net'
        $r.Text | Should -Match ('SSID\s+: ' + $pseudonym)
        $r.Text | Should -Match ('Profile\s+: ' + $pseudonym)
        $r.Text | Should -Match 'Channel\s+: 6'
        $r.SsidCount | Should -Be 2
    }

    It 'learns every valued line of a profile listing as a name and leaves the listing readable' {
        $text = "Profiles on interface Wi-Fi:`r`n`r`nUser profiles`r`n-------------`r`n    All User Profile     : Alpha`r`n    All User Profile     : Beta Guest`r`n"
        $r = Protect-WfNetshText -Text $text -Mode 'profiles' -Salt $script:Salt -KnownSsids $null
        $r.Text | Should -Match 'Alpha'
        $r.Text | Should -Match 'Profiles on interface Wi-Fi:'
        @($r.LearnedSsids) | Should -Be @('Alpha', 'Beta Guest')
        @($r.Profiles).Count | Should -Be 2
    }

    It 'replaces known names in plain and HTML encoded form in generic text and nothing else' {
        $known = New-Object 'System.Collections.Generic.List[string]'
        $known.Add('Tom & Jerry')
        $known.Add('Home')
        $text = '<td>Tom &amp; Jerry</td><td>Tom & Jerry</td><td>Homely Home</td><td>02-AA-BB-CC-DD-01</td>'
        $r = Protect-WfNetshText -Text $text -Mode 'generic' -Salt $script:Salt -KnownSsids $known
        $tom = ConvertTo-WfPseudonym -Kind 'ssid' -Value 'Tom & Jerry' -Salt $script:Salt
        $homeName = ConvertTo-WfPseudonym -Kind 'ssid' -Value 'Home' -Salt $script:Salt
        $r.Text | Should -BeExactly ('<td>' + $tom + '</td><td>' + $tom + '</td><td>Homely ' + $homeName + '</td><td>' + (ConvertTo-WfPseudonym -Kind 'mac' -Value '02:aa:bb:cc:dd:01' -Salt $script:Salt) + '</td>')
        $r.SsidCount | Should -Be 3
        $r.MacCount | Should -Be 1
    }

    It 'counts records by a language independent shape' {
        Measure-WfNetshRecords -Text "GUID : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c`nGUID : 6f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c" -Mode 'interfaces' | Should -Be 2
        Measure-WfNetshRecords -Text "BSSID 1 : mac-000000000001`nBSSID 2 : mac-000000000002`nBSSID 1 : mac-000000000001" -Mode 'networks' | Should -Be 2
        Measure-WfNetshRecords -Text "x : ssid-000000000001`ny : ssid-000000000002" -Mode 'profiles' | Should -Be 2
        Measure-WfNetshRecords -Text "Interface name: Wi-Fi`n    Driver : x`nInterface name: Wi-Fi 2`n    Driver : y`nno colon here" -Mode 'drivers' | Should -Be 2
        Measure-WfNetshRecords -Text 'There is no wireless interface on the system.' -Mode 'interfaces' | Should -Be 0
    }

    It 'tokenises every labelled line with its line number, indentation and block' {
        $fields = ConvertTo-WfNetshFields -Text "Interface name : Wi-Fi`nThere are 1 networks.`n`nSSID 1 : ssid-000000000001`n    BSSID 1 : mac-000000000001`n         Signal : 80%`n"
        @($fields).Count | Should -Be 4
        $fields[0]['line'] | Should -Be 1
        $fields[0]['block'] | Should -Be 0
        $fields[1]['line'] | Should -Be 4
        $fields[1]['block'] | Should -Be 1
        $fields[1]['label'] | Should -BeExactly 'SSID 1'
        $fields[2]['indent'] | Should -Be 4
        $fields[3]['indent'] | Should -Be 9
        $fields[3]['value'] | Should -BeExactly '80%'
    }
}

Describe 'rf-survey sources against the synthetic backend' {
    BeforeAll {
        function Start-RfCase {
            param([string]$Case = 'rf-survey')
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $Case })[0]
            & $selected['Setup']
        }
        function Get-RfSource {
            param($Run, [string]$Id)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
        }
    }

    It 'writes no neighbour name, unseen name, address or peer name in clear anywhere in the bundle' {
        Start-RfCase
        $out = Join-Path $TestDrive 'privacy'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        $files = @(Get-ChildItem -LiteralPath $out -File -Recurse)
        $files.Count | Should -BeGreaterThan 25
        # Neighbours' names, a name that only the report and an event carry, every address, and the Bluetooth peers.
        $secrets = @('Neighbour-A', 'Neighbour-F', 'Unseen-Guest', '02:aa:bb:cc:dd:01', '02-AA-BB-CC-DD-01', '02:aa:bb:cc:dd:99', '02-AA-BB-CC-DD-99', '02:11:22:33:44:55',
            'Synthetic Earbuds', 'Synthetic Game Controller', 'Synthetic BLE Mouse', 'F0F1F2000001', 'F0F1F2000002', 'F0F1F2000003')
        foreach ($file in $files) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            foreach ($secret in $secrets) {
                $text.Contains($secret) | Should -BeFalse -Because ($file.Name + ' must not carry ' + $secret)
            }
        }
        # The owner's saved profile names are the one readable exception, and only inside the profiles source.
        foreach ($file in $files) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            if ($text.Contains('Harbor-Home') -or $text.Contains('Coffee-Guest')) { $file.FullName | Should -Match 'raw[\\/]wlan_profiles[\\/]' }
        }
        $profiles = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_profiles/result.json') -Raw | ConvertFrom-Json
        @($profiles.profiles | ForEach-Object { $_.name }) | Should -Be @('Harbor-Home', 'Coffee-Guest')
        $pseudonym = ConvertTo-WfPseudonym -Kind 'ssid' -Value 'Harbor-Home' -Salt $global:WfSynthetic.Salt
        $profiles.profiles[0].pseudonym | Should -BeExactly $pseudonym
        # The same name maps to the same pseudonym in the scan, which is how an owner selection is matched.
        [System.IO.File]::ReadAllText((Join-Path $out 'raw/wlan_networks/output.txt')) | Should -Match $pseudonym
        # Events keep their System section only, and the binary export is not attempted.
        $events = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_autoconfig_events/events.json') -Raw | ConvertFrom-Json
        @($events).Count | Should -Be 2
        $events[0].message | Should -BeNullOrEmpty
        @($events[0].properties) | Should -Be @($null, $null, $null, 7, $null)
        $events[0].xml | Should -Match '<EventData/>'
        $events[0].xml | Should -Match '<EventRecordID>790</EventRecordID>'
        $events[0].xml | Should -Not -Match 'Unseen|Harbor|02:aa'
        $source = Get-RfSource -Run $run -Id 'wlan_autoconfig_events'
        $source.enabled.options.evtx_exported | Should -BeFalse
        $source.enabled.options.evtx_message | Should -Match 'System section'
        # The report is summarised, never copied.
        @(Get-ChildItem -LiteralPath (Join-Path $out 'raw/wlan_report') -File | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('report-summary.json', 'result.json', 'source.json')
        $summary = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_report/report-summary.json') -Raw | ConvertFrom-Json
        $summary.content_kept | Should -BeFalse
        $summary.address_tokens | Should -Be 3
        $summary.sha256 | Should -Match '^[0-9a-f]{64}$'
        @($run.Manifest.notes | Where-Object { $_ -match 'pseudonyms' }).Count | Should -Be 1
    }

    It 'pseudonymises Bluetooth peer nodes but not the radio, and counts them' {
        Start-RfCase 'rf-survey-clean'
        $out = Join-Path $TestDrive 'bt-peers'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $devices = Get-Content -LiteralPath (Join-Path $out 'raw/bluetooth_devices/devices.json') -Raw | ConvertFrom-Json
        $peers = @($devices | Where-Object { $_.instance_id -like 'BTHENUM\*' -or $_.instance_id -like 'BTHLE\*' })
        $peers.Count | Should -Be 3
        foreach ($peer in $peers) {
            $peer.name | Should -Match '^name-[0-9a-f]{12}$'
            $peer.instance_id | Should -Match 'mac-[0-9a-f]{12}'
            $peer.instance_id | Should -Not -Match 'F0F1F2'
            @($peer.hardware_ids)[0] | Should -Match 'mac-[0-9a-f]{12}'
        }
        $expected = ConvertTo-WfPseudonym -Kind 'mac' -Value 'f0:f1:f2:00:00:01' -Salt $global:WfSynthetic.Salt
        $peers[0].instance_id | Should -Match ([regex]::Escape($expected))
        $radio = @($devices | Where-Object { $_.instance_id -eq 'USB\VID_FFF5&PID_0005\5&1e2f3a4b&0&14' })[0]
        $radio.name | Should -BeExactly 'Synthetic Wireless Bluetooth'
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/bluetooth_devices/result.json') -Raw | ConvertFrom-Json
        $result.peer_nodes_pseudonymised | Should -Be 5
        # A peer's GATT service and HID nodes carry its address too, and the chain stays consistent once pseudonymised.
        foreach ($source in @('bluetooth_devices', 'usb_device_tree')) {
            $rows = Get-Content -LiteralPath (Join-Path $out ('raw/' + $source + '/devices.json')) -Raw | ConvertFrom-Json
            $text = [System.IO.File]::ReadAllText((Join-Path $out ('raw/' + $source + '/devices.json')))
            $text | Should -Not -Match 'F0F1F2000003|Synthetic BLE Mouse'
            $gatt = @($rows | Where-Object { $_.instance_id -like 'BTHLEDEVICE\*' })[0]
            $blePeer = @($rows | Where-Object { $_.instance_id -like 'BTHLE\*' -and $_.instance_id -eq $gatt.parent_instance_id })
            $blePeer.Count | Should -Be 1
            $gatt.bus_reported_description | Should -Match '^name-[0-9a-f]{12}$'
        }
        $tree = Get-Content -LiteralPath (Join-Path $out 'raw/usb_device_tree/devices.json') -Raw | ConvertFrom-Json
        $mouse = @($tree | Where-Object { $_.instance_id -like 'HID\{00001812*' })[0]
        $mouse.parent_instance_id | Should -BeExactly (@($tree | Where-Object { $_.instance_id -like 'BTHLEDEVICE\*' })[0].instance_id)
        $mouse.name | Should -Match '^name-[0-9a-f]{12}$'
        # A GUID keeps its last group: only bare twelve digit runs are addresses.
        Protect-WfBluetoothAddresses -Text '{a1b2c3d4-0001-4000-8000-000000000001} and DEV_F0F1F2000001' -Salt 's' | Should -Match '^\{a1b2c3d4-0001-4000-8000-000000000001\} and DEV_mac-[0-9a-f]{12}$'
    }

    It 'pseudonymises a Bluetooth HID node whose parent could not be read' {
        Start-RfCase 'rf-survey-clean'
        foreach ($device in @($global:WfSynthetic.Pnp['Devices'] | Where-Object { $_['instance_id'] -like 'HID\{00001812*' -or $_['instance_id'] -like 'BTHHFENUM\*' })) {
            $device['PropertyError'] = 'Access is denied.'
        }
        $out = Join-Path $TestDrive 'bt-hid-unread'
        $null = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $path = Join-Path $out 'raw/usb_device_tree/devices.json'
        [System.IO.File]::ReadAllText($path) | Should -Not -Match 'F0F1F2000003|Synthetic BLE Mouse|Synthetic Earbuds'
        $row = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json | Where-Object { $_.instance_id -like 'HID\{00001812*' })[0]
        $row.property_error | Should -BeExactly 'Access is denied.'
        $row.parent_instance_id | Should -BeNullOrEmpty
        $row.instance_id | Should -Match 'mac-[0-9a-f]{12}'
        $row.name | Should -Match '^name-[0-9a-f]{12}$'
        foreach ($source in @('bluetooth_devices', 'usb_device_tree')) {
            $file = Join-Path $out ('raw/' + $source + '/devices.json')
            [System.IO.File]::ReadAllText($file) | Should -Not -Match 'Synthetic Earbuds|F0F1F2'
            $hands = @(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json | Where-Object { $_.instance_id -like 'BTHHFENUM\*' })[0]
            $hands.property_error | Should -BeExactly 'Access is denied.'
            $hands.name | Should -Match '^name-[0-9a-f]{12}$'
        }
        $radio = @(Get-Content -LiteralPath (Join-Path $out 'raw/bluetooth_devices/devices.json') -Raw | ConvertFrom-Json | Where-Object { $_.instance_id -like 'BTH\MS_BTHLE*' })[0]
        $radio.name | Should -BeExactly 'Microsoft Bluetooth LE Enumerator'
    }

    It 'finds the connected network name by structure when the SSID label is translated' {
        $text = "    GUID                   : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c`r`n    Adresse physique       : 02:11:22:33:44:55`r`n    Etat                   : connecte`r`n    Nom du reseau          : Chez Moi`r`n    BSSID                  : 02:aa:bb:cc:dd:01`r`n    Canal                  : 6`r`n    Profil                 : Chez Moi`r`n"
        $r = Protect-WfNetshText -Text $text -Mode 'interfaces' -Salt 'test-salt' -KnownSsids $null
        $r.Text | Should -Not -Match 'Chez Moi'
        $r.Text | Should -Match 'Nom du reseau\s+: ssid-[0-9a-f]{12}'
        $r.Text | Should -Match 'Profil\s+: ssid-[0-9a-f]{12}'
        $r.Text | Should -Match 'GUID\s+: 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c'
        $r.SsidCount | Should -Be 2
        Start-RfCase 'rf-survey-connected'
        $out = Join-Path $TestDrive 'connected'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $listing = [System.IO.File]::ReadAllText((Join-Path $out 'raw/wlan_interfaces/output.txt'))
        $listing | Should -Not -Match 'Harbor-Home|02:aa:bb|02:11:22'
        $listing | Should -Match 'SSID\s+: ssid-[0-9a-f]{12}'
        $listing | Should -Match 'Profile\s+: ssid-[0-9a-f]{12}'
        $listing | Should -Match 'Channel\s+: 1'
        (Get-RfSource -Run $run -Id 'wlan_interfaces').enabled.options.network_names_replaced | Should -Be 2
    }

    It 'keeps saved profiles readable with their pseudonyms and counts them as records' {
        $text = "Profiles on interface Wi-Fi:`r`n`r`nUser profiles`r`n-------------`r`n    All User Profile     : Alpha`r`n    All User Profile     : Beta Guest`r`n"
        $r = Protect-WfNetshText -Text $text -Mode 'profiles' -Salt 'test-salt' -KnownSsids $null
        $r.Text | Should -Match 'Alpha'
        $r.Text | Should -Match 'Beta Guest'
        $r.SsidCount | Should -Be 0
        @($r.Profiles | ForEach-Object { $_['name'] }) | Should -Be @('Alpha', 'Beta Guest')
        $r.Profiles[1]['pseudonym'] | Should -BeExactly (ConvertTo-WfPseudonym -Kind 'ssid' -Value 'Beta Guest' -Salt 'test-salt')
        @($r.LearnedSsids) | Should -Be @('Alpha', 'Beta Guest')
        Start-RfCase
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'profiles-count')
        (Get-RfSource -Run $run -Id 'wlan_profiles').status | Should -BeExactly 'observed'
        (Get-RfSource -Run $run -Id 'wlan_profiles').enabled.options.records | Should -Be 2
    }

    It 'stops a real child process at the cap and keeps only a bounded diagnostic' {
        $pwsh = (Get-Process -Id $PID).Path
        $arguments = '-NoProfile -NonInteractive -Command "1..200 | ForEach-Object { ''x'' * 4000 }"'
        $run = & $script:RealInvokeProcess -FilePath $pwsh -Arguments $arguments -TimeoutSeconds 60 -MaxBytes 65536
        $run['Started'] | Should -BeTrue
        $run['Oversized'] | Should -BeTrue
        $run['TimedOut'] | Should -BeFalse
        $run['ExitCode'] | Should -BeNullOrEmpty
        $run['StdOut'] | Should -BeExactly ''
        $run['StdOutBytes'] | Should -BeGreaterThan 65536
        $run['StdOutBytes'] | Should -BeLessThan 200000 -Because 'the child was stopped soon after the cap, not drained to the end'
        $run['Diagnostic'].Length | Should -BeLessOrEqual 4200
        $run['Error'] | Should -Match 'more than the cap of 65536 bytes'
        $small = & $script:RealInvokeProcess -FilePath $pwsh -Arguments '-NoProfile -NonInteractive -Command "Write-Output hello; [Console]::Error.WriteLine(''warn''); exit 3"' -TimeoutSeconds 60 -MaxBytes 65536
        $small['Oversized'] | Should -BeFalse
        $small['ExitCode'] | Should -Be 3
        $small['StdOut'].Trim() | Should -BeExactly 'hello'
        $small['StdErr'].Trim() | Should -BeExactly 'warn'
        Start-RfCase
        $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 0; StdOut = ('Interface name: Wi-Fi' + "`n" + ('    Driver : ' + ('y' * 2000) + "`n") * 600); StdErr = '' }
        $out = Join-Path $TestDrive 'oversized'
        $run2 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out -Arguments @{ MaxArtifactBytes = 1048576 }
        $drivers = Get-RfSource -Run $run2 -Id 'wlan_drivers'
        $drivers.status | Should -BeExactly 'capture_failed'
        $drivers.status_reason | Should -Match 'more than the cap of 1048576 bytes'
        Test-Path -LiteralPath (Join-Path $out 'raw/wlan_drivers/output.txt') | Should -BeFalse
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_drivers/result.json') -Raw | ConvertFrom-Json
        $result.diagnostic.Length | Should -BeLessOrEqual 4200
        $result.stdout_bytes | Should -Be 0
    }

    It 'pseudonymises the head of an oversized scan kept as a diagnostic' {
        Start-RfCase
        $networks = (Get-WfSyntheticNetshText -Name 'networks-congested-en') + (('    Other : ' + ('z' * 2000) + "`n") * 600)
        $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = $networks; StdErr = '' }
        $out = Join-Path $TestDrive 'oversized-networks'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out -Arguments @{ MaxArtifactBytes = 1048576 }
        (Get-RfSource -Run $run -Id 'wlan_networks').status | Should -BeExactly 'capture_failed'
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_networks/result.json') -Raw | ConvertFrom-Json
        $result.diagnostic | Should -Match 'ssid-[0-9a-f]{12}'
        foreach ($file in @(Get-ChildItem -LiteralPath $out -File -Recurse)) {
            [System.IO.File]::ReadAllText($file.FullName) | Should -Not -Match 'Neighbour-|02:aa:bb' -Because $file.Name
        }
    }

    It 'records what netsh printed and how it exited' {
        Start-RfCase
        $out = Join-Path $TestDrive 'netsh-ok'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $networks = Get-RfSource -Run $run -Id 'wlan_networks'
        $networks.status | Should -BeExactly 'observed'
        $networks.status_reason | Should -BeNullOrEmpty
        $networks.enabled.options.records | Should -Be 10
        $networks.enabled.options.exit_code | Should -Be 0
        $networks.enabled.options.mac_addresses_replaced | Should -Be 10
        $networks.command[0] | Should -Match 'netsh\.exe$'
        $networks.command[1..3] | Should -Be @('wlan', 'show', 'networks')
        $networks.raw_time_range.start | Should -Not -BeNullOrEmpty
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/wlan_networks/result.json') -Raw | ConvertFrom-Json
        @($result.fields).Count | Should -BeGreaterThan 50
        $result.protection.network_names_replaced | Should -Be 7
        $interfaces = Get-RfSource -Run $run -Id 'wlan_interfaces'
        $interfaces.status | Should -BeExactly 'observed'
        $interfaces.enabled.options.records | Should -Be 1
        $profiles = Get-RfSource -Run $run -Id 'wlan_profiles'
        $profiles.enabled.options.records | Should -Be 2
        @($networks.artifacts | ForEach-Object { $_.role } | Sort-Object) | Should -Be @('config', 'primary', 'report')
        # Every process the run started is netsh with one of the four read only listings.
        $started = @($global:WfSynthetic.Processes.ToArray())
        $started.Count | Should -Be 4
        foreach ($call in $started) {
            $call['FilePath'] | Should -Match 'netsh\.exe$'
            $call['Arguments'] | Should -Match '^wlan show (interfaces|drivers|networks mode=bssid|profiles)$'
        }
    }

    It 'never calls an empty scan a quiet airspace, but accepts zero interfaces' {
        Start-RfCase
        $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = "`r`nInterface name : Wi-Fi `r`nThere are 0 networks currently visible. `r`n`r`n"; StdErr = '' }
        $global:WfSynthetic.Commands['wlan show interfaces'] = @{ ExitCode = 0; StdOut = "`r`nThere is no wireless interface on the system.`r`n`r`n"; StdErr = '' }
        $out = Join-Path $TestDrive 'zero-networks'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $networks = Get-RfSource -Run $run -Id 'wlan_networks'
        $networks.status | Should -BeExactly 'capture_failed'
        $networks.status_reason | Should -Match '^zero records: netsh exited with code 0'
        $networks.status_reason | Should -Match 'location consent'
        $networks.expectation.met | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $out 'raw/wlan_networks/output.txt') | Should -BeFalse
        $interfaces = Get-RfSource -Run $run -Id 'wlan_interfaces'
        $interfaces.status | Should -BeExactly 'observed_zero'
        Test-Path -LiteralPath (Join-Path $out 'raw/wlan_interfaces/output.txt') | Should -BeTrue
    }

    It 'maps a failing, a missing and a hanging netsh to the right status' {
        Start-RfCase
        $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 1; StdOut = "The Wireless AutoConfig Service (wlansvc) is not running.`r`n"; StdErr = '' }
        $global:WfSynthetic.Commands['wlan show profiles'] = @{ Stuck = $true }
        $out = Join-Path $TestDrive 'netsh-fails'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 20 }
        $drivers = Get-RfSource -Run $run -Id 'wlan_drivers'
        $drivers.status | Should -BeExactly 'capture_failed'
        $drivers.status_reason | Should -Match 'exited with code 1: The Wireless AutoConfig Service'
        Test-Path -LiteralPath (Join-Path $out 'raw/wlan_drivers/output.txt') | Should -BeFalse
        $profiles = Get-RfSource -Run $run -Id 'wlan_profiles'
        $profiles.status | Should -BeExactly 'capture_failed'
        $profiles.status_reason | Should -Match 'did not finish within'
        $profiles.enabled.options.timed_out | Should -BeTrue

        Start-RfCase
        $global:WfSynthetic.NetshPresent = $false
        $run2 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'no-netsh')
        $run2.ExitCode | Should -Be 0
        foreach ($id in @('wlan_interfaces', 'wlan_drivers', 'wlan_networks', 'wlan_profiles')) {
            $source = Get-RfSource -Run $run2 -Id $id
            $source.status | Should -BeExactly 'not_collected' -Because $id
            $source.preflight.ok | Should -BeFalse
        }
        ($run2.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
    }

    It 'summarises the WLAN report only when it exists, fits the cap and can be read, and never copies it' {
        Start-RfCase
        $out = Join-Path $TestDrive 'report-ok'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $report = Get-RfSource -Run $run -Id 'wlan_report'
        $report.status | Should -BeExactly 'observed'
        $report.enabled.options.content_kept | Should -BeFalse
        $report.requested.options.mode | Should -BeExactly 'summary'
        $report.requested.options.path_documented | Should -BeFalse
        @($report.artifacts | Where-Object { $_.role -eq 'primary' })[0].path | Should -BeExactly 'raw/wlan_report/report-summary.json'
        @($run.Manifest.notes | Where-Object { $_ -match 'summarised, not copied' }).Count | Should -Be 1

        Start-RfCase 'rf-survey-clean'
        $run2 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'report-missing')
        $missing = Get-RfSource -Run $run2 -Id 'wlan_report'
        $missing.status | Should -BeExactly 'not_collected'
        $missing.status_reason | Should -Match 'does not exist'
        $missing.status_reason | Should -Match 'Administrator'
        @($missing.artifacts | ForEach-Object { $_.role }) | Should -Not -Contain 'primary'

        Start-RfCase
        $global:WfSynthetic.Files['C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access to the path is denied.' }
        $run3 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'report-denied')
        (Get-RfSource -Run $run3 -Id 'wlan_report').status | Should -BeExactly 'not_collected'
        (Get-RfSource -Run $run3 -Id 'wlan_report').status_reason | Should -Match 'denied'

        Start-RfCase
        $global:WfSynthetic.Files['C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html'] = @{ Text = ('x' * 1100000) }
        $out4 = Join-Path $TestDrive 'report-large'
        $run4 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out4 -Arguments @{ MaxArtifactBytes = 1048576 }
        (Get-RfSource -Run $run4 -Id 'wlan_report').status | Should -BeExactly 'capture_failed'
        (Get-RfSource -Run $run4 -Id 'wlan_report').status_reason | Should -Match 'above the cap'
        Test-Path -LiteralPath (Join-Path $out4 'raw/wlan_report/report-summary.json') | Should -BeFalse
    }

    It 'follows every selected device to the root of the tree and keeps the controller' {
        Start-RfCase
        $out = Join-Path $TestDrive 'usb-tree'
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out
        $usb = Get-RfSource -Run $run -Id 'usb_device_tree'
        $usb.status | Should -BeExactly 'observed'
        $usb.enabled.options.devices_present | Should -Be 19
        # The seeds are every device of the six classes plus every USB\ instance; the three ancestors are the PCI root, the ACPI root and the tree root.
        $usb.enabled.options.ancestors_added | Should -Be 3
        $devices = Get-Content -LiteralPath (Join-Path $out 'raw/usb_device_tree/devices.json') -Raw | ConvertFrom-Json
        $byId = @{}
        foreach ($device in $devices) { $byId[$device.instance_id] = $device }
        $receiver = $byId['USB\VID_FFF1&PID_0001\5&1e2f3a4b&0&3']
        $receiver.is_seed | Should -BeTrue
        $receiver.parent_instance_id | Should -BeExactly 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'
        $receiver.location_paths | Should -Be @('PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)')
        $receiver.bus_reported_description | Should -BeExactly 'Synthetic Lightspeed Receiver'
        $controller = $byId['PCI\VEN_FFF0&DEV_A36D\3&11583659&0&A0']
        $controller.is_seed | Should -BeTrue -Because 'a host controller is of class USB'
        $controller.service | Should -BeExactly 'USBXHCI'
        $byId['HID\VID_FFF1&PID_0001&MI_00\7&4c5d6e7f&0&0000'].is_seed | Should -BeTrue -Because 'class Mouse is selected even without a USB instance id'
        $byId['PCI\VEN_FFF0&DEV_2725\4&3a2b1c0d&0&00A0'].is_seed | Should -BeTrue -Because 'class Net is selected'
        $byId['ACPI\PNP0A08\0'].is_seed | Should -BeFalse -Because 'the PCI root is only an ancestor'
        $byId.ContainsKey('HTREE\ROOT\0') | Should -BeTrue
        $byId.ContainsKey('PCI\VEN_FFFF&DEV_0001\4&3a2b1c0d&0&0008') | Should -BeFalse -Because 'the display adapter is neither selected nor an ancestor'
        $bluetooth = Get-RfSource -Run $run -Id 'bluetooth_devices'
        $bluetooth.status | Should -BeExactly 'observed'
        $bluetooth.enabled.options.devices_selected | Should -Be 8
        $routes = Get-Content -LiteralPath (Join-Path $out 'raw/default_routes/records.json') -Raw | ConvertFrom-Json
        @($routes | ForEach-Object { $_.DestinationPrefix }) | Should -Be @('0.0.0.0/0', '::/0')
        (Get-RfSource -Run $run -Id 'default_routes').requested.options.filter | Should -Match "DestinationPrefix = '0.0.0.0/0' OR"
    }

    It 'reports a device enumeration that fails, is empty or hits the cap honestly' {
        Start-RfCase
        $global:WfSynthetic.Pnp = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
        $run = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'pnp-denied')
        (Get-RfSource -Run $run -Id 'usb_device_tree').status | Should -BeExactly 'not_collected'
        (Get-RfSource -Run $run -Id 'bluetooth_devices').status | Should -BeExactly 'not_collected'
        @((Get-RfSource -Run $run -Id 'usb_device_tree').artifacts | ForEach-Object { $_.role }) | Should -Not -Contain 'primary'

        Start-RfCase
        $global:WfSynthetic.Pnp = @{ Devices = @() }
        $run2 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'pnp-empty')
        (Get-RfSource -Run $run2 -Id 'usb_device_tree').status | Should -BeExactly 'capture_failed'
        (Get-RfSource -Run $run2 -Id 'usb_device_tree').status_reason | Should -Match 'no present device'
        (Get-RfSource -Run $run2 -Id 'bluetooth_devices').status | Should -BeExactly 'capture_failed'

        Start-RfCase 'rf-survey-no-wifi'
        $run3 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory (Join-Path $TestDrive 'pnp-no-bt')
        $bluetooth = Get-RfSource -Run $run3 -Id 'bluetooth_devices'
        $bluetooth.status | Should -BeExactly 'observed_zero'
        $bluetooth.enabled.options.devices_present | Should -BeGreaterThan 0
        $bluetooth.enabled.options.devices_selected | Should -Be 0

        Start-RfCase
        $out4 = Join-Path $TestDrive 'pnp-capped'
        $run4 = Invoke-TestCollector -Collector 'rf-survey' -OutputDirectory $out4 -Arguments @{ MaxEvents = 3 }
        $usb = Get-RfSource -Run $run4 -Id 'usb_device_tree'
        $usb.status | Should -BeExactly 'capture_failed'
        $usb.status_reason | Should -Match 'cap of 3 records'
        @(Get-Content -LiteralPath (Join-Path $out4 'raw/usb_device_tree/devices.json') -Raw | ConvertFrom-Json).Count | Should -Be 3
    }
}

Describe 'presentmon-frames against the synthetic backend' {
    BeforeAll {
        function Start-PmCase {
            # The happy case's machine: the pinned binary present, the account
            # in Performance Log Users, wpr recording without loss under the
            # collector's instance name, PresentMon printing the two process CSV.
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'presentmon-frames' })[0]
            & $selected['Setup']
        }
        function Reset-PmPrograms {
            # Replaces what the synthetic programs do when started.
            param([hashtable]$Wpr = @{}, $Decode = @{})
            $global:WfSynthetic.Programs.Clear()
            if (-not $Wpr.ContainsKey('EtlBytes')) { $Wpr['EtlBytes'] = (New-WfSyntheticEtlBytes -DurationSeconds 60) }
            Add-WfSyntheticWprRuns @Wpr
            if ($null -ne $Decode) {
                if (-not $Decode.ContainsKey('CsvText')) { $Decode['CsvText'] = (Get-WfSyntheticPresentMonCsv -Name 'two-processes') }
                Add-WfSyntheticPresentMonDecode @Decode
            }
        }
        function Invoke-PmCollector {
            param([string]$OutputDirectory, [hashtable]$Arguments = @{})
            $all = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            foreach ($key in $Arguments.Keys) { $all[$key] = $Arguments[$key] }
            return (Invoke-TestCollector -Collector 'presentmon-frames' -OutputDirectory $OutputDirectory -Arguments $all)
        }
        function Get-PmSource {
            param($Run)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq 'presentmon_frames' })[0]
        }
        function Get-PmStarted {
            # Every process the run started, as "<file name> <arguments>".
            return @($global:WfSynthetic.Processes.ToArray() | ForEach-Object { (Split-Path -Leaf ([string]$_['FilePath'])) + ' ' + [string]$_['Arguments'] })
        }
        function Get-PmRecording {
            param([string]$OutputDirectory)
            return (Get-Content -LiteralPath (Join-Path $OutputDirectory 'raw/presentmon_frames/recording.json') -Raw | ConvertFrom-Json)
        }
        # The only argument strings the collector may hand to the two binaries. Every wpr call ends in the instance name.
        $script:PmInstance = ' -instancename wf-presentmon-frames$'
        $script:PmWprProbe = '^wpr\.exe -status' + $script:PmInstance
        $script:PmWprStart = '^wpr\.exe -start "[^"]+profile\.wprp!WfPresentMonFrames\.Verbose" -filemode -recordtempto "[^"]+wpr-temp"' + $script:PmInstance
        $script:PmWprStatus = '^wpr\.exe -status collectors -details' + $script:PmInstance
        $script:PmWprStop = '^wpr\.exe -stop "[^"]+trace\.etl" "win-forensics presentmon-frames" -skipPdbGen' + $script:PmInstance
        $script:PmWprCancel = '^wpr\.exe -cancel' + $script:PmInstance
        $script:PmDecode = '^PresentMon-2\.6\.0-x64\.exe --etl_file "[^"]+trace\.etl" --output_stdout --qpc_time( --process_name [A-Za-z0-9._][A-Za-z0-9._-]*)*$'
        $script:PmGold = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'fixtures/presentmon/gold-test_case_0.first-buffer.etl'
        function Assert-PmAllowlisted {
            foreach ($call in (Get-PmStarted)) {
                $allowed = ($call -match $script:PmWprProbe) -or ($call -match $script:PmWprStart) -or ($call -match $script:PmWprStatus) -or ($call -match $script:PmWprStop) -or ($call -match $script:PmWprCancel) -or ($call -match $script:PmDecode)
                $allowed | Should -BeTrue -Because $call
                $call | Should -Not -Match '--timed|--session_name|--process_id|--terminate|--stop_existing|--restart_as_admin|--hotkey|--output_file' -Because 'PresentMon never runs live and never writes a file'
                if ($call -match '^wpr') { $call | Should -Match $script:PmInstance -Because 'every wpr call names the instance' }
            }
        }
    }

    It 'records with wpr under its instance name, reads the recording with PresentMon offline, deletes it, and never starts PresentMon live' {
        Start-PmCase
        $out = Join-Path $TestDrive 'pm-ok'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'observed'
        $source.kind | Should -BeExactly 'presentmon'
        $source.preflight.ok | Should -BeTrue
        @($source.preflight.checks | ForEach-Object { $_.name }) | Should -Be @('binary_present', 'binary_sha256_pinned', 'binary_length_pinned', 'wpr_present', 'wpr_instance_idle')
        @($source.command) | Should -Be @((Get-WfSyntheticPresentMonPath), '--etl_file', 'raw/presentmon_frames/trace.etl', '--output_stdout', '--qpc_time')
        $source.events_lost | Should -Be 0
        $source.buffers.size_kb | Should -Be 64
        $source.buffers.mode | Should -BeExactly 'file'
        $source.enabled.options.records | Should -Be 10
        $source.enabled.options.qpc_time_column | Should -BeTrue
        $source.enabled.options.clock_type | Should -BeExactly 'qpc'
        $source.enabled.options.settings_match_request | Should -BeTrue
        $source.enabled.options.stop_confirmed | Should -BeTrue
        $source.enabled.options.session_ended_early | Should -BeFalse
        $source.enabled.options.etl_kept | Should -BeFalse
        $source.enabled.options.events_lost_sources.wpr_status_dropped_events | Should -Be 0
        $source.enabled.options.events_lost_sources.etl_header_events_lost | Should -Be 0
        $source.enabled.options.unknown_application_frames | Should -Be 2
        @($source.enabled.options.processes).Count | Should -Be 2
        @($source.enabled.providers) | Should -Contain 'Microsoft-Windows-DxgKrnl'
        @($source.artifacts | ForEach-Object { $_.role + ':' + (Split-Path -Leaf $_.path) } | Sort-Object) | Should -Be @('config:command.json', 'config:profile.wprp', 'log:console.txt', 'primary:frames.csv', 'report:recording.json', 'report:result.json')
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse -Because 'the recording never leaves the PC'
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/wpr-temp') | Should -BeFalse
        # The range the source claims is the collector's own bound around the recording: before the start, after the stop.
        $recording = Get-PmRecording -OutputDirectory $out
        (Get-TestUtcText $source.raw_time_range.start) | Should -BeExactly (Get-TestUtcText $recording.window_start_bound_utc)
        (Get-TestUtcText $source.raw_time_range.end) | Should -BeExactly (Get-TestUtcText $recording.window_stop_bound_utc)
        ([datetime]$recording.window_start_bound_utc) | Should -BeLessThan ([datetime]$recording.header.start_time_utc)
        ([datetime]$recording.header.end_time_utc) | Should -BeGreaterThan ([datetime]$recording.stop_requested_utc)
        $global:WfSynthetic.Waited | Should -Be 60
        # The CSV is what PresentMon printed, written without a byte order mark.
        [System.IO.File]::ReadAllBytes((Join-Path $out 'raw/presentmon_frames/frames.csv')) | Should -Be ((New-Object System.Text.UTF8Encoding($false)).GetBytes((Get-WfSyntheticPresentMonCsv -Name 'two-processes')))
        $profile = [System.IO.File]::ReadAllText((Join-Path $out 'raw/presentmon_frames/profile.wprp'))
        $profile | Should -Match 'Name="802ec45a-1e99-4b83-9920-87c98277ba9d"'
        $profile | Should -Match '<MaximumFileSize Value="48" FileMode="Sequential"/>' -Because 'three quarters of the 64 MiB cap'
        $profile | Should -Match '<Keyword Value="0x8000841"/>'
        $profile | Should -Match '<EventFilters FilterIn="true">'
        $profile | Should -Match '<EventId Value="184"/>'
        $profile | Should -Not -Match '0x4000000000000000' -Because 'the DxgKrnl Performance keyword is never enabled'
        $source.filter_hash.value | Should -BeExactly (Get-TestSha256 -Path (Join-Path $out 'raw/presentmon_frames/profile.wprp'))
        $source.config_hash.value | Should -BeExactly (Get-TestSha256 -Path (Join-Path $out 'raw/presentmon_frames/command.json'))
        # Six processes in order: probe, start, status at the end, stop, status after, PresentMon offline. No cancel.
        $started = Get-PmStarted
        $started.Count | Should -Be 6
        $started[0] | Should -Match $script:PmWprProbe
        $started[1] | Should -Match $script:PmWprStart
        $started[2] | Should -Match $script:PmWprStatus
        $started[3] | Should -Match $script:PmWprStop
        $started[4] | Should -Match $script:PmWprProbe
        $started[5] | Should -Match $script:PmDecode
        Assert-PmAllowlisted
        $run.Manifest.scenario.requested_duration_s | Should -Be 60
        $run.Manifest.calibration.method | Should -Match 'clock_type'
        @($run.Manifest.tools | Where-Object { $_.name -eq 'presentmon' })[0].sha256 | Should -BeExactly (Get-WfSyntheticPresentMonPinnedSha256)
        @($run.Manifest.tools | Where-Object { $_.name -eq 'wpr' })[0].path | Should -Match 'wpr\.exe$'
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        $result.binary.sha256_before_run | Should -BeExactly (Get-WfSyntheticPresentMonPinnedSha256)
        $result.runs.cancel.attempted | Should -BeFalse
        $result.runs.leftover_cancel.attempted | Should -BeFalse
        $result.runs.decode.exit_code | Should -Be 0
        $recording.header.found | Should -BeTrue
        $recording.header.events_lost | Should -Be 0
        $recording.etl_kept | Should -BeFalse
        $recording.etl_sha256 | Should -Match '^[0-9a-f]{64}$'
        @($recording.wpr_enabled_providers).Count | Should -Be 8
        @($recording.settings_comparison.providers | Where-Object { $_.strict -and -not $_.enabled }).Count | Should -Be 0
    }

    It 'passes names through to the offline read only and records the first as the target' {
        Start-PmCase
        $out = Join-Path $TestDrive 'pm-named'
        $run = Invoke-PmCollector -OutputDirectory $out -Arguments @{ ProcessName = @('SyntheticGame.exe', 'Other-App_2.exe') }
        $run.ExitCode | Should -Be 0
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'observed'
        @($source.command)[-4..-1] | Should -Be @('--process_name', 'SyntheticGame.exe', '--process_name', 'Other-App_2.exe')
        $source.target_process.name | Should -BeExactly 'SyntheticGame.exe'
        $source.target_process.alive_at_start | Should -BeNullOrEmpty
        $run.Manifest.scenario.target_process | Should -BeExactly 'SyntheticGame.exe'
        (Get-PmStarted)[-1] | Should -Match $script:PmDecode
        (Get-PmStarted)[1] | Should -Not -Match 'SyntheticGame' -Because 'the recording is of every process; the name filter applies to the file'
        Assert-PmAllowlisted
    }

    It 'runs nothing when the binary hash or size differs or the binary is missing' {
        foreach ($setup in @(@{ Sha256 = ('0' * 64) }, @{ Length = 980321 }, @{ Present = $false })) {
            Start-PmCase
            New-WfSyntheticPresentMon -PerformanceLogUsers $true @setup
            $out = Join-Path $TestDrive ('pm-pin-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            $run = Invoke-PmCollector -OutputDirectory $out
            $run.ExitCode | Should -Be 1
            $source = Get-PmSource -Run $run
            $source.status | Should -BeExactly 'not_collected'
            $source.status_reason | Should -Match '^preflight failed: '
            $source.preflight.ok | Should -BeFalse
            $global:WfSynthetic.Processes.Count | Should -Be 0 -Because 'nothing may run, not even wpr, before the pin matched'
            $global:WfSynthetic.Waited | Should -Be 0
            Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse
            @($source.artifacts | ForEach-Object { $_.role } | Sort-Object) | Should -Be @('config', 'config', 'report', 'report')
        }
        (Get-PmSource -Run $run).status_reason | Should -Match 'never downloads'
    }

    It 'refuses to run the binary that changed between the preflight hash and the read' {
        Start-PmCase
        Reset-PmPrograms
        # The synthetic stop swaps the binary on disk, as a writable tools folder would allow.
        $stop = @($global:WfSynthetic.Programs | Where-Object { $_['Match'] -eq '-stop' })[0]
        $stop['OnCall'] = { $global:WfSynthetic.Binaries[(Get-WfSyntheticPresentMonPath)] = @{ Length = 980320; Sha256 = ('1' * 64); FileVersion = '2.6.0.0'; ProductVersion = '2.6.0' } }
        $out = Join-Path $TestDrive 'pm-swapped'
        $run = Invoke-PmCollector -OutputDirectory $out
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'changed between the preflight check and the run \(now SHA-256 1{64}'
        @((Get-PmStarted) | Where-Object { $_ -match '^PresentMon' }).Count | Should -Be 0
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        $result.binary.pin_matched | Should -BeTrue
        $result.binary.sha256_before_run | Should -BeExactly ('1' * 64)
    }

    It 'cancels only its own leftover recording, and fails closed when the instance cannot be shown idle or wpr is missing' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ LeftoverActive = $true }
        $out = Join-Path $TestDrive 'pm-leftover'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'observed'
        $started = Get-PmStarted
        $started.Count | Should -Be 8 -Because 'probe, cancel of the leftover, probe again, then the normal six'
        $started[0] | Should -Match $script:PmWprProbe
        $started[1] | Should -Match $script:PmWprCancel
        $started[2] | Should -Match $script:PmWprProbe
        $started[3] | Should -Match $script:PmWprStart
        Assert-PmAllowlisted
        @($run.Manifest.notes | Where-Object { $_ -match 'own WPR instance \(wf-presentmon-frames\) was still active' }).Count | Should -Be 1
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        $result.runs.leftover_cancel.attempted | Should -BeTrue

        Start-PmCase
        Reset-PmPrograms -Wpr @{ ProbeInProgress = $true }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-busy')
        $run2.ExitCode | Should -Be 1
        $source2 = Get-PmSource -Run $run2
        $source2.status | Should -BeExactly 'not_collected'
        $source2.status_reason | Should -Match 'was active and the cancel did not clear it; nothing was started'
        @($source2.preflight.checks | Where-Object { $_.name -eq 'wpr_instance_idle' })[0].ok | Should -BeFalse
        @(Get-PmStarted).Count | Should -Be 3 -Because 'probe, cancel, probe; no start'
        (Get-PmStarted)[1] | Should -Match $script:PmWprCancel
        $global:WfSynthetic.Waited | Should -Be 0

        Start-PmCase
        Reset-PmPrograms -Wpr @{ ProbeFails = $true }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-probe-fails')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'not_collected'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'idle state of this collector''s WPR instance could not be established \(wpr -status exit code 2'
        @(Get-PmStarted).Count | Should -Be 1

        Start-PmCase
        Reset-PmPrograms -Wpr @{ ProbeStuck = $true }
        $run4 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-probe-stuck')
        (Get-PmSource -Run $run4).status | Should -BeExactly 'not_collected'
        (Get-PmSource -Run $run4).status_reason | Should -Match 'timed out True'
        @(Get-PmStarted).Count | Should -Be 1 -Because 'a probe that hangs starts nothing and cancels nothing'

        Start-PmCase
        $global:WfSynthetic.WprPresent = $false
        $run5 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-no-wpr')
        (Get-PmSource -Run $run5).status | Should -BeExactly 'not_collected'
        (Get-PmSource -Run $run5).status_reason | Should -Match 'Windows Performance Recorder is not at'
        $global:WfSynthetic.Processes.Count | Should -Be 0
    }

    It 'treats a refused or failed start as not collected and keeps the words wpr printed' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartExitCode = 1; StartStdErr = "Access is denied.`r`n" }
        $out = Join-Path $TestDrive 'pm-denied'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'not_collected'
        $source.status_reason | Should -Match 'wpr -start was refused \(exit code 1\): "Access is denied\."'
        $source.status_reason | Should -Match 'Performance Log Users'
        @(Get-PmStarted).Count | Should -Be 2 -Because 'the probe and the refused start; no stop, no cancel, no PresentMon'
        $global:WfSynthetic.Waited | Should -Be 0
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse
        [System.IO.File]::ReadAllText((Join-Path $out 'raw/presentmon_frames/console.txt')) | Should -Match 'Access is denied\.'

        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartExitCode = 2; StartStdOut = "synthetic wpr: the profile could not be loaded`r`n" }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-start-fails')
        (Get-PmSource -Run $run2).status | Should -BeExactly 'not_collected'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'wpr -start did not complete \(exit code 2'
        @(Get-PmStarted).Count | Should -Be 2 -Because 'a start that exited without starting leaves nothing to cancel'

        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartStuck = $true }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-start-stuck')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'not_collected'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'timed out True'
        (Get-PmStarted)[-1] | Should -Match $script:PmWprCancel -Because 'a start that did not complete may have left a recording of our instance'
    }

    It 'is capture_failed on any loss from any source, never reads the recording, and keeps nothing' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ EventsLost = 12; EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -EventsLost 12) }
        $out = Join-Path $TestDrive 'pm-lost'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^the recording lost events or buffers: 12 events lost \(wpr -status: dropped 12, collectors 12; header 12\)'
        $source.events_lost | Should -Be 12
        $source.raw_time_range | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse
        @((Get-PmStarted) | Where-Object { $_ -match '^PresentMon' }).Count | Should -Be 0 -Because 'PresentMon is not run over a recording with loss'
        @($source.artifacts | ForEach-Object { $_.role } | Sort-Object) | Should -Be @('config', 'config', 'log', 'report', 'report')

        # The controller said zero before the stop; the header the session wrote at its close says 3.
        Start-PmCase
        Reset-PmPrograms -Wpr @{ EventsLost = 0; EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -EventsLost 3) }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-header-loss')
        (Get-PmSource -Run $run2).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run2).events_lost | Should -Be 3
        (Get-PmSource -Run $run2).status_reason | Should -Match '3 events lost \(wpr -status: dropped 0, collectors 0; header 3\)'

        Start-PmCase
        Reset-PmPrograms -Wpr @{ EventsLost = 0; EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -BuffersLost 2) }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-buffers-lost')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run3).status_reason | Should -Match '2 buffers lost'
        (Get-PmSource -Run $run3).enabled.options.buffers_lost | Should -Be 2

        # Only the top level Dropped event counter shows loss.
        Start-PmCase
        Reset-PmPrograms -Wpr @{ EventsLost = 0; DroppedEvents = 5 }
        $run4 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-dropped')
        (Get-PmSource -Run $run4).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run4).events_lost | Should -Be 5
        (Get-PmSource -Run $run4).enabled.options.events_lost_sources.wpr_status_dropped_events | Should -Be 5
    }

    It 'cancels and fails when the stop does not complete, and says when it could not confirm the stop' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StopStuck = $true }
        $out = Join-Path $TestDrive 'pm-stop-stuck'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^wpr -stop did not complete .*; the recording was cancelled instead'
        $source.status_reason | Should -Not -Match 'may still be active'
        @((Get-PmStarted) | Where-Object { $_ -match $script:PmWprCancel }).Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse

        Start-PmCase
        Reset-PmPrograms -Wpr @{ StopStuck = $true; CancelStuck = $true; AfterInProgress = $true }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-stop-unconfirmed')
        $source2 = Get-PmSource -Run $run2
        $source2.status | Should -BeExactly 'capture_failed'
        $source2.status_reason | Should -Match 'the recording may still be active'
        $source2.enabled.options.stop_confirmed | Should -BeFalse
        @($run2.Manifest.notes | Where-Object { $_ -match 'could not confirm that the WPR recording of instance wf-presentmon-frames stopped' }).Count | Should -Be 1

        # The stop exited 0 but the instance still shows in progress: not confirmed, cancelled, failed.
        Start-PmCase
        Reset-PmPrograms -Wpr @{ AfterInProgress = $true }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-stop-still-running')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'exited 0 but the instance could not be confirmed idle'
        (Get-PmStarted)[-1] | Should -Match $script:PmWprCancel
        @((Get-PmStarted) | Where-Object { $_ -match '^PresentMon' }).Count | Should -Be 0
    }

    It 'fails when the recording was not in progress at the end, closed before the stop, or merged above the cap' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ InProgressAtEnd = $false }
        $run = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-died')
        (Get-PmSource -Run $run).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run).status_reason | Should -Match 'did not report a recording in progress'
        (Get-PmSource -Run $run).enabled.options.recording_in_progress | Should -BeFalse

        Start-PmCase
        Reset-PmPrograms -Wpr @{ EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -EndOffsetSeconds 30) }
        $out = Join-Path $TestDrive 'pm-capped'
        $run2 = Invoke-PmCollector -OutputDirectory $out
        $source = Get-PmSource -Run $run2
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'the session closed at .* before the stop was requested at .*: it reached its file cap of 48 MB'
        $source.enabled.options.session_ended_early | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/trace.etl') | Should -BeFalse

        Start-PmCase
        $big = New-Object byte[] 1048577
        $header = New-WfSyntheticEtlBytes -DurationSeconds 60
        [array]::Copy($header, $big, $header.Length)
        Reset-PmPrograms -Wpr @{ EtlBytes = $big }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-over-cap') -Arguments @{ MaxArtifactBytes = 1048576 }
        (Get-PmSource -Run $run3).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'merged recording is 1048577 bytes, above the artifact cap of 1048576'
        [System.IO.File]::ReadAllText((Join-Path $TestDrive 'pm-over-cap/raw/presentmon_frames/profile.wprp')) | Should -Match '<MaximumFileSize Value="1" FileMode="Sequential"/>'
    }

    It 'fails closed when the loss counters or the header cannot be read' {
        Start-PmCase
        Reset-PmPrograms
        # wpr -status collectors -details without any counter line: in progress, no Dropped event, no Events Lost.
        $global:WfSynthetic.Programs[0]['StdOut'] = ('WPR recording is in progress...' + "`r`n")
        $run = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-no-loss-count')
        (Get-PmSource -Run $run).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run).status_reason | Should -Match 'events lost could not be read from wpr -status'
        (Get-PmSource -Run $run).events_lost | Should -Be 0 -Because 'the header still gave its count; the controller did not'

        Start-PmCase
        Reset-PmPrograms -Wpr @{ EtlBytes = (New-Object byte[] 4096) }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-no-header')
        $source2 = Get-PmSource -Run $run2
        $source2.status | Should -BeExactly 'capture_failed'
        $source2.status_reason | Should -Match 'log file header could not be read \(the first event is not a system trace header'
        $source2.enabled.options.etl_header_found | Should -BeFalse
        $source2.enabled.options.clock_type | Should -BeNullOrEmpty
        $source2.events_lost | Should -Be 0 -Because 'the controller count is recorded even when the header is not'

        Start-PmCase
        Reset-PmPrograms -Wpr @{ EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -ClockType 2) }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-clock')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'observed' -Because 'the clock is recorded, not judged, by the collector'
        (Get-PmSource -Run $run3).enabled.options.clock_type | Should -BeExactly 'system_time'
    }

    It 'reads the first buffer of the vendor recording the way it reads its own, and the synthetic layout matches it' {
        Test-Path -LiteralPath $script:PmGold | Should -BeTrue
        $gold = [System.IO.File]::ReadAllBytes($script:PmGold)
        Start-PmCase
        Reset-PmPrograms -Wpr @{ EtlBytes = $gold }
        $out = Join-Path $TestDrive 'pm-gold'
        $run = Invoke-PmCollector -OutputDirectory $out
        $source = Get-PmSource -Run $run
        $recording = Get-PmRecording -OutputDirectory $out
        $recording.header.found | Should -BeTrue
        $recording.header.header_type | Should -Be 2
        $recording.header.pointer_size | Should -Be 8
        $recording.header.os_version | Should -BeExactly '10.0'
        $recording.header.os_build | Should -Be 17763
        $recording.header.number_of_processors | Should -Be 16
        $recording.header.buffers_written | Should -Be 663
        $recording.header.events_lost | Should -Be 0
        $recording.header.buffers_lost | Should -Be 0
        $recording.header.perf_freq_hz | Should -Be 10000000
        $recording.header.clock_type | Should -BeExactly 'qpc'
        $recording.header.logger_name | Should -BeExactly 'Relogger'
        (Get-TestUtcText $recording.header.start_time_utc) | Should -Match '^2020-'
        $source.status | Should -BeExactly 'capture_failed' -Because 'a recording that ended years before the stop was requested did not cover the window'
        $source.status_reason | Should -Match 'the session closed at 2020-'
        # The synthetic first buffer puts the same fields at the same offsets as the vendor file.
        $synthetic = New-WfSyntheticEtlBytes -DurationSeconds 60
        foreach ($offset in @(0x48, 0x49, 0x4a, 0x4b, 0x4e, 0x4f)) { $synthetic[$offset] | Should -Be $gold[$offset] -Because ('system trace header byte 0x{0:x}' -f $offset) }
        [System.BitConverter]::ToUInt32($synthetic, 0x68 + 44) | Should -Be ([System.BitConverter]::ToUInt32($gold, 0x68 + 44)) -Because 'PointerSize'
        $tail = 0x68 + 56 + 16 + 176
        [System.BitConverter]::ToInt64($synthetic, $tail + 8) | Should -Be ([System.BitConverter]::ToInt64($gold, $tail + 8)) -Because 'PerfFreq'
        [System.BitConverter]::ToUInt32($synthetic, $tail + 24) | Should -Be ([System.BitConverter]::ToUInt32($gold, $tail + 24)) -Because 'ReservedFlags'
        [System.BitConverter]::ToUInt32($synthetic, 0) | Should -Be ([System.BitConverter]::ToUInt32($gold, 0)) -Because 'the first buffer size'
    }

    It 'fails when wpr -status does not show the requested providers enabled with their keywords and level' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ ProviderLines = $false }
        $run = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-no-providers')
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'requested settings were not shown enabled by wpr -status collectors -details: Microsoft-Windows-DxgKrnl, Microsoft-Windows-Win32k, Microsoft-Windows-Dwm-Core, Microsoft-Windows-DXGI, Microsoft-Windows-D3D9 \(.*0 provider lines were read\)'
        $source.enabled.options.settings_match_request | Should -BeFalse
        @((Get-PmStarted) | Where-Object { $_ -match '^PresentMon' }).Count | Should -Be 0

        Start-PmCase
        Reset-PmPrograms -Wpr @{ DxgKrnlKeywords = '0x1' }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-weak-keywords')
        (Get-PmSource -Run $run2).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'not shown enabled .*: Microsoft-Windows-DxgKrnl \('
        $recording = Get-PmRecording -OutputDirectory (Join-Path $TestDrive 'pm-weak-keywords')
        @($recording.settings_comparison.providers | Where-Object { $_.id -eq 'Microsoft-Windows-DxgKrnl' })[0].keywords_ok | Should -BeFalse
    }

    It 'never claims a quiet window: an empty PresentMon output is capture_failed, scoped or not' {
        Start-PmCase
        Reset-PmPrograms -Decode @{ CsvText = '' }
        $out = Join-Path $TestDrive 'pm-empty'
        $run = Invoke-PmCollector -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match 'emitted no frame from a 60 second recording without loss'
        $source.status_reason | Should -Match 'not a quiet window claim'
        $source.enabled.options.csv_present | Should -BeFalse
        $source.enabled.options.records | Should -Be 0
        $source.raw_time_range | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse

        Start-PmCase
        Reset-PmPrograms -Decode @{ CsvText = '' }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-empty-scoped') -Arguments @{ ProcessName = @('SyntheticGame.exe') }
        (Get-PmSource -Run $run2).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'no frame for the requested process names \(SyntheticGame\.exe\)'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'no absence is claimed'

        Start-PmCase
        Reset-PmPrograms -Decode @{ CsvText = (Get-WfSyntheticPresentMonCsv -Name 'header-only') }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-header-only')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'a CSV header and no frame row'
    }

    It 'is capture_failed when PresentMon threw presents away, warned, failed, hung or printed above the cap' {
        Start-PmCase
        Reset-PmPrograms -Decode @{ StdErr = (Get-WfSyntheticPresentMonOverflowText -Count 37) }
        $out = Join-Path $TestDrive 'pm-overflow'
        $run = Invoke-PmCollector -OutputDirectory $out
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^PresentMon threw away 37 presents'
        $source.enabled.options.presentmon_overflowed_presents | Should -Be 37
        $source.enabled.options.presentmon_exit_code | Should -Be 0
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse -Because 'an incomplete frame table is not kept'
        (Get-PmRecording -OutputDirectory $out).presentmon.overflowed_presents | Should -Be 37

        Start-PmCase
        Reset-PmPrograms -Decode @{ StdErr = "warning: synthetic text`n" }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-warning')
        (Get-PmSource -Run $run2).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'reported a problem reading the recording: warning: synthetic text'
        @((Get-PmSource -Run $run2).enabled.options.presentmon_warnings) | Should -Be @('warning: synthetic text')

        Start-PmCase
        Reset-PmPrograms -Decode @{ ExitCode = 6; StdErr = "error: failed to start trace session: invalid --etl_file.`n" }
        $run3 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-exit-6')
        (Get-PmSource -Run $run3).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run3).status_reason | Should -Match 'PresentMon exited with code 6 reading the recording: "error: failed to start trace session: invalid --etl_file\."'

        Start-PmCase
        Reset-PmPrograms -Decode @{ Stuck = $true }
        $run4 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-decode-stuck')
        (Get-PmSource -Run $run4).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run4).status_reason | Should -Match 'did not finish reading the \d+ byte recording within 240 seconds'

        Start-PmCase
        $csv = Get-WfSyntheticPresentMonCsv -Name 'two-processes'
        $builder = New-Object System.Text.StringBuilder
        while ($builder.Length -lt 1100000) { $null = $builder.Append($csv) }
        Reset-PmPrograms -Decode @{ CsvText = $builder.ToString() }
        $run5 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-decode-oversized') -Arguments @{ MaxArtifactBytes = 1048576 }
        (Get-PmSource -Run $run5).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run5).status_reason | Should -Match 'printed more than the artifact cap of 1048576 bytes of CSV and was stopped'
        Test-Path -LiteralPath (Join-Path $TestDrive 'pm-decode-oversized/raw/presentmon_frames/frames.csv') | Should -BeFalse
    }

    It 'refuses a CSV whose header does not prove the requested options' {
        Start-PmCase
        Reset-PmPrograms -Decode @{ CsvText = (Get-WfSyntheticPresentMonCsv -Name 'no-qpc') }
        $out = Join-Path $TestDrive 'pm-no-qpc'
        $run = Invoke-PmCollector -OutputDirectory $out
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '--qpc_time was requested but the CSV header has no CPUStartQPC column'
        $source.enabled.options.qpc_time_column | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse -Because 'a failed source leaves no primary'

        Start-PmCase
        Reset-PmPrograms -Decode @{ CsvText = ('time,value' + "`r`n" + '1,2' + "`r`n") }
        $run2 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-not-presentmon')
        (Get-PmSource -Run $run2).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run2).status_reason | Should -Match 'not the documented PresentMon header'
    }

    It 'keeps what the programs printed in console.txt and the recording facts in recording.json' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartStdOut = "synthetic wpr: starting`r`n" }
        $out = Join-Path $TestDrive 'pm-console'
        $run = Invoke-PmCollector -OutputDirectory $out
        (Get-PmSource -Run $run).status | Should -BeExactly 'observed'
        $console = [System.IO.File]::ReadAllText((Join-Path $out 'raw/presentmon_frames/console.txt'))
        $console | Should -Match '=== wpr -status -instancename wf-presentmon-frames \(before\)'
        $console | Should -Match 'synthetic wpr: starting'
        $console | Should -Match '=== wpr -stop'
        $console | Should -Match '=== PresentMon --etl_file \(stdout is the CSV\)'
        $console | Should -Match 'stdout: the CSV \(\d+ bytes\)'
        $console | Should -Not -Match 'SyntheticGame\.exe,4242' -Because 'the CSV is frames.csv, not repeated in the log'
        $recording = Get-PmRecording -OutputDirectory $out
        $recording.instance_name | Should -BeExactly 'wf-presentmon-frames'
        $recording.session_cap_mb | Should -Be 48
        $recording.wpr_collectors | Should -Be @('wf-presentmon-frames')
        $recording.events_lost_sources.wpr_status_collectors | Should -Be 0
    }

    It 'rejects a duration, a cap or a process name outside the rules with a failed summary and no bundle' {
        Start-PmCase
        foreach ($bad in @(@{ DurationSeconds = 4 }, @{ DurationSeconds = 241 }, @{ MaxArtifactBytes = 1048575 }, @{ MaxArtifactBytes = 1073741825 }, @{ ProcessName = @('bad name.exe') }, @{ ProcessName = @('-start.exe') }, @{ ProcessName = @('a"b.exe') }, @{ ProcessName = @('1.exe', '2.exe', '3.exe', '4.exe', '5.exe', '6.exe', '7.exe', '8.exe', '9.exe') })) {
            $out = Join-Path $TestDrive ('pm-bad-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            $run = Invoke-PmCollector -OutputDirectory $out -Arguments $bad
            $run.ExitCode | Should -Be 1
            $run.Stdout.Count | Should -Be 1
            ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
            Test-Path -LiteralPath $out | Should -BeFalse
            $global:WfSynthetic.Processes.Count | Should -Be 0
        }
    }
}
