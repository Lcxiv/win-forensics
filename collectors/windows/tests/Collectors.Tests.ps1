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
        $accumulator = New-WfRowAccumulator -MaxRows 3 -MaxBytes 1048576
        $result = Invoke-WfStreamingRead -Producer { while ($true) { [ordered]@{ a = 1 } } } -Convert { param($r) $r } -Accumulator $accumulator
        $result['Ok'] | Should -BeTrue
        $accumulator.Rows.Count | Should -Be 3
        $accumulator.Truncated | Should -BeTrue
        $accumulator = New-WfRowAccumulator -MaxRows 3 -MaxBytes 1048576
        $result = Invoke-WfStreamingRead -Producer { [ordered]@{ a = 1 }; throw 'synthetic:access_denied: no' } -Convert { param($r) $r } -Accumulator $accumulator
        $result['Ok'] | Should -BeFalse
        $result['ErrorKind'] | Should -BeExactly 'access_denied'
        $result['Count'] | Should -Be 1
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

    It 'lists the binary export when wevtutil succeeds and omits it with -SkipEvtx' {
        Reset-WfSynthetic
        $global:WfSynthetic.Evtx = 'placeholder'
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $out = Join-Path $TestDrive 'with-evtx'
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out
        $source = $run.Manifest.collectors[0]
        $source.enabled.options.evtx_exported | Should -BeTrue
        @($source.artifacts | Where-Object { $_.path -eq 'raw/system_whea_events/events.evtx' -and $_.role -eq 'other' }).Count | Should -Be 1

        $out2 = Join-Path $TestDrive 'skip-evtx'
        $run2 = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory $out2 -Arguments @{ SkipEvtx = $true }
        $source2 = $run2.Manifest.collectors[0]
        $source2.requested.options.evtx_export | Should -BeFalse
        $source2.enabled.options.evtx_exported | Should -BeFalse
        @($source2.artifacts | Where-Object { $_.path -like '*.evtx' }).Count | Should -Be 0
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
        $run = Invoke-TestCollector -Collector 'reliability-records' -OutputDirectory $out -Arguments @{ TimeoutSeconds = 20; MaxEvents = 50 }
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
        $global:WfSynthetic.Ticks | Should -BeLessThan 200
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
        $run = Invoke-TestCollector -Collector 'driver-inventory' -OutputDirectory (Join-Path $TestDrive 'many-drivers') -Arguments @{ MaxEvents = 5000 }
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
