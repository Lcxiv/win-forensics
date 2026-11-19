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
        $selects[0].InnerText | Should -BeExactly "*[System[Provider[@Name='Application Error'] and (EventID=1000) and TimeCreated[@SystemTime >= '2026-01-30T12:00:00.000Z' and @SystemTime <= '2026-03-01T12:00:00.000Z']]]"
        $selects[1].InnerText | Should -BeExactly "*[System[(EventID=1002) and TimeCreated[@SystemTime >= '2026-01-30T12:00:00.000Z' and @SystemTime <= '2026-03-01T12:00:00.000Z']]]"
        # The form the gaming PC rejected at the first read (README, verification item 35).
        $text | Should -Not -Match 'timediff'
        # Quotes stay as written, as in the query text Get-WinEvent builds (GetEventCommand.cs
        # in the PowerShell repository); only &, < and > are escaped.
        $text | Should -Not -Match '&apos;|&quot;'
        $text.Contains("Provider[@Name='Application Error']") | Should -BeTrue
        $text.Contains('&gt;=') | Should -BeTrue
    }

    It 'writes the time literal with three fractional digits and refuses an end that is not on a millisecond' {
        $end = [datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc).AddTicks(1230000)
        ConvertTo-WfXPathDateTime -Value $end | Should -BeExactly '2026-03-01T12:00:00.123Z'
        ConvertTo-WfMillisecondFloor -Value $end.AddTicks(9999) | Should -Be $end
        (ConvertTo-WfMillisecondFloor -Value $end.AddTicks(9999)).Kind | Should -Be ([System.DateTimeKind]::Utc)
        { Build-WfEventQueryXml -Channel 'System' -Predicates @('(EventID=41)') -EndUtc $end.AddTicks(1) -WindowMilliseconds 1000 } | Should -Throw '*cut to the millisecond*'
        $text = Build-WfEventQueryXml -Channel 'System' -Predicates @('(EventID=41)') -EndUtc $end -WindowMilliseconds 1500
        ([xml]$text).QueryList.Query.Select.InnerText | Should -BeExactly "*[System[(EventID=41) and TimeCreated[@SystemTime >= '2026-03-01T11:59:58.623Z' and @SystemTime <= '2026-03-01T12:00:00.123Z']]]"
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

Describe 'the event query time bound on the gaming PC' {
    # On 2026-11-18 every event log source failed at its first ReadEvent on the
    # gaming PC with "The data is invalid"; the PC session isolated the cause
    # to timediff(@SystemTime, <FILETIME number>) in the query. The synthetic
    # reader models that behaviour, so these tests fail if the builder writes
    # that form again (collectors/windows/README.md, verification item 35).
    BeforeAll {
        function New-NumericTimediffQuery {
            # Build-WfEventQueryXml as it was before the fix.
            param([datetime]$EndUtc, [int64]$WindowMilliseconds = 2592000000)
            $fileTime = $EndUtc.ToUniversalTime().ToFileTimeUtc()
            $xpath = '*[System[(EventID=41) and TimeCreated[timediff(@SystemTime, {0}) >= 0 and timediff(@SystemTime, {0}) <= {1}]]]' -f $fileTime, $WindowMilliseconds
            return ('<QueryList>' + "`n" + '  <Query Id="0" Path="System">' + "`n" + '    <Select Path="System">' + [System.Security.SecurityElement]::Escape($xpath) + '</Select>' + "`n" + '  </Query>' + "`n" + '</QueryList>' + "`n")
        }
    }

    It 'opens the numeric timediff form and fails at the first pull, as the PC did' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'EventID=41' -Events @((New-WfSyntheticEvent -RecordId 5 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 3))
        $old = New-NumericTimediffQuery -EndUtc $global:WfSynthetic.Now
        Test-WfSyntheticNumericTimediff -QueryXml $old | Should -BeTrue
        $reader = Open-WfEventReader -Channel 'System' -QueryXml $old -Reverse $true
        $reader['Ok'] | Should -BeTrue
        { & $reader['ReadNext'] ([timespan]::FromSeconds(10)) } | Should -Throw '*The data is invalid*'
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $read = Read-WfEventRecords -Channel 'System' -QueryXml $old -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $read['Ok'] | Should -BeFalse
        $read['Stage'] | Should -BeExactly 'read'
        $read['ErrorKind'] | Should -BeExactly 'other'
        $read['Count'] | Should -Be 0
        $status = Resolve-WfSourceStatus -ReadErrorKind $read['ErrorKind'] -ReadErrorMessage $read['ErrorMessage'] -WindowStartUtc $global:WfSynthetic.Now.AddDays(-30)
        $status['Status'] | Should -BeExactly 'capture_failed'
        $status['Reason'] | Should -BeLike 'the read started and then failed: *The data is invalid*'
    }

    It 'reads the same records with the @SystemTime comparison the builder writes now' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'EventID=41' -Events @((New-WfSyntheticEvent -RecordId 5 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 3))
        $end = ConvertTo-WfMillisecondFloor -Value $global:WfSynthetic.Now
        $fixed = Build-WfEventQueryXml -Channel 'System' -Predicates @('(EventID=41)') -EndUtc $end -WindowMilliseconds 2592000000
        Test-WfSyntheticNumericTimediff -QueryXml $fixed | Should -BeFalse
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $read = Read-WfEventRecords -Channel 'System' -QueryXml $fixed -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $read['Ok'] | Should -BeTrue
        $read['Count'] | Should -Be 1
        $accumulator.Rows[0]['record_id'] | Should -Be 5
    }

    It 'applies the inclusive bound the query names, so a record outside the window is not read' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        $end = ConvertTo-WfMillisecondFloor -Value $global:WfSynthetic.Now
        Add-WfSyntheticQuery -Match 'EventID=41' -Events @(
            (New-WfSyntheticEvent -RecordId 1 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 45),
            (New-WfSyntheticEvent -RecordId 2 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 30),
            (New-WfSyntheticEvent -RecordId 3 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 3),
            (New-WfSyntheticEvent -RecordId 4 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 0)
        )
        $fixed = Build-WfEventQueryXml -Channel 'System' -Predicates @('(EventID=41)') -EndUtc $end -WindowMilliseconds 2592000000
        $bound = Get-WfSyntheticQueryBound -QueryXml $fixed
        $bound['End'] | Should -Be $end
        $bound['Start'] | Should -Be $end.AddDays(-30)
        $accumulator = New-WfRowAccumulator -MaxRows 10 -MaxBytes 1048576
        $read = Read-WfEventRecords -Channel 'System' -QueryXml $fixed -DeadlineUtc $global:WfSynthetic.Now.AddSeconds(60) -Accumulator $accumulator
        $read['Ok'] | Should -BeTrue
        @($accumulator.Rows | ForEach-Object { $_['record_id'] }) | Should -Be @(4, 3, 2)
    }

    It 'fails closed when a query carries a TimeCreated test the stand-in cannot parse' {
        Reset-WfSynthetic
        $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90
        Add-WfSyntheticQuery -Match 'EventID=41' -Events @((New-WfSyntheticEvent -RecordId 5 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -DaysAgo 3))
        $odd = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(EventID=41) and TimeCreated[@SystemTime &gt;= 1]]]</Select></Query></QueryList>'
        Get-WfSyntheticQueryBound -QueryXml $odd | Should -BeNullOrEmpty
        $reader = Open-WfEventReader -Channel 'System' -QueryXml $odd -Reverse $true
        $reader['Ok'] | Should -BeTrue
        { & $reader['ReadNext'] ([timespan]::FromSeconds(10)) } | Should -Throw '*cannot parse*'
    }

    It 'cuts a clock with sub-millisecond ticks to the millisecond before the query is built' {
        # Without the floor at the call site the builder refuses the end time
        # and the source is capture_failed; with it the run is a quiet window.
        Reset-WfSynthetic -Now ([datetime]::new(2026, 3, 1, 12, 0, 0, [System.DateTimeKind]::Utc).AddTicks(12345))
        $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq 'whea-errors-quiet' })[0]
        & $case['Setup']
        $run = Invoke-TestCollector -Collector 'whea-errors' -OutputDirectory (Join-Path $TestDrive 'sub-millisecond')
        $run.ExitCode | Should -Be 0
        $source = $run.Manifest.collectors[0]
        $source.enabled.options.query_accepted | Should -BeTrue
        $source.status | Should -Not -BeExactly 'capture_failed'
        $source.status | Should -BeExactly 'observed_zero'
        (ConvertFrom-WfUtcString -Text (Get-TestUtcText -Value $source.requested.options.window_end_utc)).Ticks % 10000 | Should -Be 0
        $query = [System.IO.File]::ReadAllText((Join-Path $TestDrive 'sub-millisecond/raw/system_whea_events/query.xml'))
        $query | Should -Match "@SystemTime &lt;= '2026-03-01T12:00:0\d\.001Z'"
    }

    It 'lets every event log collector read its channel end to end with the fixed form' {
        foreach ($name in @('bugcheck-history', 'whea-errors-quiet', 'application-errors', 'tdr-events-partial')) {
            Reset-WfSynthetic
            $case = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $name })[0]
            & $case['Setup']
            $run = Invoke-TestCollector -Collector $case['Collector'] -OutputDirectory (Join-Path $TestDrive ('fixed-form-' + $name)) -Arguments $case['Arguments']
            $run.ExitCode | Should -Be $case['ExitCode']
            foreach ($source in @($run.Manifest.collectors)) {
                [string]$source.status_reason | Should -Not -Match 'The data is invalid'
                $source.preflight.ok | Should -BeTrue
                $source.enabled.options.query_accepted | Should -BeTrue
            }
            foreach ($query in @(Get-ChildItem -Path (Join-Path $TestDrive ('fixed-form-' + $name)) -Recurse -Filter 'query.xml')) {
                $text = [System.IO.File]::ReadAllText($query.FullName)
                $text | Should -Not -Match 'timediff'
                $text | Should -Match "@SystemTime &gt;= '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z' and @SystemTime &lt;= '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z'"
            }
        }
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
        $out = Join-Path $TestDrive ('case-' + $Case)
        & $Setup $out
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
        Add-WfSyntheticQuery -Match "Provider[@Name='Display']" -Events @(
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
        $query.Contains("TimeCreated[@SystemTime &gt;= '" + (ConvertTo-WfXPathDateTime -Value (ConvertFrom-WfUtcString -Text $startText)) + "' and @SystemTime &lt;= '" + (ConvertTo-WfXPathDateTime -Value (ConvertFrom-WfUtcString -Text $endText)) + "']") | Should -BeTrue
        $query | Should -Not -Match 'timediff'
        # The recorded window end is on a whole millisecond, so the literal names the same instant.
        (ConvertFrom-WfUtcString -Text $endText).Ticks % 10000 | Should -Be 0
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

Describe 'config-snapshot sources against the synthetic backend' {
    BeforeAll {
        function Start-ConfigCase {
            param([string]$Case = 'config-snapshot')
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $Case })[0]
            & $selected['Setup']
        }
        function Get-ConfigSource {
            param($Run, [string]$Id)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
        }
        function Get-NativeCalls {
            # Wrapped so one match stays an array of one, and no match an empty array.
            param([string]$Name)
            return , @($global:WfSynthetic.NativeCalls | Where-Object { $_['Call'] -eq $Name })
        }
        $script:Gpu = 'PCI\VEN_FFFF&DEV_0001\4&1a2b3c4d&0&0008'
        $script:Affinity = 'Interrupt Management\Affinity Policy'
        $script:Msi = 'Interrupt Management\MessageSignaledInterruptProperties'
    }

    It 'turns a raw registry value into its type name, bytes and scalar, and omits string typed text' {
        $dword = ConvertFrom-WfRawRegistryValue -Name 'DevicePolicy' -Type 4 -Bytes ([byte[]](4, 0, 0, 0))
        $dword['kind'] | Should -BeExactly 'REG_DWORD'
        $dword['data'] | Should -Be 4
        $dword['bytes_hex'] | Should -BeExactly '04000000'
        $high = ConvertFrom-WfRawRegistryValue -Name 'x' -Type 4 -Bytes ([byte[]](0xFF, 0xFF, 0xFF, 0xFF))
        $high['data'] | Should -Be 4294967295
        $qword = ConvertFrom-WfRawRegistryValue -Name 'AssignmentSetOverride' -Type 11 -Bytes ([byte[]](1, 0, 0, 0, 0, 0, 0, 0x80))
        $qword['kind'] | Should -BeExactly 'REG_QWORD'
        $qword['data'] | Should -BeExactly '9223372036854775809' -Because 'a QWORD above int64 stays exact as text'
        $qword['bytes_hex'] | Should -BeExactly '0100000000000080'
        $binary = ConvertFrom-WfRawRegistryValue -Name 'AssignmentSetOverride' -Type 3 -Bytes ([byte[]](0x40, 0, 0, 0, 0, 0, 0, 0))
        $binary['kind'] | Should -BeExactly 'REG_BINARY'
        $binary['data'] | Should -BeExactly '4000000000000000'
        $zero = ConvertFrom-WfRawRegistryValue -Name 'MSISupported' -Type 4 -Bytes ([byte[]](0, 0, 0, 0))
        $zero['present'] | Should -BeTrue
        $zero['data'] | Should -Be 0
        $text = ConvertFrom-WfRawRegistryValue -Name 'Comment' -Type 1 -Bytes ([System.Text.Encoding]::Unicode.GetBytes('Jane Doe'))
        $text['data'] | Should -BeNullOrEmpty
        $text['bytes_hex'] | Should -BeNullOrEmpty
        $text['byte_count'] | Should -Be 16
        $text['omitted_reason'] | Should -Match 'free text'
        (ConvertTo-WfJson -Value $text) | Should -Not -Match '4a0061006e'
        $empty = ConvertFrom-WfRawRegistryValue -Name 'Empty' -Type 3 -Bytes ([byte[]]@())
        $empty['bytes_hex'] | Should -BeExactly ''
        $empty['byte_count'] | Should -Be 0
    }

    It 'opens the hardware key through the documented API with global scope, DIREG_DEV and KEY_READ, and relative read only subkeys' {
        Start-ConfigCase
        $r = Get-WfDeviceInterruptPolicy -InstanceId $script:Gpu -MaxValues 64 -MaxBytes 1048576
        $r['Ok'] | Should -BeTrue
        $r['Stage'] | Should -BeExactly 'read'
        $r['HardwareKey']['exists'] | Should -BeTrue
        $r['InterruptManagement']['exists'] | Should -BeTrue
        $leaves = @($r['Leaves'])
        $leaves.Count | Should -Be 2
        @($leaves[0]['values'] | ForEach-Object { $_['name'] }) | Should -Be @('DevicePolicy', 'AssignmentSetOverride', 'DevicePriority')
        @($leaves[0]['values'] | Where-Object { $_['name'] -eq 'AssignmentSetOverride' })[0]['bytes_hex'] | Should -BeExactly '2000000000000000'
        @($leaves[0]['values'] | Where-Object { $_['name'] -eq 'AssignmentSetOverride' })[0]['kind'] | Should -BeExactly 'REG_BINARY'
        $leaves[0]['enumeration_complete'] | Should -BeTrue
        # The recorder saw exactly the documented sequence and flags.
        $creates = Get-NativeCalls -Name 'SetupDiCreateDeviceInfoList'
        $creates.Count | Should -Be 1
        $creates[0]['Arguments'] | Should -Be @([IntPtr]::Zero, [IntPtr]::Zero)
        $opens = Get-NativeCalls -Name 'SetupDiOpenDeviceInfoW'
        $opens[0]['Arguments'][1] | Should -BeExactly $script:Gpu
        $opens[0]['Arguments'][3] | Should -Be 0 -Because 'OpenFlags 0, never DIOD_CANCEL_REMOVE'
        $keys = Get-NativeCalls -Name 'SetupDiOpenDevRegKey'
        $keys.Count | Should -Be 1
        $keys[0]['Arguments'][2] | Should -Be 1 -Because 'DICS_FLAG_GLOBAL'
        $keys[0]['Arguments'][3] | Should -Be 0 -Because 'HwProfile 0'
        $keys[0]['Arguments'][4] | Should -Be 1 -Because 'DIREG_DEV'
        $keys[0]['Arguments'][5] | Should -Be 131097 -Because 'KEY_READ, 0x20019'
        $relative = Get-NativeCalls -Name 'RegOpenKeyExW'
        @($relative | ForEach-Object { $_['Arguments'][1] }) | Should -Be @('Interrupt Management', $script:Affinity, $script:Msi)
        foreach ($call in $relative) { $call['Arguments'][2] | Should -Be 0; $call['Arguments'][3] | Should -Be 131097 }
        @($global:WfSynthetic.NativeCalls | ForEach-Object { $_['Call'] } | Sort-Object -Unique) | Should -Be @('RegCloseKey', 'RegEnumValueW', 'RegOpenKeyExW', 'SetupDiCreateDeviceInfoList', 'SetupDiDestroyDeviceInfoList', 'SetupDiOpenDeviceInfoW', 'SetupDiOpenDevRegKey')
        (Get-NativeCalls -Name 'SetupDiDestroyDeviceInfoList').Count | Should -Be 1
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0 -Because 'every key was closed and the set destroyed'
    }

    It 'tells a missing hardware key, a missing leaf, a missing value, a denied key and a gone device apart, and cleans up after each' {
        Start-ConfigCase
        # Missing hardware key: positively absent, both leaves absent, nothing opened under it.
        $global:WfSynthetic.DeviceKeys['PCI\M'] = @{ HardwareKey = 'missing' }
        $missing = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\M'
        $missing['Ok'] | Should -BeTrue
        $missing['HardwareKey']['exists'] | Should -BeFalse
        $missing['HardwareKey']['error_code'] | Should -Be 3758096900
        @($missing['Leaves'] | ForEach-Object { $_['exists'] }) | Should -Be @($false, $false)
        (Get-NativeCalls -Name 'RegOpenKeyExW').Count | Should -Be 0
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        # Missing leaf under an existing Interrupt Management: that leaf absent, the other read.
        $global:WfSynthetic.NativeCalls.Clear()
        $global:WfSynthetic.DeviceKeys['PCI\L'] = @{ HardwareKey = 'exists'; Subkeys = @{ $script:Msi = @{ Values = @(@{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](1, 0, 0, 0) }) } } }
        $leaf = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\L'
        $leaf['Ok'] | Should -BeTrue
        $leaf['InterruptManagement']['exists'] | Should -BeTrue
        $leaf['Leaves'][0]['exists'] | Should -BeFalse
        $leaf['Leaves'][1]['exists'] | Should -BeTrue
        @($leaf['Leaves'][1]['values']).Count | Should -Be 1
        # Missing Interrupt Management: both leaves absent without opening them.
        $global:WfSynthetic.NativeCalls.Clear()
        $global:WfSynthetic.DeviceKeys['PCI\N'] = @{ HardwareKey = 'exists'; Subkeys = @{} }
        $none = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\N'
        $none['Ok'] | Should -BeTrue
        $none['InterruptManagement']['exists'] | Should -BeFalse
        @($none['Leaves'] | ForEach-Object { $_['exists'] }) | Should -Be @($false, $false)
        (Get-NativeCalls -Name 'RegOpenKeyExW').Count | Should -Be 1
        # Denied hardware key: unknown, not absent, nothing under it touched, no stale handle.
        $global:WfSynthetic.NativeCalls.Clear()
        $global:WfSynthetic.DeviceKeys['PCI\D'] = @{ HardwareKey = 'denied' }
        $denied = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\D'
        $denied['Ok'] | Should -BeFalse
        $denied['Stage'] | Should -BeExactly 'open_hardware_key'
        $denied['ErrorCode'] | Should -Be 5
        $denied['HardwareKey']['exists'] | Should -BeNullOrEmpty
        @($denied['Leaves'] | ForEach-Object { $_['exists'] }) | Should -Be @($null, $null)
        (Get-NativeCalls -Name 'RegOpenKeyExW').Count | Should -Be 0
        (Get-NativeCalls -Name 'SetupDiDestroyDeviceInfoList').Count | Should -Be 1
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        # Denied leaf among readable ones: that leaf unknown with its code, the other read.
        $global:WfSynthetic.DeviceKeys['PCI\DL'] = @{ HardwareKey = 'exists'; Subkeys = @{ $script:Affinity = @{ Values = @(); Denied = $true }; $script:Msi = @{ Values = @(@{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](1, 0, 0, 0) }) } } }
        $deniedLeaf = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\DL'
        $deniedLeaf['Ok'] | Should -BeTrue
        $deniedLeaf['Leaves'][0]['exists'] | Should -BeNullOrEmpty
        $deniedLeaf['Leaves'][0]['error_code'] | Should -Be 5
        $deniedLeaf['Leaves'][1]['exists'] | Should -BeTrue
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        # A device that is gone: unknown at the open stage.
        $gone = Get-WfDeviceInterruptPolicy -InstanceId 'PCI\NOPE'
        $gone['Ok'] | Should -BeFalse
        $gone['Stage'] | Should -BeExactly 'open_device'
        $gone['ErrorCode'] | Should -Be 3758096907
        $gone['DeviceOpened'] | Should -BeFalse
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        # An empty id never opens the root device.
        $empty = Get-WfDeviceInterruptPolicy -InstanceId ''
        $empty['Stage'] | Should -BeExactly 'argument'
        $opened = Get-NativeCalls -Name 'SetupDiOpenDeviceInfoW'
        @($opened | Where-Object { -not $_['Arguments'][1] }).Count | Should -Be 0
        # A declaration that does not compile: unknown at the compile stage, no native call at all.
        $global:WfSynthetic.NativeCalls.Clear()
        $global:WfSynthetic.DeviceKeyCompile = 'fail'
        $compile = Get-WfDeviceInterruptPolicy -InstanceId $script:Gpu
        $compile['Ok'] | Should -BeFalse
        $compile['Stage'] | Should -BeExactly 'compile'
        $global:WfSynthetic.NativeCalls.Count | Should -Be 0
    }

    It 'grows the buffer on ERROR_MORE_DATA, stops at the value cap and at the deadline, and never calls unvisited values absent' {
        Start-ConfigCase
        $nic = 'PCI\VEN_FFF0&DEV_8125\4&3a2b1c0d&0&00E0'
        $r = Get-WfDeviceInterruptPolicy -InstanceId $nic -MaxValues 64 -MaxBytes 1048576
        $r['Leaves'][0]['enumeration_complete'] | Should -BeTrue
        @($r['Leaves'][0]['values']).Count | Should -Be 2
        $enumerations = Get-NativeCalls -Name 'RegEnumValueW'
        @($enumerations | Where-Object { $_['Arguments'][1] -eq 0 }).Count | Should -BeGreaterThan 1 -Because 'the first value was asked for twice, once with a larger buffer'
        # A value above the byte cap stops the enumeration and says so (the recorder answers ERROR_MORE_DATA once per value per reset).
        $global:WfSynthetic.NativeMoreDataSeen.Clear()
        $capped = Get-WfDeviceInterruptPolicy -InstanceId $nic -MaxValues 64 -MaxBytes 4096
        $capped['Leaves'][0]['enumeration_complete'] | Should -BeFalse
        $capped['Leaves'][0]['error'] | Should -Match 'above the cap'
        # The value cap.
        $few = Get-WfDeviceInterruptPolicy -InstanceId $script:Gpu -MaxValues 1 -MaxBytes 1048576
        $few['Leaves'][0]['enumeration_complete'] | Should -BeFalse
        @($few['Leaves'][0]['values']).Count | Should -Be 1
        $few['Leaves'][0]['error'] | Should -Match 'cap of 1 values'
        # The deadline, passing while values are enumerated.
        $global:WfSynthetic.DeviceKeys[$script:Gpu]['Subkeys'][$script:Affinity]['SecondsPerValue'] = 30
        $slow = Get-WfDeviceInterruptPolicy -InstanceId $script:Gpu -MaxValues 64 -MaxBytes 1048576 -DeadlineUtc ((Get-WfUtcNow).AddSeconds(45))
        $slow['Ok'] | Should -BeFalse
        $slow['Stage'] | Should -BeExactly 'timeout'
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0 -Because 'the handles are released on the timeout path too'
    }

    It 'records every PCI function with its hardware key read through the API, absence as absence, and selects no codec or USB child' {
        Start-ConfigCase
        $keysBefore = $global:WfSynthetic.Registry.Count
        $out = Join-Path $TestDrive 'policy'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial' -Because 'two questions have no documented read only path'
        $source = Get-ConfigSource -Run $run -Id 'interrupt_policy'
        $source.status | Should -BeExactly 'observed'
        $source.enabled.options.keys_read | Should -Be 8
        $source.enabled.options.keys_absent | Should -Be 2
        $source.enabled.options.keys_unknown | Should -Be 0
        @($source.command) | Should -Contain 'SetupDiOpenDevRegKey'
        ($source.requested.options | ConvertTo-Json -Depth 5) | Should -Not -Match 'Enum\\\\'
        $devices = Get-Content -LiteralPath (Join-Path $out 'raw/interrupt_policy/keys.json') -Raw | ConvertFrom-Json
        @($devices).Count | Should -Be 5
        @($devices | ForEach-Object { $_.instance_id } | Where-Object { $_ -notlike 'PCI\*' }).Count | Should -Be 0
        @($devices | ForEach-Object { $_.class } | Sort-Object -Unique) | Should -Be @('Display', 'Net', 'SCSIAdapter', 'System', 'USB')
        $gpu = @($devices | Where-Object { $_.class -eq 'Display' })[0]
        $gpu.device_key.resolver | Should -BeExactly 'SetupDiOpenDevRegKey'
        $gpu.device_key.access | Should -BeExactly 'KEY_READ'
        $gpu.stage | Should -BeExactly 'read'
        $affinity = @($gpu.interrupt_keys | Where-Object { $_.subkey -like '*Affinity Policy' })[0]
        $affinity.exists | Should -BeTrue
        @($affinity.values | ForEach-Object { $_.name }) | Should -Be @('DevicePolicy', 'AssignmentSetOverride', 'DevicePriority')
        @($affinity.values | Where-Object { $_.name -eq 'AssignmentSetOverride' })[0].bytes_hex | Should -BeExactly '2000000000000000'
        @($affinity.values | Where-Object { $_.name -eq 'AssignmentSetOverride' })[0].kind | Should -BeExactly 'REG_BINARY'
        $audio = @($devices | Where-Object { $_.service -eq 'HDAudBus' })[0]
        $audio.problem_code | Should -Be 22
        $audio.status | Should -BeExactly 'Error'
        @($audio.interrupt_keys | Where-Object { $_.subkey -like '*Affinity Policy' })[0].exists | Should -BeFalse
        @($audio.interrupt_keys | Where-Object { $_.subkey -like '*Affinity Policy' })[0].error_code | Should -BeNullOrEmpty -Because 'absent is not an error'
        $xhci = @($devices | Where-Object { $_.service -eq 'USBXHCI' })[0]
        $comment = @(@($xhci.interrupt_keys)[0].values | Where-Object { $_.name -eq 'Comment' })[0]
        $comment.omitted_reason | Should -Match 'free text'
        [System.IO.File]::ReadAllText((Join-Path $out 'raw/interrupt_policy/keys.json')) | Should -Not -Match 'Synthetic Owner|7300650074' -Because 'a string value leaves neither as text nor as hex'
        $tdr = Get-Content -LiteralPath (Join-Path $out 'raw/graphics_tdr/keys.json') -Raw | ConvertFrom-Json
        @($tdr).Count | Should -Be 1
        @($tdr[0].values | Where-Object { $_.present }).Count | Should -Be 2
        @($tdr[0].values | ForEach-Object { $_.name }) | Should -Not -Contain 'HwSchMode' -Because 'only the documented value names are read from a fixed key'
        $global:WfSynthetic.Registry.Count | Should -Be $keysBefore
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        @($global:WfSynthetic.NativeCalls | Where-Object { $_['Call'] -eq 'SetupDiOpenDevRegKey' }).Count | Should -Be 5
    }

    It 'never writes a Bluetooth peer name or address in clear, even when such a device is selected' {
        Start-ConfigCase
        $earbuds = 'BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_VID&0001004c_PID&200e\7&1a2b3c4d&0&F0F1F2000001_C00000000'
        $out = Join-Path $TestDrive 'bt-excluded'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        foreach ($file in @(Get-ChildItem -LiteralPath $out -File -Recurse)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            $text.Contains('Jane Doe') | Should -BeFalse -Because ($file.Name + ' must not carry the peer name')
            $text.Contains('F0F1F2000001') | Should -BeFalse -Because ($file.Name + ' must not carry the peer address')
        }
        # Force the selection to include the peer (a definition that selected class MEDIA would): the row leaves protected.
        $global:WfSynthetic.DeviceKeys[$earbuds] = @{ HardwareKey = 'exists'; Subkeys = @{} }
        $definition = @{ Name = 'config-snapshot'; Version = '0.0.0'; Question = 'test'; Sources = @(
                @{ Id = 'interrupt_policy'; Type = 'registry'; Mode = 'devices'; Kind = 'config_snapshot'; Required = $true; InstancePrefixes = @('PCI\'); Classes = @('MEDIA'); Expectation = 'test' }
            ) }
        $out2 = Join-Path $TestDrive 'bt-selected'
        $null = Invoke-WfCollectorScript -Definition $definition -OutputDirectory $out2
        $text = [System.IO.File]::ReadAllText((Join-Path $out2 'raw/interrupt_policy/keys.json'))
        $text | Should -Not -Match 'Jane Doe|F0F1F2000001'
        $rows = Get-Content -LiteralPath (Join-Path $out2 'raw/interrupt_policy/keys.json') -Raw | ConvertFrom-Json
        $peer = @($rows | Where-Object { $_.instance_id -like 'BTHENUM\*' })[0]
        $peer.name | Should -Match '^name-[0-9a-f]{12}$'
        $peer.instance_id | Should -Match 'mac-[0-9a-f]{12}'
        (Get-Content -LiteralPath (Join-Path $out2 'raw/interrupt_policy/result.json') -Raw | ConvertFrom-Json).peer_nodes_pseudonymised | Should -Be 1
        $manifest = Get-Content -LiteralPath (Join-Path $out2 'manifest.json') -Raw | ConvertFrom-Json
        @($manifest.notes | Where-Object { $_ -match 'pseudonyms' }).Count | Should -Be 1
    }

    It 'records a denied hardware key among readable ones as unknown, and the whole source as not_collected when none opens' {
        Start-ConfigCase 'config-snapshot-denied'
        $out = Join-Path $TestDrive 'policy-denied'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $run.ExitCode | Should -Be 1
        $source = Get-ConfigSource -Run $run -Id 'interrupt_policy'
        $source.status | Should -BeExactly 'not_collected'
        $source.status_reason | Should -Match 'none of the 5 selected devices could be read'
        $source.status_reason | Should -Match 'ERROR_ACCESS_DENIED'
        Test-Path -LiteralPath (Join-Path $out 'raw/interrupt_policy/keys.json') | Should -BeFalse
        (Get-ConfigSource -Run $run -Id 'graphics_tdr').status | Should -BeExactly 'not_collected'
        (Get-ConfigSource -Run $run -Id 'logical_processor_map').status | Should -BeExactly 'not_collected'
        (Get-ConfigSource -Run $run -Id 'logical_processor_map').status_reason | Should -Match 'stage compile'
        $global:WfSynthetic.NativeHandles.Count | Should -Be 0
        Start-ConfigCase
        $global:WfSynthetic.DeviceKeys[$script:Gpu] = @{ HardwareKey = 'denied' }
        $out2 = Join-Path $TestDrive 'policy-one-denied'
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out2
        $source2 = Get-ConfigSource -Run $run2 -Id 'interrupt_policy'
        $source2.status | Should -BeExactly 'observed'
        $source2.enabled.options.keys_unknown | Should -Be 2
        $devices = Get-Content -LiteralPath (Join-Path $out2 'raw/interrupt_policy/keys.json') -Raw | ConvertFrom-Json
        $denied = @($devices | Where-Object { $_.class -eq 'Display' })[0]
        $denied.stage | Should -BeExactly 'open_hardware_key'
        $denied.error_code | Should -Be 5
        $denied.hardware_key_state.exists | Should -BeNullOrEmpty
        @($denied.interrupt_keys | ForEach-Object { $_.exists }) | Should -Be @($null, $null) -Because 'nothing under an unreadable key is called absent'
        @($run2.Manifest.notes | Where-Object { $_ -match 'could not be read' }).Count | Should -Be 1
        # A declaration that does not compile makes the source not_collected at preflight, with no element written.
        Start-ConfigCase
        $global:WfSynthetic.DeviceKeyCompile = 'fail'
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'policy-compile')
        (Get-ConfigSource -Run $run3 -Id 'interrupt_policy').status | Should -BeExactly 'not_collected'
        (Get-ConfigSource -Run $run3 -Id 'interrupt_policy').status_reason | Should -Match 'compiled or loaded'
        Test-Path -LiteralPath (Join-Path $TestDrive 'policy-compile/raw/interrupt_policy/keys.json') | Should -BeFalse
    }

    It 'parses a GetLogicalProcessorInformationEx buffer by the documented layouts, with interleaved siblings and two groups' {
        $buffer = New-WfSyntheticLpiBuffer -Cores 6 -Groups 1 -Interleaved $true
        $records = ConvertFrom-WfLogicalProcessorInformation -Bytes $buffer
        @($records | Where-Object { $_['relationship'] -eq 0 }).Count | Should -Be 6
        $core0 = @($records | Where-Object { $_['relationship'] -eq 0 })[0]
        $core0['smt'] | Should -BeTrue
        @($core0['group_masks'][0]['processors']) | Should -Be @(0, 6) -Because 'the siblings are interleaved, not adjacent'
        $core0['group_masks'][0]['mask_hex'] | Should -BeExactly '0x41'
        $l3 = @($records | Where-Object { $_['relationship'] -eq 2 -and $_['level'] -eq 3 })[0]
        $l3['cache_size'] | Should -Be 33554432
        $l3['cache_type_name'] | Should -BeExactly 'CacheUnified'
        @($l3['group_masks'][0]['processors']).Count | Should -Be 12
        $group = @($records | Where-Object { $_['relationship'] -eq 4 })[0]
        $group['active_group_count'] | Should -Be 1
        $group['groups'][0]['active_processor_count'] | Should -Be 12
        $group['groups'][0]['active_mask_hex'] | Should -BeExactly '0xfff'
        $two = ConvertFrom-WfLogicalProcessorInformation -Bytes (New-WfSyntheticLpiBuffer -Cores 2 -Groups 2 -Interleaved $false)
        @($two | Where-Object { $_['relationship'] -eq 0 } | ForEach-Object { $_['group_masks'][0]['group'] }) | Should -Be @(0, 0, 1, 1)
        @($two | Where-Object { $_['relationship'] -eq 0 })[0]['group_masks'][0]['processors'] | Should -Be @(0, 1)
        @($two | Where-Object { $_['relationship'] -eq 4 })[0]['groups'].Count | Should -Be 2
        # A record that runs past the buffer, or trailing bytes, is a parse failure, never a partial topology.
        $cut = New-Object byte[] ($buffer.Length - 5)
        [System.Array]::Copy($buffer, $cut, $cut.Length)
        { ConvertFrom-WfLogicalProcessorInformation -Bytes $cut } | Should -Throw -ExpectedMessage '*does not fit the buffer*'
        $padded = New-Object byte[] ($buffer.Length + 3)
        [System.Array]::Copy($buffer, $padded, $buffer.Length)
        { ConvertFrom-WfLogicalProcessorInformation -Bytes $padded } | Should -Throw -ExpectedMessage '*trailing bytes*'
        # An unknown relationship is kept as bytes.
        $odd = New-WfSyntheticLpiRecord -Relationship 8 -Body ([byte[]](1, 2, 3, 4))
        $kept = ConvertFrom-WfLogicalProcessorInformation -Bytes $odd
        $kept[0]['body_hex'] | Should -BeExactly '01020304'
        $kept[0]['relationship_name'] | Should -BeExactly 'RelationProcessorSharedComputeUnit'
    }

    It 'writes the topology as an observed source, and fails closed on a bad call, a 32 bit host, a malformed buffer or no core record' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'topology'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $source = Get-ConfigSource -Run $run -Id 'logical_processor_map'
        $source.status | Should -BeExactly 'observed'
        $source.enabled.options.cores | Should -Be 6
        $source.enabled.options.records | Should -Be 28
        $records = Get-Content -LiteralPath (Join-Path $out 'raw/logical_processor_map/topology.json') -Raw | ConvertFrom-Json
        @($records).Count | Should -Be 28
        $report = Get-Content -LiteralPath (Join-Path $out 'raw/logical_processor_map/result.json') -Raw | ConvertFrom-Json
        $report.buffer_hex.Length | Should -Be (2 * $report.byte_count)
        $report.record_counts.RelationProcessorCore | Should -Be 6
        Start-ConfigCase
        $global:WfSynthetic.Topology = @{ Stage = 'read'; ErrorCode = 1450; ErrorMessage = 'the call returned FALSE' }
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'topology-fail')
        (Get-ConfigSource -Run $run2 -Id 'logical_processor_map').status | Should -BeExactly 'capture_failed'
        (Get-ConfigSource -Run $run2 -Id 'logical_processor_map').status_reason | Should -Match 'Win32 error 1450'
        Test-Path -LiteralPath (Join-Path $TestDrive 'topology-fail/raw/logical_processor_map/topology.json') | Should -BeFalse
        Start-ConfigCase
        $global:WfSynthetic.Topology = @{ Bytes = (New-WfSyntheticLpiBuffer -Cores 2); PointerSize = 4 }
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'topology-32')
        (Get-ConfigSource -Run $run3 -Id 'logical_processor_map').status | Should -BeExactly 'unsupported'
        Start-ConfigCase
        $global:WfSynthetic.Topology = @{ Bytes = [byte[]](0, 0, 0, 0, 200, 0, 0, 0) }
        $run4 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'topology-bad')
        (Get-ConfigSource -Run $run4 -Id 'logical_processor_map').status | Should -BeExactly 'capture_failed'
        (Get-ConfigSource -Run $run4 -Id 'logical_processor_map').status_reason | Should -Match 'documented layout'
        Start-ConfigCase
        $global:WfSynthetic.Topology = @{ Bytes = (New-WfSyntheticLpiRecord -Relationship 4 -Body (New-Object byte[] 24)) }
        $run5 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'topology-nocore')
        (Get-ConfigSource -Run $run5 -Id 'logical_processor_map').status_reason | Should -Match 'no RelationProcessorCore record'
    }

    It 'replaces user profile folder names, e-mail shaped tokens, UNC hosts and addresses in copied text, and keeps the standard folders' {
        $text = "a=C:\Users\Jane Doe\Games\x.exe`r`nb=C:\\Users\\Jane Doe\\Desktop`r`nc=C:\Users\Public\Desktop`r`nd=/Users/janedoe/x`r`nmail=jane.doe@example.test`r`nmac=02:11:22:33:44:55`r`nshare=\\DESKTOP-JANE01\share\x`r`njson=`"\\\\DESKTOP-JANE01\\share`"`r`nkey=HKLM\\SYSTEM\\CurrentControlSet\\Enum`r`n"
        $r = Protect-WfCopiedText -Text $text -Salt 'test-salt'
        $r['Text'] | Should -Not -Match 'Jane Doe|janedoe|jane\.doe@|02:11:22|DESKTOP-JANE01'
        $r['Text'] | Should -Match 'a=C:\\Users\\user-[0-9a-f]{12}\\Games\\x\.exe'
        $r['Text'] | Should -Match 'b=C:\\\\Users\\\\user-[0-9a-f]{12}\\\\Desktop'
        $r['Text'] | Should -Match 'c=C:\\Users\\Public\\Desktop'
        $r['Text'] | Should -Match 'mail=mail-[0-9a-f]{12}'
        $r['Text'] | Should -Match 'mac=mac-[0-9a-f]{12}'
        $r['Text'] | Should -Match 'share=\\\\host-[0-9a-f]{12}\\share\\x'
        $r['Text'] | Should -Match 'json="\\\\\\\\host-[0-9a-f]{12}\\\\share"'
        $r['Text'] | Should -Match 'key=HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum' -Because 'an escaped separator pair inside a path is not a UNC root'
        $r['Text'] | Should -Match "`r`n" -Because 'line endings are kept as they are'
        $r['UserCount'] | Should -Be 3
        $r['MailCount'] | Should -Be 1
        $r['HostCount'] | Should -Be 2
        $r['MacCount'] | Should -Be 1
        $one = ConvertTo-WfPseudonym -Kind 'user' -Value 'jane doe' -Salt 'test-salt'
        @([regex]::Matches($r['Text'], [regex]::Escape($one))).Count | Should -Be 2
    }

    It 'replaces a profile folder name that ends at a character a folder name cannot hold' {
        $cases = @('<p>C:\Users\alice</p>', 'a=C:\Users\alice|b', 'C:\Users\alice>out.txt', 'C:\Users\alice:stream', 'C:\Users\alice?', 'C:\Users\alice*', 'cannot write C:\\Users\\alice: access denied')
        foreach ($case in $cases) {
            $r = Protect-WfCopiedText -Text $case -Salt 'test-salt'
            $r['Text'] | Should -Not -Match 'alice' -Because $case
            $r['Text'] | Should -Match 'Users[\\]{1,2}user-[0-9a-f]{12}' -Because $case
            $r['UserCount'] | Should -Be 1 -Because $case
        }
        $kept = Protect-WfCopiedText -Text '<p>C:\Users\Public</p> C:\Users\Default User|x C:\Users\All Users:y' -Salt 'test-salt'
        $kept['UserCount'] | Should -Be 0
        $kept['Text'] | Should -BeExactly '<p>C:\Users\Public</p> C:\Users\Default User|x C:\Users\All Users:y'
    }

    It 'decodes text by its byte order mark and says so' {
        $utf16 = [byte[]](0xFF, 0xFE) + [System.Text.Encoding]::Unicode.GetBytes('x=1')
        $d = ConvertFrom-WfTextBytes -Bytes $utf16
        $d['Text'] | Should -BeExactly 'x=1'
        $d['Encoding'] | Should -BeExactly 'utf-16le'
        $d['HadByteOrderMark'] | Should -BeTrue
        $plain = ConvertFrom-WfTextBytes -Bytes ([System.Text.Encoding]::ASCII.GetBytes('y=2'))
        $plain['Encoding'] | Should -BeExactly 'utf-8'
        $plain['HadByteOrderMark'] | Should -BeFalse
    }

    It 'writes a map with an entry named keys or values as plain members' {
        (ConvertTo-WfJson -Value ([ordered]@{ keys = @(1); values = 'v'; count = 2 })) | Should -BeExactly '{"keys":[1],"values":"v","count":2}'
    }

    It 'protects the timer helper command line and image path at the collection boundary' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'helper'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        foreach ($file in @(Get-ChildItem -LiteralPath $out -File -Recurse)) {
            [System.IO.File]::ReadAllText($file.FullName).Contains('Synthetic Owner') | Should -BeFalse -Because ($file.Name + ' must not carry the profile name')
        }
        $records = Get-Content -LiteralPath (Join-Path $out 'raw/timer_helper_process/records.json') -Raw | ConvertFrom-Json
        $records[0].CommandLine | Should -Match '^"C:\\Users\\user-[0-9a-f]{12}\\Downloads\\Stutter Guard\\DpcTimerRes\.exe" 10000$'
        $records[0].ExecutablePath | Should -Match '^C:\\Users\\user-[0-9a-f]{12}\\Downloads\\Stutter Guard\\DpcTimerRes\.exe$'
        $source = Get-ConfigSource -Run $run -Id 'timer_helper_process'
        $source.requested.options.protected_properties | Should -Be @('CommandLine', 'ExecutablePath')
        $source.enabled.options.protection.user_profile_names_replaced | Should -Be 2
        @($run.Manifest.notes | Where-Object { $_ -match 'Copied text' }).Count | Should -Be 1
    }

    It 'copies the owner files with pseudonyms and the hash of the original, and keeps an unchanged file verbatim' {
        Start-ConfigCase
        $global:WfSynthetic.Files['C:\ProgramData\Stutter Guard\journal.json'] = @{ Text = '{"records":[]}' }
        $out = Join-Path $TestDrive 'copies'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        foreach ($file in @(Get-ChildItem -LiteralPath $out -File -Recurse)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            $text.Contains('Synthetic Owner') | Should -BeFalse -Because ($file.Name + ' must not carry the user profile name')
            $text.Contains('owner@example.test') | Should -BeFalse -Because ($file.Name + ' must not carry the e-mail address')
            $text.Contains('DESKTOP-SYNTH01') | Should -BeFalse -Because ($file.Name + ' must not carry the computer name')
        }
        $ini = [System.IO.File]::ReadAllText((Join-Path $out 'raw/process_lasso_config/prolasso.ini'))
        $ini | Should -Match 'ExcludedProcesses=C:\\Users\\user-[0-9a-f]{12}\\Games\\launcher\.exe'
        $ini | Should -Match 'SupportContact=mail-[0-9a-f]{12}'
        $ini | Should -Match 'ConfigPath=\\\\host-[0-9a-f]{12}\\ProcessLasso\\config'
        $ini | Should -Match 'TargetPowerPlan=Synthetic Low Latency'
        $report = Get-Content -LiteralPath (Join-Path $out 'raw/process_lasso_config/result.json') -Raw | ConvertFrom-Json
        $report.protection.user_profile_names_replaced | Should -Be 2
        $report.protection.email_addresses_replaced | Should -Be 1
        $report.protection.unc_hosts_replaced | Should -Be 1
        $report.copy_is_verbatim | Should -BeFalse
        $report.source_sha256 | Should -BeExactly (Get-WfSha256OfText -Text $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\config\prolasso.ini']['Text'])
        $source = Get-ConfigSource -Run $run -Id 'process_lasso_config'
        $source.enabled.options.content_kept | Should -BeTrue
        $source.requested.options.timeout_seconds | Should -Be 50
        $journal = Get-Content -LiteralPath (Join-Path $out 'raw/stutter_guard_journal/result.json') -Raw | ConvertFrom-Json
        $journal.copy_is_verbatim | Should -BeTrue
        $journal.source_sha256 | Should -BeExactly (Get-TestSha256 -Path (Join-Path $out 'raw/stutter_guard_journal/journal.json'))
        $log = Get-ConfigSource -Run $run -Id 'process_lasso_log'
        @($log.requested.options.path_candidates).Count | Should -Be 3
        $log.enabled.options.path | Should -BeExactly 'C:\ProgramData\ProcessLasso\logs\processlasso.log'
        $log.requested.options.mode | Should -BeExactly 'summary'
    }

    It 'summarises the vendor log and lets no line of it into the bundle, whatever the INI says' {
        $text = "-password=x`r`n'C:\a\game.exe' -token=abc`r`ngame.exe; -key s3cr3t`r`n"
        foreach ($case in @(@{ Name = 'off'; Replace = 'IncludeCommandLines=false' }, @{ Name = 'on'; Replace = 'IncludeCommandLines=true' }, @{ Name = 'missing'; Replace = 'LogDisable=false' }, @{ Name = 'noini'; Replace = $null })) {
            Start-ConfigCase
            if ($null -eq $case['Replace']) {
                $global:WfSynthetic.Files.Remove('C:\ProgramData\ProcessLasso\config\prolasso.ini')
            } else {
                $ini = $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\config\prolasso.ini']['Text']
                $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\config\prolasso.ini'] = @{ Text = $ini.Replace('IncludeCommandLines=false', [string]$case['Replace']) }
            }
            $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\logs\processlasso.log'] = @{ Text = $text }
            $out = Join-Path $TestDrive ('log-' + $case['Name'])
            $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
            $log = Get-ConfigSource -Run $run -Id 'process_lasso_log'
            $log.status | Should -BeExactly 'observed' -Because $case['Name']
            $log.requested.options.mode | Should -BeExactly 'summary'
            $log.requested.options.PSObject.Properties.Name | Should -Not -Contain 'copy_gate'
            $log.requested.options.protection | Should -BeNullOrEmpty
            $log.enabled.options.content_kept | Should -BeFalse
            foreach ($file in @(Get-ChildItem -LiteralPath $out -File -Recurse)) {
                $content = [System.IO.File]::ReadAllText($file.FullName)
                foreach ($secret in @('password', 'token=abc', 's3cr3t')) {
                    $content.Contains($secret) | Should -BeFalse -Because ($file.Name + ' must not carry ' + $secret)
                }
            }
            @(Get-ChildItem -LiteralPath (Join-Path $out 'raw/process_lasso_log') -File | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('log-summary.json', 'result.json', 'source.json')
            $summary = Get-Content -LiteralPath (Join-Path $out 'raw/process_lasso_log/log-summary.json') -Raw | ConvertFrom-Json
            @($summary.PSObject.Properties.Name | Sort-Object) | Should -Be @('address_tokens', 'bytes', 'content_kept', 'creation_time_utc', 'last_write_time_utc', 'lines', 'path', 'sha256')
            $summary.content_kept | Should -BeFalse
            $summary.bytes | Should -Be $text.Length
            $summary.lines | Should -Be 4
            $summary.sha256 | Should -BeExactly (Get-WfSha256OfText -Text $text)
            $summary.creation_time_utc | Should -Not -BeNullOrEmpty
            $summary.last_write_time_utc | Should -Not -BeNullOrEmpty
            $report = Get-Content -LiteralPath (Join-Path $out 'raw/process_lasso_log/result.json') -Raw | ConvertFrom-Json
            $report.summarised | Should -BeTrue
            $report.copied | Should -BeFalse
            $report.protection | Should -BeNullOrEmpty
            $report.why | Should -Match 'command line arguments'
            @($run.Manifest.notes | Where-Object { $_ -match 'process_lasso_log' -and $_ -match 'summarised, not copied' }).Count | Should -Be 1
        }
    }

    It 'finds the log at an alternate candidate and reports a missing file with every candidate tried' {
        Start-ConfigCase
        $text = $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\logs\processlasso.log']
        $global:WfSynthetic.Files.Remove('C:\ProgramData\ProcessLasso\logs\processlasso.log')
        $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\logs\prolasso.log'] = $text
        $out = Join-Path $TestDrive 'alternate'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $log = Get-ConfigSource -Run $run -Id 'process_lasso_log'
        $log.status | Should -BeExactly 'observed'
        $log.enabled.options.path | Should -BeExactly 'C:\ProgramData\ProcessLasso\logs\prolasso.log'
        Test-Path -LiteralPath (Join-Path $out 'raw/process_lasso_log/log-summary.json') | Should -BeTrue -Because 'the primary keeps the definition''s file name'
        Start-ConfigCase 'config-snapshot-clean'
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'no-log')
        $missing = Get-ConfigSource -Run $run2 -Id 'process_lasso_log'
        $missing.status | Should -BeExactly 'not_collected'
        $missing.status_reason | Should -Match 'processlasso\.log or .*prolasso\.log or .*prolasso\.log'
        $missing.status_reason | Should -Match 'Configure Startup'
    }

    It 'enforces the per source deadline on a slow file, a slow last folder entry and a slow fixed key, and keeps no primary' {
        Start-ConfigCase
        $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\config\prolasso.ini']['SecondsToRead'] = 120
        $out = Join-Path $TestDrive 'slow-file'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $slow = Get-ConfigSource -Run $run -Id 'process_lasso_config'
        $slow.status | Should -BeExactly 'capture_failed'
        $slow.status_reason | Should -Match 'timed out'
        Test-Path -LiteralPath (Join-Path $out 'raw/process_lasso_config/prolasso.ini') | Should -BeFalse
        Start-ConfigCase
        $global:WfSynthetic.Directories['C:\Program Files\Stutter Guard']['SecondsPerFile'] = 40
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'slow-folder')
        $folder = Get-ConfigSource -Run $run2 -Id 'stutter_guard_install'
        $folder.status | Should -BeExactly 'capture_failed'
        $folder.status_reason | Should -Match 'timed out'
        Test-Path -LiteralPath (Join-Path $TestDrive 'slow-folder/raw/stutter_guard_install/listing.json') | Should -BeFalse
        Start-ConfigCase
        $global:WfSynthetic.Registry['HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers']['SecondsToRead'] = 120
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'slow-key')
        $key = Get-ConfigSource -Run $run3 -Id 'graphics_tdr'
        $key.status | Should -BeExactly 'capture_failed'
        $key.status_reason | Should -Match 'timed out'
        Test-Path -LiteralPath (Join-Path $TestDrive 'slow-key/raw/graphics_tdr/keys.json') | Should -BeFalse
    }

    It 'lists install folders as arrays without copying and calls a missing folder an observation' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'installs'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $source = Get-ConfigSource -Run $run -Id 'process_lasso_install'
        $source.status | Should -BeExactly 'observed'
        $files = Get-Content -LiteralPath (Join-Path $out 'raw/process_lasso_install/listing.json') -Raw | ConvertFrom-Json
        @($files | ForEach-Object { $_.name }) | Should -Contain 'ProcessGovernor.exe'
        @($files | Where-Object { $_.name -eq 'ProcessLasso.exe' })[0].file_version | Should -BeExactly '19.0.0.94'
        $report = Get-Content -LiteralPath (Join-Path $out 'raw/process_lasso_install/result.json') -Raw | ConvertFrom-Json
        $report.exists | Should -BeTrue
        $report.parent_exists | Should -BeTrue
        $report.file_count | Should -Be 6
        @(Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object { $_.Extension -eq '.exe' }).Count | Should -Be 0
        Start-ConfigCase 'config-snapshot-clean'
        $out2 = Join-Path $TestDrive 'no-installs'
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out2
        $absent = Get-ConfigSource -Run $run2 -Id 'stutter_guard_install'
        $absent.status | Should -BeExactly 'observed_zero'
        $absent.raw_time_range | Should -Not -BeNullOrEmpty
        (Get-Content -LiteralPath (Join-Path $out2 'raw/stutter_guard_install/listing.json') -Raw).Trim() | Should -BeExactly '[]'
        (Get-Content -LiteralPath (Join-Path $out2 'raw/stutter_guard_install/result.json') -Raw | ConvertFrom-Json).exists | Should -BeFalse
        @($run2.Manifest.notes | Where-Object { $_ -match 'nothing is installed at' }).Count | Should -Be 2
        Start-ConfigCase
        $global:WfSynthetic.Directories['C:\Program Files\Stutter Guard'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access to the path is denied.' }
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'denied-folder')
        (Get-ConfigSource -Run $run3 -Id 'stutter_guard_install').status | Should -BeExactly 'not_collected'
        Start-ConfigCase
        $run4 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'capped-folder') -Arguments @{ MaxEvents = 3 }
        $capped = Get-ConfigSource -Run $run4 -Id 'process_lasso_install'
        $capped.status | Should -BeExactly 'capture_failed'
        $capped.status_reason | Should -Match 'cap of 3 files'
    }

    It 'runs only the powercfg listings, records a failing one, and a missing tool as not_collected' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'power'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        $powercfg = @($global:WfSynthetic.Processes | Where-Object { $_['FilePath'] -like '*powercfg.exe' } | ForEach-Object { $_['Arguments'] })
        @($powercfg | Sort-Object) | Should -Be @('/aliases', '/getactivescheme', '/list', '/qh', '/query')
        @($global:WfSynthetic.Processes | Where-Object { $_['FilePath'] -notlike '*powercfg.exe' }).Count | Should -Be 0
        (Get-ConfigSource -Run $run -Id 'power_settings').enabled.options.records | Should -Be 7
        (Get-ConfigSource -Run $run -Id 'power_active_scheme').enabled.options.records | Should -Be 1
        [System.IO.File]::ReadAllText((Join-Path $out 'raw/power_settings/output.txt')) | Should -Match 'Current AC Power Setting Index: 0x00000064'
        Start-ConfigCase 'config-snapshot-clean'
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'power-de')
        $hidden = Get-ConfigSource -Run $run2 -Id 'power_settings_hidden'
        $hidden.status | Should -BeExactly 'capture_failed'
        $hidden.status_reason | Should -Match 'exited with code 1'
        (Get-ConfigSource -Run $run2 -Id 'power_settings').status | Should -BeExactly 'observed'
        Start-ConfigCase
        $global:WfSynthetic.Commands['/query'] = @{ ExitCode = 0; StdOut = "No GUID here`r`n"; StdErr = '' }
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'power-empty')
        $empty = Get-ConfigSource -Run $run3 -Id 'power_settings'
        $empty.status | Should -BeExactly 'capture_failed'
        $empty.status_reason | Should -Match 'zero records: powercfg exited with code 0 and printed no line with a GUID'
        Start-ConfigCase
        $global:WfSynthetic.PowercfgPresent = $false
        $run4 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'power-missing')
        (Get-ConfigSource -Run $run4 -Id 'power_active_scheme').status | Should -BeExactly 'not_collected'
        (Get-ConfigSource -Run $run4 -Id 'power_active_scheme').status_reason | Should -Match 'powercfg\.exe'
    }

    It 'records the two questions without a documented read as not_collected with their reasons and no primary' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'unavailable'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out
        foreach ($id in @('power_mode', 'timer_resolution')) {
            $source = Get-ConfigSource -Run $run -Id $id
            $source.status | Should -BeExactly 'not_collected'
            $source.preflight.ok | Should -BeFalse
            $source.raw_time_range | Should -BeNullOrEmpty
            @($source.artifacts | ForEach-Object { $_.role }) | Should -Be @('config')
            $reason = Get-Content -LiteralPath (Join-Path $out ('raw/' + $id + '/reason.json')) -Raw | ConvertFrom-Json
            @($reason.documented_paths).Count | Should -BeGreaterThan 0
            $reason.follow_up | Should -Not -BeNullOrEmpty
        }
        (Get-ConfigSource -Run $run -Id 'timer_resolution').status_reason | Should -Match 'timeGetDevCaps'
        (Get-ConfigSource -Run $run -Id 'timer_resolution').status_reason | Should -Match 'Nothing here requests a timer period'
        (Get-ConfigSource -Run $run -Id 'timer_resolution').status_reason | Should -Not -Match 'Administrator'
    }

    It 'reads the process list without command lines, the timer helper with its protected command line, and labels the snapshot' {
        Start-ConfigCase
        $out = Join-Path $TestDrive 'processes'
        $run = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory $out -Arguments @{ Snapshot = 'stop' }
        $processes = Get-ConfigSource -Run $run -Id 'processes'
        $processes.requested.options.snapshot | Should -BeExactly 'stop'
        $processes.enabled.options.snapshot | Should -BeExactly 'stop'
        $processes.kind | Should -BeExactly 'process_inventory'
        $records = Get-Content -LiteralPath (Join-Path $out 'raw/processes/records.json') -Raw | ConvertFrom-Json
        @($records).Count | Should -Be 7
        @($records[0].PSObject.Properties.Name) | Should -Not -Contain 'CommandLine'
        @($records[0].PSObject.Properties.Name) | Should -Not -Contain 'ExecutablePath'
        $helper = Get-ConfigSource -Run $run -Id 'timer_helper_process'
        $helper.status | Should -BeExactly 'observed'
        $helperRecords = Get-Content -LiteralPath (Join-Path $out 'raw/timer_helper_process/records.json') -Raw | ConvertFrom-Json
        @($helperRecords).Count | Should -Be 1
        $helperRecords[0].CommandLine | Should -Match 'DpcTimerRes\.exe" 10000$'
        Start-ConfigCase 'config-snapshot-clean'
        $run2 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'no-helper')
        (Get-ConfigSource -Run $run2 -Id 'timer_helper_process').status | Should -BeExactly 'observed_zero'
        (Get-Content -LiteralPath (Join-Path $TestDrive 'no-helper/raw/timer_helper_process/records.json') -Raw).Trim() | Should -BeExactly '[]'
        $run3 = Invoke-TestCollector -Collector 'config-snapshot' -OutputDirectory (Join-Path $TestDrive 'bad-snapshot') -Arguments @{ Snapshot = 'middle' }
        $run3.ExitCode | Should -Be 1
        $run3.Pipeline.Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $TestDrive 'bad-snapshot') | Should -BeFalse -Because 'the check runs before the helper is loaded, so nothing is written (the one failed line goes to the real stdout, like a missing -OutputDirectory)'
    }

    It 'loads the helper twice without redefining the native boundary or printing anything' {
        $output = @(. (Join-Path $script:CollectorRoot '_common.ps1'))
        $output.Count | Should -Be 0
        (Get-Command -Name 'New-WfDeviceKeyNative').ScriptBlock.ToString() | Should -Match 'synthetic' -Because 'the load once guard keeps the recorder in place'
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
        $global:WfSynthetic.Wpr.Present = $false
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

        # The same start had already opened its session file under wpr-temp: it does not stay in the bundle.
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartStuck = $true }
        $out4 = Join-Path $TestDrive 'pm-start-stuck-session-file'
        $global:PmSessionDir = Join-Path $out4 'raw/presentmon_frames/wpr-temp'
        $start = @($global:WfSynthetic.Programs | Where-Object { $_['Match'] -eq '-start' })[0]
        $start['OnCall'] = {
            $null = New-Item -ItemType Directory -Path $global:PmSessionDir -Force
            [System.IO.File]::WriteAllBytes((Join-Path $global:PmSessionDir 'session.etl'), [byte[]](1..16))
        }
        $run4 = Invoke-PmCollector -OutputDirectory $out4
        $source4 = Get-PmSource -Run $run4
        $source4.status | Should -BeExactly 'not_collected'
        Test-Path -LiteralPath $global:PmSessionDir | Should -BeFalse -Because 'the session file never leaves the PC'
        @($source4.artifacts | ForEach-Object { $_.role }) | Should -Not -Contain 'other'
        @($source4.artifacts | Where-Object { $_.path -match 'wpr-temp' }).Count | Should -Be 0
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

    It 'still writes the manifest and both notes when the session it could not stop keeps its file from being deleted' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StopStuck = $true; CancelStuck = $true; AfterInProgress = $true }
        $out = Join-Path $TestDrive 'pm-temp-held'
        $global:PmSessionDir = Join-Path $out 'raw/presentmon_frames/wpr-temp'
        # The synthetic start opens a session file in a folder nothing can be removed from, as a live session holds its file.
        $start = @($global:WfSynthetic.Programs | Where-Object { $_['Match'] -eq '-start' })[0]
        $start['OnCall'] = {
            $null = New-Item -ItemType Directory -Path $global:PmSessionDir -Force
            [System.IO.File]::WriteAllBytes((Join-Path $global:PmSessionDir 'session.etl'), [byte[]](1..16))
            # Not readable either, as a file a writer holds without read sharing: hashing it would fail.
            & chmod 000 (Join-Path $global:PmSessionDir 'session.etl')
            & chmod 555 $global:PmSessionDir
        }
        try {
            $run = Invoke-PmCollector -OutputDirectory $out
        } finally {
            if (Test-Path -LiteralPath $global:PmSessionDir) { & chmod 755 $global:PmSessionDir }
        }
        $run.ExitCode | Should -Be 1
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^wpr -stop did not complete'
        $source.status_reason | Should -Match 'the recording may still be active'
        $source.status_reason | Should -Match 'recorded data could not be deleted from the bundle'
        @($run.Manifest.notes | Where-Object { $_ -match 'run "wpr -cancel -instancename wf-presentmon-frames" as an administrator' }).Count | Should -Be 1
        @($run.Manifest.notes | Where-Object { $_ -match 'recorded data could not be deleted and is still in the bundle.*wpr-temp' }).Count | Should -Be 1
        @($run.Manifest.notes | Where-Object { $_ -match 'raw/presentmon_frames/wpr-temp/session\.etl \(16 bytes\)' }).Count | Should -Be 1
        @($run.Manifest.tools | ForEach-Object { $_.name }) | Should -Contain 'presentmon' -Because 'the tools that ran are recorded whether or not recorded data was left behind'
        @($run.Manifest.tools | ForEach-Object { $_.name }) | Should -Contain 'wpr'
        # The held file is named by path and size and never opened: it is not an artifact and has no hash.
        @($source.artifacts | Where-Object { $_.path -match 'wpr-temp' }).Count | Should -Be 0
        @($source.artifacts | ForEach-Object { $_.role + ':' + (Split-Path -Leaf $_.path) } | Sort-Object) | Should -Be @('config:command.json', 'config:profile.wprp', 'log:console.txt', 'report:recording.json', 'report:result.json')
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        @($result.recorded_data_left).Count | Should -Be 1
        $result.recorded_data_left[0].path | Should -BeExactly 'raw/presentmon_frames/wpr-temp/session.etl'
        $result.recorded_data_left[0].bytes | Should -Be 16
    }

    It 'is capture_failed, not not_collected, when a start that timed out left a session file that cannot be deleted' {
        Start-PmCase
        Reset-PmPrograms -Wpr @{ StartStuck = $true }
        $out = Join-Path $TestDrive 'pm-start-stuck-held'
        $global:PmSessionDir = Join-Path $out 'raw/presentmon_frames/wpr-temp'
        $start = @($global:WfSynthetic.Programs | Where-Object { $_['Match'] -eq '-start' })[0]
        $start['OnCall'] = {
            $null = New-Item -ItemType Directory -Path $global:PmSessionDir -Force
            [System.IO.File]::WriteAllBytes((Join-Path $global:PmSessionDir 'session.etl'), [byte[]](1..16))
            & chmod 555 $global:PmSessionDir
        }
        try {
            $run = Invoke-PmCollector -OutputDirectory $out
        } finally {
            if (Test-Path -LiteralPath $global:PmSessionDir) { & chmod 755 $global:PmSessionDir }
        }
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^wpr -start did not complete'
        $source.status_reason | Should -Match 'recorded data could not be deleted from the bundle'
        $source.status_reason | Should -Not -Match 'nothing was recorded'
    }

    It 'claims no frames when the read succeeded but the recording could not be deleted afterwards' -Skip:(-not $IsMacOS) {
        Start-PmCase
        Reset-PmPrograms
        $out = Join-Path $TestDrive 'pm-etl-held'
        $global:PmHeldEtl = Join-Path $out 'raw/presentmon_frames/trace.etl'
        # The file flag stands in for a recording something still holds: it can be read but not deleted.
        $decode = @($global:WfSynthetic.Programs | Where-Object { $_['Match'] -eq '--etl_file' })[0]
        $decode['OnCall'] = { & chflags uchg $global:PmHeldEtl }
        try {
            $run = Invoke-PmCollector -OutputDirectory $out
        } finally {
            if (Test-Path -LiteralPath $global:PmHeldEtl) { & chflags nouchg $global:PmHeldEtl }
        }
        $source = Get-PmSource -Run $run
        $source.status | Should -BeExactly 'capture_failed'
        $source.status_reason | Should -Match '^recorded data could not be deleted from the bundle'
        $source.enabled.options.records | Should -Be 0
        $source.expectation.detail | Should -Match '; 0 frames from '
        $source.raw_time_range | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $out 'raw/presentmon_frames/frames.csv') | Should -BeFalse
        @($source.artifacts | Where-Object { $_.path -match 'trace\.etl' }).Count | Should -Be 0
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        @($result.recorded_data_left | ForEach-Object { $_.path }) | Should -Be @('raw/presentmon_frames/trace.etl')
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

        # A header with no end time cannot show the session ran until the stop: never skipped, always failed.
        Start-PmCase
        Reset-PmPrograms -Wpr @{ EtlBytes = (New-WfSyntheticEtlBytes -DurationSeconds 60 -NoEndTime) }
        $run4 = Invoke-PmCollector -OutputDirectory (Join-Path $TestDrive 'pm-no-end-time')
        (Get-PmSource -Run $run4).status | Should -BeExactly 'capture_failed'
        (Get-PmSource -Run $run4).status_reason | Should -Match 'carries no end time \(EndTime is zero\)'
        (Get-PmSource -Run $run4).enabled.options.recording_end_utc | Should -BeNullOrEmpty
        @((Get-PmStarted) | Where-Object { $_ -match '^PresentMon' }).Count | Should -Be 0

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
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/presentmon_frames/result.json') -Raw | ConvertFrom-Json
        $result.csv.present | Should -BeFalse -Because 'result.json describes the bundle as it was left'
        $source.enabled.options.csv_present | Should -BeFalse

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

Describe 'dpcisr-trace against the synthetic backend' {
    BeforeAll {
        function Start-TraceCase {
            param([string]$Case = 'dpcisr-trace')
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $Case })[0]
            & $selected['Setup']
            return $selected['Arguments']
        }
        function Get-TraceSource {
            param($Run, [string]$Id)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
        }
        function Get-WprCalls {
            # verb and instance of every wpr call, in order
            return @($global:WfSynthetic.Processes | Where-Object { $_.FilePath -like '*wpr.exe' } | ForEach-Object {
                    $tokens = Split-WfSyntheticArguments -Arguments $_.Arguments
                    [pscustomobject]@{ Verb = $tokens[0]; Instance = (Get-WfSyntheticInstance -Tokens $tokens); Arguments = $_.Arguments }
                })
        }
        function Get-WprVerbs { return @(Get-WprCalls | ForEach-Object { $_.Verb }) }
        function Get-XperfRuns { return @($global:WfSynthetic.Processes | Where-Object { $_.FilePath -like '*xperf.exe' }) }
        function Get-TracerptRuns { return @($global:WfSynthetic.Processes | Where-Object { $_.FilePath -like '*tracerpt.exe' }) }
        function Assert-NoTraceLeft {
            param([string]$Out)
            Test-Path -LiteralPath (Join-Path $Out 'private') | Should -BeFalse -Because 'the kernel trace never leaves the machine'
            @(Get-ChildItem -LiteralPath $Out -Recurse -File -Filter '*.etl').Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $Out -Directory | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('logs', 'raw')
        }
        function With-Arguments {
            param([hashtable]$Base, [hashtable]$More)
            $all = $Base.Clone()
            foreach ($key in $More.Keys) { $all[$key] = $More[$key] }
            return $all
        }
    }

    It 'records a clean session as observed with the profile, the status text, the summary and the session record, and no trace' {
        $arguments = Start-TraceCase
        $out = Join-Path $TestDrive 'clean'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        $calls = Get-WprCalls
        @($calls | ForEach-Object { $_.Verb }) | Should -Be @('-status', '-profiles', '-start', '-status', '-stop', '-status')
        $calls[0].Instance | Should -BeExactly '' -Because 'the preflight looks at the default instance'
        $calls[1].Instance | Should -BeExactly ''
        foreach ($call in $calls[2..5]) { $call.Instance | Should -Match '^WfDpcIsrTrace-[0-9]{8}T[0-9]{6}Z$' }
        foreach ($call in $calls[2..5]) { $call.Arguments | Should -Match ' -instancename WfDpcIsrTrace-[0-9TZ]+$' -Because 'the instance name is the last parameter' }
        @(Get-TracerptRuns).Count | Should -Be 1
        @(Get-TracerptRuns)[0].Arguments | Should -Match '^<?.*private[/\\]trace\.etl -summary .*tracerpt-summary\.txt -y$'
        Assert-NoTraceLeft -Out $out
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'observed'
        $trace.kind | Should -BeExactly 'wpr'
        $trace.events_lost | Should -Be 0
        $trace.buffers_lost | Should -Be 0
        $trace.buffers.size_kb | Should -Be 1024
        $trace.buffers.count | Should -Be 64
        $trace.buffers.mode | Should -BeExactly 'file'
        @($trace.enabled.keywords) | Should -Be @('Interrupt', 'DPC', 'Loader')
        @($trace.requested.keywords) | Should -Be @($trace.enabled.keywords)
        $trace.enabled.options.session_confirmed_stopped | Should -BeTrue
        $trace.enabled.options.session_state_final | Should -BeExactly 'idle'
        $trace.enabled.options.trace_kept_in_bundle | Should -BeFalse
        $trace.enabled.options.trace_sha256 | Should -Match '^[0-9a-f]{64}$'
        $trace.enabled.options.recording_seconds | Should -BeGreaterOrEqual 10
        $trace.enabled.options.recording_seconds | Should -BeLessThan 13
        $trace.raw_time_range.domain | Should -BeExactly 'system_time'
        @($trace.artifacts | ForEach-Object { $_.path }) | Should -Be @('raw/wpr_trace/dpcisr-trace.wprp', 'raw/wpr_trace/session.json', 'raw/wpr_trace/status.txt', 'raw/wpr_trace/tracerpt-summary.txt')
        @($trace.artifacts | Where-Object { $_.role -eq 'primary' } | ForEach-Object { $_.path }) | Should -Be @('raw/wpr_trace/tracerpt-summary.txt')
        $wprp = Join-Path $out 'raw/wpr_trace/dpcisr-trace.wprp'
        $trace.config_hash.value | Should -BeExactly (Get-TestSha256 -Path $wprp)
        $xml = [xml](Get-Content -LiteralPath $wprp -Raw)
        @($xml.WindowsPerformanceRecorder.Profiles.SystemProvider.Keywords.Keyword | ForEach-Object { $_.Value }) | Should -Be @('Interrupt', 'DPC', 'Loader')
        $xml.WindowsPerformanceRecorder.Profiles.SystemCollector.Name | Should -BeExactly 'NT Kernel Logger'
        @($xml.WindowsPerformanceRecorder.Profiles.Profile | ForEach-Object { $_.LoggingMode }) | Should -Be @('File', 'Memory')
        $report = Get-TraceSource -Run $run -Id 'dpcisr_report'
        $report.status | Should -BeExactly 'observed'
        $report.kind | Should -BeExactly 'xperf'
        @($report.command) | Should -Be @('C:\Tools\WindowsPerformanceToolkit\xperf.exe', '-i', '<bundle>/private/trace.etl', '-a', 'dpcisr')
        $report.raw_time_range.start | Should -BeExactly $trace.raw_time_range.start -Because 'the report describes the trace, not the moment xperf ran'
        $report.raw_time_range.end | Should -BeExactly $trace.raw_time_range.end
        $report.enabled.options.trace_sha256 | Should -BeExactly $trace.enabled.options.trace_sha256
        @($trace.command) | Should -Be @('C:\Windows\System32\wpr.exe', '-start', '<bundle>/raw/wpr_trace/dpcisr-trace.wprp!WfDpcIsrTrace.Verbose', '-filemode', '-recordtempto', '<bundle>/private/temp', '-instancename', $trace.enabled.options.instance_name)
        (Get-Content -LiteralPath (Join-Path $out 'raw/wpr_trace/session.json') -Raw) | Should -Not -Match ([regex]::Escape($out)) -Because 'the bundle records no absolute path of its own location'
        (Get-Content -LiteralPath (Join-Path $out 'manifest.json') -Raw) | Should -Not -Match ([regex]::Escape($out))
        @($run.Manifest.tools | ForEach-Object { $_.name }) | Should -Be @('powershell', 'wevtutil', 'collector:dpcisr-trace', 'collector-helper:_common.ps1', 'wpr', 'tracerpt', 'xperf')
        @($run.Manifest.tools | Where-Object { $_.name -eq 'xperf' })[0].sha256 | Should -BeExactly '7f3a9c2e4b1d6058a2c4e6f8091b3d5f7a9c1e3b5d7f9a0c2e4b6d8f0a1c3e5b'
        $run.Manifest.capture.elevated | Should -BeTrue
        $run.Manifest.calibration.status | Should -BeExactly 'not_collected'
        $run.Manifest.scenario.requested_duration_s | Should -Be 10
    }

    It 'runs nothing when the account is not elevated and says why' {
        $arguments = Start-TraceCase -Case 'dpcisr-trace-not-elevated'
        $out = Join-Path $TestDrive 'not-elevated'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        $global:WfSynthetic.Processes.Count | Should -Be 0
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'not_collected'
        $trace.status_reason | Should -Match 'not elevated'
        $trace.preflight.ok | Should -BeFalse
        @($trace.artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 0
        (Get-TraceSource -Run $run -Id 'dpcisr_report').status | Should -BeExactly 'not_collected'
        Assert-NoTraceLeft -Out $out
    }

    It 'never cancels a recording it did not start, and treats an unreadable default status as not idle' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.State = 'recording'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'busy') -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'not_collected'
        $trace.status_reason | Should -Match 'did not read as idle'
        Get-WprVerbs | Should -Be @('-status')

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.IdleText = "Der Rekorder zeichnet nicht auf`r`n"
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'busy-unknown') -Arguments $arguments
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status | Should -BeExactly 'not_collected'
        Get-WprVerbs | Should -Be @('-status')

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StatusExitCode = 5
        $global:WfSynthetic.Wpr.StatusStdErr = "Error: 0x80070005 Access is denied.`r`n"
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'busy-error') -Arguments $arguments
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status | Should -BeExactly 'not_collected'
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status_reason | Should -Match 'reads as unknown'
    }

    It 'reports a missing wpr, a missing tracerpt and a refused profile as not_collected' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.Present = $false
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'no-wpr') -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'not_collected'
        $trace.status_reason | Should -Match 'does not exist'
        $global:WfSynthetic.Processes.Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.Present = $false
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'no-tracerpt') -Arguments $arguments
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status | Should -BeExactly 'not_collected'
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status_reason | Should -Match 'tracerpt.exe'
        $global:WfSynthetic.Processes.Count | Should -Be 0 -Because 'without the final statistics reader no session is started'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.ProfilesExitCode = 2
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'bad-profile') -Arguments $arguments
        $trace3 = Get-TraceSource -Run $run3 -Id 'wpr_trace'
        $trace3.status | Should -BeExactly 'not_collected'
        $trace3.status_reason | Should -Match 'did not enumerate the recording profile'
        Get-WprVerbs | Should -Be @('-status', '-profiles')
    }

    It 'checks its own instance after a refused start and cancels what the start left behind' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StartExitCode = 1
        $global:WfSynthetic.Wpr.StartStdErr = "synthetic wpr: access is denied`r`n"
        $out = Join-Path $TestDrive 'start-refused'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'not_collected'
        $trace.status_reason | Should -Match 'wpr -start was refused.*access is denied'
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status') -Because 'the instance is checked even after a refusal'
        $trace.enabled.options.session_state_final | Should -BeExactly 'idle'
        Assert-NoTraceLeft -Out $out

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StartExitCode = 1
        $global:WfSynthetic.Wpr.StartLeavesRunning = $true
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'start-left-running') -Arguments $arguments
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-cancel', '-status')
        $calls = Get-WprCalls
        $calls[4].Instance | Should -Match '^WfDpcIsrTrace-' -Because 'the cancel is scoped to the instance the collector started'
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').enabled.options.session_state_final | Should -BeExactly 'idle'
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status | Should -BeExactly 'not_collected'
        $global:WfSynthetic.Wpr.Instances.Values | Should -Not -Contain 'recording'
    }

    It 'reports a refused start whose leftover session survives the cancel as capture_failed, never as not_collected' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StartExitCode = 1
        $global:WfSynthetic.Wpr.StartStdErr = "synthetic wpr: access is denied`r`n"
        $global:WfSynthetic.Wpr.StartLeavesRunning = $true
        $global:WfSynthetic.Wpr.CancelLeavesRunning = $true
        $out = Join-Path $TestDrive 'start-refused-unconfirmed'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-cancel', '-status')
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed' -Because 'a session may still be recording, which is not the same as nothing having run'
        $trace.status_reason | Should -Match 'reads as active after the session was given up and the cancel'
        $trace.status_reason | Should -Match 'wpr -start was refused.*access is denied'
        $trace.enabled.options.session_state_final | Should -BeExactly 'active'
        $trace.enabled.options.session_confirmed_stopped | Should -BeFalse
        @($run.Manifest.notes | Where-Object { $_ -match 'wpr -cancel -instancename WfDpcIsrTrace-' }).Count | Should -BeGreaterThan 0
        @(Get-TracerptRuns).Count | Should -Be 0
        Assert-NoTraceLeft -Out $out
    }

    It 'cancels its own session and confirms when the stop fails or does not finish' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StopExitCode = 1
        $global:WfSynthetic.Wpr.StopStdErr = "synthetic wpr: the merge failed`r`n"
        $out = Join-Path $TestDrive 'stop-fails'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'wpr -stop failed.*merge failed'
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-stop', '-status', '-cancel', '-status')
        $trace.enabled.options.session_confirmed_stopped | Should -BeTrue
        $global:WfSynthetic.Wpr.Instances.Values | Should -Not -Contain 'recording'
        @(Get-TracerptRuns).Count | Should -Be 0
        (Get-TraceSource -Run $run -Id 'dpcisr_report').status | Should -BeExactly 'not_collected'
        @(Get-XperfRuns).Count | Should -Be 0
        Assert-NoTraceLeft -Out $out

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StopStuck = $true
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'stop-stuck') -Arguments (With-Arguments $arguments @{ TimeoutSeconds = 30 })
        $trace2 = Get-TraceSource -Run $run2 -Id 'wpr_trace'
        $trace2.status | Should -BeExactly 'capture_failed'
        $trace2.status_reason | Should -Match 'did not finish within 30 seconds'
        Get-WprVerbs | Should -Contain '-cancel'
        $global:WfSynthetic.Wpr.Instances.Values | Should -Not -Contain 'recording'
    }

    It 'cancels a session that a successful stop left running, and reports it as unconfirmed only when the cancel fails too' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StopLeavesRunning = $true
        $out = Join-Path $TestDrive 'stop-leaves-running'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-stop', '-status', '-cancel', '-status')
        $global:WfSynthetic.Wpr.Instances.Values | Should -Not -Contain 'recording' -Because 'the leftover session is cancelled, never left to the operator'
        $trace.enabled.options.session_state_after_stop | Should -BeExactly 'active'
        $trace.enabled.options.session_state_final | Should -BeExactly 'idle'
        $trace.status | Should -BeExactly 'observed' -Because 'the stop saved the trace and the leftover was cleaned up and confirmed idle'
        @($run.Manifest.notes | Where-Object { $_ -match 'wpr -cancel -instancename' }).Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StopLeavesRunning = $true
        $global:WfSynthetic.Wpr.CancelLeavesRunning = $true
        $out2 = Join-Path $TestDrive 'unconfirmed'
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out2 -Arguments $arguments
        $trace2 = Get-TraceSource -Run $run2 -Id 'wpr_trace'
        $trace2.status | Should -BeExactly 'capture_failed'
        $trace2.status_reason | Should -Match 'reads as active after the stop and the cancel'
        $trace2.enabled.options.session_confirmed_stopped | Should -BeFalse
        @($run2.Stderr | Where-Object { $_ -match 'wpr -cancel -instancename WfDpcIsrTrace-' }).Count | Should -BeGreaterThan 0
        @(Get-TracerptRuns).Count | Should -Be 0 -Because 'an unconfirmed session has no final statistics worth reading'
        Assert-NoTraceLeft -Out $out2
    }

    It 'never lets a failed status command confirm the stop' {
        $arguments = Start-TraceCase
        # The status right after the start is fine; the ones after the stop fail.
        $global:WfSynthetic.Wpr.StopLeavesRunning = $true
        $global:WfSynthetic.Wpr.StatusFailAfterCalls = 2
        $out = Join-Path $TestDrive 'status-error'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.enabled.options.session_state_final | Should -BeExactly 'unknown'
        $trace.enabled.options.session_confirmed_stopped | Should -BeFalse
        Get-WprVerbs | Should -Contain '-cancel'
    }

    It 'bounds the recording by a monotonic clock whatever the status calls take' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StatusDelaySeconds = 25
        $out = Join-Path $TestDrive 'slow-status'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments (With-Arguments $arguments @{ DurationSeconds = 40 })
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'observed'
        # The status after the start takes 25 synthetic seconds and counts toward the recording; the loop then waits
        # only the remainder, so the recording stays within the requested 40 seconds plus one poll.
        $trace.enabled.options.recording_seconds | Should -BeGreaterOrEqual 40
        $trace.enabled.options.recording_seconds | Should -BeLessThan 43
        $session = Get-Content -LiteralPath (Join-Path $out 'raw/wpr_trace/session.json') -Raw | ConvertFrom-Json
        $session.worst_case_seconds | Should -Be (40 + 4 * 120 + 5 * 30)
    }

    It 'keeps the final figures authoritative: a loss the summary shows fails the trace even when the live status showed none' {
        $arguments = Start-TraceCase -Case 'dpcisr-trace-events-lost'
        $out = Join-Path $TestDrive 'lossy'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'lost 544 events and 0 buffers'
        $trace.events_lost | Should -Be 544
        $trace.buffers_lost | Should -Be 0
        $trace.enabled.options.events_lost_after_start | Should -Be 0
        $trace.expectation.met | Should -BeFalse
        (Get-Content -LiteralPath (Join-Path $out 'raw/wpr_trace/tracerpt-summary.txt') -Raw) | Should -Match 'Events\s+Lost\s+544'
        $report = Get-TraceSource -Run $run -Id 'dpcisr_report'
        $report.status | Should -BeExactly 'capture_failed'
        $report.status_reason | Should -Match 'with -tle'
        @($report.command)[-1] | Should -BeExactly '-tle'
        Test-Path -LiteralPath (Join-Path $out 'raw/dpcisr_report/dpcisr.txt') | Should -BeTrue
        Assert-NoTraceLeft -Out $out
    }

    It 'fails the trace on lost buffers with zero events lost, and on any loss figure that is missing or not a number' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.BuffersLost = 3
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'buffers-lost') -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'lost 0 events and 3 buffers'
        $trace.buffers_lost | Should -Be 3

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.Labels = 'missing'
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'summary-no-labels') -Arguments $arguments
        $trace2 = Get-TraceSource -Run $run2 -Id 'wpr_trace'
        $trace2.status | Should -BeExactly 'capture_failed'
        $trace2.status_reason | Should -Match 'no single whole number for events lost or buffers lost'
        $trace2.events_lost | Should -BeNullOrEmpty
        $trace2.buffers_lost | Should -BeNullOrEmpty

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.Labels = 'nonnumeric'
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'summary-nonnumeric') -Arguments $arguments
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status_reason | Should -Match 'no single whole number for events lost'
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').events_lost | Should -BeNullOrEmpty

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.Labels = 'events-only'
        $run4 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'summary-events-only') -Arguments $arguments
        (Get-TraceSource -Run $run4 -Id 'wpr_trace').status_reason | Should -Match 'no single whole number for buffers lost'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tracerpt.ExitCode = 1
        $run5 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'summary-fails') -Arguments $arguments
        (Get-TraceSource -Run $run5 -Id 'wpr_trace').status_reason | Should -Match 'final loss statistics could not be read.*exited with code 1'
        @((Get-TraceSource -Run $run5 -Id 'wpr_trace').artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 0
    }

    It 'cancels a session whose live status cannot verify the settings: unreadable loss, missing keywords, no collector, lost buffers listed' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.EventsLostText = '1,234'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'early-nonnumeric') -Arguments $arguments
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'cancelled without saving a trace because the kernel collector''s "Events Lost" figure is missing or not a number \("1,234"\)'
        Get-WprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-status', '-cancel', '-status')
        Get-WprVerbs | Should -Not -Contain '-stop'
        @(Get-TracerptRuns).Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.Keywords = @('Interrupt', 'DPC')
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'fewer-keywords') -Arguments $arguments
        $trace2 = Get-TraceSource -Run $run2 -Id 'wpr_trace'
        $trace2.status | Should -BeExactly 'capture_failed'
        $trace2.status_reason | Should -Match 'requested settings were not enabled.*no Loader keyword'
        @($trace2.enabled.keywords) | Should -Be @('Interrupt', 'DPC')

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.Keywords = @()
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'no-keywords') -Arguments $arguments
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status | Should -BeExactly 'capture_failed'
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status_reason | Should -Match 'lists no System Keywords'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.CollectorName = $null
        $run4 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'no-collector') -Arguments $arguments
        (Get-TraceSource -Run $run4 -Id 'wpr_trace').status_reason | Should -Match 'lists 0 collector'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.StatusLabels = 'missing'
        $run5 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'early-no-labels') -Arguments $arguments
        (Get-TraceSource -Run $run5 -Id 'wpr_trace').status_reason | Should -Match 'figure is missing or not a number \(no line\)'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.BuffersLostLine = 'Buffers Lost            : 2'
        $run6 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'early-buffers') -Arguments $arguments
        (Get-TraceSource -Run $run6 -Id 'wpr_trace').status_reason | Should -Match 'lists lost buffers'
        $global:WfSynthetic.Wpr.Instances.Values | Should -Not -Contain 'recording'
    }

    It 'stops early at the cap and keeps the shorter window as capture_failed, and never reads a trace above the cap or an empty one' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.TempBytes = 16777217
        $out = Join-Path $TestDrive 'temp-cap'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments (With-Arguments $arguments @{ MaxTraceBytes = 16777216 })
        $trace = Get-TraceSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'stopped early.*above the cap of 16777216'
        $trace.enabled.options.stopped_early_at_cap | Should -BeTrue
        $trace.enabled.options.recording_seconds | Should -BeLessThan 10
        Get-WprVerbs | Should -Contain '-stop'
        Assert-NoTraceLeft -Out $out

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.EtlBytes = 16777217
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'etl-cap') -Arguments (With-Arguments $arguments @{ MaxTraceBytes = 16777216 })
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status_reason | Should -Match 'above the cap of 16777216, and was not read'
        @(Get-TracerptRuns).Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.EtlBytes = 0
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'etl-empty') -Arguments $arguments
        (Get-TraceSource -Run $run3 -Id 'wpr_trace').status_reason | Should -Match 'missing or empty'
    }

    It 'refuses an xperf that is absent, not pinned by hash, not pinned by version, or changed during the run' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Tools.Clear()
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-absent') -Arguments $arguments
        $report = Get-TraceSource -Run $run -Id 'dpcisr_report'
        $report.status | Should -BeExactly 'not_collected'
        $report.status_reason | Should -Match 'does not exist'
        @(Get-XperfRuns).Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tools['C:\Tools\WindowsPerformanceToolkit\xperf.exe'] = @{ Sha256 = '0000000000000000000000000000000000000000000000000000000000000001'; Version = '10.0.26100.1 (synthetic)' }
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-hash') -Arguments $arguments
        $report2 = Get-TraceSource -Run $run2 -Id 'dpcisr_report'
        $report2.status | Should -BeExactly 'not_collected'
        $report2.status_reason | Should -Match 'refused to run an unpinned tool.*matches none of the 1 pinned builds'
        @(Get-XperfRuns).Count | Should -Be 0
        @($run2.Manifest.tools | ForEach-Object { $_.name }) | Should -Not -Contain 'xperf'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Tools['C:\Tools\WindowsPerformanceToolkit\xperf.exe'] = @{ Sha256 = '7f3a9c2e4b1d6058a2c4e6f8091b3d5f7a9c1e3b5d7f9a0c2e4b6d8f0a1c3e5b'; Version = '10.0.22621.1 (other)' }
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-version') -Arguments $arguments
        (Get-TraceSource -Run $run3 -Id 'dpcisr_report').status | Should -BeExactly 'not_collected'
        @(Get-XperfRuns).Count | Should -Be 0

        $arguments = Start-TraceCase
        $global:WfSynthetic.PinnedTools['xperf'] = @()
        $run4 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-no-pin') -Arguments $arguments
        $report4 = Get-TraceSource -Run $run4 -Id 'dpcisr_report'
        $report4.status | Should -BeExactly 'not_collected'
        $report4.status_reason | Should -Match 'no xperf build is pinned'
        ($run4.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Xperf['ChangeHashAfterRun'] = $true
        $run5 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-changed') -Arguments $arguments
        $report5 = Get-TraceSource -Run $run5 -Id 'dpcisr_report'
        $report5.status | Should -BeExactly 'capture_failed'
        $report5.status_reason | Should -Match 'changed during the run'
        Test-Path -LiteralPath (Join-Path (Join-Path $TestDrive 'xperf-changed') 'raw/dpcisr_report/dpcisr.txt') | Should -BeFalse
        @($run5.Manifest.tools | ForEach-Object { $_.name }) | Should -Not -Contain 'xperf'
    }

    It 'reports a failing, hanging or empty xperf honestly, keeps no report, and downgrades the trace when xperf names a loss' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Xperf = @{ ExitCode = 1; StdOut = ''; StdErr = 'synthetic xperf: cannot open the trace'; Stuck = $false }
        $out = Join-Path $TestDrive 'xperf-fails'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $report = Get-TraceSource -Run $run -Id 'dpcisr_report'
        $report.status | Should -BeExactly 'capture_failed'
        $report.status_reason | Should -Match 'exited with code 1: synthetic xperf: cannot open the trace'
        Test-Path -LiteralPath (Join-Path $out 'raw/dpcisr_report/dpcisr.txt') | Should -BeFalse
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        (Get-TraceSource -Run $run -Id 'wpr_trace').status | Should -BeExactly 'observed'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Xperf = @{ ExitCode = 1; StdOut = ''; StdErr = 'synthetic xperf: the trace has lost events; use -tle to tolerate them'; Stuck = $false }
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-lost') -Arguments $arguments
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status | Should -BeExactly 'capture_failed'
        (Get-TraceSource -Run $run2 -Id 'wpr_trace').status_reason | Should -Match 'xperf refused the trace naming lost events'
        ($run2.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Xperf = @{ ExitCode = 0; StdOut = ''; StdErr = ''; Stuck = $true }
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-stuck') -Arguments (With-Arguments $arguments @{ TimeoutSeconds = 20 })
        (Get-TraceSource -Run $run3 -Id 'dpcisr_report').status_reason | Should -Match 'did not finish within 20 seconds'

        $arguments = Start-TraceCase
        $global:WfSynthetic.Xperf = @{ ExitCode = 0; StdOut = "Some other report`r`n"; StdErr = ''; Stuck = $false }
        $run4 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'xperf-other') -Arguments $arguments
        (Get-TraceSource -Run $run4 -Id 'dpcisr_report').status_reason | Should -Match 'no DPC Info and Interrupt Info sections'
    }

    It 'rejects a duration or a trace cap outside its range with a failed summary and no bundle' {
        $arguments = Start-TraceCase
        $out = Join-Path $TestDrive 'bad-duration'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments (With-Arguments $arguments @{ DurationSeconds = 1 })
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        Test-Path -LiteralPath $out | Should -BeFalse
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'bad-cap') -Arguments (With-Arguments $arguments @{ MaxTraceBytes = 1024 })
        $run2.ExitCode | Should -Be 1
        $global:WfSynthetic.Processes.Count | Should -Be 0
    }

    It 'refuses to start when the worst case run time exceeds the dispatcher budget, and runs at the budget' {
        $arguments = Start-TraceCase
        $out = Join-Path $TestDrive 'over-budget'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments (With-Arguments $arguments @{ DurationSeconds = 300 })
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        @($run.Stderr | Where-Object { $_ -match 'worst case run time is 930 seconds' }).Count | Should -BeGreaterThan 0
        Test-Path -LiteralPath $out | Should -BeFalse
        $global:WfSynthetic.Processes.Count | Should -Be 0 -Because 'the refusal comes before any wpr call'

        $arguments = Start-TraceCase
        $run2 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'one-over-budget') -Arguments (With-Arguments $arguments @{ DurationSeconds = 271 })
        $run2.ExitCode | Should -Be 1
        $global:WfSynthetic.Processes.Count | Should -Be 0

        $arguments = Start-TraceCase
        $out3 = Join-Path $TestDrive 'at-budget'
        $run3 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out3 -Arguments (With-Arguments $arguments @{ DurationSeconds = 270 })
        $run3.ExitCode | Should -Be 0
        $trace3 = Get-TraceSource -Run $run3 -Id 'wpr_trace'
        $trace3.status | Should -BeExactly 'observed'
        $trace3.requested.options.worst_case_seconds | Should -Be 900
        (Get-Content -LiteralPath (Join-Path $out3 'raw/wpr_trace/session.json') -Raw | ConvertFrom-Json).worst_case_seconds | Should -Be 900

        $arguments = Start-TraceCase
        $out4 = Join-Path $TestDrive 'short-duration'
        $run4 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out4 -Arguments (With-Arguments $arguments @{ DurationSeconds = 5 })
        (Get-TraceSource -Run $run4 -Id 'wpr_trace').requested.options.worst_case_seconds | Should -Be (5 + 25 + 4 * 120 + 5 * 30) -Because 'the status read after the start can outlast a duration below its own deadline'

        $arguments = Start-TraceCase
        $run5 = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory (Join-Path $TestDrive 'long-with-short-timeouts') -Arguments (With-Arguments $arguments @{ DurationSeconds = 300; TimeoutSeconds = 112 })
        $run5.ExitCode | Should -Be 0 -Because '300 + 4 * 112 + 150 is 898'
    }

    It 'records the parsed status, the final figures and every tool call in the session record, and pseudonymises hardware addresses in the texts that leave' {
        $arguments = Start-TraceCase
        $global:WfSynthetic.Wpr.BuffersLostLine = $null
        $global:WfSynthetic.Xperf.StdOut = $global:WfSynthetic.Xperf.StdOut + "Adapter 02:aa:bb:cc:dd:01 noted`r`n"
        $out = Join-Path $TestDrive 'session-record'
        $run = Invoke-TestCollector -Collector 'dpcisr-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        $session = Get-Content -LiteralPath (Join-Path $out 'raw/wpr_trace/session.json') -Raw | ConvertFrom-Json
        $session.instance_name | Should -Match '^WfDpcIsrTrace-'
        $session.status_after_start.dropped_events | Should -Be 0
        $session.status_after_start.logging_mode | Should -BeExactly 'File'
        @($session.status_after_start.collectors).Count | Should -Be 1
        $session.status_after_start.collectors[0].name | Should -BeExactly 'NT Kernel Logger'
        $session.status_after_start.collectors[0].buffer_size_kb | Should -Be 1024
        $session.status_after_start.collectors[0].events_lost | Should -Be 0
        @($session.status_after_start.collectors[0].keywords) | Should -Be @('Interrupt', 'DPC', 'Loader')
        $session.settings_verified | Should -BeTrue
        $session.final.events_lost | Should -Be 0
        $session.final.buffers_lost | Should -Be 0
        $session.final.events_lost_lines | Should -Be 1
        $session.trace_kept_in_bundle | Should -BeFalse
        $session.trace_sha256 | Should -Match '^[0-9a-f]{64}$'
        $session.session_confirmed_stopped | Should -BeTrue
        @($session.runs | ForEach-Object { $_.tool + ' ' + $_.verb }) | Should -Be @('wpr.exe status', 'wpr.exe profiles', 'wpr.exe start', 'wpr.exe status', 'wpr.exe stop', 'wpr.exe status', 'tracerpt.exe ')
        $session.runs[2].arguments | Should -BeExactly ('-start <bundle>/raw/wpr_trace/dpcisr-trace.wprp!WfDpcIsrTrace.Verbose -filemode -recordtempto <bundle>/private/temp -instancename ' + $session.instance_name)
        $session.runs[4].arguments | Should -Match ('^-stop <bundle>/private/trace\.etl "win-forensics dpcisr-trace [0-9TZ]+" -skipPdbGen -instancename ' + $session.instance_name + '$')
        $session.runs[6].arguments | Should -BeExactly '<bundle>/private/trace.etl -summary <bundle>/raw/wpr_trace/tracerpt-summary.txt -y'
        (Get-Content -LiteralPath (Join-Path $out 'raw/wpr_trace/status.txt') -Raw) | Should -Match 'WPR recording is in progress'
        $reportText = Get-Content -LiteralPath (Join-Path $out 'raw/dpcisr_report/dpcisr.txt') -Raw
        $reportText | Should -Not -Match '02:aa:bb:cc:dd:01'
        $reportText | Should -Match 'mac-[0-9a-f]{12}'
        (Get-TraceSource -Run $run -Id 'dpcisr_report').enabled.options.mac_addresses_replaced | Should -Be 1
    }
}

Describe 'clock-calibration against the synthetic backend' {
    BeforeAll {
        function Start-ClockCase {
            param([string]$Case, [string]$OutputDirectory)
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $Case })[0]
            & $selected['Setup'] $OutputDirectory
            return $selected
        }
        function Get-ClockSource {
            param($Run, [string]$Id)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
        }
        function Invoke-Mark {
            # The mark command as the person at the PC runs it; returns its exit code and its one stdout line.
            param([string]$OutputDirectory, [string]$Label)
            $before = $global:WfSynthetic.Stdout.Count
            & (Join-Path $script:CollectorRoot 'clock-calibration.ps1') -OutputDirectory $OutputDirectory -Mark $Label
            $exit = $LASTEXITCODE
            $lines = @($global:WfSynthetic.Stdout.ToArray())[$before..($global:WfSynthetic.Stdout.Count - 1)]
            return [pscustomobject]@{ ExitCode = $exit; Lines = @($lines); Parsed = ($lines[-1] | ConvertFrom-Json) }
        }
        function New-OpenSession {
            # A directory that looks like a running session: the live marks file and a session.json with a deadline.
            param([string]$OutputDirectory, [datetime]$AcceptsUntil)
            $null = New-Item -ItemType Directory -Force -Path (Join-Path $OutputDirectory 'raw/operator_marks')
            $null = New-Item -ItemType Directory -Force -Path (Join-Path $OutputDirectory 'raw/clock_calibration')
            Write-WfTextFile -Path (Join-Path $OutputDirectory 'raw/operator_marks/marks.open.jsonl') -Text ''
            Write-WfJsonFile -Path (Join-Path $OutputDirectory 'raw/clock_calibration/session.json') -Object ([ordered]@{ accepts_marks_until_utc = (ConvertTo-WfUtcString -Value $AcceptsUntil) })
        }
    }

    It 'takes the pairs the contract asks for at the edges of the system clock, and writes them to the manifest and the samples file alike' {
        $out = Join-Path $TestDrive 'clock-ok'
        $null = Start-ClockCase -Case 'clock-calibration' -OutputDirectory $out
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 60 }
        $run.ExitCode | Should -Be 0
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'observed'
        $clock.command | Should -Be @('Stopwatch.GetTimestamp', 'DateTime.UtcNow.ToFileTimeUtc', 'Stopwatch.GetTimestamp')
        $pairs = @($run.Manifest.calibration.pairs)
        $pairs.Count | Should -Be 13
        $run.Manifest.calibration.expected_pairs | Should -Be 13
        $run.Manifest.calibration.missing_pairs | Should -Be 0
        $run.Manifest.calibration.status | Should -BeExactly 'observed'
        $run.Manifest.calibration.qpc_frequency_hz | Should -Be 10000000
        $run.Manifest.calibration.time_adjustment.start | Should -BeNullOrEmpty
        $run.Manifest.calibration.time_adjustment.stop | Should -BeNullOrEmpty
        $run.Manifest.scenario.requested_duration_s | Should -Be 60
        @($pairs | ForEach-Object { $_.phase }) | Should -Be (@('start') + @(1..11 | ForEach-Object { 'interval' }) + @('stop'))
        @($pairs | ForEach-Object { $_.seq }) | Should -Be @(0..12)
        foreach ($pair in $pairs) {
            $pair.qpc_after | Should -BeGreaterThan $pair.qpc_before
            # The bracket runs from the counter read before the last unchanged clock reading to the one after the
            # changed reading: five synthetic reads of 50 x 100 ns.
            ($pair.qpc_after - $pair.qpc_before) | Should -Be 250
            # An edge pair's file time is a whole clock increment (1 ms here).
            ($pair.filetime_utc_100ns % 10000) | Should -Be 0
        }
        for ($i = 1; $i -lt $pairs.Count; $i++) {
            $qpcSpan = $pairs[$i].qpc_before - $pairs[$i - 1].qpc_before
            $qpcSpan | Should -BeGreaterOrEqual 49990000
            $qpcSpan | Should -BeLessThan 50020000
        }
        # The system clock runs 50 ppm fast: 60 s of counter are 60.003 s of system time, read exactly at its edges.
        ($pairs[12].filetime_utc_100ns - $pairs[0].filetime_utc_100ns) | Should -BeGreaterOrEqual 600020000
        ($pairs[12].filetime_utc_100ns - $pairs[0].filetime_utc_100ns) | Should -BeLessOrEqual 600040000
        $samples = @((Get-Content -LiteralPath (Join-Path $out 'raw/clock_calibration/samples.jsonl')) | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
        $samples.Count | Should -Be 13
        for ($i = 0; $i -lt 13; $i++) {
            $samples[$i].seq | Should -Be $pairs[$i].seq
            $samples[$i].qpc_before | Should -Be $pairs[$i].qpc_before
            $samples[$i].filetime_utc_100ns | Should -Be $pairs[$i].filetime_utc_100ns
            $samples[$i].edge | Should -BeTrue
            $samples[$i].step_100ns | Should -Be 10000
            # Each wait is rounded up to a whole millisecond and the edge wait adds up to one increment, so a pair
            # lands within 2 ms of its slot.
            $samples[$i].late_ticks | Should -BeLessThan 20000
        }
        $clock.enabled.options.edge_pairs | Should -Be 13
        $clock.enabled.options.largest_step_100ns | Should -Be 10000
        $clock.enabled.options.qpc_high_resolution | Should -BeTrue
        $clock.expectation.met | Should -BeTrue
        @($clock.artifacts | ForEach-Object { $_.role } | Sort-Object) | Should -Be @('config', 'primary', 'report')
        $session = Get-Content -LiteralPath (Join-Path $out 'raw/clock_calibration/session.json') -Raw | ConvertFrom-Json
        (Get-TestUtcText $session.accepts_marks_until_utc) | Should -BeGreaterThan (Get-TestUtcText $session.started_utc)
    }

    It 'records the marks dropped from the second console with their own counter bracket and closes the file at the stop' {
        $out = Join-Path $TestDrive 'clock-marks'
        $null = Start-ClockCase -Case 'clock-calibration' -OutputDirectory $out
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 60 }
        $run.ExitCode | Should -Be 0
        $run.Stdout.Count | Should -Be 1 -Because 'the mark commands print on their own stdout, not the session''s'
        $marks = Get-ClockSource -Run $run -Id 'operator_marks'
        $marks.status | Should -BeExactly 'observed'
        $marks.enabled.options.marks | Should -Be 2
        $marks.enabled.options.closed | Should -BeTrue
        @($run.Manifest.scenario.marks | ForEach-Object { $_.label }) | Should -Be @('felt a stutter', 'second stutter, shorter')
        $first = $run.Manifest.scenario.marks[0]
        # 17.3 s of true time after the synthetic clock's reset, on the counter the mark process read itself.
        ($first.qpc - $global:WfSynthetic.Clock.StartQpc) | Should -BeGreaterOrEqual 173000000
        ($first.qpc - $global:WfSynthetic.Clock.StartQpc) | Should -BeLessThan 173001000
        (Get-TestUtcText $first.at_utc) | Should -BeExactly '2026-03-01T12:00:17.3000000Z'
        Test-Path -LiteralPath (Join-Path $out 'raw/operator_marks/marks.jsonl') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $out 'raw/operator_marks/marks.open.jsonl') | Should -BeFalse -Because 'the live file is renamed right after the stop pair'
        $lines = @(Get-Content -LiteralPath (Join-Path $out 'raw/operator_marks/marks.jsonl') | Where-Object { $_ })
        $lines.Count | Should -Be 2
        $record = $lines[0] | ConvertFrom-Json
        @($record.PSObject.Properties.Name) | Should -Be @('label', 'qpc_before', 'filetime_utc_100ns', 'qpc_after', 'at_utc', 'process_id')
        $record.process_id | Should -Be 4242
        $instructions = Get-Content -LiteralPath (Join-Path $out 'raw/operator_marks/instructions.json') -Raw | ConvertFrom-Json
        $instructions.how_to_mark | Should -Match '-ExecutionPolicy Bypass -File'
        # A mark after the stop is refused and leaves nothing behind.
        $late = Invoke-Mark -OutputDirectory $out -Label 'too late'
        $late.ExitCode | Should -Be 1
        $late.Parsed.error | Should -Match 'finished'
        (Get-Content -LiteralPath (Join-Path $out 'raw/operator_marks/marks.jsonl') | Where-Object { $_ }).Count | Should -Be 2
        @(Get-ChildItem -LiteralPath (Join-Path $out 'raw/operator_marks') -File | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('instructions.json', 'marks.jsonl', 'result.json')
    }

    It 'refuses a mark when no session is running, when the label is empty or too long, and never creates a marks file' {
        Reset-WfSynthetic
        $out = Join-Path $TestDrive 'clock-nosession'
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $out 'raw/operator_marks')
        $none = Invoke-Mark -OutputDirectory $out -Label 'stutter'
        $none.ExitCode | Should -Be 1
        $none.Lines.Count | Should -Be 1
        $none.Parsed.error | Should -Match 'no clock-calibration session is accepting marks'
        Test-Path -LiteralPath (Join-Path $out 'raw/operator_marks/marks.open.jsonl') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $out 'raw/operator_marks/marks.jsonl') | Should -BeFalse
        $missing = Invoke-Mark -OutputDirectory (Join-Path $TestDrive 'clock-nowhere') -Label 'stutter'
        $missing.ExitCode | Should -Be 1
        # A live file exists, but the label is unusable.
        New-OpenSession -OutputDirectory $out -AcceptsUntil $global:WfSynthetic.Now.AddHours(1)
        (Invoke-Mark -OutputDirectory $out -Label '   ').ExitCode | Should -Be 1
        $empty = Invoke-Mark -OutputDirectory $out -Label ''
        $empty.ExitCode | Should -Be 1
        $empty.Lines.Count | Should -Be 1
        $empty.Parsed.error | Should -Match 'the mark label is empty'
        Test-Path -LiteralPath (Join-Path $out 'manifest.json') | Should -BeFalse
        (Invoke-Mark -OutputDirectory $out -Label ('x' * 81)).ExitCode | Should -Be 1
        (Invoke-Mark -OutputDirectory $out -Label "tab`there").ExitCode | Should -Be 1
        (Get-Content -LiteralPath (Join-Path $out 'raw/operator_marks/marks.open.jsonl') -Raw) | Should -BeNullOrEmpty
        $ok = Invoke-Mark -OutputDirectory $out -Label ('y' * 80)
        $ok.ExitCode | Should -Be 0
        $ok.Parsed.file | Should -BeExactly 'raw/operator_marks/marks.open.jsonl'
        $ok.Parsed.qpc | Should -BeGreaterThan 0
    }

    It 'refuses a mark into a session that passed its deadline without finishing, or that has no session.json' {
        Reset-WfSynthetic
        $out = Join-Path $TestDrive 'clock-killed'
        # The session started long ago and never wrote a manifest: it was killed. Its live file still exists.
        New-OpenSession -OutputDirectory $out -AcceptsUntil $global:WfSynthetic.Now.AddHours(-2)
        $late = Invoke-Mark -OutputDirectory $out -Label 'stutter'
        $late.ExitCode | Should -Be 1
        $late.Parsed.error | Should -Match 'passed its deadline'
        (Get-Content -LiteralPath (Join-Path $out 'raw/operator_marks/marks.open.jsonl') -Raw) | Should -BeNullOrEmpty
        Remove-Item -LiteralPath (Join-Path $out 'raw/clock_calibration/session.json')
        $none = Invoke-Mark -OutputDirectory $out -Label 'stutter'
        $none.ExitCode | Should -Be 1
        $none.Parsed.error | Should -Match 'session.json'
    }

    It 'keeps every mark when several mark commands append at once, and holds the cap' {
        # Eight real processes append through the real mark command (the Windows adapters, not the synthetic
        # ones: the counter is Stopwatch on this host too) into one live file at the same time.
        $out = Join-Path $TestDrive 'clock-concurrent'
        New-OpenSession -OutputDirectory $out -AcceptsUntil ([datetime]::UtcNow.AddHours(1))
        $live = Join-Path $out 'raw/operator_marks/marks.open.jsonl'
        $barrier = Join-Path $TestDrive 'clock-concurrent-go'
        if (Test-Path -LiteralPath $barrier) { Remove-Item -LiteralPath $barrier }
        $collector = Join-Path $script:CollectorRoot 'clock-calibration.ps1'
        $worker = Join-Path $TestDrive 'mark-worker.ps1'
        Write-WfTextFile -Path $worker -Text @"
param([string]`$Barrier, [string]`$Directory, [string]`$Worker, [int]`$Count)
while (-not (Test-Path -LiteralPath `$Barrier)) { Start-Sleep -Milliseconds 5 }
`$failed = 0
for (`$i = 1; `$i -le `$Count; `$i++) {
    `$null = & '$collector' -OutputDirectory `$Directory -Mark ('w' + `$Worker + '-' + `$i) 2>&1
    if (`$LASTEXITCODE -ne 0) { `$failed += 1 }
}
[Console]::Out.WriteLine('failed=' + `$failed)
"@
        $pwsh = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $processes = @()
        foreach ($w in 1..8) {
            $info = New-Object System.Diagnostics.ProcessStartInfo
            $info.FileName = $pwsh
            $info.Arguments = ('-NoProfile -NonInteractive -File "{0}" -Barrier "{1}" -Directory "{2}" -Worker {3} -Count 40' -f $worker, $barrier, $out, $w)
            $info.UseShellExecute = $false
            $info.RedirectStandardOutput = $true
            $processes += [System.Diagnostics.Process]::Start($info)
        }
        Start-Sleep -Milliseconds 500
        Write-WfTextFile -Path $barrier -Text 'go'
        $failed = 0
        foreach ($process in $processes) {
            $process.WaitForExit(120000) | Should -BeTrue
            # The mark command prints its own JSON line per mark; the worker's last line is its count of failures.
            $last = @($process.StandardOutput.ReadToEnd().Trim() -split "`n")[-1].Trim()
            $last | Should -Match '^failed=\d+$'
            $failed += [int]($last.Substring(7))
            $process.Dispose()
        }
        $lines = @(Get-Content -LiteralPath $live | Where-Object { $_ })
        $shape = '^\{"label":"w\d-\d+","qpc_before":\d+,"filetime_utc_100ns":\d+,"qpc_after":\d+,"at_utc":"[^"]+","process_id":\d+\}$'
        # Every acknowledged append survives exactly once, whole, and nothing else is in the file.
        @($lines | Where-Object { $_ -notmatch $shape }).Count | Should -Be 0
        $lines.Count | Should -Be (320 - $failed)
        @($lines | ForEach-Object { ($_ | ConvertFrom-Json).label } | Sort-Object -Unique).Count | Should -Be $lines.Count
        $failed | Should -BeLessThan 320
        # The cap holds under concurrency: fill the file to just under the smallest cap and let eight writers race.
        $cap = Join-Path $TestDrive 'clock-cap'
        New-OpenSession -OutputDirectory $cap -AcceptsUntil ([datetime]::UtcNow.AddHours(1))
        $capLive = Join-Path $cap 'raw/operator_marks/marks.open.jsonl'
        $filler = '{"label":"' + ('f' * 60) + '","qpc_before":1,"filetime_utc_100ns":134168400000000000,"qpc_after":2,"at_utc":"2026-03-01T12:00:00.0000000Z","process_id":1}'
        $builder = New-Object System.Text.StringBuilder
        while ($builder.Length -lt (1048576 - 2 * ($filler.Length + 1))) { $null = $builder.Append($filler).Append("`n") }
        Write-WfTextFile -Path $capLive -Text $builder.ToString()
        $before = (Get-Item -LiteralPath $capLive).Length
        $processes = @()
        $capBarrier = Join-Path $TestDrive 'clock-cap-go'
        foreach ($w in 1..8) {
            $info = New-Object System.Diagnostics.ProcessStartInfo
            $info.FileName = $pwsh
            $info.Arguments = ('-NoProfile -NonInteractive -Command "& ''{0}'' -OutputDirectory ''{1}'' -Mark ''cap{2}'' -MaxArtifactBytes 1048576; exit $LASTEXITCODE"' -f $collector, $cap, $w)
            $info.UseShellExecute = $false
            $processes += [System.Diagnostics.Process]::Start($info)
        }
        $succeeded = 0
        foreach ($process in $processes) {
            $process.WaitForExit(120000) | Should -BeTrue
            if ($process.ExitCode -eq 0) { $succeeded += 1 }
            $process.Dispose()
        }
        (Get-Item -LiteralPath $capLive).Length | Should -BeLessOrEqual 1048576
        $capLines = @(Get-Content -LiteralPath $capLive | Where-Object { $_ -like '{"label":"cap*' })
        $capLines.Count | Should -Be $succeeded
        $succeeded | Should -BeLessOrEqual 1 -Because 'room was left for at most one more mark'
        (Get-Item -LiteralPath $capLive).Length | Should -BeGreaterOrEqual $before
    }

    It 'treats a line that is not a mark as a lost mark: the source is capture_failed and the file is kept as written' {
        $out = Join-Path $TestDrive 'clock-malformed'
        $null = Start-ClockCase -Case 'clock-calibration-missed-slot' -OutputDirectory $out
        # Something else writes into the live file during the session: a plain line and a mark with an escape the writer never produces.
        $global:WfSynthetic.Clock.Marks = @(@{ AtElapsed100ns = 150000000; Label = 'real mark' })
        $global:WfSynthetic.Clock.OvershootMs = @{}
        $hook = Join-Path $out 'raw/operator_marks/marks.open.jsonl'
        $original = ${function:Invoke-WfSyntheticMark}
        try {
            function Invoke-WfSyntheticMark {
                param([string]$Label, [string]$OutputDirectory)
                & $original -Label $Label -OutputDirectory $OutputDirectory
                $forged = '{"label":"bad \q escape","qpc_before":1,"filetime_utc_100ns":134168400000000000,"qpc_after":2,"at_utc":"2026-03-01T12:00:00.0000000Z","process_id":1}'
                [System.IO.File]::AppendAllText($hook, "not a mark`n" + $forged + "`n", (New-Object System.Text.UTF8Encoding($false)))
            }
            $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 30 }
        } finally {
            ${function:Invoke-WfSyntheticMark} = $original
        }
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $marks = Get-ClockSource -Run $run -Id 'operator_marks'
        $marks.status | Should -BeExactly 'capture_failed'
        $marks.status_reason | Should -Match '2 line\(s\) of the marks file are not marks'
        $marks.expectation.met | Should -BeFalse
        @($marks.artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 1 -Because 'the file is kept so nothing is lost, and the status says it is incomplete'
        @($run.Manifest.scenario.marks).Count | Should -Be 1
        (Get-ClockSource -Run $run -Id 'clock_calibration').status | Should -BeExactly 'observed'
    }

    It 'refuses the whole session when the managed timer is not the high resolution counter' {
        Reset-WfSynthetic
        $global:WfSynthetic.Clock = New-WfSyntheticClock -HighResolution $false
        $out = Join-Path $TestDrive 'clock-noqpc'
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 20 }
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'unsupported'
        $clock.status_reason | Should -Match 'IsHighResolution'
        $clock.preflight.ok | Should -BeFalse
        (Get-ClockSource -Run $run -Id 'operator_marks').status | Should -BeExactly 'unsupported'
        $run.Manifest.calibration.status | Should -BeExactly 'unsupported'
        $run.Manifest.calibration.pairs.Count | Should -Be 0
        $run.Manifest.calibration.missing_pairs | Should -Be $run.Manifest.calibration.expected_pairs
        @(Get-ChildItem -LiteralPath (Join-Path $out 'raw') -File -Recurse | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('instructions.json', 'result.json', 'result.json', 'session.json')
        # And a mark is refused too.
        Reset-WfSynthetic
        $global:WfSynthetic.Clock = New-WfSyntheticClock -HighResolution $false
        $dir = Join-Path $TestDrive 'clock-noqpc-mark'
        New-OpenSession -OutputDirectory $dir -AcceptsUntil $global:WfSynthetic.Now.AddHours(1)
        $mark = Invoke-Mark -OutputDirectory $dir -Label 'stutter'
        $mark.ExitCode | Should -Be 1
        $mark.Parsed.error | Should -Match 'high resolution'
    }

    It 'keeps the pairs taken when a counter read fails after two of them, counts the stop pair missing, and closes the marks file' {
        $out = Join-Path $TestDrive 'clock-readfail'
        $null = Start-ClockCase -Case 'clock-calibration-read-failed' -OutputDirectory $out
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 20 }
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'observed'
        $clock.status_reason | Should -BeNullOrEmpty
        $clock.expectation.met | Should -BeFalse
        $clock.expectation.detail | Should -Match 'performance counter read failed'
        $clock.expectation.detail | Should -Match 'stop pair taken: False'
        $clock.enabled.options.failure | Should -Match 'performance counter read failed'
        Test-Path -LiteralPath (Join-Path $out 'raw/clock_calibration/samples.jsonl') | Should -BeTrue
        $run.Manifest.calibration.status | Should -BeExactly 'observed'
        $run.Manifest.calibration.pairs.Count | Should -Be 4
        $run.Manifest.calibration.expected_pairs | Should -Be 5
        $run.Manifest.calibration.missing_pairs | Should -Be 1
        @($run.Manifest.calibration.pairs | ForEach-Object { $_.phase }) | Should -Be @('start', 'interval', 'interval', 'interval')
        $run.Stderr | Should -Contain ('source clock_calibration: the session failed: synthetic backend: the performance counter read failed; the 4 pairs taken are kept and the 1 pairs not taken (the stop pair included) are counted in missing_pairs; timestamps after the last pair are unaligned')
        $marks = Get-ClockSource -Run $run -Id 'operator_marks'
        $marks.status | Should -BeExactly 'observed_zero'
        $marks.enabled.options.closed | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $out 'raw/operator_marks/marks.jsonl') | Should -BeTrue
    }

    It 'is capture_failed with no samples file when a read fails before two pairs exist' {
        Reset-WfSynthetic
        # The first counter read after the start pair throws: one pair is not a calibration.
        $global:WfSynthetic.Clock = New-WfSyntheticClock -Increment100ns 10000 -ThrowAtElapsed100ns 20000000
        $out = Join-Path $TestDrive 'clock-onepair'
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 20 }
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'capture_failed'
        $clock.status_reason | Should -Match '1 pair had been taken and is not kept'
        Test-Path -LiteralPath (Join-Path $out 'raw/clock_calibration/samples.jsonl') | Should -BeFalse
        $run.Manifest.calibration.pairs.Count | Should -Be 0
        $run.Manifest.calibration.missing_pairs | Should -Be 5
        (Get-ClockSource -Run $run -Id 'operator_marks').status | Should -BeExactly 'observed_zero'
    }

    It 'records a slot reached more than one interval late as missing, not as a late pair' {
        $out = Join-Path $TestDrive 'clock-missed'
        $null = Start-ClockCase -Case 'clock-calibration-missed-slot' -OutputDirectory $out
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 30 }
        $run.ExitCode | Should -Be 0
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'observed'
        $clock.expectation.met | Should -BeFalse -Because 'the expectation is the full count (timestamps.md section 3, the clock calibration exception)'
        $clock.expectation.detail | Should -Match '1 missing'
        $run.Manifest.calibration.missing_pairs | Should -Be 1
        $run.Manifest.calibration.expected_pairs | Should -Be 7
        @($run.Manifest.calibration.pairs | ForEach-Object { $_.seq }) | Should -Be @(0, 1, 3, 4, 5, 6)
        $report = Get-Content -LiteralPath (Join-Path $out 'raw/clock_calibration/result.json') -Raw | ConvertFrom-Json
        @($report.missed_slots).Count | Should -Be 1
        $report.missed_slots[0].seq | Should -Be 2
        $report.largest_step_100ns | Should -Be 156250
        $run.Stderr | Should -Contain ('source clock_calibration: 1 of 7 expected pairs are missing (interval slots the session reached more than one interval late); the calibration is usable over longer segments, see docs/contracts/timestamps.md section 4.5')
    }

    It 'fails the session at its deadline instead of running past the dispatcher' {
        Reset-WfSynthetic
        # The first wait overruns by 90 s: a 20 s session with an 80 s deadline hits it before its first interval
        # slot, with only the start pair taken.
        $global:WfSynthetic.Clock = New-WfSyntheticClock -OvershootMs @{ 1 = 90000 }
        $out = Join-Path $TestDrive 'clock-deadline'
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 20 }
        $run.ExitCode | Should -Be 0
        $clock = Get-ClockSource -Run $run -Id 'clock_calibration'
        $clock.status | Should -BeExactly 'capture_failed'
        $clock.status_reason | Should -Match 'passed its deadline of 80 s before slot 1'
        Test-Path -LiteralPath (Join-Path $out 'raw/clock_calibration/samples.jsonl') | Should -BeFalse
        (Get-ClockSource -Run $run -Id 'operator_marks').enabled.options.closed | Should -BeTrue
        # The same overrun after two pairs keeps them and counts the rest missing.
        Reset-WfSynthetic
        $global:WfSynthetic.Clock = New-WfSyntheticClock -OvershootMs @{ 2 = 90000 }
        $out2 = Join-Path $TestDrive 'clock-deadline-2'
        $run2 = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out2 -Arguments @{ DurationSeconds = 20 }
        $clock2 = Get-ClockSource -Run $run2 -Id 'clock_calibration'
        $clock2.status | Should -BeExactly 'observed'
        $clock2.expectation.met | Should -BeFalse
        $clock2.enabled.options.failure | Should -Match 'passed its deadline of 80 s before slot 2'
        $run2.Manifest.calibration.pairs.Count | Should -Be 2
        $run2.Manifest.calibration.missing_pairs | Should -Be 3
    }

    It 'rejects a duration outside its range with a failed summary and no bundle' {
        Reset-WfSynthetic
        foreach ($arguments in @(@{ DurationSeconds = 5 }, @{ DurationSeconds = 9 }, @{ DurationSeconds = 841 })) {
            $out = Join-Path $TestDrive ('clock-range-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
            $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments $arguments
            $run.ExitCode | Should -Be 1
            $run.Stdout.Count | Should -Be 1
            ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
            Test-Path -LiteralPath $out | Should -BeFalse
        }
    }

    It 'is dispatched like every other collector: one summary line, the bundle is the directory given' {
        $out = Join-Path $TestDrive 'clock-seam'
        $null = Start-ClockCase -Case 'clock-calibration-clock-step' -OutputDirectory $out
        $run = Invoke-TestCollector -Collector 'clock-calibration' -OutputDirectory $out -Arguments @{ DurationSeconds = 30 }
        $run.Pipeline.Count | Should -Be 0
        $run.Stdout.Count | Should -Be 1
        $summary = $run.Stdout[0] | ConvertFrom-Json
        $summary.collector | Should -BeExactly 'clock-calibration'
        $summary.bundle | Should -BeExactly $out
        $summary.artifacts | Should -Be 6
        $run.Manifest.scenario.id | Should -BeExactly 'clock_calibration'
        # The collector records the pairs as they are; the step is the Mac side fit's business.
        $pairs = @($run.Manifest.calibration.pairs)
        ($pairs[3].filetime_utc_100ns - $pairs[2].filetime_utc_100ns) | Should -BeGreaterOrEqual 52490000
        ($pairs[3].filetime_utc_100ns - $pairs[2].filetime_utc_100ns) | Should -BeLessOrEqual 52510000
        ($pairs[3].qpc_before - $pairs[2].qpc_before) | Should -BeLessThan 50020000
    }
}

Describe 'diskio-trace against the synthetic backend' {
    BeforeAll {
        # The collector's pure functions (path rules, number and summary
        # readers, the header reader), loaded from the script without running
        # its body, so the rules can be checked one by one.
        $script:DiskIoScript = Join-Path $script:CollectorRoot 'diskio-trace.ps1'
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($script:DiskIoScript, [ref]$null, [ref]$null)
        foreach ($fn in $parsed.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
            if ($fn.Name -like '*-DiskIo*') { . ([scriptblock]::Create($fn.Extent.Text)) }
        }
        $pmParsed = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:CollectorRoot 'presentmon-frames.ps1'), [ref]$null, [ref]$null)
        foreach ($fn in $pmParsed.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-WfEtlHeader' }, $false)) {
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:DiskGold = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'fixtures/presentmon/gold-test_case_0.first-buffer.etl'

        function Start-DiskCase {
            # The named case's machine, or the default machine with options.
            param([string]$Case = 'diskio-trace', [hashtable]$Machine = $null)
            Reset-WfSynthetic
            $selected = @(Get-WfSyntheticCases | Where-Object { $_['Case'] -eq $Case })[0]
            if ($null -ne $Machine) { New-WfSyntheticDiskIoMachine @Machine } else { & $selected['Setup'] }
            return $selected['Arguments']
        }
        function Invoke-DiskCase {
            param([string]$Name, [hashtable]$Arguments)
            $out = Join-Path $TestDrive $Name
            return (Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $Arguments)
        }
        function Get-DiskSource {
            param($Run, [string]$Id)
            return @($Run.Manifest.collectors | Where-Object { $_.id -eq $Id })[0]
        }
        function Get-DiskWprCalls {
            return @($global:WfSynthetic.Processes | Where-Object { $_.FilePath -like '*wpr.exe' } | ForEach-Object {
                    $tokens = Split-WfSyntheticArguments -Arguments $_.Arguments
                    [pscustomobject]@{ Verb = $tokens[0]; Instance = (Get-WfSyntheticInstance -Tokens $tokens); Arguments = $_.Arguments }
                })
        }
        function Get-DiskWprVerbs { return @(Get-DiskWprCalls | ForEach-Object { $_.Verb }) }
        function Get-DiskTracerptRuns { return @($global:WfSynthetic.Processes | Where-Object { $_.FilePath -like '*tracerpt.exe' }) }
        function Get-DiskRows {
            param([string]$Out)
            $path = Join-Path $Out 'raw/diskio_aggregate/aggregate.jsonl'
            return @(Get-Content -LiteralPath $path | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
        }
        function Assert-DiskNothingLeft {
            param([string]$Out)
            Test-Path -LiteralPath (Join-Path $Out 'private') | Should -BeFalse -Because 'the trace and its dump never leave the machine'
            @(Get-ChildItem -LiteralPath $Out -Recurse -File | Where-Object { $_.Extension -in @('.etl', '.xml') }).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $Out -Directory | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('logs', 'raw')
        }
        function Get-DiskBundleText {
            param([string]$Out)
            return ((Get-ChildItem -LiteralPath $Out -Recurse -File | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n")
        }
    }

    It 'records a clean session, aggregates it on the machine, and keeps only the aggregate, the rules and the hashes' {
        $arguments = Start-DiskCase
        $out = Join-Path $TestDrive 'clean'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'ok'
        $calls = Get-DiskWprCalls
        @($calls | ForEach-Object { $_.Verb }) | Should -Be @('-status', '-profiles', '-start', '-status', '-stop', '-status')
        $calls[0].Instance | Should -BeExactly '' -Because 'the preflight looks at the default instance and never touches it'
        foreach ($call in $calls[2..5]) { $call.Arguments | Should -Match ' -instancename WfDiskIoTrace-[0-9]{8}T[0-9]{6}Z$' -Because 'the instance name is the last parameter' }
        $tracerpt = @(Get-DiskTracerptRuns)
        $tracerpt.Count | Should -Be 1 -Because 'one call writes the dump and the summary, each under a name the collector gave, so no file is written under a default name'
        $tracerpt[0].Arguments | Should -Match 'private[/\\]trace\.etl -o .*private[/\\]dump\.xml -of XML -summary .*raw[/\\]wpr_trace[/\\]tracerpt-summary\.txt -y$'
        Assert-DiskNothingLeft -Out $out
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'observed'
        $trace.kind | Should -BeExactly 'wpr'
        @($trace.requested.keywords) | Should -Be @('DiskIO', 'Filename', 'HardFaults', 'ProcessThread')
        @($trace.enabled.keywords) | Should -Be @($trace.requested.keywords)
        $trace.events_lost | Should -Be 0
        $trace.buffers_lost | Should -Be 0
        $trace.enabled.options.clock_type | Should -BeExactly 'qpc'
        $trace.enabled.options.concurrent_kernel_session_check | Should -BeExactly 'not_checked'
        $trace.enabled.options.session_confirmed_stopped | Should -BeTrue
        (Get-TestUtcText -Value $trace.raw_time_range.start) | Should -BeExactly '2026-03-01T12:00:07.0000000Z' -Because 'the range is the trace header''s own start and end'
        @($trace.artifacts | ForEach-Object { $_.path }) | Should -Be @('raw/wpr_trace/diskio-trace.wprp', 'raw/wpr_trace/session.json', 'raw/wpr_trace/status.txt', 'raw/wpr_trace/tracerpt-summary.txt')
        $wprp = Join-Path $out 'raw/wpr_trace/diskio-trace.wprp'
        $trace.config_hash.value | Should -BeExactly (Get-TestSha256 -Path $wprp)
        $xml = [xml](Get-Content -LiteralPath $wprp -Raw)
        @($xml.WindowsPerformanceRecorder.Profiles.SystemProvider.Keywords.Keyword | ForEach-Object { $_.Value }) | Should -Be @('DiskIO', 'Filename', 'HardFaults', 'ProcessThread')
        @($xml.WindowsPerformanceRecorder.Profiles.Profile | ForEach-Object { $_.Id }) | Should -Be @('WfDiskIoTrace.Verbose.File', 'WfDiskIoTrace.Verbose.Memory')
        $aggregate = Get-DiskSource -Run $run -Id 'diskio_aggregate'
        $aggregate.status | Should -BeExactly 'observed'
        @($aggregate.artifacts | ForEach-Object { $_.path }) | Should -Be @('raw/diskio_aggregate/aggregate.jsonl', 'raw/diskio_aggregate/command.json', 'raw/diskio_aggregate/result.json')
        @($aggregate.command) | Should -Be @('C:\Windows\System32\tracerpt.exe', '<bundle>/private/trace.etl', '-o', '<bundle>/private/dump.xml', '-of', 'XML', '-summary', '<bundle>/raw/wpr_trace/tracerpt-summary.txt', '-y')
        $aggregate.enabled.options.recording_and_dump_removed | Should -BeTrue
        $aggregate.enabled.options.trace_sha256 | Should -BeExactly $trace.enabled.options.trace_sha256
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/diskio_aggregate/result.json') -Raw | ConvertFrom-Json
        $result.dump_events | Should -Be $result.trace_events_processed
        $result.counts.malformed | Should -Be 0
        $rows = Get-DiskRows -Out $out
        $rows.Count | Should -Be $result.rows
        ($rows | Measure-Object -Property operations -Sum).Sum | Should -Be 14
        $game = @($rows | Where-Object { $_.process_image -eq 'SyntheticGame.exe' -and $_.operation -eq 'read' -and $_.extension -eq '.pak' })
        $game.Count | Should -Be 1
        $game[0].operations | Should -Be 2
        $game[0].transferred_bytes | Should -Be 196608
        $game[0].response_time_max_us | Should -Be 250 -Because 'HighResResponseTime ticks over a 10 MHz PerfFreq'
        $game[0].directory | Should -Match '^\\Program Files\\SyntheticGame\\dir-[0-9a-f]{12}\\dir-[0-9a-f]{12}$'
        @($rows | Where-Object { $_.operation -eq 'hard_fault' })[0].disk_number | Should -BeNullOrEmpty
        @($rows | Where-Object { $_.extension -eq '.sav' })[0].process_image | Should -BeExactly 'SyntheticLauncher.exe' -Because 'a thread named only by its end event is resolved at the end of the read'
        @($rows | Where-Object { $_.extension -eq '.sav' })[0].directory | Should -Match '^\\Users\\<profile>\\dir-[0-9a-f]{12}\\dir-[0-9a-f]{12}$'
        @($rows | Where-Object { $_.extension -eq '.dat' })[0].directory | Should -Match '^\\ProgramData\\SyntheticLauncher\\dir-'
        @($rows | Where-Object { $null -eq $_.process_id }).Count | Should -Be 1 -Because 'a thread the trace never names has no process, never a guessed one'
        @($rows | Where-Object { $_.path_class -eq 'unnamed' }).Count | Should -Be 1
        @($rows | Where-Object { $_.process_id -eq 3400 })[0].process_image | Should -Match '^image-[0-9a-f]{12}$'
        @($rows | Where-Object { $_.directory -eq '\' }).Count | Should -Be 1 -Because 'a file in the volume root counts under \ without its name'
        $text = Get-DiskBundleText -Out $out
        foreach ($secret in @('SyntheticOwner', 'secret-token', '02-00-5E-10-20-30', 'S-1-5-21-', 'cache01', 'world.pak', 'slot1', 'index.dat', 'ShaderCache', 'Saved Games', 'Synthetic-Operational', 'Manifests')) {
            $text | Should -Not -Match ([regex]::Escape($secret)) -Because "$secret was in the trace and must not leave the machine"
        }
        $recorded = (Get-ChildItem -LiteralPath (Join-Path $out 'raw') -Recurse -File | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
        $recorded + (Get-Content -LiteralPath (Join-Path $out 'manifest.json') -Raw) | Should -Not -Match ([regex]::Escape($out)) -Because 'the bundle records no absolute path of its own location'
        @($run.Manifest.tools | ForEach-Object { $_.name }) | Should -Be @('powershell', 'wevtutil', 'collector:diskio-trace', 'collector-helper:_common.ps1', 'wpr', 'tracerpt')
        $run.Manifest.capture.elevated | Should -BeTrue
        $run.Manifest.calibration.status | Should -BeExactly 'not_collected'
    }

    It 'salts its pseudonyms per run: the same directory keeps one pseudonym inside a bundle and another in the next' {
        $arguments = Start-DiskCase
        $first = Join-Path $TestDrive 'salt-a'
        $null = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $first -Arguments $arguments
        $cache = @(Get-DiskRows -Out $first | Where-Object { $_.extension -eq '.bin' } | ForEach-Object { $_.directory } | Sort-Object -Unique)
        $cache.Count | Should -Be 1 -Because 'three rows of the same directory share its pseudonym'
        $arguments = Start-DiskCase
        $global:WfSynthetic.Salt = 'synthetic-salt-0002'
        $second = Join-Path $TestDrive 'salt-b'
        $null = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $second -Arguments $arguments
        $other = @(Get-DiskRows -Out $second | Where-Object { $_.extension -eq '.bin' } | ForEach-Object { $_.directory } | Sort-Object -Unique)
        $other[0] | Should -Not -BeExactly $cache[0]
        $other[0] | Should -Match '^\\Users\\<profile>\\AppData\\Local\\SyntheticGame\\dir-'
    }

    It 'counts the collector''s own files apart, without a directory' {
        $out = Join-Path $TestDrive 'own-files'
        $arguments = Start-DiskCase -Machine @{ CollectorRoot = (Resolve-WfBundleRoot -OutputDirectory $out) }
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        $own = @(Get-DiskRows -Out $out | Where-Object { $_.path_class -eq 'collector' })
        $own.Count | Should -Be 1
        $own[0].directory | Should -BeNullOrEmpty
        $own[0].transferred_bytes | Should -Be 65536
    }

    It 'charges a request to the image that owned the process id when it happened, when the id is reused inside the window' {
        $arguments = Start-DiskCase -Machine @{ PidReuse = $true }
        $out = Join-Path $TestDrive 'pid-reuse'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'observed'
        $rows = Get-DiskRows -Out $out
        $reused = @($rows | Where-Object { $_.process_id -eq 5120 } | Sort-Object -Property bin_start_s)
        $reused.Count | Should -Be 2
        $reused[0].bin_start_s | Should -Be 3
        $reused[0].process_image | Should -BeExactly 'SyntheticUpdater.exe' -Because 'the updater owned the id when it wrote, whatever started under that id later'
        $reused[0].transferred_bytes | Should -Be 1048576
        $reused[1].bin_start_s | Should -Be 5
        $reused[1].process_image | Should -BeExactly 'SyntheticOther.exe'
        $reused[1].transferred_bytes | Should -Be 512
        $late = @($rows | Where-Object { $_.process_id -eq 6000 })
        $late.Count | Should -Be 1
        $late[0].process_image | Should -BeExactly 'SyntheticEarly.exe' -Because 'an id first named after the request takes the first image the trace gives it, not the last'
        $early = @($rows | Where-Object { $_.transferred_bytes -eq 3072 })
        $early.Count | Should -Be 1
        $early[0].process_id | Should -Be 1200 -Because 'a request before its thread''s first Thread event belongs to the first process the trace gives that thread id, not to the one the id went to later'
        $early[0].process_image | Should -BeExactly 'SyntheticGame.exe'
        $unnamedThen = @($rows | Where-Object { $_.transferred_bytes -eq 5120 })
        $unnamedThen.Count | Should -Be 1
        $unnamedThen[0].directory | Should -Match '^\\ProgramData\\SyntheticGame\\dir-[0-9a-f]{12}\\dir-[0-9a-f]{12}$' -Because 'a request before its file object''s first name event belongs to the first file the trace names by that object, not to the one the address named later'
        $unnamedThen[0].extension | Should -BeExactly '.log'
    }

    It 'fails the run and keeps no aggregate when the recording cannot be confirmed removed' {
        $arguments = Start-DiskCase
        $out = Join-Path $TestDrive 'held'
        $global:DiskPrivateDir = Join-Path $out 'private'
        # As a file another process holds open without delete sharing: nothing can be removed from the folder.
        $global:WfSynthetic.Tracerpt.OnDump = { & chmod 555 $global:DiskPrivateDir }
        try {
            $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
            Test-Path -LiteralPath (Join-Path $global:DiskPrivateDir 'trace.etl') | Should -BeTrue -Because 'the case is about a recording that is still there'
        } finally {
            if (Test-Path -LiteralPath $global:DiskPrivateDir) { & chmod 755 $global:DiskPrivateDir }
        }
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        $aggregate = Get-DiskSource -Run $run -Id 'diskio_aggregate'
        $aggregate.status | Should -BeExactly 'capture_failed'
        $aggregate.status_reason | Should -Match 'recording under <bundle>/private .* could not be confirmed removed'
        $aggregate.expectation.met | Should -BeFalse
        $aggregate.enabled.options.recording_and_dump_removed | Should -BeFalse
        @($aggregate.artifacts | ForEach-Object { $_.path }) | Should -Be @('raw/diskio_aggregate/command.json', 'raw/diskio_aggregate/result.json')
        Test-Path -LiteralPath (Join-Path $out 'raw/diskio_aggregate/aggregate.jsonl') | Should -BeFalse
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed' -Because 'no source of a run that left its recording behind is presented as observed'
        $trace.status_reason | Should -Match 'could not be confirmed removed'
        $trace.expectation.met | Should -BeFalse
        $run.Manifest.capture.incomplete | Should -BeTrue
        @($run.Manifest.notes | Where-Object { $_ -match 'delete <bundle>/private by hand' }).Count | Should -Be 1
        $result = Get-Content -LiteralPath (Join-Path $out 'raw/diskio_aggregate/result.json') -Raw | ConvertFrom-Json
        $result.recording_and_dump_removed | Should -BeFalse
        $result.rows | Should -Be 0
        (Get-Content -LiteralPath (Join-Path $out 'manifest.json') -Raw) + (Get-Content -LiteralPath (Join-Path $out 'raw/diskio_aggregate/result.json') -Raw) | Should -Not -Match ([regex]::Escape($out)) -Because 'the reason names the folder as <bundle>/private, not by its location'
    }

    It 'runs nothing when the account is not elevated, and the aggregate says why' {
        $arguments = Start-DiskCase -Case 'diskio-trace-not-elevated'
        $out = Join-Path $TestDrive 'not-elevated'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        $global:WfSynthetic.Processes.Count | Should -Be 0
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'not elevated'
        $aggregate = Get-DiskSource -Run $run -Id 'diskio_aggregate'
        $aggregate.status | Should -BeExactly 'not_collected'
        $aggregate.status_reason | Should -Match 'no complete trace'
        @($aggregate.artifacts | Where-Object { $_.role -eq 'primary' }).Count | Should -Be 0
        Assert-DiskNothingLeft -Out $out
    }

    It 'refuses a busy default instance, a missing wpr or tracerpt, and a profile wpr does not enumerate' {
        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.State = 'recording'
        $run = Invoke-DiskCase -Name 'busy' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'did not read as idle'
        Get-DiskWprVerbs | Should -Be @('-status') -Because 'a recording it did not start is never cancelled'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.Present = $false
        $run = Invoke-DiskCase -Name 'no-wpr' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status | Should -BeExactly 'not_collected'
        $global:WfSynthetic.Processes.Count | Should -Be 0

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.Present = $false
        $run = Invoke-DiskCase -Name 'no-tracerpt' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'tracerpt.exe'
        $global:WfSynthetic.Processes.Count | Should -Be 0

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.ProfilesExitCode = 2
        $run = Invoke-DiskCase -Name 'bad-profile' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'did not enumerate'
        Get-DiskWprVerbs | Should -Be @('-status', '-profiles')
    }

    It 'reports a refused start as not_collected, and cancels what a refused start left running' {
        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StartExitCode = 1
        $global:WfSynthetic.Wpr.StartStdErr = "The NT Kernel Logger session is already in use.`r`n"
        $run = Invoke-DiskCase -Name 'start-refused' -Arguments $arguments
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'not_collected'
        $trace.status_reason | Should -Match 'wpr -start was refused'
        $trace.status_reason | Should -Match 'already in use'
        Get-DiskWprVerbs | Should -Be @('-status', '-profiles', '-start', '-status')

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StartExitCode = 1
        $global:WfSynthetic.Wpr.StartLeavesRunning = $true
        $run = Invoke-DiskCase -Name 'start-left-running' -Arguments $arguments
        Get-DiskWprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-cancel', '-status')
        (Get-DiskSource -Run $run -Id 'wpr_trace').enabled.options.session_confirmed_stopped | Should -BeTrue

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StartStuck = $true
        $global:WfSynthetic.Wpr.CancelLeavesRunning = $true
        $run = Invoke-DiskCase -Name 'start-stuck' -Arguments $arguments
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'may still be recording'
        @($run.Manifest.notes | Where-Object { $_ -match 'wpr -cancel -instancename WfDiskIoTrace-' }).Count | Should -Be 1
    }

    It 'cancels a session whose settings cannot be verified, and never records it' {
        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.Keywords = @('DiskIO', 'Filename', 'ProcessThread')
        $run = Invoke-DiskCase -Name 'no-hardfaults' -Arguments $arguments
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'no HardFaults keyword'
        Get-DiskWprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-status', '-cancel', '-status')
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'not_collected'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.EventsLostText = 'n/a'
        $run = Invoke-DiskCase -Name 'unreadable-loss' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'Events Lost'
    }

    It 'cancels and confirms when the stop fails or does not finish, and keeps nothing' {
        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StopExitCode = 1
        $global:WfSynthetic.Wpr.StopStdErr = "synthetic stop failure`r`n"
        $out = Join-Path $TestDrive 'stop-failed'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.status_reason | Should -Match 'wpr -stop failed'
        Get-DiskWprVerbs | Should -Be @('-status', '-profiles', '-start', '-status', '-stop', '-status', '-cancel', '-status')
        Assert-DiskNothingLeft -Out $out

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StopStuck = $true
        $run = Invoke-DiskCase -Name 'stop-stuck' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'did not finish within'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.StopLeavesRunning = $true
        $global:WfSynthetic.Wpr.CancelLeavesRunning = $true
        $run = Invoke-DiskCase -Name 'still-running' -Arguments $arguments
        $trace = Get-DiskSource -Run $run -Id 'wpr_trace'
        $trace.status | Should -BeExactly 'capture_failed'
        $trace.enabled.options.session_confirmed_stopped | Should -BeFalse
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'not_collected'
    }

    It 'fails the trace on any final loss, an unreadable header, a header without an end, and a clock other than the counter' {
        $arguments = Start-DiskCase -Case 'diskio-trace-events-lost'
        $run = Invoke-DiskCase -Name 'lost' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'lost 544 events'
        @(Get-DiskTracerptRuns).Count | Should -Be 1 -Because 'no dump is made from a lossy trace'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.BuffersLost = 2
        $run = Invoke-DiskCase -Name 'lost-buffers' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status | Should -BeExactly 'capture_failed'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.Labels = 'nonnumeric'
        $run = Invoke-DiskCase -Name 'loss-unreadable' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'no single whole number'
        (Get-DiskSource -Run $run -Id 'wpr_trace').events_lost | Should -BeNullOrEmpty -Because 'an unreadable figure is null, never zero'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.EtlContent = $null
        $run = Invoke-DiskCase -Name 'no-header' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'log file header could not be read'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.EtlContent = New-WfSyntheticEtlBytes -DurationSeconds 10 -NoEndTime
        $run = Invoke-DiskCase -Name 'no-end' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'no end time'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.EtlContent = New-WfSyntheticEtlBytes -DurationSeconds 10 -ClockType 2
        $run = Invoke-DiskCase -Name 'system-clock' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'system_time clock'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Wpr.EtlContent = New-WfSyntheticEtlBytes -DurationSeconds 10 -EventsLost 3
        $run = Invoke-DiskCase -Name 'header-loss' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'header records 3 events lost'
    }

    It 'never presents a dump it could not read whole as an aggregate' {
        $arguments = Start-DiskCase -Case 'diskio-trace-dump-unrendered'
        $out = Join-Path $TestDrive 'unrendered'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 0
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'partial'
        $aggregate = Get-DiskSource -Run $run -Id 'diskio_aggregate'
        $aggregate.status | Should -BeExactly 'capture_failed'
        $aggregate.status_reason | Should -Match 'could not be read'
        Test-Path -LiteralPath (Join-Path $out 'raw/diskio_aggregate/aggregate.jsonl') | Should -BeFalse
        Assert-DiskNothingLeft -Out $out

        $arguments = Start-DiskCase -Machine @{ ExtraProcessed = 1 }
        $run = Invoke-DiskCase -Name 'count-mismatch' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status_reason | Should -Match 'events processed'

        $arguments = Start-DiskCase -Machine @{ NoDiskEvents = $true }
        $run = Invoke-DiskCase -Name 'no-disk' -Arguments $arguments
        $aggregate = Get-DiskSource -Run $run -Id 'diskio_aggregate'
        $aggregate.status | Should -BeExactly 'capture_failed' -Because 'zero disk requests is never a quiet window'
        $aggregate.status_reason | Should -Match 'not accepted as a quiet window'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.Stuck = $true
        $out = Join-Path $TestDrive 'read-stuck'
        $run = Invoke-TestCollector -Collector 'diskio-trace' -OutputDirectory $out -Arguments $arguments
        $run.ExitCode | Should -Be 1
        (Get-DiskSource -Run $run -Id 'wpr_trace').status | Should -BeExactly 'capture_failed'
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'final loss statistics could not be read.*did not finish within'
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'not_collected'
        @(Get-DiskTracerptRuns).Count | Should -Be 1 -Because 'the aggregate starts no tracerpt of its own'
        Assert-DiskNothingLeft -Out $out

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.ExitCode = 5
        $run = Invoke-DiskCase -Name 'read-failed' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'wpr_trace').status_reason | Should -Match 'final loss statistics could not be read'
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'not_collected'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.DumpXml = $null
        $run = Invoke-DiskCase -Name 'dump-missing' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status_reason | Should -Match 'wrote no dump'

        $arguments = Start-DiskCase
        $global:WfSynthetic.Tracerpt.DumpXml = '<Events><Event><System>'
        $run = Invoke-DiskCase -Name 'dump-broken' -Arguments $arguments
        (Get-DiskSource -Run $run -Id 'diskio_aggregate').status | Should -BeExactly 'capture_failed'
    }

    It 'refuses a run whose worst case exceeds the dispatcher budget, and values out of range' {
        Start-DiskCase | Out-Null
        $run = Invoke-DiskCase -Name 'too-long' -Arguments @{ DurationSeconds = 300; TimeoutSeconds = 120 }
        $run.ExitCode | Should -Be 1
        ($run.Stdout[0] | ConvertFrom-Json).status | Should -BeExactly 'failed'
        Test-Path -LiteralPath (Join-Path $TestDrive 'too-long') | Should -BeFalse
        $global:WfSynthetic.Processes.Count | Should -Be 0
        $run = Invoke-DiskCase -Name 'small-dump-cap' -Arguments @{ MaxDumpBytes = 1024 }
        $run.ExitCode | Should -Be 1
        (Get-DiskIoWorstCaseSeconds -DurationSeconds 60 -TimeoutSeconds 120) | Should -Be 690
    }

    It 'keeps fixed roots and one level below them, replaces the user folder, and pseudonymises everything deeper' {
        $salt = 'unit-salt'
        $p = ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\Alice\Documents\Taxes\2025\return.pdf' -Salt $salt -CollectorPrefix ''
        $p.volume | Should -BeExactly 'HarddiskVolume3'
        $p.directory | Should -BeExactly ('\Users\<profile>\Documents\Taxes\' + (ConvertTo-WfPseudonym -Kind 'dir' -Value '\users\alice\documents\taxes\2025' -Salt $salt))
        $p.extension | Should -BeExactly '.pdf'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\Alice\notes.txt' -Salt $salt -CollectorPrefix '').directory | Should -BeExactly '\Users\<profile>'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\Alice\Music\Band\a.mp3' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\Users\\<profile>\\dir-[0-9a-f]{12}\\dir-[0-9a-f]{12}$'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\Alice\AppData\Roaming\App\x\y.db' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\Users\\<profile>\\AppData\\Roaming\\App\\dir-[0-9a-f]{12}$'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Windows\System32\drivers\x.sys' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\Windows\\System32\\dir-[0-9a-f]{12}$'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Program Files (x86)\Vendor\bin\a.dll' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\Program Files \(x86\)\\Vendor\\dir-'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$Mft' -Salt $salt -CollectorPrefix '').directory | Should -BeExactly '\'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$Extend\$UsnJrnl' -Salt $salt -CollectorPrefix '').directory | Should -BeExactly '\$Extend'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\pagefile.sys' -Salt $salt -CollectorPrefix '').extension | Should -BeExactly '.sys'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$Extend\$RmMetadata\$TxfLog\$TxfLog.blf' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\\$Extend\\\$RmMetadata\\dir-[0-9a-f]{12}$'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$Extend\Alice\x.dat' -Salt $salt -CollectorPrefix '').directory | Should -Match '^\\\$Extend\\dir-[0-9a-f]{12}$' -Because 'below $Extend only the names NTFS reserves there stay readable'
        $bin = ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$Recycle.Bin\S-1-5-21-1000000001-1000000002-1000000003-1001\$I1234.txt' -Salt $salt -CollectorPrefix ''
        $bin.directory | Should -Match '^\\dir-[0-9a-f]{12}\\dir-[0-9a-f]{12}$' -Because 'a $ name that is not NTFS metadata is no root, so the account id below the recycle bin is never readable'
        $bin.directory | Should -Not -Match 'S-1-5|Recycle'
        $bin.extension | Should -BeExactly '.txt'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\$WINDOWS.~BT\Sources\Panther\setup.log' -Salt $salt -CollectorPrefix '').directory | Should -Match '^(\\dir-[0-9a-f]{12}){3}$'
        $c = ConvertTo-DiskIoPathParts -FileName 'C:\Games\Library\Title\data.bin' -Salt $salt -CollectorPrefix ''
        $c.volume | Should -BeNullOrEmpty
        $c.directory | Should -Match '^(\\dir-[0-9a-f]{12}){4}$' -Because 'a name with a drive letter, which the kernel does not write, has no fixed root: every component is a pseudonym'
        $share = ConvertTo-DiskIoPathParts -FileName '\Device\Mup\fileserver\share\f.txt' -Salt $salt -CollectorPrefix ''
        $share.volume | Should -BeExactly 'Mup'
        $share.directory | Should -Not -Match 'fileserver|share'
        (ConvertTo-DiskIoPathParts -FileName '\Device\Weird-Name\a.txt' -Salt $salt -CollectorPrefix '').volume | Should -Match '^dir-[0-9a-f]{12}$'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Windows\a.tar~1' -Salt $salt -CollectorPrefix '').extension | Should -BeExactly 'other'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Windows\README' -Salt $salt -CollectorPrefix '').extension | Should -BeNullOrEmpty
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Windows\Setup.LOG' -Salt $salt -CollectorPrefix '').extension | Should -BeExactly '.log'
        # The trace cannot tell a folder from a file: the tail of a dotted folder name is never kept as an extension.
        $profileFolder = ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\john.smith' -Salt $salt -CollectorPrefix ''
        $profileFolder.directory | Should -BeExactly '\Users'
        $profileFolder.extension | Should -BeExactly 'other'
        $dotted = ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\x\Documents\Private\Taxes.2025' -Salt $salt -CollectorPrefix ''
        $dotted.directory | Should -BeExactly '\Users\<profile>\Documents\Private'
        $dotted.extension | Should -BeExactly 'other'
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Users\Alice\Music\Band\a.mp3' -Salt $salt -CollectorPrefix '').extension | Should -BeExactly 'other' -Because 'only the listed file classes keep their extension'
        @((Get-DiskIoPseudonymRules).kept_extensions) | Should -Be @(Get-DiskIoKeptExtensions) -Because 'the bundle states the list the rule applied'
        $own = ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Out\Bundle\private\trace.etl' -Salt $salt -CollectorPrefix '\out\bundle'
        $own.path_class | Should -BeExactly 'collector'
        $own.directory | Should -BeNullOrEmpty
        (ConvertTo-DiskIoPathParts -FileName '\Device\HarddiskVolume3\Out\BundleOther\x.etl' -Salt $salt -CollectorPrefix '\out\bundle').path_class | Should -BeExactly 'named'
        ConvertTo-DiskIoImageName -Image 'Game-Shipping.exe' -Salt $salt | Should -BeExactly 'Game-Shipping.exe'
        ConvertTo-DiskIoImageName -Image 'C:\Users\Alice\x.exe' -Salt $salt | Should -Match '^image-[0-9a-f]{12}$'
        ConvertTo-DiskIoImageName -Image '' -Salt $salt | Should -BeNullOrEmpty
    }

    It 'reads numbers and summaries without ever turning an unreadable value into zero' {
        ConvertTo-DiskIoNumber -Text ' 12 ' | Should -Be 12
        ConvertTo-DiskIoNumber -Text '0x1F' | Should -Be 31
        ConvertTo-DiskIoNumber -Text '-1' | Should -BeNullOrEmpty
        ConvertTo-DiskIoNumber -Text '1,234' | Should -BeNullOrEmpty
        ConvertTo-DiskIoNumber -Text $null | Should -BeNullOrEmpty
        $summary = Read-DiskIoSummary -Text "Total Buffers Processed 69`r`nTotal Events  Processed 31`r`nTotal Events  Lost      0`r`nTotal Buffers Lost      0`r`n"
        $summary.events_processed | Should -Be 31
        $summary.events_lost | Should -Be 0
        $summary.buffers_lost | Should -Be 0
        (Read-DiskIoSummary -Text "Events Lost: 0`nEvents Lost: 4`nBuffers Lost: 0").events_lost | Should -BeNullOrEmpty -Because 'two lines that disagree give no figure'
        (Read-DiskIoSummary -Text "Events Lost: n/a`nBuffers Lost: 0").events_lost | Should -BeNullOrEmpty
        (Read-DiskIoSummary -Text 'nothing here').events_processed | Should -BeNullOrEmpty
    }

    It 'reads the log file header as the presentmon-frames reader does, on the vendor''s first buffer and the synthetic one' {
        foreach ($path in @($script:DiskGold)) {
            $mine = Read-DiskIoEtlHeader -Path $path
            $theirs = Read-WfEtlHeader -Path $path
            $mine.found | Should -BeTrue
            $mine.clock_type | Should -BeExactly $theirs.clock_type
            $mine.perf_freq_hz | Should -Be $theirs.perf_freq_hz
            $mine.start_time_utc | Should -BeExactly $theirs.start_time_utc
            $mine.end_time_utc | Should -BeExactly $theirs.end_time_utc
            $mine.events_lost | Should -Be $theirs.events_lost
            $mine.buffers_lost | Should -Be $theirs.buffers_lost
        }
        Reset-WfSynthetic
        $synthetic = Join-Path $TestDrive 'synthetic-header.etl'
        [System.IO.File]::WriteAllBytes($synthetic, (New-WfSyntheticEtlBytes -DurationSeconds 10))
        $header = Read-DiskIoEtlHeader -Path $synthetic
        $header.found | Should -BeTrue
        $header.clock_type | Should -BeExactly 'qpc'
        $header.start_time_utc | Should -BeExactly '2026-03-01T12:00:07.0000000Z'
        $filler = Join-Path $TestDrive 'filler.etl'
        Write-WfSyntheticFiller -Path $filler -Bytes 4096
        (Read-DiskIoEtlHeader -Path $filler).found | Should -BeFalse
    }
}
