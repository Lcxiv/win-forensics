# Pester 5 tests for dispatch.ps1, the forced command. They run the real script under PowerShell 7
# off Windows against a throwaway copy of the installed layout, with fake collectors. What they
# cannot show is behaviour that belongs to Windows PowerShell 5.1 or to sshd on Windows; the
# loopback self test in Install-FrontDoor.ps1 and the Mac side acceptance checks cover that.

BeforeAll {
    $script:WindowsDir = (Resolve-Path (Join-Path $PSScriptRoot '../windows')).Path
    . (Join-Path $script:WindowsDir 'dispatch.ps1')

    function New-TestLayout {
        # <root>/remote/{dispatch.ps1,WfCommon.ps1,collectors/} and <root>/outbox, as installed.
        $root = Join-Path $TestDrive ([System.Guid]::NewGuid().ToString('N'))
        $remote = Join-Path $root 'remote'
        [void](New-Item -ItemType Directory -Path (Join-Path $remote 'collectors') -Force)
        [void](New-Item -ItemType Directory -Path (Join-Path $root 'outbox') -Force)
        Copy-Item -LiteralPath (Join-Path $script:WindowsDir 'dispatch.ps1') -Destination $remote
        Copy-Item -LiteralPath (Join-Path $script:WindowsDir 'WfCommon.ps1') -Destination $remote
        return Get-WfDispatchConfig -RemoteDir $remote -DispatcherPath (Join-Path $remote 'dispatch.ps1')
    }

    function Add-TestCollector {
        param([hashtable]$Config, [string]$Name, [string]$Body)
        $text = "param([Parameter(Mandatory = `$true)][string]`$OutputDirectory)`n" + $Body + "`n"
        [System.IO.File]::WriteAllText((Join-Path $Config.CollectorsDir ($Name + '.ps1')), $text)
    }

    function Invoke-TestDispatch {
        # In process: returns exit code plus what was written to the two streams.
        param([hashtable]$Config, [AllowNull()][string]$Requested)
        $out = New-Object System.IO.MemoryStream
        $err = New-Object System.IO.MemoryStream
        $code = @(Invoke-WfDispatch -Requested $Requested -Config $Config -OutStream $out -ErrStream $err)
        return @{
            ExitCode = [int]$code[$code.Count - 1]
            StdOut   = [System.Text.Encoding]::UTF8.GetString($out.ToArray())
            StdErr   = [System.Text.Encoding]::UTF8.GetString($err.ToArray())
        }
    }

    $script:OkCollector = @'
[void](New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'raw'))
[System.IO.File]::WriteAllText((Join-Path $OutputDirectory 'manifest.json'), '{"manifest_version":"1.0.0"}')
[System.IO.File]::WriteAllText((Join-Path (Join-Path $OutputDirectory 'raw') 'events.json'), ('[]' * 40000))
[Console]::Error.WriteLine('collector diagnostic')
[Console]::Out.WriteLine('some earlier output')
[Console]::Out.WriteLine('{"collector":"sample-ok","status":"ok","bundle":"ignored","artifacts":2}')
exit 0
'@
}

Describe 'Resolve-WfVerb: the allowlist' {
    It 'allows exactly <Requested>' -ForEach @(
        @{ Requested = 'ping'; Verb = 'ping'; Argument = '' }
        @{ Requested = 'list-bundles'; Verb = 'list-bundles'; Argument = '' }
        @{ Requested = 'security-log-access'; Verb = 'security-log-access'; Argument = '' }
        @{ Requested = 'collect-bugcheck-history'; Verb = 'collect'; Argument = 'bugcheck-history' }
        @{ Requested = 'fetch-20260930T171044Z_bugcheck-history_d1392f17'; Verb = 'fetch'; Argument = '20260930T171044Z_bugcheck-history_d1392f17' }
    ) {
        $resolved = Resolve-WfVerb -Requested $Requested
        $resolved.Verb | Should -BeExactly $Verb
        $resolved.Argument | Should -BeExactly $Argument
    }

    It 'refuses <Requested>' -ForEach @(
        @{ Requested = $null }
        @{ Requested = '' }
        @{ Requested = 'whoami' }
        @{ Requested = 'PING' }
        @{ Requested = 'ping ' }
        @{ Requested = ' ping' }
        @{ Requested = "ping`n" }
        @{ Requested = 'ping; whoami' }
        @{ Requested = 'ping & whoami' }
        @{ Requested = 'ping | whoami' }
        @{ Requested = 'ping whoami' }
        @{ Requested = 'ping$(whoami)' }
        @{ Requested = 'ping`whoami`' }
        @{ Requested = 'powershell -Command whoami' }
        @{ Requested = 'cmd /c whoami' }
        @{ Requested = 'scp -f C:\Windows\win.ini' }
        @{ Requested = 'internal-sftp' }
        @{ Requested = 'collect-' }
        @{ Requested = 'collect-a' }
        @{ Requested = 'collect-A' }
        @{ Requested = 'collect-../../evil' }
        @{ Requested = 'collect-..\evil' }
        @{ Requested = 'collect-ok -OutputDirectory C:\' }
        @{ Requested = 'collect-ok;whoami' }
        @{ Requested = 'collect-ok.ps1' }
        @{ Requested = 'fetch-' }
        @{ Requested = 'fetch-..' }
        @{ Requested = 'fetch-20260930T171044Z_ab_d1392f17/../..' }
        @{ Requested = 'fetch-20260930T171044Z_ab_D1392F17' }
        @{ Requested = 'fetch-C:\Windows\System32\config\SAM' }
        @{ Requested = ('ping' + ('x' * 200)) }
    ) {
        (Resolve-WfVerb -Requested $Requested).Verb | Should -BeExactly 'refuse'
    }
}

Describe 'Refusal' {
    It 'answers a refused request with JSON, a message on stderr, exit code 64, and no echo of the request' {
        $config = New-TestLayout
        $result = Invoke-TestDispatch -Config $config -Requested 'whoami-MARKER-7731'
        $result.ExitCode | Should -Be 64
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.ok | Should -BeFalse
        $json.error | Should -BeExactly 'refused'
        $result.StdErr | Should -Match 'refused'
        ($result.StdOut + $result.StdErr) | Should -Not -Match 'MARKER-7731'
    }

    It 'never starts a process for a refused request' {
        $config = New-TestLayout
        Mock Invoke-WfNative { throw 'a refused request must not run anything' }
        (Invoke-TestDispatch -Config $config -Requested 'collect-../x').ExitCode | Should -Be 64
        (Invoke-TestDispatch -Config $config -Requested 'ping; whoami').ExitCode | Should -Be 64
        Should -Invoke Invoke-WfNative -Times 0
    }
}

Describe 'ping' {
    It 'returns one line of health JSON with the host name hashed, not shown' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'sample-ok' -Body $script:OkCollector
        Add-TestCollector -Config $config -Name 'Not_A_Collector' -Body 'exit 0'
        $result = Invoke-TestDispatch -Config $config -Requested 'ping'
        $result.ExitCode | Should -Be 0
        @($result.StdOut.TrimEnd("`n") -split "`n").Count | Should -Be 1
        $result.StdOut | Should -Match '"ok":true'
        $result.StdOut | Should -Match '"verb":"ping"'
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.host_id | Should -MatchExactly '\A[0-9a-f]{16}\z'
        # Checked on the raw text: ConvertFrom-Json turns date shaped strings into DateTime.
        $result.StdOut | Should -MatchExactly '"time_utc":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
        $json.account | Should -BeExactly ([System.Environment]::UserName)
        @($json.collectors) | Should -Be @('sample-ok')
        $json.dispatcher_sha256 | Should -BeExactly (Get-WfFileSha256 -Path $config.DispatcherPath)
        $json.outbox.bundles | Should -Be 0
        $result.StdOut.ToLowerInvariant().Contains([System.Environment]::MachineName.ToLowerInvariant()) | Should -BeFalse
    }

    It 'never lists, and never runs, a helper file that sits next to the collectors' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'sample-ok' -Body $script:OkCollector
        Add-TestCollector -Config $config -Name '_common' -Body '[Console]::Out.WriteLine("helper ran")'
        @((ConvertFrom-Json -InputObject (Invoke-TestDispatch -Config $config -Requested 'ping').StdOut).collectors) | Should -Be @('sample-ok')
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-_common'
        $result.ExitCode | Should -Be 64
        $result.StdOut | Should -Not -Match 'helper ran'
        @(Get-ChildItem -LiteralPath $config.OutboxDir).Count | Should -Be 0
    }

    It 'writes ASCII only' {
        $line = ConvertTo-WfJsonLine -InputObject ([ordered]@{ name = ([string][char]0xE9) + 'cole'; tab = "a`tb" })
        $line | Should -MatchExactly '\A[\x20-\x7E]+\z'
        (ConvertFrom-Json -InputObject $line).name | Should -BeExactly (([string][char]0xE9) + 'cole')
    }
}

Describe 'collect' {
    It 'answers "unknown collector" with exit code 65 while no collector is installed' {
        $config = New-TestLayout
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-bugcheck-history'
        $result.ExitCode | Should -Be 65
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.error | Should -BeExactly 'unknown collector'
        $json.collector | Should -BeExactly 'bugcheck-history'
        @($json.available).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $config.OutboxDir).Count | Should -Be 0
    }

    It 'runs the named collector into a new outbox directory and reports the bundle' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'sample-ok' -Body $script:OkCollector
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-sample-ok'
        $result.ExitCode | Should -Be 0
        $result.StdErr | Should -Match 'collector diagnostic'
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.ok | Should -BeTrue
        $json.bundle_dir | Should -MatchExactly '\A[0-9]{8}T[0-9]{6}Z_sample-ok_[0-9a-f]{8}\z'
        $json.summary_valid | Should -BeTrue
        $json.summary.status | Should -BeExactly 'ok'
        $json.summary.artifacts | Should -Be 2
        $json.files | Should -Be 2
        $json.fetch | Should -BeExactly ('fetch-' + $json.bundle_dir)
        Test-Path -LiteralPath (Join-Path (Join-Path $config.OutboxDir $json.bundle_dir) 'manifest.json') | Should -BeTrue
    }

    It 'passes the collector exactly one parameter, a directory inside the outbox' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'show-args' -Body @'
[System.IO.File]::WriteAllText((Join-Path $OutputDirectory 'args.txt'), ($OutputDirectory + '|' + $args.Count))
[Console]::Out.WriteLine('{"collector":"show-args","status":"ok","bundle":"x","artifacts":1}')
'@
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-show-args'
        $result.ExitCode | Should -Be 0
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $written = [System.IO.File]::ReadAllText((Join-Path (Join-Path $config.OutboxDir $json.bundle_dir) 'args.txt'))
        $written | Should -BeExactly ((Join-Path $config.OutboxDir $json.bundle_dir) + '|0')
    }

    It 'reports a failing collector with exit code 71 and keeps the partial bundle' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'sample-bad' -Body @'
[System.IO.File]::WriteAllText((Join-Path $OutputDirectory 'partial.txt'), 'x')
[Console]::Out.WriteLine('{"collector":"sample-bad","status":"failed","bundle":"x","artifacts":1}')
exit 3
'@
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-sample-bad'
        $result.ExitCode | Should -Be 71
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.ok | Should -BeFalse
        $json.collector_exit_code | Should -Be 3
        $json.summary.status | Should -BeExactly 'failed'
        $json.files | Should -Be 1
    }

    It 'treats a summary line that is not of the agreed shape as data it does not trust' {
        $config = New-TestLayout
        Add-TestCollector -Config $config -Name 'sample-odd' -Body @'
[Console]::Out.WriteLine('{"collector":"someone-else","status":"ok","bundle":"C:\\Windows","artifacts":1,"run":"whoami"}')
'@
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-sample-odd'
        $result.ExitCode | Should -Be 0
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.summary_valid | Should -BeFalse
        $json.summary | Should -BeNullOrEmpty
        $result.StdOut | Should -Not -Match 'whoami'
    }

    It 'stops a collector that runs past the time limit with exit code 72' {
        $config = New-TestLayout
        $config.CollectorTimeoutSeconds = 2
        Add-TestCollector -Config $config -Name 'sample-slow' -Body 'Start-Sleep -Seconds 60'
        $result = Invoke-TestDispatch -Config $config -Requested 'collect-sample-slow'
        $result.ExitCode | Should -Be 72
        (ConvertFrom-Json -InputObject $result.StdOut).timed_out | Should -BeTrue
    }

    It 'refuses to collect when the outbox is full, with exit code 73' {
        $config = New-TestLayout
        $config.MaxBundles = 1
        Add-TestCollector -Config $config -Name 'sample-ok' -Body $script:OkCollector
        (Invoke-TestDispatch -Config $config -Requested 'collect-sample-ok').ExitCode | Should -Be 0
        $second = Invoke-TestDispatch -Config $config -Requested 'collect-sample-ok'
        $second.ExitCode | Should -Be 73
        (ConvertFrom-Json -InputObject $second.StdOut).error | Should -BeExactly 'outbox full'
    }
}

Describe 'ConvertFrom-WfCollectorSummary' {
    It 'accepts the agreed summary line and drops the bundle path' {
        $summary = ConvertFrom-WfCollectorSummary -StdOut "noise`r`n{`"collector`":`"ab`",`"status`":`"partial`",`"bundle`":`"C:\\x`",`"artifacts`":3}`r`n" -CollectorName 'ab'
        $summary.status | Should -BeExactly 'partial'
        $summary.artifacts | Should -Be 3
        $summary.Contains('bundle') | Should -BeFalse
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'no output'; StdOut = '' }
        @{ Case = 'text that is not JSON'; StdOut = 'done' }
        @{ Case = 'a JSON array'; StdOut = '[1,2]' }
        @{ Case = 'an unknown status'; StdOut = '{"collector":"ab","status":"great","artifacts":1}' }
        @{ Case = 'a missing field'; StdOut = '{"collector":"ab","status":"ok"}' }
        @{ Case = 'a negative count'; StdOut = '{"collector":"ab","status":"ok","artifacts":-1}' }
        @{ Case = 'another collector name'; StdOut = '{"collector":"cd","status":"ok","artifacts":1}' }
    ) {
        ConvertFrom-WfCollectorSummary -StdOut $StdOut -CollectorName 'ab' | Should -BeNullOrEmpty
    }
}

Describe 'list-bundles and fetch' {
    BeforeAll {
        $script:FetchConfig = New-TestLayout
        Add-TestCollector -Config $script:FetchConfig -Name 'sample-ok' -Body $script:OkCollector
        $collected = Invoke-TestDispatch -Config $script:FetchConfig -Requested 'collect-sample-ok'
        $script:BundleId = (ConvertFrom-Json -InputObject $collected.StdOut).bundle_dir
        [void](New-Item -ItemType Directory -Path (Join-Path $script:FetchConfig.OutboxDir 'not-a-bundle'))
    }

    It 'lists finished bundles and nothing else' {
        $result = Invoke-TestDispatch -Config $script:FetchConfig -Requested 'list-bundles'
        $result.ExitCode | Should -Be 0
        $json = ConvertFrom-Json -InputObject $result.StdOut
        @($json.bundles).Count | Should -Be 1
        $json.bundles[0].bundle_dir | Should -BeExactly $script:BundleId
        $json.bundles[0].files | Should -Be 2
    }

    It 'streams the bundle as a framed base64 zip whose size and SHA-256 match the header' {
        $result = Invoke-TestDispatch -Config $script:FetchConfig -Requested ('fetch-' + $script:BundleId)
        $result.ExitCode | Should -Be 0
        $result.StdOut | Should -Not -Match "`r"
        $lines = @($result.StdOut.TrimEnd("`n") -split "`n")
        $lines[0] | Should -MatchExactly ('\AWF-BUNDLE-BEGIN v1 dir=' + [regex]::Escape($script:BundleId) + ' bytes=[0-9]+ sha256=[0-9a-f]{64}\z')
        $lines[$lines.Count - 1] | Should -BeExactly ('WF-BUNDLE-END v1 dir=' + $script:BundleId)
        $body = @($lines[1..($lines.Count - 2)])
        foreach ($line in $body) { $line.Length | Should -BeLessOrEqual 76 }
        $bytes = [System.Convert]::FromBase64String(($body -join ''))
        $lines[0] -match 'bytes=([0-9]+) sha256=([0-9a-f]{64})' | Should -BeTrue
        $bytes.Length | Should -Be ([int]$Matches[1])
        $expectedHash = $Matches[2]
        $zipPath = Join-Path $TestDrive 'fetched.zip'
        [System.IO.File]::WriteAllBytes($zipPath, $bytes)
        Get-WfFileSha256 -Path $zipPath | Should -BeExactly $expectedHash

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $names = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        } finally {
            $zip.Dispose()
        }
        $names | Should -Be @("$script:BundleId/manifest.json", "$script:BundleId/raw/events.json")
    }

    It 'leaves nothing behind in the staging directory' {
        @(Get-ChildItem -LiteralPath $script:FetchConfig.StagingDir -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'answers "unknown bundle" with exit code 66 for a well formed id that is not there' {
        $result = Invoke-TestDispatch -Config $script:FetchConfig -Requested 'fetch-20200101T000000Z_sample-ok_00000000'
        $result.ExitCode | Should -Be 66
        (ConvertFrom-Json -InputObject $result.StdOut).error | Should -BeExactly 'unknown bundle'
    }
}

Describe 'security-log-access' {
    It 'parses channelAccess out of wevtutil gl output' {
        $text = "name: Security`r`nenabled: true`r`n  channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)`r`nlogging:`r`n"
        Get-WfChannelAccess -Text $text | Should -BeExactly 'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)'
        Get-WfChannelAccess -Text 'Access is denied.' | Should -BeNullOrEmpty
    }

    It 'reports what the two wevtutil queries returned, as a measurement' {
        $config = New-TestLayout
        $config.WevtutilExe = $config.DispatcherPath
        Mock Invoke-WfNative {
            if ($ArgumentList[0] -eq 'gl') {
                return [pscustomobject]@{ ExitCode = 0; StdOut = "name: Security`r`nchannelAccess: O:BAG:SYD:(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)`r`n"; StdErr = ''; TimedOut = $false }
            }
            return [pscustomobject]@{ ExitCode = 5; StdOut = ''; StdErr = 'Access is denied.'; TimedOut = $false }
        }
        $result = Invoke-TestDispatch -Config $config -Requested 'security-log-access'
        $result.ExitCode | Should -Be 0
        $json = ConvertFrom-Json -InputObject $result.StdOut
        $json.config_readable | Should -BeTrue
        $json.channel_access | Should -BeExactly 'O:BAG:SYD:(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)'
        $json.event_log_readers_read_entry | Should -BeTrue
        $json.log_readable | Should -BeFalse
        $json.log_info_exit_code | Should -Be 5
        Should -Invoke Invoke-WfNative -Times 2 -Exactly
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { ($ArgumentList -join ' ') -ceq 'gl Security' }
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { ($ArgumentList -join ' ') -ceq 'gli Security' }
    }

    It 'says so when the Security channel has no read entry for Event Log Readers' {
        $config = New-TestLayout
        $config.WevtutilExe = $config.DispatcherPath
        Mock Invoke-WfNative { [pscustomobject]@{ ExitCode = 0; StdOut = "channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)`r`n"; StdErr = ''; TimedOut = $false } }
        $json = ConvertFrom-Json -InputObject (Invoke-TestDispatch -Config $config -Requested 'security-log-access').StdOut
        $json.event_log_readers_read_entry | Should -BeFalse
    }
}

Describe 'dispatch.ps1 run as the forced command' {
    BeforeAll {
        $script:RunConfig = New-TestLayout
        Add-TestCollector -Config $script:RunConfig -Name 'sample-ok' -Body $script:OkCollector
        $script:Exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

        function Invoke-ForcedCommand {
            # As sshd does it: the client's words only in SSH_ORIGINAL_COMMAND, no arguments.
            param([AllowNull()][string]$Requested)
            $saved = $env:SSH_ORIGINAL_COMMAND
            try {
                if ($null -eq $Requested) { Remove-Item Env:SSH_ORIGINAL_COMMAND -ErrorAction SilentlyContinue } else { $env:SSH_ORIGINAL_COMMAND = $Requested }
                return Invoke-WfNative -FilePath $script:Exe -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $script:RunConfig.DispatcherPath)
            } finally {
                if ($null -eq $saved) { Remove-Item Env:SSH_ORIGINAL_COMMAND -ErrorAction SilentlyContinue } else { $env:SSH_ORIGINAL_COMMAND = $saved }
            }
        }
    }

    It 'exits 0 for ping with JSON on stdout and nothing on stderr' {
        $run = Invoke-ForcedCommand -Requested 'ping'
        $run.ExitCode | Should -Be 0
        $run.StdErr | Should -BeExactly ''
        (ConvertFrom-Json -InputObject $run.StdOut).verb | Should -BeExactly 'ping'
    }

    It 'exits 64 for <Requested> and runs nothing' -ForEach @(
        @{ Requested = 'whoami' }
        @{ Requested = 'ping; touch PWNED' }
        @{ Requested = 'collect-sample-ok; touch PWNED' }
        @{ Requested = '$(touch PWNED)' }
    ) {
        $run = Invoke-ForcedCommand -Requested $Requested
        $run.ExitCode | Should -Be 64
        $run.StdOut | Should -Match '"error":"refused"'
        @(Get-ChildItem -LiteralPath $script:RunConfig.OutboxDir).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:RunConfig.RemoteDir 'PWNED') | Should -BeFalse
    }

    It 'exits 64 when no command was given (a request for an interactive shell)' {
        (Invoke-ForcedCommand -Requested $null).ExitCode | Should -Be 64
    }

    It 'exits 65 for a collector that is not installed' {
        (Invoke-ForcedCommand -Requested 'collect-not-there').ExitCode | Should -Be 65
    }

    It 'collects and then fetches through the real process boundary' {
        $collect = Invoke-ForcedCommand -Requested 'collect-sample-ok'
        $collect.ExitCode | Should -Be 0
        $id = (ConvertFrom-Json -InputObject (@($collect.StdOut.Trim() -split "`n")[-1])).bundle_dir
        $fetch = Invoke-ForcedCommand -Requested ('fetch-' + $id)
        $fetch.ExitCode | Should -Be 0
        $fetch.StdOut | Should -Match ('\AWF-BUNDLE-BEGIN v1 dir=' + [regex]::Escape($id) + ' ')
        $fetch.StdOut.TrimEnd() | Should -Match ('WF-BUNDLE-END v1 dir=' + [regex]::Escape($id) + '\z')
    }

    It 'takes no script parameters and reads no variable but SSH_ORIGINAL_COMMAND' {
        $text = [System.IO.File]::ReadAllText((Join-Path $script:WindowsDir 'dispatch.ps1'))
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $ast.ParamBlock | Should -BeNullOrEmpty
        $envVariables = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] -and $node.VariablePath.DriveName -eq 'env' }, $true) | ForEach-Object { $_.VariablePath.UserPath } | Sort-Object -Unique)
        $envVariables | Should -Be @('env:SSH_ORIGINAL_COMMAND')
    }

    It 'never uses Invoke-Expression, a script block built from text, or a shell to run anything' {
        foreach ($file in @('dispatch.ps1', 'WfCommon.ps1')) {
            $text = [System.IO.File]::ReadAllText((Join-Path $script:WindowsDir $file))
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
            $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
            foreach ($banned in @('Invoke-Expression', 'iex', 'Start-Process', 'cmd', 'cmd.exe', 'Invoke-Command')) { $commands | Should -Not -Contain $banned }
            $text | Should -Not -Match '\[scriptblock\]::Create|ExecutionContext\.InvokeCommand|AddScript\('
        }
    }
}
