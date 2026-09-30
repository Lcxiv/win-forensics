# Pester 5 tests for the pure functions behind Install-FrontDoor.ps1 (WfSetupLib.ps1, WfCommon.ps1).
# Run off Windows under PowerShell 7; see remote-access/README.md, "Tests".

BeforeAll {
    . (Join-Path $PSScriptRoot '../windows/WfCommon.ps1')
    . (Join-Path $PSScriptRoot '../windows/WfSetupLib.ps1')

    $script:PowerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $script:Layout = Get-WfLayout -ProgramData 'C:\ProgramData'
    $script:Forced = Get-WfForcedCommand -PowerShellExe $script:PowerShellExe -DispatcherPath $script:Layout.Dispatcher
    $script:DefaultConfig = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/sshd_config_default'))
    # A syntactically valid Ed25519 public key: the 19 byte header followed by 32 bytes of 0x07.
    $blob = [byte[]](0, 0, 0, 11) + [System.Text.Encoding]::ASCII.GetBytes('ssh-ed25519') + [byte[]](0, 0, 0, 32) + [byte[]](@(7) * 32)
    $script:KeyBase64 = [System.Convert]::ToBase64String($blob)
}

Describe 'ConvertTo-WfNativeArgument' {
    It 'quotes <Value> as <Expected>' -ForEach @(
        @{ Value = 'plain'; Expected = 'plain' }
        @{ Value = ''; Expected = '""' }
        @{ Value = 'two words'; Expected = '"two words"' }
        @{ Value = 'C:\dir with space\'; Expected = '"C:\dir with space\\"' }
        @{ Value = 'say "hi"'; Expected = '"say \"hi\""' }
        @{ Value = 'a\"b'; Expected = '"a\\\"b"' }
        @{ Value = 'C:\ProgramData\win-forensics'; Expected = 'C:\ProgramData\win-forensics' }
    ) {
        ConvertTo-WfNativeArgument -Argument $Value | Should -BeExactly $Expected
    }
}

Describe 'Invoke-WfNative' {
    It 'returns exit code, stdout, and stderr without involving a shell' {
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $run = Invoke-WfNative -FilePath $exe -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', '[Console]::Out.WriteLine("o; echo injected"); [Console]::Error.WriteLine("e"); exit 7')
        $run.ExitCode | Should -Be 7
        $run.StdOut.Trim() | Should -BeExactly 'o; echo injected'
        $run.StdErr.Trim() | Should -BeExactly 'e'
        $run.TimedOut | Should -BeFalse
    }

    It 'reports a timeout and does not wait for the child' {
        $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $run = Invoke-WfNative -FilePath $exe -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') -TimeoutSeconds 2
        $run.TimedOut | Should -BeTrue
    }
}

Describe 'Write-WfTextFile' {
    It 'writes UTF-8 without a byte order mark' {
        $path = Join-Path $TestDrive 'nobom.txt'
        Write-WfTextFile -Path $path -Text "PasswordAuthentication no`n"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0] | Should -Be ([byte][char]'P')
        $bytes.Length | Should -Be 26
    }
}

Describe 'Collector names and bundle ids' {
    It 'accepts the collector name <Name>' -ForEach @(
        @{ Name = 'bugcheck-history' }, @{ Name = 'ab' }, @{ Name = 'a1' }, @{ Name = ('a' + ('b' * 40)) }
    ) {
        Test-WfCollectorName -Name $Name | Should -BeTrue
    }

    It 'rejects the collector name <Name>' -ForEach @(
        @{ Name = '' }, @{ Name = 'a' }, @{ Name = 'A-upper' }, @{ Name = '1abc' }, @{ Name = '-abc' }
        @{ Name = 'a_b' }, @{ Name = 'a.b' }, @{ Name = '../x' }, @{ Name = 'a b' }, @{ Name = "ab`n" }
        @{ Name = ('a' + ('b' * 41)) }, @{ Name = 'ab;whoami' }
    ) {
        Test-WfCollectorName -Name $Name | Should -BeFalse
    }

    It 'accepts a well formed bundle id and rejects near misses' {
        Test-WfBundleDirName -Name '20260930T171044Z_bugcheck-history_d1392f17' | Should -BeTrue
        Test-WfBundleDirName -Name '20260930T171044Z_bugcheck-history_D1392F17' | Should -BeFalse
        Test-WfBundleDirName -Name '20260930T171044Z_bugcheck-history_d1392f17/..' | Should -BeFalse
        Test-WfBundleDirName -Name '..' | Should -BeFalse
        Test-WfBundleDirName -Name "20260930T171044Z_ab_d1392f17`n" | Should -BeFalse
    }
}

Describe 'Get-WfIPv4Info' {
    It 'accepts the private address <Address> without a warning' -ForEach @(
        @{ Address = '192.168.1.23' }, @{ Address = '10.0.0.5' }, @{ Address = '172.16.4.9' }, @{ Address = '172.31.255.1' }
    ) {
        $info = Get-WfIPv4Info -Text $Address
        $info.Valid | Should -BeTrue
        $info.Warning | Should -BeExactly ''
    }

    It 'accepts <Address> but warns' -ForEach @(
        @{ Address = '203.0.113.7' }, @{ Address = '169.254.10.10' }, @{ Address = '192.168.1.255' }, @{ Address = '172.32.0.1' }
    ) {
        $info = Get-WfIPv4Info -Text $Address
        $info.Valid | Should -BeTrue
        $info.Warning | Should -Not -BeNullOrEmpty
    }

    It 'rejects <Address>' -ForEach @(
        @{ Address = '' }, @{ Address = '192.168.1' }, @{ Address = '192.168.1.256' }, @{ Address = '192.168.01.5' }
        @{ Address = '127.0.0.1' }, @{ Address = '0.1.2.3' }, @{ Address = '224.0.0.1' }, @{ Address = 'gaming-pc.local' }
        @{ Address = '192.168.1.23 ' }, @{ Address = '192.168.1.23/24' }, @{ Address = 'fe80::1' }
    ) {
        (Get-WfIPv4Info -Text $Address).Valid | Should -BeFalse
    }

    It 'explains that a hardware address is not what is wanted' {
        $info = Get-WfIPv4Info -Text 'a4:83:e7:12:34:56'
        $info.Valid | Should -BeFalse
        $info.Reason | Should -Match 'hardware'
    }
}

Describe 'Read-WfPublicKey' {
    It 'parses one Ed25519 public key line and drops the comment' {
        $key = Read-WfPublicKey -Text "ssh-ed25519 $script:KeyBase64 someone@some-mac`n"
        $key.KeyType | Should -BeExactly 'ssh-ed25519'
        $key.KeyBase64 | Should -BeExactly $script:KeyBase64
        $key.Fingerprint | Should -Match '\ASHA256:[A-Za-z0-9+/]{43}\z'
    }

    It 'refuses a private key file loudly' {
        { Read-WfPublicKey -Text "-----BEGIN OPENSSH PRIVATE KEY-----`nabc`n-----END OPENSSH PRIVATE KEY-----`n" } | Should -Throw '*PRIVATE key*'
    }

    It 'refuses <Case>' -ForEach @(
        @{ Case = 'an empty file'; Text = '' }
        @{ Case = 'two keys'; Text = "ssh-ed25519 AAAA a`nssh-ed25519 AAAA b`n" }
        @{ Case = 'an RSA key'; Text = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x' }
        @{ Case = 'a line that already has options'; Text = 'command="x" ssh-ed25519 AAAA x' }
        @{ Case = 'a truncated key'; Text = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x' }
        @{ Case = 'bad base64'; Text = 'ssh-ed25519 not*base64 x' }
        @{ Case = 'a type only'; Text = 'ssh-ed25519' }
    ) {
        { Read-WfPublicKey -Text $Text } | Should -Throw
    }

    It 'computes the same fingerprint as ssh-keygen' -Skip:($null -eq (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        $keyPath = Join-Path $TestDrive 'fp_key'
        $made = Invoke-WfNative -FilePath (Get-Command ssh-keygen).Source -ArgumentList @('-q', '-t', 'ed25519', '-N', '', '-C', 'fp-test', '-f', $keyPath)
        $made.ExitCode | Should -Be 0
        $listed = Invoke-WfNative -FilePath (Get-Command ssh-keygen).Source -ArgumentList @('-l', '-E', 'sha256', '-f', ($keyPath + '.pub'))
        $expected = ($listed.StdOut.Trim() -split '\s+')[1]
        (Read-WfPublicKey -Text ([System.IO.File]::ReadAllText($keyPath + '.pub'))).Fingerprint | Should -BeExactly $expected
    }
}

Describe 'Forced command and authorized_keys line' {
    It 'renders the forced command with no quotes and no spaces inside either path' {
        $script:Forced | Should -BeExactly 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File C:\ProgramData\win-forensics\remote\dispatch.ps1'
    }

    It 'refuses a path with a space (the PowerShell 7 install path)' {
        { Get-WfForcedCommand -PowerShellExe 'C:\Program Files\PowerShell\7\pwsh.exe' -DispatcherPath $script:Layout.Dispatcher } | Should -Throw '*space*'
    }

    It 'renders command, restrict, and from in front of the key' {
        $line = Format-WfAuthorizedKeysLine -ForcedCommand $script:Forced -FromAddress '192.0.2.10' -KeyBase64 $script:KeyBase64
        $line | Should -BeExactly ('command="' + $script:Forced + '",restrict,from="192.0.2.10" ssh-ed25519 ' + $script:KeyBase64 + ' win-forensics-mac')
    }

    It 'is parsed by ssh-keygen as one valid key line with options' -Skip:($null -eq (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        $path = Join-Path $TestDrive 'authorized_keys'
        $line = Format-WfAuthorizedKeysLine -ForcedCommand $script:Forced -FromAddress '192.0.2.10' -KeyBase64 $script:KeyBase64
        Write-WfTextFile -Path $path -Text ($line + "`n")
        $listed = Invoke-WfNative -FilePath (Get-Command ssh-keygen).Source -ArgumentList @('-l', '-f', $path)
        $listed.ExitCode | Should -Be 0
        $listed.StdOut | Should -Match 'ED25519'
    }

    It 'refuses <Case>' -ForEach @(
        @{ Case = 'a quote in the command'; Command = 'a "b"'; From = '192.0.2.10'; Comment = 'ok' }
        @{ Case = 'a from pattern'; Command = 'a'; From = '192.0.2.*'; Comment = 'ok' }
        @{ Case = 'a comment with a space'; Command = 'a'; From = '192.0.2.10'; Comment = 'two words' }
    ) {
        { Format-WfAuthorizedKeysLine -ForcedCommand $Command -FromAddress $From -KeyBase64 $script:KeyBase64 -Comment $Comment } | Should -Throw
    }

    It 'points AuthorizedKeysFile at the ProgramData token, not at a profile' {
        Get-WfAuthorizedKeysFileToken | Should -BeExactly '__PROGRAMDATA__/win-forensics/remote/authorized_keys'
        $script:Layout.AuthorizedKeys | Should -BeExactly 'C:\ProgramData\win-forensics\remote\authorized_keys'
    }
}

Describe 'Merge-WfSshdConfig' {
    BeforeAll {
        $script:GlobalBlock = @(Format-WfSshdGlobalBlock -AccountName 'wfcollector')
        $script:MatchBlock = @(Format-WfSshdMatchBlock -AccountName 'wfcollector' -ForcedCommand $script:Forced -AuthorizedKeysFileToken (Get-WfAuthorizedKeysFileToken))
        $script:Merged = Merge-WfSshdConfig -Existing $script:DefaultConfig -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock
        $script:MergedLines = @($script:Merged -split "`n")
    }

    It 'puts the global block first so its values are the first sshd reads' {
        $script:MergedLines[0] | Should -Match '^# BEGIN win-forensics front door \(global\)'
        $first = @($script:MergedLines | Where-Object { $_ -match '^PasswordAuthentication' })[0]
        $first | Should -BeExactly 'PasswordAuthentication no'
        $script:MergedLines | Should -Contain 'AllowUsers wfcollector'
        $script:MergedLines | Should -Contain 'SyslogFacility LOCAL0'
    }

    It 'puts the Match User block before the existing Match Group administrators block' {
        $ours = [array]::IndexOf($script:MergedLines, 'Match User wfcollector')
        $theirs = [array]::IndexOf($script:MergedLines, 'Match Group administrators')
        $ours | Should -BeGreaterThan 0
        $theirs | Should -BeGreaterThan $ours
    }

    It 'keeps every line of the original file, in order' {
        $original = @($script:DefaultConfig -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
        $kept = @($script:MergedLines | Where-Object { $_.Trim().Length -gt 0 -and $script:GlobalBlock -notcontains $_ -and $script:MatchBlock -notcontains $_ })
        $kept | Should -Be $original
    }

    It 'is idempotent' {
        $again = Merge-WfSshdConfig -Existing $script:Merged -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock
        $again | Should -BeExactly $script:Merged
    }

    It 'replaces an older managed block instead of adding a second one' {
        $oldMatch = @(Format-WfSshdMatchBlock -AccountName 'wfcollector' -ForcedCommand 'C:\old\command' -AuthorizedKeysFileToken (Get-WfAuthorizedKeysFileToken))
        $old = Merge-WfSshdConfig -Existing $script:DefaultConfig -GlobalBlock $script:GlobalBlock -MatchBlock $oldMatch
        $new = Merge-WfSshdConfig -Existing $old -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock
        $new | Should -BeExactly $script:Merged
        $new | Should -Not -Match 'C:\\old\\command'
    }

    It 'appends the Match block when the file has no Match line' {
        $merged = Merge-WfSshdConfig -Existing "Subsystem sftp sftp-server.exe`n" -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock
        $lines = @($merged.TrimEnd("`n") -split "`n")
        $lines[$lines.Count - 1] | Should -BeExactly '# END win-forensics front door (match)'
        $lines | Should -Contain 'Subsystem sftp sftp-server.exe'
    }

    It 'keeps CRLF line endings when the file uses them' {
        $crlf = $script:DefaultConfig -replace "`r?`n", "`r`n"
        $merged = Merge-WfSshdConfig -Existing $crlf -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock
        ($merged -replace "`r`n", '') | Should -Not -Match "[`r`n]"
        (Merge-WfSshdConfig -Existing $merged -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock) | Should -BeExactly $merged
    }

    It 'renders the Match block with the hardening directives' {
        $script:MatchBlock | Should -Contain "    ForceCommand $script:Forced"
        $script:MatchBlock | Should -Contain '    AuthorizedKeysFile __PROGRAMDATA__/win-forensics/remote/authorized_keys'
        $script:MatchBlock | Should -Contain '    PermitTTY no'
        $script:MatchBlock | Should -Contain '    PasswordAuthentication no'
        $script:MatchBlock | Should -Contain '    AuthenticationMethods publickey'
    }

    It 'uses no directive Microsoft lists as unavailable on Windows' {
        $unsupported = @('AcceptEnv', 'AllowStreamLocalForwarding', 'AuthorizedKeysCommand', 'AuthorizedKeysCommandUser',
            'AuthorizedPrincipalsCommand', 'AuthorizedPrincipalsCommandUser', 'ExposeAuthInfo', 'GSSAPICleanupCredentials',
            'GSSAPIStrictAcceptorCheck', 'HostbasedAcceptedKeyTypes', 'HostbasedAuthentication', 'HostbasedUsesNameFromPacketOnly',
            'IgnoreRhosts', 'IgnoreUserKnownHosts', 'KbdInteractiveAuthentication', 'KerberosAuthentication', 'KerberosGetAFSToken',
            'KerberosOrLocalPasswd', 'KerberosTicketCleanup', 'PermitTunnel', 'PermitUserEnvironment', 'PermitUserRC', 'PidFile',
            'PrintLastLog', 'PrintMotd', 'RDomain', 'StreamLocalBindMask', 'StreamLocalBindUnlink', 'StrictModes', 'X11DisplayOffset',
            'X11Forwarding', 'X11UseLocalhost', 'XAuthLocation')
        $used = @(($script:GlobalBlock + $script:MatchBlock) | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object { ($_.Trim() -split '\s+')[0] })
        foreach ($keyword in $used) { $unsupported | Should -Not -Contain $keyword }
    }

    It 'refuses a file with a broken managed block' {
        { Merge-WfSshdConfig -Existing "# BEGIN win-forensics front door (global)`nPasswordAuthentication no`n" -GlobalBlock $script:GlobalBlock -MatchBlock $script:MatchBlock } | Should -Throw '*without an END*'
    }

    It 'is accepted by the local sshd in test mode' -Skip:(-not (Test-Path '/usr/sbin/sshd')) {
        # A syntax check by a real sshd, with the two Windows only path forms swapped for local
        # ones. It proves keyword spelling and block structure, nothing about Windows behaviour.
        $keyPath = Join-Path $TestDrive 'hostkey'
        (Invoke-WfNative -FilePath (Get-Command ssh-keygen).Source -ArgumentList @('-q', '-t', 'ed25519', '-N', '', '-f', $keyPath)).ExitCode | Should -Be 0
        $portable = "HostKey $keyPath`n" + (($script:GlobalBlock + @('') + $script:MatchBlock) -join "`n") + "`n"
        $portable = $portable.Replace('__PROGRAMDATA__/', '/var/empty/').Replace('AllowUsers wfcollector', 'AllowUsers nobody').Replace('Match User wfcollector', 'Match User nobody')
        $configPath = Join-Path $TestDrive 'sshd_config'
        Write-WfTextFile -Path $configPath -Text $portable
        $check = Invoke-WfNative -FilePath '/usr/sbin/sshd' -ArgumentList @('-t', '-f', $configPath)
        $check.StdErr | Should -Not -Match 'Bad configuration option|Unsupported option|not allowed within a Match block'
        $check.ExitCode | Should -Be 0
    }
}

Describe 'Find-WfSshdConfigConflict' {
    It 'finds nothing in the default file' {
        @(Find-WfSshdConfigConflict -Text $script:DefaultConfig -AccountName 'wfcollector').Count | Should -Be 0
    }

    It 'reports other allow lists, a non default port, includes, and Match All' {
        $text = "AllowUsers louis`nPort 2222`nInclude extra.conf`nDenyGroups x`nMatch All`n  ForceCommand x`n"
        $notes = @(Find-WfSshdConfigConflict -Text $text -AccountName 'wfcollector')
        $notes.Count | Should -Be 5
    }

    It 'ignores the managed blocks and comments' {
        $global = @(Format-WfSshdGlobalBlock -AccountName 'wfcollector')
        $text = ($global -join "`n") + "`n#AllowUsers someone`n"
        @(Find-WfSshdConfigConflict -Text $text -AccountName 'wfcollector').Count | Should -Be 0
    }
}

Describe 'Get-WfDefaultShellDecision' {
    BeforeAll { $script:Cmd = 'C:\Windows\System32\cmd.exe' }

    It 'leaves an unset DefaultShell alone' {
        (Get-WfDefaultShellDecision -DefaultShell $null -DefaultShellCommandOption $null -SystemCmdPath $script:Cmd).Action | Should -BeExactly 'none'
        (Get-WfDefaultShellDecision -DefaultShell '' -DefaultShellCommandOption '-c' -SystemCmdPath $script:Cmd).Action | Should -BeExactly 'none'
    }

    It 'leaves an explicit cmd.exe alone, whatever its case or slashes' {
        (Get-WfDefaultShellDecision -DefaultShell 'c:/windows/system32/CMD.EXE' -DefaultShellCommandOption '/c' -SystemCmdPath $script:Cmd).Action | Should -BeExactly 'none'
    }

    It 'removes <Shell>' -ForEach @(
        @{ Shell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Option = $null }
        @{ Shell = 'C:\Program Files\PowerShell\7\pwsh.exe'; Option = '-c' }
        @{ Shell = 'C:\Windows\System32\cmd.exe'; Option = '-c' }
        @{ Shell = 'C:\Windows\System32\bash.exe'; Option = $null }
    ) {
        (Get-WfDefaultShellDecision -DefaultShell $Shell -DefaultShellCommandOption $Option -SystemCmdPath $script:Cmd).Action | Should -BeExactly 'remove'
    }
}

Describe 'Firewall decisions' {
    It 'knows which port specifications include 22' {
        Test-WfPortSpecIncludes -Spec @('22') -Port 22 | Should -BeTrue
        Test-WfPortSpecIncludes -Spec @('80', '20-25') -Port 22 | Should -BeTrue
        Test-WfPortSpecIncludes -Spec @('2222', '220', '23-30') -Port 22 | Should -BeFalse
        Test-WfPortSpecIncludes -Spec @('Any') -Port 22 | Should -BeFalse
        Test-WfPortSpecIncludes -Spec @('RPC') -Port 22 | Should -BeFalse
        Test-WfPortSpecIncludes -Spec $null -Port 22 | Should -BeFalse
    }

    It 'disables the default rule and any other rule that opens 22, and never its own' {
        $rules = @(
            @{ Name = 'OpenSSH-Server-In-TCP'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'C:\Windows\System32\OpenSSH\sshd.exe' }
            @{ Name = '{renamed-guid}'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('20-25'); Program = 'Any' }
            @{ Name = 'sshd-any-port'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'Any'; LocalPort = @('Any'); Program = 'C:\Windows\System32\OpenSSH\sshd.exe' }
            @{ Name = 'win-forensics-ssh-in'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any' }
            @{ Name = 'already-off'; Enabled = $false; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any' }
            @{ Name = 'a-block-rule'; Enabled = $true; Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any' }
            @{ Name = 'outbound'; Enabled = $true; Direction = 'Outbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any' }
            @{ Name = 'a-game'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'Any'; LocalPort = @('Any'); Program = 'C:\Games\game.exe' }
            @{ Name = 'udp-22'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'UDP'; LocalPort = @('22'); Program = 'Any' }
        )
        $plan = @(Get-WfFirewallPlan -Rules $rules -OwnRuleName 'win-forensics-ssh-in' | Sort-Object)
        $plan | Should -Be @('{renamed-guid}', 'OpenSSH-Server-In-TCP', 'sshd-any-port')
    }

    It 'has nothing to do on a second run' {
        $rules = @(
            @{ Name = 'OpenSSH-Server-In-TCP'; Enabled = $false; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'x\sshd.exe' }
            @{ Name = 'win-forensics-ssh-in'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any' }
        )
        @(Get-WfFirewallPlan -Rules $rules -OwnRuleName 'win-forensics-ssh-in').Count | Should -Be 0
    }

    It 'accepts its own rule only when scoped to the Mac and the Private profile' {
        $good = @{ Name = 'win-forensics-ssh-in'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = @('22'); RemoteAddress = @('192.0.2.10') }
        @(Test-WfOwnFirewallRule -Rule $good -MacAddress '192.0.2.10').Count | Should -Be 0
        $masked = $good.Clone(); $masked.RemoteAddress = @('192.0.2.10/255.255.255.255')
        @(Test-WfOwnFirewallRule -Rule $masked -MacAddress '192.0.2.10').Count | Should -Be 0
        foreach ($change in @(@{ RemoteAddress = @('Any') }, @{ RemoteAddress = @('192.0.2.10', '192.0.2.11') }, @{ Profile = 'Any' }, @{ Profile = 'Private, Public' }, @{ Enabled = $false }, @{ LocalPort = @('22', '23') }, @{ Action = 'Block' })) {
            $bad = $good.Clone()
            foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
            @(Test-WfOwnFirewallRule -Rule $bad -MacAddress '192.0.2.10').Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Effective sshd configuration check' {
    BeforeAll {
        $script:GoodDump = @(
            'port 22'
            'passwordauthentication no'
            'pubkeyauthentication yes'
            'permittty no'
            'allowtcpforwarding no'
            'allowagentforwarding no'
            'authenticationmethods publickey'
            'syslogfacility LOCAL0'
            "forcecommand $script:Forced"
            'authorizedkeysfile __PROGRAMDATA__/win-forensics/remote/authorized_keys'
            'allowusers wfcollector'
        ) -join "`r`n"
    }

    It 'passes the intended configuration' {
        $result = Test-WfSshdEffectiveConfig -Dump (ConvertFrom-WfSshdDump -Text $script:GoodDump) -AccountName 'wfcollector' -ForcedCommand $script:Forced
        @($result.Problems).Count | Should -Be 0
        @($result.Notes).Count | Should -Be 0
    }

    It 'accepts the key file path however sshd prints it' {
        $dump = $script:GoodDump.Replace('__PROGRAMDATA__/win-forensics/remote/authorized_keys', 'C:\ProgramData\win-forensics\remote\authorized_keys')
        @((Test-WfSshdEffectiveConfig -Dump (ConvertFrom-WfSshdDump -Text $dump) -AccountName 'wfcollector' -ForcedCommand $script:Forced).Problems).Count | Should -Be 0
    }

    It 'fails when <Case>' -ForEach @(
        @{ Case = 'passwords are allowed'; Old = 'passwordauthentication no'; New = 'passwordauthentication yes' }
        @{ Case = 'another forced command wins'; Old = 'forcecommand C:'; New = 'forcecommand D:' }
        @{ Case = 'there is no forced command'; Old = 'forcecommand '; New = 'xforcecommand ' }
        @{ Case = 'a terminal is allowed'; Old = 'permittty no'; New = 'permittty yes' }
        @{ Case = 'the key file is the profile one'; Old = '__PROGRAMDATA__/win-forensics/remote/authorized_keys'; New = '.ssh/authorized_keys' }
        @{ Case = 'the account is not allowed'; Old = 'allowusers wfcollector'; New = 'allowusers other' }
        @{ Case = 'logging goes to ETW'; Old = 'syslogfacility LOCAL0'; New = 'syslogfacility AUTH' }
    ) {
        $dump = $script:GoodDump.Replace($Old, $New)
        @((Test-WfSshdEffectiveConfig -Dump (ConvertFrom-WfSshdDump -Text $dump) -AccountName 'wfcollector' -ForcedCommand $script:Forced).Problems).Count | Should -BeGreaterThan 0
    }

    It 'notes other allowed accounts without failing' {
        $dump = $script:GoodDump + "`r`nallowusers louis"
        $result = Test-WfSshdEffectiveConfig -Dump (ConvertFrom-WfSshdDump -Text $dump) -AccountName 'wfcollector' -ForcedCommand $script:Forced
        @($result.Problems).Count | Should -Be 0
        @($result.Notes).Count | Should -Be 1
    }
}

Describe 'ConvertFrom-WfPowerCfgQuery' {
    It 'reads the AC and DC values by position, whatever the label language' {
        $text = @(
            'GUID du parametre d''alimentation : 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Mettre en veille apres)'
            '  Parametre minimal possible : 0x00000000'
            '  Parametre maximal possible : 0xffffffff'
            '  Increment de parametres possibles : 0x00000001'
            '  Unites de parametres possibles : Secondes'
            '  Index actuel du parametre de courant alternatif : 0x00000000'
            '  Index actuel du parametre de courant continu : 0x00000384'
        ) -join "`r`n"
        $values = ConvertFrom-WfPowerCfgQuery -Text $text
        $values.AcSeconds | Should -Be 0
        $values.DcSeconds | Should -Be 900
    }

    It 'returns nothing when the output has another shape' {
        ConvertFrom-WfPowerCfgQuery -Text 'Invalid Parameters' | Should -BeNullOrEmpty
        ConvertFrom-WfPowerCfgQuery -Text '' | Should -BeNullOrEmpty
    }
}

Describe 'Test-WfAclRule' {
    BeforeAll {
        $script:Account = 'S-1-5-21-1-2-3-1001'
        $script:ReadExecute = 0x1200A9
        $script:Modify = 0x1301BF
        $script:Full = 0x1F01FF
        $script:Base = @(@{ Sid = 'S-1-5-18'; Rights = $script:Full }, @{ Sid = 'S-1-5-32-544'; Rights = $script:Full })
    }

    It 'accepts SYSTEM, Administrators, and a read only collector account' {
        $rules = $script:Base + @(@{ Sid = $script:Account; Rights = $script:ReadExecute })
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account).Count | Should -Be 0
    }

    It 'rejects a collector account that can write where the forced command lives' {
        $rules = $script:Base + @(@{ Sid = $script:Account; Rights = $script:Modify })
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account).Count | Should -Be 1
    }

    It 'lets the collector account write in the outbox only' {
        $rules = $script:Base + @(@{ Sid = $script:Account; Rights = $script:Modify })
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account -AccountMayWrite).Count | Should -Be 0
    }

    It 'rejects any other principal, even read only, unless told otherwise' {
        $rules = $script:Base + @(@{ Sid = 'S-1-5-32-545'; Rights = $script:ReadExecute })
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account).Count | Should -Be 1
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account -OthersMayRead).Count | Should -Be 0
    }

    It 'rejects the ProgramData default that lets every user create files' {
        # BUILTIN\Users with WriteData and AppendData, as inherited from C:\ProgramData.
        $rules = $script:Base + @(@{ Sid = 'S-1-5-32-545'; Rights = 0x1200AF })
        @(Test-WfAclRule -Rules $rules -AccountSid $script:Account -OthersMayRead).Count | Should -Be 1
    }
}

Describe 'New-WfRandomPassword' {
    It 'returns a read only SecureString of the asked length with all four character classes' {
        $secure = New-WfRandomPassword -Length 40
        $secure | Should -BeOfType ([System.Security.SecureString])
        $secure.IsReadOnly() | Should -BeTrue
        $secure.Length | Should -Be 40
        $plain = (New-Object System.Net.NetworkCredential('', $secure)).Password
        $plain | Should -MatchExactly '[A-Z]'
        $plain | Should -MatchExactly '[a-z]'
        $plain | Should -MatchExactly '[0-9]'
        $plain | Should -MatchExactly '[^A-Za-z0-9]'
        $plain | Should -Not -Match '[\s"''`$]'
    }

    It 'does not repeat itself' {
        $a = (New-Object System.Net.NetworkCredential('', (New-WfRandomPassword))).Password
        $b = (New-Object System.Net.NetworkCredential('', (New-WfRandomPassword))).Password
        $a | Should -Not -BeExactly $b
    }
}

Describe 'Get-WfSummaryResult' {
    It 'passes with warnings and exits 0' {
        $r = Get-WfSummaryResult -Steps @(@{ Status = 'PASS' }, @{ Status = 'WARN' })
        $r.Result | Should -BeExactly 'PASS'
        $r.ExitCode | Should -Be 0
        $r.Warnings | Should -Be 1
    }

    It 'fails when any step failed or was skipped, and exits 1' {
        $r = Get-WfSummaryResult -Steps @(@{ Status = 'PASS' }, @{ Status = 'FAIL' }, @{ Status = 'SKIP' })
        $r.Result | Should -BeExactly 'FAIL'
        $r.ExitCode | Should -Be 1
        $r.Skipped | Should -Be 1
    }
}
