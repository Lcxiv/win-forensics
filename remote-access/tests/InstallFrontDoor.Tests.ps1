# Pester 5 tests for the step logic of Install-FrontDoor.ps1, with every Windows cmdlet replaced
# by a mock. They prove the decisions the script makes (what it calls, in which order, what it
# does when a check fails), not that the Windows cmdlets behave as documented. That part can only
# be proven on Windows; remote-access/README.md lists it under "Not verified off Windows".

BeforeAll {
    # Windows only commands the steps call. Pester can only mock a command that exists.
    function Get-NetFirewallRule { [CmdletBinding()] param($Name) }
    function Remove-NetFirewallRule { [CmdletBinding()] param($Name) }
    function Disable-NetFirewallRule { [CmdletBinding()] param($Name) }
    function New-NetFirewallRule { [CmdletBinding()] param($Name, $DisplayName, $Description, $Group, $Direction, $Action, $Protocol, $LocalPort, $RemoteAddress, $Profile, $Enabled) }
    function Get-LocalUser { [CmdletBinding()] param($Name) }
    function New-LocalUser { [CmdletBinding()] param($Name, $Password, [switch]$PasswordNeverExpires, [switch]$UserMayNotChangePassword, [switch]$AccountNeverExpires, $FullName, $Description) }
    function Set-LocalUser { [CmdletBinding()] param($Name, $PasswordNeverExpires) }
    function Enable-LocalUser { [CmdletBinding()] param($Name) }
    function Add-LocalGroupMember { [CmdletBinding()] param($SID, $Member) }
    function Get-Service { [CmdletBinding()] param($Name) }
    function Start-Service { [CmdletBinding()] param($Name) }
    function Restart-Service { [CmdletBinding()] param($Name, [switch]$Force) }

    # The steps narrate to the console; keep the test output readable.
    Mock Write-Host { }

    $script:InstallScript = (Resolve-Path (Join-Path $PSScriptRoot '../windows/Install-FrontDoor.ps1')).Path
    . $script:InstallScript -MacIpAddress '192.0.2.10' -MacPublicKeyFile 'not-used.pub'

    $script:DefaultConfig = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures/sshd_config_default'))
    $blob = [byte[]](0, 0, 0, 11) + [System.Text.Encoding]::ASCII.GetBytes('ssh-ed25519') + [byte[]](0, 0, 0, 32) + [byte[]](@(9) * 32)
    $script:KeyBase64 = [System.Convert]::ToBase64String($blob)

    function New-TestContext {
        # A context whose paths all live under TestDrive.
        $base = Join-Path $TestDrive ([System.Guid]::NewGuid().ToString('N'))
        $sshDir = Join-Path $base 'ssh'
        $root = Join-Path $base 'win-forensics'
        $remote = Join-Path $root 'remote'
        $bin = Join-Path $base 'OpenSSH'
        foreach ($dir in @($sshDir, $remote, $bin)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $forced = Get-WfForcedCommand -PowerShellExe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -DispatcherPath 'C:\ProgramData\win-forensics\remote\dispatch.ps1'
        $macLine = Format-WfAuthorizedKeysLine -ForcedCommand $forced -FromAddress '192.0.2.10' -KeyBase64 $script:KeyBase64
        return @{
            MacIpAddress       = '192.0.2.10'
            AccountName        = 'wfcollector'
            AccountSid         = 'S-1-5-21-1-2-3-1001'
            FirewallRuleName   = 'win-forensics-ssh-in'
            SshdExe            = Join-Path $bin 'sshd.exe'
            SourceDir          = $base
            ForcedCommand      = $forced
            MacKeyLine         = $macLine
            HostKeyLine        = 'ssh-ed25519 ' + $script:KeyBase64
            HostKeyFingerprint = 'SHA256:examplefingerprintexamplefingerprintexample'
            State              = @{
                capability_installed_by_this_script = $false
                account_created_by_this_script      = $false
                disabled_firewall_rules             = @()
                previous_default_shell              = $null
                standby_timeout_ac_set              = $false
            }
            Layout             = @{
                Root           = $root
                Remote         = $remote
                AuthorizedKeys = Join-Path $remote 'authorized_keys'
                SshDir         = $sshDir
                SshdConfig     = Join-Path $sshDir 'sshd_config'
                SshdLog        = Join-Path (Join-Path $sshDir 'logs') 'sshd.log'
            }
        }
    }

    function Invoke-TestStep {
        # Run one step function through the real step runner and return its record.
        param([scriptblock]$Action)
        $script:WfAbort = $false
        Invoke-WfStep -Id 'T' -Title 'test step' -Action $Action
        return $script:WfSteps[$script:WfSteps.Count - 1]
    }

    function Get-NativeResult {
        param([int]$ExitCode = 0, [string]$StdOut = '', [string]$StdErr = '')
        return [pscustomobject]@{ ExitCode = $ExitCode; StdOut = $StdOut; StdErr = $StdErr; TimedOut = $false }
    }
}

Describe 'Install-FrontDoor.ps1 as a file' {
    It 'is plain ASCII, like every script that Windows PowerShell 5.1 has to read' {
        foreach ($file in @(Get-ChildItem -LiteralPath (Split-Path -Parent $script:InstallScript) -Filter '*.ps1')) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because "$($file.Name) would be read as ANSI by Windows PowerShell 5.1"
        }
    }

    It 'does not hard code an address, a key, or a password' {
        $text = [System.IO.File]::ReadAllText($script:InstallScript)
        $text | Should -Not -Match '\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}(\.\d{1,3})?\b'
        $text | Should -Not -Match 'AAAAC3NzaC1lZDI1NTE5'
        $text | Should -Not -Match 'ConvertTo-SecureString'
    }

    It 'never writes the password to the console or to a file' {
        $text = [System.IO.File]::ReadAllText($script:InstallScript)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $uses = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] -and $node.VariablePath.UserPath -eq 'password' }, $true))
        # Assigned once, passed to New-LocalUser once, disposed once. Nothing else touches it.
        $uses.Count | Should -Be 3
        @($uses | Where-Object { $_.Parent.Extent.Text -match 'Write-|Add-Wf|Out-File|Set-Content' }).Count | Should -Be 0
    }
}

Describe 'Invoke-WfStep' {
    It 'records PASS, turns a warning into WARN, and a throw into FAIL' {
        (Invoke-TestStep { Add-WfNote 'fine' }).Status | Should -BeExactly 'PASS'
        (Invoke-TestStep { Add-WfWarning 'hmm' }).Status | Should -BeExactly 'WARN'
        $failed = Invoke-TestStep { throw 'boom' }
        $failed.Status | Should -BeExactly 'FAIL'
        ($failed.Details -join ' ') | Should -Match 'what happened: boom'
    }

    It 'does not run the steps after a failure, and the summary fails' {
        $script:WfSteps.Clear()
        $script:WfAbort = $false
        $script:Ran = $false
        Invoke-WfStep -Id 'A' -Title 'first' -Action { throw 'stop here' }
        Invoke-WfStep -Id 'B' -Title 'second' -Action { $script:Ran = $true }
        $script:Ran | Should -BeFalse
        $script:WfSteps[1].Status | Should -BeExactly 'SKIP'
        (Get-WfSummaryResult -Steps $script:WfSteps.ToArray()).ExitCode | Should -Be 1
    }
}

Describe 'Update-WfSshdConfigFile' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:ConfigPath = $script:Ctx.Layout.SshdConfig
        Write-WfTextFile -Path $script:ConfigPath -Text $script:DefaultConfig
        $script:NewText = $script:DefaultConfig + "# changed`n"
    }

    It 'validates a copy first, then replaces the file and keeps the original and the previous version' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 0 }
        $result = Update-WfSshdConfigFile -ConfigPath $script:ConfigPath -NewText $script:NewText -SshdExe 'sshd'
        $result.Changed | Should -BeTrue
        $result.Problem | Should -BeExactly ''
        [System.IO.File]::ReadAllText($script:ConfigPath) | Should -BeExactly $script:NewText
        [System.IO.File]::ReadAllText($script:ConfigPath + '.wf-original') | Should -BeExactly $script:DefaultConfig
        [System.IO.File]::ReadAllText($script:ConfigPath + '.wf-previous') | Should -BeExactly $script:DefaultConfig
        Test-Path -LiteralPath ($script:ConfigPath + '.wf-candidate') | Should -BeFalse
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { $ArgumentList[0] -ceq '-t' -and $ArgumentList[2].EndsWith('.wf-candidate') }
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { $ArgumentList[0] -ceq '-t' -and $ArgumentList[2] -eq $script:ConfigPath }
    }

    It 'never touches the live file when sshd rejects the candidate' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 255 -StdErr 'sshd_config.wf-candidate: line 3: Bad configuration option: Nope' }
        $result = Update-WfSshdConfigFile -ConfigPath $script:ConfigPath -NewText $script:NewText -SshdExe 'sshd'
        $result.Changed | Should -BeFalse
        $result.Restored | Should -BeFalse
        $result.Problem | Should -Match 'was not changed'
        $result.Output | Should -Match 'Bad configuration option'
        [System.IO.File]::ReadAllText($script:ConfigPath) | Should -BeExactly $script:DefaultConfig
        Test-Path -LiteralPath ($script:ConfigPath + '.wf-previous') | Should -BeFalse
        Test-Path -LiteralPath ($script:ConfigPath + '.wf-candidate') | Should -BeFalse
    }

    It 'puts the previous file back when validation fails once the new file is in place' {
        $script:Calls = 0
        Mock Invoke-WfNative {
            $script:Calls++
            if ($script:Calls -eq 1) { return Get-NativeResult -ExitCode 0 }
            return Get-NativeResult -ExitCode 255 -StdErr 'no hostkeys available'
        }
        $result = Update-WfSshdConfigFile -ConfigPath $script:ConfigPath -NewText $script:NewText -SshdExe 'sshd'
        $result.Changed | Should -BeFalse
        $result.Restored | Should -BeTrue
        [System.IO.File]::ReadAllText($script:ConfigPath) | Should -BeExactly $script:DefaultConfig
    }

    It 'changes nothing on a second run with the same text' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 0 }
        [void](Update-WfSshdConfigFile -ConfigPath $script:ConfigPath -NewText $script:NewText -SshdExe 'sshd')
        $stamp = (Get-Item -LiteralPath ($script:ConfigPath + '.wf-previous')).LastWriteTimeUtc
        $again = Update-WfSshdConfigFile -ConfigPath $script:ConfigPath -NewText $script:NewText -SshdExe 'sshd'
        $again.Changed | Should -BeFalse
        $again.Problem | Should -BeExactly ''
        (Get-Item -LiteralPath ($script:ConfigPath + '.wf-previous')).LastWriteTimeUtc | Should -Be $stamp
        [System.IO.File]::ReadAllText($script:ConfigPath + '.wf-original') | Should -BeExactly $script:DefaultConfig
    }
}

Describe 'Set-WfSshdConfig' {
    BeforeEach {
        $script:Ctx = New-TestContext
        Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text $script:DefaultConfig
        $script:GoodDump = @(
            'passwordauthentication no', 'pubkeyauthentication yes', 'permittty no', 'allowtcpforwarding no',
            'allowagentforwarding no', 'authenticationmethods publickey', 'syslogfacility LOCAL0',
            "forcecommand $($script:Ctx.ForcedCommand)", 'authorizedkeysfile __PROGRAMDATA__/win-forensics/remote/authorized_keys',
            'allowusers wfcollector'
        ) -join "`n"
        Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
        Mock Restart-Service { }
        Mock Start-Service { }
    }

    It 'writes both managed blocks, restarts sshd, and confirms the effective configuration' {
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $script:GoodDump } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        $text = [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig)
        $text | Should -Match '(?m)^PasswordAuthentication no$'
        $text | Should -Match '(?m)^AllowUsers wfcollector$'
        $text | Should -Match '(?m)^Match User wfcollector$'
        $text | Should -Match ([regex]::Escape("ForceCommand $($script:Ctx.ForcedCommand)"))
        Should -Invoke Restart-Service -Times 1 -Exactly
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { $ArgumentList[0] -ceq '-T' -and ($ArgumentList -join ' ') -match 'user=wfcollector,host=192\.0\.2\.10,addr=192\.0\.2\.10' }
    }

    It 'restores the previous sshd_config when sshd will not restart with the new one' {
        Mock Invoke-WfNative { Get-NativeResult }
        Mock Restart-Service { throw 'service did not start' }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'previous sshd_config was restored'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig) | Should -BeExactly $script:DefaultConfig
        Should -Invoke Start-Service -Times 1 -Exactly
    }

    It 'does not restart sshd at all when sshd rejects the new configuration' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 255 -StdErr 'Bad configuration option' }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig) | Should -BeExactly $script:DefaultConfig
        Should -Invoke Restart-Service -Times 0
    }

    It 'fails when the effective configuration shows another forced command winning' {
        $badDump = $script:GoodDump.Replace("forcecommand $($script:Ctx.ForcedCommand)", 'forcecommand internal-sftp')
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $badDump } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'ForceCommand'
    }

    It 'only warns when sshd cannot print the effective configuration' {
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -ExitCode 1 } else { Get-NativeResult } }
        (Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }).Status | Should -BeExactly 'WARN'
    }

    It 'warns about an allow list that was already in the file' {
        Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text ("AllowUsers louis`n" + $script:DefaultConfig)
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut ($script:GoodDump + "`nallowusers louis") } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'WARN'
        ($record.Details -join ' ') | Should -Match 'louis'
    }
}

Describe 'Set-WfFirewall' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:DefaultRule = @{ Name = 'OpenSSH-Server-In-TCP'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'C:\Windows\System32\OpenSSH\sshd.exe'; RemoteAddress = @('Any') }
        $script:OwnRule = @{ Name = 'win-forensics-ssh-in'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any'; RemoteAddress = @('192.0.2.10') }
        Mock Get-NetFirewallRule { $null }
        Mock Remove-NetFirewallRule { }
        Mock New-NetFirewallRule { }
        Mock Disable-NetFirewallRule { $script:DefaultRule.Enabled = $false }
        Mock Get-WfSshFirewallRule { @($script:DefaultRule.Clone(), $script:OwnRule.Clone()) }
    }

    It 'creates its own rule for the Mac on Private only, and disables the rule the install created' {
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'win-forensics-ssh-in' -and $RemoteAddress -eq '192.0.2.10' -and $Profile -eq 'Private' -and
            $Direction -eq 'Inbound' -and $Action -eq 'Allow' -and $Protocol -eq 'TCP' -and $LocalPort -eq 22
        }
        Should -Invoke Disable-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'OpenSSH-Server-In-TCP' }
        $script:Ctx.State.disabled_firewall_rules | Should -Be @('OpenSSH-Server-In-TCP')
    }

    It 'replaces its own rule on a second run and disables nothing more' {
        $script:DefaultRule.Enabled = $false
        Mock Get-NetFirewallRule { [pscustomobject]@{ Name = 'win-forensics-ssh-in' } }
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Disable-NetFirewallRule -Times 0
    }

    It 'fails when a rule that opens port 22 is still enabled afterwards' {
        Mock Disable-NetFirewallRule { }
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'still allow inbound SSH'
    }

    It 'fails when its own rule came out wider than the Mac''s address' {
        $script:OwnRule.RemoteAddress = @('Any')
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'remote address'
    }
}

Describe 'Set-WfAccount' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:Ctx.AccountSid = ''
        $script:Marker = 'win-forensics SSH collector (key only)'
        $script:User = [pscustomobject]@{ Name = 'wfcollector'; Enabled = $true; PasswordExpires = $null; Description = $script:Marker; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' } }
        $script:Groups = @()
        Mock New-LocalUser { $script:User }
        Mock Set-LocalUser { }
        Mock Enable-LocalUser { $script:User.Enabled = $true }
        Mock Add-LocalGroupMember { $script:Groups = @('S-1-5-32-573') }
        Mock Get-WfAccountGroupSid { @{ Sids = $script:Groups; Complete = $true } }
    }

    It 'creates the account with a SecureString password that never expires, in Event Log Readers only' {
        $script:Exists = $false
        Mock Get-LocalUser { if ($script:Exists) { $script:User } else { $null } }
        Mock New-LocalUser {
            # Looked at here, while the call is in progress: the script disposes the password
            # as soon as New-LocalUser returns.
            $script:PasswordSeen = @{ IsSecure = ($Password -is [System.Security.SecureString]); Length = $Password.Length }
            $script:Exists = $true
            $script:User
        }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-LocalUser -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'wfcollector' -and $PasswordNeverExpires -and $UserMayNotChangePassword -and
            $Description -eq 'win-forensics SSH collector (key only)'
        }
        $script:PasswordSeen.IsSecure | Should -BeTrue
        $script:PasswordSeen.Length | Should -BeGreaterOrEqual 20
        Should -Invoke Add-LocalGroupMember -Times 1 -Exactly -ParameterFilter { $SID -eq 'S-1-5-32-573' -and $Member -eq 'wfcollector' }
        $script:Ctx.AccountSid | Should -BeExactly 'S-1-5-21-1-2-3-1001'
        $script:Ctx.State.account_created_by_this_script | Should -BeTrue
        ($record.Details -join ' ') | Should -Not -Match 'System\.Security\.SecureString'
    }

    It 'keeps the description within the 48 characters New-LocalUser allows' {
        $script:Marker.Length | Should -BeLessOrEqual 48
    }

    It 'reuses its own account on a second run without creating or re-adding anything' {
        $script:Groups = @('S-1-5-32-573')
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-LocalUser -Times 0
        Should -Invoke Add-LocalGroupMember -Times 0
        Should -Invoke Set-LocalUser -Times 1 -Exactly -ParameterFilter { $PasswordNeverExpires -eq $true }
    }

    It 'enables its own account again when it had been disabled' {
        $script:Groups = @('S-1-5-32-573')
        $script:User.Enabled = $false
        Mock Get-LocalUser { $script:User }
        (Invoke-TestStep { Set-WfAccount -Context $script:Ctx }).Status | Should -BeExactly 'PASS'
        Should -Invoke Enable-LocalUser -Times 1 -Exactly
    }

    It 'refuses an account of that name that it did not create' {
        $script:User.Description = 'Louis'
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        Should -Invoke Set-LocalUser -Times 0
        Should -Invoke Add-LocalGroupMember -Times 0
    }

    It 'fails when the account is an administrator' {
        $script:Groups = @('S-1-5-32-573', 'S-1-5-32-544')
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'Administrators'
    }

    It 'warns when the account is in a group beyond Event Log Readers' {
        $script:Groups = @('S-1-5-32-573', 'S-1-5-32-559')
        Mock Get-LocalUser { $script:User }
        (Invoke-TestStep { Set-WfAccount -Context $script:Ctx }).Status | Should -BeExactly 'WARN'
    }
}

Describe 'Install-WfLayout' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:Ctx.Layout.Outbox = Join-Path $script:Ctx.Layout.Root 'outbox'
        $script:Ctx.Layout.Collectors = Join-Path $script:Ctx.Layout.Remote 'collectors'
        $script:Ctx.Layout.Dispatcher = Join-Path $script:Ctx.Layout.Remote 'dispatch.ps1'
        $script:Ctx.SourceDir = Split-Path -Parent $script:InstallScript
        $source = Join-Path $TestDrive ([System.Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path (Join-Path $source 'tests') -Force)
        foreach ($name in @('alpha-one.ps1', 'beta-two.ps1', '_common.ps1', 'README.md', 'tests/Alpha.Tests.ps1')) {
            Write-WfTextFile -Path (Join-Path $source $name) -Text "# $name`n"
        }
        $script:Ctx.CollectorSource = $source
        $script:AclCalls = New-Object System.Collections.Generic.List[object]
        Mock Set-WfDirectoryAcl { $script:AclCalls.Add(@{ Path = $Path; Rights = [string]$AccountRights; Inherits = [bool]$AccountRuleInherits }) }
        Mock Assert-WfAcl { }
    }

    It 'installs every script directly in the source, the shared helper included, and never the tests directory' {
        $record = Invoke-TestStep { Install-WfLayout -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        $installed = @(Get-ChildItem -LiteralPath $script:Ctx.Layout.Collectors -Recurse | ForEach-Object { $_.Name } | Sort-Object)
        $installed | Should -Be @('_common.ps1', 'alpha-one.ps1', 'beta-two.ps1')
        ($record.Details -join ' ') | Should -Match 'collectors installed: alpha-one, beta-two'
        ($record.Details -join ' ') | Should -Match 'not verbs\): _common\.ps1'
        foreach ($file in @('dispatch.ps1', 'WfCommon.ps1')) {
            Get-WfFileSha256 -Path (Join-Path $script:Ctx.Layout.Remote $file) | Should -BeExactly (Get-WfFileSha256 -Path (Join-Path $script:Ctx.SourceDir $file))
        }
        $script:Ctx.DispatcherSha256 | Should -BeExactly (Get-WfFileSha256 -Path (Join-Path $script:Ctx.SourceDir 'dispatch.ps1'))
    }

    It 'locks the directories before copying anything, and only the outbox is writable by the account' {
        [void](Invoke-TestStep { Install-WfLayout -Context $script:Ctx })
        $script:AclCalls.Count | Should -Be 3
        $script:AclCalls[0].Path | Should -BeExactly $script:Ctx.Layout.Root
        $script:AclCalls[0].Rights | Should -BeExactly 'ReadAndExecute'
        $script:AclCalls[0].Inherits | Should -BeFalse
        $script:AclCalls[1].Path | Should -BeExactly $script:Ctx.Layout.Remote
        $script:AclCalls[1].Rights | Should -BeExactly 'ReadAndExecute'
        $script:AclCalls[2].Path | Should -BeExactly $script:Ctx.Layout.Outbox
        $script:AclCalls[2].Rights | Should -BeExactly 'Modify'
        Should -Invoke Assert-WfAcl -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Ctx.Layout.Outbox -and $AccountMayWrite }
        Should -Invoke Assert-WfAcl -Times 0 -ParameterFilter { $Path -ne $script:Ctx.Layout.Outbox -and $AccountMayWrite }
    }

    It 'mirrors the kit: a collector the kit no longer holds is removed, and bundles are left alone' {
        [void](Invoke-TestStep { Install-WfLayout -Context $script:Ctx })
        $bundle = Join-Path $script:Ctx.Layout.Outbox '20260930T171044Z_alpha-one_0123abcd'
        [void](New-Item -ItemType Directory -Path $bundle)
        Remove-Item -LiteralPath (Join-Path $script:Ctx.CollectorSource 'beta-two.ps1')
        $record = Invoke-TestStep { Install-WfLayout -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Test-Path -LiteralPath (Join-Path $script:Ctx.Layout.Collectors 'beta-two.ps1') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Ctx.Layout.Collectors 'alpha-one.ps1') | Should -BeTrue
        Test-Path -LiteralPath $bundle | Should -BeTrue
    }

    It 'installs the front door with no collectors at all and says so' {
        $script:Ctx.CollectorSource = Join-Path $TestDrive 'there-is-no-such-directory'
        $record = Invoke-TestStep { Install-WfLayout -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        ($record.Details -join ' ') | Should -Match 'unknown collector'
        @(Get-ChildItem -LiteralPath $script:Ctx.Layout.Collectors).Count | Should -Be 0
    }

    It 'fails when a permission check fails' {
        Mock Assert-WfAcl { throw 'C:\x has unsafe permissions: S-1-5-32-545 has write access' }
        (Invoke-TestStep { Install-WfLayout -Context $script:Ctx }).Status | Should -BeExactly 'FAIL'
    }
}

Describe 'Invoke-WfSelfTest' {
    BeforeEach {
        $script:Ctx = New-TestContext
        foreach ($tool in @('ssh.exe', 'ssh-keygen.exe', 'sshd.exe')) { Write-WfTextFile -Path (Join-Path (Split-Path -Parent $script:Ctx.SshdExe) $tool) -Text '' }
        $script:KeyWrites = New-Object System.Collections.Generic.List[object]
        Mock Set-WfAuthorizedKey {
            $script:KeyWrites.Add(@($Lines))
            Write-WfTextFile -Path $Path -Text (($Lines -join "`n") + "`n")
        }
        Mock Invoke-WfChecked {
            # Stands in for ssh-keygen: write a public key next to the requested key path.
            $keyPath = $ArgumentList[$ArgumentList.Count - 1]
            Write-WfTextFile -Path ($keyPath + '.pub') -Text ("ssh-ed25519 $script:KeyBase64 wf-selftest`n")
            Get-NativeResult
        }
    }

    It 'authorizes a throwaway loopback key, checks ping and a refusal, and removes the key again' {
        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        $script:KeyWrites.Count | Should -Be 2
        $script:KeyWrites[0].Count | Should -Be 2
        $script:KeyWrites[0][1] | Should -Match 'from="127\.0\.0\.1"'
        $script:KeyWrites[0][1] | Should -Match ([regex]::Escape('command="' + $script:Ctx.ForcedCommand + '",restrict'))
        $script:KeyWrites[1] | Should -Be @($script:Ctx.MacKeyLine)
        [System.IO.File]::ReadAllText($script:Ctx.Layout.AuthorizedKeys) | Should -BeExactly ($script:Ctx.MacKeyLine + "`n")
        @(Get-ChildItem -LiteralPath $script:Ctx.Layout.Root -Filter 'selftest-*').Count | Should -Be 0
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { ($ArgumentList -join ' ') -match 'StrictHostKeyChecking=yes' -and $ArgumentList[$ArgumentList.Count - 2] -eq 'wfcollector@127.0.0.1' -and $ArgumentList[$ArgumentList.Count - 1] -eq 'ping' }
    }

    It 'fails, and still removes the throwaway key, when ping does not come back' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 255 -StdErr 'Permission denied (publickey).' }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'Permission denied'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.AuthorizedKeys) | Should -BeExactly ($script:Ctx.MacKeyLine + "`n")
        @(Get-ChildItem -LiteralPath $script:Ctx.Layout.Root -Filter 'selftest-*').Count | Should -Be 0
    }

    It 'fails when a command outside the allowlist is not refused' {
        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            return Get-NativeResult -ExitCode 0 -StdOut 'gamingpc\wfcollector'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'NOT refused'
    }

    It 'warns when the refusal arrives with the wrong exit code' {
        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            return Get-NativeResult -ExitCode 1 -StdOut '{"ok":false,"error":"refused"}'
        }
        (Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }).Status | Should -BeExactly 'WARN'
    }

    It 'skips with a warning when the OpenSSH client tools are not there' {
        Remove-Item -LiteralPath (Join-Path (Split-Path -Parent $script:Ctx.SshdExe) 'ssh.exe')
        Mock Invoke-WfNative { throw 'must not be called' }
        (Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }).Status | Should -BeExactly 'WARN'
        $script:KeyWrites.Count | Should -Be 0
    }
}

Describe 'Write-WfSummary' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:WfSteps.Clear()
        $script:WfAbort = $false
    }

    It 'ends a clean run with PASS, the host key fingerprint, and the next two Mac commands' {
        Invoke-WfStep -Id 'S1' -Title 'one' -Action { Add-WfNote 'detail' }
        $code = Write-WfSummary -Context $script:Ctx
        $code | Should -Be 0
        $report = [System.IO.File]::ReadAllText((Join-Path $script:Ctx.SourceDir 'wf-frontdoor-report.txt'))
        $report | Should -Match 'RESULT: PASS'
        $report | Should -Match ([regex]::Escape($script:Ctx.HostKeyFingerprint))
        $report | Should -Match 'wf-pin-host-key\.sh --fingerprint'
        $report | Should -Match 'wf-acceptance\.sh'
    }

    It 'ends a failed run with FAIL, the reason, the checklist row, and exit code 1' {
        Invoke-WfStep -Id 'S3' -Title 'firewall' -Action { throw 'the network is Public' }
        Invoke-WfStep -Id 'S4' -Title 'service' -Action { }
        $code = Write-WfSummary -Context $script:Ctx
        $code | Should -Be 1
        $report = [System.IO.File]::ReadAllText((Join-Path $script:Ctx.SourceDir 'wf-frontdoor-report.txt'))
        $report | Should -Match 'RESULT: FAIL \(1 failed, 1 not run\)'
        $report | Should -Match 'what happened: the network is Public'
        $report | Should -Match 'row S3'
        $report | Should -Match '\[SKIP\] S4'
        $report | Should -Not -Match 'wf-pin-host-key'
    }
}

Describe 'install-state.json' {
    It 'round trips what earlier runs did, so a later run does not forget it' {
        $ctx = New-TestContext
        $ctx.Layout.State = Join-Path $ctx.Layout.Remote 'install-state.json'
        $ctx.State.disabled_firewall_rules = @('OpenSSH-Server-In-TCP')
        $ctx.State.account_created_by_this_script = $true
        $ctx.State.previous_default_shell = @{ DefaultShell = 'C:\x\pwsh.exe'; DefaultShellCommandOption = $null; DefaultShellArguments = $null }
        Save-WfState -Context $ctx
        $read = Read-WfState -Path $ctx.Layout.State
        $read.disabled_firewall_rules | Should -Be @('OpenSSH-Server-In-TCP')
        $read.account_created_by_this_script | Should -BeTrue
        $read.capability_installed_by_this_script | Should -BeFalse
        $read.previous_default_shell.DefaultShell | Should -BeExactly 'C:\x\pwsh.exe'
    }

    It 'starts from defaults when there is no state file or it is unreadable' {
        (Read-WfState -Path (Join-Path $TestDrive 'missing.json')).disabled_firewall_rules.Count | Should -Be 0
        $bad = Join-Path $TestDrive 'bad.json'
        Write-WfTextFile -Path $bad -Text '{not json'
        (Read-WfState -Path $bad 3>$null).account_created_by_this_script | Should -BeFalse
    }
}
