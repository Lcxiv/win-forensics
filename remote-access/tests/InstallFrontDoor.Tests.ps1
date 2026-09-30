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
    function Stop-Service { [CmdletBinding()] param($Name, [switch]$Force) }
    function Set-Service { [CmdletBinding()] param($Name, $StartupType) }
    function Get-LocalGroup { [CmdletBinding()] param() }
    function Get-LocalGroupMember { [CmdletBinding()] param($SID, $Member) }
    function Get-NetFirewallPortFilter { [CmdletBinding()] param($PolicyStore, [switch]$All) }
    function Get-NetFirewallApplicationFilter { [CmdletBinding()] param($PolicyStore, [switch]$All) }
    function Get-NetFirewallServiceFilter { [CmdletBinding()] param($PolicyStore, [switch]$All) }
    function Get-NetFirewallAddressFilter { [CmdletBinding()] param($PolicyStore, [switch]$All) }

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
}

Describe 'Invoke-WfInstall' {
    BeforeAll {
        $script:StepFunctions = @(
            'Invoke-WfPreflight', 'Install-WfOpenSshServer', 'Set-WfFirewall', 'Start-WfSshd', 'Set-WfDefaultShell',
            'Set-WfAccount', 'Install-WfLayout', 'Install-WfAuthorizedKey', 'Set-WfSshdConfig', 'Set-WfPower',
            'Show-WfSecurityLogAccess', 'Show-WfHostKey', 'Invoke-WfSelfTest'
        )

        function Invoke-TestInstall {
            # The real step sequence and summary, with every step's work replaced by a recorder.
            param([bool]$SkipSelfTest = $false)
            $script:Seen = New-Object System.Collections.Generic.List[object]
            $script:ReportText = ''
            foreach ($name in $script:StepFunctions) {
                Mock $name { $script:Seen.Add($Context) }
            }
            Mock Save-WfState { }
            Mock Write-WfTextFile { $script:ReportText = $Text }
            $script:WfSteps.Clear()
            $script:WfAbort = $false
            $savedProgramData = $env:ProgramData
            try {
                $env:ProgramData = Join-Path $TestDrive 'ProgramData'
                $results = @(Invoke-WfInstall -MacIpAddress ' 192.0.2.10 ' -MacPublicKeyFile 'mac.pub' -AccountName 'wfcollector' -CollectorSource '' -SkipSelfTest $SkipSelfTest)
            } finally {
                $env:ProgramData = $savedProgramData
            }
            return [int]$results[$results.Count - 1]
        }
    }

    It 'runs every step with the address and key file it was given, and nothing built in' {
        $code = Invoke-TestInstall
        $code | Should -Be 0
        @($script:WfSteps | ForEach-Object { $_.Id }) | Should -Be @('S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12', 'S13')
        foreach ($name in $script:StepFunctions) { Should -Invoke $name -Times 1 -Exactly }
        foreach ($context in $script:Seen) {
            $context.MacIpAddress | Should -BeExactly '192.0.2.10'
            $context.MacPublicKeyFile | Should -BeExactly 'mac.pub'
            $context.AccountName | Should -BeExactly 'wfcollector'
            $context.Layout.Root | Should -BeExactly ((Join-Path $TestDrive 'ProgramData') + '\win-forensics')
        }
        $script:ReportText | Should -Match 'RESULT: PASS'
    }

    It 'ends INCOMPLETE with exit code 2 and never runs the self test when -SkipSelfTest is given' {
        $code = Invoke-TestInstall -SkipSelfTest $true
        $code | Should -Be 2
        Should -Invoke Invoke-WfSelfTest -Times 0
        ($script:WfSteps | Where-Object { $_.Id -eq 'S13' }).Status | Should -BeExactly 'INCOMPLETE'
        $script:ReportText | Should -Match 'RESULT: INCOMPLETE'
    }

    It 'reports only step ids that have a row under "If a step fails" in the checklist' {
        [void](Invoke-TestInstall)
        $checklist = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot '../CHECKLIST.md'))
        foreach ($id in @($script:WfSteps | ForEach-Object { $_.Id })) {
            $checklist | Should -Match ('(?m)^\| ' + $id + ' \|') -Because "the summary sends the reader to row $id"
        }
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
        $script:Service = [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' }
        Mock Get-Service { $script:Service }
        Mock Start-Service { $script:Service.Status = 'Running' }
        Mock Stop-Service { $script:Service.Status = 'Stopped' }
        Mock Set-Service { $script:Service.StartType = [string]$StartupType }
    }

    It 'writes both managed blocks, confirms the effective configuration, then starts sshd for the first time and makes it automatic' {
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $script:GoodDump } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        $text = [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig)
        $text | Should -Match '(?m)^PasswordAuthentication no$'
        $text | Should -Match '(?m)^AllowUsers wfcollector$'
        $text | Should -Match '(?m)^Match User wfcollector$'
        $text | Should -Match ([regex]::Escape("ForceCommand $($script:Ctx.ForcedCommand)"))
        Should -Invoke Start-Service -Times 1 -Exactly
        Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter { $StartupType -eq 'Automatic' }
        $script:Service.Status | Should -BeExactly 'Running'
        $script:Service.StartType | Should -BeExactly 'Automatic'
        # The probe names the client's address as addr and host, and nothing about the server side.
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { $ArgumentList[0] -ceq '-T' -and $ArgumentList[4] -ceq 'user=wfcollector,host=192.0.2.10,addr=192.0.2.10' }
    }

    It 'reads the effective configuration before anything listens' {
        $script:Order = New-Object System.Collections.Generic.List[string]
        Mock Invoke-WfNative { $script:Order.Add([string]$ArgumentList[0]); if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $script:GoodDump } else { Get-NativeResult } }
        Mock Start-Service { $script:Order.Add('start'); $script:Service.Status = 'Running' }
        [void](Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx })
        $script:Order.IndexOf('-T') | Should -BeLessThan $script:Order.IndexOf('start')
    }

    It 'restores the previous sshd_config and leaves sshd stopped when it will not start' {
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $script:GoodDump } else { Get-NativeResult } }
        Mock Start-Service { throw 'service did not start' }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'previous sshd_config was restored and sshd is left stopped'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig) | Should -BeExactly $script:DefaultConfig
        Should -Invoke Set-Service -Times 0
        $script:Service.Status | Should -BeExactly 'Stopped'
    }

    It 'does not start sshd at all when sshd rejects the new configuration' {
        Mock Invoke-WfNative { Get-NativeResult -ExitCode 255 -StdErr 'Bad configuration option' }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.SshdConfig) | Should -BeExactly $script:DefaultConfig
        Should -Invoke Start-Service -Times 0
        $script:Service.Status | Should -BeExactly 'Stopped'
    }

    It 'fails, without starting sshd, when the effective configuration shows another forced command winning' {
        $badDump = $script:GoodDump.Replace("forcecommand $($script:Ctx.ForcedCommand)", 'forcecommand internal-sftp')
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut $badDump } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'ForceCommand'
        Should -Invoke Start-Service -Times 0
    }

    It 'is INCOMPLETE, not PASS, when sshd cannot print the effective configuration' {
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -ExitCode 1 } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'INCOMPLETE'
        ($record.Details -join ' ') | Should -Match 'not verified: sshd -T'
        (Get-WfSummaryResult -Steps @($record)).ExitCode | Should -Be 2
    }

    It 'warns about an allow list that was already in the file' {
        Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text ("AllowUsers louis`n" + $script:DefaultConfig)
        Mock Invoke-WfNative { if ($ArgumentList[0] -ceq '-T') { Get-NativeResult -StdOut ($script:GoodDump + "`nallowusers louis") } else { Get-NativeResult } }
        $record = Invoke-TestStep { Set-WfSshdConfig -Context $script:Ctx }
        $record.Status | Should -BeExactly 'WARN'
        ($record.Details -join ' ') | Should -Match 'louis'
    }
}

Describe 'Start-WfSshd (S4) leaves nothing listening' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:Service = [pscustomobject]@{ Status = 'Stopped'; StartType = 'Automatic' }
        Mock Get-Service { $script:Service }
        Mock Start-Service {
            $script:Service.Status = 'Running'
            Write-WfTextFile -Path (Join-Path $script:Ctx.Layout.SshDir 'ssh_host_ed25519_key.pub') -Text ("ssh-ed25519 $script:KeyBase64 host`n")
            Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text $script:DefaultConfig
        }
        Mock Stop-Service { $script:Service.Status = 'Stopped' }
        Mock Set-Service { $script:Service.StartType = [string]$StartupType }
    }

    It 'starts sshd once to create host keys and the default config, then stops it and keeps it manual' {
        $record = Invoke-TestStep { Start-WfSshd -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke Start-Service -Times 1 -Exactly
        Should -Invoke Stop-Service -Times 1 -Exactly
        Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter { $StartupType -eq 'Manual' }
        $script:Service.Status | Should -BeExactly 'Stopped'
        $script:Service.StartType | Should -BeExactly 'Manual'
    }

    It 'stops a running sshd from an earlier run too' {
        $script:Service.Status = 'Running'
        Write-WfTextFile -Path (Join-Path $script:Ctx.Layout.SshDir 'ssh_host_ed25519_key.pub') -Text ("ssh-ed25519 $script:KeyBase64 host`n")
        Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text $script:DefaultConfig
        (Invoke-TestStep { Start-WfSshd -Context $script:Ctx }).Status | Should -BeExactly 'PASS'
        Should -Invoke Start-Service -Times 0
        $script:Service.Status | Should -BeExactly 'Stopped'
    }

    It 'fails, with sshd stopped, when no host key appeared' {
        Mock Start-Service { $script:Service.Status = 'Running'; Write-WfTextFile -Path $script:Ctx.Layout.SshdConfig -Text $script:DefaultConfig }
        $record = Invoke-TestStep { Start-WfSshd -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        $script:Service.Status | Should -BeExactly 'Stopped'
    }
}

Describe 'Set-WfFirewall' {
    BeforeEach {
        $script:Ctx = New-TestContext
        function New-Rule {
            param([hashtable]$Overrides)
            $rule = @{ Name = 'rule'; Enabled = $true; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = @('22'); Program = 'Any'; Package = ''; Service = 'Any'; RemoteAddress = @('Any'); PolicyStoreSourceType = 'Local'; Unclassified = '' }
            foreach ($key in $Overrides.Keys) { $rule[$key] = $Overrides[$key] }
            return $rule
        }
        $script:Inventory = New-Object System.Collections.Generic.List[object]
        $script:Inventory.Add((New-Rule @{ Name = 'OpenSSH-Server-In-TCP'; Program = 'C:\Windows\System32\OpenSSH\sshd.exe' }))
        $script:Inventory.Add((New-Rule @{ Name = 'win-forensics-ssh-in'; Profile = 'Private'; RemoteAddress = @('192.0.2.10') }))
        $script:Inventory.Add((New-Rule @{ Name = 'a-game'; Protocol = 'Any'; LocalPort = @('Any'); Program = 'C:\Games\game.exe' }))
        $script:Service = [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' }
        Mock Get-NetFirewallRule { $null }
        Mock Remove-NetFirewallRule { }
        Mock New-NetFirewallRule { }
        Mock Disable-NetFirewallRule { foreach ($rule in $script:Inventory) { if ($rule.Name -eq $Name) { $rule.Enabled = $false } } }
        Mock Get-WfInboundAllowRule { @($script:Inventory | ForEach-Object { $_.Clone() }) }
        Mock Get-Service { $script:Service }
        Mock Stop-Service { $script:Service.Status = 'Stopped' }
        Mock Set-Service { $script:Service.StartType = [string]$StartupType }
    }

    It 'creates its own rule for the Mac on Private only, and disables the rule the install created' {
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'win-forensics-ssh-in' -and $RemoteAddress -eq '192.0.2.10' -and $Profile -eq 'Private' -and
            $Direction -eq 'Inbound' -and $Action -eq 'Allow' -and $Protocol -eq 'TCP' -and $LocalPort -eq 22
        }
        Should -Invoke Disable-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'OpenSSH-Server-In-TCP' }
        Should -Invoke Get-WfInboundAllowRule -Times 2 -Exactly
        $script:Ctx.State.disabled_firewall_rules | Should -Be @('OpenSSH-Server-In-TCP')
        Should -Invoke Stop-Service -Times 0
    }

    It 'disables a renamed default rule and a broad Any protocol, Any port rule as well' {
        $script:Inventory.Add((New-Rule @{ Name = '{c0ffee}'; LocalPort = @('20-25'); Program = 'C:\Windows\System32\OpenSSH\sshd.exe' }))
        $script:Inventory.Add((New-Rule @{ Name = 'wide-open'; Protocol = 'Any'; LocalPort = @('Any') }))
        (Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }).Status | Should -BeExactly 'PASS'
        Should -Invoke Disable-NetFirewallRule -Times 3 -Exactly
        @($script:Ctx.State.disabled_firewall_rules | Sort-Object) | Should -Be @('{c0ffee}', 'OpenSSH-Server-In-TCP', 'wide-open')
    }

    It 'replaces its own rule on a second run and disables nothing more' {
        $script:Inventory[0].Enabled = $false
        Mock Get-NetFirewallRule { [pscustomobject]@{ Name = 'win-forensics-ssh-in' } }
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Disable-NetFirewallRule -Times 0
    }

    It 'fails closed, with sshd stopped and manual, when a rule that admits SSH cannot be disabled' {
        Mock Disable-NetFirewallRule { }
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'still admit inbound SSH.*sshd is stopped'
        $script:Service.Status | Should -BeExactly 'Stopped'
        $script:Service.StartType | Should -BeExactly 'Manual'
    }

    It 'fails closed on a policy delivered rule and on a rule it cannot read' {
        $script:Inventory.Add((New-Rule @{ Name = 'from-policy'; Protocol = 'Any'; LocalPort = @('Any'); PolicyStoreSourceType = 'GroupPolicy' }))
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'from-policy.*GroupPolicy'
        $script:Service.Status | Should -BeExactly 'Stopped'

        $script:Inventory.RemoveAt($script:Inventory.Count - 1)
        $script:Inventory.Add((New-Rule @{ Name = 'mystery'; Unclassified = 'missing port filter' }))
        $script:Service.Status = 'Running'
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'mystery.*could not be read'
        $script:Service.Status | Should -BeExactly 'Stopped'
    }

    It 'fails closed when its own rule came out wider than the Mac''s address' {
        $script:Inventory[1].RemoteAddress = @('Any')
        $record = Invoke-TestStep { Set-WfFirewall -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'remote address'
        $script:Service.Status | Should -BeExactly 'Stopped'
    }
}

Describe 'ConvertTo-WfFirewallRuleInfo' {
    It 'flattens a rule and its four filters, and marks a rule with a missing filter unclassified' {
        $rule = [pscustomobject]@{ Name = 'r'; DisplayName = 'R'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; PolicyStoreSourceType = 'Local' }
        $port = [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('22') }
        $app = [pscustomobject]@{ Program = 'Any'; Package = $null }
        $service = [pscustomobject]@{ Service = 'Any' }
        $address = [pscustomobject]@{ RemoteAddress = @('192.0.2.10') }
        $info = ConvertTo-WfFirewallRuleInfo -Rule $rule -PortFilter $port -ApplicationFilter $app -ServiceFilter $service -AddressFilter $address
        $info.Enabled | Should -BeTrue
        $info.Protocol | Should -BeExactly 'TCP'
        $info.LocalPort | Should -Be @('22')
        $info.Package | Should -BeExactly ''
        $info.Unclassified | Should -BeExactly ''
        (ConvertTo-WfFirewallRuleInfo -Rule $rule -PortFilter $null -ApplicationFilter $app -ServiceFilter $service -AddressFilter $address).Unclassified | Should -Match 'port filter'
    }
}

Describe 'Set-WfAccount' {
    BeforeEach {
        $script:Ctx = New-TestContext
        $script:Ctx.AccountSid = ''
        $script:Marker = 'win-forensics SSH collector (key only)'
        $script:Sid = 'S-1-5-21-1-2-3-1001'
        $script:User = [pscustomobject]@{ Name = 'wfcollector'; Enabled = $true; PasswordExpires = $null; Description = $script:Marker; SID = [pscustomobject]@{ Value = $script:Sid } }
        # The baseline as Windows creates it: Users holds Authenticated Users and INTERACTIVE.
        $script:Groups = @(
            @{ Sid = 'S-1-5-32-544'; MemberSids = @('S-1-5-21-1-2-3-1000') }
            @{ Sid = 'S-1-5-32-545'; MemberSids = @('S-1-5-11', 'S-1-5-4') }
            @{ Sid = 'S-1-5-32-573'; MemberSids = @() }
        )
        Mock New-LocalUser { $script:User }
        Mock Set-LocalUser { }
        Mock Enable-LocalUser { $script:User.Enabled = $true }
        Mock Add-LocalGroupMember { $script:Groups[2].MemberSids = @($script:Sid) }
        Mock Get-WfLocalGroupMembership { $script:Groups }
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
        $script:Ctx.AccountSid | Should -BeExactly $script:Sid
        $script:Ctx.State.account_created_by_this_script | Should -BeTrue
        ($record.Details -join ' ') | Should -Not -Match 'System\.Security\.SecureString'
        ($record.Details -join ' ') | Should -Match 'no other group'
    }

    It 'never shows, returns, or records the password it generated' {
        $script:Secret = 'MARKER-PASSWORD-4411-abcdefghijklmnopqrstuvwxyz'
        Mock New-WfRandomPassword {
            $secure = New-Object System.Security.SecureString
            foreach ($ch in $script:Secret.ToCharArray()) { $secure.AppendChar($ch) }
            return $secure
        }
        $script:Exists = $false
        Mock Get-LocalUser { if ($script:Exists) { $script:User } else { $null } }
        Mock New-LocalUser { $script:Exists = $true; $script:User }
        $script:Printed = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { $script:Printed.Add([string]$Object) }
        $before = @(Get-ChildItem -LiteralPath $TestDrive -Recurse -File | ForEach-Object { $_.FullName })
        $output = @(Invoke-TestStep { Set-WfAccount -Context $script:Ctx } 6>&1 5>&1 4>&1 3>&1 2>&1)
        $record = $script:WfSteps[$script:WfSteps.Count - 1]
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-LocalUser -Times 1 -Exactly
        $seen = @($script:Printed) + @($record.Details) + @($output | ForEach-Object { [string]$_ }) + @(ConvertTo-Json -InputObject $script:Ctx.State -Depth 5)
        ($seen -join "`n") | Should -Not -Match 'MARKER-PASSWORD'
        foreach ($file in @(Get-ChildItem -LiteralPath $TestDrive -Recurse -File | Where-Object { $before -notcontains $_.FullName })) {
            [System.IO.File]::ReadAllText($file.FullName) | Should -Not -Match 'MARKER-PASSWORD'
        }
    }

    It 'keeps the description within the 48 characters New-LocalUser allows' {
        $script:Marker.Length | Should -BeLessOrEqual 48
    }

    It 'reuses its own account on a second run without creating or re-adding anything' {
        $script:Groups[2].MemberSids = @($script:Sid)
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        Should -Invoke New-LocalUser -Times 0
        Should -Invoke Add-LocalGroupMember -Times 0
        Should -Invoke Set-LocalUser -Times 1 -Exactly -ParameterFilter { $PasswordNeverExpires -eq $true }
    }

    It 'enables its own account again when it had been disabled' {
        $script:Groups[2].MemberSids = @($script:Sid)
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
        $script:Groups[0].MemberSids = @('S-1-5-21-1-2-3-1000', $script:Sid)
        $script:Groups[2].MemberSids = @($script:Sid)
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'Administrators'
    }

    It 'fails, not warns, when the account is in any group beyond Event Log Readers' {
        $script:Groups += @{ Sid = 'S-1-5-32-559'; MemberSids = @($script:Sid) }
        $script:Groups[2].MemberSids = @($script:Sid)
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'S-1-5-32-559'
    }

    It 'fails when another group grants through Everyone or Authenticated Users' {
        $script:Groups += @{ Sid = 'S-1-5-32-580'; MemberSids = @('S-1-5-11') }
        $script:Groups[2].MemberSids = @($script:Sid)
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'S-1-5-32-580'
    }

    It 'fails when the groups cannot be enumerated completely' {
        Mock Get-WfLocalGroupMembership { throw 'could not read the members of group S-1-5-32-544: Failed to compare two elements in the array' }
        Mock Get-LocalUser { $script:User }
        $record = Invoke-TestStep { Set-WfAccount -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'Failed to compare'
    }
}

Describe 'Get-WfLocalGroupMembership fallback' {
    It 'throws instead of returning a partial list when a group cannot be read' {
        Mock Get-LocalGroup { @([pscustomobject]@{ Name = 'Administrators'; SID = [pscustomobject]@{ Value = 'S-1-5-32-544' } }, [pscustomobject]@{ Name = 'Event Log Readers'; SID = [pscustomobject]@{ Value = 'S-1-5-32-573' } }) }
        Mock Get-LocalGroupMember { if ($SID -eq 'S-1-5-32-544') { throw 'Failed to compare two elements in the array.' } else { @() } }
        { Get-WfLocalGroupMembership } | Should -Throw '*Failed to compare*'
    }

    It 'returns every group with its member SIDs when the fallback can read them all' {
        Mock Get-LocalGroup { @([pscustomobject]@{ Name = 'Users'; SID = [pscustomobject]@{ Value = 'S-1-5-32-545' } }) }
        Mock Get-LocalGroupMember { @([pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-11' } }, [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-4' } }) }
        $groups = @(Get-WfLocalGroupMembership)
        $groups.Count | Should -Be 1
        $groups[0].Sid | Should -BeExactly 'S-1-5-32-545'
        @($groups[0].MemberSids) | Should -Be @('S-1-5-11', 'S-1-5-4')
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

    It 'authorizes a throwaway loopback key, checks ping, a refusal, and a terminal request, and removes the key again' {
        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            if ($ArgumentList -contains '-tt') { return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}' -StdErr 'PTY allocation request failed on channel 0' }
            return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'PASS'
        ($record.Details -join ' ') | Should -Match 'terminal request \(-tt\) was refused a terminal'
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { $ArgumentList -contains '-tt' -and $ArgumentList[$ArgumentList.Count - 1] -eq 'wfcollector@127.0.0.1' }
        $script:KeyWrites.Count | Should -Be 2
        $script:KeyWrites[0].Count | Should -Be 2
        $script:KeyWrites[0][1] | Should -Match 'from="127\.0\.0\.1"'
        $script:KeyWrites[0][1] | Should -Match ([regex]::Escape('command="' + $script:Ctx.ForcedCommand + '",restrict'))
        $script:KeyWrites[1] | Should -Be @($script:Ctx.MacKeyLine)
        [System.IO.File]::ReadAllText($script:Ctx.Layout.AuthorizedKeys) | Should -BeExactly ($script:Ctx.MacKeyLine + "`n")
        @(Get-ChildItem -LiteralPath $script:Ctx.Layout.Root -Filter 'selftest-*').Count | Should -Be 0
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { ($ArgumentList -join ' ') -match 'StrictHostKeyChecking=yes' -and $ArgumentList[$ArgumentList.Count - 2] -eq 'wfcollector@127.0.0.1' -and $ArgumentList[$ArgumentList.Count - 1] -eq 'ping' }
    }

    It 'fails when a forced terminal request gets a shell prompt or a granted terminal' {
        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            if ($ArgumentList -contains '-tt') { return Get-NativeResult -ExitCode 0 -StdOut "Microsoft Windows`r`nC:\Users\wfcollector>" }
            return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'terminal request \(-tt\) was NOT refused'
        [System.IO.File]::ReadAllText($script:Ctx.Layout.AuthorizedKeys) | Should -BeExactly ($script:Ctx.MacKeyLine + "`n")

        Mock Invoke-WfNative {
            if ($ArgumentList[$ArgumentList.Count - 1] -eq 'ping') { return Get-NativeResult -StdOut '{"ok":true,"verb":"ping"}' }
            if ($ArgumentList -contains '-tt') { return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}' -StdErr '' }
            return Get-NativeResult -ExitCode 64 -StdOut '{"ok":false,"error":"refused"}'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'granted a terminal'
    }

    It 'reports the network logon rights when ping is denied' {
        Mock Invoke-WfNative {
            if ($ArgumentList[0] -eq '/export') {
                Write-WfTextFile -Path $ArgumentList[2] -Text "[Privilege Rights]`r`nSeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545`r`nSeDenyNetworkLogonRight = *S-1-5-113`r`n"
                return Get-NativeResult
            }
            return Get-NativeResult -ExitCode 255 -StdErr 'Permission denied (publickey).'
        }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'FAIL'
        ($record.Details -join ' ') | Should -Match 'SeNetworkLogonRight = S-1-5-32-544,S-1-5-32-545; SeDenyNetworkLogonRight = S-1-5-113'
        ($record.Details -join ' ') | Should -Match 'row S13'
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
            if ($ArgumentList -contains '-tt') { return Get-NativeResult -ExitCode 1 -StdOut '{"ok":false,"error":"refused"}' -StdErr 'PTY allocation request failed on channel 0' }
            return Get-NativeResult -ExitCode 1 -StdOut '{"ok":false,"error":"refused"}'
        }
        (Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }).Status | Should -BeExactly 'WARN'
    }

    It 'is INCOMPLETE, never PASS, when the OpenSSH client tools are not there' {
        Remove-Item -LiteralPath (Join-Path (Split-Path -Parent $script:Ctx.SshdExe) 'ssh.exe')
        Mock Invoke-WfNative { throw 'must not be called' }
        $record = Invoke-TestStep { Invoke-WfSelfTest -Context $script:Ctx }
        $record.Status | Should -BeExactly 'INCOMPLETE'
        $script:KeyWrites.Count | Should -Be 0
        (Get-WfSummaryResult -Steps @($record)).ExitCode | Should -Be 2
    }
}

Describe 'Set-WfPower' {
    BeforeEach { $script:Ctx = New-TestContext }

    It 'passes when the read back says never' {
        Mock Invoke-WfNative {
            if ($ArgumentList[0] -eq '/change') { return Get-NativeResult }
            Get-NativeResult -StdOut "  Current AC Power Setting Index: 0x00000000`r`n  Current DC Power Setting Index: 0x00000384`r`n"
        }
        (Invoke-TestStep { Set-WfPower -Context $script:Ctx }).Status | Should -BeExactly 'PASS'
        Should -Invoke Invoke-WfNative -Times 1 -Exactly -ParameterFilter { ($ArgumentList -join ' ') -ceq '/change standby-timeout-ac 0' }
    }

    It 'fails when the read back is not zero, and is INCOMPLETE when it cannot be read' {
        Mock Invoke-WfNative {
            if ($ArgumentList[0] -eq '/change') { return Get-NativeResult }
            Get-NativeResult -StdOut "  Current AC Power Setting Index: 0x00000708`r`n  Current DC Power Setting Index: 0x00000384`r`n"
        }
        (Invoke-TestStep { Set-WfPower -Context $script:Ctx }).Status | Should -BeExactly 'FAIL'
        Mock Invoke-WfNative { Get-NativeResult -StdOut 'Invalid Parameters' }
        $record = Invoke-TestStep { Set-WfPower -Context $script:Ctx }
        $record.Status | Should -BeExactly 'INCOMPLETE'
        (Get-WfSummaryResult -Steps @($record)).Result | Should -BeExactly 'INCOMPLETE'
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

    It 'ends a run whose self test could not run with INCOMPLETE, exit code 2, and no Mac handoff' {
        Invoke-WfStep -Id 'S12' -Title 'host key' -Action { Add-WfNote 'fingerprint shown' }
        Invoke-WfStep -Id 'S13' -Title 'Loopback self test' -Action { Add-WfIncomplete 'skipped because -SkipSelfTest was given; the front door has not been exercised' }
        $code = Write-WfSummary -Context $script:Ctx
        $code | Should -Be 2
        $report = [System.IO.File]::ReadAllText((Join-Path $script:Ctx.SourceDir 'wf-frontdoor-report.txt'))
        $report | Should -Match 'RESULT: INCOMPLETE'
        $report | Should -Not -Match 'RESULT: PASS'
        $report | Should -Not -Match 'wf-pin-host-key'
        $report | Should -Match '\[INCOMPLETE\] S13'
        $report | Should -Match 'row S13'
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
        $ctx.State.previous_default_shell = @{ DefaultShell = 'C:\x\pwsh.exe'; DefaultShellCommandOption = $null; DefaultShellArguments = $null; DefaultShellEscapeArguments = '1' }
        Save-WfState -Context $ctx
        $read = Read-WfState -Path $ctx.Layout.State
        $read.disabled_firewall_rules | Should -Be @('OpenSSH-Server-In-TCP')
        $read.account_created_by_this_script | Should -BeTrue
        $read.capability_installed_by_this_script | Should -BeFalse
        $read.previous_default_shell.DefaultShell | Should -BeExactly 'C:\x\pwsh.exe'
        $read.previous_default_shell.DefaultShellEscapeArguments | Should -BeExactly '1'
        $read.previous_default_shell.Keys.Count | Should -Be 4
    }

    It 'starts from defaults when there is no state file or it is unreadable' {
        (Read-WfState -Path (Join-Path $TestDrive 'missing.json')).disabled_firewall_rules.Count | Should -Be 0
        $bad = Join-Path $TestDrive 'bad.json'
        Write-WfTextFile -Path $bad -Text '{not json'
        (Read-WfState -Path $bad 3>$null).account_created_by_this_script | Should -BeFalse
    }
}
