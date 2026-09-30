# Pester 5 tests for the double click launcher, Start-FrontDoorSetup.ps1: the kit code check, the
# parameter parsing, the elevation request, and the elevated run end to end with every Windows
# only call replaced by a mock. What the mocks stand in for can only be proven at the PC;
# remote-access/README.md lists it under "Not verified off Windows".

BeforeAll {
    # Windows only commands the launcher calls. Pester can only mock a command that exists.
    function Find-NetRoute { [CmdletBinding()] param($RemoteIPAddress) }
    function Get-NetConnectionProfile { [CmdletBinding()] param($InterfaceIndex) }
    if (-not (Get-Command Unblock-File -ErrorAction SilentlyContinue)) {
        function Unblock-File { [CmdletBinding()] param($LiteralPath) }
    }
    Mock Write-Host { }

    $script:Launcher = (Resolve-Path (Join-Path $PSScriptRoot '../windows/Start-FrontDoorSetup.ps1')).Path
    $script:WindowsDir = Split-Path -Parent $script:Launcher
    . $script:Launcher -KitFolder 'not-used'
    # For the fingerprint the tests expect; the launcher itself loads these from the unpacked kit.
    . (Join-Path $script:WindowsDir 'WfCommon.ps1')
    . (Join-Path $script:WindowsDir 'WfSetupLib.ps1')

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $blob = [byte[]](0, 0, 0, 11) + [System.Text.Encoding]::ASCII.GetBytes('ssh-ed25519') + [byte[]](0, 0, 0, 32) + [byte[]](@(5) * 32)
    $script:HostKeyBase64 = [System.Convert]::ToBase64String($blob)

    function New-TestKit {
        # A kit folder under TestDrive holding a zip shaped exactly as wf-make-kit.sh builds it,
        # with the real setup files from this checkout. Returns @{ Folder; Zip; Hash; Code }.
        param([string]$Parameters = "mac_address=192.0.2.10`naccount=wfcollector`n", [switch]$OmitCommon)
        $base = Join-Path $TestDrive ([System.Guid]::NewGuid().ToString('N'))
        $stage = Join-Path $base 'stage'
        $top = Join-Path $stage 'wf-frontdoor-kit'
        $windows = Join-Path (Join-Path $top 'remote-access') 'windows'
        $folder = Join-Path $base 'wf-frontdoor'
        foreach ($dir in @($windows, (Join-Path (Join-Path $top 'collectors') 'windows'), $folder)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        foreach ($name in @('Install-FrontDoor.ps1', 'WfSetupLib.ps1', 'WfCommon.ps1', 'dispatch.ps1')) {
            if ($OmitCommon -and $name -eq 'WfCommon.ps1') { continue }
            Copy-Item -LiteralPath (Join-Path $script:WindowsDir $name) -Destination (Join-Path $windows $name)
        }
        [System.IO.File]::WriteAllText((Join-Path $top 'mac-public-key.pub'), "ssh-ed25519 $script:HostKeyBase64 win-forensics-mac`n")
        [System.IO.File]::WriteAllText((Join-Path $top 'kit-parameters.txt'), $Parameters)
        $zip = Join-Path $folder 'wf-frontdoor-kit.zip'
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)
        $hash = ([string](Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash).ToLowerInvariant()
        return @{ Folder = $folder; Zip = $zip; Hash = $hash; Code = (Get-WfKitCode -HexHash $hash) }
    }

    function New-TestProgramData {
        # A ProgramData with the host key sshd would have created.
        $programData = Join-Path $TestDrive ('pd-' + [System.Guid]::NewGuid().ToString('N'))
        $ssh = Join-Path $programData 'ssh'
        [void](New-Item -ItemType Directory -Path $ssh -Force)
        [System.IO.File]::WriteAllText((Join-Path $ssh 'ssh_host_ed25519_key.pub'), "ssh-ed25519 $script:HostKeyBase64 gamingpc\gamer@gamingpc`n")
        return $programData
    }
}

Describe 'Get-WfKitCode and Test-WfKitCode' {
    BeforeAll { $script:Hash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }

    It 'is the left-most 32 hex characters in 8 groups of 4, lower case, the same as wf_kit_code on the Mac' {
        Get-WfKitCode -HexHash $script:Hash.ToUpperInvariant() | Should -BeExactly '0123 4567 89ab cdef 0123 4567 89ab cdef'
        Get-WfKitCodeLength | Should -Be 32
    }

    It 'accepts the code typed with spaces, hyphens, or in upper case, and the full digest' {
        foreach ($typed in @('0123 4567 89ab cdef 0123 4567 89ab cdef', '0123456789abcdef0123456789abcdef', '0123-4567-89AB-CDEF-0123-4567-89AB-CDEF', "  0123456789ABCDEF0123456789ABCDEF `t", $script:Hash)) {
            $check = Test-WfKitCode -Typed $typed -HexHash $script:Hash
            $check.Valid | Should -BeTrue -Because $typed
            $check.Match | Should -BeTrue -Because $typed
        }
    }

    It 'rejects a code that is not one, saying why, without calling it a mismatch' {
        foreach ($typed in @('', $null, 'hello there', '0123 4567 89ab cdef', ($script:Hash + '0'), '0123456789abcdef0123456789abcdeg')) {
            $check = Test-WfKitCode -Typed $typed -HexHash $script:Hash
            $check.Valid | Should -BeFalse -Because "'$typed'"
            $check.Match | Should -BeFalse
            $check.Reason | Should -Not -BeNullOrEmpty
        }
    }

    It 'reports a well formed code that differs as a mismatch' {
        $check = Test-WfKitCode -Typed '0123 4567 89ab cdef 0123 4567 89ab cdee' -HexHash $script:Hash
        $check.Valid | Should -BeTrue
        $check.Match | Should -BeFalse
    }
}

Describe 'Read-WfKitParameters' {
    It 'reads the address and the account, ignoring comments and CRLF' {
        $values = Read-WfKitParameters -Text "# comment`r`nmac_address=192.0.2.10`r`naccount=wfcollector2`r`n`r`n"
        $values.MacAddress | Should -BeExactly '192.0.2.10'
        $values.AccountName | Should -BeExactly 'wfcollector2'
    }

    It 'refuses <Why>' -ForEach @(
        @{ Text = "account=wfcollector`n"; Why = 'a missing address' }
        @{ Text = "mac_address=192.0.2.10`n"; Why = 'a missing account' }
        @{ Text = "mac_address=gaming-mac.local`naccount=wfcollector`n"; Why = 'an address that is not IPv4' }
        @{ Text = "mac_address=192.0.2.10`naccount=wf; whoami`n"; Why = 'an account name with anything but lower case letters and digits' }
        @{ Text = "mac_address=192.0.2.10`naccount=Admin`n"; Why = 'an account name in upper case' }
        @{ Text = "mac_address=192.0.2.10 & whoami`naccount=wfcollector`n"; Why = 'an address with a shell separator' }
        @{ Text = "mac_address=192.0.2.10`naccount=wfcollector`nsomething else`n"; Why = 'a line it does not understand' }
    ) {
        { Read-WfKitParameters -Text $Text } | Should -Throw
    }
}

Describe 'ConvertTo-WfQuotedPath' {
    It 'quotes <Path> as <Expected>' -ForEach @(
        @{ Path = 'C:\Users\A Gamer\Desktop\wf-frontdoor'; Expected = '"C:\Users\A Gamer\Desktop\wf-frontdoor"' }
        @{ Path = 'E:\'; Expected = '"E:\\"' }
        @{ Path = 'E:\wf-frontdoor\'; Expected = '"E:\wf-frontdoor\\"' }
    ) {
        ConvertTo-WfQuotedPath -Path $Path | Should -BeExactly $Expected
    }

    It 'refuses a path with a double quote rather than building a command line around it' {
        { ConvertTo-WfQuotedPath -Path 'C:\x"y' } | Should -Throw
    }
}

Describe 'The unelevated run' {
    It 'asks Windows for the elevated copy with -Verb RunAs, -NoExit, quoted paths, and -Elevated' {
        Mock Start-Process { }
        $code = Invoke-WfLauncher -KitFolder 'C:\Users\A Gamer\Desktop\wf-frontdoor\.' -LauncherPath 'C:\Users\A Gamer\Desktop\wf-frontdoor\Start-FrontDoorSetup.ps1' -Elevated $false
        $code | Should -Be 0
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $Verb -eq 'RunAs' -and
            $FilePath -like '*powershell.exe' -and
            $ArgumentList -like '-NoProfile -NoExit -ExecutionPolicy Bypass -File "*Start-FrontDoorSetup.ps1" -KitFolder "*" -Elevated' -and
            $ArgumentList -like '*"C:\Users\A Gamer\Desktop\wf-frontdoor\Start-FrontDoorSetup.ps1"*'
        }
    }

    It 'explains a declined permission prompt and returns 1 without running anything' {
        Mock Start-Process { throw 'This operation requires an interactive window station' }
        Mock Write-Host { }
        $code = Invoke-WfUnelevatedRun -LauncherPath 'C:\kit\Start-FrontDoorSetup.ps1' -KitFolder 'C:\kit'
        $code | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED: the permission prompt was declined*nothing was changed*' }
    }
}

Describe 'Invoke-WfSetupScript' {
    It 'runs the setup script as a child Windows PowerShell with RemoteSigned in the same window and returns its exit code' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = 2 } }
        $code = Invoke-WfSetupScript -InstallPath 'C:\Users\A Gamer\AppData\Local\Temp\win-forensics-kit\wf-frontdoor-kit\remote-access\windows\Install-FrontDoor.ps1' -PublicKeyPath 'C:\t\mac-public-key.pub' -MacAddress '192.0.2.10' -AccountName 'wfcollector'
        $code | Should -Be 2
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $NoNewWindow -and $Wait -and $PassThru -and $FilePath -like '*powershell.exe' -and
            $ArgumentList -ceq '-NoProfile -ExecutionPolicy RemoteSigned -File "C:\Users\A Gamer\AppData\Local\Temp\win-forensics-kit\wf-frontdoor-kit\remote-access\windows\Install-FrontDoor.ps1" -MacIpAddress 192.0.2.10 -MacPublicKeyFile "C:\t\mac-public-key.pub" -AccountName wfcollector'
        }
    }
}

Describe 'Test-WfNetworkPrivate' {
    It 'is ok for a Private profile on the adapter that reaches the Mac' {
        Mock Find-NetRoute { [pscustomobject]@{ InterfaceIndex = 7 } }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Private'; Name = 'Home'; InterfaceAlias = 'Ethernet' } }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeTrue
        $network.InterfaceIndex | Should -Be 7
        Should -Invoke Get-NetConnectionProfile -ParameterFilter { $InterfaceIndex -eq 7 }
    }

    It 'names the network and the interface when the profile is Public, and says when there is no route' {
        Mock Find-NetRoute { [pscustomobject]@{ InterfaceIndex = 7 } }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Public'; Name = 'Home'; InterfaceAlias = 'Wi-Fi' } }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeFalse
        $network.Reason | Should -Match "'Home'.*'Wi-Fi'.*Public"
        Mock Find-NetRoute { }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeFalse
        $network.Reason | Should -Match 'no network route'
    }
}

Describe 'Expand-WfKit' {
    It 'unpacks the zip, checks the files it needs, and unblocks every file' {
        $kit = New-TestKit
        Mock Unblock-File { }
        $destination = Join-Path $TestDrive ('unpack-' + [System.Guid]::NewGuid().ToString('N'))
        $files = Expand-WfKit -ZipPath $kit.Zip -Destination $destination
        Test-Path -LiteralPath $files.Install | Should -BeTrue
        Test-Path -LiteralPath $files.Parameters | Should -BeTrue
        $count = @(Get-ChildItem -LiteralPath $files.Root -Recurse -File).Count
        $count | Should -BeGreaterThan 4
        Should -Invoke Unblock-File -Times $count -Exactly
        # A second run starts from an empty folder.
        [System.IO.File]::WriteAllText((Join-Path $destination 'leftover.txt'), 'x')
        [void](Expand-WfKit -ZipPath $kit.Zip -Destination $destination)
        Test-Path -LiteralPath (Join-Path $destination 'leftover.txt') | Should -BeFalse
    }

    It 'fails when a file the setup needs is missing from the kit' {
        $kit = New-TestKit -OmitCommon
        Mock Unblock-File { }
        { Expand-WfKit -ZipPath $kit.Zip -Destination (Join-Path $TestDrive 'unpack-missing') } | Should -Throw '*WfCommon.ps1*'
    }
}

Describe 'The elevated run' {
    BeforeEach {
        Mock Get-WfPSEdition { 'Desktop' }
        Mock Test-WfElevated { $true }
        Mock Unblock-File { }
        Mock Find-NetRoute { [pscustomobject]@{ InterfaceIndex = 7 } }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Private'; Name = 'Home'; InterfaceAlias = 'Ethernet' } }
        Mock Invoke-WfSetupScript {
            [System.IO.File]::WriteAllText((Join-Path (Split-Path -Parent $InstallPath) 'wf-frontdoor-report.txt'), "the report`r`n")
            return 0
        }
        Mock Write-Host { }
        $script:Kit = New-TestKit
        $script:Typed = New-Object System.Collections.Generic.Queue[string]
        $script:Typed.Enqueue($script:Kit.Code)
        Mock Read-WfTypedCode { $script:Typed.Dequeue() }
        $script:SavedProgramData = $env:ProgramData
        $env:ProgramData = New-TestProgramData
        # The unpack folder is under the temp directory; keep each test's apart.
        $script:Unpacked = Join-Path $TestDrive ('unpacked-' + [System.Guid]::NewGuid().ToString('N'))
        Mock Get-WfKitFile {
            $files = @{
                Zip      = Join-Path $KitFolder 'wf-frontdoor-kit.zip'
                HostKey  = Join-Path $KitFolder 'pc-host-key.pub'
                Report   = Join-Path $KitFolder 'wf-frontdoor-report.txt'
                Launcher = Join-Path $KitFolder 'Start-FrontDoorSetup.ps1'
                Unpacked = $script:Unpacked
            }
            return $files
        }
    }
    AfterEach { $env:ProgramData = $script:SavedProgramData }

    It 'verifies the code, unpacks, reads the parameters, checks the network, runs the setup, and writes the host key back' {
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 0
        Should -Invoke Read-WfTypedCode -Times 1 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 1 -Exactly -ParameterFilter {
            $MacAddress -eq '192.0.2.10' -and $AccountName -eq 'wfcollector' -and
            $InstallPath -like '*wf-frontdoor-kit*Install-FrontDoor.ps1' -and $PublicKeyPath -like '*wf-frontdoor-kit*mac-public-key.pub'
        }
        # Unblock happened before the setup ran, on the unpacked files.
        Should -Invoke Unblock-File -ParameterFilter { $LiteralPath -like '*Install-FrontDoor.ps1' }
        $hostKey = Join-Path $script:Kit.Folder 'pc-host-key.pub'
        $bytes = [System.IO.File]::ReadAllBytes($hostKey)
        $bytes[0] | Should -Be ([byte][char]'s') -Because 'no byte order mark'
        [System.Text.Encoding]::ASCII.GetString($bytes) | Should -BeExactly "ssh-ed25519 $script:HostKeyBase64 win-forensics-pc`n"
        [System.IO.File]::ReadAllText((Join-Path $script:Kit.Folder 'wf-frontdoor-report.txt')) | Should -BeExactly "the report`r`n"
        $fingerprint = Get-WfKeyFingerprint -KeyBase64 $script:HostKeyBase64
        Should -Invoke Write-Host -ParameterFilter { $Object -eq "    $fingerprint" }
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: PASS*' }
        Test-Path -LiteralPath $script:Unpacked | Should -BeFalse -Because 'the unpacked copy is removed at the end'
    }

    It 'lets a typo be corrected' {
        $script:Typed.Clear()
        $script:Typed.Enqueue('not a code')
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 0
        Should -Invoke Read-WfTypedCode -Times 2 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 1 -Exactly
    }

    It 'stops after three wrong codes without unpacking anything' {
        $script:Typed.Clear()
        $wrong = '0000 0000 0000 0000 0000 0000 0000 0000'
        foreach ($i in 1..3) { $script:Typed.Enqueue($wrong) }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Test-Path -LiteralPath $script:Unpacked | Should -BeFalse
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED: the kit code did not match*' }
    }

    It 'stops with the Set-NetConnectionProfile line when the network is Public, before the setup runs' {
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Public'; Name = 'Home'; InterfaceAlias = 'Wi-Fi' } }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*Public, not Private*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*Set-NetConnectionProfile -InterfaceIndex 7 -NetworkCategory Private*' }
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
    }

    It 'passes INCOMPLETE and FAIL through unchanged and writes no host key then' {
        Mock Invoke-WfSetupScript { 2 }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 2
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: INCOMPLETE*' }
        Mock Invoke-WfSetupScript { 1 }
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: FAIL*' }
        Mock Invoke-WfSetupScript { 9 }
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
    }

    It 'still reports PASS with the fingerprint when the kit folder cannot be written' {
        Mock Write-WfHostKeyToKit { @{ Fingerprint = 'SHA256:examplefingerprintexamplefingerprintexample'; Written = $false; Problem = 'read only' } }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*could not write into*type the fingerprint instead*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -eq '    SHA256:examplefingerprintexamplefingerprintexample' }
    }

    It 'stops when the kit parameters are not usable' {
        $script:Kit = New-TestKit -Parameters "mac_address=192.0.2.10`naccount=Admin User`n"
        $script:Typed.Clear()
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
    }

    It 'stops when not elevated, when not in Windows PowerShell, and when the zip is missing' {
        Mock Test-WfElevated { $false }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Read-WfTypedCode -Times 0 -Exactly
        Mock Test-WfElevated { $true }
        Mock Get-WfPSEdition { 'Core' }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Mock Get-WfPSEdition { 'Desktop' }
        Remove-Item -LiteralPath $script:Kit.Zip
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*wf-frontdoor-kit.zip is missing*' }
        Should -Invoke Read-WfTypedCode -Times 0 -Exactly
    }
}
