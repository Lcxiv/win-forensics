# Pester 5 tests for the double click launcher, Start-FrontDoorSetup.ps1: the removable drive
# rule, the kit code check, the parameter parsing, the elevation request, the private staging,
# and the elevated run end to end with every Windows only call replaced by a mock. What the
# mocks stand in for can only be proven at the PC; remote-access/README.md lists it under "Not
# verified off Windows". The launcher loads WfCommon.ps1 and WfSetupLib.ps1 itself, from the
# unpacked kit; this suite does not preload them, so a launcher that forgot would fail here.

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

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $blob = [byte[]](0, 0, 0, 11) + [System.Text.Encoding]::ASCII.GetBytes('ssh-ed25519') + [byte[]](0, 0, 0, 32) + [byte[]](@(5) * 32)
    $script:HostKeyBase64 = [System.Convert]::ToBase64String($blob)
    # The fingerprint ssh-keygen -l prints, computed here without the setup library.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $script:HostKeyFingerprint = 'SHA256:' + [System.Convert]::ToBase64String($sha.ComputeHash($blob)).TrimEnd('=')
    $sha.Dispose()

    function New-TestKit {
        # A kit folder under TestDrive holding a zip shaped exactly as wf-make-kit.sh builds it,
        # with the real setup files from this checkout. Returns @{ Folder; Zip; Hash; Code }.
        param([string]$Parameters = "mac_address=192.0.2.10`naccount=wfcollector`n", [switch]$OmitCommon, [string]$ExtraEntry = '')
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
        if ($ExtraEntry -ne '') {
            $archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Update)
            try {
                $entry = $archive.CreateEntry($ExtraEntry)
                $stream = $entry.Open()
                $stream.WriteByte(65)
                $stream.Dispose()
            } finally {
                $archive.Dispose()
            }
        }
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

    function Get-RouteObjects {
        # What Find-NetRoute documents: the local address first, then the route, both with the
        # interface index.
        param([int]$Index = 7)
        return @(
            [pscustomobject]@{ IPAddress = '192.0.2.20'; InterfaceIndex = $Index; InterfaceAlias = 'Ethernet' },
            [pscustomobject]@{ DestinationPrefix = '192.0.2.0/24'; InterfaceIndex = $Index; NextHop = '0.0.0.0' }
        )
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

Describe 'Read-WfKitParameters and Test-WfIPv4Text' {
    It 'reads the address and the account, ignoring comments and CRLF' {
        $values = Read-WfKitParameters -Text "# comment`r`nmac_address=192.0.2.10`r`naccount=wfcollector2`r`n`r`n"
        $values.MacAddress | Should -BeExactly '192.0.2.10'
        $values.AccountName | Should -BeExactly 'wfcollector2'
    }

    It 'checks every octet is 0 to 255' {
        Test-WfIPv4Text -Text '255.255.255.255' | Should -BeTrue
        Test-WfIPv4Text -Text '0.0.0.0' | Should -BeTrue
        foreach ($bad in @('999.999.999.999', '256.0.0.1', '192.0.2.300', '1.2.3', '1.2.3.4.5', '', $null, 'a.b.c.d')) {
            Test-WfIPv4Text -Text $bad | Should -BeFalse -Because "'$bad'"
        }
    }

    It 'refuses <Why>' -ForEach @(
        @{ Text = "account=wfcollector`n"; Why = 'a missing address' }
        @{ Text = "mac_address=192.0.2.10`n"; Why = 'a missing account' }
        @{ Text = "mac_address=gaming-mac.local`naccount=wfcollector`n"; Why = 'an address that is not IPv4' }
        @{ Text = "mac_address=999.999.999.999`naccount=wfcollector`n"; Why = 'an address with an octet above 255' }
        @{ Text = "mac_address=192.0.2.256`naccount=wfcollector`n"; Why = 'an address with a last octet above 255' }
        @{ Text = "mac_address=192.0.2.10`naccount=wf; whoami`n"; Why = 'an account name with anything but lower case letters and digits' }
        @{ Text = "mac_address=192.0.2.10`naccount=Admin`n"; Why = 'an account name in upper case' }
        @{ Text = "mac_address=192.0.2.10 & whoami`naccount=wfcollector`n"; Why = 'an address with a shell separator' }
        @{ Text = "mac_address=192.0.2.10`naccount=wfcollector`nsomething else`n"; Why = 'a line it does not understand' }
    ) {
        { Read-WfKitParameters -Text $Text } | Should -Throw
    }
}

Describe 'ConvertTo-WfQuotedPath and Test-WfZipEntryName' {
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

    It 'turns what SETUP-PC.cmd passes into the kit folder' {
        ConvertTo-WfKitPath -Path 'E:\wf-frontdoor\.' | Should -BeExactly 'E:\wf-frontdoor'
        ConvertTo-WfKitPath -Path 'E:\.' | Should -BeExactly 'E:\'
        ConvertTo-WfKitPath -Path 'C:\Users\A Gamer\Desktop\wf-frontdoor' | Should -BeExactly 'C:\Users\A Gamer\Desktop\wf-frontdoor'
    }

    It 'allows only plain relative zip entry names' {
        foreach ($good in @('wf-frontdoor-kit/', 'wf-frontdoor-kit/remote-access/windows/Install-FrontDoor.ps1', 'a/b.c')) {
            Test-WfZipEntryName -Name $good | Should -BeTrue -Because $good
        }
        foreach ($bad in @('../x', 'a/../../x', '/etc/passwd', 'C:/Windows/win.ini', 'a\b', './a', '', $null)) {
            Test-WfZipEntryName -Name $bad | Should -BeFalse -Because "'$bad'"
        }
    }
}

Describe 'Test-WfRemovableKit' {
    It 'is removable only for a drive letter root that .NET reports as Removable' {
        Mock Get-WfDriveType { 'Removable' } -ParameterFilter { $Root -eq 'E:\' }
        Mock Get-WfDriveType { 'Fixed' } -ParameterFilter { $Root -eq 'C:\' }
        (Test-WfRemovableKit -KitFolder 'E:\wf-frontdoor').Removable | Should -BeTrue
        (Test-WfRemovableKit -KitFolder 'E:\').Removable | Should -BeTrue
        $fixed = Test-WfRemovableKit -KitFolder 'C:\Users\A Gamer\Desktop\wf-frontdoor'
        $fixed.Removable | Should -BeFalse
        $fixed.DriveType | Should -BeExactly 'Fixed'
    }

    It 'reports a UNC path as a network drive without asking .NET, and a path with no root as unknown' {
        Get-WfPathRoot -Path '\\server\share\wf-frontdoor' | Should -BeExactly '\\server\share\'
        Get-WfPathRoot -Path 'E:\wf-frontdoor' | Should -BeExactly 'E:\'
        Get-WfDriveType -Root '\\server\share\' | Should -BeExactly 'Network'
        (Test-WfRemovableKit -KitFolder '\\server\share\wf-frontdoor').DriveType | Should -BeExactly 'Network'
        (Test-WfRemovableKit -KitFolder '/tmp/wf-frontdoor').Removable | Should -BeFalse
    }
}

Describe 'The unelevated run' {
    BeforeEach { Mock Get-WfDriveType { 'Removable' } }

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

    It 'refuses a kit that is not on a removable drive before asking for elevation' {
        Mock Get-WfDriveType { 'Fixed' }
        Mock Start-Process { }
        Mock Write-Host { }
        $code = Invoke-WfUnelevatedRun -LauncherPath 'C:\Users\A Gamer\Desktop\wf-frontdoor\Start-FrontDoorSetup.ps1' -KitFolder 'C:\Users\A Gamer\Desktop\wf-frontdoor'
        $code | Should -Be 1
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*Fixed drive, not on a removable one*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*Get-FileHash*' }
    }
}

Describe 'Invoke-WfSetupScript' {
    It 'runs the setup script as a child Windows PowerShell with RemoteSigned in the same window and returns its exit code' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = 2 } }
        $code = Invoke-WfSetupScript -InstallPath 'C:\ProgramData\win-forensics-kit-abc\wf-frontdoor-kit\remote-access\windows\Install-FrontDoor.ps1' -PublicKeyPath 'C:\t\mac-public-key.pub' -MacAddress '192.0.2.10' -AccountName 'wfcollector'
        $code | Should -Be 2
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $NoNewWindow -and $Wait -and $PassThru -and $FilePath -like '*powershell.exe' -and
            $ArgumentList -ceq '-NoProfile -ExecutionPolicy RemoteSigned -File "C:\ProgramData\win-forensics-kit-abc\wf-frontdoor-kit\remote-access\windows\Install-FrontDoor.ps1" -MacIpAddress 192.0.2.10 -MacPublicKeyFile "C:\t\mac-public-key.pub" -AccountName wfcollector'
        }
    }

    It 'returns null, never 0, when the process object carries no exit code' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = $null } }
        $code = Invoke-WfSetupScript -InstallPath 'C:\k\Install-FrontDoor.ps1' -PublicKeyPath 'C:\k\mac-public-key.pub' -MacAddress '192.0.2.10' -AccountName 'wfcollector'
        $null -eq $code | Should -BeTrue
        Mock Start-Process { }
        $code = Invoke-WfSetupScript -InstallPath 'C:\k\Install-FrontDoor.ps1' -PublicKeyPath 'C:\k\mac-public-key.pub' -MacAddress '192.0.2.10' -AccountName 'wfcollector'
        $null -eq $code | Should -BeTrue
    }
}

Describe 'Test-WfNetworkPrivate' {
    It 'is ok for a Private profile on the adapter that reaches the Mac, taking the index from the documented two objects' {
        Mock Find-NetRoute { Get-RouteObjects -Index 7 }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Private'; Name = 'Home'; InterfaceAlias = 'Ethernet' } }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeTrue
        $network.InterfaceIndex | Should -Be 7
        Should -Invoke Get-NetConnectionProfile -Times 1 -Exactly -ParameterFilter { $InterfaceIndex -eq 7 }
    }

    It 'names the network and the interface when the profile is Public' {
        Mock Find-NetRoute { Get-RouteObjects -Index 7 }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Public'; Name = 'Home'; InterfaceAlias = 'Wi-Fi' } }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeFalse
        $network.Reason | Should -Match "'Home'.*'Wi-Fi'.*Public"
    }

    It 'gives a reason, not an error, when there is no route or the lookup throws' {
        Mock Find-NetRoute { }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeFalse
        $network.Reason | Should -Match 'no network route'
        Mock Find-NetRoute { throw 'No matching MSFT_NetRoute objects found' }
        $network = Test-WfNetworkPrivate -MacAddress '192.0.2.10'
        $network.Ok | Should -BeFalse
        $network.Reason | Should -Match 'could not look up a route.*No matching'
        Mock Find-NetRoute { Get-RouteObjects -Index 7 }
        Mock Get-NetConnectionProfile { }
        (Test-WfNetworkPrivate -MacAddress '192.0.2.10').Reason | Should -Match 'no network profile'
    }
}

Describe 'Staging and Expand-WfKit' {
    BeforeEach {
        Mock Unblock-File { }
        Mock New-WfPrivateDirectory { [void](New-Item -ItemType Directory -Path $Path) }
        $script:StagingParent = Join-Path $TestDrive ('staging-' + [System.Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $script:StagingParent)
        Mock Get-WfStagingParent { $script:StagingParent }
    }

    It 'creates a fresh, randomly named, private staging folder and never reuses one' {
        $first = New-WfStaging
        $second = New-WfStaging
        $first | Should -Not -Be $second
        Split-Path -Leaf $first | Should -Match '\Awin-forensics-kit-[0-9a-f]{32}\z'
        Split-Path -Parent $first | Should -Be $script:StagingParent
        Should -Invoke New-WfPrivateDirectory -Times 2 -Exactly
        Mock Get-WfRandomName { Split-Path -Leaf $first | ForEach-Object { $_.Substring('win-forensics-kit-'.Length) } }
        { New-WfStaging } | Should -Throw '*already exists*not touched*'
        Test-Path -LiteralPath $first | Should -BeTrue
    }

    It 'refuses to stage under a reparse point' {
        Mock Test-WfReparsePoint { $true } -ParameterFilter { $Path -eq $script:StagingParent }
        Mock Test-WfReparsePoint { $false }
        { New-WfStaging } | Should -Throw '*reparse point*'
        Should -Invoke New-WfPrivateDirectory -Times 0 -Exactly
    }

    It 'unpacks the zip, checks the files it needs, and unblocks every file' {
        $kit = New-TestKit
        $destination = New-WfStaging
        $files = Expand-WfKit -ZipPath $kit.Zip -Destination $destination
        Test-Path -LiteralPath $files.Install | Should -BeTrue
        Test-Path -LiteralPath $files.Parameters | Should -BeTrue
        $count = @(Get-ChildItem -LiteralPath $files.Root -Recurse -File).Count
        $count | Should -BeGreaterThan 4
        Should -Invoke Unblock-File -Times $count -Exactly
    }

    It 'refuses a zip entry that would climb out of the staging folder before unpacking anything' {
        $kit = New-TestKit -ExtraEntry '../escaped.ps1'
        $destination = New-WfStaging
        { Expand-WfKit -ZipPath $kit.Zip -Destination $destination } | Should -Throw '*would not stay inside*escaped.ps1*'
        @(Get-ChildItem -LiteralPath $destination -Force).Count | Should -Be 0
        Should -Invoke Unblock-File -Times 0 -Exactly
    }

    It 'fails when a file the setup needs is missing from the kit' {
        $kit = New-TestKit -OmitCommon
        { Expand-WfKit -ZipPath $kit.Zip -Destination (New-WfStaging) } | Should -Throw '*WfCommon.ps1*'
    }
}

Describe 'The elevated run' {
    BeforeEach {
        Mock Get-WfPSEdition { 'Desktop' }
        Mock Test-WfElevated { $true }
        # The test kit lives on this Mac; to the launcher it looks like a stick.
        Mock Get-WfPathRoot { 'E:\' }
        Mock Get-WfDriveType { 'Removable' }
        Mock Unblock-File { }
        Mock Find-NetRoute { Get-RouteObjects -Index 7 }
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Private'; Name = 'Home'; InterfaceAlias = 'Ethernet' } }
        Mock Invoke-WfSetupScript {
            [System.IO.File]::WriteAllText((Join-Path (Split-Path -Parent $InstallPath) 'wf-frontdoor-report.txt'), "the report`r`n")
            return 0
        }
        Mock Write-Host { }
        Mock New-WfPrivateDirectory { [void](New-Item -ItemType Directory -Path $Path) }
        $script:StagingParent = Join-Path $TestDrive ('staging-' + [System.Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $script:StagingParent)
        Mock Get-WfStagingParent { $script:StagingParent }
        $script:Kit = New-TestKit
        $script:Typed = New-Object System.Collections.Generic.Queue[string]
        $script:Typed.Enqueue($script:Kit.Code)
        Mock Read-WfTypedCode { $script:Typed.Dequeue() }
        $script:SavedProgramData = $env:ProgramData
        $env:ProgramData = New-TestProgramData
    }
    AfterEach { $env:ProgramData = $script:SavedProgramData }
    BeforeAll {
        function Get-StagingLeftovers { @(Get-ChildItem -LiteralPath $script:StagingParent -Force).Count }
    }

    It 'verifies the code, stages, reads the parameters, checks the network, runs the setup, and writes the host key and report back' {
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 0
        Should -Invoke Read-WfTypedCode -Times 1 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 1 -Exactly -ParameterFilter {
            $MacAddress -eq '192.0.2.10' -and $AccountName -eq 'wfcollector' -and
            $InstallPath -like "$($script:StagingParent)*win-forensics-kit-*wf-frontdoor-kit*Install-FrontDoor.ps1" -and $PublicKeyPath -like '*wf-frontdoor-kit*mac-public-key.pub'
        }
        Should -Invoke Unblock-File -ParameterFilter { $LiteralPath -like '*Install-FrontDoor.ps1' }
        $hostKey = Join-Path $script:Kit.Folder 'pc-host-key.pub'
        $bytes = [System.IO.File]::ReadAllBytes($hostKey)
        $bytes[0] | Should -Be ([byte][char]'s') -Because 'no byte order mark'
        [System.Text.Encoding]::ASCII.GetString($bytes) | Should -BeExactly "ssh-ed25519 $script:HostKeyBase64 win-forensics-pc`n"
        [System.IO.File]::ReadAllText((Join-Path $script:Kit.Folder 'wf-frontdoor-report.txt')) | Should -BeExactly "the report`r`n"
        Should -Invoke Write-Host -ParameterFilter { $Object -eq "    $script:HostKeyFingerprint" }
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: PASS*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*pc-host-key.pub (the PC''s public identity) is next to the zip*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*wf-frontdoor-report.txt (the setup script''s summary) is next to the zip*' }
        Get-StagingLeftovers | Should -Be 0 -Because 'the staging folder is removed at the end'
    }

    It 'refuses a kit on a fixed drive before hashing, unpacking, or unblocking anything' {
        Mock Get-WfDriveType { 'Fixed' }
        Mock Get-WfZipSha256 { throw 'must not be reached' }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 1
        Should -Invoke Get-WfZipSha256 -Times 0 -Exactly
        Should -Invoke Read-WfTypedCode -Times 0 -Exactly
        Should -Invoke Unblock-File -Times 0 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke New-WfPrivateDirectory -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*Fixed drive, not on a removable one*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*manual path in CHECKLIST.md*' }
    }

    It 'lets a typo be corrected' {
        $script:Typed.Clear()
        $script:Typed.Enqueue('not a code')
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 0
        Should -Invoke Read-WfTypedCode -Times 2 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 1 -Exactly
    }

    It 'stops after three wrong codes without staging anything' {
        $script:Typed.Clear()
        $wrong = '0000 0000 0000 0000 0000 0000 0000 0000'
        foreach ($i in 1..3) { $script:Typed.Enqueue($wrong) }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke New-WfPrivateDirectory -Times 0 -Exactly
        Get-StagingLeftovers | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED: the kit code did not match*' }
    }

    It 'stops with the Set-NetConnectionProfile line when the network is Public, before the setup runs, and cleans up' {
        Mock Get-NetConnectionProfile { [pscustomobject]@{ NetworkCategory = 'Public'; Name = 'Home'; InterfaceAlias = 'Wi-Fi' } }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*Public, not Private*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*Set-NetConnectionProfile -InterfaceIndex 7 -NetworkCategory Private*' }
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
        Get-StagingLeftovers | Should -Be 0
    }

    It 'stops with a plain reason when the route lookup throws' {
        Mock Find-NetRoute { throw 'No matching MSFT_NetRoute objects found' }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED: Windows could not look up a route*' }
        Get-StagingLeftovers | Should -Be 0
    }

    It 'stops before the route lookup when the kit holds an out of range address, and cleans up' {
        $script:Kit = New-TestKit -Parameters "mac_address=999.999.999.999`naccount=wfcollector`n"
        $script:Typed.Clear()
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Find-NetRoute -Times 0 -Exactly
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED:*999.999.999.999*' }
        Get-StagingLeftovers | Should -Be 0
    }

    It 'stops when the kit parameters are not usable, and cleans up' {
        $script:Kit = New-TestKit -Parameters "mac_address=192.0.2.10`naccount=Admin User`n"
        $script:Typed.Clear()
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Get-StagingLeftovers | Should -Be 0
    }

    It 'stops when a zip entry would climb out of the staging folder' {
        $script:Kit = New-TestKit -ExtraEntry '../escaped.ps1'
        $script:Typed.Clear()
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Invoke-WfSetupScript -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'STOPPED: the kit could not be unpacked*would not stay inside*' }
        Get-StagingLeftovers | Should -Be 0
    }

    It 'passes INCOMPLETE and FAIL through, keeps the report for both, and writes no host key then' {
        Mock Invoke-WfSetupScript {
            [System.IO.File]::WriteAllText((Join-Path (Split-Path -Parent $InstallPath) 'wf-frontdoor-report.txt'), "incomplete report`r`n")
            return 2
        }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 2
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: INCOMPLETE. Nothing failed*' }
        [System.IO.File]::ReadAllText((Join-Path $script:Kit.Folder 'wf-frontdoor-report.txt')) | Should -BeExactly "incomplete report`r`n"
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
        Get-StagingLeftovers | Should -Be 0

        Mock Invoke-WfSetupScript {
            [System.IO.File]::WriteAllText((Join-Path (Split-Path -Parent $InstallPath) 'wf-frontdoor-report.txt'), "failed report`r`n")
            return 1
        }
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: FAIL*' }
        [System.IO.File]::ReadAllText((Join-Path $script:Kit.Folder 'wf-frontdoor-report.txt')) | Should -BeExactly "failed report`r`n"
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse

        Mock Invoke-WfSetupScript { 9 }
        $script:Typed.Enqueue($script:Kit.Code)
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*left no report to copy*' }
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
    }

    It 'treats an unreadable exit code as INCOMPLETE, never as a pass' {
        Mock Invoke-WfSetupScript { $null }
        $code = Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true
        $code | Should -Be 2
        Should -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: INCOMPLETE. The setup script ran, but its exit code could not be read*' }
        Should -Not -Invoke Write-Host -ParameterFilter { $Object -like 'DONE: RESULT: PASS*' }
        Test-Path -LiteralPath (Join-Path $script:Kit.Folder 'pc-host-key.pub') | Should -BeFalse
    }

    It 'still reports PASS with the fingerprint when the host key file cannot be written, and says so' {
        Mock Write-WfHostKeyToKit { @{ Fingerprint = 'SHA256:examplefingerprintexamplefingerprintexample'; Written = $false; Problem = 'read only' } }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*pc-host-key.pub could not be written into*type the fingerprint instead*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*wf-frontdoor-report.txt (the setup script''s summary) is next to the zip*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -eq '    SHA256:examplefingerprintexamplefingerprintexample' }
    }

    It 'says when the report could not be copied, separately from the host key' {
        Mock Copy-WfReportToKit { @{ Copied = $false; Present = $true; Problem = 'read only' } }
        Invoke-WfLauncher -KitFolder $script:Kit.Folder -LauncherPath $script:Launcher -Elevated $true | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*report could not be copied into*photograph the summary*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*pc-host-key.pub (the PC''s public identity) is next to the zip*' }
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
