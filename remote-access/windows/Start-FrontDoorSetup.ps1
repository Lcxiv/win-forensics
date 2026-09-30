#Requires -Version 5.1
<#
.SYNOPSIS
The double click launcher for the win-forensics front door kit. SETUP-PC.cmd starts it; nobody
types this command.

.DESCRIPTION
Runs twice. The first run (started by SETUP-PC.cmd, not elevated) asks Windows to start a second,
elevated copy through the normal User Account Control prompt and says so in its own window. The
elevated copy, with -Elevated, does the work in a window that stays open:

  1. asks for the kit code the Mac printed and compares it with the SHA-256 of the zip in the
     kit folder (up to three tries; a mismatch stops everything before anything is unpacked)
  2. unpacks the verified zip into a folder under the elevated user's temp directory and removes
     the "downloaded from the internet" mark from the unpacked files
  3. reads the Mac's address and the account name from the kit's kit-parameters.txt
  4. checks that the network the Mac is reached through is marked Private, and stops with the
     exact command to fix it if not (nothing has been changed at that point)
  5. runs Install-FrontDoor.ps1 from the unpacked kit as a child Windows PowerShell with the
     RemoteSigned execution policy, exactly as RUN-AT-PC.txt would, and shows its output
  6. after a PASS, writes the PC's host public key as pc-host-key.pub next to the zip, copies
     wf-frontdoor-report.txt next to it, and prints the host key fingerprint

The result line is the setup script's own: RESULT: PASS, INCOMPLETE, or FAIL. The exit code is
the setup script's (0, 2, 1), or 1 when the launcher stopped before running it.

Everything this launcher relies on is documented in remote-access/README.md ("The launcher").
It holds no address, no key, and no secret; the values come from the verified kit.

.PARAMETER KitFolder
The folder holding SETUP-PC.cmd, this file, and wf-frontdoor-kit.zip. SETUP-PC.cmd passes its own
folder.

.PARAMETER Elevated
Set by the launcher itself when it starts its elevated copy. Do not pass it by hand.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$KitFolder,
    [switch]$Elevated
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------
# Pure helpers (tested under PowerShell 7 off Windows)
# ---------------------------------------------------------------------------------------------

function Get-WfKitCodeLength {
    # The kit code is the left-most 32 hex characters (128 bits) of the zip's SHA-256. A digest
    # truncated to its left-most bits keeps a preimage and second preimage resistance equal to
    # its length in bits (NIST SP 800-107 Rev. 1, section 5.1), and 128 bits is the smallest
    # security strength NIST rates "Acceptable" beyond 2030 (NIST SP 800-57 Part 1 Rev. 5,
    # Table 4). wf-common.sh on the Mac derives the same code; the two must agree.
    32
}

function Get-WfKitCode {
    # Format a lower case hex digest as the code the Mac prints: 8 groups of 4 characters.
    param([Parameter(Mandatory = $true)][string]$HexHash)
    $length = Get-WfKitCodeLength
    $prefix = $HexHash.ToLowerInvariant().Substring(0, $length)
    $groups = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $length; $i += 4) { $groups.Add($prefix.Substring($i, 4)) }
    return ($groups.ToArray() -join ' ')
}

function Test-WfKitCode {
    # Compare what the person typed with the zip's digest. Spaces, hyphens, and case are
    # ignored; at least the 32 characters of the code must be typed, and typing the full 64
    # character digest is accepted too. Returns @{ Valid; Match; Reason }.
    param(
        [AllowNull()][AllowEmptyString()][string]$Typed,
        [Parameter(Mandatory = $true)][string]$HexHash
    )
    $result = @{ Valid = $false; Match = $false; Reason = '' }
    $normalized = ''
    if ($null -ne $Typed) { $normalized = ($Typed -replace '[\s\-]', '').ToLowerInvariant() }
    $minimum = Get-WfKitCodeLength
    if ($normalized -notmatch '\A[0-9a-f]+\z') {
        $result.Reason = 'the code holds only the digits 0 to 9 and the letters a to f'
        return $result
    }
    if ($normalized.Length -lt $minimum) {
        $result.Reason = "the code has $minimum characters (8 groups of 4); $($normalized.Length) were typed"
        return $result
    }
    if ($normalized.Length -gt 64) {
        $result.Reason = "too many characters ($($normalized.Length)); the code has $minimum, the full digest 64"
        return $result
    }
    $result.Valid = $true
    $result.Match = ($HexHash.ToLowerInvariant().Substring(0, $normalized.Length) -ceq $normalized)
    return $result
}

function Read-WfKitParameters {
    # kit-parameters.txt, written by wf-make-kit.sh inside the zip: "mac_address=<IPv4>" and
    # "account=<name>". Both are checked against the same patterns Install-FrontDoor.ps1 applies,
    # so nothing that is not an address or an account name ever reaches a command line.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $values = @{}
    foreach ($line in @($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '\A([a-z_]+)=(.*)\z') { throw "kit-parameters.txt has a line this launcher does not understand: $trimmed" }
        $values[$Matches[1]] = $Matches[2].Trim()
    }
    foreach ($name in @('mac_address', 'account')) {
        if (-not $values.ContainsKey($name)) { throw "kit-parameters.txt does not name $name; make a new kit on the Mac" }
    }
    if ($values.mac_address -notmatch '\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\z') {
        throw "kit-parameters.txt holds a Mac address that is not an IPv4 address: $($values.mac_address)"
    }
    if ($values.account -cnotmatch '\A[a-z][a-z0-9]{2,19}\z') {
        throw "kit-parameters.txt holds an account name that is not usable: $($values.account)"
    }
    return @{ MacAddress = $values.mac_address; AccountName = $values.account }
}

function ConvertTo-WfQuotedPath {
    # Quote one path for a Windows command line. A double quote cannot appear in a Windows path,
    # so the only rule that matters is the C runtime's: a backslash right before the closing
    # quote must be doubled, or it escapes the quote (a kit folder at the root of a USB stick
    # ends with one). https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.Contains('"')) { throw "a path with a double quote cannot be passed on: $Path" }
    $trailing = $Path.Length - $Path.TrimEnd('\').Length
    return '"' + $Path + ('\' * $trailing) + '"'
}

function Get-WfKitFile {
    # Where things are in the kit folder and in the unpacked copy.
    param([Parameter(Mandatory = $true)][string]$KitFolder)
    return @{
        Zip        = Join-Path $KitFolder 'wf-frontdoor-kit.zip'
        HostKey    = Join-Path $KitFolder 'pc-host-key.pub'
        Report     = Join-Path $KitFolder 'wf-frontdoor-report.txt'
        Launcher   = Join-Path $KitFolder 'Start-FrontDoorSetup.ps1'
        Unpacked   = Join-Path ([System.IO.Path]::GetTempPath()) 'win-forensics-kit'
    }
}

function Get-WfUnpackedKitFile {
    # The files the launcher needs inside the unpacked kit (the zip's top directory is
    # wf-frontdoor-kit, as wf-make-kit.sh builds it).
    param([Parameter(Mandatory = $true)][string]$Unpacked)
    $root = Join-Path $Unpacked 'wf-frontdoor-kit'
    $windows = Join-Path (Join-Path $root 'remote-access') 'windows'
    return @{
        Root       = $root
        Windows    = $windows
        Install    = Join-Path $windows 'Install-FrontDoor.ps1'
        Common     = Join-Path $windows 'WfCommon.ps1'
        SetupLib   = Join-Path $windows 'WfSetupLib.ps1'
        Report     = Join-Path $windows 'wf-frontdoor-report.txt'
        PublicKey  = Join-Path $root 'mac-public-key.pub'
        Parameters = Join-Path $root 'kit-parameters.txt'
    }
}

# ---------------------------------------------------------------------------------------------
# Thin wrappers around Windows. Kept small so the tests can replace them.
# ---------------------------------------------------------------------------------------------

function Get-WfPowerShellExe {
    return (Join-Path ([System.Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
}

function Get-WfPSEdition {
    return [string]$PSVersionTable.PSEdition
}

function Test-WfElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-WfElevatedLauncher {
    # Ask Windows to start the elevated copy. -Verb RunAs is the "Run as administrator" verb of
    # Start-Process, which shows the User Account Control prompt. A declined prompt makes
    # Start-Process throw (Windows reports ERROR_CANCELLED, 1223, "The operation was canceled by
    # the user"), which is reported as a plain message, not as a crash.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1
    # https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-
    # -NoExit keeps the elevated window open when the script ends, so the result can be read:
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
    param(
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [Parameter(Mandatory = $true)][string]$KitFolder
    )
    $arguments = @(
        '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-WfQuotedPath -Path $LauncherPath),
        '-KitFolder', (ConvertTo-WfQuotedPath -Path $KitFolder),
        '-Elevated'
    ) -join ' '
    try {
        Start-Process -FilePath (Get-WfPowerShellExe) -Verb RunAs -ArgumentList $arguments
        return @{ Started = $true; Message = '' }
    } catch {
        return @{ Started = $false; Message = $_.Exception.Message }
    }
}

function Get-WfZipSha256 {
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1
    param([Parameter(Mandatory = $true)][string]$Path)
    return ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
}

function Read-WfTypedCode {
    param([Parameter(Mandatory = $true)][string]$Prompt)
    return [string](Read-Host -Prompt $Prompt)
}

function Request-WfKitCode {
    # Ask for the code until it matches, up to $Attempts times. A typo is explained and asked
    # again; a code that is well formed but different stops the run, because that is what a
    # damaged or altered kit looks like.
    param(
        [Parameter(Mandatory = $true)][string]$ZipHash,
        [int]$Attempts = 3
    )
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $typed = Read-WfTypedCode -Prompt 'Kit code from the Mac (8 groups of 4, spaces optional)'
        $check = Test-WfKitCode -Typed $typed -HexHash $ZipHash
        if ($check.Valid -and $check.Match) { return $true }
        if (-not $check.Valid) {
            Write-Host "      That does not look like a kit code: $($check.Reason). Try again." -ForegroundColor Yellow
        } else {
            Write-Host '      The code does not match this kit. Check each group against the Mac screen and try again.' -ForegroundColor Yellow
        }
    }
    return $false
}

function Expand-WfKit {
    # Unpack the verified zip into a fresh folder and remove the "downloaded from the internet"
    # mark from every unpacked file, so that the RemoteSigned policy the setup runs under
    # accepts them. Only a verified kit reaches this point.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/expand-archive?view=powershell-5.1
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $Destination)
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $Destination -Force
    $files = Get-WfUnpackedKitFile -Unpacked $Destination
    foreach ($name in @('Install', 'Common', 'SetupLib', 'PublicKey', 'Parameters')) {
        if (-not (Test-Path -LiteralPath $files[$name] -PathType Leaf)) {
            throw "the kit is missing $($files[$name]) after unpacking; make a new kit on the Mac"
        }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $files.Root -Recurse -File)) {
        Unblock-File -LiteralPath $file.FullName
    }
    return $files
}

function Test-WfNetworkPrivate {
    # The network the Mac is reached through must be Private: the firewall rule the setup
    # creates applies to that profile only. Same reading as the setup script's S1, done here so
    # the person gets the guidance before anything starts.
    # https://learn.microsoft.com/en-us/powershell/module/nettcpip/find-netroute
    # https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile
    param([Parameter(Mandatory = $true)][string]$MacAddress)
    $result = @{ Ok = $false; Category = ''; Name = ''; InterfaceAlias = ''; InterfaceIndex = 0; Reason = '' }
    $route = @(Find-NetRoute -RemoteIPAddress $MacAddress | Select-Object -First 1)
    if ($route.Count -eq 0) {
        $result.Reason = "this PC has no network route to $MacAddress. Check that both machines are on the home network"
        return $result
    }
    $result.InterfaceIndex = [int]$route[0].InterfaceIndex
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $result.InterfaceIndex -ErrorAction SilentlyContinue)
    if ($profiles.Count -eq 0) {
        $result.Reason = "the network adapter used to reach the Mac (interface $($result.InterfaceIndex)) has no network profile; is it connected?"
        return $result
    }
    $result.Category = [string]$profiles[0].NetworkCategory
    $result.Name = [string]$profiles[0].Name
    $result.InterfaceAlias = [string]$profiles[0].InterfaceAlias
    $result.Ok = ($result.Category -eq 'Private')
    if (-not $result.Ok) { $result.Reason = "the network '$($result.Name)' on adapter '$($result.InterfaceAlias)' is set to $($result.Category), not Private" }
    return $result
}

function Invoke-WfSetupScript {
    # Run Install-FrontDoor.ps1 as its own Windows PowerShell process, in this window, with the
    # RemoteSigned policy for that process only: the unpacked files were unblocked after the
    # kit was verified, so RemoteSigned runs them, and nothing about the machine's policy
    # changes. A single argument string is what Start-Process documents as most reliable.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
    param(
        [Parameter(Mandatory = $true)][string]$InstallPath,
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$MacAddress,
        [Parameter(Mandatory = $true)][string]$AccountName
    )
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
        '-File', (ConvertTo-WfQuotedPath -Path $InstallPath),
        '-MacIpAddress', $MacAddress,
        '-MacPublicKeyFile', (ConvertTo-WfQuotedPath -Path $PublicKeyPath),
        '-AccountName', $AccountName
    ) -join ' '
    $process = Start-Process -FilePath (Get-WfPowerShellExe) -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    return [int]$process.ExitCode
}

function Write-WfHostKeyToKit {
    # After a PASS, put the PC's host public key (not a secret) into the kit folder so the Mac
    # can read it from the same stick, and copy the report next to it. Returns the fingerprint,
    # and where the files went or why they could not be written.
    param(
        [Parameter(Mandatory = $true)][hashtable]$KitFiles,
        [Parameter(Mandatory = $true)][hashtable]$Unpacked,
        [Parameter(Mandatory = $true)][string]$ProgramData
    )
    $sshDir = Join-Path $ProgramData 'ssh'
    $hostKeyPath = Join-Path $sshDir 'ssh_host_ed25519_key.pub'
    $tokens = @(([System.IO.File]::ReadAllText($hostKeyPath)).Trim() -split '\s+')
    if ($tokens.Count -lt 2 -or $tokens[0] -cne 'ssh-ed25519') { throw "$hostKeyPath is not an Ed25519 public key" }
    $line = "$($tokens[0]) $($tokens[1]) win-forensics-pc"
    $result = @{ Fingerprint = (Get-WfKeyFingerprint -KeyBase64 $tokens[1]); Written = $false; Problem = '' }
    try {
        Write-WfTextFile -Path $KitFiles.HostKey -Text ($line + "`n")
        if (Test-Path -LiteralPath $Unpacked.Report -PathType Leaf) {
            Copy-Item -LiteralPath $Unpacked.Report -Destination $KitFiles.Report -Force
        }
        $result.Written = $true
    } catch {
        $result.Problem = $_.Exception.Message
    }
    return $result
}

# ---------------------------------------------------------------------------------------------
# The two runs
# ---------------------------------------------------------------------------------------------

function Invoke-WfUnelevatedRun {
    param(
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [Parameter(Mandatory = $true)][string]$KitFolder
    )
    Write-Host 'win-forensics front door: PC setup'
    Write-Host ''
    Write-Host 'Windows will now ask whether this program may make changes to your device.'
    Write-Host 'Choose Yes. A second window opens and the setup continues there.'
    Write-Host ''
    $started = Start-WfElevatedLauncher -LauncherPath $LauncherPath -KitFolder $KitFolder
    if (-not $started.Started) {
        Write-Host 'STOPPED: the permission prompt was declined or closed, so nothing was started and nothing was changed.' -ForegroundColor Red
        Write-Host "         (Windows said: $($started.Message))"
        Write-Host '         Double click SETUP-PC.cmd again and choose Yes at the prompt.'
        return 1
    }
    Write-Host 'The setup is running in the new window. Read the result there; this window can be closed.'
    return 0
}

function Invoke-WfElevatedRun {
    param([Parameter(Mandatory = $true)][string]$KitFolder)
    Write-Host '==================== win-forensics front door: PC setup ===================='
    Write-Host "Kit folder: $KitFolder"
    Write-Host ''
    if ((Get-WfPSEdition) -ne 'Desktop') {
        Write-Host 'STOPPED: this must run in Windows PowerShell (powershell.exe). Double click SETUP-PC.cmd instead of running this file.' -ForegroundColor Red
        return 1
    }
    if (-not (Test-WfElevated)) {
        Write-Host 'STOPPED: this window is not running as Administrator, so nothing can be set up. Double click SETUP-PC.cmd and choose Yes at the permission prompt.' -ForegroundColor Red
        return 1
    }
    $kit = Get-WfKitFile -KitFolder $KitFolder
    if (-not (Test-Path -LiteralPath $kit.Zip -PathType Leaf)) {
        Write-Host "STOPPED: $($kit.Zip) is missing. Copy the whole wf-frontdoor folder from the Mac, not single files. If the folder is on a network drive, copy it to the Desktop first: an administrator window may not see mapped drives." -ForegroundColor Red
        return 1
    }

    # 1. The kit code, compared with the zip's SHA-256 before the zip is opened.
    Write-Host '[1] Checking the kit against the code the Mac printed'
    $zipHash = Get-WfZipSha256 -Path $kit.Zip
    Write-Host "      This kit's code is computed from $($kit.Zip)."
    if (-not (Request-WfKitCode -ZipHash $zipHash)) {
        Write-Host ''
        Write-Host 'STOPPED: the kit code did not match after three tries. Nothing was unpacked and nothing was changed.' -ForegroundColor Red
        Write-Host '         Either a group was mistyped, or this copy of the kit is not the one the Mac made (damaged in transit,'
        Write-Host '         or changed). Copy the wf-frontdoor folder from the Mac again and double click SETUP-PC.cmd again.'
        return 1
    }
    Write-Host '      ok: the code matches this kit' -ForegroundColor Green

    # 2. Unpack and unblock.
    Write-Host '[2] Unpacking the verified kit'
    try {
        $unpacked = Expand-WfKit -ZipPath $kit.Zip -Destination $kit.Unpacked
    } catch {
        Write-Host "STOPPED: the kit could not be unpacked: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
    Write-Host "      ok: unpacked to $($unpacked.Root)" -ForegroundColor Green
    . $unpacked.Common
    . $unpacked.SetupLib

    # 3. Parameters from the verified kit.
    Write-Host '[3] Reading the kit parameters'
    try {
        $parameters = Read-WfKitParameters -Text ([System.IO.File]::ReadAllText($unpacked.Parameters))
    } catch {
        Write-Host "STOPPED: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
    Write-Host "      ok: the Mac's address is $($parameters.MacAddress); the account will be '$($parameters.AccountName)'" -ForegroundColor Green

    # 4. Private network, with the fix spelled out.
    Write-Host '[4] Checking that the home network is marked Private'
    $network = Test-WfNetworkPrivate -MacAddress $parameters.MacAddress
    if (-not $network.Ok) {
        Write-Host "STOPPED: $($network.Reason). Nothing was changed." -ForegroundColor Red
        if ($network.Category -ne '') {
            Write-Host '         If this is your own home network, mark it Private, then double click SETUP-PC.cmd again. Either:'
            Write-Host '           Settings > Network & internet > your connection > Network profile type > Private network'
            Write-Host '         or, in a Windows PowerShell window opened as Administrator:'
            Write-Host "           Set-NetConnectionProfile -InterfaceIndex $($network.InterfaceIndex) -NetworkCategory Private"
            Write-Host '         Private lets other devices at home see this PC. Only do this for your own network.'
        }
        return 1
    }
    Write-Host "      ok: network '$($network.Name)' on adapter '$($network.InterfaceAlias)' is Private" -ForegroundColor Green

    # 5. The setup script itself, in this window.
    Write-Host '[5] Running the setup script (its own steps S1 to S13 follow; S2 can take a few minutes)'
    Write-Host ''
    $code = Invoke-WfSetupScript -InstallPath $unpacked.Install -PublicKeyPath $unpacked.PublicKey -MacAddress $parameters.MacAddress -AccountName $parameters.AccountName
    Write-Host ''

    # 6. The host key back into the kit folder.
    if ($code -eq 0) {
        Write-Host '[6] Writing the PC''s host key into the kit folder for the Mac'
        try {
            $hostKey = Write-WfHostKeyToKit -KitFiles $kit -Unpacked $unpacked -ProgramData $env:ProgramData
        } catch {
            Write-Host "      could not read the host key: $($_.Exception.Message)" -ForegroundColor Yellow
            $hostKey = @{ Fingerprint = ''; Written = $false; Problem = $_.Exception.Message }
        }
        if ($hostKey.Written) {
            Write-Host "      ok: pc-host-key.pub and wf-frontdoor-report.txt are next to the zip in $KitFolder" -ForegroundColor Green
        } else {
            Write-Host "      could not write into $KitFolder ($($hostKey.Problem)); the Mac step will ask you to type the fingerprint instead" -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host 'DONE: RESULT: PASS' -ForegroundColor Green
        if ($hostKey.Fingerprint -ne '') {
            Write-Host 'The PC''s host key fingerprint (public, not a secret):'
            Write-Host "    $($hostKey.Fingerprint)"
        }
        Write-Host 'Next: take the wf-frontdoor folder (the USB stick) back to the Mac and run:  sh remote-access/mac/wf-finish.sh'
        Write-Host 'If the kit did not travel on a USB stick, the Mac will show this fingerprint and ask you to compare it with the line above.'
    } elseif ($code -eq 2) {
        Write-Host 'DONE: RESULT: INCOMPLETE. Nothing failed, but a check could not run, so this is not a pass.' -ForegroundColor Yellow
        Write-Host 'Read the "not verified" line in the summary above, fix what it names, and double click SETUP-PC.cmd again. Do not continue on the Mac yet.'
    } elseif ($code -eq 1) {
        Write-Host 'DONE: RESULT: FAIL. A step failed; the summary above names it and the checklist row to read.' -ForegroundColor Red
        Write-Host 'Fix it and double click SETUP-PC.cmd again. It is safe to repeat.'
    } else {
        Write-Host "DONE: the setup script ended with exit code $code, which it never uses. Read the output above and tell firstmate." -ForegroundColor Red
        $code = 1
    }
    Remove-Item -LiteralPath $kit.Unpacked -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host 'You can close this window.'
    return $code
}

function Invoke-WfLauncher {
    param(
        [Parameter(Mandatory = $true)][string]$KitFolder,
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [bool]$Elevated
    )
    $resolvedKit = [System.IO.Path]::GetFullPath($KitFolder)
    if ($Elevated) { return (Invoke-WfElevatedRun -KitFolder $resolvedKit) }
    return (Invoke-WfUnelevatedRun -LauncherPath $LauncherPath -KitFolder $resolvedKit)
}

# Run only when executed, not when the tests dot-source this file.
if ($MyInvocation.InvocationName -ne '.') {
    $results = @(Invoke-WfLauncher -KitFolder $KitFolder -LauncherPath $PSCommandPath -Elevated $Elevated.IsPresent)
    exit ([int]$results[$results.Count - 1])
}
