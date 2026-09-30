#Requires -Version 5.1
<#
.SYNOPSIS
The double click launcher for the win-forensics front door kit, for a kit on a USB stick.
SETUP-PC.cmd starts it; nobody types this command.

.DESCRIPTION
This launcher travels next to the kit zip, so it cannot prove itself: whoever could alter the zip
on the way could alter this file too. It is therefore allowed only where the way is trusted: a
removable drive (a USB stick) that stayed in the person's hands. On any other drive (the Desktop,
a cloud folder, a network share, a download) it refuses before it hashes, unpacks, unblocks, or
runs anything, and points at the manual path in CHECKLIST.md, where Windows' own Get-FileHash
checks the zip against the full SHA-256 typed from the Mac before any kit script runs.

Runs twice. The first run (started by SETUP-PC.cmd, not elevated) checks the drive, then asks
Windows to start a second, elevated copy through the normal User Account Control prompt and says
so in its own window. The elevated copy, with -Elevated, does the work in a window that stays open:

  0. checks again that the kit folder is on a removable drive
  1. reads the zip in the kit folder once, asks for the kit code the Mac printed and compares it
     with the SHA-256 of those bytes (up to three tries; a mismatch stops everything before
     anything is unpacked)
  2. creates a fresh, randomly named staging folder that only SYSTEM and Administrators can use,
     writes the verified bytes there, refuses a zip entry that would land outside it, unpacks
     that copy, refuses any
     unpacked reparse point, and removes the "downloaded from the internet" mark from the files
  3. reads the Mac's address and the account name from the kit's kit-parameters.txt
  4. checks that the network the Mac is reached through is marked Private, and stops with the
     exact command to fix it if not (nothing has been changed at that point)
  5. runs Install-FrontDoor.ps1 from the staging folder as a child Windows PowerShell with the
     RemoteSigned execution policy, exactly as RUN-AT-PC.txt would, and shows its output
  6. copies wf-frontdoor-report.txt next to the zip whatever the result, and after a PASS writes
     the PC's host public key as pc-host-key.pub next to it and prints the host key fingerprint
  The staging folder is removed whatever happened.

The result line is the setup script's own: RESULT: PASS, INCOMPLETE, or FAIL. The exit code is
the setup script's (0, 2, 1), 2 when its exit code could not be read, or 1 when the launcher
stopped before running it.

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

function Test-WfIPv4Text {
    # Four numbers separated by dots, each 0 to 255 (the shape and range check; the loaded
    # setup library's Get-WfIPv4Info adds its loopback, multicast, and leading zero policy).
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -notmatch '\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\z') { return $false }
    foreach ($index in 1..4) {
        if ([int]$Matches[$index] -gt 255) { return $false }
    }
    return $true
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
    if (-not (Test-WfIPv4Text -Text $values.mac_address)) {
        throw "kit-parameters.txt holds a Mac address that is not an IPv4 address (four numbers 0 to 255 separated by dots): $($values.mac_address). Make a new kit on the Mac with --mac-address"
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

function Test-WfZipEntryName {
    # A zip entry is unpacked only if it is a plain relative path with forward slashes: no
    # drive, no leading separator, no ".." segment, no backslash. What is not allowed cannot
    # land outside the staging folder.
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    if ($Name.Contains('\') -or $Name.Contains(':') -or $Name.StartsWith('/')) { return $false }
    foreach ($segment in $Name.Split('/')) {
        if ($segment -eq '..' -or $segment -eq '.') { return $false }
    }
    return $true
}

function Get-WfKitFile {
    # Where things are in the kit folder.
    param([Parameter(Mandatory = $true)][string]$KitFolder)
    return @{
        Zip      = Join-Path $KitFolder 'wf-frontdoor-kit.zip'
        HostKey  = Join-Path $KitFolder 'pc-host-key.pub'
        Report   = Join-Path $KitFolder 'wf-frontdoor-report.txt'
        Launcher = Join-Path $KitFolder 'Start-FrontDoorSetup.ps1'
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

function Stop-WfLauncher {
    # A stop the launcher explains: the message becomes the STOPPED line.
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "STOPPED: $Message"
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

function Get-WfDriveType {
    # The drive type of a path's root, as .NET names it: Removable ("a removable storage device,
    # such as a USB flash drive"), Fixed, Network, CDRom, Ram, Unknown, NoRootDirectory. A root
    # that is not a drive letter (a UNC path) has no DriveInfo and is reported as Network.
    # https://learn.microsoft.com/en-us/dotnet/api/system.io.driveinfo.drivetype
    # https://learn.microsoft.com/en-us/dotnet/api/system.io.drivetype
    param([Parameter(Mandatory = $true)][string]$Root)
    if ($Root -notmatch '\A[A-Za-z]:\\\z') { return 'Network' }
    try {
        $drive = New-Object System.IO.DriveInfo($Root)
        return [string]$drive.DriveType
    } catch {
        return 'Unknown'
    }
}

function Get-WfPathRoot {
    # The root of a Windows path, by its shape: "E:\" for a drive letter path, "\\server\share\"
    # for a UNC path, and an empty string for anything else. Done by pattern rather than by
    # .NET so that the tests can feed Windows paths through PowerShell 7 on a Mac.
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -match '\A([A-Za-z]:\\)') { return $Matches[1] }
    if ($Path -match '\A(\\\\[^\\]+\\[^\\]+)') { return ($Matches[1] + '\') }
    return ''
}

function Test-WfRemovableKit {
    # The one double click path is allowed only for a kit folder on a removable drive.
    param([Parameter(Mandatory = $true)][string]$KitFolder)
    $root = Get-WfPathRoot -Path $KitFolder
    if ($root -eq '') { return @{ Removable = $false; Root = $KitFolder; DriveType = 'Unknown' } }
    $type = Get-WfDriveType -Root $root
    return @{ Removable = ($type -eq 'Removable'); Root = $root; DriveType = $type }
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

function Read-WfZipBytes {
    # The zip is read from the stick once. The bytes that are hashed are the bytes that are
    # later written into the staging folder and unpacked, so a zip changed on the stick while
    # the code is being typed is never the one that runs.
    param([Parameter(Mandatory = $true)][string]$Path)
    return ,([System.IO.File]::ReadAllBytes($Path))
}

function Get-WfZipSha256 {
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $stream = New-Object System.IO.MemoryStream(, $Bytes)
    try {
        return ([string](Get-FileHash -InputStream $stream -Algorithm SHA256).Hash).ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
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

function Get-WfRandomName {
    # 16 bytes from the system's cryptographic random number generator, as 32 hex characters.
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator.create
    $bytes = New-Object byte[] 16
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
}

function Get-WfStagingParent {
    # Under ProgramData, beside the setup script's own layout, never inside it. The elevated
    # copy runs as an administrator; what it creates there is not the unelevated user's to
    # rename or remove, and the staging folder gets its own access list on top.
    return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
}

function Test-WfReparsePoint {
    # Whether a path carries the reparse point attribute (a symbolic link, a junction, a mount
    # point): https://learn.microsoft.com/en-us/dotnet/api/system.io.fileattributes
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    return (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function New-WfPrivateDirectory {
    # Create the directory together with its access list: owner Administrators, SYSTEM and
    # Administrators full control, no inheritance, nobody else. The directory and its list are
    # created in one call, so there is no moment in which it exists with the parent's list.
    # https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createdirectory
    param([Parameter(Mandatory = $true)][string]$Path)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $inheritAll = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $noPropagation = [System.Security.AccessControl.PropagationFlags]::None
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($admins)
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $full, $inheritAll, $noPropagation, $allow)))
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $full, $inheritAll, $noPropagation, $allow)))
    [void][System.IO.Directory]::CreateDirectory($Path, $security)
}

function New-WfStaging {
    # A fresh staging folder: random name, created only if nothing is there (nothing that
    # already exists is ever removed or reused), private access list, and no reparse point
    # anywhere on its path.
    $parent = Get-WfStagingParent
    $path = Join-Path $parent ('win-forensics-kit-' + (Get-WfRandomName))
    if (Test-Path -LiteralPath $path) { throw "the staging folder $path already exists; it was not touched. Run again" }
    $ancestor = $parent
    while ($null -ne $ancestor -and $ancestor -ne '') {
        if (Test-WfReparsePoint -Path $ancestor) { throw "$ancestor is a reparse point (a link or junction), so no staging folder is created under it" }
        $ancestor = Split-Path -Parent $ancestor
    }
    New-WfPrivateDirectory -Path $path
    if (Test-WfReparsePoint -Path $path) { throw "$path is a reparse point right after being created; nothing was unpacked" }
    return $path
}

function Test-WfZipEntries {
    # Every entry name is checked before the zip is opened for unpacking.
    param([Parameter(Mandatory = $true)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in @($archive.Entries)) {
            if (-not (Test-WfZipEntryName -Name $entry.FullName)) {
                throw "the kit zip holds an entry that would not stay inside the staging folder: $($entry.FullName). Nothing was unpacked"
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Expand-WfKit {
    # Unpack the verified zip into the private staging folder, refuse any unpacked reparse
    # point, check the files the setup needs are there, and remove the "downloaded from the
    # internet" mark from every unpacked file so that the RemoteSigned policy the setup runs
    # under accepts them. Only the verified bytes, written into the staging folder, reach
    # this point.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/expand-archive?view=powershell-5.1
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Test-WfZipEntries -ZipPath $ZipPath
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $Destination -Force
    $files = Get-WfUnpackedKitFile -Unpacked $Destination
    foreach ($item in @(Get-ChildItem -LiteralPath $Destination -Recurse -Force)) {
        if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "the unpacked kit holds a reparse point (a link): $($item.FullName). Nothing is run from it"
        }
    }
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

function Remove-WfStaging {
    # Remove the staging folder this run created. Only ever called with that path.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

function Test-WfNetworkPrivate {
    # The network the Mac is reached through must be Private: the firewall rule the setup
    # creates applies to that profile only. Same reading as the setup script's S1, done here so
    # the person gets the guidance before anything starts. Find-NetRoute returns two objects,
    # the local address and the route; either carries the InterfaceIndex, and the first that
    # does is used. A lookup that throws is a reason, not a crash.
    # https://learn.microsoft.com/en-us/powershell/module/nettcpip/find-netroute
    # https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile
    param([Parameter(Mandatory = $true)][string]$MacAddress)
    $result = @{ Ok = $false; Category = ''; Name = ''; InterfaceAlias = ''; InterfaceIndex = 0; Reason = '' }
    try {
        $objects = @(Find-NetRoute -RemoteIPAddress $MacAddress -ErrorAction Stop)
    } catch {
        $result.Reason = "Windows could not look up a route to $MacAddress ($($_.Exception.Message)). Check the address and that both machines are on the home network"
        return $result
    }
    $index = 0
    foreach ($object in $objects) {
        if ($null -eq $object) { continue }
        $property = $object.PSObject.Properties['InterfaceIndex']
        if ($null -ne $property -and $null -ne $property.Value -and [int]$property.Value -gt 0) {
            $index = [int]$property.Value
            break
        }
    }
    if ($index -eq 0) {
        $result.Reason = "this PC has no network route to $MacAddress. Check the address and that both machines are on the home network"
        return $result
    }
    $result.InterfaceIndex = $index
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $index -ErrorAction SilentlyContinue)
    if ($profiles.Count -eq 0) {
        $result.Reason = "the network adapter used to reach the Mac (interface $index) has no network profile; is it connected?"
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
    # Returns the exit code, or $null when the process object does not carry one.
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
    if ($null -eq $process) { return $null }
    $property = $process.PSObject.Properties['ExitCode']
    if ($null -eq $property -or $null -eq $property.Value) { return $null }
    return [int]$property.Value
}

function Copy-WfReportToKit {
    # The setup script's summary, next to the zip, whatever the result. Returns @{ Copied;
    # Present; Problem }.
    param(
        [Parameter(Mandatory = $true)][hashtable]$KitFiles,
        [Parameter(Mandatory = $true)][hashtable]$Unpacked
    )
    $result = @{ Copied = $false; Present = $false; Problem = '' }
    if (-not (Test-Path -LiteralPath $Unpacked.Report -PathType Leaf)) { return $result }
    $result.Present = $true
    try {
        Copy-Item -LiteralPath $Unpacked.Report -Destination $KitFiles.Report -Force
        $result.Copied = $true
    } catch {
        $result.Problem = $_.Exception.Message
    }
    return $result
}

function Write-WfHostKeyToKit {
    # After a PASS, put the PC's host public key (not a secret) into the kit folder so the Mac
    # can read it from the same stick. Returns the fingerprint, and whether the file was
    # written or why not.
    param(
        [Parameter(Mandatory = $true)][hashtable]$KitFiles,
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
        $result.Written = $true
    } catch {
        $result.Problem = $_.Exception.Message
    }
    return $result
}

# ---------------------------------------------------------------------------------------------
# The two runs
# ---------------------------------------------------------------------------------------------

function Write-WfNotRemovableStop {
    param([Parameter(Mandatory = $true)][hashtable]$Drive, [Parameter(Mandatory = $true)][string]$KitFolder)
    Write-Host "STOPPED: the kit folder $KitFolder is on a $($Drive.DriveType) drive, not on a removable one (a USB stick)." -ForegroundColor Red
    Write-Host '         This launcher travels next to the kit and cannot prove it was not changed on the way, so it only runs'
    Write-Host '         from a stick that stayed in your hands. Nothing was checked, unpacked, or changed.'
    Write-Host '         For a kit that came through a cloud folder, a network share, a download, or a copy on this PC, use the'
    Write-Host '         manual path in CHECKLIST.md (action 2, "any other way"): Windows'' own Get-FileHash checks the zip against'
    Write-Host '         the full SHA-256 the Mac printed before any kit file runs. Or copy the folder to a USB stick from the Mac'
    Write-Host '         and double click it there.'
}

function Invoke-WfUnelevatedRun {
    param(
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [Parameter(Mandatory = $true)][string]$KitFolder
    )
    Write-Host 'win-forensics front door: PC setup'
    Write-Host ''
    $drive = Test-WfRemovableKit -KitFolder $KitFolder
    if (-not $drive.Removable) {
        Write-WfNotRemovableStop -Drive $drive -KitFolder $KitFolder
        return 1
    }
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
        Write-Host "STOPPED: $($kit.Zip) is missing. Copy the whole wf-frontdoor folder from the Mac to a USB stick, not single files. An administrator window may not see network drives." -ForegroundColor Red
        return 1
    }

    # 0. Removable drive only; the launcher cannot vouch for itself anywhere else.
    Write-Host '[0] Checking that the kit is on a removable drive'
    $drive = Test-WfRemovableKit -KitFolder $KitFolder
    if (-not $drive.Removable) {
        Write-WfNotRemovableStop -Drive $drive -KitFolder $KitFolder
        return 1
    }
    Write-Host "      ok: $($drive.Root) is a removable drive" -ForegroundColor Green

    # 1. The kit code, compared with the zip's SHA-256 before the zip is opened.
    Write-Host '[1] Checking the kit against the code the Mac printed'
    $zipBytes = Read-WfZipBytes -Path $kit.Zip
    $zipHash = Get-WfZipSha256 -Bytes $zipBytes
    Write-Host "      This kit's code is computed from $($kit.Zip)."
    if (-not (Request-WfKitCode -ZipHash $zipHash)) {
        Write-Host ''
        Write-Host 'STOPPED: the kit code did not match after three tries. Nothing was unpacked and nothing was changed.' -ForegroundColor Red
        Write-Host '         Either a group was mistyped, or this copy of the kit is not the one the Mac made (damaged in transit,'
        Write-Host '         or changed). Copy the wf-frontdoor folder from the Mac again and double click SETUP-PC.cmd again.'
        return 1
    }
    Write-Host '      ok: the code matches this kit' -ForegroundColor Green

    # 2 to 6 happen with a staging folder that is removed whatever happens.
    Write-Host '[2] Unpacking the verified kit into a private staging folder'
    try {
        $staging = New-WfStaging
    } catch {
        Write-Host "STOPPED: no staging folder could be made: $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
    $unpacked = Get-WfUnpackedKitFile -Unpacked $staging
    $code = 1
    $setupExit = $null
    $hostKey = $null
    $report = @{ Copied = $false; Present = $false; Problem = '' }
    try {
        try {
            $stagedZip = Join-Path $staging 'wf-frontdoor-kit.zip'
            [System.IO.File]::WriteAllBytes($stagedZip, $zipBytes)
            $unpacked = Expand-WfKit -ZipPath $stagedZip -Destination $staging
        } catch {
            Stop-WfLauncher -Message "the kit could not be unpacked: $($_.Exception.Message)"
        }
        Write-Host "      ok: unpacked to $($unpacked.Root)" -ForegroundColor Green
        . $unpacked.Common
        . $unpacked.SetupLib

        # 3. Parameters from the verified kit.
        Write-Host '[3] Reading the kit parameters'
        try {
            $parameters = Read-WfKitParameters -Text ([System.IO.File]::ReadAllText($unpacked.Parameters))
        } catch {
            Stop-WfLauncher -Message $_.Exception.Message
        }
        $address = Get-WfIPv4Info -Text $parameters.MacAddress
        if (-not $address.Valid) { Stop-WfLauncher -Message "the Mac address in the kit, $($parameters.MacAddress), is not usable: $($address.Reason). Make a new kit on the Mac with --mac-address" }
        if ($address.Warning -ne '') { Write-Host "      warning: $($address.Warning)" -ForegroundColor Yellow }
        Write-Host "      ok: the Mac's address is $($parameters.MacAddress); the account will be '$($parameters.AccountName)'" -ForegroundColor Green

        # 4. Private network, with the fix spelled out.
        Write-Host '[4] Checking that the home network is marked Private'
        $network = Test-WfNetworkPrivate -MacAddress $parameters.MacAddress
        if (-not $network.Ok) {
            if ($network.Category -ne '') {
                Write-Host '         If this is your own home network, mark it Private, then double click SETUP-PC.cmd again. Either:'
                Write-Host '           Settings > Network & internet > your connection > Network profile type > Private network'
                Write-Host '         or, in a Windows PowerShell window opened as Administrator:'
                Write-Host "           Set-NetConnectionProfile -InterfaceIndex $($network.InterfaceIndex) -NetworkCategory Private"
                Write-Host '         Private lets other devices at home see this PC. Only do this for your own network.'
            }
            Stop-WfLauncher -Message "$($network.Reason). Nothing was changed"
        }
        Write-Host "      ok: network '$($network.Name)' on adapter '$($network.InterfaceAlias)' is Private" -ForegroundColor Green

        # 5. The setup script itself, in this window.
        Write-Host '[5] Running the setup script (its own steps S1 to S13 follow; S2 can take a few minutes)'
        Write-Host ''
        $setupExit = Invoke-WfSetupScript -InstallPath $unpacked.Install -PublicKeyPath $unpacked.PublicKey -MacAddress $parameters.MacAddress -AccountName $parameters.AccountName
        Write-Host ''
        if ($null -eq $setupExit) {
            $code = 2
        } elseif ($setupExit -eq 0 -or $setupExit -eq 1 -or $setupExit -eq 2) {
            $code = $setupExit
        } else {
            $code = 1
        }

        # 6. The host key back into the kit folder, after a PASS only.
        if ($code -eq 0 -and $setupExit -eq 0) {
            Write-Host '[6] Writing the PC''s host key into the kit folder for the Mac'
            try {
                $hostKey = Write-WfHostKeyToKit -KitFiles $kit -ProgramData $env:ProgramData
            } catch {
                $hostKey = @{ Fingerprint = ''; Written = $false; Problem = $_.Exception.Message }
            }
        }
    } catch {
        $message = $_.Exception.Message
        if ($message -notlike 'STOPPED:*') { $message = "STOPPED: something unexpected happened: $message" }
        Write-Host $message -ForegroundColor Red
        $code = 1
    } finally {
        $report = Copy-WfReportToKit -KitFiles $kit -Unpacked $unpacked
        Remove-WfStaging -Path $staging
    }

    # What went next to the zip, said exactly.
    if ($report.Copied) {
        Write-Host "      wf-frontdoor-report.txt (the setup script's summary) is next to the zip in $KitFolder" -ForegroundColor Green
    } elseif ($report.Present) {
        Write-Host "      the setup script's report could not be copied into $KitFolder ($($report.Problem)); photograph the summary above instead" -ForegroundColor Yellow
    } elseif ($null -ne $setupExit -or $code -eq 2) {
        Write-Host '      the setup script left no report to copy' -ForegroundColor Yellow
    }
    if ($null -ne $hostKey) {
        if ($hostKey.Written) {
            Write-Host "      pc-host-key.pub (the PC's public identity) is next to the zip in $KitFolder" -ForegroundColor Green
        } else {
            Write-Host "      pc-host-key.pub could not be written into $KitFolder ($($hostKey.Problem)); the Mac step will ask you to type the fingerprint instead" -ForegroundColor Yellow
        }
    }
    Write-Host ''
    if ($null -eq $setupExit -and $code -eq 2) {
        Write-Host 'DONE: RESULT: INCOMPLETE. The setup script ran, but its exit code could not be read, so nothing here can call it a pass.' -ForegroundColor Yellow
        Write-Host 'Read its RESULT line in the summary above. If it says PASS, double click SETUP-PC.cmd again (it is safe to repeat) so the host key can be written for the Mac.'
    } elseif ($code -eq 0) {
        Write-Host 'DONE: RESULT: PASS' -ForegroundColor Green
        if ($null -ne $hostKey -and $hostKey.Fingerprint -ne '') {
            Write-Host 'The PC''s host key fingerprint (public, not a secret):'
            Write-Host "    $($hostKey.Fingerprint)"
        }
        Write-Host 'Next: take the USB stick back to the Mac and run:  sh remote-access/mac/wf-finish.sh'
    } elseif ($code -eq 2) {
        Write-Host 'DONE: RESULT: INCOMPLETE. Nothing failed, but a check could not run, so this is not a pass.' -ForegroundColor Yellow
        Write-Host 'Read the "not verified" line in the summary above, fix what it names, and double click SETUP-PC.cmd again. Do not continue on the Mac yet.'
    } elseif ($null -ne $setupExit) {
        if ($setupExit -ne 1) { Write-Host "The setup script ended with exit code $setupExit, which it never uses; tell firstmate." -ForegroundColor Yellow }
        Write-Host 'DONE: RESULT: FAIL. A step failed; the summary above names it and the checklist row to read.' -ForegroundColor Red
        Write-Host 'Fix it and double click SETUP-PC.cmd again. It is safe to repeat.'
    } else {
        Write-Host 'DONE: stopped before the setup script ran. Nothing was changed on this PC.' -ForegroundColor Red
    }
    Write-Host ''
    Write-Host 'You can close this window.'
    return $code
}

function ConvertTo-WfKitPath {
    # SETUP-PC.cmd passes "<folder>\." (see its comments); drop that trailing element and any
    # trailing separators, keeping the backslash of a bare drive root. Done by shape, not by
    # .NET, so that the tests can feed Windows paths through PowerShell 7 on a Mac.
    param([Parameter(Mandatory = $true)][string]$Path)
    $result = $Path.Trim()
    if ($result -match '\A(.*?)[\\/]\.\z') { $result = $Matches[1] }
    if ($result -match '\A[A-Za-z]:\z') { $result += '\' }
    return $result
}

function Invoke-WfLauncher {
    param(
        [Parameter(Mandatory = $true)][string]$KitFolder,
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [bool]$Elevated
    )
    $resolvedKit = ConvertTo-WfKitPath -Path $KitFolder
    if ($Elevated) { return (Invoke-WfElevatedRun -KitFolder $resolvedKit) }
    return (Invoke-WfUnelevatedRun -LauncherPath $LauncherPath -KitFolder $resolvedKit)
}

# Run only when executed, not when the tests dot-source this file.
if ($MyInvocation.InvocationName -ne '.') {
    $results = @(Invoke-WfLauncher -KitFolder $KitFolder -LauncherPath $PSCommandPath -Elevated $Elevated.IsPresent)
    exit ([int]$results[$results.Count - 1])
}
