<#
dispatch.ps1: the forced command behind the win-forensics SSH front door.

sshd runs this script, and only this script, for the collector account. Two independent settings
name it: the ForceCommand line of a Match User block in sshd_config, and the command="..." option
on the account's one authorized_keys line. Whatever the client asked for never reaches a shell.
sshd puts the client's original request in the SSH_ORIGINAL_COMMAND environment variable and runs
the forced command instead:

  sshd(8), AUTHORIZED_KEYS FILE FORMAT, command="command": "The command originally supplied by
  the client is available in the SSH_ORIGINAL_COMMAND environment variable."
  https://man.openbsd.org/sshd#command=_command_
  sshd_config(5), ForceCommand: https://man.openbsd.org/sshd_config#ForceCommand

Win32-OpenSSH does the same. session.c sets SSH_ORIGINAL_COMMAND whenever a forced command
replaced the client's request, and the Windows exec path copies that environment into the child:
  https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/session.c#L645-L652
  https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/session.c#L1149-L1151
  https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-doexec.c#L209-L226

Rules this script keeps:
  - The client's string is compared, never executed. It is matched against an exact allowlist
    with case sensitive, fully anchored patterns; nothing from it is passed to a shell, to
    Invoke-Expression, or to a command line. The only parts that travel further are a collector
    name and a bundle directory name, and only after they matched a fixed pattern.
  - No script parameters and no configuration read from the environment. Paths come from this
    file's own location, which the collector account cannot write. Win32-OpenSSH does not
    support AcceptEnv or PermitUserEnvironment, so the client cannot set other variables either:
    https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
  - Read only toward the machine. It reads, runs the named collectors, and writes only under the
    outbox directory.
  - Collector output is data. The summary line a collector prints is parsed, checked field by
    field, and re-serialized; it is never trusted as a path or an instruction.

Verbs (see remote-access/README.md for the full protocol):
  ping                    health JSON
  list-bundles            finished bundles waiting in the outbox
  collect-<name>          run collectors\<name>.ps1; publish its directory in the outbox if it exits 0
  fetch-<bundle dir>      stream one bundle as a zip, base64 framed, with its SHA-256
  security-log-access     run "wevtutil gl Security" and "wevtutil gli Security" and report

Exit codes: 0 ok, 64 refused, 65 unknown collector, 66 unknown bundle, 70 internal error,
71 collector failed, 72 collector timed out, 73 outbox full, 75 busy.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Progress records would otherwise be written to the SSH client's stderr.
$ProgressPreference = 'SilentlyContinue'

. (Join-Path $PSScriptRoot 'WfCommon.ps1')

function Test-WfWindows {
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-WfDispatchConfig {
    # Everything the dispatcher needs to know about where it is installed. RemoteDir is the
    # directory holding this script; the outbox is its sibling (see remote-access/README.md).
    param(
        [Parameter(Mandatory = $true)][string]$RemoteDir,
        [Parameter(Mandatory = $true)][string]$DispatcherPath
    )
    $root = Split-Path -Parent $RemoteDir
    $outbox = Join-Path $root 'outbox'
    $systemDirectory = [System.Environment]::SystemDirectory
    if (Test-WfWindows) {
        # Windows PowerShell 5.1, the interpreter the collector seam names. Its path has no space.
        $powerShellExe = Join-Path $systemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
        $wevtutilExe = Join-Path $systemDirectory 'wevtutil.exe'
        $sshdExe = Join-Path $systemDirectory 'OpenSSH\sshd.exe'
    } else {
        # Only reached when the tests run this file under PowerShell 7 off Windows.
        $powerShellExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $wevtutilExe = ''
        $sshdExe = ''
    }
    return @{
        RemoteDir               = $RemoteDir
        DispatcherPath          = $DispatcherPath
        CollectorsDir           = Join-Path $RemoteDir 'collectors'
        OutboxDir               = $outbox
        StagingDir              = Join-Path $outbox '.staging'
        PowerShellExe           = $powerShellExe
        WevtutilExe             = $wevtutilExe
        SshdExe                 = $sshdExe
        CollectorTimeoutSeconds = 900
        MaxBundles              = 50
        MaxOutboxBytes          = [long]2147483648
    }
}

function Resolve-WfVerb {
    # Map the client's request to one allowlisted verb, or to 'refuse'. Pure: no side effects.
    param([AllowNull()][AllowEmptyString()][string]$Requested)
    if ([string]::IsNullOrEmpty($Requested)) {
        return @{ Verb = 'refuse'; Argument = ''; Reason = 'no command given; this account has no shell' }
    }
    if ($Requested.Length -gt 128) {
        return @{ Verb = 'refuse'; Argument = ''; Reason = 'request too long' }
    }
    if ($Requested -ceq 'ping') { return @{ Verb = 'ping'; Argument = ''; Reason = '' } }
    if ($Requested -ceq 'list-bundles') { return @{ Verb = 'list-bundles'; Argument = ''; Reason = '' } }
    if ($Requested -ceq 'security-log-access') { return @{ Verb = 'security-log-access'; Argument = ''; Reason = '' } }
    if ($Requested.StartsWith('collect-', [System.StringComparison]::Ordinal)) {
        $name = $Requested.Substring(8)
        if (Test-WfCollectorName -Name $name) { return @{ Verb = 'collect'; Argument = $name; Reason = '' } }
        return @{ Verb = 'refuse'; Argument = ''; Reason = 'collector name is not of the form [a-z][a-z0-9-]{1,40}' }
    }
    if ($Requested.StartsWith('fetch-', [System.StringComparison]::Ordinal)) {
        $id = $Requested.Substring(6)
        if (Test-WfBundleDirName -Name $id) { return @{ Verb = 'fetch'; Argument = $id; Reason = '' } }
        return @{ Verb = 'refuse'; Argument = ''; Reason = 'bundle directory name is not of the form <yyyymmddThhmmssZ>_<collector>_<8 hex>' }
    }
    return @{ Verb = 'refuse'; Argument = ''; Reason = 'not an allowed verb' }
}

function ConvertTo-WfJsonLine {
    # One compact JSON line, ASCII only, so the bytes on the wire do not depend on a code page.
    param([Parameter(Mandatory = $true)]$InputObject)
    $json = ConvertTo-Json -InputObject $InputObject -Compress -Depth 8
    return [regex]::Replace($json, '[^\x20-\x7E]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}

function Write-WfLine {
    # Write one line of UTF-8 text and a line feed straight to a stream.
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
}

function Get-WfUtcStamp {
    param([string]$Format = 'yyyy-MM-ddTHH:mm:ssZ')
    return [System.DateTime]::UtcNow.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-WfHostId {
    # The host name never leaves the machine through this script; only a hash of it does.
    return (Get-WfStringSha256 -Text ([System.Environment]::MachineName.ToLowerInvariant())).Substring(0, 16)
}

function Get-WfCollectorList {
    # Collectors are the .ps1 files in the collectors directory whose base name matches the
    # collector name pattern. Helper files that sit next to them (the collectors' shared
    # _common.ps1, for one) do not match it, so they are never listed and can never be a verb.
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    $names = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $Config.CollectorsDir -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $Config.CollectorsDir -Filter '*.ps1' -File)) {
            if (Test-WfCollectorName -Name $file.BaseName) { $names.Add($file.BaseName) }
        }
    }
    $names.Sort([System.StringComparer]::Ordinal)
    # Emitted one by one. Callers collect with @(...): an array handed back as a single object is
    # wrapped by the pipeline, and Windows PowerShell 5.1's ConvertTo-Json would then serialize it
    # as an object with value and Count members instead of as a JSON array.
    return $names.ToArray()
}

function Get-WfDirectoryStat {
    # File count and total bytes under a directory.
    param([Parameter(Mandatory = $true)][string]$Path)
    $count = 0
    [long]$bytes = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force)) {
        $count++
        $bytes += $file.Length
    }
    return @{ Files = $count; Bytes = $bytes }
}

function Get-WfBundleList {
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    $bundles = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $Config.OutboxDir -PathType Container) {
        $dirs = @(Get-ChildItem -LiteralPath $Config.OutboxDir -Directory | Sort-Object -Property Name)
        foreach ($dir in $dirs) {
            if (-not (Test-WfBundleDirName -Name $dir.Name)) { continue }
            $stat = Get-WfDirectoryStat -Path $dir.FullName
            $bundles.Add([ordered]@{
                    bundle_dir = $dir.Name
                    files     = $stat.Files
                    bytes     = $stat.Bytes
                })
        }
    }
    return $bundles.ToArray()
}

function Get-WfOsInfo {
    $info = [ordered]@{
        platform        = [System.Environment]::OSVersion.Platform.ToString()
        version         = [System.Environment]::OSVersion.Version.ToString()
        build           = $null
        ubr             = $null
        display_version = $null
    }
    if (Test-WfWindows) {
        try {
            $key = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            foreach ($pair in @(@('build', 'CurrentBuildNumber'), @('ubr', 'UBR'), @('display_version', 'DisplayVersion'))) {
                $property = $key.PSObject.Properties[$pair[1]]
                if ($null -ne $property) { $info[$pair[0]] = [string]$property.Value }
            }
        } catch {
            Write-Verbose "reading the Windows version from the registry failed: $_"
        }
    }
    return $info
}

function Get-WfBootTimeUtc {
    if (-not (Test-WfWindows)) { return $null }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 10
        return $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return $null
    }
}

function Test-WfConsoleUserPresent {
    # Is somebody signed in at the PC's own screen? Only yes or no leaves the machine, never the
    # name. The acceptance checks use it to show that the front door works after a restart with
    # nobody signed in. Win32_ComputerSystem.UserName is "the name of the user that is logged on
    # to the console"; it is empty when nobody is.
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
    if (-not (Test-WfWindows)) { return $null }
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 10
        return (-not [string]::IsNullOrEmpty([string]$system.UserName))
    } catch {
        return $null
    }
}

function Get-WfSshdFileVersion {
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    if ([string]::IsNullOrEmpty($Config.SshdExe)) { return $null }
    if (-not (Test-Path -LiteralPath $Config.SshdExe -PathType Leaf)) { return $null }
    try {
        return [string](Get-Item -LiteralPath $Config.SshdExe).VersionInfo.ProductVersion
    } catch {
        return $null
    }
}

function Invoke-WfPing {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream
    )
    $bundles = @(Get-WfBundleList -Config $Config)
    [long]$outboxBytes = 0
    foreach ($bundle in $bundles) { $outboxBytes += $bundle.bytes }
    $health = [ordered]@{
        ok                = $true
        verb              = 'ping'
        protocol          = 1
        time_utc          = Get-WfUtcStamp
        host_id           = Get-WfHostId
        account           = [System.Environment]::UserName
        os                = Get-WfOsInfo
        openssh_server    = Get-WfSshdFileVersion -Config $Config
        powershell        = $PSVersionTable.PSVersion.ToString()
        dispatcher_sha256 = Get-WfFileSha256 -Path $Config.DispatcherPath
        collectors        = [string[]]@(Get-WfCollectorList -Config $Config)
        outbox            = [ordered]@{
            bundles     = $bundles.Count
            bytes       = $outboxBytes
            max_bundles = $Config.MaxBundles
            max_bytes   = $Config.MaxOutboxBytes
        }
        boot_time_utc     = Get-WfBootTimeUtc
        console_user      = Test-WfConsoleUserPresent
    }
    Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $health)
    return 0
}

function Invoke-WfListBundles {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream
    )
    $result = [ordered]@{
        ok      = $true
        verb    = 'list-bundles'
        bundles = [object[]]@(Get-WfBundleList -Config $Config)
    }
    Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $result)
    return 0
}

function ConvertFrom-WfCollectorSummary {
    # The seam: a collector's last stdout line is
    # {"collector":"<name>","status":"ok|partial|failed","bundle":"<dir>","artifacts":<count>}.
    # Returns a checked copy, or $null when the line is missing or not of that shape. The
    # "bundle" field is dropped on purpose: the dispatcher chose the directory and reports its id.
    param(
        [AllowNull()][AllowEmptyString()][string]$StdOut,
        [Parameter(Mandatory = $true)][string]$CollectorName
    )
    if ([string]::IsNullOrEmpty($StdOut)) { return $null }
    $lines = @($StdOut -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -eq 0) { return $null }
    $last = $lines[$lines.Count - 1].Trim()
    if ($last.Length -gt 4096) { return $null }
    try {
        $parsed = ConvertFrom-Json -InputObject $last
    } catch {
        return $null
    }
    if ($null -eq $parsed -or $parsed -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    foreach ($field in @('collector', 'status', 'artifacts')) {
        if ($null -eq $parsed.PSObject.Properties[$field]) { return $null }
    }
    if ([string]$parsed.collector -cne $CollectorName) { return $null }
    if (@('ok', 'partial', 'failed') -cnotcontains [string]$parsed.status) { return $null }
    $artifacts = 0
    if (-not [int]::TryParse([string]$parsed.artifacts, [ref]$artifacts)) { return $null }
    if ($artifacts -lt 0) { return $null }
    return [ordered]@{
        collector = $CollectorName
        status    = [string]$parsed.status
        artifacts = $artifacts
    }
}

function Invoke-WfCollect {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream,
        [Parameter(Mandatory = $true)][System.IO.Stream]$ErrStream
    )
    # $Name already matched the collector name pattern, so it cannot contain a path separator,
    # a dot, or a space. The path is built here, never taken from the client.
    $collectorPath = Join-Path $Config.CollectorsDir ($Name + '.ps1')
    if (-not (Test-Path -LiteralPath $collectorPath -PathType Leaf)) {
        $unknown = [ordered]@{
            ok        = $false
            verb      = 'collect'
            error     = 'unknown collector'
            collector = $Name
            available = [string[]]@(Get-WfCollectorList -Config $Config)
        }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $unknown)
        Write-WfLine -Stream $ErrStream -Text "wf-dispatch: unknown collector '$Name'; run ping to list the installed collectors"
        return 65
    }

    $bundles = @(Get-WfBundleList -Config $Config)
    # The byte limit counts everything under the outbox, including what failed runs left in
    # .staging, so that a collector failing again and again cannot fill the disk unseen.
    [long]$outboxBytes = 0
    if (Test-Path -LiteralPath $Config.OutboxDir -PathType Container) { $outboxBytes = (Get-WfDirectoryStat -Path $Config.OutboxDir).Bytes }
    if ($bundles.Count -ge $Config.MaxBundles -or $outboxBytes -ge $Config.MaxOutboxBytes) {
        $full = [ordered]@{
            ok      = $false
            verb    = 'collect'
            error   = 'outbox full'
            bundles = $bundles.Count
            bytes   = $outboxBytes
        }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $full)
        Write-WfLine -Stream $ErrStream -Text 'wf-dispatch: outbox full; fetch what you need, then delete old bundle folders at the PC (checklist, "Housekeeping")'
        return 73
    }

    # The collector writes into outbox\.staging\<bundle dir>, which list-bundles, ping, and
    # fetch never look at. Only a run that exited 0 is moved into the outbox, by a rename on the
    # same volume, so a bundle still being written, or one from a run that failed, timed out, or
    # lost its SSH session, can never be listed or fetched.
    $machineShort = (Get-WfHostId).Substring(0, 8)
    $dirName = ''
    $bundleDir = ''
    $workDir = ''
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $candidate = '{0}_{1}_{2}' -f (Get-WfUtcStamp -Format 'yyyyMMddTHHmmssZ'), $Name, $machineShort
        $candidateDir = Join-Path $Config.OutboxDir $candidate
        $candidateWork = Join-Path $Config.StagingDir $candidate
        if (-not (Test-Path -LiteralPath $candidateDir) -and -not (Test-Path -LiteralPath $candidateWork)) {
            $dirName = $candidate
            $bundleDir = $candidateDir
            $workDir = $candidateWork
            break
        }
        Start-Sleep -Milliseconds 1100
    }
    if ($dirName -eq '') {
        $busy = [ordered]@{ ok = $false; verb = 'collect'; error = 'busy'; collector = $Name }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $busy)
        Write-WfLine -Stream $ErrStream -Text 'wf-dispatch: another run of this collector started in the same second; try again'
        return 75
    }
    [void](New-Item -ItemType Directory -Path $workDir -Force)

    # The collector runs as its own Windows PowerShell process, as the seam says: standalone,
    # -OutputDirectory as its one parameter, a JSON summary as its last stdout line. -File makes
    # the collector's "exit N" the process exit code. The execution policy is set for this one
    # process only and to the narrowest value that runs an unsigned local script: RemoteSigned
    # "doesn't require digital signatures on scripts that are written on the local computer and
    # not downloaded from the internet". The setup script unblocks every file it installs.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
    # Status "partial" exits 0 (a complete bundle, some source unread); "failed" exits non zero.
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-File', $collectorPath, '-OutputDirectory', $workDir)
    $run = Invoke-WfNative -FilePath $Config.PowerShellExe -ArgumentList $arguments -TimeoutSeconds $Config.CollectorTimeoutSeconds

    if (-not [string]::IsNullOrEmpty($run.StdErr)) {
        # Diagnostics are for a person reading the terminal. Keep the tail, and keep it printable.
        $tail = $run.StdErr
        if ($tail.Length -gt 8192) { $tail = $tail.Substring($tail.Length - 8192) }
        $tail = [regex]::Replace($tail, '[^\x09\x0A\x0D\x20-\x7E]', '?')
        Write-WfLine -Stream $ErrStream -Text $tail.TrimEnd()
    }

    $summary = ConvertFrom-WfCollectorSummary -StdOut $run.StdOut -CollectorName $Name
    $stat = Get-WfDirectoryStat -Path $workDir
    $exitCode = 0
    $errorText = $null
    if ($run.TimedOut) {
        $exitCode = 72
        $errorText = 'collector timed out'
    } elseif ($run.ExitCode -ne 0) {
        $exitCode = 71
        $errorText = 'collector failed'
    }
    $result = [ordered]@{
        ok                  = ($exitCode -eq 0)
        verb                = 'collect'
        collector           = $Name
        bundle_dir          = $dirName
        collector_exit_code = $run.ExitCode
        timed_out           = $run.TimedOut
        summary_valid       = ($null -ne $summary)
        summary             = $summary
        files               = $stat.Files
        bytes               = $stat.Bytes
        fetch               = 'fetch-' + $dirName
    }
    if ($null -ne $errorText) {
        $result['error'] = $errorText
        $result.Remove('fetch')
    } else {
        Move-Item -LiteralPath $workDir -Destination $bundleDir
    }
    Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $result)
    return $exitCode
}

function New-WfBundleZip {
    # Zip one bundle directory. Entry names are written by hand with forward slashes and the
    # bundle directory name as the top directory, so the archive is the same whatever the .NET version's
    # default path separator for ZipFile.CreateFromDirectory is.
    param(
        [Parameter(Mandatory = $true)][string]$BundleDir,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ZipPath
    )
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $base = (Get-Item -LiteralPath $BundleDir).FullName.TrimEnd('\', '/')
    $files = @(Get-ChildItem -LiteralPath $base -Recurse -File -Force | Sort-Object -Property FullName)
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($base.Length).TrimStart('\', '/').Replace('\', '/')
            $entryName = $Name + '/' + $relative
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally {
        $zip.Dispose()
    }
}

function Invoke-WfFetch {
    # Transfer format, one line feed after every line:
    #   WF-BUNDLE-BEGIN v1 dir=<bundle dir> bytes=<zip byte count> sha256=<lower case hex>
    #   <base64 of the zip, 76 characters per line>
    #   WF-BUNDLE-END v1 dir=<bundle dir>
    # The forced command blocks scp and sftp, so the bundle travels on stdout of this same
    # command. remote-access/mac/wf-fetch.sh decodes it and refuses it unless the byte count and
    # the SHA-256 match the header.
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream,
        [Parameter(Mandatory = $true)][System.IO.Stream]$ErrStream
    )
    # $Name already matched the bundle directory pattern: no separators, no dots.
    $bundleDir = Join-Path $Config.OutboxDir $Name
    if (-not (Test-Path -LiteralPath $bundleDir -PathType Container)) {
        $unknown = [ordered]@{ ok = $false; verb = 'fetch'; error = 'unknown bundle'; bundle_dir = $Name }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $unknown)
        Write-WfLine -Stream $ErrStream -Text "wf-dispatch: no bundle '$Name' in the outbox; run list-bundles"
        return 66
    }
    if (-not (Test-Path -LiteralPath $Config.StagingDir -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $Config.StagingDir -Force)
    }
    $zipPath = Join-Path $Config.StagingDir ('{0}.{1}.zip' -f $Name, [System.Guid]::NewGuid().ToString('N'))
    try {
        New-WfBundleZip -BundleDir $bundleDir -Name $Name -ZipPath $zipPath
        $sha256 = Get-WfFileSha256 -Path $zipPath
        $length = (Get-Item -LiteralPath $zipPath).Length
        Write-WfLine -Stream $OutStream -Text ('WF-BUNDLE-BEGIN v1 dir={0} bytes={1} sha256={2}' -f $Name, $length, $sha256)
        # 57 bytes encode to exactly one 76 character base64 line, so every chunk but the last
        # ends on a line boundary and no chunk needs padding in the middle of the stream.
        $buffer = New-Object byte[] (57 * 1024)
        $stream = [System.IO.File]::OpenRead($zipPath)
        try {
            while ($true) {
                $filled = 0
                while ($filled -lt $buffer.Length) {
                    $read = $stream.Read($buffer, $filled, $buffer.Length - $filled)
                    if ($read -le 0) { break }
                    $filled += $read
                }
                if ($filled -le 0) { break }
                $text = [System.Convert]::ToBase64String($buffer, 0, $filled, [System.Base64FormattingOptions]::InsertLineBreaks)
                Write-WfLine -Stream $OutStream -Text $text.Replace("`r`n", "`n")
                if ($filled -lt $buffer.Length) { break }
            }
        } finally {
            $stream.Dispose()
        }
        Write-WfLine -Stream $OutStream -Text ('WF-BUNDLE-END v1 dir={0}' -f $Name)
    } finally {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    }
    return 0
}

function Get-WfChannelAccess {
    # Pull the channelAccess value (an SDDL string) out of "wevtutil gl <log>" output.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line -match '^\s*channelAccess:\s*(\S+)\s*$') { return $Matches[1] }
    }
    return $null
}

function Invoke-WfSecurityLogAccess {
    # The plan asks for a measurement, not an assumption, of what this account can see of the
    # Security log. Two read only queries, neither of which returns an event:
    #   wevtutil gl Security   the channel configuration, including channelAccess (the SDDL)
    #   wevtutil gli Security  status information (record count and so on); needs read access
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream
    )
    if ([string]::IsNullOrEmpty($Config.WevtutilExe) -or -not (Test-Path -LiteralPath $Config.WevtutilExe -PathType Leaf)) {
        $missing = [ordered]@{ ok = $false; verb = 'security-log-access'; error = 'wevtutil not found' }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $missing)
        return 70
    }
    $configRun = Invoke-WfNative -FilePath $Config.WevtutilExe -ArgumentList @('gl', 'Security') -TimeoutSeconds 30
    $infoRun = Invoke-WfNative -FilePath $Config.WevtutilExe -ArgumentList @('gli', 'Security') -TimeoutSeconds 30
    $channelAccess = Get-WfChannelAccess -Text $configRun.StdOut
    $readersAce = $null
    if ($null -ne $channelAccess) {
        # Event Log Readers is S-1-5-32-573; an allow entry whose rights include bit 0x1 is read.
        $readersAce = ($channelAccess -match '\(A;[^;]*;0x[0-9a-fA-F]*[13579bdfBDF];;;S-1-5-32-573\)')
    }
    $result = [ordered]@{
        ok                           = $true
        verb                         = 'security-log-access'
        account                      = [System.Environment]::UserName
        config_exit_code             = $configRun.ExitCode
        config_readable              = ($configRun.ExitCode -eq 0)
        channel_access               = $channelAccess
        event_log_readers_read_entry = $readersAce
        log_info_exit_code           = $infoRun.ExitCode
        log_readable                 = ($infoRun.ExitCode -eq 0)
        config_output                = [string[]]@($configRun.StdOut -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
        config_error                 = $configRun.StdErr.Trim()
        log_info_error               = $infoRun.StdErr.Trim()
    }
    Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $result)
    return 0
}

function Invoke-WfDispatch {
    # Returns the process exit code. Everything the client sees is written to the two streams.
    param(
        [AllowNull()][AllowEmptyString()][string]$Requested,
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][System.IO.Stream]$OutStream,
        [Parameter(Mandatory = $true)][System.IO.Stream]$ErrStream
    )
    $resolved = Resolve-WfVerb -Requested $Requested
    try {
        switch ($resolved.Verb) {
            'ping' { return (Invoke-WfPing -Config $Config -OutStream $OutStream) }
            'list-bundles' { return (Invoke-WfListBundles -Config $Config -OutStream $OutStream) }
            'security-log-access' { return (Invoke-WfSecurityLogAccess -Config $Config -OutStream $OutStream) }
            'collect' { return (Invoke-WfCollect -Config $Config -Name $resolved.Argument -OutStream $OutStream -ErrStream $ErrStream) }
            'fetch' { return (Invoke-WfFetch -Config $Config -Name $resolved.Argument -OutStream $OutStream -ErrStream $ErrStream) }
            default {
                # The client's string is deliberately not echoed back.
                $refusal = [ordered]@{
                    ok      = $false
                    error   = 'refused'
                    reason  = $resolved.Reason
                    allowed = [string[]]@('ping', 'list-bundles', 'collect-NAME', 'fetch-BUNDLE_DIR', 'security-log-access')
                }
                Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $refusal)
                Write-WfLine -Stream $ErrStream -Text ('wf-dispatch: refused: ' + $resolved.Reason)
                return 64
            }
        }
    } catch {
        $failure = [ordered]@{ ok = $false; error = 'internal error'; verb = $resolved.Verb; detail = $_.Exception.Message }
        Write-WfLine -Stream $OutStream -Text (ConvertTo-WfJsonLine -InputObject $failure)
        Write-WfLine -Stream $ErrStream -Text ('wf-dispatch: internal error: ' + $_.Exception.Message)
        return 70
    }
}

# Run only when executed (powershell.exe -File dispatch.ps1), not when the tests dot-source it.
if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 70
    try {
        $config = Get-WfDispatchConfig -RemoteDir $PSScriptRoot -DispatcherPath $PSCommandPath
        $stdout = [System.Console]::OpenStandardOutput()
        $stderr = [System.Console]::OpenStandardError()
        $results = @(Invoke-WfDispatch -Requested $env:SSH_ORIGINAL_COMMAND -Config $config -OutStream $stdout -ErrStream $stderr)
        $exitCode = [int]$results[$results.Count - 1]
        $stdout.Flush()
        $stderr.Flush()
    } catch {
        try { [System.Console]::Error.WriteLine('wf-dispatch: internal error') } catch { Write-Verbose "stderr unavailable: $_" }
        $exitCode = 70
    }
    exit $exitCode
}
