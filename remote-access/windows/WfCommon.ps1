# WfCommon.ps1: helpers shared by Install-FrontDoor.ps1 and dispatch.ps1.
#
# Dot-sourced by both scripts, so it defines functions only: no statements with side effects and
# no variables. It must stay valid Windows PowerShell 5.1 (the forced command runs under
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe) and must also load under PowerShell 7
# on a non-Windows machine, because that is where tests/remote-access runs it.

function Get-WfCollectorNamePattern {
    # The seam with collectors/windows/<name>.ps1. \A and \z rather than ^ and $ so that a trailing
    # newline can never be part of a match. Always use with -cmatch: names are lower case only.
    '\A[a-z][a-z0-9-]{1,40}\z'
}

function Get-WfBundleDirPattern {
    # The name of one collector run's directory in the outbox:
    # <yyyymmddThhmmssZ>_<collector name>_<8 hex of the host id>. It is shaped like the bundle
    # directory name in docs/contracts/bundle.md section 1, but it is only the dispatcher's
    # handle for listing and fetching. The bundle_id inside the collector's manifest.json is
    # the authoritative id and may differ from it.
    '\A[0-9]{8}T[0-9]{6}Z_[a-z][a-z0-9-]{1,40}_[0-9a-f]{8}\z'
}

function Test-WfCollectorName {
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -cmatch (Get-WfCollectorNamePattern))
}

function Test-WfBundleDirName {
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -cmatch (Get-WfBundleDirPattern))
}

function ConvertTo-WfNativeArgument {
    # Quote one argument the way the Microsoft C runtime splits a command line, so that a path
    # with a space or an empty string survives as exactly one argument.
    # https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
    param([AllowEmptyString()][string]$Argument)
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $backslashes = 0
    foreach ($ch in $Argument.ToCharArray()) {
        if ($ch -eq [char]'\') {
            $backslashes++
            continue
        }
        if ($ch -eq [char]'"') {
            [void]$sb.Append([char]'\', ($backslashes * 2 + 1))
            [void]$sb.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$sb.Append([char]'\', $backslashes)
            $backslashes = 0
        }
        [void]$sb.Append($ch)
    }
    if ($backslashes -gt 0) { [void]$sb.Append([char]'\', ($backslashes * 2)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Invoke-WfNative {
    # Run one executable with a fixed argument list and return its exit code and output as data.
    # No shell is involved and nothing is evaluated, so an argument can never become code. This
    # also avoids the Windows PowerShell 5.1 behaviour where redirecting a native command's
    # stderr under $ErrorActionPreference = 'Stop' raises a terminating NativeCommandError.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 120
    )
    $quoted = @($ArgumentList | ForEach-Object { ConvertTo-WfNativeArgument -Argument $_ })
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    # Nothing here ever feeds a child process: close stdin so a child that reads it sees end of
    # file instead of waiting.
    $process.StandardInput.Close()
    # Read both streams asynchronously so that a child filling one pipe cannot deadlock the other.
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        Stop-WfProcessTree -Process $process
        [void]$process.WaitForExit(5000)
    } else {
        # The parameterless overload also waits for the redirected streams to drain.
        $process.WaitForExit()
    }
    $stdout = ''
    $stderr = ''
    if ($stdoutTask.Wait(5000)) { $stdout = $stdoutTask.Result }
    if ($stderrTask.Wait(5000)) { $stderr = $stderrTask.Result }
    $exitCode = -1
    if ($process.HasExited) { $exitCode = $process.ExitCode }
    $process.Dispose()
    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut   = $stdout
        StdErr   = $stderr
        TimedOut = $timedOut
    }
}

function Stop-WfProcessTree {
    # End a process that ran past its limit together with every process it started. On Windows
    # PowerShell 5.1 (.NET Framework) Process.Kill() ends only the one process, so a capture tool
    # a collector started would keep running and keep the output pipe open. taskkill /T "ends the
    # specified process and any child processes started by it", /F forcefully:
    # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
        $taskkill = Join-Path ([System.Environment]::SystemDirectory) 'taskkill.exe'
        try {
            [void](Invoke-WfNative -FilePath $taskkill -ArgumentList @('/T', '/F', '/PID', [string]$Process.Id) -TimeoutSeconds 30)
        } catch {
            Write-Verbose "taskkill after timeout: $_"
        }
    }
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
    } catch {
        Write-Verbose "kill after timeout: $_"
    }
}

function Get-WfFileSha256 {
    # Lower case hex SHA-256 of a file, streamed.
    param([Parameter(Mandatory = $true)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hash = $sha.ComputeHash($stream)
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
}

function Get-WfStringSha256 {
    # Lower case hex SHA-256 of the UTF-8 bytes of a string.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    } finally {
        $sha.Dispose()
    }
    return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
}

function Write-WfTextFile {
    # Write text as UTF-8 without a byte order mark. Set-Content -Encoding UTF8 in Windows
    # PowerShell 5.1 writes a byte order mark, and sshd would read those three bytes as part of
    # the first keyword of sshd_config or of the first key line of authorized_keys.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}
