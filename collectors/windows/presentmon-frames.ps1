# presentmon-frames: What did the frame pipeline do, frame by frame, during a
# bounded window: present cadence, time in the Present call, CPU and GPU busy
# and wait time, display latency, with every frame stamped in the ETW
# performance counter domain?
#
# Live capture, passive. Runs under Windows PowerShell 5.1 as the standard
# collector account. Writes one bundle (docs/contracts/bundle.md) into
# -OutputDirectory, prints one JSON summary line on stdout, and exits 0 when
# the bundle is complete. See collectors/windows/README.md for the interface,
# the pinned binary, every option with its citation, the status rules, the
# anti-cheat position, and the facts still to be verified on a real machine.
#
# The one program this collector starts is the operator supplied PresentMon
# console application (GameTechDev/PresentMon, Intel), pinned by version and
# SHA-256 (below) and verified before it runs. Nothing is downloaded or
# installed: when the binary is missing or its hash differs, nothing runs and
# the source is not_collected with the reason.
#
# How PresentMon observes, in the vendor's words: the PresentData library
# "performs the lowest-level collection and analysis of ETW events"
# (https://github.com/GameTechDev/PresentMon/blob/v2.6.0/README.md), and the
# console application starts an ETW trace session, which fails with "failed
# to start trace session (access denied)" for a user outside the Performance
# Log Users group (same page, "User access denied"). The options used here
# capture by process name or every presenting process; --process_id is never
# used. The console application documents no overlay and no injection; the
# capture application's overlay is a different program that is not used.
# Whether the console application opens a handle to any observed process is
# not documented, and this collector does not claim that it does not.
#
# Every option passed is documented in
# https://github.com/GameTechDev/PresentMon/blob/v2.6.0/README-ConsoleApplication.md:
#   --session_name name          "Use the specified session name instead of the default"
#   --output_file path           "Write CSV output to the specified path."
#   --no_console_stats           "Do not display active swap chains and frame statistics in the console."
#   --qpc_time                   "Output the CPU start time as a performance counter value."
#                                (the column is then named CPUStartQPC; docs/contracts/timestamps.md)
#   --timed seconds              "Stop recording after the specified amount of time."
#   --terminate_after_timed      "When using --timed, terminate PresentMon after the timed capture completes."
#   --process_name name          "Only record processes with the specified exe name." (repeatable)
#   --terminate_existing_session "If a trace session with the same name is already running,
#                                stop the existing session then exit." (the cleanup call)
#
# The run is bounded twice: PresentMon stops itself after -DurationSeconds
# (--timed, --terminate_after_timed), and the process runner stops it at
# -DurationSeconds plus a grace period if it has not exited by then. After
# every started run, whatever its outcome, the cleanup call above is made
# with the same session name so a trace session left behind by a stopped
# process does not outlive the collector; the manifest records whether that
# call ran, because ETW sessions are kernel objects that outlive the process
# that started them unless stopped.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How long PresentMon records, in seconds (5 to 600). This is the value of
    # --timed; the hard maximum is enforced by the process runner at this
    # value plus the grace period.
    [int]$DurationSeconds = 60,
    # Process names to record (each becomes one --process_name). Empty means
    # every presenting process, which is the default because PresentMon
    # documents that without administrator privilege the processes of other
    # user accounts are listed as "<unknown>" and cannot be targeted by name.
    [string[]]$ProcessName = @(),
    # Where the pinned PresentMon console binary is. Empty means
    # <install root>\tools\PresentMon-2.6.0-x64.exe, two directories above
    # this script (C:\ProgramData\win-forensics\tools on the PC).
    [string]$PresentMonPath = '',
    # Cap on the size of the CSV PresentMon writes, in bytes (1 MiB to 1 GiB).
    # A CSV above it is not kept and the source is capture_failed.
    [long]$MaxArtifactBytes = 67108864
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'presentmon-frames'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $common)) {
    # Without the helper or an output directory there is no bundle to write;
    # the summary line is still printed so the dispatcher gets its one line.
    if (-not $OutputDirectory) { [Console]::Error.WriteLine($collectorName + ': -OutputDirectory is required') }
    else { [Console]::Error.WriteLine($collectorName + ': the shared helper is missing: ' + $common) }
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}
. $common

# --- the pin -----------------------------------------------------------------
# GitHub release v2.6.0 of GameTechDev/PresentMon, published 2026-09-21, asset
# PresentMon-2.6.0-x64.exe. The digest is the one GitHub records for the
# release asset (the release API's digest field, read 2026-11-18); the size is
# the asset size from the same record. Only these exact bytes are run.
function Get-WfPresentMonPinnedVersion { return '2.6.0' }
function Get-WfPresentMonPinnedFileName { return 'PresentMon-2.6.0-x64.exe' }
function Get-WfPresentMonPinnedSha256 { return 'b2a706bc6ad475749e3b7e3409263aa1e6906d45bdcf993f6dbc0f660188f1af' }
function Get-WfPresentMonPinnedLength { return [int64]980320 }
function Get-WfPresentMonReleaseUrl { return 'https://github.com/GameTechDev/PresentMon/releases/tag/v2.6.0' }
function Get-WfPresentMonAssetUrl { return 'https://github.com/GameTechDev/PresentMon/releases/download/v2.6.0/PresentMon-2.6.0-x64.exe' }
function Get-WfPresentMonDocumentationUrl { return 'https://github.com/GameTechDev/PresentMon/blob/v2.6.0/README-ConsoleApplication.md' }
function Get-WfPresentMonSessionName { return 'wf-presentmon-frames' }
# Seconds the process runner waits after the timed capture should have ended
# before it stops PresentMon; also the deadline of the cleanup call.
function Get-WfPresentMonGraceSeconds { return 30 }
# Cap on what PresentMon may print on its two console streams (the CSV goes
# to a file, so the console carries status text only).
function Get-WfPresentMonConsoleCapBytes { return [int64]1048576 }
function Get-WfPresentMonProcessNamePattern { return '^[A-Za-z0-9._-]{1,120}$' }

function Get-WfPresentMonDefaultPath {
    # <install root>\tools\<pinned file name>: the collectors live two levels
    # below the install root (remote\collectors on the PC; collectors\windows
    # in the repository, where tools\ is ignored by git).
    param([string]$ScriptRoot)
    $installRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)
    return [System.IO.Path]::Combine($installRoot, 'tools', (Get-WfPresentMonPinnedFileName))
}

function Get-WfPresentMonFlaggedLines {
    # Lines of PresentMon's console text that look like a warning or an error,
    # kept verbatim (capped) so the reader sees what the tool said. PresentMon
    # 2.6.0 documents no lost event or dropped event report for the console
    # application, so this is a net, not a parser: events_lost stays null.
    param([string]$Text, [int]$Limit = 20)
    $flagged = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($Text -split "`r?`n")) {
        if ($flagged.Count -ge $Limit) { break }
        if ($line -match '(?i)\b(warn|warning|error|fail|failed|lost|dropped|denied|unknown)\b') { $flagged.Add($line.TrimEnd()) }
    }
    # No comma: the caller wraps the result in @(), which turns no line into
    # an empty array and one line into an array of one.
    return $flagged.ToArray()
}

function Read-WfPresentMonCsvSummary {
    # Reads the CSV PresentMon wrote, line by line, and returns its header
    # columns, the number of frame rows, the frames per (Application,
    # ProcessID) pair (the first 50 pairs), and how many rows PresentMon
    # attributed to "<unknown>" (its documented name for a process it could
    # not resolve without administrator privilege). The file is not changed.
    param([string]$Path)
    $summary = [ordered]@{ header = @(); frames = 0; processes = @(); unknown_application_frames = 0; truncated_process_list = $false; error = $null }
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path, (New-Object System.Text.UTF8Encoding($false)), $true)
        $headerLine = $reader.ReadLine()
        if ($null -eq $headerLine) { return $summary }
        $header = @($headerLine.TrimEnd("`r") -split ',' | ForEach-Object { $_.Trim() })
        $summary.header = $header
        $applicationIndex = [array]::IndexOf($header, 'Application')
        $processIndex = [array]::IndexOf($header, 'ProcessID')
        $counts = [ordered]@{}
        $frames = 0
        $unknown = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Trim().Length -eq 0) { continue }
            $frames += 1
            if ($applicationIndex -lt 0 -or $processIndex -lt 0) { continue }
            $cells = $line -split ','
            $application = ''
            $process = ''
            if ($cells.Count -gt $applicationIndex) { $application = $cells[$applicationIndex].Trim() }
            if ($cells.Count -gt $processIndex) { $process = $cells[$processIndex].Trim() }
            if ($application -eq '<unknown>') { $unknown += 1 }
            $key = $application + "`t" + $process
            if ($counts.Contains($key)) { $counts[$key] = [int]$counts[$key] + 1 }
            elseif ($counts.Count -lt 50) { $counts[$key] = 1 }
            else { $summary.truncated_process_list = $true }
        }
        $summary.frames = $frames
        $summary.unknown_application_frames = $unknown
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($key in $counts.Keys) {
            $parts = $key -split "`t"
            $processId = $null
            $parsed = 0
            if ([int]::TryParse($parts[1], [ref]$parsed)) { $processId = $parsed }
            $list.Add([ordered]@{ application = $parts[0]; process_id = $processId; frames = [int]$counts[$key] })
        }
        $summary.processes = @($list.ToArray())
    } catch {
        $summary.error = $_.Exception.Message
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    return $summary
}

function Invoke-WfPresentMonFramesSource {
    # The custom source the definition below names. Verifies the pinned binary,
    # runs it once for the bounded window, makes the cleanup call, and writes
    # under raw/presentmon_frames/:
    #   command.json  the binary with its pin, the exact argument list, the
    #                 limits and the option citations (role config, hashed as config_hash)
    #   frames.csv    the CSV PresentMon wrote, untouched (role primary)
    #   console.txt   what PresentMon printed on stdout and stderr, verbatim (role log)
    #   result.json   the verification, the run, the CSV summary, the console
    #                 lines that look like warnings, the cleanup call (role report)
    param(
        [hashtable]$Source,
        [string]$BundleRoot,
        [int64]$MaxArtifactBytes,
        [int]$TimeoutSeconds,
        [System.Collections.Generic.List[string]]$Log,
        [System.Collections.Generic.List[string]]$Notes,
        [hashtable]$Context
    )
    # The context carries the pseudonym salt the network sources share; frame
    # rows carry process names and addresses of swap chains, nothing it protects.
    if ($null -eq $Context) { $Context = @{} }
    $id = [string]$Source['Id']
    $exe = [string]$Source['BinaryPath']
    $duration = [int]$Source['DurationSeconds']
    $grace = [int]$Source['GraceSeconds']
    # Assigned directly, not wrapped in @(): the helper's list function
    # returns its array as one object, which @() would nest.
    $names = Get-WfList -Value $Source['ProcessNames']
    $sessionName = Get-WfPresentMonSessionName
    $consoleCap = Get-WfPresentMonConsoleCapBytes
    $entry = New-WfCollectorEntry -Id $id -Kind 'presentmon' -Required $true
    $roles = @{ 'command.json' = 'config'; 'frames.csv' = 'primary'; 'console.txt' = 'log'; 'result.json' = 'report' }
    $relativeDir = 'raw/' + $id
    $dir = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $relativeDir
    $outputPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/frames.csv')
    $consolePath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/console.txt')
    $started = Get-WfUtcNow
    $entry.started_utc = ConvertTo-WfUtcString -Value $started
    $tools = @()
    $frames = 0
    try {
        $null = New-Item -ItemType Directory -Force -Path $dir

        # The exact command line, as a list (manifest command) and as the
        # argument string the process runner passes. Only the output path
        # needs quoting; process names are restricted to a pattern without
        # spaces or quotes before this function is called.
        # The manifest records the output file by its bundle relative path; the
        # process receives the absolute path of the same file, quoted. Nothing
        # else differs between the recorded and the passed argument list.
        $relativeCsv = $relativeDir + '/frames.csv'
        $arguments = New-Object 'System.Collections.Generic.List[string]'
        $arguments.Add('--session_name'); $arguments.Add($sessionName)
        $arguments.Add('--output_file'); $arguments.Add($relativeCsv)
        $arguments.Add('--no_console_stats')
        $arguments.Add('--qpc_time')
        $arguments.Add('--timed'); $arguments.Add([string]$duration)
        $arguments.Add('--terminate_after_timed')
        foreach ($name in $names) { $arguments.Add('--process_name'); $arguments.Add([string]$name) }
        $argumentText = (@($arguments.ToArray() | ForEach-Object { if ($_ -eq $relativeCsv) { '"' + $outputPath + '"' } else { $_ } }) -join ' ')
        $cleanupArguments = @('--session_name', $sessionName, '--terminate_existing_session')
        $cleanupText = ($cleanupArguments -join ' ')

        $account = Get-WfAccountInfo
        $binary = Get-WfBinaryInfo -Path $exe
        $pinMatched = ($binary['exists'] -and [string]$binary['sha256'] -eq (Get-WfPresentMonPinnedSha256))
        $sizeMatched = ($binary['exists'] -and [int64]$binary['length'] -eq (Get-WfPresentMonPinnedLength))
        $config = [ordered]@{
            tool                   = $exe
            pinned                 = [ordered]@{
                version           = Get-WfPresentMonPinnedVersion
                file_name         = Get-WfPresentMonPinnedFileName
                sha256            = Get-WfPresentMonPinnedSha256
                length            = Get-WfPresentMonPinnedLength
                release_url       = Get-WfPresentMonReleaseUrl
                asset_url         = Get-WfPresentMonAssetUrl
                documentation_url = Get-WfPresentMonDocumentationUrl
                digest_source     = 'the digest GitHub records for the release asset (release API digest field), read 2026-11-18'
            }
            arguments              = @($arguments.ToArray())
            output_file_recorded_as = 'the bundle relative path of frames.csv; the process received the absolute path of that file in this bundle, in double quotes'
            cleanup_arguments      = @($cleanupArguments)
            session_name           = $sessionName
            duration_seconds       = $duration
            grace_seconds          = $grace
            hard_maximum_seconds   = $duration + $grace
            helper_deadline_seconds = $TimeoutSeconds
            process_names          = @($names)
            observes               = 'ETW trace session consumed by PresentMon (vendor README: the PresentData library performs the lowest-level collection and analysis of ETW events); capture by process name or for every process, never by process id; no overlay, no injection'
            max_artifact_bytes     = $MaxArtifactBytes
            console_cap_bytes      = $consoleCap
            option_citations       = [ordered]@{
                '--session_name'               = 'Use the specified session name instead of the default "PresentMon".'
                '--output_file'                = 'Write CSV output to the specified path.'
                '--no_console_stats'           = 'Do not display active swap chains and frame statistics in the console.'
                '--qpc_time'                   = 'Output the CPU start time as a performance counter value.'
                '--timed'                      = 'Stop recording after the specified amount of time.'
                '--terminate_after_timed'      = 'When using --timed, terminate PresentMon after the timed capture completes.'
                '--process_name'               = 'Only record processes with the specified exe name. This argument can be repeated to capture multiple processes.'
                '--terminate_existing_session' = 'If a trace session with the same name is already running, stop the existing session then exit.'
            }
            account                = [ordered]@{ elevated = $account['elevated']; performance_log_users = $account['performance_log_users'] }
        }
        $configPath = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/command.json')
        Write-WfJsonFile -Path $configPath -Object $config
        $entry.config_hash = [ordered]@{ algorithm = 'sha256'; value = (Get-WfSha256OfFile -Path $configPath) }
        $entry.command = @($exe) + @($arguments.ToArray())
        $entry.requested = [ordered]@{ providers = @(); keywords = @(); stack_walk = @(); counters = @(); options = $config }
        if ($names.Count -gt 0) {
            $entry.target_process = [ordered]@{ name = [string]$names[0]; pid = $null; alive_at_start = $null; alive_at_stop = $null }
        }

        $checks = @(
            [ordered]@{ name = 'binary_present'; ok = [bool]$binary['exists']; detail = $exe },
            [ordered]@{ name = 'binary_sha256_pinned'; ok = $pinMatched; detail = $(if ($binary['exists']) { 'sha256 ' + [string]$binary['sha256'] + ', pinned ' + (Get-WfPresentMonPinnedSha256) } else { 'no file' }) },
            [ordered]@{ name = 'binary_length_pinned'; ok = $sizeMatched; detail = $(if ($binary['exists']) { [string]$binary['length'] + ' bytes, pinned ' + [string](Get-WfPresentMonPinnedLength) } else { 'no file' }) }
        )
        $preflightOk = ($binary['exists'] -and $pinMatched -and $sizeMatched)
        $entry.preflight = [ordered]@{ ok = $preflightOk; at_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow); checks = $checks }
        $toolVersion = $null
        if ($pinMatched) { $toolVersion = Get-WfPresentMonPinnedVersion } elseif ($binary['exists']) { $toolVersion = $binary['product_version'] }
        $tools = @([ordered]@{ name = 'presentmon'; version = $toolVersion; path = $exe; sha256 = $binary['sha256'] })

        if (-not $account['elevated'] -and -not $account['performance_log_users']) {
            $message = 'source ' + $id + ': the account is neither elevated nor a member of Performance Log Users (S-1-5-32-559); PresentMon documents that it then fails with "failed to start trace session (access denied)"'
            $Notes.Add($message); $Log.Add($message)
        }
        if ($names.Count -gt 0 -and -not $account['elevated']) {
            $message = 'source ' + $id + ': process names were requested without administrator privilege; PresentMon documents that processes of other user accounts are then listed as "<unknown>" and cannot be targeted by name, so a game running under another account yields zero frames here'
            $Notes.Add($message); $Log.Add($message)
        }

        $readErrorKind = ''
        $readErrorMessage = ''
        $run = $null
        $cleanup = [ordered]@{ attempted = $false; started = $false; exit_code = $null; timed_out = $false; duration_ms = $null; output = $null }
        if (-not $binary['exists']) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the PresentMon console binary is not at {0}. Download {1} from {2}, check that its SHA-256 is {3}, and place it there (or pass -PresentMonPath); the collector never downloads it' -f $exe, (Get-WfPresentMonPinnedFileName), (Get-WfPresentMonReleaseUrl), (Get-WfPresentMonPinnedSha256))
        } elseif (-not $preflightOk) {
            $readErrorKind = 'preflight'
            $readErrorMessage = ('the file at {0} has SHA-256 {1} ({2} bytes); the pinned PresentMon {3} console binary has {4} ({5} bytes), so nothing was run' -f $exe, [string]$binary['sha256'], [string]$binary['length'], (Get-WfPresentMonPinnedVersion), (Get-WfPresentMonPinnedSha256), [string](Get-WfPresentMonPinnedLength))
        } else {
            $Log.Add('source ' + $id + ': starting ' + $exe + ' ' + (@($arguments.ToArray()) -join ' '))
            $run = Invoke-WfProcess -FilePath $exe -Arguments $argumentText -TimeoutSeconds ($duration + $grace) -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes $consoleCap
            if ($run['Started']) {
                # The cleanup call, after every started run: a session left by
                # a stopped process is stopped here; a session PresentMon
                # already closed is left as it is (what the call then prints
                # is on the verification list, so its result is recorded, not judged).
                $cleanup.attempted = $true
                $Log.Add('source ' + $id + ': cleanup ' + $exe + ' ' + $cleanupText)
                $cleanupRun = Invoke-WfProcess -FilePath $exe -Arguments $cleanupText -TimeoutSeconds $grace -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes $consoleCap
                $cleanup.started = [bool]$cleanupRun['Started']
                $cleanup.exit_code = $cleanupRun['ExitCode']
                $cleanup.timed_out = [bool]$cleanupRun['TimedOut']
                $cleanup.duration_ms = $cleanupRun['DurationMs']
                $cleanupOutput = (([string]$cleanupRun['StdOut'] + "`n" + [string]$cleanupRun['StdErr'] + "`n" + [string]$cleanupRun['Diagnostic']).Trim())
                if ($cleanupOutput.Length -gt 2000) { $cleanupOutput = $cleanupOutput.Substring(0, 2000) }
                if ($cleanupOutput.Length -gt 0) { $cleanup.output = $cleanupOutput }
                if ($cleanupRun['Error']) { $cleanup.output = ([string]$cleanupRun['Error'] + ' ' + [string]$cleanup.output).Trim() }
            }
        }
        $cleanupRan = ($cleanup.started -and -not $cleanup.timed_out)
        $sessionWarning = ''
        if ($null -ne $run -and $run['Started'] -and -not $cleanupRan) {
            $sessionWarning = ('; the cleanup call ({0}) did not run to completion, so the trace session {1} may still be running: stop it by running that call by hand' -f $cleanupText, $sessionName)
            $message = 'source ' + $id + ': could not confirm that the trace session ' + $sessionName + ' was stopped' + $sessionWarning
            $Notes.Add($message); $Log.Add($message)
        }

        $consoleText = ''
        $csv = [ordered]@{ header = @(); frames = 0; processes = @(); unknown_application_frames = 0; truncated_process_list = $false; error = $null }
        $csvBytes = [int64]0
        $qpcColumn = $false
        if ($null -ne $run) {
            $consoleText = ('stdout:' + "`n" + [string]$run['StdOut'] + "`n" + 'stderr:' + "`n" + [string]$run['StdErr'] + "`n")
            if ($run['Diagnostic']) { $consoleText = $consoleText + 'diagnostic head (the run was stopped):' + "`n" + [string]$run['Diagnostic'] + "`n" }
            if ($run['Started']) { Write-WfTextFile -Path $consolePath -Text $consoleText }
            if (-not $run['Started']) {
                $readErrorKind = 'other'
                $readErrorMessage = 'the PresentMon process could not be started: ' + [string]$run['Error']
            } elseif ($run['TimedOut']) {
                $readErrorKind = 'timeout'
                $readErrorMessage = ('PresentMon did not exit within {0} seconds (the requested {1} second capture plus a {2} second grace period) and was stopped{3}' -f ($duration + $grace), $duration, $grace, $sessionWarning)
            } elseif ($run['Oversized']) {
                $readErrorKind = 'other'
                $readErrorMessage = [string]$run['Error'] + $sessionWarning
            } elseif ([int]$run['ExitCode'] -ne 0) {
                $said = (([string]$run['StdOut'] + ' ' + [string]$run['StdErr']).Trim() -replace '\s+', ' ')
                if ($said.Length -gt 500) { $said = $said.Substring(0, 500) }
                if ($said -match '(?i)access denied') {
                    $readErrorKind = 'access_denied'
                    $readErrorMessage = ('PresentMon could not start its trace session (exit code {0}): {1}. PresentMon documents that the user must be a member of Performance Log Users or run elevated' -f [int]$run['ExitCode'], $said)
                } else {
                    $readErrorKind = 'other'
                    $readErrorMessage = ('PresentMon exited with code {0}: {1}{2}' -f [int]$run['ExitCode'], $said, $sessionWarning)
                }
            } elseif (-not (Test-Path -LiteralPath $outputPath)) {
                $readErrorKind = 'other'
                $readErrorMessage = 'PresentMon exited with code 0 but wrote no CSV at ' + $outputPath + $sessionWarning
            } else {
                $csvBytes = [int64](Get-Item -LiteralPath $outputPath).Length
                if ($csvBytes -eq 0) {
                    $readErrorKind = 'other'
                    $readErrorMessage = 'PresentMon exited with code 0 and left a CSV of zero bytes, which has no header to prove the options in effect' + $sessionWarning
                } elseif ($csvBytes -gt $MaxArtifactBytes) {
                    $readErrorKind = 'other'
                    $readErrorMessage = ('the CSV is {0} bytes, above the cap of {1}, and was not kept{2}' -f $csvBytes, $MaxArtifactBytes, $sessionWarning)
                } else {
                    $csv = Read-WfPresentMonCsvSummary -Path $outputPath
                    $qpcColumn = (@($csv['header']) -contains 'CPUStartQPC')
                    if ($csv['error']) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'the CSV could not be read: ' + [string]$csv['error']
                    } elseif (@($csv['header']).Count -eq 0 -or -not (@($csv['header']) -contains 'Application') -or -not (@($csv['header']) -contains 'ProcessID')) {
                        $readErrorKind = 'other'
                        $readErrorMessage = 'the CSV header is not the documented PresentMon header (no Application and ProcessID columns): ' + (@($csv['header']) -join ',')
                    } elseif (-not $qpcColumn) {
                        $readErrorKind = 'other'
                        $readErrorMessage = '--qpc_time was requested but the CSV header has no CPUStartQPC column, so the requested setting was not in effect: ' + (@($csv['header']) -join ',')
                    } else {
                        $frames = [int]$csv['frames']
                    }
                }
            }
        }
        $stopped = Get-WfUtcNow
        $flagged = @()
        if ($consoleText.Length -gt 0) { $flagged = @(Get-WfPresentMonFlaggedLines -Text $consoleText) }

        $report = [ordered]@{
            binary      = [ordered]@{
                path            = $exe
                exists          = $binary['exists']
                length          = $binary['length']
                sha256          = $binary['sha256']
                file_version    = $binary['file_version']
                product_version = $binary['product_version']
                error           = $binary['error']
                pin_matched     = $pinMatched
                length_matched  = $sizeMatched
            }
            run         = [ordered]@{
                started_utc  = ConvertTo-WfUtcString -Value $started
                stopped_utc  = ConvertTo-WfUtcString -Value $stopped
                started      = $(if ($null -ne $run) { [bool]$run['Started'] } else { $false })
                exit_code    = $(if ($null -ne $run) { $run['ExitCode'] } else { $null })
                timed_out    = $(if ($null -ne $run) { [bool]$run['TimedOut'] } else { $false })
                oversized    = $(if ($null -ne $run) { [bool]$run['Oversized'] } else { $false })
                duration_ms  = $(if ($null -ne $run) { $run['DurationMs'] } else { $null })
                stdout_bytes = $(if ($null -ne $run) { $run['StdOutBytes'] } else { $null })
                stderr_bytes = $(if ($null -ne $run) { $run['StdErrBytes'] } else { $null })
                error        = $(if ($null -ne $run) { $run['Error'] } else { $null })
            }
            csv         = [ordered]@{
                path                       = $relativeDir + '/frames.csv'
                bytes                      = $csvBytes
                header                     = @($csv['header'])
                qpc_time_column            = $qpcColumn
                frames                     = [int]$csv['frames']
                processes                  = @($csv['processes'])
                truncated_process_list     = [bool]$csv['truncated_process_list']
                unknown_application_frames = [int]$csv['unknown_application_frames']
            }
            console_flagged_lines = @($flagged)
            events_lost = $null
            events_lost_note = 'PresentMon 2.6.0 documents no lost event count for the console application; the console text is kept verbatim in console.txt and the lines above are the ones that look like warnings'
            cleanup     = $cleanup
            account     = $config.account
        }
        Write-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ($relativeDir + '/result.json')) -Object $report

        if ($readErrorKind -eq 'preflight') {
            # Nothing ran (docs/contracts/measurement-status.md: not started is not_collected).
            $entry.status = 'not_collected'
            $entry.status_reason = 'preflight failed: ' + $readErrorMessage
            $met = $false
        } elseif ($readErrorKind -eq 'access_denied') {
            # PresentMon started but its trace session did not: no capture began.
            $entry.status = 'not_collected'
            $entry.status_reason = 'preflight failed, the trace session could not be started: ' + $readErrorMessage
            $met = $false
        } elseif ($readErrorKind) {
            $entry.status = 'capture_failed'
            $entry.status_reason = $readErrorMessage
            $met = $false
        } elseif ($frames -gt 0) {
            $entry.status = 'observed'
            $entry.status_reason = $null
            $met = $true
        } elseif ($names.Count -eq 0) {
            # Every presenting process was eligible, PresentMon ran to the end
            # of its timed window and wrote the documented header: nothing
            # presented. That is the quiet window the status contract allows.
            $entry.status = 'observed_zero'
            $entry.status_reason = $null
            $met = $true
        } else {
            # Scoped to named processes and none of them presented a frame.
            # The status contract names a target process that was not alive
            # across the window as capture_failed, and this collector cannot
            # tell that case from a name PresentMon could not resolve.
            $entry.status = 'capture_failed'
            $entry.status_reason = ('zero frames for the requested process names ({0}) in a {1} second capture that otherwise completed: the process was not alive across the window or did not present, or, without administrator privilege, PresentMon listed it as "<unknown>" and could not match the name (vendor README, "User access denied")' -f ($names -join ', '), $duration)
            $met = $false
            $Notes.Add('source ' + $id + ': ' + $entry.status_reason)
        }
        Remove-WfPrimaryUnlessKept -Path $outputPath -Status $entry.status -Truncated $false -RecordCount $frames -Log $Log -SourceId $id
        if (Test-WfObservedStatus -Status $entry.status) { $entry.raw_time_range = New-WfTimeRange -StartUtc $started -EndUtc $stopped }
        $entry.enabled = [ordered]@{
            providers = @(); keywords = @(); stack_walk = @(); counters = @()
            options   = [ordered]@{
                exit_code                  = $report.run.exit_code
                timed_out                  = $report.run.timed_out
                duration_ms                = $report.run.duration_ms
                csv_bytes                  = $csvBytes
                csv_header                 = @($csv['header'])
                qpc_time_column            = $qpcColumn
                records                    = $frames
                processes                  = @($csv['processes'])
                unknown_application_frames = [int]$csv['unknown_application_frames']
                console_flagged_lines      = @($flagged)
                cleanup_ran                = $cleanupRan
                cleanup_exit_code          = $cleanup.exit_code
                elevated                   = $account['elevated']
                performance_log_users      = $account['performance_log_users']
            }
            verified_by = 'the CSV header PresentMon wrote (a CPUStartQPC column proves --qpc_time was in effect), its exit code, and its console text in console.txt; the cleanup call is recorded in result.json'
        }
        $entry.events_lost = $null
        $entry.expectation = [ordered]@{
            declared = [string]$Source['Expectation']
            met      = $met
            detail   = ('exit code {0}; {1} frames from {2} processes; CPUStartQPC column {3}; cleanup ran {4}' -f $report.run.exit_code, $frames, @($csv['processes']).Count, $qpcColumn, $cleanupRan)
        }
    } catch {
        $entry.status = 'capture_failed'
        $entry.status_reason = 'the collector raised while running this source: ' + $_.Exception.Message
        $Log.Add('source ' + $id + ' raised: ' + $_.Exception.Message)
        if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    }
    $entry.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $entry.artifacts = Get-WfArtifactRecords -BundleRoot $BundleRoot -SourceId $id -Roles $roles
    $Log.Add(('source {0}: status {1}, {2} artifacts' -f $id, $entry.status, @($entry.artifacts).Count))
    return [ordered]@{ Entry = $entry; Rows = @(); Tools = $tools }
}

# --- parameter checks, before anything is written -----------------------------
$problems = New-Object 'System.Collections.Generic.List[string]'
if ($DurationSeconds -lt 5 -or $DurationSeconds -gt 600) { $problems.Add('DurationSeconds must be between 5 and 600') }
$names = @($ProcessName | ForEach-Object { [string]$_ } | Where-Object { $_.Length -gt 0 })
if ($names.Count -gt 8) { $problems.Add('at most 8 process names can be given') }
foreach ($name in $names) {
    if ($name -notmatch (Get-WfPresentMonProcessNamePattern)) { $problems.Add('process name does not match ' + (Get-WfPresentMonProcessNamePattern) + ': ' + $name) }
}
$binaryPath = $PresentMonPath
if (-not $binaryPath) { $binaryPath = Get-WfPresentMonDefaultPath -ScriptRoot $PSScriptRoot }
if ($problems.Count -gt 0) {
    foreach ($problem in $problems) { Write-WfStderrLine -Text ($collectorName + ': ' + $problem) }
    Write-WfStdoutLine -Text (ConvertTo-WfSummaryLine -Collector $collectorName -Status 'failed' -Bundle $OutputDirectory -Artifacts 0)
    exit 1
}

$grace = Get-WfPresentMonGraceSeconds
$targetProcess = $null
if ($names.Count -gt 0) { $targetProcess = [string]$names[0] }
$definition = @{
    Name                     = $collectorName
    Version                  = '1.0.0'
    Question                 = 'What did the frame pipeline do, frame by frame, during a bounded window: present cadence, time in Present, CPU and GPU busy and wait, display latency, every frame stamped in the ETW performance counter domain?'
    RequestedDurationSeconds = $DurationSeconds
    TargetProcess            = $targetProcess
    CalibrationMethod        = 'none in this collector: frame timestamps are performance counter values (PresentMon --qpc_time, CPUStartQPC), the etw_qpc master domain of docs/contracts/timestamps.md; the calibration pairs that relate them to system time come from the clock collector of a later runner'
    Sources                  = @(
        @{
            Id              = 'presentmon_frames'
            Type            = 'custom'
            Invoke          = 'Invoke-WfPresentMonFramesSource'
            Required        = $true
            BinaryPath      = $binaryPath
            DurationSeconds = $DurationSeconds
            GraceSeconds    = $grace
            ProcessNames    = @($names)
            Expectation     = 'the pinned PresentMon binary exits with code 0 after its timed run, the CSV header carries CPUStartQPC (the --qpc_time option in effect), and at least one frame row was written; with no process filter, zero rows after a completed run is a quiet window (observed_zero); with a process filter, zero rows is capture_failed'
        }
    )
}

# The helper's per source deadline covers the timed run, its grace period and
# the cleanup call; the source applies the two deadlines itself.
$timeout = $DurationSeconds + $grace + $grace
$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $timeout -CollectorPath $PSCommandPath)[-1]
exit $exitCode
