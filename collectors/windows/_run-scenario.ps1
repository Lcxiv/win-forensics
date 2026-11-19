# The local scenario runner. Runs a named scenario's collectors in a fixed,
# bounded order on this PC, each as its own Windows PowerShell process, and
# merges what they wrote into one bundle whose manifest is written last.
# It is started at the PC (by the owner, or by the agent session on the PC
# acting on the owner's direction), never through the SSH dispatcher: the
# leading underscore keeps it out of the dispatcher's verbs.
#
#   powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File _run-scenario.ps1 -OutputDirectory <new folder>
#
# What it runs, what it checks first, and what it refuses are in
# collectors/windows/README.md, "Scenario runner". It prints one JSON line on
# stdout ({"collector":"scenario-runner","status":...,"bundle":...,"artifacts":...})
# and exits 0 when the status is ok or partial, 1 otherwise.
[CmdletBinding()]
param(
    # A folder that does not hold a bundle yet. Never prompted for.
    [string]$OutputDirectory,
    # The scenario to run. s1 is the only one.
    [string]$Scenario = 's1',
    # The window of each live capture (dpcisr-trace and presentmon-frames),
    # in seconds (10 to 240).
    [int]$DurationSeconds = 60,
    # One process name for PresentMon to keep (empty keeps every presenting
    # process). One only: a script started with -File cannot take an array
    # (about_PowerShell_exe, the -File parameter).
    [string]$ProcessName = '',
    # The pinned PresentMon console binary. Empty means the collector's
    # default under the install root (C:\ProgramData\win-forensics\tools).
    [string]$PresentMonPath = '',
    # A pinned xperf.exe for the per CPU report; empty leaves that optional
    # source not_collected.
    [string]$XperfPath = '',
    # The artifact cap passed to every collector, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$runnerName = 'scenario-runner'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
$library = Join-Path -Path $PSScriptRoot -ChildPath '_scenarios.ps1'
$problems = New-Object 'System.Collections.Generic.List[string]'
if (-not $OutputDirectory) { $problems.Add('-OutputDirectory is required') }
if (-not (Test-Path -LiteralPath $common) -or -not (Test-Path -LiteralPath $library)) { $problems.Add('the shared helper or the runner library is missing beside this script') }
if ($DurationSeconds -lt 10 -or $DurationSeconds -gt 240) { $problems.Add('DurationSeconds must be between 10 and 240') }
if ($MaxArtifactBytes -lt 1048576 -or $MaxArtifactBytes -gt 1073741824) { $problems.Add('MaxArtifactBytes must be between 1 MiB and 1 GiB') }
if ($problems.Count -eq 0) {
    . $common
    . $library
    if ($ProcessName -and $ProcessName -notmatch (Get-WfPresentMonProcessNamePattern)) { $problems.Add('ProcessName does not match ' + (Get-WfPresentMonProcessNamePattern)) }
    if (@(Get-WfScenarioIds) -notcontains $Scenario) { $problems.Add('unknown scenario ' + $Scenario + '; known: ' + (@(Get-WfScenarioIds) -join ', ')) }
}
if ($problems.Count -gt 0) {
    foreach ($problem in $problems) { [Console]::Error.WriteLine($runnerName + ': ' + $problem) }
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $runnerName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}

$exitCode = @(Invoke-WfScenarioScript -ScenarioId $Scenario -OutputDirectory $OutputDirectory -DurationSeconds $DurationSeconds -ProcessName $ProcessName `
        -PresentMonPath $PresentMonPath -XperfPath $XperfPath -MaxArtifactBytes $MaxArtifactBytes -CollectorRoot $PSScriptRoot -RunnerPath $PSCommandPath)[-1]
exit $exitCode
