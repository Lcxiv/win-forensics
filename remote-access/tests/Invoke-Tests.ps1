# Run the Pester suite and the PSScriptAnalyzer check for remote-access/windows.
#   pwsh -NoProfile -File remote-access/tests/Invoke-Tests.ps1 [-ModulePath <dir holding Pester and PSScriptAnalyzer>]
# Exit code 0 when every test passes and the analyzer reports nothing. tests/test_remote_access.py
# calls this when a PowerShell 7 is available and skips otherwise.
[CmdletBinding()]
param([string]$ModulePath = '')

$ErrorActionPreference = 'Stop'
if ($ModulePath -ne '') {
    $env:PSModulePath = (Resolve-Path -LiteralPath $ModulePath).Path + [System.IO.Path]::PathSeparator + $env:PSModulePath
}
Import-Module Pester -MinimumVersion 5.5.0
Import-Module PSScriptAnalyzer

$windowsDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows'
$findings = @(Invoke-ScriptAnalyzer -Path $windowsDir -Recurse -Settings (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'))
foreach ($finding in $findings) {
    Write-Output ('ANALYZER {0}:{1} [{2}] {3}: {4}' -f $finding.ScriptName, $finding.Line, $finding.Severity, $finding.RuleName, $finding.Message)
}
Write-Output "ANALYZER findings: $($findings.Count)"

$configuration = New-PesterConfiguration
$configuration.Run.Path = $PSScriptRoot
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Normal'
$result = Invoke-Pester -Configuration $configuration
Write-Output "PESTER passed: $($result.PassedCount) failed: $($result.FailedCount) skipped: $($result.SkippedCount)"

if ($findings.Count -gt 0 -or $result.FailedCount -gt 0 -or $result.PassedCount -eq 0) { exit 1 }
exit 0
