# Runs the checks that need PowerShell: PSScriptAnalyzer over the collectors
# (including the Windows PowerShell 5.1 compatibility rules) and the Pester
# suite.
#
#   pwsh -NoProfile -File collectors/windows/tests/Invoke-Checks.ps1 [-ModulePath <dir>]
#
# -ModulePath is a directory that holds Pester 5 and PSScriptAnalyzer when
# they are not installed for the user, for example one filled with
# Save-Module. Exit codes: 0 all checks passed, 1 a check failed, 3 a module
# is missing (tests/test_collectors_pwsh.py turns that into a skip).
[CmdletBinding()]
param(
    [string]$ModulePath = ''
)

$ErrorActionPreference = 'Stop'
if ($ModulePath) { $env:PSModulePath = $ModulePath + [System.IO.Path]::PathSeparator + $env:PSModulePath }

$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.3.0' } | Sort-Object -Property Version -Descending | Select-Object -First 1
$analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object -Property Version -Descending | Select-Object -First 1
if (-not $pester -or -not $analyzer) {
    [Console]::Error.WriteLine('Pester 5.3 or later and PSScriptAnalyzer are required; pass -ModulePath or install them with Install-Module.')
    exit 3
}
Import-Module $pester.Path
Import-Module $analyzer.Path

$collectorRoot = Split-Path -Parent $PSScriptRoot
$settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
$failed = $false

# The shipped scripts must be clean under every rule in the settings file.
# The test files only have to parse as Windows PowerShell 5.1; they use
# Pester 5 commands, which the 5.1 command profile does not know.
$findings = @()
foreach ($file in @(Get-ChildItem -LiteralPath $collectorRoot -Filter '*.ps1' -File)) {
    $findings += @(Invoke-ScriptAnalyzer -Path $file.FullName -Settings $settings)
}
$compatibility = @('PSUseCompatibleSyntax')
foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)) {
    $findings += @(Invoke-ScriptAnalyzer -Path $file.FullName -Settings $settings | Where-Object { $compatibility -contains $_.RuleName -or $_.Severity -eq 'Error' -or $_.Severity -eq 'ParseError' })
}
if ($findings.Count -gt 0) {
    $failed = $true
    foreach ($finding in $findings) {
        [Console]::Error.WriteLine(('{0}:{1}: {2}: {3}' -f $finding.ScriptName, $finding.Line, $finding.RuleName, $finding.Message))
    }
}
[Console]::Error.WriteLine(('PSScriptAnalyzer: {0} findings' -f $findings.Count))

$configuration = New-PesterConfiguration
$configuration.Run.Path = $PSScriptRoot
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Normal'
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.FailedBlocksCount -gt 0 -or $result.FailedContainersCount -gt 0 -or $result.PassedCount -eq 0) { $failed = $true }

if ($failed) { exit 1 }
exit 0
