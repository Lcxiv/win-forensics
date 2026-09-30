# Regenerates the synthetic collector bundles under fixtures/collector-bundles.
#
#   pwsh -NoProfile -File collectors/windows/tests/New-FixtureBundles.ps1
#
# Run it from the repository root (the output path is relative to the current
# directory, and that relative path is what each summary line records). It
# runs the real collector scripts against the synthetic backend, so the
# bundles show exactly what the collectors write, with invented content.
# tests/test_collector_bundles.py validates the committed bundles, and
# tests/test_collectors_pwsh.py fails when they differ from a fresh run.
[CmdletBinding()]
param(
    [string]$OutputRoot = 'fixtures/collector-bundles'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$collectorRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $collectorRoot '_common.ps1')
. (Join-Path $PSScriptRoot 'SyntheticBackend.ps1')
. (Join-Path $PSScriptRoot 'SyntheticScenarios.ps1')

foreach ($case in @(Get-WfSyntheticCases)) {
    $target = $OutputRoot + '/' + $case['Case']
    $resolved = Resolve-WfBundleRoot -OutputDirectory $target
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    Reset-WfSynthetic
    & $case['Setup']
    $arguments = @{ OutputDirectory = $target }
    foreach ($key in $case['Arguments'].Keys) { $arguments[$key] = $case['Arguments'][$key] }
    & (Join-Path $collectorRoot ($case['Collector'] + '.ps1')) @arguments
    $exit = $LASTEXITCODE
    $line = $global:WfSynthetic.Stdout[$global:WfSynthetic.Stdout.Count - 1]
    if ($global:WfSynthetic.Stdout.Count -ne 1) { throw ('case ' + $case['Case'] + ' printed ' + $global:WfSynthetic.Stdout.Count + ' stdout lines') }
    if ($exit -ne $case['ExitCode']) { throw ('case ' + $case['Case'] + ' exited ' + $exit + ', expected ' + $case['ExitCode'] + ': ' + $line) }
    [Console]::Error.WriteLine(('{0}: exit {1}: {2}' -f $case['Case'], $exit, $line))
}
