#Requires -Version 7
<#
.SYNOPSIS
Phase 0a fact finding harness for Process Monitor on the GitHub hosted Windows runner.

.DESCRIPTION
Not a collector. Runs bounded captures with the committed test configurations,
exports them, and records what happened, so that docs/contracts/procmon-facts.md
can cite committed fixtures instead of assumptions. See the workflow
.github/workflows/procmon-facts.yml.

Runs:
  A  /LoadConfig wf-default-columns.pmc, /Runtime N, load generator running
     exports: filtered CSV (/SaveApplyFilter), unfiltered CSV, XML with stacks (/SaveAs1)
  B  /LoadConfig wf-all-columns.pmc, /Runtime N, load generator running
     export: filtered CSV
  C  /NoFilter /RingBuffer /RingBufferSize 1, /Runtime N, no configuration
     export: unfiltered CSV (row count only)
  D  /NoFilter, /Runtime N, no configuration
     export: unfiltered CSV (row count only)
Then dumps HKCU\Software\Sysinternals\Process Monitor.
#>
param(
    [string]$OutDir = "out",
    [string]$ProcmonDir = "tools/ProcessMonitor",
    [int]$RuntimeSeconds = 10
)
$ErrorActionPreference = "Stop"
$OutDir = (New-Item -ItemType Directory -Force -Path $OutDir).FullName
$procmon = (Resolve-Path (Join-Path $ProcmonDir "Procmon64.exe")).Path
$fixtures = (Resolve-Path "fixtures/procmon").Path
$nonce = [guid]::NewGuid().ToString("N").Substring(0, 8)
$loadRoot = "C:\wf-procmon-facts\$nonce"
New-Item -ItemType Directory -Force -Path $loadRoot | Out-Null
$runs = [System.Collections.Generic.List[object]]::new()
$harnessLog = Join-Path $OutDir "harness.log"

function Write-Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $msg
    Write-Host $line
    Add-Content -Path $harnessLog -Value $line
}

function Start-Load([int]$seconds) {
    $script = @"
`$end = (Get-Date).AddSeconds($seconds)
`$i = 0
while ((Get-Date) -lt `$end) {
    `$p = Join-Path '$loadRoot' ('f{0:d5}.txt' -f `$i)
    Set-Content -Path `$p -Value ('nonce $nonce ' + `$i)
    Get-Content -Path `$p | Out-Null
    Remove-Item -Path `$p
    `$i++
    Start-Sleep -Milliseconds 10
}
"@
    $path = Join-Path $OutDir "load-$nonce.ps1"
    Set-Content -Path $path -Value $script
    return Start-Process -FilePath "pwsh" -ArgumentList @("-NoProfile", "-File", $path) -PassThru -WindowStyle Hidden
}

function Invoke-Procmon([string]$label, [string[]]$arguments, [int]$timeoutSec) {
    Write-Log "$label : Procmon64.exe $($arguments -join ' ')"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $procmon -ArgumentList $arguments -PassThru
    $exited = $p.WaitForExit($timeoutSec * 1000)
    $forced = $false
    if (-not $exited) {
        Write-Log "$label : did not exit within $timeoutSec s; sending /Terminate"
        Start-Process -FilePath $procmon -ArgumentList @("/Terminate", "/Quiet") -Wait
        Start-Sleep -Seconds 3
        if (-not $p.HasExited) { $forced = $true; Stop-Process -Id $p.Id -Force }
    }
    $sw.Stop()
    $entry = [ordered]@{
        label = $label
        arguments = ($arguments -join ' ')
        exited_on_own = $exited
        forced_kill = $forced
        exit_code = $p.ExitCode
        elapsed_s = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
    Write-Log "$label : exited_on_own=$exited exit_code=$($p.ExitCode) elapsed=$($entry.elapsed_s)s"
    return $entry
}

function Invoke-Capture([string]$label, [string]$pmc, [string[]]$extra) {
    $pml = Join-Path $OutDir "$label.pml"
    $load = Start-Load ($RuntimeSeconds + 4)
    Start-Sleep -Seconds 1
    $arguments = @("/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", $pml, "/Runtime", "$RuntimeSeconds")
    if ($pmc) { $arguments += @("/LoadConfig", (Join-Path $fixtures $pmc)) }
    if ($extra) { $arguments += $extra }
    $entry = Invoke-Procmon "$label-capture" $arguments ($RuntimeSeconds + 90)
    if (-not $load.HasExited) { $load.WaitForExit(30000) | Out-Null }
    $entry.kind = "capture"
    $entry.pmc = $pmc
    $entry.load_root = $loadRoot
    $entry.pml_files = @(Get-ChildItem -Path $OutDir -Filter "$label*.pml" | ForEach-Object { [ordered]@{ name = $_.Name; bytes = $_.Length } })
    $runs.Add($entry)
    return $pml
}

function Invoke-Export([string]$label, [string]$pml, [string]$outName, [string]$pmc, [string]$saveSwitch, [bool]$applyFilter) {
    $outFile = Join-Path $OutDir $outName
    $arguments = @("/AcceptEula", "/Quiet", "/OpenLog", $pml)
    if ($pmc) { $arguments += @("/LoadConfig", (Join-Path $fixtures $pmc)) }
    if ($applyFilter) { $arguments += "/SaveApplyFilter" }
    $arguments += @($saveSwitch, $outFile)
    $entry = Invoke-Procmon "$label-export" $arguments 240
    $waited = 0
    while (-not (Test-Path $outFile) -and $waited -lt 30) { Start-Sleep -Seconds 1; $waited++ }
    $entry.kind = "export"
    $entry.pmc = $pmc
    $entry.output = $outName
    $entry.output_exists = (Test-Path $outFile)
    $entry.output_bytes = if (Test-Path $outFile) { (Get-Item $outFile).Length } else { $null }
    $runs.Add($entry)
}

try {
    Write-Log "nonce=$nonce loadRoot=$loadRoot procmon=$procmon runtime=$RuntimeSeconds"

    $pmlA = Invoke-Capture "A" "wf-default-columns.pmc" @()
    Invoke-Export "A-filtered" $pmlA "A_default_filtered.csv" "wf-default-columns.pmc" "/SaveAs" $true
    Invoke-Export "A-all" $pmlA "A_default_unfiltered.csv" "wf-default-columns.pmc" "/SaveAs" $false
    Invoke-Export "A-stacks" $pmlA "A_default_filtered_stacks.xml" "wf-default-columns.pmc" "/SaveAs1" $true

    $pmlB = Invoke-Capture "B" "wf-all-columns.pmc" @()
    Invoke-Export "B-filtered" $pmlB "B_allcolumns_filtered.csv" "wf-all-columns.pmc" "/SaveAs" $true

    $pmlC = Invoke-Capture "C" "" @("/NoFilter", "/RingBuffer", "/RingBufferSize", "1")
    Invoke-Export "C-all" $pmlC "C_ringbuffer_unfiltered.csv" "" "/SaveAs" $false

    $pmlD = Invoke-Capture "D" "" @("/NoFilter")
    Invoke-Export "D-all" $pmlD "D_plain_unfiltered.csv" "" "/SaveAs" $false
}
finally {
    Start-Process -FilePath $procmon -ArgumentList @("/Terminate", "/Quiet") -Wait -ErrorAction SilentlyContinue
    $runs | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $OutDir "runs.json")

    $regPath = 'HKCU:\Software\Sysinternals\Process Monitor'
    $reg = [ordered]@{ key = $regPath; exists = (Test-Path $regPath); values = @() }
    if (Test-Path $regPath) {
        $key = Get-Item $regPath
        $reg.values = @(foreach ($name in $key.GetValueNames()) {
            $kind = $key.GetValueKind($name).ToString()
            $raw = $key.GetValue($name)
            $value = switch ($kind) {
                "DWord" { [int64]$raw }
                "QWord" { [int64]$raw }
                "String" { [string]$raw }
                "ExpandString" { [string]$raw }
                default { $null }
            }
            $bytes = if ($raw -is [byte[]]) { $raw.Length } else { $null }
            [ordered]@{ name = $name; kind = $kind; value = $value; binary_bytes = $bytes }
        })
    }
    $reg | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutDir "registry-after-run.json")
    Write-Log "registry values: $($reg.values.Count)"
    Remove-Item -Recurse -Force -Path $loadRoot -ErrorAction SilentlyContinue
}
