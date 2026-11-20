# Network tuning for the gaming PC's one wired Realtek adapter: only the
# settings with an include verdict in docs/changes/network-tuning-research.md,
# each read live from what the installed driver exposes, never assumed.
#
#   network-tuning.ps1 [-Plan]     read only; the default
#   network-tuning.ps1 -Apply      save the before-state, write, read back
#   network-tuning.ps1 -Undo       restore the saved before-state
#   network-tuning.ps1 -Readback   read only; PASS or FAIL per value
#   -Only <names>                  a subset of the settings (comma separated)
#
# Run by hand at the PC in Windows PowerShell 5.1, with the game and its
# launcher closed. Apply and Undo need an elevated console (Run as
# administrator) and run only on the captain's own Yes. The script never
# prompts and never restarts the adapter or the PC; the operator page is
# docs/changes/network-tuning.md and the area's rules are in
# changes/windows/README.md.
#
# Exit codes: 0 done (Plan: ready to apply; Readback: every value PASS), 1 a
# write or a readback failed, 2 refused or nothing to do, with nothing
# changed.
[CmdletBinding()]
param(
    [switch]$Plan,
    [switch]$Apply,
    [switch]$Undo,
    [switch]$Readback,
    [string[]]$Only = @(),
    [string]$EvidenceRoot = '',
    [string]$EvidenceFolder = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_network-tuning-lib.ps1')

$verbs = @()
if ($Plan) { $verbs += 'Plan' }
if ($Apply) { $verbs += 'Apply' }
if ($Undo) { $verbs += 'Undo' }
if ($Readback) { $verbs += 'Readback' }
if ($verbs.Count -gt 1) {
    Write-WfNtOut -Line ('REFUSED: name one verb, not ' + ($verbs -join ' and ') + '. Nothing changed.')
    exit 2
}
$verb = 'Plan'
if ($verbs.Count -eq 1) { $verb = $verbs[0] }
if ($EvidenceFolder -and $verb -ne 'Undo') {
    Write-WfNtOut -Line 'REFUSED: -EvidenceFolder goes with -Undo only. Nothing changed.'
    exit 2
}
if (@($Only).Count -gt 0 -and $verb -eq 'Undo') {
    Write-WfNtOut -Line 'REFUSED: -Undo restores everything one Apply saved; name the run with -EvidenceFolder, not -Only. Nothing changed.'
    exit 2
}

if (-not $EvidenceRoot) {
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    $EvidenceRoot = Join-Path -Path (Join-Path -Path (Join-Path -Path $programData -ChildPath 'win-forensics') -ChildPath 'changes') -ChildPath (Get-WfNtChangeName)
}

$code = 2
try {
    $code = Invoke-WfNtMain -Verb $verb -Only $Only -EvidenceRoot $EvidenceRoot -EvidenceFolder $EvidenceFolder
} catch {
    Write-WfNtOut -Line ('STOPPED: an unexpected error (' + $_.Exception.GetType().Name + '). Run -Readback to see the live values; if Apply had started writing, run -Undo.')
    if ($verb -eq 'Apply' -or $verb -eq 'Undo') { $code = 1 } else { $code = 2 }
}
exit $code
