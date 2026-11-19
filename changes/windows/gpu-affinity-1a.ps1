# Step 1a of the undo order: puts the display adapter's interrupt Affinity
# Policy values (DevicePolicy, AssignmentSetOverride) back to their state
# before 12 November, as recorded by the single matching Originals rows of
# Stutter Guard's journal, cross-checked against Stutter Guard's own reg
# export of that session and Bitsum's saved originals.
#
#   gpu-affinity-1a.ps1 [-Plan]     read only; the default
#   gpu-affinity-1a.ps1 -Apply      save the before-state, write, read back
#   gpu-affinity-1a.ps1 -Undo       restore the saved before-state
#   gpu-affinity-1a.ps1 -Readback   read only; PASS or FAIL per value
#
# Run by hand at the PC in Windows PowerShell 5.1. Apply and Undo need an
# elevated console (Run as administrator) and run only on the captain's own
# Yes for this change. The script never prompts, never restarts and never
# runs anything else; the operator page is docs/changes/step-1a-gpu-affinity.md
# and the area's rules are in changes/windows/README.md.
#
# Exit codes: 0 done (Plan: every precondition holds; Readback: every value
# PASS), 1 a write or a readback failed, 2 refused or cannot tell (nothing
# changed).
[CmdletBinding()]
param(
    [switch]$Plan,
    [switch]$Apply,
    [switch]$Undo,
    [switch]$Readback,
    [string]$StutterGuardDataDirectory = '',
    [string]$EvidenceRoot = '',
    [string]$EvidenceFolder = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_gpu-affinity-1a-lib.ps1')

$verbs = @()
if ($Plan) { $verbs += 'Plan' }
if ($Apply) { $verbs += 'Apply' }
if ($Undo) { $verbs += 'Undo' }
if ($Readback) { $verbs += 'Readback' }
if ($verbs.Count -gt 1) {
    Write-Wf1aOut -Line ('REFUSED: name one verb, not ' + ($verbs -join ' and ') + '. Nothing changed.')
    exit 2
}
$verb = 'Plan'
if ($verbs.Count -eq 1) { $verb = $verbs[0] }
if ($EvidenceFolder -and $verb -ne 'Undo') {
    Write-Wf1aOut -Line 'REFUSED: -EvidenceFolder goes with -Undo only. Nothing changed.'
    exit 2
}

$programData = [Environment]::GetFolderPath('CommonApplicationData')
if (-not $StutterGuardDataDirectory) { $StutterGuardDataDirectory = Join-Path -Path $programData -ChildPath 'Stutter Guard' }
if (-not $EvidenceRoot) { $EvidenceRoot = Join-Path -Path (Join-Path -Path (Join-Path -Path $programData -ChildPath 'win-forensics') -ChildPath 'changes') -ChildPath (Get-Wf1aChangeName) }

$code = 2
try {
    $code = Invoke-Wf1aMain -Verb $verb -StutterGuardDataDirectory $StutterGuardDataDirectory -EvidenceRoot $EvidenceRoot -EvidenceFolder $EvidenceFolder
} catch {
    Write-Wf1aOut -Line ('STOPPED: an unexpected error (' + $_.Exception.GetType().Name + '). Run -Readback to see the live values; if Apply had started writing, run -Undo.')
    if ($verb -eq 'Apply' -or $verb -eq 'Undo') { $code = 1 } else { $code = 2 }
}
exit $code
