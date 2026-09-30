# whea-errors: Did the Windows Hardware Error Architecture report corrected or uncorrected hardware errors?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Source: the System channel, provider Microsoft-Windows-WHEA-Logger, every
# event id. Microsoft: "The name of the provider that logs the hardware error
# events is Microsoft-Windows-WHEA-Logger", and WHEA records its events in the
# system event log:
# https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/querying-the-system-event-log-for-hardware-error-events
# https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/whea-hardware-error-events
# Each event carries the raw error record; events.json keeps it in the
# properties array and in the event XML.
#
# Access: the default security descriptor of the System log grants read to
# Event Log Readers, (A;;0x1;;;S-1-5-32-573):
# https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
#
# Not read here: the Microsoft-Windows-Kernel-WHEA channels. Microsoft Learn
# documents neither their content nor their access, so they are left for a
# verification step (README).
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How far back to read, in days (1 to 365).
    [int]$WindowDays = 30,
    # Cap on records per source (1 to 100000). Reaching it marks the source capture_failed.
    [int]$MaxEvents = 5000,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for reading one source, in seconds (1 to 3600). A read that
    # does not finish in time is recorded as capture_failed.
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'whea-errors'
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

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = 'Did the Windows Hardware Error Architecture report corrected or uncorrected hardware errors?'
    Sources  = @(
        @{
            Id         = 'system_whea_events'
            Type       = 'eventlog'
            Required   = $true
            Channel    = 'System'
            Providers  = @('Microsoft-Windows-WHEA-Logger')
            EventIds   = @()
            Predicates = @("Provider[@Name='Microsoft-Windows-WHEA-Logger']")
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
