# reliability-records: What does Reliability Monitor hold: failures, installs, and the stability index over time?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Sources: two WMI classes in root\cimv2, read with Get-CimInstance.
#   Win32_ReliabilityRecords          the events behind Reliability Monitor
#                                     (source, event id, message, product, time)
#   Win32_ReliabilityStabilityMetrics the stability index, 1 (least stable)
#                                     to 10, with the time it was calculated
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/racwmiprov/win32-reliabilityrecords
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/racwmiprov/win32-reliabilitystabilitymetrics
# TimeGenerated is UTC in both classes. The classes need the policy
# "Configure Reliability WMI Providers", which is enabled by default on
# Windows client systems. The window is pushed into the WQL filter as a
# CIM DATETIME comparison and only the documented properties are requested,
# so the provider never has to hand over more than the collector keeps:
# https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1
# https://learn.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime
#
# Access: Authenticated Users have Enable Account (read) on WMI namespaces by
# default, and a local read needs nothing more:
# https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces
# Microsoft does not state whether this particular provider asks for more
# than that, so a refusal is recorded as not_collected with the provider's
# message (README, unverified facts).
#
# There is no binary export for these sources: the classes are computed by
# the provider, not stored in a file the account could copy.
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

$collectorName = 'reliability-records'
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
    Question = 'What does Reliability Monitor hold: failures, installs, and the stability index over time?'
    Sources  = @(
        @{
            Id           = 'reliability_records'
            Type         = 'cim'
            Kind         = 'other'
            Required     = $true
            ClassName    = 'Win32_ReliabilityRecords'
            Properties   = @('ComputerName', 'EventIdentifier', 'InsertionStrings', 'Logfile', 'Message', 'ProductName', 'RecordNumber', 'SourceName', 'TimeGenerated', 'User')
            TimeProperty = 'TimeGenerated'
        },
        @{
            Id           = 'reliability_stability_metrics'
            Type         = 'cim'
            Kind         = 'other'
            Required     = $false
            ClassName    = 'Win32_ReliabilityStabilityMetrics'
            Properties   = @('EndMeasurementDate', 'RelID', 'StartMeasurementDate', 'SystemStabilityIndex', 'TimeGenerated')
            TimeProperty = 'TimeGenerated'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
