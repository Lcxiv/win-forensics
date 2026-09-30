# application-errors: Which applications crashed or stopped responding, and with what fault?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Source: the Application channel, four provider and event id pairs:
#   Application Error        1000  a process crashed (faulting application,
#                                  module, exception code)
#   Application Hang         1002  a process stopped responding
#   Windows Error Reporting  1001  the report Windows Error Reporting filed
#   .NET Runtime             1026  an unhandled .NET exception with its stack
# Microsoft's own event collection query for application crashes and hangs
# names the first three providers and ids, and the crash troubleshooting
# articles name 1000, 1001 and 1026:
# https://learn.microsoft.com/en-us/azure/azure-local/manage/disconnected-operations-security
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior
# https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/site-behavior-performance/process-termination-crash
#
# Access: the default security descriptor of the Application log grants read
# to Event Log Readers, (A;;0x1;;;S-1-5-32-573):
# https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
#
# Not read here: the crash dumps themselves. Per application Windows Error
# Reporting dump keys are set up later, with the elevated task (README).
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

$collectorName = 'application-errors'
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
    Question = 'Which applications crashed or stopped responding, and with what fault?'
    Sources  = @(
        @{
            Id         = 'application_error_events'
            Type       = 'eventlog'
            Required   = $true
            Channel    = 'Application'
            Providers  = @('Application Error', 'Application Hang', 'Windows Error Reporting', '.NET Runtime')
            EventIds   = @(1000, 1002, 1001, 1026)
            Predicates = @(
                "Provider[@Name='Application Error'] and (EventID=1000)",
                "Provider[@Name='Application Hang'] and (EventID=1002)",
                "Provider[@Name='Windows Error Reporting'] and (EventID=1001)",
                "Provider[@Name='.NET Runtime'] and (EventID=1026)"
            )
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
