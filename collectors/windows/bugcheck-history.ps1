# bugcheck-history: Did Windows stop with a bug check or shut down uncleanly, and what changed around it?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Source: the System channel, selected by event id. Microsoft lists these ids
# for reconstructing restart history:
#   41    Kernel-Power, the system rebooted without shutting down cleanly; its
#         event data carries BugcheckCode and the four parameters
#   1001  WER-SystemErrorReporting, "The computer has rebooted from a bugcheck",
#         with the bug check code and the dump path
#   6008  EventLog, the previous shutdown was unexpected
#   1074  User32, a process requested a restart or shutdown
#   6006  EventLog, a clean shutdown
#   6009  EventLog, logged at start
#   7045  Service Control Manager, a service (kernel drivers included) was installed
#   46    volmgr, crash dump initialization failed (why a bug check left no dump)
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart
# Ids 12, 13 and 19 from the same list are left out: many providers share
# them, and 6006, 6009 and 1074 already mark starts and shutdowns.
#
# Access: the default security descriptor of the System log grants read to
# Event Log Readers, (A;;0x1;;;S-1-5-32-573):
# https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
#
# Not read here: the dump files the events point at (C:\Windows\Minidump,
# MEMORY.DMP). Those are for the elevated scheduled task; see the README.
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
    # Skip the binary wevtutil export and keep only the structured one.
    [switch]$SkipEvtx
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'bugcheck-history'
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
    Question = 'Did Windows stop with a bug check or shut down uncleanly, and what changed around it?'
    Sources  = @(
        @{
            Id         = 'system_restart_events'
            Type       = 'eventlog'
            Required   = $true
            Channel    = 'System'
            Providers  = @()
            EventIds   = @(41, 46, 1001, 1074, 6006, 6008, 6009, 7045)
            Predicates = @('(EventID=41 or EventID=46 or EventID=1001 or EventID=1074 or EventID=6006 or EventID=6008 or EventID=6009 or EventID=7045)')
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -SkipEvtx $SkipEvtx.IsPresent -CollectorPath $PSCommandPath)[-1]
exit $exitCode
