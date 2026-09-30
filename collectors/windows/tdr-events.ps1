# tdr-events: Did the GPU driver time out, and did Windows recover the display or stop with a bug check?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Timeout detection and recovery (TDR) has two outcomes, read as two sources.
#
# Source 1, recovered timeouts: the System channel, provider "Display", every
# event id. Microsoft documents the behaviour: after a successful recovery
# Windows shows "Display driver stopped responding and has recovered" and
# "Logs the preceding message in the Event Viewer application":
# https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery
# Microsoft Learn does not say which log, provider, or event id carries that
# message. "Display" in the System log is the working assumption, so this
# source is marked QuietClaimVerified = $false: records it finds are
# evidence, but an empty result is reported as capture_failed, never as a
# quiet window, until the verification step in the README has been done on
# the machine.
#
# Source 2, failed recoveries: the System channel, event ids 41 and 1001,
# which carry the bug check code. When recovery fails, or when more than
# five timeouts occur within a minute, Windows stops with bug check 0x116
# VIDEO_TDR_FAILURE:
# https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x116---video-tdr-failure
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
# The collector exports every 41 and 1001 record; a decoder keeps the ones
# with that code.
#
# Not read here: the live dumps. Codes 0x117 VIDEO_TDR_TIMEOUT_DETECTED,
# 0x141 VIDEO_ENGINE_TIMEOUT_DETECTED and 0x142 VIDEO_TDR_APPLICATION_BLOCKED
# are kernel live dump codes: Windows keeps running, so there is no restart
# event, and writes a dump under %SystemRoot%\LiveKernelReports:
# https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/kernel-live-dump-code-reference
# Reading that directory is left to the elevated scheduled task (README).
#
# Access: the default security descriptor of the System log grants read to
# Event Log Readers, (A;;0x1;;;S-1-5-32-573):
# https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
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

$collectorName = 'tdr-events'
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
    Question = 'Did the GPU driver time out, and did Windows recover the display or stop with a bug check?'
    Sources  = @(
        @{
            Id                 = 'system_display_events'
            Type               = 'eventlog'
            Required           = $false
            Channel            = 'System'
            Providers          = @('Display')
            EventIds           = @()
            Predicates         = @("Provider[@Name='Display']")
            QuietClaimVerified = $false
        },
        @{
            Id         = 'system_bugcheck_events'
            Type       = 'eventlog'
            Required   = $true
            Channel    = 'System'
            Providers  = @()
            EventIds   = @(41, 1001)
            Predicates = @('(EventID=41 or EventID=1001)')
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -SkipEvtx $SkipEvtx.IsPresent -CollectorPath $PSCommandPath)[-1]
exit $exitCode
