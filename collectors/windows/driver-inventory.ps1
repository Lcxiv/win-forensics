# driver-inventory: Which drivers are installed, in which versions, from which providers, and which kernel drivers are running?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# Sources: two WMI classes in root\cimv2, read with Get-CimInstance. Both are
# snapshots taken when the collector runs; there is no time window.
#   Win32_PnPSignedDriver  one row per device driver: device, class, version,
#                          date, provider, INF name, signer
#   Win32_SystemDriver     one row per kernel and file system driver service:
#                          name, path, state, start mode
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394354(v=vs.85)
# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemdriver
# Only the documented properties named below are requested, under an
# operation timeout, so a provider that does not answer cannot hold the
# collector:
# https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1
# The rows are shaped for the config_snapshot table (category driver), and
# the manifest's machine.drivers list is filled from Win32_PnPSignedDriver
# (the first 2000 named drivers; the manifest says when that cut anything).
#
# Access: Authenticated Users have Enable Account (read) on WMI namespaces by
# default, and a local read needs nothing more:
# https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces
#
# Not read here: the driver store itself and driver binaries.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # Cap on instances per source (1 to 100000). Reaching it marks the source capture_failed.
    [int]$MaxEvents = 20000,
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

$collectorName = 'driver-inventory'
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
    Question = 'Which drivers are installed, in which versions, from which providers, and which kernel drivers are running?'
    Sources  = @(
        @{
            Id                  = 'pnp_signed_drivers'
            Type                = 'cim'
            Kind                = 'config_snapshot'
            Required            = $true
            ClassName           = 'Win32_PnPSignedDriver'
            Properties          = @('DeviceID', 'DeviceName', 'DeviceClass', 'ClassGuid', 'Description', 'FriendlyName', 'Manufacturer', 'DriverProviderName', 'DriverVersion', 'DriverDate', 'DriverName', 'InfName', 'IsSigned', 'Signer', 'HardWareID', 'CompatID', 'Location', 'Started', 'StartMode', 'Status')
            FillsMachineDrivers = $true
        },
        @{
            Id        = 'system_drivers'
            Type      = 'cim'
            Kind      = 'config_snapshot'
            Required  = $true
            ClassName = 'Win32_SystemDriver'
            Properties = @('Name', 'DisplayName', 'Description', 'PathName', 'ServiceType', 'StartMode', 'State', 'Started', 'Status', 'ErrorControl', 'ExitCode', 'AcceptStop', 'TagId')
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
