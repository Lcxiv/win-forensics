# rf-survey: What does the 2.4 GHz airspace around the desk look like, and where do the wireless receivers sit on the PC?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, the privacy rule for other people's
# networks, and the facts still to be verified on a real machine; the method
# and its limits are in docs/rf-survey.md.
#
# The PC is on Ethernet. Its Wi-Fi adapter is used only as a receiver that
# can see the 2.4 GHz networks around the desk (the ones a wireless mouse or
# headset receiver shares the band with), so the sources are:
#
#   net_adapters, default_routes   which adapter carries the PC's traffic
#                                  (MSFT_NetAdapter, MSFT_NetRoute in
#                                  root/StandardCimv2, read with Get-CimInstance)
#   wlan_interfaces, wlan_drivers, wlan_networks, wlan_profiles
#                                  the four netsh wlan show queries Microsoft
#                                  names for wireless troubleshooting; the
#                                  networks query with mode=bssid "adds the
#                                  BSSID, signal strength, channel, and radio
#                                  type for each visible network"
#   wlan_report                    the HTML report netsh wlan show wlanreport
#                                  writes: its size, time and hash if it exists,
#                                  never its text (it names networks this run
#                                  cannot recognise); the collector never
#                                  generates it (Administrator)
#   wlan_autoconfig_events         the WLAN AutoConfig operational channel
#   usb_device_tree                present USB, input, audio and network
#                                  devices with their parent chain to the host
#                                  controller (Win32_PnPEntity, Get-PnpDeviceProperty)
#   bluetooth_devices              the Bluetooth device nodes that are present:
#                                  the radio, its enumerators and the remembered
#                                  peers (pairing and radio power are not
#                                  measured; peer names and addresses are
#                                  pseudonymised)
#
# https://learn.microsoft.com/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting
# https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wlan
# https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
# https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netroute
# https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-parent
#
# Nothing here connects, disconnects, or changes a setting, and the collector
# requests no scan itself. Microsoft documents "netsh wlan show networks" as
# displaying the visible networks; whether netsh reads the service's cached
# list or asks it to scan is not documented and is verification item 21 in
# the README. Network names and hardware addresses are pseudonymised before
# anything is written (see Protect-WfNetshText in _common.ps1); the saved
# profiles of this PC stay readable, with their pseudonyms, so the owner can
# name his network at analysis time.
#
# Access: WMI namespaces grant Enable Account (read) to Authenticated Users
# by default (https://learn.microsoft.com/windows/win32/wmisdk/access-to-wmi-namespaces);
# whether a standard account in a session started by sshd gets the scan list
# at all is the first item on the README's verification list for this
# collector (Windows withholds BSSIDs without location consent:
# https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes).
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How far back to read the WLAN AutoConfig channel, in days (1 to 365).
    [int]$WindowDays = 30,
    # Cap on records per source (1 to 100000). Reaching it marks the source capture_failed.
    [int]$MaxEvents = 5000,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for reading one source, in seconds (1 to 3600). Ten sources
    # share the dispatcher's 900 second budget, so the default is 80.
    [int]$TimeoutSeconds = 80,
    # Where the WLAN report is. Empty means the conventional location under
    # ProgramData; the report location is not documented by Microsoft, so a
    # person running by hand may pass the path netsh printed.
    [string]$WlanReportPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'rf-survey'
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

$scanWithheld = 'netsh exited with code 0 and listed no network. Windows withholds the scan list from a process without location consent (https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes), and a session started by sshd cannot answer the consent prompt, so an empty list cannot be told from an empty airspace; see verification item 15 in collectors/windows/README.md'

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = 'What does the 2.4 GHz airspace around the desk look like, which adapter carries the traffic, and where do the wireless receivers sit on the PC?'
    Sources  = @(
        @{
            Id         = 'net_adapters'
            Type       = 'cim'
            Kind       = 'config_snapshot'
            Required   = $true
            Namespace  = 'root/StandardCimv2'
            ClassName  = 'MSFT_NetAdapter'
            Properties = @('Name', 'InterfaceDescription', 'InterfaceIndex', 'InterfaceGuid', 'InterfaceName', 'NdisMedium', 'NdisPhysicalMedium',
                'InterfaceOperationalStatus', 'InterfaceAdminStatus', 'MediaConnectState', 'State', 'Status', 'Virtual', 'Hidden', 'HardwareInterface',
                'ConnectorPresent', 'EndPointInterface', 'ReceiveLinkSpeed', 'TransmitLinkSpeed', 'DriverDescription', 'DriverVersionString',
                'DriverProvider', 'DriverDate', 'PnPDeviceID', 'LowerLayerInterfaceIndices', 'HigherLayerInterfaceIndices')
        },
        @{
            Id                         = 'default_routes'
            Type                       = 'cim'
            Kind                       = 'config_snapshot'
            Required                   = $false
            Namespace                  = 'root/StandardCimv2'
            ClassName                  = 'MSFT_NetRoute'
            Filter                     = "DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0'"
            Properties                 = @('DestinationPrefix', 'NextHop', 'InterfaceIndex', 'InterfaceAlias', 'RouteMetric', 'Protocol', 'AddressFamily', 'Store', 'Publish', 'TypeOfRoute')
            EmptySnapshotIsObservation = $true
        },
        @{
            Id             = 'wlan_profiles'
            Type           = 'command'
            Required       = $false
            Arguments      = 'wlan show profiles'
            Protect        = 'profiles'
            ZeroRule       = 'observed_zero'
            RecordsMeaning = 'saved wireless profiles, counted by valued lines; the names stay readable (the owner''s own networks) and result.json maps each to its pseudonym'
            Expectation    = 'netsh exits with code 0 and prints the profile list; no saved profile is a legitimate zero'
        },
        @{
            Id             = 'wlan_interfaces'
            Type           = 'command'
            Required       = $false
            Arguments      = 'wlan show interfaces'
            Protect        = 'interfaces'
            ZeroRule       = 'observed_zero'
            RecordsMeaning = 'wireless interfaces, counted by the GUID each one prints'
            Expectation    = 'netsh exits with code 0 and prints the interface list; a PC without a wireless interface is a legitimate zero'
        },
        @{
            Id             = 'wlan_drivers'
            Type           = 'command'
            Required       = $false
            Arguments      = 'wlan show drivers'
            Protect        = 'drivers'
            ZeroRule       = 'observed_zero'
            RecordsMeaning = 'wireless driver blocks, counted by unindented header lines'
            Expectation    = 'netsh exits with code 0 and prints the driver properties; a PC without a wireless interface is a legitimate zero'
        },
        @{
            Id             = 'wlan_networks'
            Type           = 'command'
            Required       = $false
            Arguments      = 'wlan show networks mode=bssid'
            Protect        = 'networks'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $scanWithheld
            RecordsMeaning = 'visible access points (BSSIDs), counted by distinct address pseudonyms'
            Expectation    = 'netsh exits with code 0 and lists at least one network; zero networks is not accepted as an empty airspace'
        },
        @{
            Id             = 'wlan_report'
            Type           = 'file'
            Required       = $false
            Path           = $WlanReportPath
            Folder         = 'ProgramData'
            PathTail       = 'Microsoft\Windows\WlanReport\wlan-report-latest.html'
            PathDocumented = $false
            FileName       = 'report-summary.json'
            MissingHint    = 'The report is created by "netsh wlan show wlanreport" from an Administrator command prompt (https://support.microsoft.com/windows/analyze-the-wireless-network-report-76da0daa-1db2-6049-d154-7bb679eb03ed), which prints where it saved the file; this collector never creates it and never copies its text.'
            Expectation    = 'the report exists at the conventional location and is readable; its size, time and hash are recorded, its text is not'
        },
        @{
            Id         = 'wlan_autoconfig_events'
            Type       = 'eventlog'
            Required   = $false
            Channel    = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            Providers  = @('Microsoft-Windows-WLAN-AutoConfig')
            EventIds   = @()
            Predicates = @("Provider[@Name='Microsoft-Windows-WLAN-AutoConfig']")
            Protect    = $true
        },
        @{
            Id                = 'usb_device_tree'
            Type              = 'pnp'
            Kind              = 'config_snapshot'
            Required          = $true
            Classes           = @('USB', 'HIDClass', 'Mouse', 'Keyboard', 'Media', 'Net')
            InstancePrefixes  = @('USB\')
            IncludeAncestors  = $true
            ZeroIsObservation = $false
            Expectation       = 'at least one USB device is present (a PC has USB host controllers) and every selected device is followed to the root of the device tree'
        },
        @{
            Id                = 'bluetooth_devices'
            Type              = 'pnp'
            Kind              = 'config_snapshot'
            Required          = $false
            Classes           = @('Bluetooth')
            InstancePrefixes  = @('BTH')
            IncludeAncestors  = $true
            ZeroIsObservation = $true
            Expectation       = 'the device enumeration completes; no present Bluetooth device node is a legitimate zero. Presence of a node says nothing about pairing or radio power, which are not measured'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
