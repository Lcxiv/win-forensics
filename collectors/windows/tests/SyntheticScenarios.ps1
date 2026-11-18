# The cases behind fixtures/collector-bundles and the end to end Pester tests.
# Each case names a collector, prepares the synthetic backend, and states the
# exit code the collector must return. All content is invented.

function Get-WfSyntheticCases {
    $cases = New-Object 'System.Collections.Generic.List[object]'

    # A bug check followed by an unclean restart, inside a log that reaches
    # back well past the window: status ok, source observed.
    $cases.Add(@{
            Case = 'bugcheck-history'; Collector = 'bugcheck-history'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
                Add-WfSyntheticQuery -Match 'EventID=6008' -Events @(
                    (New-WfSyntheticEvent -RecordId 40110 -Provider 'EventLog' -EventId 6009 -Level 4 -LevelDisplay 'Information' -DaysAgo 12.5 -Properties @('10.00.', '26100', 'Multiprocessor Free') -Message 'Microsoft (R) Windows (R) 10.00. 26100 Multiprocessor Free.'),
                    (New-WfSyntheticEvent -RecordId 40871 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -LevelDisplay 'Critical' -DaysAgo 3.25 -Properties @(159, '0x3', '0xffff000000000001', '0xffff000000000002', '0xffff000000000003') -Message 'The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly.'),
                    (New-WfSyntheticEvent -RecordId 40875 -Provider 'EventLog' -EventId 6008 -DaysAgo 3.2499 -Properties @('12:00:00 PM', '2/26/2026') -Message 'The previous system shutdown at 12:00:00 PM on 2/26/2026 was unexpected.'),
                    (New-WfSyntheticEvent -RecordId 40902 -Provider 'Microsoft-Windows-WER-SystemErrorReporting' -EventId 1001 -DaysAgo 3.2498 -Properties @('0x0000009f (0x0000000000000003, 0xffff000000000001, 0xffff000000000002, 0xffff000000000003)', 'C:\Windows\MEMORY.DMP', '00000000-0000-0000-0000-000000000001') -Message 'The computer has rebooted from a bugcheck.  The bugcheck was: 0x0000009f (0x0000000000000003, 0xffff000000000001, 0xffff000000000002, 0xffff000000000003). A dump was saved in: C:\Windows\MEMORY.DMP. Report Id: 00000000-0000-0000-0000-000000000001.')
                )
            }
        })

    # The account is not in Event Log Readers: the channel cannot be read, the
    # source is not_collected, nothing is observed, and the collector exits 1.
    $cases.Add(@{
            Case = 'bugcheck-history-access-denied'; Collector = 'bugcheck-history'; ExitCode = 1; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -Readable $false -ErrorKind 'access_denied' -ErrorMessage 'Attempted to perform an unauthorized operation.'
            }
        })

    # No hardware error records in a log that covers the whole window: a
    # quiet window, observed_zero, status ok.
    $cases.Add(@{
            Case = 'whea-errors-quiet'; Collector = 'whea-errors'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
            }
        })

    # One crash and one hang, in a log that only reaches back nine days: the
    # source is observed and its covered range starts at the oldest record.
    $cases.Add(@{
            Case = 'application-errors'; Collector = 'application-errors'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['Application'] = New-WfSyntheticChannelState -OldestDaysAgo 9 -RecordCount 5300
                Add-WfSyntheticQuery -Match 'Application Error' -Events @(
                    (New-WfSyntheticEvent -RecordId 5120 -Channel 'Application' -Provider 'Application Error' -EventId 1000 -DaysAgo 4.5 -Properties @('example.exe', '1.0.0.0', '00000000', 'examplemodule.dll', '1.0.0.0', '00000000', 'c0000005', '0000000000001000', '0x1a2b', '0x01d00000000000', 'C:\Program Files\Example\example.exe', 'C:\Program Files\Example\examplemodule.dll', '00000000-0000-0000-0000-000000000002') -Message 'Faulting application name: example.exe, version: 1.0.0.0. Faulting module name: examplemodule.dll, version: 1.0.0.0. Exception code: 0xc0000005.'),
                    (New-WfSyntheticEvent -RecordId 5188 -Channel 'Application' -Provider 'Application Hang' -EventId 1002 -DaysAgo 1.75 -Properties @('example.exe', '1.0.0.0', '2b3c', '01d00000000001', '4294967295', 'C:\Program Files\Example\example.exe', '00000000-0000-0000-0000-000000000003') -Message 'The program example.exe version 1.0.0.0 stopped interacting with Windows and was closed.')
                )
            }
        })

    # No Display records and no bug checks. The bug check source is a quiet
    # window; the Display source is capture_failed because its provider is
    # not documented, so the collector reports partial and exits 0.
    $cases.Add(@{
            Case = 'tdr-events-partial'; Collector = 'tdr-events'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
            }
        })

    # Reliability records and hourly stability values.
    $cases.Add(@{
            Case = 'reliability-records'; Collector = 'reliability-records'; ExitCode = 0; Arguments = @{}
            Setup = {
                $now = $global:WfSynthetic.Now
                $global:WfSynthetic.Cim['Win32_ReliabilityRecords'] = @{ Rows = @(
                        [ordered]@{ ComputerName = 'SYNTHETIC-PC'; EventIdentifier = 1000; InsertionStrings = @('example.exe', '1.0.0.0'); Logfile = 'Application'; Message = 'Faulting application name: example.exe, version: 1.0.0.0.'; ProductName = 'example.exe'; RecordNumber = 5120; SourceName = 'Application Error'; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-4.5)); User = $null },
                        [ordered]@{ ComputerName = 'SYNTHETIC-PC'; EventIdentifier = 1033; InsertionStrings = @('Example Application', '1.0.0.0'); Logfile = 'Application'; Message = 'Windows Installer installed the product. Product Name: Example Application.'; ProductName = 'Example Application'; RecordNumber = 4800; SourceName = 'MsiInstaller'; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-20)); User = 'SYNTHETIC-PC\owner' },
                        [ordered]@{ ComputerName = 'SYNTHETIC-PC'; EventIdentifier = 19; InsertionStrings = @('Example Update'); Logfile = 'System'; Message = 'Installation Successful: Windows successfully installed the following update: Example Update'; ProductName = 'Example Update'; RecordNumber = 30001; SourceName = 'Microsoft-Windows-WindowsUpdateClient'; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-45)); User = $null }
                    )
                }
                $global:WfSynthetic.Cim['Win32_ReliabilityStabilityMetrics'] = @{ Rows = @(
                        [ordered]@{ EndMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-40)); RelID = '00000000-0000-0000-0000-00000000000a'; StartMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-68)); SystemStabilityIndex = 9.1; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-40)) },
                        [ordered]@{ EndMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-4)); RelID = '00000000-0000-0000-0000-00000000000a'; StartMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-32)); SystemStabilityIndex = 6.4; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-4)) },
                        [ordered]@{ EndMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-1)); RelID = '00000000-0000-0000-0000-00000000000a'; StartMeasurementDate = (ConvertTo-WfUtcString -Value $now.AddDays(-29)); SystemStabilityIndex = 7.2; TimeGenerated = (ConvertTo-WfUtcString -Value $now.AddDays(-1)) }
                    )
                }
            }
        })

    # A driver snapshot.
    $cases.Add(@{
            Case = 'driver-inventory'; Collector = 'driver-inventory'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Cim['Win32_PnPSignedDriver'] = @{ Rows = @(
                        [ordered]@{ ClassGuid = '{4d36e968-e325-11ce-bfc1-08002be10318}'; CompatID = $null; Description = 'Synthetic Display Adapter'; DeviceClass = 'DISPLAY'; DeviceID = 'PCI\VEN_FFFF&DEV_0001\0'; DeviceName = 'Synthetic Display Adapter'; DevLoader = $null; DriverDate = '2026-01-15T00:00:00.0000000Z'; DriverName = $null; DriverProviderName = 'Synthetic Graphics'; DriverVersion = '1.2.3.4'; FriendlyName = $null; HardWareID = 'PCI\VEN_FFFF&DEV_0001'; InfName = 'oem1.inf'; InstallDate = $null; IsSigned = $true; Location = 'PCI bus 1, device 0, function 0'; Manufacturer = 'Synthetic Graphics'; Name = $null; PDO = '\Device\NTPNP_PCI0001'; Signer = 'Microsoft Windows Hardware Compatibility Publisher'; Started = $null; StartMode = $null; Status = $null; SystemCreationClassName = $null; SystemName = $null },
                        [ordered]@{ ClassGuid = '{4d36e97d-e325-11ce-bfc1-08002be10318}'; CompatID = $null; Description = 'ACPI x64-based PC'; DeviceClass = 'SYSTEM'; DeviceID = 'ROOT\ACPI_HAL\0000'; DeviceName = 'ACPI x64-based PC'; DevLoader = $null; DriverDate = '2006-06-21T00:00:00.0000000Z'; DriverName = $null; DriverProviderName = 'Microsoft'; DriverVersion = '10.0.26100.1'; FriendlyName = $null; HardWareID = 'acpiapic'; InfName = 'hal.inf'; InstallDate = $null; IsSigned = $true; Location = $null; Manufacturer = '(Standard computers)'; Name = $null; PDO = '\Device\00000001'; Signer = 'Microsoft Windows'; Started = $null; StartMode = $null; Status = $null; SystemCreationClassName = $null; SystemName = $null },
                        [ordered]@{ ClassGuid = $null; CompatID = $null; Description = $null; DeviceClass = $null; DeviceID = 'ROOT\UNKNOWN\0000'; DeviceName = $null; DevLoader = $null; DriverDate = $null; DriverName = $null; DriverProviderName = $null; DriverVersion = $null; FriendlyName = $null; HardWareID = $null; InfName = $null; InstallDate = $null; IsSigned = $null; Location = $null; Manufacturer = $null; Name = $null; PDO = $null; Signer = $null; Started = $null; StartMode = $null; Status = $null; SystemCreationClassName = $null; SystemName = $null }
                    )
                }
                $global:WfSynthetic.Cim['Win32_SystemDriver'] = @{ Rows = @(
                        [ordered]@{ AcceptPause = $false; AcceptStop = $true; Caption = 'Synthetic Display Driver'; CreationClassName = 'Win32_SystemDriver'; Description = 'Synthetic Display Driver'; DesktopInteract = $false; DisplayName = 'Synthetic Display Driver'; ErrorControl = 'Normal'; ExitCode = 0; InstallDate = $null; Name = 'synthdisp'; PathName = 'C:\Windows\System32\drivers\synthdisp.sys'; ServiceSpecificExitCode = 0; ServiceType = 'Kernel Driver'; Started = $true; StartMode = 'Manual'; StartName = $null; State = 'Running'; Status = 'OK'; SystemCreationClassName = 'Win32_ComputerSystem'; SystemName = 'SYNTHETIC-PC'; TagId = 0 },
                        [ordered]@{ AcceptPause = $false; AcceptStop = $true; Caption = 'ACPI Driver'; CreationClassName = 'Win32_SystemDriver'; Description = 'ACPI Driver'; DesktopInteract = $false; DisplayName = 'Microsoft ACPI Driver'; ErrorControl = 'Critical'; ExitCode = 0; InstallDate = $null; Name = 'ACPI'; PathName = 'C:\Windows\System32\drivers\ACPI.sys'; ServiceSpecificExitCode = 0; ServiceType = 'Kernel Driver'; Started = $true; StartMode = 'Boot'; StartName = $null; State = 'Running'; Status = 'OK'; SystemCreationClassName = 'Win32_ComputerSystem'; SystemName = 'SYNTHETIC-PC'; TagId = 2 }
                    )
                }
            }
        })

    # The RF survey on an Ethernet PC. Four cases share one invented machine
    # (see New-WfSyntheticRfMachine) and differ in what the airspace and the
    # wireless service look like. All names, addresses and devices are made up.

    # Congested 2.4 GHz: the owner's router on channel 6 next to two
    # neighbours, a third neighbour on channel 8, a 5 GHz network from the
    # same router, the mouse receiver on the xHCI (USB 3) root hub while an
    # EHCI (USB 2) controller exists, Bluetooth on with nothing paired, the
    # WLAN report present. Status ok.
    $cases.Add(@{
            Case = 'rf-survey'; Collector = 'rf-survey'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticRfMachine -Receiver 'xhci' -Ehci $true -Bluetooth 'unpaired' -WifiAdapter 'enabled'
                $global:WfSynthetic.Commands['wlan show interfaces'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'interfaces-disconnected-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'drivers-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'networks-congested-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show profiles'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'profiles-en'); StdErr = '' }
                $global:WfSynthetic.Files['C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html'] = @{ Text = (Get-WfSyntheticNetshText -Name 'wlan-report') }
                $global:WfSynthetic.Channels['Microsoft-Windows-WLAN-AutoConfig/Operational'] = New-WfSyntheticChannelState -OldestDaysAgo 60 -RecordCount 800
                Add-WfSyntheticQuery -Match 'WLAN-AutoConfig' -Events @(
                    (New-WfSyntheticEvent -RecordId 790 -Channel 'Microsoft-Windows-WLAN-AutoConfig/Operational' -Provider 'Microsoft-Windows-WLAN-AutoConfig' -EventId 8003 -Level 4 -LevelDisplay 'Information' -DaysAgo 12.3 -Properties @('Synthetic Wi-Fi 6E AX Adapter', 'Unseen-Guest', 'Infrastructure', 7, 'The operation was successful.') -Message 'WLAN AutoConfig service has successfully disconnected from a wireless network. Network Adapter: Synthetic Wi-Fi 6E AX Adapter Interface GUID: {5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c} Connection Mode: Automatic connection with a profile Profile Name: Unseen-Guest SSID: Unseen-Guest BSSID: 02:aa:bb:cc:dd:99 BSS Type: Infrastructure Reason: The operation was successful.'),
                    (New-WfSyntheticEvent -RecordId 798 -Channel 'Microsoft-Windows-WLAN-AutoConfig/Operational' -Provider 'Microsoft-Windows-WLAN-AutoConfig' -EventId 4003 -Level 4 -LevelDisplay 'Information' -DaysAgo 0.4 -Properties @('Synthetic Wi-Fi 6E AX Adapter', 'Disconnected') -Message 'WLAN AutoConfig service has detected that the wireless network adapter state changed. Network Adapter: Synthetic Wi-Fi 6E AX Adapter Interface GUID: {5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c} State: Disconnected')
                )
            }
        })

    # Clean 2.4 GHz: the owner's router alone on channel 1, two weak
    # neighbours on 6 and 11, no 5 GHz network in sight, the receiver on the
    # EHCI (USB 2) root hub, two Bluetooth devices paired, no WLAN report,
    # a quiet WLAN AutoConfig channel. Status partial (the report is missing).
    $cases.Add(@{
            Case = 'rf-survey-clean'; Collector = 'rf-survey'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticRfMachine -Receiver 'ehci' -Ehci $true -Bluetooth 'paired' -WifiAdapter 'enabled'
                $global:WfSynthetic.Commands['wlan show interfaces'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'interfaces-disconnected-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'drivers-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'networks-clean-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show profiles'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'profiles-one-en'); StdErr = '' }
                $global:WfSynthetic.Channels['Microsoft-Windows-WLAN-AutoConfig/Operational'] = New-WfSyntheticChannelState -OldestDaysAgo 60 -RecordCount 800
            }
        })

    # No wireless service: every netsh query fails with the message Windows
    # prints when WlanSvc is stopped, no report, no WLAN channel, no
    # Bluetooth radio, the receiver on the xHCI root hub and no EHCI
    # controller at all. Status partial: the adapter, route and USB sources
    # still observe.
    $cases.Add(@{
            Case = 'rf-survey-no-wifi'; Collector = 'rf-survey'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticRfMachine -Receiver 'xhci' -Ehci $false -Bluetooth 'absent' -WifiAdapter 'absent'
                foreach ($arguments in @('wlan show interfaces', 'wlan show drivers', 'wlan show networks mode=bssid', 'wlan show profiles')) {
                    $global:WfSynthetic.Commands[$arguments] = @{ ExitCode = 1; StdOut = "The Wireless AutoConfig Service (wlansvc) is not running.`r`n"; StdErr = '' }
                }
            }
        })

    # A connected Wi-Fi interface on a PC whose traffic still goes over
    # Ethernet: the interface listing carries the connected SSID, BSSID,
    # profile, band, channel and signal, every one of which must leave the
    # bundle as a pseudonym. Clean airspace, receiver on the USB 3 root hub,
    # Bluetooth on with nothing remembered, no report. Status partial.
    $cases.Add(@{
            Case = 'rf-survey-connected'; Collector = 'rf-survey'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticRfMachine -Receiver 'xhci' -Ehci $true -Bluetooth 'unpaired' -WifiAdapter 'connected'
                $global:WfSynthetic.Commands['wlan show interfaces'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'interfaces-connected-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'drivers-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'networks-clean-en'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show profiles'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'profiles-en'); StdErr = '' }
                $global:WfSynthetic.Channels['Microsoft-Windows-WLAN-AutoConfig/Operational'] = New-WfSyntheticChannelState -OldestDaysAgo 60 -RecordCount 800
            }
        })

    # A German display language: a congested airspace printed with translated
    # labels and comma decimals, so only the structure and the shape of the
    # values can be relied on; the interface is connected and its SSID label
    # is translated too (an invented translation, to exercise the structural
    # fallback); the Bluetooth radio is disabled in Device Manager with two
    # remembered peers. Status partial (no report).
    $cases.Add(@{
            Case = 'rf-survey-non-english'; Collector = 'rf-survey'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticRfMachine -Receiver 'xhci' -Ehci $true -Bluetooth 'disabled' -WifiAdapter 'connected'
                $global:WfSynthetic.Commands['wlan show interfaces'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'interfaces-connected-de'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show drivers'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'drivers-de'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show networks mode=bssid'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'networks-congested-de'); StdErr = '' }
                $global:WfSynthetic.Commands['wlan show profiles'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticNetshText -Name 'profiles-de'); StdErr = '' }
                $global:WfSynthetic.Channels['Microsoft-Windows-WLAN-AutoConfig/Operational'] = New-WfSyntheticChannelState -OldestDaysAgo 60 -RecordCount 800
            }
        })


    # The configuration snapshot of an invented gaming PC whose owner pinned
    # the display adapter's interrupts to one logical processor and runs
    # Process Lasso and Stutter Guard: every documented key present, both
    # programs installed with their files, the timer helper running. Status
    # partial by design: three questions have no documented read only path
    # and are recorded not_collected with their reasons.
    $cases.Add(@{
            Case = 'config-snapshot'; Collector = 'config-snapshot'; ExitCode = 0; Arguments = @{}
            Setup = {
                New-WfSyntheticConfigMachine -Variant 'full'
            }
        })

    # The same machine without any tuning: hardware keys that hold no
    # Interrupt Management (absent, not unknown), no TDR value set, neither
    # program installed, no timer helper, a German display language for
    # powercfg and a /qh that fails. Status partial.
    $cases.Add(@{
            Case = 'config-snapshot-clean'; Collector = 'config-snapshot'; ExitCode = 0; Arguments = @{ Snapshot = 'stop' }
            Setup = {
                New-WfSyntheticConfigMachine -Variant 'clean'
            }
        })

    # An account that may read nothing: every hardware key refuses (access
    # denied at the SetupDiOpenDevRegKey stage), the GraphicsDrivers key
    # refuses, WMI refuses the processor and process classes, the topology
    # declaration does not compile, powercfg is not where Windows keeps it,
    # the folders and files refuse. Every source is a status with a reason and
    # no export; the collector exits 1.
    $cases.Add(@{
            Case = 'config-snapshot-denied'; Collector = 'config-snapshot'; ExitCode = 1; Arguments = @{}
            Setup = {
                New-WfSyntheticConfigMachine -Variant 'denied'
            }
        })

    return $cases.ToArray()
}

function New-WfSyntheticRfMachine {
    # The invented Ethernet gaming PC behind the rf-survey cases: network
    # adapters and default routes (MSFT_NetAdapter, MSFT_NetRoute) and the
    # present Plug and Play devices with their parent chain.
    #   -Receiver xhci|ehci   which root hub the mouse receiver hangs off
    #   -Ehci                 whether a USB 2 (EHCI) host controller exists
    #   -Bluetooth absent|unpaired|paired
    #   -WifiAdapter enabled|absent
    param([string]$Receiver, [bool]$Ehci, [string]$Bluetooth, [string]$WifiAdapter)
    $adapters = New-Object 'System.Collections.Generic.List[object]'
    $adapters.Add([ordered]@{ Name = 'Ethernet'; InterfaceDescription = 'Synthetic 2.5GbE Controller'; InterfaceIndex = 12; InterfaceGuid = '{0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d}'; InterfaceName = 'ethernet_32768'; NdisMedium = 0; NdisPhysicalMedium = 14; InterfaceOperationalStatus = 1; InterfaceAdminStatus = 1; MediaConnectState = 1; State = 2; Status = 'OK'; Virtual = $false; Hidden = $false; HardwareInterface = $true; ConnectorPresent = $true; EndPointInterface = $false; ReceiveLinkSpeed = 2500000000; TransmitLinkSpeed = 2500000000; DriverDescription = 'Synthetic 2.5GbE Controller'; DriverVersionString = '11.0.0.1'; DriverProvider = 'Synthetic Networks'; DriverDate = '2025-12-01'; PnPDeviceID = 'PCI\VEN_FFF0&DEV_8125\4&3a2b1c0d&0&00E0'; LowerLayerInterfaceIndices = @(); HigherLayerInterfaceIndices = @() })
    if ($WifiAdapter -eq 'enabled' -or $WifiAdapter -eq 'connected') {
        $up = ($WifiAdapter -eq 'connected')
        $adapters.Add([ordered]@{ Name = 'Wi-Fi'; InterfaceDescription = 'Synthetic Wi-Fi 6E AX Adapter'; InterfaceIndex = 7; InterfaceGuid = '{5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c}'; InterfaceName = 'wireless_32768'; NdisMedium = 16; NdisPhysicalMedium = 9; InterfaceOperationalStatus = $(if ($up) { 1 } else { 2 }); InterfaceAdminStatus = 1; MediaConnectState = $(if ($up) { 1 } else { 2 }); State = 2; Status = 'OK'; Virtual = $false; Hidden = $false; HardwareInterface = $true; ConnectorPresent = $true; EndPointInterface = $false; ReceiveLinkSpeed = 0; TransmitLinkSpeed = 0; DriverDescription = 'Synthetic Wi-Fi 6E AX Adapter'; DriverVersionString = '23.0.0.1'; DriverProvider = 'Synthetic Wireless'; DriverDate = '2026-01-10'; PnPDeviceID = 'PCI\VEN_FFF0&DEV_2725\4&3a2b1c0d&0&00A0'; LowerLayerInterfaceIndices = @(); HigherLayerInterfaceIndices = @() })
    }
    if ($Bluetooth -ne 'absent') {
        $adapters.Add([ordered]@{ Name = 'Bluetooth Network Connection'; InterfaceDescription = 'Bluetooth Device (Personal Area Network)'; InterfaceIndex = 9; InterfaceGuid = '{7e6d5c4b-3a29-4180-9f8e-7d6c5b4a3928}'; InterfaceName = 'ethernet_32769'; NdisMedium = 0; NdisPhysicalMedium = 10; InterfaceOperationalStatus = 2; InterfaceAdminStatus = 1; MediaConnectState = 2; State = 2; Status = 'OK'; Virtual = $false; Hidden = $false; HardwareInterface = $true; ConnectorPresent = $true; EndPointInterface = $false; ReceiveLinkSpeed = 3000000; TransmitLinkSpeed = 3000000; DriverDescription = 'Bluetooth Device (Personal Area Network)'; DriverVersionString = '10.0.26100.1'; DriverProvider = 'Microsoft'; DriverDate = '2006-06-21'; PnPDeviceID = 'BTH\MS_BTHPAN\6&2f1e0d9c&0&2'; LowerLayerInterfaceIndices = @(); HigherLayerInterfaceIndices = @() })
    }
    $adapters.Add([ordered]@{ Name = 'Local Area Connection* 1'; InterfaceDescription = 'Synthetic Wi-Fi Direct Virtual Adapter'; InterfaceIndex = 15; InterfaceGuid = '{9c8b7a69-5847-4362-a1f0-e9d8c7b6a594}'; InterfaceName = 'wireless_32769'; NdisMedium = 16; NdisPhysicalMedium = 9; InterfaceOperationalStatus = 2; InterfaceAdminStatus = 1; MediaConnectState = 2; State = 2; Status = 'OK'; Virtual = $true; Hidden = $true; HardwareInterface = $false; ConnectorPresent = $false; EndPointInterface = $false; ReceiveLinkSpeed = 0; TransmitLinkSpeed = 0; DriverDescription = 'Synthetic Wi-Fi Direct Virtual Adapter'; DriverVersionString = '10.0.26100.1'; DriverProvider = 'Microsoft'; DriverDate = '2006-06-21'; PnPDeviceID = 'SWD\MSWIFIDIRECT\0'; LowerLayerInterfaceIndices = @(); HigherLayerInterfaceIndices = @() })
    $global:WfSynthetic.Cim['MSFT_NetAdapter'] = @{ Rows = $adapters.ToArray() }
    $global:WfSynthetic.Cim['MSFT_NetRoute'] = @{ Rows = @(
            [ordered]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '192.168.1.1'; InterfaceIndex = 12; InterfaceAlias = 'Ethernet'; RouteMetric = 0; Protocol = 3; AddressFamily = 2; Store = 1; Publish = 0; TypeOfRoute = 3 },
            [ordered]@{ DestinationPrefix = '::/0'; NextHop = 'fe80::1'; InterfaceIndex = 12; InterfaceAlias = 'Ethernet'; RouteMetric = 256; Protocol = 1; AddressFamily = 23; Store = 1; Publish = 0; TypeOfRoute = 3 },
            [ordered]@{ DestinationPrefix = '192.168.1.0/24'; NextHop = '0.0.0.0'; InterfaceIndex = 12; InterfaceAlias = 'Ethernet'; RouteMetric = 256; Protocol = 2; AddressFamily = 2; Store = 1; Publish = 0; TypeOfRoute = 3 }
        )
    }

    $devices = New-Object 'System.Collections.Generic.List[object]'
    $devices.Add(@{ instance_id = 'HTREE\ROOT\0'; class = $null; class_guid = $null; name = $null; description = $null; manufacturer = $null; service = $null; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @(); compatible_ids = @(); Properties = @{ DEVPKEY_Device_EnumeratorName = 'HTREE' } })
    $devices.Add(@{ instance_id = 'ROOT\ACPI_HAL\0000'; class = 'Computer'; class_guid = '{4d36e966-e325-11ce-bfc1-08002be10318}'; name = 'ACPI x64-based PC'; description = 'ACPI x64-based PC'; manufacturer = '(Standard computers)'; service = $null; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('acpiapic'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'HTREE\ROOT\0'; DEVPKEY_Device_EnumeratorName = 'ROOT' } })
    $devices.Add(@{ instance_id = 'ACPI\PNP0A08\0'; class = 'System'; class_guid = '{4d36e97d-e325-11ce-bfc1-08002be10318}'; name = 'PCI Express Root Complex'; description = 'PCI Express Root Complex'; manufacturer = '(Standard system devices)'; service = 'pci'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('ACPI\VEN_PNP&DEV_0A08'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'ROOT\ACPI_HAL\0000'; DEVPKEY_Device_LocationPaths = @('ACPI(_SB_)#ACPI(PCI0)'); DEVPKEY_Device_EnumeratorName = 'ACPI' } })
    $devices.Add(@{ instance_id = 'PCI\VEN_FFF0&DEV_A36D\3&11583659&0&A0'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'Synthetic USB 3.1 eXtensible Host Controller'; description = 'Synthetic USB 3.1 eXtensible Host Controller'; manufacturer = 'Synthetic Chipsets'; service = 'USBXHCI'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_A36D&SUBSYS_0001FFF0&REV_10'); compatible_ids = @('PCI\CC_0C0330'); Properties = @{ DEVPKEY_Device_Parent = 'ACPI\PNP0A08\0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1400)'); DEVPKEY_Device_LocationInfo = 'PCI bus 0, device 20, function 0'; DEVPKEY_Device_Address = 1310720; DEVPKEY_Device_EnumeratorName = 'PCI' } })
    $devices.Add(@{ instance_id = 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'USB Root Hub (USB 3.0)'; description = 'USB Root Hub (USB 3.0)'; manufacturer = '(Standard USB HUBs)'; service = 'USBHUB3'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\ROOT_HUB30&VID8086&PID_A36D&REV_0010', 'USB\ROOT_HUB30'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'PCI\VEN_FFF0&DEV_A36D\3&11583659&0&A0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1400)#USBROOT(0)'); DEVPKEY_Device_EnumeratorName = 'USB' } })
    if ($Ehci) {
        $devices.Add(@{ instance_id = 'PCI\VEN_FFF0&DEV_A2AF\3&11583659&0&E8'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'Synthetic USB Enhanced Host Controller'; description = 'Synthetic USB Enhanced Host Controller'; manufacturer = 'Synthetic Chipsets'; service = 'usbehci'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_A2AF&SUBSYS_0001FFF0&REV_10'); compatible_ids = @('PCI\CC_0C0320'); Properties = @{ DEVPKEY_Device_Parent = 'ACPI\PNP0A08\0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1D00)'); DEVPKEY_Device_LocationInfo = 'PCI bus 0, device 29, function 0'; DEVPKEY_Device_Address = 1900544; DEVPKEY_Device_EnumeratorName = 'PCI' } })
        $devices.Add(@{ instance_id = 'USB\ROOT_HUB20\4&1f0e9d8c&0&0'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'USB Root Hub'; description = 'USB Root Hub'; manufacturer = '(Standard USB Host Controller)'; service = 'usbhub'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\ROOT_HUB20&VID8086&PID_A2AF&REV_0010', 'USB\ROOT_HUB20'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'PCI\VEN_FFF0&DEV_A2AF\3&11583659&0&E8'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1D00)#USBROOT(0)'); DEVPKEY_Device_EnumeratorName = 'USB' } })
        $devices.Add(@{ instance_id = 'USB\VID_FFF4&PID_0004\5&1e2f3a4b&0&1'; class = 'HIDClass'; class_guid = '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}'; name = 'USB Input Device'; description = 'USB Input Device'; manufacturer = '(Standard system devices)'; service = 'HidUsb'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF4&PID_0004&REV_0100', 'USB\VID_FFF4&PID_0004'); compatible_ids = @('USB\Class_03&SubClass_01&Prot_01', 'USB\Class_03&SubClass_01', 'USB\Class_03'); Properties = @{ DEVPKEY_Device_Parent = 'USB\ROOT_HUB20\4&1f0e9d8c&0&0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1D00)#USBROOT(0)#USB(1)'); DEVPKEY_Device_LocationInfo = 'Port_#0001.Hub_#0002'; DEVPKEY_Device_Address = 1; DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic Mechanical Keyboard'; DEVPKEY_Device_EnumeratorName = 'USB' } })
    }
    $receiverHub = 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'
    $receiverPath = 'PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)'
    $receiverInfo = 'Port_#0003.Hub_#0001'
    if ($Receiver -eq 'ehci') {
        $receiverHub = 'USB\ROOT_HUB20\4&1f0e9d8c&0&0'
        $receiverPath = 'PCIROOT(0)#PCI(1D00)#USBROOT(0)#USB(3)'
        $receiverInfo = 'Port_#0003.Hub_#0002'
    }
    $devices.Add(@{ instance_id = 'USB\VID_FFF1&PID_0001\5&1e2f3a4b&0&3'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'USB Composite Device'; description = 'USB Composite Device'; manufacturer = '(Standard USB Host Controller)'; service = 'usbccgp'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF1&PID_0001&REV_0301', 'USB\VID_FFF1&PID_0001'); compatible_ids = @('USB\DevClass_00&SubClass_00&Prot_00', 'USB\DevClass_00&SubClass_00', 'USB\DevClass_00', 'USB\COMPOSITE'); Properties = @{ DEVPKEY_Device_Parent = $receiverHub; DEVPKEY_Device_LocationPaths = @($receiverPath); DEVPKEY_Device_LocationInfo = $receiverInfo; DEVPKEY_Device_Address = 3; DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic Lightspeed Receiver'; DEVPKEY_Device_ContainerId = '{a1b2c3d4-0001-4000-8000-000000000001}'; DEVPKEY_Device_EnumeratorName = 'USB' } })
    $devices.Add(@{ instance_id = 'USB\VID_FFF1&PID_0001&MI_00\6&3b4c5d6e&0&0000'; class = 'HIDClass'; class_guid = '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}'; name = 'USB Input Device'; description = 'USB Input Device'; manufacturer = '(Standard system devices)'; service = 'HidUsb'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF1&PID_0001&REV_0301&MI_00', 'USB\VID_FFF1&PID_0001&MI_00'); compatible_ids = @('USB\Class_03&SubClass_01&Prot_02', 'USB\Class_03&SubClass_01', 'USB\Class_03'); Properties = @{ DEVPKEY_Device_Parent = 'USB\VID_FFF1&PID_0001\5&1e2f3a4b&0&3'; DEVPKEY_Device_LocationPaths = @($receiverPath + '#USBMI(0)'); DEVPKEY_Device_LocationInfo = '0000.0014.0000.003.000.000.000.000.000'; DEVPKEY_Device_Address = 0; DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic Lightspeed Receiver'; DEVPKEY_Device_ContainerId = '{a1b2c3d4-0001-4000-8000-000000000001}'; DEVPKEY_Device_EnumeratorName = 'USB' } })
    $devices.Add(@{ instance_id = 'HID\VID_FFF1&PID_0001&MI_00\7&4c5d6e7f&0&0000'; class = 'Mouse'; class_guid = '{4d36e96f-e325-11ce-bfc1-08002be10318}'; name = 'HID-compliant mouse'; description = 'HID-compliant mouse'; manufacturer = 'Microsoft'; service = 'mouhid'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('HID\VID_FFF1&PID_0001&REV_0301&MI_00', 'HID_DEVICE_SYSTEM_MOUSE', 'HID_DEVICE_UP:0001_U:0002'); compatible_ids = @('HID_DEVICE_SYSTEM_MOUSE'); Properties = @{ DEVPKEY_Device_Parent = 'USB\VID_FFF1&PID_0001&MI_00\6&3b4c5d6e&0&0000'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_ContainerId = '{a1b2c3d4-0001-4000-8000-000000000001}'; DEVPKEY_Device_EnumeratorName = 'HID' } })
    $devices.Add(@{ instance_id = 'USB\VID_FFF2&PID_0002\5&1e2f3a4b&0&4'; class = 'MEDIA'; class_guid = '{4d36e96c-e325-11ce-bfc1-08002be10318}'; name = 'Synthetic Wireless Headset Dongle'; description = 'USB Audio Device'; manufacturer = 'Synthetic Audio'; service = 'usbaudio'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF2&PID_0002&REV_0100', 'USB\VID_FFF2&PID_0002'); compatible_ids = @('USB\Class_01&SubClass_01&Prot_00', 'USB\Class_01&SubClass_01', 'USB\Class_01'); Properties = @{ DEVPKEY_Device_Parent = 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(4)'); DEVPKEY_Device_LocationInfo = 'Port_#0004.Hub_#0001'; DEVPKEY_Device_Address = 4; DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic Wireless Headset Dongle'; DEVPKEY_Device_ContainerId = '{a1b2c3d4-0002-4000-8000-000000000002}'; DEVPKEY_Device_EnumeratorName = 'USB' } })
    $devices.Add(@{ instance_id = 'USB\VID_FFF3&PID_0003\0123456789AB'; class = 'USB'; class_guid = '{36fc9e60-c465-11cf-8056-444553540000}'; name = 'USB Mass Storage Device'; description = 'USB Mass Storage Device'; manufacturer = 'Compatible USB storage device'; service = 'USBSTOR'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF3&PID_0003&REV_0100', 'USB\VID_FFF3&PID_0003'); compatible_ids = @('USB\Class_08&SubClass_06&Prot_50', 'USB\Class_08&SubClass_06', 'USB\Class_08'); Properties = @{ DEVPKEY_Device_Parent = 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)'); DEVPKEY_Device_LocationInfo = 'Port_#0002.Hub_#0001'; DEVPKEY_Device_Address = 2; DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic Portable SSD'; DEVPKEY_Device_ContainerId = '{a1b2c3d4-0003-4000-8000-000000000003}'; DEVPKEY_Device_EnumeratorName = 'USB' } })
    if ($Bluetooth -ne 'absent') {
        # 'disabled' is the radio switched off in Device Manager: present, problem code 22 (device is disabled).
        $radioStatus = 'OK'
        $radioProblem = 0
        if ($Bluetooth -eq 'disabled') { $radioStatus = 'Error'; $radioProblem = 22 }
        $devices.Add(@{ instance_id = 'USB\VID_FFF5&PID_0005\5&1e2f3a4b&0&14'; class = 'Bluetooth'; class_guid = '{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'; name = 'Synthetic Wireless Bluetooth'; description = 'Synthetic Wireless Bluetooth'; manufacturer = 'Synthetic Wireless'; service = 'BTHUSB'; status = $radioStatus; problem_code = $radioProblem; present = $true; hardware_ids = @('USB\VID_FFF5&PID_0005&REV_0001', 'USB\VID_FFF5&PID_0005'); compatible_ids = @('USB\Class_E0&SubClass_01&Prot_01', 'USB\Class_E0&SubClass_01', 'USB\Class_E0'); Properties = @{ DEVPKEY_Device_Parent = 'USB\ROOT_HUB30\4&2a1b3c4d&0&0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(14)'); DEVPKEY_Device_LocationInfo = 'Port_#0014.Hub_#0001'; DEVPKEY_Device_Address = 14; DEVPKEY_Device_BusReportedDeviceDesc = $null; DEVPKEY_Device_EnumeratorName = 'USB' } })
        $devices.Add(@{ instance_id = 'BTH\MS_BTHLE\6&2f1e0d9c&0&1'; class = 'Bluetooth'; class_guid = '{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'; name = 'Microsoft Bluetooth LE Enumerator'; description = 'Microsoft Bluetooth LE Enumerator'; manufacturer = 'Microsoft'; service = 'BthLEEnum'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTH\MS_BTHLE'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'USB\VID_FFF5&PID_0005\5&1e2f3a4b&0&14'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTH' } })
        $devices.Add(@{ instance_id = 'BTH\MS_BTHPAN\6&2f1e0d9c&0&2'; class = 'Net'; class_guid = '{4d36e972-e325-11ce-bfc1-08002be10318}'; name = 'Bluetooth Device (Personal Area Network)'; description = 'Bluetooth Device (Personal Area Network)'; manufacturer = 'Microsoft'; service = 'BthPan'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTH\MS_BTHPAN'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'USB\VID_FFF5&PID_0005\5&1e2f3a4b&0&14'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTH' } })
    }
    if ($Bluetooth -eq 'paired' -or $Bluetooth -eq 'disabled') {
        $devices.Add(@{ instance_id = 'BTHENUM\DEV_F0F1F2000001\7&3a2b1c0d&0&BLUETOOTHDEVICE_F0F1F2000001'; class = 'Bluetooth'; class_guid = '{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'; name = 'Synthetic Earbuds'; description = 'Bluetooth Device'; manufacturer = 'Microsoft'; service = 'BTHENUM'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHENUM\Dev_F0F1F2000001'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'USB\VID_FFF5&PID_0005\5&1e2f3a4b&0&14'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTHENUM' } })
        $devices.Add(@{ instance_id = 'BTHLE\DEV_F0F1F2000002\8&1b2c3d4e&0&F0F1F2000002'; class = 'Bluetooth'; class_guid = '{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'; name = 'Synthetic Game Controller'; description = 'Bluetooth LE Device'; manufacturer = 'Microsoft'; service = 'BthLEEnum'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHLE\Dev_F0F1F2000002'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'BTH\MS_BTHLE\6&2f1e0d9c&0&1'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTHLE' } })
        $devices.Add(@{ instance_id = 'BTHHFENUM\BthHFPAudio\8&2d3e4f50&0&97'; class = 'MEDIA'; class_guid = '{4d36e96c-e325-11ce-bfc1-08002be10318}'; name = 'Synthetic Earbuds Hands-Free AG Audio'; description = 'Bluetooth Hands-free Audio and Call Control HID Enumerator'; manufacturer = 'Microsoft'; service = 'BthHFAud'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHHFENUM\BthHFPAudio'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'BTHENUM\DEV_F0F1F2000001\7&3a2b1c0d&0&BLUETOOTHDEVICE_F0F1F2000001'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTHHFENUM' } })
        # A Bluetooth LE mouse: the peer node, its GATT HID service node and the HID mouse collection, each carrying the peer's address.
        $devices.Add(@{ instance_id = 'BTHLE\DEV_F0F1F2000003\8&1b2c3d4e&0&F0F1F2000003'; class = 'Bluetooth'; class_guid = '{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'; name = 'Synthetic BLE Mouse'; description = 'Bluetooth LE Device'; manufacturer = 'Microsoft'; service = 'BthLEEnum'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHLE\Dev_F0F1F2000003'); compatible_ids = @(); Properties = @{ DEVPKEY_Device_Parent = 'BTH\MS_BTHLE\6&2f1e0d9c&0&1'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'BTHLE' } })
        $devices.Add(@{ instance_id = 'BTHLEDEVICE\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006_REV&0001_F0F1F2000003\9&2c3d4e5f&0&0022'; class = 'HIDClass'; class_guid = '{745a17a0-74d3-11d0-b6fe-00a0c90f57da}'; name = 'Bluetooth Low Energy GATT compliant HID device'; description = 'Bluetooth Low Energy GATT compliant HID device'; manufacturer = 'Microsoft'; service = 'HidBth'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHLEDEVICE\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006_REV&0001', 'BTHLEDEVICE\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006'); compatible_ids = @('BTHLEDEVICE\GENERIC_GATT_SERVICE'); Properties = @{ DEVPKEY_Device_Parent = 'BTHLE\DEV_F0F1F2000003\8&1b2c3d4e&0&F0F1F2000003'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_BusReportedDeviceDesc = 'Synthetic BLE Mouse'; DEVPKEY_Device_EnumeratorName = 'BTHLEDEVICE' } })
        $devices.Add(@{ instance_id = 'HID\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006_REV&0001_F0F1F2000003&Col01\a&1d2e3f40&0&0000'; class = 'Mouse'; class_guid = '{4d36e96f-e325-11ce-bfc1-08002be10318}'; name = 'HID-compliant mouse'; description = 'HID-compliant mouse'; manufacturer = 'Microsoft'; service = 'mouhid'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('HID\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006_REV&0001_F0F1F2000003&Col01', 'HID_DEVICE_SYSTEM_MOUSE'); compatible_ids = @('HID_DEVICE_SYSTEM_MOUSE'); Properties = @{ DEVPKEY_Device_Parent = 'BTHLEDEVICE\{00001812-0000-1000-8000-00805f9b34fb}_Dev_VID&02fff6_PID&0006_REV&0001_F0F1F2000003\9&2c3d4e5f&0&0022'; DEVPKEY_Device_LocationPaths = @(); DEVPKEY_Device_EnumeratorName = 'HID' } })
    }
    if ($WifiAdapter -eq 'enabled' -or $WifiAdapter -eq 'connected') {
        $devices.Add(@{ instance_id = 'PCI\VEN_FFF0&DEV_2725\4&3a2b1c0d&0&00A0'; class = 'Net'; class_guid = '{4d36e972-e325-11ce-bfc1-08002be10318}'; name = 'Synthetic Wi-Fi 6E AX Adapter'; description = 'Synthetic Wi-Fi 6E AX Adapter'; manufacturer = 'Synthetic Wireless'; service = 'SynWifi'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_2725&SUBSYS_0001FFF0&REV_1A'); compatible_ids = @('PCI\CC_028000'); Properties = @{ DEVPKEY_Device_Parent = 'ACPI\PNP0A08\0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1403)'); DEVPKEY_Device_LocationInfo = 'PCI bus 0, device 20, function 3'; DEVPKEY_Device_Address = 1310723; DEVPKEY_Device_EnumeratorName = 'PCI' } })
    }
    $devices.Add(@{ instance_id = 'PCI\VEN_FFF0&DEV_8125\4&3a2b1c0d&0&00E0'; class = 'Net'; class_guid = '{4d36e972-e325-11ce-bfc1-08002be10318}'; name = 'Synthetic 2.5GbE Controller'; description = 'Synthetic 2.5GbE Controller'; manufacturer = 'Synthetic Networks'; service = 'syneth'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_8125&SUBSYS_0001FFF0&REV_05'); compatible_ids = @('PCI\CC_020000'); Properties = @{ DEVPKEY_Device_Parent = 'ACPI\PNP0A08\0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(1C04)#PCI(0000)'); DEVPKEY_Device_LocationInfo = 'PCI bus 5, device 0, function 0'; DEVPKEY_Device_Address = 0; DEVPKEY_Device_EnumeratorName = 'PCI' } })
    $devices.Add(@{ instance_id = 'PCI\VEN_FFFF&DEV_0001\4&3a2b1c0d&0&0008'; class = 'Display'; class_guid = '{4d36e968-e325-11ce-bfc1-08002be10318}'; name = 'Synthetic Display Adapter'; description = 'Synthetic Display Adapter'; manufacturer = 'Synthetic Graphics'; service = 'synthdisp'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFFF&DEV_0001'); compatible_ids = @('PCI\CC_030000'); Properties = @{ DEVPKEY_Device_Parent = 'ACPI\PNP0A08\0'; DEVPKEY_Device_LocationPaths = @('PCIROOT(0)#PCI(0100)#PCI(0000)'); DEVPKEY_Device_EnumeratorName = 'PCI' } })
    $global:WfSynthetic.Pnp = @{ Devices = $devices.ToArray() }
}

function Get-WfSyntheticNetshText {
    # Invented netsh outputs in the layout the collector expects (an
    # unindented name line per network, indented address lines, labels and
    # values separated by a colon). The German texts translate the labels
    # and use comma decimals; the only non ASCII character is built with
    # [char] so this file stays plain ASCII.
    param([string]$Name)
    $ue = [char]0xFC
    $nl = "`r`n"
    switch ($Name) {
        'interfaces-disconnected-en' {
            return (@(
                    '',
                    'There is 1 interface on the system:',
                    '',
                    '    Name                   : Wi-Fi',
                    '    Description            : Synthetic Wi-Fi 6E AX Adapter',
                    '    GUID                   : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c',
                    '    Physical address       : 02:11:22:33:44:55',
                    '    Interface type         : Primary',
                    '    State                  : disconnected',
                    '    Radio status           : Hardware On',
                    '                             Software On',
                    '',
                    '    Hosted network status  : Not available',
                    ''
                ) -join $nl) + $nl
        }
        'interfaces-disconnected-de' {
            return (@(
                    '',
                    'Auf dem System ist 1 Schnittstelle vorhanden:',
                    '',
                    '    Name                   : WLAN',
                    '    Beschreibung           : Synthetic Wi-Fi 6E AX Adapter',
                    '    GUID                   : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c',
                    '    Physische Adresse      : 02:11:22:33:44:55',
                    ('    Schnittstellentyp      : Prim' + [char]0xE4 + 'r'),
                    '    Status                 : Getrennt',
                    '    Funkstatus             : Hardware Ein',
                    '                             Software Ein',
                    '',
                    ('    Status des gehosteten Netzwerks  : Nicht verf' + $ue + 'gbar'),
                    ''
                ) -join $nl) + $nl
        }
        'interfaces-connected-en' {
            return (@(
                    '',
                    'There is 1 interface on the system:',
                    '',
                    '    Name                   : Wi-Fi',
                    '    Description            : Synthetic Wi-Fi 6E AX Adapter',
                    '    GUID                   : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c',
                    '    Physical address       : 02:11:22:33:44:55',
                    '    Interface type         : Primary',
                    '    State                  : connected',
                    '    SSID                   : Harbor-Home',
                    '    BSSID                  : 02:aa:bb:cc:dd:01',
                    '    Network type           : Infrastructure',
                    '    Radio type             : 802.11n',
                    '    Authentication         : WPA2-Personal',
                    '    Cipher                 : CCMP',
                    '    Connection mode        : Auto Connect',
                    '    Band                   : 2.4 GHz',
                    '    Channel                : 1',
                    '    Receive rate (Mbps)    : 144.4',
                    '    Transmit rate (Mbps)   : 144.4',
                    '    Signal                 : 90%',
                    '    Profile                : Harbor-Home',
                    '',
                    '    Hosted network status  : Not available',
                    ''
                ) -join $nl) + $nl
        }
        'interfaces-connected-de' {
            return (@(
                    '',
                    'Auf dem System ist 1 Schnittstelle vorhanden:',
                    '',
                    '    Name                   : WLAN',
                    '    Beschreibung           : Synthetic Wi-Fi 6E AX Adapter',
                    '    GUID                   : 5f4d3c2b-1a09-4e8f-9d7c-6b5a4f3e2d1c',
                    '    Physische Adresse      : 02:11:22:33:44:55',
                    ('    Schnittstellentyp      : Prim' + [char]0xE4 + 'r'),
                    '    Status                 : Verbunden',
                    '    Netzwerkname           : Harbor-Home',
                    '    BSSID                  : 02:aa:bb:cc:dd:01',
                    '    Netzwerktyp            : Infrastruktur',
                    '    Funktyp                : 802.11ax',
                    '    Authentifizierung      : WPA2-Personal',
                    ('    Verschl' + $ue + 'sselung         : CCMP'),
                    '    Verbindungsmodus       : Automatische Verbindung',
                    '    Band                   : 2,4 GHz',
                    '    Kanal                  : 6',
                    '    Empfangsrate (MBit/s)  : 144,4',
                    ('    ' + $ue + 'bertragungsrate (MBit/s) : 144,4'),
                    '    Signal                 : 94%',
                    '    Profil                 : Harbor-Home',
                    ''
                ) -join $nl) + $nl
        }
        'drivers-en' {
            return (@(
                    '',
                    'Interface name: Wi-Fi',
                    '',
                    '    Driver                    : Synthetic Wi-Fi 6E AX Adapter',
                    '    Vendor                    : Synthetic Wireless',
                    '    Provider                  : Synthetic Wireless',
                    '    Date                      : 1/10/2026',
                    '    Version                   : 23.0.0.1',
                    '    INF file                  : oem42.inf',
                    '    Type                      : Native Wi-Fi Driver',
                    '    Radio types supported     : 802.11b 802.11g 802.11n 802.11a 802.11ac 802.11ax',
                    '    FIPS 140-2 mode supported : Yes',
                    '    802.11w Management Frame Protection supported : Yes',
                    '    Hosted network supported  : No',
                    '    Authentication and cipher supported in infrastructure mode:',
                    '                                Open             None',
                    '                                WPA2-Personal    CCMP',
                    '                                WPA3-Personal    CCMP',
                    '    IHV service present       : Yes',
                    '    IHV adapter OUI           : [00 00 00], type: [00]',
                    '    IHV extensibility DLL path: C:\Windows\System32\SynIhv.dll',
                    '    IHV UI extensibility ClSID: {00000000-0000-0000-0000-000000000000}',
                    '    IHV diagnostics CLSID     : {00000000-0000-0000-0000-000000000000}',
                    '    Wireless Display Supported: Yes (Graphics Driver: Yes, Wi-Fi Driver: Yes)',
                    ''
                ) -join $nl) + $nl
        }
        'drivers-de' {
            return (@(
                    '',
                    'Schnittstellenname: WLAN',
                    '',
                    '    Treiber                   : Synthetic Wi-Fi 6E AX Adapter',
                    '    Anbieter                  : Synthetic Wireless',
                    '    Hersteller                : Synthetic Wireless',
                    '    Datum                     : 10.01.2026',
                    '    Version                   : 23.0.0.1',
                    '    INF-Datei                 : oem42.inf',
                    '    Typ                       : Systemeigener WLAN-Treiber',
                    ('    Unterst' + $ue + 'tzte Funktypen       : 802.11b 802.11g 802.11n 802.11a 802.11ac 802.11ax'),
                    ('    FIPS 140-2-Modus unterst' + $ue + 'tzt : Ja'),
                    ('    Gehostetes Netzwerk unterst' + $ue + 'tzt : Nein'),
                    ''
                ) -join $nl) + $nl
        }
        'networks-congested-en' {
            return (@(
                    '',
                    'Interface name : Wi-Fi ',
                    'There are 8 networks currently visible. ',
                    '',
                    'SSID 1 : Harbor-Home',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:01',
                    '         Signal             : 94%  ',
                    '         Radio type         : 802.11ax',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 6 ',
                    '         Bss Load:',
                    '             Connected Stations:         3',
                    '             Channel Utilization:        92 (36 %)',
                    '             Medium Available Capacity:  21875 (700 ms)',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '    BSSID 2                 : 02:aa:bb:cc:dd:02',
                    '         Signal             : 88%  ',
                    '         Radio type         : 802.11ax',
                    '         Band               : 5 GHz',
                    '         Channel            : 36 ',
                    '         Bss Load:',
                    '             Connected Stations:         1',
                    '             Channel Utilization:        10 (3 %)',
                    '             Medium Available Capacity:  30000 (960 ms)',
                    '         Basic rates (Mbps) : 6 12 24',
                    '         Other rates (Mbps) : 9 18 36 48 54',
                    '    BSSID 3                 : 02:aa:bb:cc:dd:03',
                    '         Signal             : 60%  ',
                    '         Radio type         : 802.11ax',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 11 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 2 : Neighbour-A',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:11',
                    '         Signal             : 96%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 6 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 3 : Neighbour-B',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:21',
                    '         Signal             : 62%  ',
                    '         Radio type         : 802.11ax',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 6 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 4 : Neighbour-C',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:31',
                    '         Signal             : 55%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 8 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 5 : Neighbour-D',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA3-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:41',
                    '         Signal             : 40%  ',
                    '         Radio type         : 802.11ax',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 1 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 6 : Neighbour-E',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:51',
                    '         Signal             : 35%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 11 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 7 : Neighbour-F',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:61',
                    '         Signal             : 50%  ',
                    '         Radio type         : 802.11ac',
                    '         Band               : 5 GHz',
                    '         Channel            : 44 ',
                    '         Basic rates (Mbps) : 6 12 24',
                    '         Other rates (Mbps) : 9 18 36 48 54',
                    '',
                    'SSID 8 : ',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:71',
                    '         Signal             : 30%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 1 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    ''
                ) -join $nl) + $nl
        }
        'networks-clean-en' {
            return (@(
                    '',
                    'Interface name : Wi-Fi ',
                    'There are 3 networks currently visible. ',
                    '',
                    'SSID 1 : Harbor-Home',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:01',
                    '         Signal             : 90%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 1 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 2 : Neighbour-A',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:11',
                    '         Signal             : 28%  ',
                    '         Radio type         : 802.11n',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 11 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 3 : Neighbour-B',
                    '    Network type            : Infrastructure',
                    '    Authentication          : WPA2-Personal',
                    '    Encryption              : CCMP ',
                    '    BSSID 1                 : 02:aa:bb:cc:dd:21',
                    '         Signal             : 20%  ',
                    '         Radio type         : 802.11g',
                    '         Band               : 2.4 GHz',
                    '         Channel            : 6 ',
                    '         Basic rates (Mbps) : 1 2 5.5 11',
                    '         Other rates (Mbps) : 6 9 12 18 24 36 48 54',
                    ''
                ) -join $nl) + $nl
        }
        'networks-congested-de' {
            return (@(
                    '',
                    'Schnittstellenname : WLAN ',
                    'Derzeit sind 4 Netzwerke sichtbar. ',
                    '',
                    'SSID 1 : Harbor-Home',
                    '    Netzwerktyp             : Infrastruktur',
                    '    Authentifizierung       : WPA2-Personal',
                    ('    Verschl' + $ue + 'sselung         : CCMP '),
                    '    BSSID 1                 : 02:aa:bb:cc:dd:01',
                    '         Signal             : 94%  ',
                    '         Funktyp            : 802.11ax',
                    '         Band               : 2,4 GHz',
                    '         Kanal              : 6 ',
                    '         Bss Load:',
                    '             Verbundene Stationen:       3',
                    '             Kanalauslastung:            92 (36 %)',
                    ('             Verf' + $ue + 'gbare Medienkapazit' + [char]0xE4 + 't: 21875 (700 ms)'),
                    '         Basisraten (MBit/s) : 1 2 5,5 11',
                    '         Andere Raten (MBit/s) : 6 9 12 18 24 36 48 54',
                    '    BSSID 2                 : 02:aa:bb:cc:dd:02',
                    '         Signal             : 88%  ',
                    '         Funktyp            : 802.11ax',
                    '         Band               : 5 GHz',
                    '         Kanal              : 36 ',
                    '         Basisraten (MBit/s) : 6 12 24',
                    '         Andere Raten (MBit/s) : 9 18 36 48 54',
                    '',
                    'SSID 2 : Nachbar-A',
                    '    Netzwerktyp             : Infrastruktur',
                    '    Authentifizierung       : WPA2-Personal',
                    ('    Verschl' + $ue + 'sselung         : CCMP '),
                    '    BSSID 1                 : 02:aa:bb:cc:dd:11',
                    '         Signal             : 70%  ',
                    '         Funktyp            : 802.11n',
                    '         Band               : 2,4 GHz',
                    '         Kanal              : 6 ',
                    '         Basisraten (MBit/s) : 1 2 5,5 11',
                    '         Andere Raten (MBit/s) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 3 : Nachbar-B',
                    '    Netzwerktyp             : Infrastruktur',
                    '    Authentifizierung       : WPA2-Personal',
                    ('    Verschl' + $ue + 'sselung         : CCMP '),
                    '    BSSID 1                 : 02:aa:bb:cc:dd:21',
                    '         Signal             : 62%  ',
                    '         Funktyp            : 802.11ax',
                    '         Band               : 2,4 GHz',
                    '         Kanal              : 6 ',
                    '         Basisraten (MBit/s) : 1 2 5,5 11',
                    '         Andere Raten (MBit/s) : 6 9 12 18 24 36 48 54',
                    '',
                    'SSID 4 : Nachbar-E',
                    '    Netzwerktyp             : Infrastruktur',
                    '    Authentifizierung       : WPA2-Personal',
                    ('    Verschl' + $ue + 'sselung         : CCMP '),
                    '    BSSID 1                 : 02:aa:bb:cc:dd:51',
                    '         Signal             : 35%  ',
                    '         Funktyp            : 802.11n',
                    '         Band               : 2,4 GHz',
                    '         Kanal              : 11 ',
                    '         Basisraten (MBit/s) : 1 2 5,5 11',
                    '         Andere Raten (MBit/s) : 6 9 12 18 24 36 48 54',
                    ''
                ) -join $nl) + $nl
        }
        'profiles-en' {
            return (@(
                    '',
                    'Profiles on interface Wi-Fi:',
                    '',
                    'Group policy profiles (read only)',
                    '---------------------------------',
                    '    <None>',
                    '',
                    'User profiles',
                    '-------------',
                    '    All User Profile     : Harbor-Home',
                    '    All User Profile     : Coffee-Guest',
                    ''
                ) -join $nl) + $nl
        }
        'profiles-one-en' {
            return (@(
                    '',
                    'Profiles on interface Wi-Fi:',
                    '',
                    'Group policy profiles (read only)',
                    '---------------------------------',
                    '    <None>',
                    '',
                    'User profiles',
                    '-------------',
                    '    All User Profile     : Harbor-Home',
                    ''
                ) -join $nl) + $nl
        }
        'profiles-de' {
            return (@(
                    '',
                    'Profile auf Schnittstelle WLAN:',
                    '',
                    ('Gruppenrichtlinienprofile (schreibgesch' + $ue + 'tzt)'),
                    '---------------------------------',
                    '    <Keine>',
                    '',
                    'Benutzerprofile',
                    '-------------',
                    ('    Profil f' + $ue + 'r alle Benutzer     : Harbor-Home'),
                    ''
                ) -join $nl) + $nl
        }
        'wlan-report' {
            return (@(
                    '<!DOCTYPE html>',
                    '<html><head><meta charset="utf-8"><title>Wireless Network Report</title></head>',
                    '<body>',
                    '<h1>Wi-Fi Summary</h1>',
                    '<p>Report generated 2026-02-28 by a synthetic machine.</p>',
                    '<h2>Network Adapters</h2>',
                    '<table><tr><td>Synthetic Wi-Fi 6E AX Adapter</td><td>02:11:22:33:44:55</td></tr></table>',
                    '<h2>Script Output</h2>',
                    '<pre>',
                    'Profile Harbor-Home on interface Wi-Fi:',
                    '    SSID name              : &quot;Harbor-Home&quot;',
                    '    Connection mode        : Connect automatically',
                    'Profile Coffee-Guest on interface Wi-Fi:',
                    '    SSID name              : &quot;Coffee-Guest&quot;',
                    '</pre>',
                    '<h2>Wireless Sessions</h2>',
                    '<table><tr><td>Session 1</td><td>Harbor-Home</td><td>02-AA-BB-CC-DD-01</td><td>Disconnected by user</td></tr></table>',
                    '<table><tr><td>Session 2</td><td>Unseen-Guest</td><td>02-AA-BB-CC-DD-99</td><td>Disconnected by user</td></tr></table>',
                    '</body></html>'
                ) -join "`n") + "`n"
        }
    }
    throw ('no synthetic netsh text named ' + $Name)
}

function New-WfSyntheticConfigMachine {
    # The invented machine behind the config-snapshot cases. Every value is
    # made up: device names, masks, versions, file text. Variants:
    #   full    every key present, both programs installed, helper running
    #   clean   no tuning keys, nothing installed, German powercfg output
    #   denied  every read refused
    param([string]$Variant)
    $gpu = 'PCI\VEN_FFFF&DEV_0001\4&1a2b3c4d&0&0008'
    $nic = 'PCI\VEN_FFF0&DEV_8125\4&3a2b1c0d&0&00E0'
    $xhci = 'PCI\VEN_FFF0&DEV_A36D\3&11583659&0&A0'
    $hdaController = 'PCI\VEN_FFF0&DEV_A348\3&11583659&0&FB'
    $nvme = 'PCI\VEN_FFF2&DEV_5017\4&2b3c4d5e&0&0010'
    $codec = 'HDAUDIO\FUNC_01&VEN_FFFF&DEV_0002&SUBSYS_00000001\5&2f3e4d5c&0&0001'
    $mouse = 'USB\VID_FFF1&PID_C539\6&1234abcd&0&3'
    # An invented remembered Bluetooth audio peer: class MEDIA, named after its owner, its address in the id.
    $earbuds = 'BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_VID&0001004c_PID&200e\7&1a2b3c4d&0&F0F1F2000001_C00000000'
    $devices = New-Object 'System.Collections.Generic.List[object]'
    $devices.Add(@{ instance_id = 'ROOT\ACPI_HAL\0000'; class = 'Computer'; name = 'ACPI x64-based PC'; description = 'ACPI x64-based PC'; manufacturer = '(Standard computers)'; service = $null; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('acpiapic'); compatible_ids = @() })
    $devices.Add(@{ instance_id = $gpu; class = 'Display'; name = 'Synthetic Display Adapter'; description = 'Synthetic Display Adapter'; manufacturer = 'Synthetic Graphics'; service = 'syngfx'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFFF&DEV_0001&SUBSYS_0001FFFF&REV_A1'); compatible_ids = @('PCI\CC_030000') })
    $devices.Add(@{ instance_id = $nic; class = 'Net'; name = 'Synthetic 2.5GbE Controller'; description = 'Synthetic 2.5GbE Controller'; manufacturer = 'Synthetic Networks'; service = 'syneth'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_8125&SUBSYS_0001FFF0&REV_05'); compatible_ids = @('PCI\CC_020000') })
    $devices.Add(@{ instance_id = $xhci; class = 'USB'; name = 'Synthetic USB 3.1 eXtensible Host Controller'; description = 'Synthetic USB 3.1 eXtensible Host Controller'; manufacturer = 'Synthetic Chipsets'; service = 'USBXHCI'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_A36D&SUBSYS_0001FFF0&REV_10'); compatible_ids = @('PCI\CC_0C0330') })
    $devices.Add(@{ instance_id = $hdaController; class = 'System'; name = 'Synthetic High Definition Audio Controller'; description = 'High Definition Audio Controller'; manufacturer = 'Microsoft'; service = 'HDAudBus'; status = $(if ($Variant -eq 'full') { 'Error' } else { 'OK' }); problem_code = $(if ($Variant -eq 'full') { 22 } else { 0 }); present = $true; hardware_ids = @('PCI\VEN_FFF0&DEV_A348&SUBSYS_0001FFF0&REV_10'); compatible_ids = @('PCI\CC_0403') })
    $devices.Add(@{ instance_id = $nvme; class = 'SCSIAdapter'; name = 'Synthetic NVMe Controller'; description = 'Standard NVM Express Controller'; manufacturer = 'Microsoft'; service = 'stornvme'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('PCI\VEN_FFF2&DEV_5017&SUBSYS_0001FFF2&REV_01'); compatible_ids = @('PCI\CC_010802') })
    $devices.Add(@{ instance_id = $codec; class = 'MEDIA'; name = 'Synthetic High Definition Audio Device'; description = 'Synthetic High Definition Audio Device'; manufacturer = 'Synthetic Audio'; service = 'synaud'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('HDAUDIO\FUNC_01&VEN_FFFF&DEV_0002'); compatible_ids = @() })
    $devices.Add(@{ instance_id = $mouse; class = 'USB'; name = 'Synthetic Wireless Receiver'; description = 'USB Composite Device'; manufacturer = '(Standard USB Host Controller)'; service = 'usbccgp'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('USB\VID_FFF1&PID_C539&REV_0401'); compatible_ids = @('USB\COMPOSITE') })
    $devices.Add(@{ instance_id = $earbuds; class = 'MEDIA'; name = 'Jane Doe Earbuds Stereo'; description = 'Jane Doe Earbuds Stereo'; manufacturer = 'Microsoft'; service = 'BthA2dp'; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @('BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_VID&0001004c_PID&200e'); compatible_ids = @() })
    $devices.Add(@{ instance_id = 'SWD\PRINTENUM\{a1b2c3d4-0000-4000-8000-000000000011}'; class = 'PrintQueue'; name = 'Synthetic PDF Printer'; description = 'Synthetic PDF Printer'; manufacturer = 'Synthetic'; service = $null; status = 'OK'; problem_code = 0; present = $true; hardware_ids = @(); compatible_ids = @() })
    $global:WfSynthetic.Pnp = @{ Devices = $devices.ToArray() }

    # The device hardware keys, as the native recorder serves them, and the
    # fixed GraphicsDrivers key, as the registry provider serves it.
    $deviceKeys = @{}
    $registry = @{}
    $graphics = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
    $affinity = 'Interrupt Management\Affinity Policy'
    $msi = 'Interrupt Management\MessageSignaledInterruptProperties'
    if ($Variant -eq 'denied') {
        foreach ($instance in @($gpu, $nic, $xhci, $hdaController, $nvme)) { $deviceKeys[$instance] = @{ HardwareKey = 'denied' } }
        $registry[$graphics] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Requested registry access is not allowed.' }
    } elseif ($Variant -eq 'clean') {
        # Hardware keys exist (every installed device has one) but hold no Interrupt Management.
        foreach ($instance in @($gpu, $nic, $xhci, $hdaController, $nvme)) { $deviceKeys[$instance] = @{ HardwareKey = 'exists'; Subkeys = @{} } }
        $registry[$graphics] = @{ Values = @(@{ Name = 'HwSchMode'; Kind = 'DWord'; Data = 2 }); SubKeys = @('Configuration', 'Connectivity') }
    } else {
        # The display adapter pinned to one logical processor (bit 5 of group 0), the mask as REG_BINARY little
        # endian; a priority value whose registry name Microsoft does not document is present and kept as it is.
        $deviceKeys[$gpu] = @{ HardwareKey = 'exists'; Subkeys = @{
                $affinity = @{ Values = @(
                        @{ Name = 'DevicePolicy'; Type = 4; Bytes = [byte[]](4, 0, 0, 0) },
                        @{ Name = 'AssignmentSetOverride'; Type = 3; Bytes = [byte[]](0x20, 0, 0, 0, 0, 0, 0, 0) },
                        @{ Name = 'DevicePriority'; Type = 4; Bytes = [byte[]](3, 0, 0, 0) }
                    ) }
                $msi = @{ Values = @(
                        @{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](1, 0, 0, 0) },
                        @{ Name = 'MessageNumberLimit'; Type = 4; Bytes = [byte[]](16, 0, 0, 0) }
                    ) }
            } }
        # The network adapter spread over four logical processors, the mask as REG_DWORD; one value needs a larger buffer.
        $deviceKeys[$nic] = @{ HardwareKey = 'exists'; Subkeys = @{
                $affinity = @{ Values = @(
                        @{ Name = 'DevicePolicy'; Type = 4; Bytes = [byte[]](4, 0, 0, 0) },
                        @{ Name = 'AssignmentSetOverride'; Type = 4; Bytes = [byte[]](0x00, 0x0F, 0, 0) }
                    ); MoreData = 8192 }
                $msi = @{ Values = @(
                        @{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](1, 0, 0, 0) },
                        @{ Name = 'MessageNumberLimit'; Type = 4; Bytes = [byte[]](32, 0, 0, 0) }
                    ) }
            } }
        # The USB host controller on one processor, the mask as REG_QWORD, no MSI key, and a string typed note nobody documents.
        $deviceKeys[$xhci] = @{ HardwareKey = 'exists'; Subkeys = @{
                $affinity = @{ Values = @(
                        @{ Name = 'DevicePolicy'; Type = 4; Bytes = [byte[]](4, 0, 0, 0) },
                        @{ Name = 'AssignmentSetOverride'; Type = 11; Bytes = [byte[]](4, 0, 0, 0, 0, 0, 0, 0) },
                        @{ Name = 'Comment'; Type = 1; Bytes = [System.Text.Encoding]::Unicode.GetBytes("set by Synthetic Owner`0") }
                    ) }
            } }
        # The HD Audio controller, disabled in Device Manager, with MSI switched off and no affinity policy.
        $deviceKeys[$hdaController] = @{ HardwareKey = 'exists'; Subkeys = @{
                $msi = @{ Values = @(@{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](0, 0, 0, 0) }) }
            } }
        # The storage controller spreads its messages (policy 5) and has no mask.
        $deviceKeys[$nvme] = @{ HardwareKey = 'exists'; Subkeys = @{
                $affinity = @{ Values = @(@{ Name = 'DevicePolicy'; Type = 4; Bytes = [byte[]](5, 0, 0, 0) }) }
                $msi = @{ Values = @(@{ Name = 'MSISupported'; Type = 4; Bytes = [byte[]](1, 0, 0, 0) }, @{ Name = 'MessageNumberLimit'; Type = 4; Bytes = [byte[]](8, 0, 0, 0) }) }
            } }
        $registry[$graphics] = @{ Values = @(
                @{ Name = 'HwSchMode'; Kind = 'DWord'; Data = 2 },
                @{ Name = 'TdrLevel'; Kind = 'DWord'; Data = 3 },
                @{ Name = 'TdrDelay'; Kind = 'DWord'; Data = 10 }
            ); SubKeys = @('Configuration', 'Connectivity') }
    }
    $global:WfSynthetic.DeviceKeys = $deviceKeys
    $global:WfSynthetic.Registry = $registry

    # CPU topology: Win32_Processor and Win32_CacheMemory as WMI reports them
    # (one socket, six cores, twelve logical processors, three cache levels)
    # and the GetLogicalProcessorInformationEx buffer with the siblings
    # interleaved (core i holds logical processors i and i + 6).
    if ($Variant -eq 'denied') {
        $global:WfSynthetic.Cim['Win32_Processor'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
        $global:WfSynthetic.Cim['Win32_CacheMemory'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
        $global:WfSynthetic.Cim['Win32_Process'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
        $global:WfSynthetic.Topology = @{ Stage = 'compile'; ErrorMessage = 'synthetic backend: the compiler is not available' }
        $global:WfSynthetic.DeviceKeyCompile = 'ok'
    } else {
        $global:WfSynthetic.Topology = @{ Bytes = (New-WfSyntheticLpiBuffer -Cores 6 -Groups 1 -Interleaved $true) }
        $global:WfSynthetic.Cim['Win32_Processor'] = @{ Rows = @(
                [ordered]@{ DeviceID = 'CPU0'; Name = 'Synthetic CPU 6-Core Processor'; Manufacturer = 'SyntheticSilicon'; Description = 'Synthetic Family 1 Model 2 Stepping 3'; SocketDesignation = 'AM0'; NumberOfCores = 6; NumberOfEnabledCore = 6; NumberOfLogicalProcessors = 12; ThreadCount = 12; L2CacheSize = 6144; L3CacheSize = 32768; MaxClockSpeed = 4700; CurrentClockSpeed = 4700; Architecture = 9; Family = 107; Level = 25; Revision = 8448; Stepping = '2'; ProcessorId = '0000000000000000'; VirtualizationFirmwareEnabled = $true; SecondLevelAddressTranslationExtensions = $true; Status = 'OK'; CpuStatus = 1; Availability = 3 }
            )
        }
        $global:WfSynthetic.Cim['Win32_CacheMemory'] = @{ Rows = @(
                [ordered]@{ DeviceID = 'Cache Memory 0'; Purpose = 'L1 Cache'; Level = 3; CacheType = 5; Associativity = 7; InstalledSize = 384; MaxCacheSize = 384; BlockSize = 64; NumberOfBlocks = 6144; LineSize = 64; CacheSpeed = $null; Location = 0; Status = 'OK'; ErrorCorrectType = 5; WritePolicy = 3 },
                [ordered]@{ DeviceID = 'Cache Memory 1'; Purpose = 'L2 Cache'; Level = 4; CacheType = 5; Associativity = 7; InstalledSize = 6144; MaxCacheSize = 6144; BlockSize = 64; NumberOfBlocks = 98304; LineSize = 64; CacheSpeed = $null; Location = 0; Status = 'OK'; ErrorCorrectType = 5; WritePolicy = 3 },
                [ordered]@{ DeviceID = 'Cache Memory 2'; Purpose = 'L3 Cache'; Level = 5; CacheType = 5; Associativity = 8; InstalledSize = 32768; MaxCacheSize = 32768; BlockSize = 64; NumberOfBlocks = 524288; LineSize = 64; CacheSpeed = $null; Location = 0; Status = 'OK'; ErrorCorrectType = 5; WritePolicy = 3 }
            )
        }
        $created = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddHours(-3)
        $processes = New-Object 'System.Collections.Generic.List[object]'
        $processes.Add([ordered]@{ Name = 'System'; ProcessId = 4; ParentProcessId = 0; SessionId = 0; CreationDate = $created; Priority = 8; ThreadCount = 240; HandleCount = 4100; WorkingSetSize = 122880; PageFaults = 1200; KernelModeTime = 912500000; UserModeTime = 0; CommandLine = $null; ExecutablePath = $null })
        $processes.Add([ordered]@{ Name = 'explorer.exe'; ProcessId = 4120; ParentProcessId = 4000; SessionId = 1; CreationDate = $created; Priority = 8; ThreadCount = 70; HandleCount = 2900; WorkingSetSize = 180355072; PageFaults = 540000; KernelModeTime = 150000000; UserModeTime = 310000000; CommandLine = 'C:\Windows\Explorer.EXE'; ExecutablePath = 'C:\Windows\Explorer.EXE' })
        $processes.Add([ordered]@{ Name = 'dwm.exe'; ProcessId = 1500; ParentProcessId = 1420; SessionId = 1; CreationDate = $created; Priority = 13; ThreadCount = 20; HandleCount = 1200; WorkingSetSize = 90112000; PageFaults = 220000; KernelModeTime = 400000000; UserModeTime = 900000000; CommandLine = $null; ExecutablePath = $null })
        if ($Variant -eq 'full') {
            $processes.Add([ordered]@{ Name = 'ProcessLasso.exe'; ProcessId = 6100; ParentProcessId = 4120; SessionId = 1; CreationDate = $created; Priority = 8; ThreadCount = 14; HandleCount = 600; WorkingSetSize = 40960000; PageFaults = 30000; KernelModeTime = 12000000; UserModeTime = 48000000; CommandLine = '"C:\Program Files\Process Lasso\ProcessLasso.exe" /tray'; ExecutablePath = 'C:\Program Files\Process Lasso\ProcessLasso.exe' })
            $processes.Add([ordered]@{ Name = 'ProcessGovernor.exe'; ProcessId = 6140; ParentProcessId = 6100; SessionId = 1; CreationDate = $created; Priority = 13; ThreadCount = 9; HandleCount = 450; WorkingSetSize = 20480000; PageFaults = 12000; KernelModeTime = 30000000; UserModeTime = 25000000; CommandLine = '"C:\Program Files\Process Lasso\ProcessGovernor.exe"'; ExecutablePath = 'C:\Program Files\Process Lasso\ProcessGovernor.exe' })
            $processes.Add([ordered]@{ Name = 'bitsumsessionagent.exe'; ProcessId = 6180; ParentProcessId = 1100; SessionId = 1; CreationDate = $created; Priority = 8; ThreadCount = 3; HandleCount = 120; WorkingSetSize = 8192000; PageFaults = 3000; KernelModeTime = 1000000; UserModeTime = 500000; CommandLine = $null; ExecutablePath = $null })
            # The timer helper started from a copy under the owner's profile: its path must leave as a pseudonym.
            $processes.Add([ordered]@{ Name = 'DpcTimerRes.exe'; ProcessId = 7000; ParentProcessId = 1100; SessionId = 0; CreationDate = $created; Priority = 8; ThreadCount = 2; HandleCount = 60; WorkingSetSize = 4096000; PageFaults = 900; KernelModeTime = 500000; UserModeTime = 200000; CommandLine = '"C:\Users\Synthetic Owner\Downloads\Stutter Guard\DpcTimerRes.exe" 10000'; ExecutablePath = 'C:\Users\Synthetic Owner\Downloads\Stutter Guard\DpcTimerRes.exe' })
        }
        $global:WfSynthetic.Cim['Win32_Process'] = @{ Rows = $processes.ToArray() }
    }

    # powercfg listings, English in the full variant and an invented German
    # translation in the clean one; /qh fails there, as a tool that refuses
    # the hidden listing would.
    if ($Variant -eq 'denied') {
        $global:WfSynthetic.PowercfgPresent = $false
    } else {
        $language = $(if ($Variant -eq 'full') { 'en' } else { 'de' })
        $global:WfSynthetic.Commands['/getactivescheme'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name ('getactivescheme-' + $language)); StdErr = '' }
        $global:WfSynthetic.Commands['/list'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name ('list-' + $language)); StdErr = '' }
        $global:WfSynthetic.Commands['/aliases'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name 'aliases'); StdErr = '' }
        $global:WfSynthetic.Commands['/query'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name ('query-' + $language)); StdErr = '' }
        if ($Variant -eq 'full') {
            $global:WfSynthetic.Commands['/qh'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name 'qh-en'); StdErr = '' }
        } else {
            $global:WfSynthetic.Commands['/qh'] = @{ ExitCode = 1; StdOut = ''; StdErr = "Invalid Parameters -- try `"/?`" for help`r`n" }
        }
    }

    # The install folders and the owner's files. The INI, the log and the
    # journal carry a user profile path, an e-mail shaped token and a UNC host
    # on purpose, so the tests can show that none reaches the bundle in clear.
    $global:WfSynthetic.Directories = @{}
    $global:WfSynthetic.Files = @{}
    if ($Variant -eq 'full') {
        $written = ConvertTo-WfUtcString -Value $global:WfSynthetic.Now.AddDays(-20)
        $global:WfSynthetic.Directories['C:\Program Files\Process Lasso'] = @{ Files = @(
                @{ name = 'bitsumsessionagent.exe'; bytes = 210944; last_write_time_utc = $written; sha256 = ('a1' * 32); file_version = '19.0.0.94'; product_version = '19.0.0.94'; product_name = 'Process Lasso'; company_name = 'Bitsum LLC'; original_filename = 'bitsumsessionagent.exe' },
                @{ name = 'IRQControl.exe'; bytes = 1048576; last_write_time_utc = $written; sha256 = ('a2' * 32); file_version = '1.0.0.26'; product_version = '1.0.0.26'; product_name = 'IRQControl'; company_name = 'Bitsum LLC'; original_filename = 'IRQControl.exe' },
                @{ name = 'LatencyTest.exe'; bytes = 1572864; last_write_time_utc = $written; sha256 = ('a3' * 32); file_version = '1.0.0.26'; product_version = '1.0.0.26'; product_name = 'LatencyTest'; company_name = 'Bitsum LLC'; original_filename = 'LatencyTest.exe' },
                @{ name = 'ProcessGovernor.exe'; bytes = 3145728; last_write_time_utc = $written; sha256 = ('a4' * 32); file_version = '19.0.0.94'; product_version = '19.0.0.94'; product_name = 'Process Lasso'; company_name = 'Bitsum LLC'; original_filename = 'ProcessGovernor.exe' },
                @{ name = 'ProcessLasso.exe'; bytes = 7340032; last_write_time_utc = $written; sha256 = ('a5' * 32); file_version = '19.0.0.94'; product_version = '19.0.0.94'; product_name = 'Process Lasso'; company_name = 'Bitsum LLC'; original_filename = 'ProcessLasso.exe' },
                @{ name = 'prolasso.chm'; bytes = 524288; last_write_time_utc = $written; sha256 = ('a6' * 32) }
            )
        }
        $global:WfSynthetic.Directories['C:\Program Files\Stutter Guard'] = @{ Files = @(
                @{ name = 'DpcTimerRes.exe'; bytes = 143360; last_write_time_utc = $written; sha256 = ('b1' * 32); file_version = '1.3.0.0'; product_version = '1.3.0'; product_name = 'Stutter Guard'; company_name = $null; original_filename = 'DpcTimerRes.exe' },
                @{ name = 'StutterGuard.exe'; bytes = 70254592; last_write_time_utc = $written; sha256 = ('b2' * 32); file_version = '1.3.0.0'; product_version = '1.3.0'; product_name = 'Stutter Guard'; company_name = $null; original_filename = 'StutterGuard.exe' }
            )
        }
        $nl = "`r`n"
        $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\config\prolasso.ini'] = @{ Text = (@(
                    '[Administration]',
                    'LogPath=C:\ProgramData\ProcessLasso\logs',
                    'ConfigPath=\\DESKTOP-SYNTH01\ProcessLasso\config',
                    '[OutOfControlProcessRestraint]',
                    'Enabled=true',
                    'RestraintPriority=belownormal',
                    'ExcludedProcesses=C:\Users\Synthetic Owner\Games\launcher.exe',
                    '[GUI]',
                    'ShowGraphLicenseName=false',
                    'SupportContact=owner@example.test',
                    '[GPUAdapters]',
                    'Preferences=C:\Users\Synthetic Owner\Games\game.exe,1',
                    '[Logging]',
                    'LogDisable=false',
                    'IncludeCommandLines=false',
                    '[PowerManagement]',
                    'TargetPowerPlan=Synthetic Low Latency',
                    ''
                ) -join $nl)
        }
        $global:WfSynthetic.Files['C:\ProgramData\ProcessLasso\logs\processlasso.log'] = @{ Text = (@(
                    '"Date","Time","Action","Process","PID","Details"',
                    '"2026-02-09","19:02:11","ProBalance","example.exe","8120","Priority lowered to Below Normal"',
                    '"2026-02-09","19:02:41","ProBalance","example.exe","8120","Priority restored to Normal"',
                    '"2026-02-10","08:14:02","Rule","C:\Users\Synthetic Owner\Games\game.exe","9344","GPU adapter preference set"',
                    ''
                ) -join $nl)
        }
        $global:WfSynthetic.Files['C:\ProgramData\Stutter Guard\journal.json'] = @{ Text = (@(
                    '{',
                    '  "version": 3,',
                    '  "records": [',
                    ('    { "tweak": "interrupts", "kind": "registry", "target": "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\' + $gpu.Replace('\', '\\') + '\\Device Parameters\\Interrupt Management\\Affinity Policy\\DevicePolicy", "old": null, "new": 4, "at": "2026-02-01T10:00:00Z" },'),
                    '    { "tweak": "boot-tasks", "kind": "task", "target": "Timer resolution", "old": null, "new": "enabled", "at": "2026-02-01T10:00:05Z" }',
                    '  ],',
                    '  "options": { "profile": "Full", "applyOnBattery": false, "exportedBy": "C:\\Users\\Synthetic Owner\\Desktop" }',
                    '}',
                    ''
                ) -join "`n")
        }
    } elseif ($Variant -eq 'denied') {
        $global:WfSynthetic.Directories['C:\Program Files\Process Lasso'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access to the path is denied.' }
        $global:WfSynthetic.Directories['C:\Program Files\Stutter Guard'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access to the path is denied.' }
        foreach ($path in @('C:\ProgramData\ProcessLasso\config\prolasso.ini', 'C:\ProgramData\ProcessLasso\logs\processlasso.log', 'C:\ProgramData\Stutter Guard\journal.json')) {
            $global:WfSynthetic.Files[$path] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access to the path is denied.' }
        }
    }
}

function Get-WfSyntheticPowercfgText {
    # Invented powercfg listings. The English layout follows what the tool
    # prints (a GUID per scheme, subgroup, setting and alias line, the
    # possible settings and the current AC and DC indices as hex); the German
    # one is an invented translation with the same GUIDs and hex values, so a
    # decoder that relies on structure reads the same numbers from both.
    param([string]$Name)
    $nl = "`r`n"
    $scheme = '11111111-2222-4333-8444-555555555555'
    switch ($Name) {
        'getactivescheme-en' { return ('Power Scheme GUID: ' + $scheme + '  (Synthetic Low Latency)' + $nl) }
        'getactivescheme-de' { return ('GUID des Energieschemas: 381b4222-f694-41f0-9685-ff5bb260df2e  (Ausbalanciert)' + $nl) }
        'list-en' {
            return (@(
                    '',
                    'Existing Power Schemes (* Active)',
                    '-----------------------------------',
                    'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)',
                    'Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)',
                    'Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)',
                    ('Power Scheme GUID: ' + $scheme + '  (Synthetic Low Latency) *'),
                    ''
                ) -join $nl)
        }
        'list-de' {
            return (@(
                    '',
                    'Vorhandene Energieschemas (* Aktiv)',
                    '-----------------------------------',
                    'GUID des Energieschemas: 381b4222-f694-41f0-9685-ff5bb260df2e  (Ausbalanciert) *',
                    'GUID des Energieschemas: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (Hoechstleistung)',
                    'GUID des Energieschemas: a1841308-3541-4fab-bc81-f71556f20b4a  (Energiesparmodus)',
                    ''
                ) -join $nl)
        }
        'aliases' {
            return (@(
                    'a1841308-3541-4fab-bc81-f71556f20b4a  SCHEME_MAX',
                    '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  SCHEME_MIN',
                    '381b4222-f694-41f0-9685-ff5bb260df2e  SCHEME_BALANCED',
                    '54533251-82be-4824-96c1-47b60b740d00  SUB_PROCESSOR',
                    '  893dee8e-2bef-41e0-89c6-b55d0929964c  PROCTHROTTLEMIN',
                    '  bc5038f7-23e0-4960-96da-33abaf5935ec  PROCTHROTTLEMAX',
                    '  0cc5b647-c1df-4637-891a-dec35c318583  CPMINCORES',
                    '  ea062031-0e34-4ff1-9b6d-eb1059334028  CPMAXCORES',
                    '  5d76a2ca-e8c0-402f-a133-2158492d58ad  IDLEDISABLE',
                    '  be337238-0d82-4146-a960-4f3749d470c7  PERFBOOSTMODE',
                    '  45bcc044-d885-43e2-8605-ee0ec6e96b59  PERFBOOSTPOL',
                    '  36687f9e-e3a5-4dbf-b1dc-15eb381c6863  PERFEPP',
                    '7516b95f-f776-4464-8c53-06167f40cc99  SUB_VIDEO',
                    '  3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e  VIDEOIDLE',
                    ''
                ) -join $nl)
        }
        'query-en' {
            return (@(
                    ('Power Scheme GUID: ' + $scheme + '  (Synthetic Low Latency)'),
                    '  Subgroup GUID: 54533251-82be-4824-96c1-47b60b740d00  (Processor power management)',
                    '    GUID Alias: SUB_PROCESSOR',
                    '    Power Setting GUID: 893dee8e-2bef-41e0-89c6-b55d0929964c  (Minimum processor state)',
                    '      GUID Alias: PROCTHROTTLEMIN',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000064',
                    '    Current DC Power Setting Index: 0x00000005',
                    '',
                    '    Power Setting GUID: bc5038f7-23e0-4960-96da-33abaf5935ec  (Maximum processor state)',
                    '      GUID Alias: PROCTHROTTLEMAX',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000064',
                    '    Current DC Power Setting Index: 0x00000064',
                    '',
                    '    Power Setting GUID: be337238-0d82-4146-a960-4f3749d470c7  (Processor performance boost mode)',
                    '      GUID Alias: PERFBOOSTMODE',
                    '      Possible Setting Index: 000',
                    '      Possible Setting Friendly Name: Disabled',
                    '      Possible Setting Index: 001',
                    '      Possible Setting Friendly Name: Enabled',
                    '      Possible Setting Index: 002',
                    '      Possible Setting Friendly Name: Aggressive',
                    '    Current AC Power Setting Index: 0x00000002',
                    '    Current DC Power Setting Index: 0x00000001',
                    '',
                    '  Subgroup GUID: 7516b95f-f776-4464-8c53-06167f40cc99  (Display)',
                    '    GUID Alias: SUB_VIDEO',
                    '    Power Setting GUID: 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e  (Turn off display after)',
                    '      GUID Alias: VIDEOIDLE',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0xffffffff',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: Seconds',
                    '    Current AC Power Setting Index: 0x00000000',
                    '    Current DC Power Setting Index: 0x0000012c',
                    ''
                ) -join $nl)
        }
        'qh-en' {
            return (@(
                    ('Power Scheme GUID: ' + $scheme + '  (Synthetic Low Latency)'),
                    '  Subgroup GUID: 54533251-82be-4824-96c1-47b60b740d00  (Processor power management)',
                    '    GUID Alias: SUB_PROCESSOR',
                    '    Power Setting GUID: 0cc5b647-c1df-4637-891a-dec35c318583  (Processor performance core parking min cores)',
                    '      GUID Alias: CPMINCORES',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000064',
                    '    Current DC Power Setting Index: 0x00000064',
                    '',
                    '    Power Setting GUID: ea062031-0e34-4ff1-9b6d-eb1059334028  (Processor performance core parking max cores)',
                    '      GUID Alias: CPMAXCORES',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000064',
                    '    Current DC Power Setting Index: 0x00000064',
                    '',
                    '    Power Setting GUID: 5d76a2ca-e8c0-402f-a133-2158492d58ad  (Processor idle disable)',
                    '      GUID Alias: IDLEDISABLE',
                    '      Possible Setting Index: 000',
                    '      Possible Setting Friendly Name: Enable idle',
                    '      Possible Setting Index: 001',
                    '      Possible Setting Friendly Name: Disable idle',
                    '    Current AC Power Setting Index: 0x00000001',
                    '    Current DC Power Setting Index: 0x00000000',
                    '',
                    '    Power Setting GUID: 893dee8e-2bef-41e0-89c6-b55d0929964c  (Minimum processor state)',
                    '      GUID Alias: PROCTHROTTLEMIN',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000064',
                    '    Current DC Power Setting Index: 0x00000005',
                    '',
                    '    Power Setting GUID: 36687f9e-e3a5-4dbf-b1dc-15eb381c6863  (Processor energy performance preference policy)',
                    '      GUID Alias: PERFEPP',
                    '      Minimum Possible Setting: 0x00000000',
                    '      Maximum Possible Setting: 0x00000064',
                    '      Possible Settings increment: 0x00000001',
                    '      Possible Settings units: %',
                    '    Current AC Power Setting Index: 0x00000000',
                    '    Current DC Power Setting Index: 0x00000032',
                    ''
                ) -join $nl)
        }
        'query-de' {
            return (@(
                    'GUID des Energieschemas: 381b4222-f694-41f0-9685-ff5bb260df2e  (Ausbalanciert)',
                    '  GUID der Untergruppe: 54533251-82be-4824-96c1-47b60b740d00  (Prozessorenergieverwaltung)',
                    '    GUID-Alias: SUB_PROCESSOR',
                    '    GUID der Energieeinstellung: 893dee8e-2bef-41e0-89c6-b55d0929964c  (Minimaler Leistungszustand des Prozessors)',
                    '      GUID-Alias: PROCTHROTTLEMIN',
                    '      Minimale moegliche Einstellung: 0x00000000',
                    '      Maximale moegliche Einstellung: 0x00000064',
                    '      Schrittweite der moeglichen Einstellungen: 0x00000001',
                    '      Einheiten der moeglichen Einstellungen: %',
                    '    Aktueller Index der Netzbetriebseinstellung: 0x00000005',
                    '    Aktueller Index der Akkubetriebseinstellung: 0x00000005',
                    '',
                    '    GUID der Energieeinstellung: be337238-0d82-4146-a960-4f3749d470c7  (Modus zur Leistungssteigerung des Prozessors)',
                    '      GUID-Alias: PERFBOOSTMODE',
                    '      Index der moeglichen Einstellung: 000',
                    '      Anzeigename der moeglichen Einstellung: Deaktiviert',
                    '      Index der moeglichen Einstellung: 001',
                    '      Anzeigename der moeglichen Einstellung: Aktiviert',
                    '    Aktueller Index der Netzbetriebseinstellung: 0x00000001',
                    '    Aktueller Index der Akkubetriebseinstellung: 0x00000001',
                    ''
                ) -join $nl)
        }
    }
    throw ('no synthetic powercfg text named ' + $Name)
}

function New-WfSyntheticGroupAffinity {
    # One GROUP_AFFINITY: KAFFINITY mask (8), WORD group, WORD Reserved[3].
    param([uint64]$Mask, [int]$Group = 0)
    $bytes = New-Object byte[] 16
    [System.Array]::Copy([System.BitConverter]::GetBytes($Mask), 0, $bytes, 0, 8)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]$Group), 0, $bytes, 8, 2)
    return , $bytes
}

function New-WfSyntheticLpiRecord {
    # One SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX record: DWORD relationship, DWORD size, body.
    param([int]$Relationship, [byte[]]$Body)
    $size = 8 + $Body.Length
    $bytes = New-Object byte[] $size
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$Relationship), 0, $bytes, 0, 4)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$size), 0, $bytes, 4, 4)
    [System.Array]::Copy($Body, 0, $bytes, 8, $Body.Length)
    return , $bytes
}

function New-WfSyntheticLpiBuffer {
    # An invented GetLogicalProcessorInformationEx buffer following the
    # documented 64 bit layouts: $Cores cores in group 0, each with two logical
    # processors whose indices are i and i + $Cores (interleaved siblings, so
    # the decoder cannot get them right by assuming adjacency), an L1 data and
    # L1 instruction cache per core, an L2 per core, one L3 shared by every
    # core, one package, one NUMA node and one group. -Groups 2 adds a second
    # group with its own cores, for the parser test.
    param([int]$Cores = 6, [int]$Groups = 1, [bool]$Interleaved = $true)
    $parts = New-Object 'System.Collections.Generic.List[byte[]]'
    $groupMasks = New-Object 'System.Collections.Generic.List[uint64]'
    for ($group = 0; $group -lt $Groups; $group++) {
        $all = [uint64]0
        for ($core = 0; $core -lt $Cores; $core++) {
            $first = $core
            $second = $core + $Cores
            if (-not $Interleaved) { $first = 2 * $core; $second = 2 * $core + 1 }
            $mask = ([uint64]1 -shl $first) -bor ([uint64]1 -shl $second)
            $all = $all -bor $mask
            # PROCESSOR_RELATIONSHIP: Flags (LTP_PC_SMT = 1), EfficiencyClass, RelativePerformance, RelativeEfficiency, Reserved[16], GroupCount at 22, GroupMask at 24.
            $body = New-Object byte[] 40
            $body[0] = 1
            [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]1), 0, $body, 22, 2)
            [System.Array]::Copy((New-WfSyntheticGroupAffinity -Mask $mask -Group $group), 0, $body, 24, 16)
            $parts.Add((New-WfSyntheticLpiRecord -Relationship 0 -Body $body))
            # Caches per core: L1 data (type 2), L1 instruction (type 1), L2 unified (type 0).
            foreach ($cache in @(@{ Level = 1; Type = 2; Size = 32768 }, @{ Level = 1; Type = 1; Size = 32768 }, @{ Level = 2; Type = 0; Size = 1048576 })) {
                $cacheBody = New-Object byte[] 48
                $cacheBody[0] = [byte]$cache['Level']
                $cacheBody[1] = 8
                [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]64), 0, $cacheBody, 2, 2)
                [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$cache['Size']), 0, $cacheBody, 4, 4)
                [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$cache['Type']), 0, $cacheBody, 8, 4)
                [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]1), 0, $cacheBody, 30, 2)
                [System.Array]::Copy((New-WfSyntheticGroupAffinity -Mask $mask -Group $group), 0, $cacheBody, 32, 16)
                $parts.Add((New-WfSyntheticLpiRecord -Relationship 2 -Body $cacheBody))
            }
        }
        $groupMasks.Add($all)
        # One L3 shared by every core of the group, 32 MiB.
        $l3 = New-Object byte[] 48
        $l3[0] = 3
        $l3[1] = 16
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]64), 0, $l3, 2, 2)
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]33554432), 0, $l3, 4, 4)
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]1), 0, $l3, 30, 2)
        [System.Array]::Copy((New-WfSyntheticGroupAffinity -Mask $all -Group $group), 0, $l3, 32, 16)
        $parts.Add((New-WfSyntheticLpiRecord -Relationship 2 -Body $l3))
        # One package and one NUMA node per group.
        $package = New-Object byte[] 40
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]1), 0, $package, 22, 2)
        [System.Array]::Copy((New-WfSyntheticGroupAffinity -Mask $all -Group $group), 0, $package, 24, 16)
        $parts.Add((New-WfSyntheticLpiRecord -Relationship 3 -Body $package))
        $numa = New-Object byte[] 40
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$group), 0, $numa, 0, 4)
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]1), 0, $numa, 22, 2)
        [System.Array]::Copy((New-WfSyntheticGroupAffinity -Mask $all -Group $group), 0, $numa, 24, 16)
        $parts.Add((New-WfSyntheticLpiRecord -Relationship 1 -Body $numa))
    }
    # GROUP_RELATIONSHIP: MaximumGroupCount, ActiveGroupCount, Reserved[20], then one PROCESSOR_GROUP_INFO (48 bytes) per group.
    $groupBody = New-Object byte[] (24 + 48 * $Groups)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]$Groups), 0, $groupBody, 0, 2)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]$Groups), 0, $groupBody, 2, 2)
    for ($group = 0; $group -lt $Groups; $group++) {
        $at = 24 + 48 * $group
        $groupBody[$at] = [byte](2 * $Cores)
        $groupBody[$at + 1] = [byte](2 * $Cores)
        [System.Array]::Copy([System.BitConverter]::GetBytes([uint64]$groupMasks[$group]), 0, $groupBody, $at + 40, 8)
    }
    $parts.Add((New-WfSyntheticLpiRecord -Relationship 4 -Body $groupBody))
    $total = 0
    foreach ($part in $parts) { $total += $part.Length }
    $buffer = New-Object byte[] $total
    $offset = 0
    foreach ($part in $parts) { [System.Array]::Copy($part, 0, $buffer, $offset, $part.Length); $offset += $part.Length }
    return , $buffer
}
