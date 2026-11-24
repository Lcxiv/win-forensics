# The cases behind fixtures/collector-bundles and the end to end Pester tests.
# Each case names a collector, prepares the synthetic backend, and states the
# exit code the collector must return. All content is invented.

function New-WfSyntheticFileEntry {
    # One entry of a synthetic folder listing (see Get-WfFileMetadataListing
    # in SyntheticBackend.ps1), with times relative to the synthetic clock.
    param([string]$Type = 'file', $Folder = $null, [string]$Name, $Bytes = $null, [double]$CreatedDaysAgo, [double]$WrittenDaysAgo)
    $now = $global:WfSynthetic.Now
    return [ordered]@{
        Type = $Type; Folder = $Folder; Name = $Name; Bytes = $(if ($Type -eq 'file') { [int64]$Bytes } else { $null })
        CreationTimeUtc = $now.AddSeconds([math]::Round(-86400 * $CreatedDaysAgo)); LastWriteTimeUtc = $now.AddSeconds([math]::Round(-86400 * $WrittenDaysAgo)); Entered = $(if ($Type -eq 'folder') { $true } else { $null })
    }
}

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

    # The PresentMon frame capture: wpr records the providers PresentMon
    # needs to a file under the collector's own instance name, PresentMon
    # reads that file offline and prints its CSV on stdout, and the file is
    # deleted. The binary, wpr's output, the recording and every frame are
    # invented; the hash the synthetic file reports is the pinned one so the
    # collector's verification passes; the CSV follows the header PresentMon
    # 2.6.0 writes for its default options with --qpc_time (CsvOutput.cpp
    # WriteCsvHeader<FrameMetrics>, lines 531 to 667), and the recording's
    # first buffer follows the layout of PresentMon's own regression
    # recordings (see New-WfSyntheticEtlBytes).

    # A completed 60 second recording of every presenting process with no
    # loss, read by PresentMon into frames of a game and of a process whose
    # start event was not in the recording. Status ok, source observed.
    $cases.Add(@{
            Case = 'presentmon-frames'; Collector = 'presentmon-frames'; ExitCode = 0
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $true
                Add-WfSyntheticWprRuns -EventsLost 0 -EtlBytes (New-WfSyntheticEtlBytes -DurationSeconds 60)
                Add-WfSyntheticPresentMonDecode -CsvText (Get-WfSyntheticPresentMonCsv -Name 'two-processes')
            }
        })

    # The same recording, and PresentMon printed nothing: with the pinned
    # binary an empty output cannot be told from a read that stopped early,
    # so no quiet window is claimed and the source is capture_failed.
    $cases.Add(@{
            Case = 'presentmon-frames-no-frames'; Collector = 'presentmon-frames'; ExitCode = 1
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 30 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $true
                Add-WfSyntheticWprRuns -EventsLost 0 -EtlBytes (New-WfSyntheticEtlBytes -DurationSeconds 30)
                Add-WfSyntheticPresentMonDecode -CsvText ''
            }
        })

    # The operator has not placed the binary: nothing runs, not even wpr; the
    # source is not_collected with the download hint; the collector exits 1.
    $cases.Add(@{
            Case = 'presentmon-frames-no-binary'; Collector = 'presentmon-frames'; ExitCode = 1
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $true -Present $false
                Add-WfSyntheticWprRuns
            }
        })

    # The controller lost events during the window: the source is
    # capture_failed, PresentMon never runs, the recording is deleted like
    # every recording.
    $cases.Add(@{
            Case = 'presentmon-frames-lost-events'; Collector = 'presentmon-frames'; ExitCode = 1
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $true
                Add-WfSyntheticWprRuns -EventsLost 12 -EtlBytes (New-WfSyntheticEtlBytes -DurationSeconds 60 -EventsLost 12)
                Add-WfSyntheticPresentMonDecode -CsvText (Get-WfSyntheticPresentMonCsv -Name 'two-processes')
            }
        })

    # PresentMon read a complete recording but threw presents away (its
    # "overflowed present events" warning): the frame table would be
    # incomplete, so the source is capture_failed with the count recorded.
    $cases.Add(@{
            Case = 'presentmon-frames-overflow'; Collector = 'presentmon-frames'; ExitCode = 1
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $true
                Add-WfSyntheticWprRuns -EventsLost 0 -EtlBytes (New-WfSyntheticEtlBytes -DurationSeconds 60)
                Add-WfSyntheticPresentMonDecode -CsvText (Get-WfSyntheticPresentMonCsv -Name 'two-processes') -StdErr (Get-WfSyntheticPresentMonOverflowText -Count 37)
            }
        })

    # The account may not control event tracing sessions and wpr refuses to
    # start: not_collected with wpr's words, nothing recorded.
    $cases.Add(@{
            Case = 'presentmon-frames-access-denied'; Collector = 'presentmon-frames'; ExitCode = 1
            Arguments = @{ PresentMonPath = (Get-WfSyntheticPresentMonPath); DurationSeconds = 60 }
            Setup = {
                New-WfSyntheticPresentMon -PerformanceLogUsers $false
                Add-WfSyntheticWprRuns -StartExitCode 1 -StartStdErr "Access is denied.`r`n"
            }
        })

    # The live DPC and interrupt capture. The synthetic recorder starts and
    # stops cleanly; the synthetic xperf is a pinned build whose report puts
    # the invented graphics driver's DPC and interrupt time on CPU 6. Status
    # ok, exit 0, both sources observed.
    $cases.Add(@{
            Case = 'dpcisr-trace'; Collector = 'dpcisr-trace'; ExitCode = 0; Arguments = @{ DurationSeconds = 10; XperfPath = 'C:\Tools\WindowsPerformanceToolkit\xperf.exe' }
            Setup = { New-WfSyntheticTraceMachine -EventsLost 0 -Xperf 'pinned' }
        })

    # The same capture without an xperf on the machine: the trace is observed
    # and in the bundle, the report is not_collected and says where it can be
    # produced. Status partial, exit 0.
    $cases.Add(@{
            Case = 'dpcisr-trace-no-xperf'; Collector = 'dpcisr-trace'; ExitCode = 0; Arguments = @{ DurationSeconds = 10 }
            Setup = { New-WfSyntheticTraceMachine -EventsLost 0 -Xperf 'absent' }
        })

    # The saved trace lost events (the number is the one Microsoft's tracelog
    # example shows), which the final tracerpt summary shows and the live
    # status did not: the trace source is capture_failed, the report is
    # produced with -tle and inherits the status, nothing is observed, exit 1.
    $cases.Add(@{
            Case = 'dpcisr-trace-events-lost'; Collector = 'dpcisr-trace'; ExitCode = 1; Arguments = @{ DurationSeconds = 10; XperfPath = 'C:\Tools\WindowsPerformanceToolkit\xperf.exe' }
            Setup = { New-WfSyntheticTraceMachine -EventsLost 544 -Xperf 'pinned' }
        })

    # The account is not elevated, which is what the front door's standard
    # account looks like today: no session is started, both sources are
    # not_collected with the reason, exit 1.
    $cases.Add(@{
            Case = 'dpcisr-trace-not-elevated'; Collector = 'dpcisr-trace'; ExitCode = 1; Arguments = @{ DurationSeconds = 10; XperfPath = 'C:\Tools\WindowsPerformanceToolkit\xperf.exe' }
            Setup = { New-WfSyntheticTraceMachine -EventsLost 0 -Xperf 'pinned'; $global:WfSynthetic.Elevated = $false }
        })

    # The disk activity capture. The machine is elevated, the recorder lists
    # the four keywords diskio-trace asks for, the saved trace has a readable
    # header on the performance counter clock, and tracerpt dumps an invented
    # XML rendering of kernel events (New-WfSyntheticDiskIoDump). Every
    # process, path and number in it is invented.

    # A clean 10 s capture: both sources observed, status ok, exit 0. The
    # aggregate keeps the fixed roots and one level below them, pseudonyms
    # for everything deeper, <profile> for the user folder, and no file name.
    $cases.Add(@{
            Case = 'diskio-trace'; Collector = 'diskio-trace'; ExitCode = 0; Arguments = @{ DurationSeconds = 10 }
            Setup = { New-WfSyntheticDiskIoMachine }
        })

    # The saved trace lost events (the final tracerpt summary says so, the
    # live status did not): the trace source is capture_failed, no aggregate
    # is made, nothing is observed, exit 1.
    $cases.Add(@{
            Case = 'diskio-trace-events-lost'; Collector = 'diskio-trace'; ExitCode = 1; Arguments = @{ DurationSeconds = 10 }
            Setup = { New-WfSyntheticDiskIoMachine -EventsLost 544 }
        })

    # The account is not elevated: no session is started, both sources are
    # not_collected with the reason, exit 1.
    $cases.Add(@{
            Case = 'diskio-trace-not-elevated'; Collector = 'diskio-trace'; ExitCode = 1; Arguments = @{ DurationSeconds = 10 }
            Setup = { New-WfSyntheticDiskIoMachine; $global:WfSynthetic.Elevated = $false }
        })

    # The dump renders the disk events without HighResResponseTime, which is
    # what a tracerpt that does not render the kernel classes as the reader
    # expects would look like: the trace is observed, the aggregate is
    # capture_failed and writes nothing, status partial, exit 0.
    $cases.Add(@{
            Case = 'diskio-trace-dump-unrendered'; Collector = 'diskio-trace'; ExitCode = 0; Arguments = @{ DurationSeconds = 10 }
            Setup = { New-WfSyntheticDiskIoMachine -DropField 'HighResResponseTime' }
        })

    # The clock calibration session. Each Setup takes the output directory so
    # the synthetic clock can fire operator marks into the running session
    # (Invoke-WfSyntheticMark runs the collector's own mark mode). Every
    # counter value and clock error below is invented.

    # A 60 s session at the contract's 5 s cadence: start, eleven interval
    # pairs strictly inside, stop (13 pairs). The system clock runs 50 ppm
    # fast against the counter and steps once per millisecond; every pair is
    # taken at one of those steps; two marks are dropped from the second
    # console. Status ok.
    $cases.Add(@{
            Case = 'clock-calibration'; Collector = 'clock-calibration'; ExitCode = 0; Arguments = @{ DurationSeconds = 60 }
            Setup = {
                param([string]$OutputDirectory)
                $global:WfSynthetic.Clock = New-WfSyntheticClock -DriftPpm 50 -Increment100ns 10000 -Marks @(
                    @{ AtElapsed100ns = 173000000; Label = 'felt a stutter' },
                    @{ AtElapsed100ns = 410500000; Label = 'second stutter, shorter' }
                )
                $global:WfSynthetic.Clock.MarkDirectory = $OutputDirectory
            }
        })

    # A 30 s session during which the system clock jumps 250 ms forward at
    # 12.5 s (what a time synchronisation does): the collector records the
    # pairs as they are and one mark; the fit on the Mac flags the segment
    # that holds the step. Status ok.
    $cases.Add(@{
            Case = 'clock-calibration-clock-step'; Collector = 'clock-calibration'; ExitCode = 0; Arguments = @{ DurationSeconds = 30 }
            Setup = {
                param([string]$OutputDirectory)
                $global:WfSynthetic.Clock = New-WfSyntheticClock -Increment100ns 10000 -Steps @(@{ AtElapsed100ns = 125000000; Delta100ns = 2500000 }) -Marks @(
                    @{ AtElapsed100ns = 201000000; Label = 'after the jump' }
                )
                $global:WfSynthetic.Clock.MarkDirectory = $OutputDirectory
            }
        })

    # A 30 s session in which one wait overruns by six seconds (the process
    # was starved), so the slot at 10 s is reached more than an interval
    # late and is recorded as missing rather than taken late. The system
    # timer runs at the coarse 15.625 ms increment. Observed with
    # missing_pairs 1 and expectation not met (timestamps.md section 3, the
    # clock calibration exception); status ok; no marks.
    $cases.Add(@{
            Case = 'clock-calibration-missed-slot'; Collector = 'clock-calibration'; ExitCode = 0; Arguments = @{ DurationSeconds = 30 }
            Setup = {
                param([string]$OutputDirectory)
                $global:WfSynthetic.Clock = New-WfSyntheticClock -Increment100ns 156250 -OvershootMs @{ 2 = 6000 }
                $global:WfSynthetic.Clock.MarkDirectory = $OutputDirectory
            }
        })

    # The counter read fails at the stop pair: the four pairs taken are kept
    # (two or more pairs are a calibration), the stop pair is counted as
    # missing so file times after the last pair are unaligned, and the marks
    # file, open the whole time, holds no mark. clock_calibration observed
    # with expectation not met, operator_marks observed_zero, status ok.
    $cases.Add(@{
            Case = 'clock-calibration-read-failed'; Collector = 'clock-calibration'; ExitCode = 0; Arguments = @{ DurationSeconds = 20 }
            Setup = {
                param([string]$OutputDirectory)
                # The first counter read at or after 20 s of true time throws: that is the read the
                # stop pair's scheduling loop makes, so the stop pair is never taken.
                $global:WfSynthetic.Clock = New-WfSyntheticClock -Increment100ns 10000 -ThrowAtElapsed100ns 200000000
                $global:WfSynthetic.Clock.MarkDirectory = $OutputDirectory
            }
        })

    # The session bracket: a baseline read at logon and the read after a play
    # session, subtracted within one boot. The machine, its processes and
    # every number are invented (New-WfSyntheticBracketMachine). The baseline
    # cases come first: the after cases look for them in the same folder.

    # The baseline the logon task takes: no game running, every source read.
    # Status ok.
    $cases.Add(@{
            Case = 'session-bracket'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{}
            Setup = { New-WfSyntheticBracketMachine -Stage 'baseline' }
        })

    # The game started before the logon task ran (it auto-started, or the
    # task started late): the guard finds it by image name and nothing else is
    # read. Status partial; the after read passes this baseline over.
    $cases.Add(@{
            Case = 'session-bracket-game-running'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{}
            Setup = { New-WfSyntheticBracketMachine -Stage 'baseline' -GameRunning }
        })

    # WMI refuses the process list: whether a game runs is unknown, so nothing
    # else is read either. Every source is not_collected; the collector exits 1.
    $cases.Add(@{
            Case = 'session-bracket-guard-failed'; Collector = 'session-bracket'; ExitCode = 1; Arguments = @{}
            Setup = { New-WfSyntheticBracketMachine -Stage 'baseline' -GuardFails }
        })

    # Three hours later in the same boot: the newest baseline with a boot
    # time is the first case (the two newer looking ones are passed over and
    # named), and every gap code appears in the process delta. Status ok.
    $cases.Add(@{
            Case = 'session-bracket-after'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{ Phase = 'after' }
            Setup = { New-WfSyntheticBracketMachine -Stage 'after' }
        })

    # The machine restarted between the reads: nothing is subtracted across
    # the reboot. session_delta not_collected, status partial.
    $cases.Add(@{
            Case = 'session-bracket-after-reboot'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{ Phase = 'after' }
            Setup = { New-WfSyntheticBracketMachine -Stage 'after' -Rebooted }
        })

    # The System log no longer reaches back to the boot: its counts since
    # boot are capture_failed and the event comparison is left out, while the
    # process and disk deltas stand. Status partial.
    $cases.Add(@{
            Case = 'session-bracket-after-log-wrapped'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{ Phase = 'after' }
            Setup = { New-WfSyntheticBracketMachine -Stage 'after' -SystemLogWrapped }
        })

    # No baseline in the folder named: nothing is subtracted. Status partial.
    $cases.Add(@{
            Case = 'session-bracket-after-no-baseline'; Collector = 'session-bracket'; ExitCode = 0; Arguments = @{ Phase = 'after'; BaselineDirectory = 'fixtures/no-session-baselines-here' }
            Setup = { New-WfSyntheticBracketMachine -Stage 'after' }
        })

    # The connection quality session. Every address, round trip and loss
    # below is invented; the gateway address and the adapter's hardware
    # address in New-WfSyntheticNet are canaries the tests look for in every
    # bundle file.

    # A 30 s session on a wired adapter: the gateway answers every echo, the
    # line beyond it drops cloudflare for three seconds and google for one,
    # and the gateway's DNS relay fails one query of three. Status ok.
    $cases.Add(@{
            Case = 'connection-quality'; Collector = 'connection-quality'; ExitCode = 0; Arguments = @{ DurationSeconds = 30 }
            Setup = {
                $global:WfSynthetic.Net.Lost = @{ gateway = @(); cloudflare = @(12, 13, 14); google = @(13) }
                $global:WfSynthetic.Net.DnsFail = @{ gateway = @(20); cloudflare = @() }
            }
        })

    # A 30 s session in which the cable drops: the adapter reads disconnected
    # from 9 s to 11 s, every echo in those seconds times out and both DNS
    # queries of slot 10 wait for their timeout, so the slots after them are
    # reached more than an interval late and written as missed; the process is then
    # starved for three seconds (the 17th wait overshoots), so three more
    # slots are missed, the link reading of slot 20 among them (sampling
    # gaps, not losses); from 25 s the preferred default route is another
    # interface and gateway, which link_state records without naming either.
    # Status ok.
    $cases.Add(@{
            Case = 'connection-quality-link-drop'; Collector = 'connection-quality'; ExitCode = 0; Arguments = @{ DurationSeconds = 30 }
            Setup = {
                $net = $global:WfSynthetic.Net
                $net.LinkDown = @(@{ From = 9; To = 11 })
                $net.Lost = @{ gateway = @(9, 10, 11); cloudflare = @(9, 10, 11); google = @(9, 10, 11) }
                $net.DnsFail = @{ gateway = @(10); cloudflare = @(10, 11, 12) }
                $net.RouteChangeAtSecond = 25
                $net.RoutesAfterChange = @(@{ NextHop = '10.99.0.1'; InterfaceIndex = 12; RouteMetric = 0; Store = 1; AddressFamily = 2 })
                $global:WfSynthetic.Clock = New-WfSyntheticClock -OvershootMs @{ 17 = 3000 }
            }
        })

    # A PC whose only default route is on link (no gateway address): the
    # gateway probes and the link reading are not collected, the public
    # probes run. Status partial.
    $cases.Add(@{
            Case = 'connection-quality-no-gateway'; Collector = 'connection-quality'; ExitCode = 0; Arguments = @{ DurationSeconds = 10 }
            Setup = {
                $global:WfSynthetic.Net.Routes = @(@{ NextHop = '0.0.0.0'; InterfaceIndex = 3; RouteMetric = 0; Store = 1; AddressFamily = 2 })
            }
        })

    # The echo batch throws in the fifth second: the session did not reach
    # its stop, so every source is capture_failed and no samples file is
    # kept. Status failed.
    $cases.Add(@{
            Case = 'connection-quality-session-failed'; Collector = 'connection-quality'; ExitCode = 1; Arguments = @{ DurationSeconds = 10 }
            Setup = {
                $global:WfSynthetic.Net.PingThrowAtSecond = 4
            }
        })

    # The session ledger, run as the account that plays. Every time below is
    # invented and placed relative to the synthetic clock (2026-03-01T12:00Z)
    # so that the history cases after it share one timeline with it, and the
    # example ledger (fixtures/session-ledger) joins them.
    #   Overwatch: two logs with plain names and one whose name carries the
    #     profile name (kept as a pseudonym), and an Errors folder.
    #   Battle.net: one long launcher log.
    #   Fortnite: a backup log and the current log.
    #   Epic Games Launcher: one log.
    #   The display driver (service synthdisp) wrote one record, WerKernel one,
    #   a WATCHDOG live dump and a queued live kernel report exist, Minidump
    #   and ReportArchive are empty.
    $cases.Add(@{
            Case = 'session-ledger'; Collector = 'session-ledger'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.AccountName = 'SYNTHETIC-PC\synthetic-player'
                $global:WfSynthetic.Providers = @($global:WfSynthetic.Providers) + @('synthdisp', 'Microsoft-Windows-WerKernel')
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
                $global:WfSynthetic.Channels['Microsoft-Windows-WerKernel/Operational'] = New-WfSyntheticChannelState -OldestDaysAgo 60 -RecordCount 40
                $documents = 'C:\Users\synthetic-player\Documents'
                $local = 'C:\Users\synthetic-player\AppData\Local'
                $global:WfSynthetic.Metadata[$documents + '\Overwatch\Logs'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Name 'Overwatch-2026.02.20-06.00.00.log' -Bytes 48213 -CreatedDaysAgo 9.25 -WrittenDaysAgo 9.10),
                        (New-WfSyntheticFileEntry -Name 'Overwatch-2026.02.25-12.00.00.log' -Bytes 51877 -CreatedDaysAgo 4.0 -WrittenDaysAgo 3.85),
                        (New-WfSyntheticFileEntry -Name 'Overwatch log (synthetic-player).log' -Bytes 20480 -CreatedDaysAgo 1.5 -WrittenDaysAgo 1.4),
                        (New-WfSyntheticFileEntry -Type 'folder' -Name 'Errors' -CreatedDaysAgo 30 -WrittenDaysAgo 3.86),
                        (New-WfSyntheticFileEntry -Folder 'Errors' -Name 'crash_1.txt' -Bytes 2048 -CreatedDaysAgo 3.86 -WrittenDaysAgo 3.86),
                        (New-WfSyntheticFileEntry -Name 'settings.ini' -Bytes 512 -CreatedDaysAgo 30 -WrittenDaysAgo 4.0)
                    )
                }
                $global:WfSynthetic.Metadata[$local + '\Battle.net\Logs'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Name 'Battle.net-2026.02.25-11.55.00.log' -Bytes 90112 -CreatedDaysAgo 4.004 -WrittenDaysAgo 1.39)
                    )
                }
                $global:WfSynthetic.Metadata[$local + '\FortniteGame\Saved\Logs'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Name 'FortniteGame-backup-2026.02.23-20.00.00.log' -Bytes 3145728 -CreatedDaysAgo 5.6666667 -WrittenDaysAgo 5.5833333),
                        (New-WfSyntheticFileEntry -Name 'FortniteGame.log' -Bytes 2097152 -CreatedDaysAgo 2.0833333 -WrittenDaysAgo 1.9583333)
                    )
                }
                $global:WfSynthetic.Metadata[$local + '\EpicGamesLauncher\Saved\Logs'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Name 'EpicGamesLauncher.log' -Bytes 1048576 -CreatedDaysAgo 2.09 -WrittenDaysAgo 1.95)
                    )
                }
                $global:WfSynthetic.Metadata['C:\Windows\LiveKernelReports'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Type 'folder' -Name 'WATCHDOG' -CreatedDaysAgo 40 -WrittenDaysAgo 3.8694),
                        (New-WfSyntheticFileEntry -Folder 'WATCHDOG' -Name 'WATCHDOG-20260225-1452.dmp' -Bytes 1258291 -CreatedDaysAgo 3.8694 -WrittenDaysAgo 3.8693)
                    )
                }
                $global:WfSynthetic.Metadata['C:\Windows\Minidump'] = @{ Entries = @() }
                $global:WfSynthetic.Metadata['C:\ProgramData\Microsoft\Windows\WER\ReportQueue'] = @{ Entries = @(
                        (New-WfSyntheticFileEntry -Type 'folder' -Name 'LiveKernelEvent_141_synthdisp_0000000000000000_cab_00000001' -CreatedDaysAgo 3.8692 -WrittenDaysAgo 3.8692),
                        (New-WfSyntheticFileEntry -Folder 'LiveKernelEvent_141_synthdisp_0000000000000000_cab_00000001' -Name 'Report.wer' -Bytes 4096 -CreatedDaysAgo 3.8692 -WrittenDaysAgo 3.8692)
                    )
                }
                $global:WfSynthetic.Metadata['C:\ProgramData\Microsoft\Windows\WER\ReportArchive'] = @{ Entries = @() }
                $global:WfSynthetic.Cim['Win32_PnPEntity'] = @{ Rows = @(
                        [ordered]@{ ClassGuid = '{4d36e968-e325-11ce-bfc1-08002be10318}'; Name = 'Synthetic Display Adapter'; Service = 'synthdisp'; Status = 'OK'; ConfigManagerErrorCode = 0; Present = $true }
                    )
                }
                Add-WfSyntheticQuery -Match "@Name='synthdisp'" -Events @(
                    (New-WfSyntheticEvent -RecordId 40950 -Provider 'synthdisp' -EventId 13 -Level 2 -DaysAgo 3.8695 -Properties @('\Device\Video3', 'synthetic driver record') -Message 'Synthetic display driver record.')
                )
                Add-WfSyntheticQuery -Match 'WerKernel' -Events @(
                    (New-WfSyntheticEvent -RecordId 31 -Channel 'Microsoft-Windows-WerKernel/Operational' -Provider 'Microsoft-Windows-WerKernel' -EventId 1 -Level 4 -LevelDisplay 'Information' -DaysAgo 3.8693 -Properties @('141') -Message 'Synthetic WerKernel record.')
                )
            }
        })

    # The same collector run as a standard account that does not play: the
    # profile folders hold no game logs (not_collected), the live kernel dump
    # folder refuses the listing (not_collected), the small dump folder does
    # not exist (observed_zero, a present state), the report archive listing
    # does not finish in time (capture_failed), no display adapter names a
    # service (the driver query cannot be built: not_collected), and the
    # WerKernel channel does not exist (unsupported).
    $cases.Add(@{
            Case = 'session-ledger-standard-account'; Collector = 'session-ledger'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
                $global:WfSynthetic.Metadata['C:\Windows\LiveKernelReports'] = @{ ErrorKind = 'access_denied'; ErrorType = 'System.UnauthorizedAccessException' }
                $global:WfSynthetic.Metadata['C:\ProgramData\Microsoft\Windows\WER\ReportQueue'] = @{ Entries = @() }
                $global:WfSynthetic.Metadata['C:\ProgramData\Microsoft\Windows\WER\ReportArchive'] = @{ Entries = @(); Stuck = $true }
                $global:WfSynthetic.Cim['Win32_PnPEntity'] = @{ Rows = @(
                        [ordered]@{ ClassGuid = '{4d36e968-e325-11ce-bfc1-08002be10318}'; Name = 'Microsoft Basic Display Adapter'; Service = $null; Status = 'OK'; ConfigManagerErrorCode = 0; Present = $true }
                    )
                }
            }
        })

    # History bundles on the session-ledger timeline: two unclean restarts
    # whose Kernel-Power 41 records name their BugcheckCode (zero: the
    # machine was powered off, no bug check was written), each after a play
    # session's last log write.
    $cases.Add(@{
            Case = 'bugcheck-history-ledger'; Collector = 'bugcheck-history'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
                $names = @('BugcheckCode', 'BugcheckParameter1', 'BugcheckParameter2', 'BugcheckParameter3', 'BugcheckParameter4', 'SleepInProgress', 'PowerButtonTimestamp')
                Add-WfSyntheticQuery -Match 'EventID=6008' -Events @(
                    (New-WfSyntheticEvent -RecordId 40301 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -LevelDisplay 'Critical' -DaysAgo 9.09 -Properties @(0, '0x0', '0x0', '0x0', '0x0', 0, 0) -DataNames $names -Message 'The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly.'),
                    (New-WfSyntheticEvent -RecordId 40302 -Provider 'EventLog' -EventId 6008 -DaysAgo 9.0899 -Properties @('9:30:00 AM', '2/20/2026') -Message 'The previous system shutdown at 9:30:00 AM on 2/20/2026 was unexpected.'),
                    (New-WfSyntheticEvent -RecordId 41012 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -LevelDisplay 'Critical' -DaysAgo 0.45 -Properties @(0, '0x0', '0x0', '0x0', '0x0', 0, 0) -DataNames $names -Message 'The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly.')
                )
            }
        })

    # A recovered display timeout (Display 4101) on the same timeline, and the
    # same two Kernel-Power 41 records as bugcheck-history-ledger: the ledger
    # keeps one row for each record read twice.
    $cases.Add(@{
            Case = 'tdr-events-ledger'; Collector = 'tdr-events'; ExitCode = 0; Arguments = @{}
            Setup = {
                $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo 90 -RecordCount 41200
                $names = @('BugcheckCode', 'BugcheckParameter1', 'BugcheckParameter2', 'BugcheckParameter3', 'BugcheckParameter4', 'SleepInProgress', 'PowerButtonTimestamp')
                Add-WfSyntheticQuery -Match "Provider[@Name='Display']" -Events @(
                    (New-WfSyntheticEvent -RecordId 40960 -Provider 'Display' -EventId 4101 -Level 3 -LevelDisplay 'Warning' -DaysAgo 3.0 -Properties @('synthdisp', '') -Message 'Display driver synthdisp stopped responding and has successfully recovered.')
                )
                Add-WfSyntheticQuery -Match 'EventID=41' -Events @(
                    (New-WfSyntheticEvent -RecordId 40301 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -LevelDisplay 'Critical' -DaysAgo 9.09 -Properties @(0, '0x0', '0x0', '0x0', '0x0', 0, 0) -DataNames $names -Message 'The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly.'),
                    (New-WfSyntheticEvent -RecordId 41012 -Provider 'Microsoft-Windows-Kernel-Power' -EventId 41 -Level 1 -LevelDisplay 'Critical' -DaysAgo 0.45 -Properties @(0, '0x0', '0x0', '0x0', '0x0', 0, 0) -DataNames $names -Message 'The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding, crashed, or lost power unexpectedly.')
                )
            }
        })

    return $cases.ToArray()
}

function Get-WfSyntheticPresentMonPath {
    # Where the fixture cases say the binary is; the synthetic backend never
    # touches the path, it only looks it up.
    return 'C:\ProgramData\win-forensics\tools\PresentMon-2.6.0-x64.exe'
}

function Get-WfSyntheticWprPath {
    return 'C:\Windows\System32\wpr.exe'
}

function Get-WfSyntheticPresentMonPinnedSha256 {
    # The pin presentmon-frames.ps1 carries (GitHub release v2.6.0 asset
    # digest). Kept here as text so the synthetic file can report it; a test
    # compares it with the collector's own constant.
    return 'b2a706bc6ad475749e3b7e3409263aa1e6906d45bdcf993f6dbc0f660188f1af'
}

function New-WfSyntheticPresentMon {
    # The synthetic PresentMon binary (present with the pinned hash and size
    # unless told otherwise) and the account's group memberships.
    param([bool]$PerformanceLogUsers = $true, [bool]$Present = $true, [string]$Sha256 = '', [int64]$Length = 980320, [bool]$Elevated = $false)
    $global:WfSynthetic.Elevated = $Elevated
    $global:WfSynthetic.PerformanceLogUsers = $PerformanceLogUsers
    if (-not $Present) {
        $global:WfSynthetic.Binaries.Remove((Get-WfSyntheticPresentMonPath))
        return
    }
    if (-not $Sha256) { $Sha256 = Get-WfSyntheticPresentMonPinnedSha256 }
    $global:WfSynthetic.Binaries[(Get-WfSyntheticPresentMonPath)] = @{ Length = $Length; Sha256 = $Sha256; FileVersion = '2.6.0.0'; ProductVersion = '2.6.0' }
}

function Get-WfSyntheticPresentMonWprStatusText {
    # What the synthetic wpr -status prints. The in progress text follows the
    # sample on the WPR Command-Line Options page ("WPR recording is in
    # progress...", "Dropped event", "Collector Name", "Events Lost" per
    # collector); the text when nothing records is invented, since Microsoft
    # documents only that "a message displays that WPR is not recording";
    # the provider lines under "Providers" are invented too (the collector
    # reads "<name>: <keywords>: <level>" and the README's verification list
    # says so). -ProviderLines $false leaves the Providers block out, which
    # the collector must treat as settings it could not confirm.
    param([bool]$InProgress, [int64]$EventsLost = 0, [bool]$Collectors = $false, [int64]$DroppedEvents = -1, [bool]$ProviderLines = $true, [string]$DxgKrnlKeywords = '0x8000841')
    $nl = "`r`n"
    if (-not $InProgress) { return ('WPR is not recording.' + $nl) }
    if ($DroppedEvents -lt 0) { $DroppedEvents = $EventsLost }
    $text = 'WPR recording is in progress...' + $nl + $nl + 'Time since start        : 00:01:00' + $nl + $nl + ('Dropped event           : {0}' -f $DroppedEvents) + $nl + $nl + 'Logging mode            : File' + $nl
    if ($Collectors) {
        $text += $nl + 'Actively recording collectors:' + $nl
        $text += 'Collector Name          : wf-presentmon-frames' + $nl
        $text += 'Collector Type          : Event Collector' + $nl
        $text += 'Buffer Size (KB)        : 64' + $nl
        $text += ('Events Lost             : {0}' -f $EventsLost) + $nl
        if ($ProviderLines) {
            $text += 'Providers' + $nl
            $text += '    Microsoft-Windows-Kernel-Process: 0x8000000000000010: 0x04' + $nl
            $text += ('    {802ec45a-1e99-4b83-9920-87c98277ba9d}: ' + $DxgKrnlKeywords + ': 0x04') + $nl
            $text += '    Microsoft-Windows-Win32k: 0x8400000440c01000: 0x04' + $nl
            $text += '    Microsoft-Windows-Dwm-Core: 0x8000000000000081: 0x05' + $nl
            $text += '    {8c9dd1ad-e6e5-4b07-b455-684a9d879900}: 0x0: 0x05' + $nl
            $text += '    {65cd4c8a-0848-4583-92a0-31c0fbaf00c0}: 0x0: 0x04' + $nl
            $text += '    Microsoft-Windows-DXGI: 0x8000000000000002: 0xff' + $nl
            $text += '    Microsoft-Windows-D3D9: 0x8000000000000002: 0xff' + $nl
            $text += 'CaptureState Providers on Start' + $nl
            $text += '    Microsoft-Windows-Kernel-Process: 0x8000000000000010: 0x04' + $nl
            $text += '    {802ec45a-1e99-4b83-9920-87c98277ba9d}: 0x840: 0x04' + $nl
        }
    }
    return $text
}

function Get-WfSyntheticPresentMonOverflowText {
    # The three warning lines MainThread.cpp prints at v2.6.0 (lines 456 to
    # 459) when the consumer threw presents away, on stderr.
    param([int]$Count)
    return (('warning: {0} overflowed present events detected. This could be due to a high-fps application.' -f $Count) + "`n" +
        '         Consider increasing the present event circular buffer size to a value larger' + "`n" +
        '         than the default of 2048, e.g., --set_circular_buffer_size 4096.' + "`n")
}

function New-WfSyntheticEtlBytes {
    # A stand in for the first buffer of an ETW log file, laid out as the
    # first buffer of PresentMon's own regression recordings is
    # (Tests/Gold/test_case_0.etl at tag v2.6.0, whose first 4096 bytes are
    # committed as fixtures/presentmon/gold-test_case_0.first-buffer.etl):
    # a 72 byte buffer header (buffer size, saved offset, current offset,
    # then fields this stand in leaves zero), a 32 byte system trace header
    # (version 2, header type 2, flags 0xc0, size, hook id 0, thread and
    # process id, time stamp, kernel and user time) and TRACE_LOGFILE_HEADER
    # (the documented structure, pointer members of PointerSize each, the
    # time zone block padded to 176 bytes), followed by the logger and log
    # file names and 0xff fill to the end of the buffer. Everything in it is
    # invented; the Pester suite compares its layout with the committed
    # first buffer field by field.
    param([int]$DurationSeconds = 60, [int64]$EventsLost = 0, [int64]$BuffersLost = 0, [int64]$BuffersWritten = 40, [int]$ClockType = 1,
        [int64]$PerfFreq = 10000000, [int]$PointerSize = 8, [int]$MaximumFileSizeMb = 48, [int]$StartOffsetSeconds = 7, [int]$EndLagSeconds = 10,
        [int]$EndOffsetSeconds = -1, [int]$BufferSize = 4096, [int]$HeaderType = 2, [switch]$NoEndTime)
    $start = $global:WfSynthetic.Now.AddSeconds($StartOffsetSeconds)
    # The session starts a few synthetic seconds after the collector's own
    # start bound (the probe, the clock reads and wpr -start take about 7)
    # and ends after the stop was requested (the window, the status read
    # and a lag) unless -EndOffsetSeconds places it earlier.
    if ($EndOffsetSeconds -ge 0) { $end = $global:WfSynthetic.Now.AddSeconds($EndOffsetSeconds) } else { $end = $start.AddSeconds($DurationSeconds + 1 + $EndLagSeconds) }
    $payload = New-Object System.IO.MemoryStream
    $pw = New-Object System.IO.BinaryWriter($payload)
    try {
        $pw.Write([uint32]65536)                    # BufferSize (of the session)
        $pw.Write([byte]10); $pw.Write([byte]0); $pw.Write([byte]2); $pw.Write([byte]0)   # Version: major 10, minor 0, sub, sub minor
        $pw.Write([uint32]26100)                    # ProviderVersion (build)
        $pw.Write([uint32]16)                       # NumberOfProcessors
        if ($NoEndTime) { $pw.Write([int64]0) } else { $pw.Write([int64]$end.ToFileTimeUtc()) }      # EndTime (0 when the session never closed cleanly)
        $pw.Write([uint32]156250)                   # TimerResolution
        $pw.Write([uint32]$MaximumFileSizeMb)       # MaximumFileSize
        $pw.Write([uint32]0x1)                      # LogFileMode (sequential)
        $pw.Write([uint32]$BuffersWritten)          # BuffersWritten
        $pw.Write([uint32]1)                        # StartBuffers
        $pw.Write([uint32]$PointerSize)             # PointerSize
        $pw.Write([uint32]$EventsLost)              # EventsLost
        $pw.Write([uint32]3000)                     # CpuSpeedInMHz
        $pw.Write((New-Object byte[] (2 * $PointerSize)))  # LoggerName, LogFileName pointers
        $pw.Write((New-Object byte[] 176))          # TIME_ZONE_INFORMATION, padded
        $pw.Write([int64]$global:WfSynthetic.Now.AddDays(-2).ToFileTimeUtc())  # BootTime
        $pw.Write([int64]$PerfFreq)                 # PerfFreq
        $pw.Write([int64]$start.ToFileTimeUtc())    # StartTime
        $pw.Write([uint32]$ClockType)               # ReservedFlags (clock type)
        $pw.Write([uint32]$BuffersLost)             # BuffersLost
        $pw.Write([System.Text.Encoding]::Unicode.GetBytes("wf-presentmon-frames`0"))
        $pw.Write([System.Text.Encoding]::Unicode.GetBytes("trace.etl`0"))
        $pw.Flush()
        $payloadBytes = $payload.ToArray()
    } finally {
        $pw.Dispose()
        $payload.Dispose()
    }
    $eventSize = 32 + $payloadBytes.Length
    $savedOffset = 72 + $eventSize
    if ($savedOffset % 8 -ne 0) { $savedOffset += 8 - ($savedOffset % 8) }
    $buffer = New-Object byte[] $BufferSize
    for ($i = $savedOffset; $i -lt $BufferSize; $i++) { $buffer[$i] = 0xff }
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    try {
        $writer.Write([uint32]$BufferSize)                   # buffer header: BufferSize
        $writer.Write([uint32]$savedOffset)                  # SavedOffset
        $writer.Write([uint32]0)                             # CurrentOffset
        $writer.Write((New-Object byte[] 60))                # the rest of the 72 byte buffer header, left zero
        $writer.Write([uint16]2)                             # system trace header: Version
        $writer.Write([byte]$HeaderType)                     # HeaderType (2: 64 bit system header)
        $writer.Write([byte]0xc0)                            # Flags
        $writer.Write([uint16]$eventSize)                    # Size
        $writer.Write([uint16]0)                             # HookId 0: the log file header event
        $writer.Write([uint32]4)                             # ThreadId
        $writer.Write([uint32]4)                             # ProcessId
        $writer.Write([int64]0)                              # TimeStamp (counter value, invented)
        $writer.Write([uint32]0)                             # KernelTime
        $writer.Write([uint32]0)                             # UserTime
        $writer.Write($payloadBytes)
        $writer.Flush()
        $head = $stream.ToArray()
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
    [array]::Copy($head, $buffer, $head.Length)
    return $buffer
}

function Add-WfSyntheticWprRuns {
    # What the synthetic wpr does for each verb the collector uses, in the
    # order the collector calls them: -status (probe), -start, -status
    # collectors -details (end of window), -stop, -status (after), -cancel.
    # Every call carries -instancename; the synthetic matches on the verb.
    # -LeftoverActive makes the first probe report a recording in progress
    # and the next probe idle (the collector cancels its own leftover between
    # them); -ProbeInProgress keeps every probe in progress.
    param([bool]$ProbeInProgress = $false, [bool]$LeftoverActive = $false, [bool]$ProbeFails = $false, [bool]$ProbeStuck = $false,
        [int]$StartExitCode = 0, [string]$StartStdOut = '', [string]$StartStdErr = '', [bool]$StartStuck = $false,
        [bool]$InProgressAtEnd = $true, [int64]$EventsLost = 0, [int64]$DroppedEvents = -1, [bool]$ProviderLines = $true, [string]$DxgKrnlKeywords = '0x8000841',
        [int]$StopExitCode = 0, [bool]$StopStuck = $false, $EtlBytes = $null,
        [bool]$AfterInProgress = $false, [int]$CancelExitCode = 0, [bool]$CancelStuck = $false, [int]$StartSeconds = 3, [int]$StopSeconds = 5)
    $wpr = Get-WfSyntheticWprPath
    $global:WfSynthetic.Programs.Add(@{ Path = $wpr; Match = '-status collectors -details'; ExitCode = 0; StdOut = (Get-WfSyntheticPresentMonWprStatusText -InProgress $InProgressAtEnd -EventsLost $EventsLost -Collectors $true -DroppedEvents $DroppedEvents -ProviderLines $ProviderLines -DxgKrnlKeywords $DxgKrnlKeywords); StdErr = ''; Seconds = 1 })
    $start = @{ Path = $wpr; Match = '-start'; ExitCode = $StartExitCode; StdOut = $StartStdOut; StdErr = $StartStdErr; Seconds = $StartSeconds }
    if ($StartStuck) { $start['Stuck'] = $true }
    $global:WfSynthetic.Programs.Add($start)
    $stop = @{ Path = $wpr; Match = '-stop'; ExitCode = $StopExitCode; StdOut = ''; StdErr = ''; Seconds = $StopSeconds }
    if ($StopStuck) { $stop['Stuck'] = $true }
    if ($null -ne $EtlBytes) { $stop['OutputFileArgument'] = '-stop "([^"]+)"'; $stop['OutputBytes'] = [byte[]]$EtlBytes }
    $global:WfSynthetic.Programs.Add($stop)
    $cancel = @{ Path = $wpr; Match = '-cancel'; ExitCode = $CancelExitCode; StdOut = ''; StdErr = ''; Seconds = 1 }
    if ($CancelStuck) { $cancel['Stuck'] = $true }
    $global:WfSynthetic.Programs.Add($cancel)
    $probe = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPresentMonWprStatusText -InProgress $ProbeInProgress); StdErr = ''; Seconds = 1 }
    if ($ProbeFails) { $probe = @{ ExitCode = 2; StdOut = ''; StdErr = "synthetic wpr: -status failed`r`n"; Seconds = 1 } }
    if ($ProbeStuck) { $probe['Stuck'] = $true }
    $after = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPresentMonWprStatusText -InProgress $AfterInProgress); StdErr = ''; Seconds = 1 }
    $responses = @($probe, $after)
    # A probe that keeps reporting the instance in progress: the collector
    # cancels once, probes again, and must then stop.
    if ($ProbeInProgress) { $responses = @($probe, $probe, $after) }
    if ($LeftoverActive) {
        $responses = @(@{ ExitCode = 0; StdOut = (Get-WfSyntheticPresentMonWprStatusText -InProgress $true); StdErr = ''; Seconds = 1 }, $probe, $after)
    }
    $global:WfSynthetic.Programs.Add(@{ Path = $wpr; Match = '-status'; Responses = $responses })
}

function Add-WfSyntheticPresentMonDecode {
    # What the synthetic PresentMon does when started with --etl_file
    # --output_stdout: prints the CSV on stdout (nothing else: CommandLine.cpp
    # turns console output off for --output_stdout) and any warning on
    # stderr, as the real one does (Console.cpp PrintWarning writes to
    # stderr). An empty CSV text is an empty stdout, which is what the real
    # binary prints when no frame was emitted.
    param([int]$ExitCode = 0, [string]$CsvText = '', [string]$StdErr = '', [bool]$Stuck = $false, [int]$Seconds = 4)
    $decode = @{ Path = (Get-WfSyntheticPresentMonPath); Match = '--etl_file'; ExitCode = $ExitCode; StdOut = $CsvText; StdErr = $StdErr; Seconds = $Seconds }
    if ($Stuck) { $decode['Stuck'] = $true }
    $global:WfSynthetic.Programs.Add($decode)
}

function ConvertTo-WfSyntheticCsvCell {
    # The writer's rule for several metrics: a zero prints NA, anything else
    # prints with the given number of decimals.
    param([double]$Value, [int]$Decimals)
    if ($Value -eq 0.0) { return 'NA' }
    return $Value.ToString('F' + $Decimals, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-WfSyntheticPresentMonCsv {
    # Invented CSV text in the layout PresentMon 2.6.0 writes for the console
    # application's default options with --qpc_time: the 28 column header of
    # WriteCsvHeader<FrameMetrics> (CsvOutput.cpp lines 531 to 667, v1
    # metrics, track display, GPU and input on) and rows shaped by
    # WriteCsvRow<FrameMetrics> (lines 675 to 854): integers for the two QPC
    # columns, 14 decimals for the four Ms* columns written with DBL_DIG - 1,
    # 4 decimals elsewhere, and NA where the writer prints NA for a zero or
    # missing value. Values are made up: a 10 MHz counter, a game at about
    # 144 frames per second whose name came from the recorded Kernel-Process
    # events, and a second process whose start event was not recorded.
    param([string]$Name)
    $nl = "`r`n"
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $header = 'Application,ProcessID,SwapChainAddress,PresentRuntime,SyncInterval,PresentFlags,AllowsTearing,PresentMode,TimeInQPC,MsBetweenSimulationStart,MsBetweenPresents,MsBetweenDisplayChange,MsInPresentAPI,MsRenderPresentLatency,MsUntilDisplayed,CPUStartQPC,MsBetweenAppStart,MsCPUBusy,MsCPUWait,MsGPULatency,MsGPUTime,MsGPUBusy,MsGPUWait,MsAnimationError,AnimationTime,MsFlipDelay,MsAllInputToPhotonLatency,MsClickToPhotonLatency'
    switch ($Name) {
        'header-only' { return ($header + $nl) }
        'no-qpc' {
            return (($header -replace 'CPUStartQPC', 'CPUStartTimeInMs') + $nl +
                'SyntheticGame.exe,4242,0x1F3A0C0B2E0,DXGI,0,512,1,Hardware: Independent Flip,123456858140,NA,6.91400000000000,NA,0.21400000000000,6.11200000000000,NA,0.0000,6.9140,5.8120,1.1020,0.4010,5.6330,5.5110,0.1220,NA,NA,NA,NA,NA' + $nl)
        }
        'two-processes' {
            $lines = New-Object 'System.Collections.Generic.List[string]'
            $lines.Add($header)
            $qpc = [int64]123456789000
            # BetweenPresents, CPUBusy, CPUWait, GPULatency, GPUTime, GPUBusy, GPUWait, DisplayChange, UntilDisplayed, AnimationError, AnimationTime, FlipDelay, AllInput, Click, InPresentAPI, RenderPresentLatency
            $game = @(
                @(6.914, 5.812, 1.102, 0.401, 5.633, 5.511, 0.122, 6.944, 6.112, 0.030, 12345.6858, 0.0, 0.0, 0.0, 0.214, 6.112),
                @(6.930, 5.790, 1.140, 0.398, 5.701, 5.590, 0.111, 6.930, 6.144, -0.014, 12352.6158, 0.0, 18.772, 18.772, 0.201, 6.144),
                @(6.902, 5.820, 1.082, 0.405, 5.655, 5.540, 0.115, 6.902, 6.090, 0.028, 12359.5178, 0.0, 0.0, 0.0, 0.219, 6.090),
                @(13.804, 12.650, 1.154, 0.412, 12.511, 12.400, 0.111, 13.804, 13.011, 6.902, 12373.3218, 0.0, 0.0, 0.0, 0.233, 13.011),
                @(6.944, 5.801, 1.143, 0.399, 5.622, 5.500, 0.122, 0.0, 0.0, -6.860, 12380.2658, 0.0, 0.0, 0.0, 0.208, 6.120),
                @(6.920, 5.833, 1.087, 0.403, 5.690, 5.577, 0.113, 13.864, 6.120, 0.000, 12387.1858, 0.0, 0.0, 0.0, 0.211, 6.120),
                @(6.911, 5.809, 1.102, 0.400, 5.640, 5.521, 0.119, 6.911, 6.100, 0.009, 12394.0968, 0.0, 25.104, 25.104, 0.215, 6.100),
                @(6.933, 5.822, 1.111, 0.404, 5.661, 5.548, 0.113, 6.933, 6.133, -0.022, 12401.0298, 0.0, 0.0, 0.0, 0.209, 6.133)
            )
            $modes = @('Hardware: Independent Flip', 'Hardware: Independent Flip', 'Hardware: Independent Flip', 'Hardware Composed: Independent Flip', 'Hardware: Independent Flip', 'Hardware: Independent Flip', 'Hardware: Independent Flip', 'Hardware: Independent Flip')
            $i = 0
            foreach ($f in $game) {
                $qpc += [int64]([double]$f[0] * 10000)
                $cells = New-Object 'System.Collections.Generic.List[string]'
                $cells.Add('SyntheticGame.exe'); $cells.Add('4242'); $cells.Add('0x1F3A0C0B2E0'); $cells.Add('DXGI'); $cells.Add('0'); $cells.Add('512'); $cells.Add('1'); $cells.Add($modes[$i])
                $cells.Add([string]($qpc + 2140))                                   # TimeInQPC
                $cells.Add('NA')                                                    # MsBetweenSimulationStart (zero prints NA)
                $cells.Add(([double]$f[0]).ToString('F14', $inv))                   # MsBetweenPresents
                $cells.Add((ConvertTo-WfSyntheticCsvCell -Value $f[7] -Decimals 14)) # MsBetweenDisplayChange
                $cells.Add(([double]$f[14]).ToString('F14', $inv))                  # MsInPresentAPI
                $cells.Add(([double]$f[15]).ToString('F14', $inv))                  # MsRenderPresentLatency
                $cells.Add((ConvertTo-WfSyntheticCsvCell -Value $f[8] -Decimals 4))  # MsUntilDisplayed
                $cells.Add([string]$qpc)                                            # CPUStartQPC
                foreach ($k in @(0, 1, 2, 3, 4, 5, 6)) { $cells.Add(([double]$f[$k]).ToString('F4', $inv)) }  # MsBetweenAppStart, CPU busy and wait, GPU latency, time, busy, wait
                $cells.Add(([double]$f[9]).ToString('F4', $inv))                    # MsAnimationError
                $cells.Add(([double]$f[10]).ToString('F4', $inv))                   # AnimationTime
                $cells.Add((ConvertTo-WfSyntheticCsvCell -Value $f[11] -Decimals 4)) # MsFlipDelay
                $cells.Add((ConvertTo-WfSyntheticCsvCell -Value $f[12] -Decimals 4)) # MsAllInputToPhotonLatency
                $cells.Add((ConvertTo-WfSyntheticCsvCell -Value $f[13] -Decimals 4)) # MsClickToPhotonLatency
                $lines.Add(($cells.ToArray() -join ','))
                $i += 1
                if ($i -eq 3 -or $i -eq 6) {
                    # A frame from a process whose start or rundown event was not in the recording, composed by the desktop.
                    $u = $qpc + 31000
                    $lines.Add('<unknown>,5120,0x1F3A1D44F00,DXGI,1,0,0,Composed: Flip,' + ($u + 1800) + ',NA,16.66600000000000,16.66700000000000,0.08800000000000,1.50000000000000,20.1040,' + $u + ',16.6660,2.0110,14.6550,0.9020,1.2440,1.2010,0.0430,0.0000,' + ([double]($u / 10000.0)).ToString('F4', $inv) + ',NA,NA,NA')
                }
            }
            return (($lines.ToArray() -join $nl) + $nl)
        }
        'ragged' {
            return ($header + $nl + 'SyntheticGame.exe,4242,0x1F3A0C0B2E0,DXGI,0,512' + $nl)
        }
    }
    throw ('no synthetic PresentMon CSV named ' + $Name)
}

function New-WfSyntheticTraceMachine {
    # The machine behind the dpcisr-trace cases: an elevated account, the
    # synthetic recorder, and an xperf that is pinned, present but not pinned,
    # or absent. Every value is invented.
    param([int]$EventsLost = 0, [string]$Xperf = 'pinned')
    $global:WfSynthetic.Elevated = $true
    # The live status right after the start shows no loss; the loss, when the
    # case has one, is in the saved trace's summary: the final figure is what
    # decides, never the snapshot.
    $global:WfSynthetic.Wpr.EventsLost = 0
    $global:WfSynthetic.Wpr.DroppedEvents = 0
    $global:WfSynthetic.Tracerpt.EventsLost = $EventsLost
    $global:WfSynthetic.Tracerpt.BuffersLost = 0
    $path = 'C:\Tools\WindowsPerformanceToolkit\xperf.exe'
    $pinnedHash = '7f3a9c2e4b1d6058a2c4e6f8091b3d5f7a9c1e3b5d7f9a0c2e4b6d8f0a1c3e5b'
    if ($Xperf -ne 'absent') {
        $hash = $(if ($Xperf -eq 'pinned') { $pinnedHash } else { '0000000000000000000000000000000000000000000000000000000000000001' })
        $global:WfSynthetic.Tools[$path] = @{ Sha256 = $hash; Version = '10.0.26100.1 (synthetic)' }
    }
    $global:WfSynthetic.PinnedTools['xperf'] = @(@{ Version = '10.0.26100.1 (synthetic)'; Sha256 = $pinnedHash; Source = 'synthetic Windows Performance Toolkit build for the test suite' })
    $global:WfSynthetic.Xperf = @{ ExitCode = 0; StdOut = (Get-WfSyntheticDpcIsrReport); StdErr = ''; Stuck = $false }
}

function Get-WfSyntheticDpcIsrReport {
    # An "xperf -i trace.etl -a dpcisr" report in the shape
    # scripts/decode_dpcisr.py reads (the format fixture under
    # fixtures/example-bundle shows the real tool's layout): a DPC Info and
    # an Interrupt Info section, each with the per module, per CPU table for
    # the whole trace, the section total, one total per module, the
    # reconciliation line, and the per interval table. Sixteen CPUs; the
    # invented graphics driver's time sits on CPU 6, as a GPU interrupt
    # affinity pin would put it. Every number and module name is made up.
    $cpuCount = 16
    $spanUs = 10000000
    $intervalMs = 1000
    $nl = "`r`n"
    $sections = @(
        @{
            Name    = 'DPC Info'
            Modules = @(
                @{ Module = 'synthgfx.sys'; Count = 41200; Usec = @{ 6 = 912345 } },
                @{ Module = 'synthnic.sys'; Count = 9800; Usec = @{ 0 = 24810 } },
                @{ Module = 'synthusb.sys'; Count = 12050; Usec = @{ 2 = 18630; 3 = 2210 } },
                @{ Module = 'synthaudio.sys'; Count = 3100; Usec = @{ 4 = 9950 } },
                @{ Module = 'ntoskrnl.exe'; Count = 60300; Usec = @{ 0 = 3300; 1 = 1608; 2 = 2260; 3 = 1694; 4 = 2594; 5 = 2067; 6 = 2833; 7 = 2319; 8 = 3186; 9 = 2732; 10 = 2711; 11 = 1500; 12 = 1420; 13 = 1377; 14 = 1266; 15 = 1190 } }
            )
        },
        @{
            Name    = 'Interrupt Info'
            Modules = @(
                @{ Module = 'synthgfx.sys'; Count = 38900; Usec = @{ 6 = 486210 } },
                @{ Module = 'synthnic.sys'; Count = 9800; Usec = @{ 0 = 8120 } },
                @{ Module = 'synthusb.sys'; Count = 12050; Usec = @{ 2 = 6020; 3 = 740 } },
                @{ Module = 'ntoskrnl.exe'; Count = 5400; Usec = @{ 0 = 190; 1 = 217; 2 = 278; 3 = 465; 4 = 577; 5 = 346; 6 = 516; 7 = 245; 8 = 462; 9 = 331; 10 = 262; 11 = 169; 12 = 134; 13 = 150; 14 = 121; 15 = 118 } }
            )
        }
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('')
    foreach ($section in $sections) {
        $lines.Add('--------------------------')
        $lines.Add($section.Name)
        $lines.Add('')
        $lines.Add('--------------------------')
        $lines.Add('CPU Usage Summing By Module For the Whole Trace')
        $lines.Add('')
        $lines.Add(('CPU Usage from 0 us to {0} us:' -f $spanUs))
        $lines.Add('')
        $header = ''
        $legend = ''
        for ($cpu = 0; $cpu -lt $cpuCount; $cpu++) {
            $header += ('      CPU {0} Usage,' -f $cpu)
            $legend += '      usec      %,'
        }
        $lines.Add($header + '  ')
        $lines.Add($legend + '   ')
        $total = 0
        foreach ($module in $section.Modules) {
            $row = ''
            for ($cpu = 0; $cpu -lt $cpuCount; $cpu++) {
                $usec = 0
                if ($module.Usec.ContainsKey($cpu)) { $usec = [int]$module.Usec[$cpu] }
                $percent = [math]::Round(100.0 * $usec / $spanUs, 2)
                $row += ('{0,9} {1,6:0.00},' -f $usec, $percent)
            }
            $lines.Add($row + ' ' + $module.Module)
            $total += [int]$module.Count
        }
        $lines.Add('')
        $lines.Add(('Total = {0}' -f $total))
        $lines.Add(('Elapsed Time, >        0 usecs AND <=        1 usecs,  {0}, or  50.00%' -f [int]($total / 2)))
        $lines.Add(('Elapsed Time, >        1 usecs AND <=      256 usecs,  {0}, or  50.00%' -f ($total - [int]($total / 2))))
        $lines.Add(('Total,                                                {0}' -f $total))
        $lines.Add('')
        foreach ($module in $section.Modules) {
            $lines.Add(('Total = {0} for module {1}' -f $module.Count, $module.Module))
            $lines.Add(('Elapsed Time, >        0 usecs AND <=      256 usecs,  {0}, or 100.00%' -f $module.Count))
            $lines.Add(('Total,                                                {0}' -f $module.Count))
            $lines.Add('')
        }
        $lines.Add(('All Module = {0},  Total = {0},   EQUAL' -f $total))
        $lines.Add('')
        $lines.Add('--------------------------')
        $intervals = [int]($spanUs / 1000 / $intervalMs)
        $lines.Add(('Usage From 0 ms to {0} ms, Summing In 1 second intervals. Intervals={1}' -f ($spanUs / 1000), $intervals))
        $lines.Add('')
        $header = '                       ,'
        $legend = 'Start (ms) End (ms)    ,'
        for ($cpu = 0; $cpu -lt $cpuCount; $cpu++) {
            $header += ('      CPU {0} Usage ,' -f $cpu)
            $legend += '    (usec)      % ,'
        }
        $lines.Add($header)
        $lines.Add($legend)
        for ($i = 0; $i -lt $intervals; $i++) {
            $row = ('{0,10}-{1,-10}:,' -f ($i * $intervalMs), (($i + 1) * $intervalMs))
            $cells = New-Object 'System.Collections.Generic.List[string]'
            for ($cpu = 0; $cpu -lt $cpuCount; $cpu++) {
                $usec = 0
                foreach ($module in $section.Modules) { if ($module.Usec.ContainsKey($cpu)) { $usec += [int]([int]$module.Usec[$cpu] / $intervals) } }
                $percent = [math]::Round(100.0 * $usec / ($intervalMs * 1000), 2)
                $cells.Add(('{0,10} {1,6:0.00}' -f $usec, $percent))
            }
            $lines.Add($row + ($cells.ToArray() -join ','))
        }
        $lines.Add('')
    }
    return (($lines.ToArray() -join $nl) + $nl)
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

function Set-WfSyntheticScenarioMachine {
    # The machine the scenario runner itself sees for S1: an elevated account,
    # the pinned PresentMon at its default place, a pinned xperf, room on the
    # volume, and for each collector the case above whose Setup prepares the
    # machine that collector sees when the runner starts it. The clock session
    # runs alongside the runner. Every value is invented.
    New-WfSyntheticTraceMachine -EventsLost 0 -Xperf 'pinned'
    New-WfSyntheticPresentMon -PerformanceLogUsers $false -Elevated $true
    $global:WfSynthetic.Children = @{
        'clock-calibration'   = @{ Case = 'clock-calibration'; Concurrent = $true }
        'dpcisr-trace'        = @{ Case = 'dpcisr-trace' }
        'presentmon-frames'   = @{ Case = 'presentmon-frames' }
        'diskio-trace'        = @{ Case = 'diskio-trace' }
        'bugcheck-history'    = @{ Case = 'bugcheck-history' }
        'whea-errors'         = @{ Case = 'whea-errors-quiet' }
        'application-errors'  = @{ Case = 'application-errors' }
        'tdr-events'          = @{ Case = 'tdr-events-partial' }
        'reliability-records' = @{ Case = 'reliability-records' }
        'driver-inventory'    = @{ Case = 'driver-inventory' }
    }
}

function Get-WfSyntheticRunCases {
    # The runs behind fixtures/scenario-runs. Each Setup runs after
    # Reset-WfSynthetic and Set-WfSyntheticScenarioMachine.
    return @(
        # S1 as it should go: every capture observed, the history optional and
        # partial (the undocumented Display provider never yields a quiet
        # window), the state snapshot slots absent until it is registered. Exit 0.
        @{ Case = 's1'; ExitCode = 0; Setup = { } },
        # The account is not elevated: the kernel trace cannot be started, the
        # preflight refuses before anything runs, every declared source is
        # not_collected with the reason. Exit 1.
        @{ Case = 's1-preflight-refused'; ExitCode = 1; Setup = { $global:WfSynthetic.Elevated = $false } }
    )
}

function New-WfSyntheticDiskIoMachine {
    # The machine behind the diskio-trace cases. The live status right after
    # the start shows no loss; a loss, when the case has one, is in the saved
    # trace's summary. -CollectorRoot adds disk requests on a file inside the
    # bundle (the Pester suite passes its own directory; the fixtures do not,
    # so the dump does not depend on where the repository is checked out).
    param([int64]$EventsLost = 0, [string]$DropField = '', [string]$CollectorRoot = '', [switch]$NoDiskEvents, [int]$ExtraProcessed = 0, [switch]$PidReuse)
    $global:WfSynthetic.Elevated = $true
    $wpr = $global:WfSynthetic.Wpr
    $wpr.Keywords = @('DiskIO', 'Filename', 'HardFaults', 'ProcessThread')
    $wpr.ProfileName = 'WfDiskIoTrace'
    $wpr.EventsLost = 0
    $wpr.DroppedEvents = 0
    $wpr.EtlContent = New-WfSyntheticEtlBytes -DurationSeconds 10
    $dump = New-WfSyntheticDiskIoDump -DropField $DropField -CollectorRoot $CollectorRoot -NoDiskEvents:$NoDiskEvents -PidReuse:$PidReuse
    $global:WfSynthetic.Tracerpt.EventsLost = $EventsLost
    $global:WfSynthetic.Tracerpt.BuffersLost = 0
    $global:WfSynthetic.Tracerpt.DumpXml = $dump.Xml
    $global:WfSynthetic.Tracerpt.EventsProcessed = $dump.Count + $ExtraProcessed
}

function New-WfSyntheticDiskIoDump {
    # An invented tracerpt XML dump in the documented event schema: kernel
    # events carry the kernel logger's control GUID as provider and their
    # class GUID in ExtendedTracingInfo/EventGuid, the event type in Opcode,
    # TimeCreated/@SystemTime, and one Data element per MOF property. Times
    # are offsets from the header StartTime New-WfSyntheticEtlBytes writes
    # (Now plus 7 s). The Process events carry a command line and a user id
    # and a system configuration event carries a hardware address, so the
    # suite can show that none of them reaches the bundle. -PidReuse adds two
    # process ids that change hands inside the window: 5120 (an updater that
    # writes and exits, then another process started under the same id) and
    # 6000 (a process the trace first names by its end event, then a new
    # process under the same id); and a thread id, 7001, that writes before
    # its first Thread event, ends, and is given to another process; and a
    # file object, ...9000, written before its first name event (its delete),
    # whose address then names another file.
    param([string]$DropField = '', [string]$CollectorRoot = '', [switch]$NoDiskEvents, [switch]$PidReuse)
    $start = $global:WfSynthetic.Now.AddSeconds(7)
    $kernel = '{9e814aad-3204-11d2-9a82-006008a86939}'
    $classes = @{
        DiskIo    = '{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}'
        FileIo    = '{90cbdc39-4a3e-11d1-84f4-0000f80464e3}'
        PageFault = '{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}'
        Thread    = '{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}'
        Process   = '{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}'
        Config    = '{01853a65-418f-4f36-aefc-dc0f1d2fd235}'
    }
    $events = New-Object 'System.Collections.Generic.List[string]'
    $add = {
        param([string]$Class, [int]$Opcode, [double]$Offset, [object[]]$Data)
        $time = $start.AddTicks([int64][math]::Round($Offset * 10000000))
        $text = $time.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        $body = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $Data.Count; $i += 2) {
            if ([string]$Data[$i] -eq $DropField) { continue }
            $value = [System.Security.SecurityElement]::Escape([string]$Data[$i + 1])
            $null = $body.Append(('<Data Name="{0}">{1}</Data>' -f $Data[$i], $value))
        }
        $events.Add(('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Guid="{0}" /><EventID>0</EventID><Version>2</Version><Level>0</Level><Task>0</Task><Opcode>{1}</Opcode><Keywords>0x0</Keywords><TimeCreated SystemTime="{2}" /><Correlation ActivityID="{{00000000-0000-0000-0000-000000000000}}" /><Execution ProcessID="4" ThreadID="100" ProcessorID="0" KernelTime="0" UserTime="0" /><Channel /><Computer /></System><EventData>{3}</EventData><ExtendedTracingInfo xmlns="http://schemas.microsoft.com/win/2004/08/events/trace"><EventGuid>{4}</EventGuid></ExtendedTracingInfo></Event>' -f $kernel, $Opcode, $text, $body.ToString(), $classes[$Class]))
    }
    $volume = '\Device\HarddiskVolume3'
    # System configuration and the rundown of what was running at the start.
    & $add 'Config' 11 0.0001 @('NicDescription', 'Synthetic Network Adapter', 'PhysicalAddr', '02-00-5E-10-20-30', 'Ipv4Index', '7')
    & $add 'Process' 3 0.001 @('UniqueProcessKey', '0xffffc00000000040', 'ProcessId', '4', 'ParentId', '0', 'SessionId', '4294967295', 'ExitStatus', '259', 'UserSID', 'S-1-5-18', 'ImageFileName', 'System', 'CommandLine', '')
    & $add 'Process' 3 0.002 @('UniqueProcessKey', '0xffffc00000000080', 'ProcessId', '1200', 'ParentId', '900', 'SessionId', '1', 'ExitStatus', '259', 'UserSID', 'S-1-5-21-1000000001-1000000002-1000000003-1001', 'ImageFileName', 'SyntheticGame.exe', 'CommandLine', '"C:\Program Files\SyntheticGame\SyntheticGame.exe" -profile C:\Users\SyntheticOwner\secret-token')
    & $add 'Process' 3 0.003 @('UniqueProcessKey', '0xffffc000000000c0', 'ProcessId', '2300', 'ParentId', '900', 'SessionId', '1', 'ExitStatus', '259', 'UserSID', 'S-1-5-21-1000000001-1000000002-1000000003-1001', 'ImageFileName', 'SyntheticLauncher.exe', 'CommandLine', 'SyntheticLauncher.exe --silent')
    & $add 'Process' 3 0.004 @('UniqueProcessKey', '0xffffc00000000100', 'ProcessId', '3400', 'ParentId', '900', 'SessionId', '1', 'ExitStatus', '259', 'UserSID', 'S-1-5-21-1000000001-1000000002-1000000003-1001', 'ImageFileName', 'SyntheticOwner [helper].exe', 'CommandLine', 'helper')
    foreach ($pair in @(@(100, 4), @(1201, 1200), @(1202, 1200), @(2301, 2300), @(3401, 3400))) {
        & $add 'Thread' 3 0.005 @('ProcessId', [string]$pair[1], 'TThreadId', [string]$pair[0], 'StackBase', '0xfffff00000010000', 'StackLimit', '0xfffff0000000a000')
    }
    # File objects named at the start (name events) or only at the end (rundown).
    $files = [ordered]@{
        '0xffffa00000001000' = $volume + '\Users\SyntheticOwner\AppData\Local\SyntheticGame\ShaderCache\Pipeline\cache01.bin'
        '0xffffa00000002000' = $volume + '\Program Files\SyntheticGame\Content\Paks\world.pak'
        '0xffffa00000003000' = $volume + '\Windows\System32\winevt\Logs\Synthetic-Operational.evtx'
        '0xffffa00000004000' = $volume + '\$Mft'
    }
    foreach ($key in $files.Keys) { & $add 'FileIo' 0 0.006 @('FileObject', $key, 'FileName', $files[$key]) }
    $disk = {
        param([int]$Opcode, [double]$Offset, [string]$Thread, [string]$FileObject, [int]$Size, [string]$Flags, [int]$Ticks, [int]$DiskNumber = 0)
        & $add 'DiskIo' $Opcode $Offset @('DiskNumber', [string]$DiskNumber, 'IrpFlags', $Flags, 'TransferSize', [string]$Size, 'Reserved', '0', 'ByteOffset', '1048576', 'FileObject', $FileObject, 'Irp', '0xffffd00000000010', 'HighResResponseTime', [string]$Ticks, 'IssuingThreadId', $Thread)
    }
    if (-not $NoDiskEvents) {
        # Second 0: the game reads its pack file and its shader cache.
        & $disk 10 0.10 '1201' '0xffffa00000002000' 65536 '0x60043' 1500
        & $disk 10 0.20 '1201' '0xffffa00000002000' 131072 '0x60043' 2500
        & $disk 10 0.30 '1202' '0xffffa00000001000' 4096 '0x60043' 800
        # Second 1: the game writes its shader cache, a save written by a
        # thread only named by its end event, a log write by the system.
        & $disk 11 1.10 '1202' '0xffffa00000001000' 16384 '0x60a01' 4200
        & $disk 11 1.20 '1202' '0xffffa00000001000' 16384 '0x60a01' 3800
        & $disk 11 1.40 '2399' '0xffffa00000005000' 8192 '0x60a01' 9000
        & $disk 11 1.50 '100' '0xffffa00000003000' 4096 '0x60a03' 1200
        & $disk 10 1.60 '100' '0xffffa00000004000' 1024 '0x60a43' 300 1
        # Second 2: the launcher reads its own files; a thread the trace never
        # names; a file object the trace never names; the helper process.
        & $disk 10 2.10 '2301' '0xffffa00000006000' 32768 '0x60043' 2100
        & $disk 10 2.20 '9999' '0xffffa00000002000' 4096 '0x60043' 700
        & $disk 10 2.30 '1201' '0xffffa00000007000' 4096 '0x60043' 600
        & $disk 11 2.40 '3401' '0xffffa00000001000' 4096 '0x60a01' 1100
        if ($CollectorRoot) {
            $own = $volume + ($CollectorRoot -replace '^[A-Za-z]:', '').Replace('/', '\') + '\private\temp\synthetic.etl'
            & $add 'FileIo' 32 2.50 @('FileObject', '0xffffa00000008000', 'FileName', $own)
            & $disk 11 2.60 '100' '0xffffa00000008000' 65536 '0x60a01' 1800
        }
    }
    if ($PidReuse) {
        $process = {
            param([int]$Opcode, [double]$Offset, [string]$ProcessId, [string]$Image)
            & $add 'Process' $Opcode $Offset @('UniqueProcessKey', '0xffffc00000000140', 'ProcessId', $ProcessId, 'ParentId', '900', 'SessionId', '1', 'ExitStatus', '0', 'UserSID', 'S-1-5-21-1000000001-1000000002-1000000003-1001', 'ImageFileName', $Image, 'CommandLine', $Image)
        }
        $thread = {
            param([int]$Opcode, [double]$Offset, [string]$ProcessId, [string]$ThreadId)
            & $add 'Thread' $Opcode $Offset @('ProcessId', $ProcessId, 'TThreadId', $ThreadId, 'StackBase', '0xfffff00000030000', 'StackLimit', '0xfffff0000002a000')
        }
        & $thread 3 0.007 '6000' '6001'
        & $process 1 3.00 '5120' 'SyntheticUpdater.exe'
        & $thread 1 3.01 '5120' '5121'
        & $disk 11 3.10 '5121' '0xffffa00000001000' 1048576 '0x60a01' 5000
        & $disk 11 3.20 '6001' '0xffffa00000001000' 2048 '0x60a01' 900
        & $thread 2 3.90 '5120' '5121'
        & $process 2 4.00 '5120' 'SyntheticUpdater.exe'
        & $process 2 4.50 '6000' 'SyntheticEarly.exe'
        & $process 1 5.00 '5120' 'SyntheticOther.exe'
        & $thread 1 5.01 '5120' '5122'
        & $disk 11 5.10 '5122' '0xffffa00000001000' 512 '0x60a01' 400
        & $process 1 6.00 '6000' 'SyntheticLate.exe'
        & $disk 11 3.30 '7001' '0xffffa00000001000' 3072 '0x60a01' 700
        & $thread 3 3.31 '1200' '7001'
        & $thread 2 3.50 '1200' '7001'
        & $thread 1 5.50 '2300' '7001'
        & $disk 11 3.40 '1201' '0xffffa00000009000' 5120 '0x60a01' 600
        & $add 'FileIo' 35 3.60 @('FileObject', '0xffffa00000009000', 'FileName', ($volume + '\ProgramData\SyntheticGame\Journal\Pending\entry.log'))
        & $add 'FileIo' 32 5.60 @('FileObject', '0xffffa00000009000', 'FileName', ($volume + '\Windows\Temp\Scratch\other.tmp'))
    }
    # Hard faults: the game pages in code from its pack file.
    & $add 'PageFault' 32 0.40 @('InitialTime', '1000', 'ReadOffset', '4096', 'VirtualAddress', '0x00007ff600001000', 'FileObject', '0xffffa00000002000', 'TThreadId', '1201', 'ByteCount', '32768')
    & $add 'PageFault' 32 0.45 @('InitialTime', '1100', 'ReadOffset', '36864', 'VirtualAddress', '0x00007ff600009000', 'FileObject', '0xffffa00000002000', 'TThreadId', '1201', 'ByteCount', '16384')
    # The end of the session: a thread end, and the rundown that names the
    # file objects not named earlier.
    & $add 'Thread' 2 9.0 @('ProcessId', '2300', 'TThreadId', '2399', 'StackBase', '0xfffff00000020000', 'StackLimit', '0xfffff0000001a000')
    & $add 'FileIo' 36 10.5 @('FileObject', '0xffffa00000005000', 'FileName', ($volume + '\Users\SyntheticOwner\Saved Games\SyntheticGame\slot1.sav'))
    & $add 'FileIo' 36 10.5 @('FileObject', '0xffffa00000006000', 'FileName', ($volume + '\ProgramData\SyntheticLauncher\Manifests\Catalog\index.dat'))
    $xml = '<?xml version="1.0" encoding="UTF-8"?>' + "`r`n" + '<Events>' + "`r`n" + ($events.ToArray() -join "`r`n") + "`r`n" + '</Events>' + "`r`n"
    return @{ Xml = $xml; Count = $events.Count }
}

function New-WfSyntheticBracketMachine {
    # The invented machine behind the session-bracket cases. The baseline is
    # read at T0 (the backend's default clock), two days after the boot; the
    # after read three hours later. Process rows, in order of the gap code
    # they produce in the after read:
    #   0 System, example-launcher.exe (a count above 2^32), svchost.exe (no change)
    #   1 example-sync.exe exits
    #   2 example-updater.exe restarts under the same process id
    #   3 example-overlay.exe starts during the session
    #   4 example-agent.exe loses its write count
    #   5 example-ghost.exe has no creation time in either read
    #   6 example-cache.exe reports a lower count than before
    param([string]$Stage, [switch]$GameRunning, [switch]$GuardFails, [switch]$Rebooted, [switch]$SystemLogWrapped)
    $t0 = $global:WfSynthetic.Now
    $boot = $t0.AddDays(-2)
    if ($Stage -eq 'after') { $global:WfSynthetic.Now = $t0.AddHours(3) }
    if ($Rebooted) { $boot = $t0.AddHours(1) }
    $text = { param([datetime]$Value) ConvertTo-WfUtcString -Value $Value }
    $global:WfSynthetic.Cim['Win32_OperatingSystem'] = @{ Rows = @([ordered]@{ LastBootUpTime = (& $text $boot) }) }

    $rows = New-Object 'System.Collections.Generic.List[object]'
    $add = {
        param([string]$Name, $ProcessId, $Created, $Bytes, $Ops)
        $rows.Add([ordered]@{ Name = $Name; ProcessId = $ProcessId; CreationDate = $Created; WriteTransferCount = $Bytes; WriteOperationCount = $Ops })
    }
    if ($Rebooted) {
        & $add 'System' 4 (& $text $boot) 48000000 2100
        & $add 'svchost.exe' 912 (& $text $boot.AddSeconds(9)) 1200000 310
        & $add 'example-launcher.exe' 6020 (& $text $boot.AddMinutes(2)) 830000000 41000
    } elseif ($Stage -eq 'baseline') {
        & $add 'System' 4 (& $text $boot) 2400000000 180000
        & $add 'svchost.exe' 912 (& $text $boot.AddSeconds(9)) 5100000 2200
        & $add 'example-launcher.exe' 3000 (& $text $t0.AddHours(-1)) 4100000000 520000
        & $add 'example-sync.exe' 3100 (& $text $t0.AddHours(-20)) 990000 140
        & $add 'example-updater.exe' 3200 (& $text $t0.AddHours(-30)) 77000 12
        & $add 'example-agent.exe' 3300 (& $text $t0.AddHours(-40)) 64000 9
        & $add 'example-ghost.exe' 3500 $null 1000 1
        & $add 'example-cache.exe' 3400 (& $text $t0.AddHours(-41)) 9000000 800
        if ($GameRunning) { & $add 'FortniteClient-Win64-Shipping.exe' 3600 (& $text $t0.AddMinutes(-3)) 120000 30 }
    } else {
        & $add 'System' 4 (& $text $boot) 2650000000 199000
        & $add 'svchost.exe' 912 (& $text $boot.AddSeconds(9)) 5100000 2200
        & $add 'example-launcher.exe' 3000 (& $text $t0.AddHours(-1)) 9100000000 1030000
        & $add 'example-updater.exe' 3200 (& $text $t0.AddHours(2)) 3000 2
        & $add 'example-agent.exe' 3300 (& $text $t0.AddHours(-40)) $null 11
        & $add 'example-ghost.exe' 3500 $null 1500 2
        & $add 'example-cache.exe' 3400 (& $text $t0.AddHours(-41)) 8000000 810
        & $add 'example-overlay.exe' 3700 (& $text $t0.AddHours(1)) 2200000 400
    }
    if ($GuardFails) {
        $global:WfSynthetic.Cim['Win32_Process'] = @{ ErrorKind = 'access_denied'; ErrorMessage = 'Access denied' }
    } else {
        $global:WfSynthetic.Cim['Win32_Process'] = @{ Rows = $rows.ToArray() }
    }

    # Raw cumulative counters: two disk instances and the one Memory instance.
    $growth = $(if ($Stage -eq 'after' -and -not $Rebooted) { 1 } else { 0 })
    $stamp = [int64](($global:WfSynthetic.Now - [datetime]::new(1601, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).Ticks)
    $global:WfSynthetic.Cim['Win32_PerfRawData_PerfDisk_PhysicalDisk'] = @{ Rows = @(
            [ordered]@{ Name = '0 C:'; DiskWriteBytesPersec = 61000000000 + $growth * 3400000000; DiskWritesPersec = 2900000 + $growth * 160000; DiskReadBytesPersec = 88000000000 + $growth * 9100000000; DiskReadsPersec = 3500000 + $growth * 210000; Timestamp_Sys100NS = $stamp; Frequency_Sys100NS = 10000000 },
            [ordered]@{ Name = '_Total'; DiskWriteBytesPersec = 61000000000 + $growth * 3400000000; DiskWritesPersec = 2900000 + $growth * 160000; DiskReadBytesPersec = 88000000000 + $growth * 9100000000; DiskReadsPersec = 3500000 + $growth * 210000; Timestamp_Sys100NS = $stamp; Frequency_Sys100NS = 10000000 }
        ) }
    $global:WfSynthetic.Cim['Win32_PerfRawData_PerfOS_Memory'] = @{ Rows = @(
            [ordered]@{ Name = $null; PagesOutputPersec = 410000 + $growth * 52000; PageWritesPersec = 9100 + $growth * 700; PagesInputPersec = 2300000 + $growth * 90000; PageReadsPersec = 160000 + $growth * 6000; Timestamp_Sys100NS = $stamp; Frequency_Sys100NS = 10000000 }
        ) }

    # The configuration the trial depends on: TDR level 3, a complete memory
    # dump setting, the machine WER key without the named values, the others
    # absent.
    $global:WfSynthetic.Registry['HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'] = @{ Values = @(@{ Name = 'TdrLevel'; Kind = 'DWord'; Data = 3 }, @{ Name = 'TdrDelay'; Kind = 'DWord'; Data = 10 }); SubKeys = @('Configuration') }
    $global:WfSynthetic.Registry['HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'] = @{ Values = @(@{ Name = 'CrashDumpEnabled'; Kind = 'DWord'; Data = 1 }, @{ Name = 'LogEvent'; Kind = 'DWord'; Data = 1 }, @{ Name = 'AutoReboot'; Kind = 'DWord'; Data = 1 }); SubKeys = @() }
    $global:WfSynthetic.Registry['HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'] = @{ Values = @(); SubKeys = @('Consent') }
    $global:WfSynthetic.Commands['/getactivescheme'] = @{ ExitCode = 0; StdOut = (Get-WfSyntheticPowercfgText -Name 'getactivescheme-en'); StdErr = '' }

    # The event logs: one record before the boot (outside the count), the
    # boot itself, service starts, a recovered display driver timeout, and in
    # the after read one more timeout and one application crash.
    $systemOldest = $(if ($SystemLogWrapped) { 0.5 } else { 30 })
    $global:WfSynthetic.Channels['System'] = New-WfSyntheticChannelState -OldestDaysAgo $systemOldest -RecordCount 18200
    $global:WfSynthetic.Channels['Application'] = New-WfSyntheticChannelState -OldestDaysAgo 30 -RecordCount 9400
    $sinceBoot = { param([double]$Hours) (($global:WfSynthetic.Now - $boot).TotalDays) - ($Hours / 24.0) }
    $system = New-Object 'System.Collections.Generic.List[object]'
    $application = New-Object 'System.Collections.Generic.List[object]'
    $system.Add((New-WfSyntheticEvent -RecordId 18001 -Provider 'EventLog' -EventId 6006 -Level 4 -LevelDisplay 'Information' -DaysAgo (& $sinceBoot -0.1)))
    $system.Add((New-WfSyntheticEvent -RecordId 18010 -Provider 'Microsoft-Windows-Kernel-General' -EventId 12 -Level 4 -LevelDisplay 'Information' -DaysAgo (& $sinceBoot 0.001)))
    $system.Add((New-WfSyntheticEvent -RecordId 18020 -Provider 'Service Control Manager' -EventId 7036 -Level 4 -LevelDisplay 'Information' -DaysAgo (& $sinceBoot 0.01)))
    $system.Add((New-WfSyntheticEvent -RecordId 18021 -Provider 'Service Control Manager' -EventId 7036 -Level 4 -LevelDisplay 'Information' -DaysAgo (& $sinceBoot 0.02)))
    if (-not $Rebooted) {
        $system.Add((New-WfSyntheticEvent -RecordId 18100 -Provider 'Display' -EventId 4101 -Level 3 -LevelDisplay 'Warning' -DaysAgo (& $sinceBoot 20)))
        $application.Add((New-WfSyntheticEvent -RecordId 9300 -Channel 'Application' -Provider 'Application Error' -EventId 1000 -DaysAgo (& $sinceBoot 30)))
    }
    if ($Stage -eq 'after') {
        $system.Add((New-WfSyntheticEvent -RecordId 18200 -Provider 'Display' -EventId 4101 -Level 3 -LevelDisplay 'Warning' -DaysAgo 0.05))
        $application.Add((New-WfSyntheticEvent -RecordId 9390 -Channel 'Application' -Provider 'Application Error' -EventId 1000 -DaysAgo 0.04))
    }
    Add-WfSyntheticQuery -Match 'Path="System"' -Events $system.ToArray()
    Add-WfSyntheticQuery -Match 'Path="Application"' -Events $application.ToArray()
}
