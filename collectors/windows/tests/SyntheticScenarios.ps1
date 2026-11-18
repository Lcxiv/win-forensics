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
    $global:WfSynthetic.Account = @{ Elevated = $Elevated; EventLogReaders = $true; PerformanceLogUsers = $PerformanceLogUsers }
    if (-not $Present) {
        $global:WfSynthetic.Binaries.Remove((Get-WfSyntheticPresentMonPath))
        return
    }
    if (-not $Sha256) { $Sha256 = Get-WfSyntheticPresentMonPinnedSha256 }
    $global:WfSynthetic.Binaries[(Get-WfSyntheticPresentMonPath)] = @{ Length = $Length; Sha256 = $Sha256; FileVersion = '2.6.0.0'; ProductVersion = '2.6.0' }
}

function Get-WfSyntheticWprStatusText {
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
        [int]$EndOffsetSeconds = -1, [int]$BufferSize = 4096, [int]$HeaderType = 2)
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
        $pw.Write([int64]$end.ToFileTimeUtc())      # EndTime
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
    $global:WfSynthetic.Programs.Add(@{ Path = $wpr; Match = '-status collectors -details'; ExitCode = 0; StdOut = (Get-WfSyntheticWprStatusText -InProgress $InProgressAtEnd -EventsLost $EventsLost -Collectors $true -DroppedEvents $DroppedEvents -ProviderLines $ProviderLines -DxgKrnlKeywords $DxgKrnlKeywords); StdErr = ''; Seconds = 1 })
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
    $probe = @{ ExitCode = 0; StdOut = (Get-WfSyntheticWprStatusText -InProgress $ProbeInProgress); StdErr = ''; Seconds = 1 }
    if ($ProbeFails) { $probe = @{ ExitCode = 2; StdOut = ''; StdErr = "synthetic wpr: -status failed`r`n"; Seconds = 1 } }
    if ($ProbeStuck) { $probe['Stuck'] = $true }
    $after = @{ ExitCode = 0; StdOut = (Get-WfSyntheticWprStatusText -InProgress $AfterInProgress); StdErr = ''; Seconds = 1 }
    $responses = @($probe, $after)
    # A probe that keeps reporting the instance in progress: the collector
    # cancels once, probes again, and must then stop.
    if ($ProbeInProgress) { $responses = @($probe, $probe, $after) }
    if ($LeftoverActive) {
        $responses = @(@{ ExitCode = 0; StdOut = (Get-WfSyntheticWprStatusText -InProgress $true); StdErr = ''; Seconds = 1 }, $probe, $after)
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
