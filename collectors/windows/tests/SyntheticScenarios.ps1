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

    return $cases.ToArray()
}
