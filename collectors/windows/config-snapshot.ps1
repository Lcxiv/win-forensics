# config-snapshot: What machine configuration confounds a latency run, as it stands right now?
#
# Read only. Runs under Windows PowerShell 5.1 as a standard account that is a
# member of Event Log Readers. Writes one bundle (docs/contracts/bundle.md)
# into -OutputDirectory, prints one JSON summary line on stdout, and exits 0
# when the bundle is complete. See collectors/windows/README.md for the
# interface, the artifact formats, and the facts still to be verified on a
# real machine.
#
# A run sheet records this snapshot before and after a capture (-Snapshot
# start, then -Snapshot stop), so that a verdict can say which configuration
# the capture ran under and whether it changed during the run. Every source
# is a snapshot; there is no time window. Sources:
#
#   interrupt_policy      for every present PCI function (the display adapter,
#                         the network adapter, the USB host controllers, the HD
#                         Audio controller that owns the audio interrupt, the
#                         storage controllers): the values under Interrupt
#                         Management\Affinity Policy and Interrupt Management\
#                         MessageSignaledInterruptProperties of the device's
#                         hardware key, opened through SetupDiOpenDevRegKey
#                         (DIREG_DEV, KEY_READ), each with its registry type and
#                         bytes, next to the device's status and problem code
#   graphics_tdr          the documented timeout detection and recovery values
#                         under Control\GraphicsDrivers, present or absent
#   processors, cpu_caches
#                         Win32_Processor and Win32_CacheMemory: cores, logical
#                         processors, threads, cache levels and sizes
#   logical_processor_map GetLogicalProcessorInformationEx with RelationAll:
#                         which logical processors share a core (the SMT
#                         siblings), a cache, a package and a group, from the
#                         documented buffer layouts
#   power_active_scheme, power_schemes, power_aliases, power_settings,
#   power_settings_hidden powercfg /getactivescheme, /list, /aliases, /query
#                         and /qh: the active scheme, every scheme, the alias
#                         to GUID map, and the AC and DC indices of every
#                         setting of the active scheme
#   power_mode            not collected: no documented command prints the
#                         power mode overlay by itself (see reason.json)
#   timer_resolution      not collected: the current timer resolution has no
#                         documented read this collector can make without a
#                         timer request of its own; see reason.json
#   processes             Win32_Process, the properties the system process list
#                         carries (no command line, no image path)
#   timer_helper_process  Win32_Process filtered to DpcTimerRes.exe, with its
#                         command line and image path
#   process_lasso_install, stutter_guard_install
#                         the files under the conventional install folders,
#                         hashed and versioned, never copied
#   process_lasso_config, process_lasso_log, stutter_guard_journal
#                         protected copies of the configuration, the action
#                         log and the journal, with the hash of the original
#
# Citations for the keys and classes read:
# https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority
# https://learn.microsoft.com/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry
# https://learn.microsoft.com/windows-hardware/drivers/install/opening-a-device-s-hardware-key
# https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey
# https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_irq_device_policy
# https://learn.microsoft.com/windows-hardware/drivers/audio/intel-s-hd-audio-architecture
# https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex
# https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-processor
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-cachememory
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-process
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity
# https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options
#
# Nothing here applies or changes a setting, creates a registry key, starts
# or stops a service or process, or opens a handle to any process: the
# registry is opened for reading (KEY_READ), powercfg is run with listing
# verbs only, the two native reads (the device hardware keys and the
# processor topology) are documented queries declared in two literal blocks
# the static tests pin, and the process list is read through the WMI provider
# with the properties the system process list carries; the command line is
# requested only for the timer helper and is protected before it is written
# (what the provider does inside the WMI host to fill a property is not
# documented and is on the README's verification list). Take this snapshot
# with the game and its anti-cheat closed.
#
# Access: WMI namespaces grant Enable Account (read) to Authenticated Users
# by default (https://learn.microsoft.com/windows/win32/wmisdk/access-to-wmi-namespaces).
# Whether a standard account may open the device hardware keys through
# SetupDiOpenDevRegKey, whether the two native declarations compile under
# Windows PowerShell 5.1, and whether it may run the powercfg listings and
# list the Program Files folders is on the README's verification list; each
# is recorded as a status with Windows' message when it cannot.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # Which snapshot of a before and after pair this run is: start (also a
    # standalone read) or stop. Recorded with the process list so the decoder
    # can label the process_inventory rows.
    [string]$Snapshot = 'start',
    # Cap on records per source (1 to 100000): processes, devices, files.
    [int]$MaxEvents = 5000,
    # Cap on the size of one export, in bytes (1 MiB to 1 GiB).
    [long]$MaxArtifactBytes = 67108864,
    # Deadline for reading one source, in seconds (1 to 3600). Seventeen sources
    # read something and share the dispatcher's 900 second budget, so the
    # default is 50.
    [int]$TimeoutSeconds = 50
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# powershell.exe writes progress and warning records to stdout, which belongs
# to the summary line alone. Problems are reported through the manifest and
# stderr instead.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$collectorName = 'config-snapshot'
$common = Join-Path -Path $PSScriptRoot -ChildPath '_common.ps1'
if (-not $OutputDirectory -or -not (Test-Path -LiteralPath $common) -or ($Snapshot -ne 'start' -and $Snapshot -ne 'stop')) {
    # Without the helper or an output directory there is no bundle to write;
    # the summary line is still printed so the dispatcher gets its one line.
    if (-not $OutputDirectory) { [Console]::Error.WriteLine($collectorName + ': -OutputDirectory is required') }
    elseif (-not (Test-Path -LiteralPath $common)) { [Console]::Error.WriteLine($collectorName + ': the shared helper is missing: ' + $common) }
    else { [Console]::Error.WriteLine($collectorName + ': -Snapshot must be start or stop') }
    $bundleText = ([string]$OutputDirectory).Replace('\', '\\').Replace('"', '\"')
    [Console]::Out.WriteLine('{"collector":"' + $collectorName + '","status":"failed","bundle":"' + $bundleText + '","artifacts":0}')
    exit 1
}
. $common

$powercfgZero = 'powercfg exited with code 0 and printed no line with a GUID; every scheme, subgroup, setting and alias line carries one, so this output is not the listing asked for'
$powercfgExpectation = 'powercfg exits with code 0 and prints at least one line with a GUID'

# The questions this collector cannot answer with a documented read only
# path. Each is recorded as not_collected with its reason, never as an
# empty observation, and listed in the README's source table.
$powerModeReason = 'Microsoft documents the power mode (performance power slider) overlays and their GUIDs (https://learn.microsoft.com/windows-hardware/customize/desktop/customize-power-slider) and that "powercfg /q" without arguments enumerates the active overlay scheme when one is active (https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options), but no command that prints the active overlay by itself; the decoder compares the scheme GUID printed by /query (power_settings) with /getactivescheme (power_active_scheme) and names a documented overlay GUID when they differ, which is an interpretation of that sentence, not a direct read'
$timerReason = 'the current timer resolution has no documented read this collector can make: timeGetDevCaps (https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timegetdevcaps) returns the minimum and maximum period only, and Microsoft documents no public query of the period in effect; "powercfg /energy" observes the system for 60 seconds by default and writes a report file, which Microsoft documents for an idle system with no open programs (https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options), so it is left to the elevated task, and whether its report names the timer resolution and its requesters is a verification item, not a fact asserted here. "powercfg /requests" lists power requests, not timer requests, and is not timer evidence. Nothing here requests a timer period'

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = 'What machine configuration confounds a latency run right now: device interrupt policy and MSI mode, CPU topology, power scheme and settings, timer state, and the state of Process Lasso and Stutter Guard?'
    Sources  = @(
        @{
            Id               = 'interrupt_policy'
            Type             = 'registry'
            Mode             = 'devices'
            Kind             = 'config_snapshot'
            Required         = $true
            # Every present PCI function: the bus whose devices own interrupts and
            # message signaled interrupt configuration. The display adapter, the
            # network adapter, the USB host controllers and the HD Audio controller
            # are PCI functions; the audio codec nodes (HDAUDIO\FUNC_xx) and USB
            # devices are children that own no interrupt of their own, so they are
            # not selected.
            InstancePrefixes = @('PCI\')
            Classes          = @()
            MaxValuesPerKey  = 64
            Citations        = @(
                'https://learn.microsoft.com/windows-hardware/drivers/install/opening-a-device-s-hardware-key',
                'https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey',
                'https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority',
                'https://learn.microsoft.com/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry',
                'https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_irq_device_policy',
                'https://learn.microsoft.com/windows-hardware/drivers/audio/intel-s-hd-audio-architecture',
                'https://learn.microsoft.com/windows-hardware/drivers/audio/low-latency-audio'
            )
            Expectation      = 'at least one present PCI function exists; for each, its hardware key is opened through SetupDiOpenDevRegKey and the two Interrupt Management subkeys are read, recorded absent when the API says they are not there, or recorded unknown when they could not be opened. Registry intention is not effective routing: which processor actually services an interrupt is not readable here and comes from a trace'
        },
        @{
            Id          = 'graphics_tdr'
            Type        = 'registry'
            Mode        = 'keys'
            Kind        = 'config_snapshot'
            Required    = $false
            Keys        = @(
                @{
                    Path     = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
                    Values   = @('TdrLevel', 'TdrDelay', 'TdrDdiDelay', 'TdrDebugMode', 'TdrLimitTime', 'TdrLimitCount', 'TdrTestMode')
                    Citation = 'https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys'
                }
            )
            Citations   = @('https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys')
            Expectation = 'the GraphicsDrivers key is opened and each documented TDR value is recorded as present (with type and bytes) or absent'
        },
        @{
            Id         = 'processors'
            Type       = 'cim'
            Kind       = 'config_snapshot'
            Required   = $true
            ClassName  = 'Win32_Processor'
            Properties = @('DeviceID', 'Name', 'Manufacturer', 'Description', 'SocketDesignation', 'NumberOfCores', 'NumberOfEnabledCore', 'NumberOfLogicalProcessors', 'ThreadCount',
                'L2CacheSize', 'L3CacheSize', 'MaxClockSpeed', 'CurrentClockSpeed', 'Architecture', 'Family', 'Level', 'Revision', 'Stepping', 'ProcessorId',
                'VirtualizationFirmwareEnabled', 'SecondLevelAddressTranslationExtensions', 'Status', 'CpuStatus', 'Availability')
        },
        @{
            Id         = 'cpu_caches'
            Type       = 'cim'
            Kind       = 'config_snapshot'
            Required   = $false
            ClassName  = 'Win32_CacheMemory'
            Properties = @('DeviceID', 'Purpose', 'Level', 'CacheType', 'Associativity', 'InstalledSize', 'MaxCacheSize', 'BlockSize', 'NumberOfBlocks', 'LineSize', 'CacheSpeed', 'Location', 'Status', 'ErrorCorrectType', 'WritePolicy')
        },
        @{
            Id          = 'logical_processor_map'
            Type        = 'topology'
            Kind        = 'config_snapshot'
            Required    = $true
            Citations   = @(
                'https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex',
                'https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex',
                'https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-processor_relationship',
                'https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-cache_relationship',
                'https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_relationship',
                'https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_affinity'
            )
            Expectation = 'GetLogicalProcessorInformationEx returns a buffer that parses by the documented layouts and holds one RelationProcessorCore record per active core, so each logical processor can be placed on its core next to its SMT sibling, its caches and its group'
        },
        @{
            Id             = 'power_active_scheme'
            Type           = 'command'
            Kind           = 'powercfg'
            Required       = $true
            Tool           = 'powercfg'
            Arguments      = '/getactivescheme'
            Protect        = 'generic'
            Records        = 'guid_lines'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $powercfgZero
            RecordsMeaning = 'lines carrying a GUID (the active scheme)'
            Expectation    = $powercfgExpectation
        },
        @{
            Id             = 'power_schemes'
            Type           = 'command'
            Kind           = 'powercfg'
            Required       = $false
            Tool           = 'powercfg'
            Arguments      = '/list'
            Protect        = 'generic'
            Records        = 'guid_lines'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $powercfgZero
            RecordsMeaning = 'lines carrying a GUID (one per scheme)'
            Expectation    = $powercfgExpectation
        },
        @{
            Id             = 'power_aliases'
            Type           = 'command'
            Kind           = 'powercfg'
            Required       = $false
            Tool           = 'powercfg'
            Arguments      = '/aliases'
            Protect        = 'generic'
            Records        = 'guid_lines'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $powercfgZero
            RecordsMeaning = 'lines carrying a GUID (one per alias)'
            Expectation    = $powercfgExpectation
        },
        @{
            Id             = 'power_settings'
            Type           = 'command'
            Kind           = 'powercfg'
            Required       = $true
            Tool           = 'powercfg'
            Arguments      = '/query'
            Protect        = 'generic'
            Records        = 'guid_lines'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $powercfgZero
            RecordsMeaning = 'lines carrying a GUID (the scheme, each subgroup, each setting)'
            Expectation    = $powercfgExpectation
        },
        @{
            Id             = 'power_settings_hidden'
            Type           = 'command'
            Kind           = 'powercfg'
            Required       = $false
            Tool           = 'powercfg'
            Arguments      = '/qh'
            Protect        = 'generic'
            Records        = 'guid_lines'
            ZeroRule       = 'capture_failed'
            ZeroReason     = $powercfgZero
            RecordsMeaning = 'lines carrying a GUID (the scheme, each subgroup, each setting including the hidden ones)'
            Expectation    = $powercfgExpectation
        },
        @{
            Id              = 'power_mode'
            Type            = 'unavailable'
            Kind            = 'powercfg'
            Required        = $false
            Question        = 'Which Windows power mode (performance power slider overlay) is active?'
            Reason          = $powerModeReason
            DocumentedPaths = @(
                [ordered]@{ path = 'powercfg /q (no arguments)'; citation = 'https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options'; why_not_used = 'read by the power_settings source; Microsoft says it enumerates the active overlay when one is active, so the decoder derives the overlay from the GUID it prints, which is marked as derived' },
                [ordered]@{ path = 'overlay GUIDs'; citation = 'https://learn.microsoft.com/windows-hardware/customize/desktop/customize-power-slider'; why_not_used = 'documents the overlay GUIDs, not a command that prints the active one' }
            )
            FollowUp        = 'a documented direct read of the active overlay, if Microsoft publishes one'
            Expectation     = 'the active power mode overlay is read directly'
        },
        @{
            Id              = 'timer_resolution'
            Type            = 'unavailable'
            Kind            = 'other'
            Required        = $false
            Question        = 'What are the current, minimum and maximum timer resolutions, and which processes hold a request?'
            Reason          = $timerReason
            DocumentedPaths = @(
                [ordered]@{ path = 'timeGetDevCaps (TIMECAPS wPeriodMin, wPeriodMax)'; citation = 'https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timegetdevcaps'; why_not_used = 'native call; minimum and maximum only' },
                [ordered]@{ path = 'powercfg /energy /output <file> /duration <s>'; citation = 'https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options'; why_not_used = 'observes the system for 60 seconds and writes a report; Microsoft documents it for an idle system; left to the elevated task' },
                [ordered]@{ path = 'powercfg /requests'; citation = 'https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options'; why_not_used = 'lists power requests (display, system, away mode), which are not timer resolution requests' }
            )
            FollowUp        = 'the elevated task runs powercfg /energy into the bundle, or a later collector gets a documented native read; the timer helper process and its command line are recorded by timer_helper_process meanwhile'
            Expectation     = 'the current, minimum and maximum timer resolutions are read without requesting a period'
        },
        @{
            Id         = 'processes'
            Type       = 'cim'
            Kind       = 'process_inventory'
            Required   = $true
            ClassName  = 'Win32_Process'
            Properties = @('Name', 'ProcessId', 'ParentProcessId', 'SessionId', 'CreationDate', 'Priority', 'ThreadCount', 'HandleCount', 'WorkingSetSize', 'PageFaults', 'KernelModeTime', 'UserModeTime')
            Options    = [ordered]@{ snapshot = $Snapshot; command_line_requested = $false; image_path_requested = $false }
        },
        @{
            Id                         = 'timer_helper_process'
            Type                       = 'cim'
            Kind                       = 'process_inventory'
            Required                   = $false
            ClassName                  = 'Win32_Process'
            Filter                     = "Name = 'DpcTimerRes.exe'"
            Properties                 = @('Name', 'ProcessId', 'ParentProcessId', 'SessionId', 'CreationDate', 'Priority', 'CommandLine', 'ExecutablePath')
            ProtectProperties          = @('CommandLine', 'ExecutablePath')
            EmptySnapshotIsObservation = $true
            Options                    = [ordered]@{ snapshot = $Snapshot; command_line_requested = $true; image_path_requested = $true }
        },
        @{
            Id             = 'process_lasso_install'
            Type           = 'directory'
            Kind           = 'config_snapshot'
            Required       = $false
            Folder         = 'ProgramFiles'
            PathTail       = 'Process Lasso'
            PathDocumented = $false
            Expectation    = 'the folder is listed when it exists; a missing folder is an observation (not installed at the conventional path)'
        },
        @{
            Id             = 'process_lasso_config'
            Type           = 'file'
            Mode           = 'copy'
            Kind           = 'config_snapshot'
            Required       = $false
            Folder         = 'ProgramData'
            PathTail       = 'ProcessLasso\config\prolasso.ini'
            PathDocumented = $false
            FileName       = 'prolasso.ini'
            MissingHint    = 'Bitsum documents a per user configuration folder by default and a global path chosen in the installer (https://bitsum.com/apps/process-lasso/docs/reference/ini-config/); the About window of Process Lasso shows the actual path. A per user path sits in the owner''s profile, which this account cannot read.'
            Expectation    = 'the configuration file exists at the global ProgramData path and is readable; its protected text and the hash of the original are recorded'
        },
        @{
            Id                 = 'process_lasso_log'
            Type               = 'file'
            Mode               = 'copy'
            Kind               = 'config_snapshot'
            Required           = $false
            Folder             = 'ProgramData'
            PathTail           = 'ProcessLasso\logs\processlasso.log'
            AlternatePathTails = @('ProcessLasso\logs\prolasso.log', 'ProcessLasso\prolasso.log')
            PathDocumented     = $false
            FileName           = 'processlasso.log'
            # Bitsum: process command lines are not logged by default "because they
            # may contain user sensitive information" and are switched on by the
            # IncludeCommandLines setting (https://bitsum.com/apps/process-lasso/docs/interface/logging/,
            # https://bitsum.com/apps/process-lasso/docs/reference/ini-config/). The
            # log is copied only when the copied INI says that switch is off;
            # otherwise it is summarised (size, time, hash, line count). The
            # switch says nothing about lines written while it was on, so in
            # the copy everything after a program in a field is removed by
            # shape first; the gate is the second layer.
            StripArgumentsAfterExecutable = $true
            CopyGate           = @{ Source = 'process_lasso_config'; Pattern = '(?im)^\s*IncludeCommandLines\s*=\s*(false|0)\s*$'; Reason = 'the INI does not say IncludeCommandLines is off, so the log may carry process command lines, which the vendor documents as possibly sensitive and whose removal by shape misses a program without a known extension' }
            MissingHint        = 'Bitsum names the action log prolasso.log (https://bitsum.com/apps/process-lasso/docs/getting-started/how-it-works/) and says its path is set under Options / General / Configure Startup (https://bitsum.com/apps/process-lasso/docs/interface/logging/); the candidates tried are listed in source.json.'
            Expectation        = 'the action log exists at one of the candidate paths and is readable; its protected text and the hash of the original are recorded'
        },
        @{
            Id             = 'stutter_guard_install'
            Type           = 'directory'
            Kind           = 'config_snapshot'
            Required       = $false
            Folder         = 'ProgramFiles'
            PathTail       = 'Stutter Guard'
            PathDocumented = $false
            Expectation    = 'the folder is listed when it exists (StutterGuard.exe and DpcTimerRes.exe are hashed and versioned); a missing folder is an observation (not installed at the conventional path)'
        },
        @{
            Id             = 'stutter_guard_journal'
            Type           = 'file'
            Mode           = 'copy'
            Kind           = 'config_snapshot'
            Required       = $false
            Folder         = 'ProgramData'
            PathTail       = 'Stutter Guard\journal.json'
            PathDocumented = $false
            FileName       = 'journal.json'
            # The journal path and the install folder come from the program's published
            # source (Paths.cs: DataDir is CommonApplicationData\Stutter Guard, JournalFile
            # is journal.json, InstallDir is ProgramFiles\Stutter Guard); its options are
            # saved inside the journal's state (Options.cs, Save), so there is no separate
            # settings file to copy:
            # https://github.com/Kareem-Shabaka/stutter-guard/blob/4e1a61b13a7b7151552935116655c2264dfc1923/src/DpcTweaker.Core/Infra/Paths.cs#L13
            # https://github.com/Kareem-Shabaka/stutter-guard/blob/4e1a61b13a7b7151552935116655c2264dfc1923/src/DpcTweaker.Core/Tweaks/Options.cs#L282
            MissingHint    = 'Stutter Guard keeps its journal at CommonApplicationData\Stutter Guard\journal.json (Paths.cs in its published source, pinned above); no journal means it never applied anything here or keeps its data elsewhere.'
            Expectation    = 'the journal exists and is readable; its protected text and the hash of the original are recorded; the program''s options are saved inside it'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
