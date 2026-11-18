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
#   interrupt_policy      for every present Display, Net, USB and MEDIA (audio)
#                         device: the values under Interrupt Management\
#                         Affinity Policy and Interrupt Management\
#                         MessageSignaledInterruptProperties of the device's
#                         hardware key, each with its registry type and bytes,
#                         next to the device's status and problem code
#   graphics_tdr          the documented timeout detection and recovery values
#                         under Control\GraphicsDrivers, present or absent
#   processors, cpu_caches
#                         Win32_Processor and Win32_CacheMemory: cores, logical
#                         processors, threads, cache levels and sizes
#   logical_processor_map not collected: which logical processor shares a core
#                         with which (the SMT siblings) needs
#                         GetLogicalProcessorInformationEx, a native call this
#                         script cannot make without compiling
#   power_active_scheme, power_schemes, power_aliases, power_settings,
#   power_settings_hidden powercfg /getactivescheme, /list, /aliases, /query
#                         and /qh: the active scheme, every scheme, the alias
#                         to GUID map, and the AC and DC indices of every
#                         setting of the active scheme
#   power_mode            not collected: no documented command prints the
#                         power mode overlay by itself (see reason.json)
#   timer_resolution      not collected: the current timer resolution has no
#                         documented read a 5.1 script can make; the inbox
#                         report that carries it needs Administrator
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
# https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_irq_device_policy
# https://learn.microsoft.com/windows-hardware/drivers/display/tdr-registry-keys
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-processor
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-cachememory
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-process
# https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity
# https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options
#
# Nothing here applies or changes a setting, creates a registry key, starts
# or stops a service or process, or opens a handle to a game: the registry is
# opened for reading, powercfg is run with listing verbs only, and the process
# list is read through the WMI provider with the properties the system
# process list carries; the command line is requested only for the timer
# helper (what the provider does inside the WMI host to fill a property is
# not documented and is on the README's verification list).
#
# Access: WMI namespaces grant Enable Account (read) to Authenticated Users
# by default (https://learn.microsoft.com/windows/win32/wmisdk/access-to-wmi-namespaces).
# Whether a standard account may open the hardware keys under Enum, run the
# powercfg listings, and list the Program Files folders is on the README's
# verification list; each is recorded as a status with Windows' message when
# it cannot.
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
    # Deadline for reading one source, in seconds (1 to 3600). Sixteen sources
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
# empty observation, and listed under Follow-up in the README.
$logicalProcessorMapReason = 'the logical processor to core map (which logical processors are SMT siblings, which share a cache, which group each belongs to) is exposed by GetLogicalProcessorInformationEx (https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex), a native call this Windows PowerShell 5.1 script cannot make without compiling code at run time, which the read only posture excludes; no CIM class documents the per logical processor mapping. Win32_Processor gives the core and logical processor counts (processors source), and Microsoft documents that a system with fewer than 64 logical processors has the single group 0 (https://learn.microsoft.com/windows/win32/procthread/processor-groups)'
$powerModeReason = 'Microsoft documents the power mode (performance power slider) overlays and their GUIDs (https://learn.microsoft.com/windows-hardware/customize/desktop/customize-power-slider) and that "powercfg /q" without arguments enumerates the active overlay scheme when one is active (https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options), but no command that prints the active overlay by itself; the decoder compares the scheme GUID printed by /query (power_settings) with /getactivescheme (power_active_scheme) and names a documented overlay GUID when they differ, which is an interpretation of that sentence, not a direct read'
$timerReason = 'the current timer resolution has no documented read a 5.1 script can make: timeGetDevCaps (https://learn.microsoft.com/windows/win32/api/timeapi/nf-timeapi-timegetdevcaps) returns the minimum and maximum period only and is a native call; the inbox report that lists the platform timer resolution and the outstanding requests is "powercfg /energy", which observes the system for 60 seconds and writes a report file, and Microsoft documents it for an idle system (https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options); it is left to the elevated task (collectors/windows/README.md, Needs elevation). "powercfg /requests" lists power requests, not timer requests, and is not timer evidence. Nothing here requests a timer period'

$definition = @{
    Name     = $collectorName
    Version  = '1.0.0'
    Question = 'What machine configuration confounds a latency run right now: device interrupt policy and MSI mode, CPU topology, power scheme and settings, timer state, and the state of Process Lasso and Stutter Guard?'
    Sources  = @(
        @{
            Id          = 'interrupt_policy'
            Type        = 'registry'
            Mode        = 'devices'
            Kind        = 'config_snapshot'
            Required    = $true
            Classes     = @('Display', 'Net', 'USB', 'MEDIA')
            SubKeys     = @('Interrupt Management\Affinity Policy', 'Interrupt Management\MessageSignaledInterruptProperties')
            Citations   = @(
                'https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority',
                'https://learn.microsoft.com/windows-hardware/drivers/kernel/enabling-message-signaled-interrupts-in-the-registry',
                'https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_irq_device_policy',
                'https://learn.microsoft.com/windows-hardware/drivers/install/hklm-system-currentcontrolset-enum-registry-tree'
            )
            Expectation = 'at least one present Display, Net, USB or MEDIA device exists; for each, the two Interrupt Management subkeys are read or recorded absent. Registry intention is not effective routing: which processor actually services an interrupt is not readable here and comes from a trace'
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
            Id              = 'logical_processor_map'
            Type            = 'unavailable'
            Kind            = 'config_snapshot'
            Required        = $false
            Question        = 'Which logical processors are SMT siblings of each other, which share a cache, and in which processor group is each?'
            Reason          = $logicalProcessorMapReason
            DocumentedPaths = @(
                [ordered]@{ path = 'GetLogicalProcessorInformationEx(RelationProcessorCore, RelationCache, RelationGroup)'; citation = 'https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex'; why_not_used = 'native call; needs code compiled at run time, which writes to the temp folder, both excluded by the read only posture' },
                [ordered]@{ path = 'Win32_Processor NumberOfCores and NumberOfLogicalProcessors'; citation = 'https://learn.microsoft.com/windows/win32/cimwin32prov/win32-processor'; why_not_used = 'read by the processors source; it tells whether SMT is enabled (NumberOfCores less than NumberOfLogicalProcessors), not which logical processor pairs with which' }
            )
            FollowUp        = 'a later collector with a documented native read, or the trace itself, must establish the sibling map; until then "CPU 6 and its sibling" is not evidence'
            Expectation     = 'the logical processor to core map is recorded with its group and cache sharing'
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
            MissingHint    = 'Stutter Guard keeps its journal under its ProgramData folder according to its published source; no journal means it never applied anything here or keeps it elsewhere.'
            Expectation    = 'the journal exists and is readable; its protected text and the hash of the original are recorded'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
