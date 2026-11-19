# session-ledger: When was a game or launcher played, and which crash records does the machine keep that the history collectors do not read?
#
# Read only, history only: nothing here starts a trace or waits for a game.
# Runs under Windows PowerShell 5.1 between play sessions, as the account
# that plays (the game and launcher logs sit in that account's own profile
# folders, which another standard account cannot list). Writes one bundle
# (docs/contracts/bundle.md) into -OutputDirectory, prints one JSON summary
# line on stdout, and exits 0 when the bundle is complete. See
# collectors/windows/README.md ("The session-ledger sources") for the
# interface, the artifact formats, the status rules, and the facts still to be
# verified on a real machine, and docs/session-ledger.md for how the Mac side
# builds the ledger from this bundle and the history bundles.
#
# What this collector adds, and what it leaves to the others. The ledger joins
# this bundle with bugcheck-history (Kernel-Power 41 with its BugcheckCode,
# bug check 1001), tdr-events (the Display provider), application-errors
# (Application Error 1000, Application Hang 1002, Windows Error Reporting
# 1001) and whea-errors; none of those records is read again here. This
# collector reads only what none of them reads:
#
#   play sessions   the times of the game and launcher log files, from the
#                   folder listing alone: a log's creation time is taken as a
#                   session start and its last write as an inferred end. No
#                   log is opened: the times answer the question, and the
#                   text can carry account and network details. No game
#                   process is touched: the listing reads the file system,
#                   never a process, so there is no handle, injection, overlay
#                   or priority change for an anti-cheat to see.
#   display driver  the System log records of the display adapter's own
#                   driver. Device drivers write to the System log under a
#                   source name of their own:
#                   https://learn.microsoft.com/windows/win32/eventlog/event-sources
#                   Which name is not documented for any vendor, so the
#                   collector reads the service name of every Display class
#                   device (class GUID 4d36e968-e325-11ce-bfc1-08002be10318,
#                   https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors)
#                   from Win32_PnPEntity.Service:
#                   https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity
#                   and queries the System log for providers of that name.
#                   That the provider name equals the service name is the
#                   working assumption (README verification list), so the
#                   source is QuietClaimVerified false: records found are
#                   evidence, an empty result is capture_failed.
#   WerKernel       the Microsoft-Windows-WerKernel/Operational channel.
#                   Microsoft Learn does not document it; QuietClaimVerified
#                   false, and a channel that is not there is unsupported.
#   crash files     the names, sizes and times (never the contents) of the
#                   live kernel dumps (%systemroot%\LiveKernelReports, one
#                   folder per component:
#                   https://learn.microsoft.com/windows-hardware/drivers/debugger/kernel-live-dump-code-reference),
#                   the small memory dumps (%SystemRoot%\Minidump:
#                   https://learn.microsoft.com/windows-hardware/drivers/debugger/small-memory-dump),
#                   and the queued and archived Windows Error Reporting
#                   reports (%ProgramData%\Microsoft\Windows\WER\ReportQueue
#                   and ReportArchive:
#                   https://learn.microsoft.com/windows-server/failover-clustering/troubleshooting-using-wer-reports).
#
# Not read: Process Lasso's log. Bitsum documents where the log is and which
# settings turn process logging on, not the format of a line:
# https://bitsum.com/apps/process-lasso/docs/interface/logging/
# Parsing it safely needs that format, so it is a follow-up, and the play
# times come from the games' own logs.
#
# Elevation: none is required. The two dump folders under the Windows
# directory have no documented access list; a refused listing is
# not_collected with its reason (README, Needs elevation). The collector never
# builds an elevation of its own.
[CmdletBinding()]
param(
    # The only parameter the dispatcher passes. It is checked in the script
    # body, not marked Mandatory, because a missing Mandatory parameter makes
    # an interactive PowerShell prompt and a collector never prompts.
    [string]$OutputDirectory,
    # How far back to read the event log sources, in days (1 to 365). The file
    # listings are snapshots of what the folders hold now.
    [int]$WindowDays = 30,
    # Cap on records per event source and on entries per listing (1 to
    # 100000). Reaching it marks the source capture_failed.
    [int]$MaxEvents = 5000,
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

$collectorName = 'session-ledger'
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

# Names kept verbatim. Anything else becomes name-<12 hex>: a log or report
# name the patterns do not expect could carry an account or machine name.
#   game and launcher logs: a word, then optional "-backup", then numeric groups
$logNamePattern = '^[A-Za-z]{1,40}(-backup)?([-_. ][0-9]{1,20}){0,8}\.(log|txt)$'
#   dump files: a component word or a date code, then numeric groups
$dumpNamePattern = '^[A-Za-z0-9]{1,40}([-_][0-9]{1,20}){0,6}\.dmp$'
#   live kernel dump component folders: an upper case word (WATCHDOG, NDIS)
$componentPattern = '^[A-Za-z0-9]{1,40}$'
#   files inside a report folder: Report.wer, memory.hdmp, a cab
$reportFilePattern = '^[A-Za-z0-9]{1,40}(\.[A-Za-z0-9]{1,12}){1,3}$'

$definition = @{
    Name               = $collectorName
    Version            = '1.0.0'
    Question           = 'When was a game or launcher played, and which crash records does the machine keep that the history collectors do not read?'
    Sources            = @(
        @{
            # Blizzard documents Documents > Overwatch > Logs (with an Errors
            # folder inside) as where Overwatch writes its logs:
            # https://us.support.blizzard.com/en/article/82454
            Id             = 'overwatch_logs'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'MyDocuments'
            PathTail       = 'Overwatch\Logs'
            PathDocumented = 'https://us.support.blizzard.com/en/article/82454'
            Depth          = 1
            Include        = @('*.log', '*.txt')
            NamePattern    = $logNamePattern
            FolderPattern  = '^[A-Za-z]{1,40}$'
            Absence        = 'unproven'
            AbsentReason   = 'Overwatch writes this folder for the account that plays; run the collector as that account'
            ZeroReason     = 'a folder with no retained log cannot show that the game was not played'
            Expectation    = 'the Overwatch log folder exists and holds at least one log'
        },
        @{
            # Blizzard does not document a Battle.net desktop app log folder
            # (README verification list); this path is the working assumption.
            Id             = 'battlenet_logs'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'LocalApplicationData'
            PathTail       = 'Battle.net\Logs'
            PathDocumented = 'not documented by Blizzard; working assumption, see collectors/windows/README.md'
            Depth          = 0
            Include        = @('*.log')
            NamePattern    = $logNamePattern
            Absence        = 'unproven'
            AbsentReason   = 'the Battle.net log folder is not documented, so a missing folder may be a wrong path as well as an app that never ran for this account'
            ZeroReason     = 'a folder with no retained log cannot show that the launcher did not run'
            Expectation    = 'the Battle.net log folder exists and holds at least one log'
        },
        @{
            # Epic documents %localappdata%\FortniteGame\Saved\Logs:
            # https://www.epicgames.com/help/en-US/c-Category_Fortnite/c-Fortnite_TechnicalSupport/how-do-i-gather-logs-for-fortnite-a000084841
            Id             = 'fortnite_logs'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'LocalApplicationData'
            PathTail       = 'FortniteGame\Saved\Logs'
            PathDocumented = 'https://www.epicgames.com/help/en-US/c-Category_Fortnite/c-Fortnite_TechnicalSupport/how-do-i-gather-logs-for-fortnite-a000084841'
            Depth          = 0
            Include        = @('FortniteGame*.log')
            NamePattern    = $logNamePattern
            Absence        = 'unproven'
            AbsentReason   = 'Fortnite writes this folder for the account that plays; run the collector as that account'
            ZeroReason     = 'a folder with no retained log cannot show that the game was not played'
            Expectation    = 'the Fortnite log folder exists and holds at least one log'
        },
        @{
            # Epic documents %localappdata%\EpicGamesLauncher\Saved\Logs:
            # https://www.epicgames.com/help/en-US/c-Category_EpicGamesStore/c-EpicGamesStore_LauncherSupport/how-do-i-gather-logs-for-epic-games-launcher-a000084789
            Id             = 'epic_launcher_logs'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'LocalApplicationData'
            PathTail       = 'EpicGamesLauncher\Saved\Logs'
            PathDocumented = 'https://www.epicgames.com/help/en-US/c-Category_EpicGamesStore/c-EpicGamesStore_LauncherSupport/how-do-i-gather-logs-for-epic-games-launcher-a000084789'
            Depth          = 0
            Include        = @('EpicGamesLauncher*.log')
            NamePattern    = $logNamePattern
            Absence        = 'unproven'
            AbsentReason   = 'the Epic Games Launcher writes this folder for the account that runs it; run the collector as that account'
            ZeroReason     = 'a folder with no retained log cannot show that the launcher did not run'
            Expectation    = 'the Epic Games Launcher log folder exists and holds at least one log'
        },
        @{
            # The display adapters and the service that drives each one. The
            # rows are handed to display_driver_events below.
            Id                         = 'display_adapters'
            Type                       = 'cim'
            Required                   = $false
            Kind                       = 'other'
            ClassName                  = 'Win32_PnPEntity'
            Properties                 = @('Name', 'Service', 'Status', 'ConfigManagerErrorCode', 'Present')
            Filter                     = "ClassGuid = '{4d36e968-e325-11ce-bfc1-08002be10318}'"
            EmptySnapshotIsObservation = $false
        },
        @{
            Id       = 'display_driver_events'
            Type     = 'script'
            Required = $false
            Invoke   = {
                param($Source, $BundleRoot, $MaxArtifactBytes, $TimeoutSeconds, $Log, $Notes, $Context)
                # The provider names come from the display adapters read just
                # before; each must be a plain service name before it goes into
                # the query (it is a value Windows reported, not a literal).
                $services = New-Object 'System.Collections.Generic.List[string]'
                $rows = @()
                if ($Context['SourceRows'].ContainsKey('display_adapters')) { $rows = $Context['SourceRows']['display_adapters'] }
                foreach ($row in @($rows)) {
                    $service = [string]$row['Service']
                    if ($service -cmatch '^[A-Za-z0-9_.-]{1,64}$' -and -not $services.Contains($service)) { $services.Add($service) }
                }
                if ($services.Count -eq 0) {
                    $unavailable = @{
                        Id       = [string]$Source['Id']
                        Type     = 'unavailable'
                        Required = $false
                        Question = 'Which System log records did the display adapter driver write?'
                        DocumentedPaths = @('https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity', 'https://learn.microsoft.com/windows/win32/eventlog/event-sources')
                        Reason   = 'no display adapter service name was read (source display_adapters did not report one), so there is no provider name to query the System log for'
                    }
                    return (Invoke-WfUnavailableSource -Source $unavailable -BundleRoot $BundleRoot -Log $Log)
                }
                $names = @($services.ToArray() | ForEach-Object { "@Name='" + $_ + "'" })
                $eventSource = @{
                    Id                 = [string]$Source['Id']
                    Type               = 'eventlog'
                    Required           = $false
                    Channel            = 'System'
                    Providers          = @($services.ToArray())
                    EventIds           = @()
                    Predicates         = @('Provider[' + ($names -join ' or ') + ']')
                    QuietClaimVerified = $false
                }
                return (Invoke-WfEventSource -Source $eventSource -BundleRoot $BundleRoot -WindowDays ([int]$Context['WindowDays']) -MaxEvents ([int]$Context['MaxEvents']) `
                        -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -Log $Log -Notes $Notes -Context $Context)
            }
        },
        @{
            # Not documented on Microsoft Learn: records found are evidence,
            # an empty result is not a quiet window.
            Id                 = 'werkernel_events'
            Type               = 'eventlog'
            Required           = $false
            Channel            = 'Microsoft-Windows-WerKernel/Operational'
            Providers          = @()
            EventIds           = @()
            Predicates         = @()
            QuietClaimVerified = $false
        },
        @{
            Id             = 'live_kernel_reports'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'dump'
            Folder         = 'Windows'
            PathTail       = 'LiveKernelReports'
            PathDocumented = 'https://learn.microsoft.com/windows-hardware/drivers/debugger/kernel-live-dump-code-reference'
            Depth          = 1
            Include        = @('*.dmp')
            NamePattern    = $dumpNamePattern
            FolderPattern  = $componentPattern
            Absence        = 'observation'
            Expectation    = 'the live kernel dump folder could be listed'
        },
        @{
            Id             = 'minidumps'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'dump'
            Folder         = 'Windows'
            PathTail       = 'Minidump'
            PathDocumented = 'https://learn.microsoft.com/windows-hardware/drivers/debugger/small-memory-dump'
            Depth          = 0
            Include        = @('*.dmp')
            NamePattern    = $dumpNamePattern
            Absence        = 'observation'
            Expectation    = 'the small memory dump folder could be listed'
        },
        @{
            # A report is a folder; its name starts with the report kind
            # (Critical_, NonCritical_, AppCrash_ ...) and goes on with an
            # application name and hashes, so the folder name is a pseudonym
            # and only the leading kind word is kept (PrefixPattern).
            Id             = 'wer_report_queue'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'ProgramData'
            PathTail       = 'Microsoft\Windows\WER\ReportQueue'
            PathDocumented = 'https://learn.microsoft.com/windows-server/failover-clustering/troubleshooting-using-wer-reports'
            Depth          = 1
            Include        = @()
            NamePattern    = $reportFilePattern
            FolderPattern  = '^$'
            PrefixPattern  = '^([A-Za-z]{1,32})_'
            Absence        = 'observation'
            Expectation    = 'the queued report folder could be listed'
        },
        @{
            Id             = 'wer_report_archive'
            Type           = 'metadata'
            Required       = $false
            Kind           = 'other'
            Folder         = 'ProgramData'
            PathTail       = 'Microsoft\Windows\WER\ReportArchive'
            PathDocumented = 'https://learn.microsoft.com/windows-server/failover-clustering/troubleshooting-using-wer-reports'
            Depth          = 1
            Include        = @()
            NamePattern    = $reportFilePattern
            FolderPattern  = '^$'
            PrefixPattern  = '^([A-Za-z]{1,32})_'
            Absence        = 'observation'
            Expectation    = 'the archived report folder could be listed'
        }
    )
}

$exitCode = @(Invoke-WfCollectorScript -Definition $definition -OutputDirectory $OutputDirectory -WindowDays $WindowDays -MaxEvents $MaxEvents -MaxArtifactBytes $MaxArtifactBytes -TimeoutSeconds $TimeoutSeconds -CollectorPath $PSCommandPath)[-1]
exit $exitCode
