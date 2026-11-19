# The local scenario runner's library: the collector registry, the scenarios,
# the preflight, the bounded run of each collector as its own process, the
# end check of a live session whose collector was stopped at its deadline,
# and the merge into one bundle whose manifest is written last.
#
# Dot sourced by _run-scenario.ps1 after _common.ps1, and by the Pester suite
# after the synthetic backend. The leading underscore keeps it out of the
# dispatcher's verbs: the runner is started at the PC, never through SSH.
#
# Rules this file keeps (collectors/windows/README.md, "Scenario runner"):
# - The runner reads and refuses; it never changes a setting, and the only
#   things it starts are the collector scripts (Start-WfCollectorChild) and,
#   after it stopped presentmon-frames at its deadline, wpr -status and
#   -cancel of that collector's own named recording.
# - A collector that did not run yields no evidence: its sources are listed
#   with not_collected and the reason, never as an empty export.
# - Every text the runner writes passes through Protect-WfRunnerText, which
#   writes <profile> for the profile folder, <account> for the account name
#   and <bundle> for the output directory.

if (Get-Command -Name 'Invoke-WfScenarioScript' -CommandType Function -ErrorAction SilentlyContinue) { return }

function Get-WfRunnerName { return 'scenario-runner' }
function Get-WfRunnerVersion { return '1.1.0' }
function Get-WfRunnerManifestVersion { return '1.2.0' }
# Added to every collector's own worst case to make the runner's deadline:
# the helper's machine inventory reads six WMI classes with a 60 second
# operation timeout each, plus a minute for the process start and the writes.
function Get-WfRunnerDeadlineMarginSeconds { return 420 }
# How long the runner waits for a background collector to report ready.
function Get-WfRunnerReadySeconds { return 60 }

# ---------------------------------------------------------------------------
# The collector registry. One entry per collector the runner can schedule;
# adding a collector to a scenario is one entry here and one step there.
#   Name        the collector script (<Name>.ps1 beside this file)
#   Sources     the source ids it declares, their kind and whether the
#               collector marks them required (Pester checks these against
#               the committed collector bundles)
#   Rights      none | event_log_readers | administrator |
#               administrator_or_performance_log_users
#   DiskCaps    how many artifact caps (-MaxArtifactBytes) it can write
#   DiskExtra   bytes it can hold beyond them while it runs (a temporary trace),
#               given the artifact cap
#   Tools       operator supplied tools: the runner parameter that names the
#               path, the source that needs it, and the pin to check
#   ReadyFile   for a collector that runs in the background, the file whose
#               presence means it is ready (bundle relative)
#   Session     for a live collector: the WPR instance it owns, when the name
#               is fixed, so the runner can end it after a stop at the deadline
#   WorstCase   seconds the collector can take with these arguments, from the
#               bound each collector states for itself
# ---------------------------------------------------------------------------
function Get-WfCollectorRegistry {
    return @(
        [ordered]@{
            Name = 'clock-calibration'; Rights = 'none'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @()
            Sources = @([ordered]@{ Id = 'clock_calibration'; Kind = 'clock'; Required = $true }, [ordered]@{ Id = 'operator_marks'; Kind = 'other'; Required = $false })
            ReadyFile = 'raw/operator_marks/marks.open.jsonl'; Session = $null
            # clock-calibration.ps1 hands the helper a deadline of the duration plus 60 seconds.
            WorstCase = { param($A) return ([int]$A['DurationSeconds'] + 60) }
        },
        [ordered]@{
            Name = 'dpcisr-trace'; Rights = 'administrator'; DiskCaps = 2; DiskExtra = { return [int64]2147483648 }
            Tools = @([ordered]@{ Tool = 'xperf'; Parameter = 'XperfPath'; Source = 'dpcisr_report' })
            Sources = @([ordered]@{ Id = 'wpr_trace'; Kind = 'wpr'; Required = $true }, [ordered]@{ Id = 'dpcisr_report'; Kind = 'xperf'; Required = $false })
            ReadyFile = $null
            # The instance name carries the collector's start time, so the runner
            # cannot address it; it reports the prefix instead.
            Session = [ordered]@{ Instance = $null; InstancePrefix = 'WfDpcIsrTrace-' }
            # Get-DpcIsrWorstCaseSeconds with the default -TimeoutSeconds 120.
            WorstCase = { param($A) $d = [int]$A['DurationSeconds']; return ($d + [math]::Max(0, 30 - $d) + 4 * 120 + 5 * 30) }
        },
        [ordered]@{
            Name = 'presentmon-frames'; Rights = 'administrator_or_performance_log_users'; DiskCaps = 2
            # The collector's own disk_budget.peak_bytes_bound, less the two caps counted above.
            DiskExtra = { param($Max) return ((Get-WfPresentMonPeakBytesBound -MaxArtifactBytes $Max) - 2 * [int64]$Max) }
            Tools = @([ordered]@{ Tool = 'presentmon'; Parameter = 'PresentMonPath'; Source = 'presentmon_frames' })
            Sources = @([ordered]@{ Id = 'presentmon_frames'; Kind = 'presentmon'; Required = $true })
            ReadyFile = $null
            Session = [ordered]@{ Instance = (Get-WfPresentMonInstanceName); InstancePrefix = $null }
            # The helper deadline presentmon-frames.ps1 computes from its phase deadlines.
            WorstCase = { param($A) return (4 * (Get-WfPresentMonStatusDeadline) + 3 * (Get-WfPresentMonCancelDeadline) + (Get-WfPresentMonStartDeadline) + [int]$A['DurationSeconds'] + (Get-WfPresentMonStopDeadline) + (Get-WfPresentMonDecodeDeadline)) }
        },
        [ordered]@{
            Name = 'diskio-trace'; Rights = 'administrator'; DiskCaps = 2
            # The trace and the XML dump tracerpt makes of it are both held in the
            # private folder while the aggregate is read: the two caps at their
            # defaults (-MaxTraceBytes 2 GiB, -MaxDumpBytes 4 GiB).
            DiskExtra = { return ([int64]2147483648 + [int64]4294967296) }
            Tools = @()
            Sources = @([ordered]@{ Id = 'wpr_trace'; Kind = 'wpr'; Required = $true }, [ordered]@{ Id = 'diskio_aggregate'; Kind = 'other'; Required = $true })
            ReadyFile = $null
            # Like dpcisr-trace, the instance name carries the start time.
            Session = [ordered]@{ Instance = $null; InstancePrefix = 'WfDiskIoTrace-' }
            # Get-DiskIoWorstCaseSeconds with the default -TimeoutSeconds 120.
            WorstCase = { param($A) $d = [int]$A['DurationSeconds']; return ($d + [math]::Max(0, 30 - $d) + 4 * 120 + 5 * 30) }
        },
        [ordered]@{
            Name = 'bugcheck-history'; Rights = 'event_log_readers'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'system_restart_events'; Kind = 'eventlog'; Required = $true })
            WorstCase = { return 300 }
        },
        [ordered]@{
            Name = 'whea-errors'; Rights = 'event_log_readers'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'system_whea_events'; Kind = 'eventlog'; Required = $true })
            WorstCase = { return 300 }
        },
        [ordered]@{
            Name = 'application-errors'; Rights = 'event_log_readers'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'application_error_events'; Kind = 'eventlog'; Required = $true })
            WorstCase = { return 300 }
        },
        [ordered]@{
            Name = 'tdr-events'; Rights = 'event_log_readers'; DiskCaps = 4; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'system_display_events'; Kind = 'eventlog'; Required = $false }, [ordered]@{ Id = 'system_bugcheck_events'; Kind = 'eventlog'; Required = $true })
            WorstCase = { return 600 }
        },
        [ordered]@{
            Name = 'reliability-records'; Rights = 'none'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'reliability_records'; Kind = 'other'; Required = $true }, [ordered]@{ Id = 'reliability_stability_metrics'; Kind = 'other'; Required = $false })
            WorstCase = { return 600 }
        },
        [ordered]@{
            Name = 'driver-inventory'; Rights = 'none'; DiskCaps = 2; DiskExtra = { return [int64]0 }; Tools = @(); ReadyFile = $null; Session = $null
            Sources = @([ordered]@{ Id = 'pnp_signed_drivers'; Kind = 'config_snapshot'; Required = $true }, [ordered]@{ Id = 'system_drivers'; Kind = 'config_snapshot'; Required = $true })
            WorstCase = { return 600 }
        },
        # The state snapshot, run twice in S1 (before the first capture and
        # after the last one), with the game closed: README verification item
        # 60, and the game windows of Invoke-WfScenario. It is a history read,
        # not a live capture: no session, no ready file, no tool.
        [ordered]@{
            Name = 'config-snapshot'; Rights = 'none'; Tools = @(); ReadyFile = $null; Session = $null
            # Sixteen exports are held to -MaxArtifactBytes (the two keys.json,
            # two WMI records.json and two process lists, topology.json, five
            # powercfg output.txt, two listing.json and two protected copies),
            # and each powercfg listing's result.json repeats its output line by
            # line, counted as one more cap each.
            DiskCaps = 21; DiskExtra = { return [int64]0 }
            Sources = @(
                [ordered]@{ Id = 'interrupt_policy'; Kind = 'config_snapshot'; Required = $true },
                [ordered]@{ Id = 'graphics_tdr'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'processors'; Kind = 'config_snapshot'; Required = $true },
                [ordered]@{ Id = 'cpu_caches'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'logical_processor_map'; Kind = 'config_snapshot'; Required = $true },
                [ordered]@{ Id = 'power_active_scheme'; Kind = 'powercfg'; Required = $true },
                [ordered]@{ Id = 'power_schemes'; Kind = 'powercfg'; Required = $false },
                [ordered]@{ Id = 'power_aliases'; Kind = 'powercfg'; Required = $false },
                [ordered]@{ Id = 'power_settings'; Kind = 'powercfg'; Required = $true },
                [ordered]@{ Id = 'power_settings_hidden'; Kind = 'powercfg'; Required = $false },
                [ordered]@{ Id = 'power_mode'; Kind = 'powercfg'; Required = $false },
                [ordered]@{ Id = 'timer_resolution'; Kind = 'other'; Required = $false },
                [ordered]@{ Id = 'processes'; Kind = 'process_inventory'; Required = $true },
                [ordered]@{ Id = 'timer_helper_process'; Kind = 'process_inventory'; Required = $false },
                [ordered]@{ Id = 'process_lasso_install'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'process_lasso_config'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'process_lasso_log'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'stutter_guard_install'; Kind = 'config_snapshot'; Required = $false },
                [ordered]@{ Id = 'stutter_guard_journal'; Kind = 'config_snapshot'; Required = $false }
            )
            # Seventeen of the nineteen sources read something (power_mode and
            # timer_resolution are unavailable), each under the default
            # -TimeoutSeconds 50 of config-snapshot.ps1.
            WorstCase = { return (17 * 50) }
        }
    )
}

function Get-WfRegistryEntry {
    param([string]$Name)
    foreach ($entry in @(Get-WfCollectorRegistry)) { if ($entry['Name'] -eq $Name) { return $entry } }
    throw ('no registry entry for collector ' + $Name)
}

# ---------------------------------------------------------------------------
# Scenarios. A step names a collector from the registry, its arguments, a
# phase, whether its sources are required in this scenario, whether it runs
# in the background (started, waited for until ready, waited for to the end
# after the foreground steps of its phase), and the prefix its source ids get
# in the merged manifest (the state snapshot runs twice).
# ---------------------------------------------------------------------------
function Get-WfScenarioIds { return @('s1') }

function Get-WfScenarioDefinition {
    param([string]$Id, [int]$DurationSeconds, [string]$ProcessName)
    if ($Id -ne 's1') { throw ('unknown scenario: ' + $Id + '; known: ' + ((Get-WfScenarioIds) -join ', ')) }
    $frames = [ordered]@{ DurationSeconds = $DurationSeconds }
    if ($ProcessName) { $frames['ProcessName'] = $ProcessName }
    # The clock session must cover the three captures: their windows plus a
    # planning allowance for each collector's start, stop and save (90 s for
    # each kernel trace with its tracerpt read, 60 s for the frame recording;
    # the offline PresentMon read happens after its stop and needs no cover),
    # plus 30 s. These are planning figures, not measured ones;
    # run.clock_brackets_live says whether the pairs did cover the captures.
    $clockSeconds = [math]::Min(840, 30 + ($DurationSeconds + 90) + ($DurationSeconds + 60) + ($DurationSeconds + 90))
    return [ordered]@{
        Id       = 's1'
        Version  = '1.1.0'
        Question = 'One bounded latency session on the gaming PC: the state before, the DPC and interrupt trace, the frame recording and the disk activity trace one after another inside one clock calibration session, the history collectors, and the state after.'
        Steps    = @(
            [ordered]@{ Step = 'state_before'; Collector = 'config-snapshot'; Phase = 'state'; Required = $false; Background = $false; Prefix = 'state_before_'; Arguments = [ordered]@{ Snapshot = 'start' } },
            [ordered]@{ Step = 'clock'; Collector = 'clock-calibration'; Phase = 'live'; Required = $true; Background = $true; Prefix = ''; Arguments = [ordered]@{ DurationSeconds = [int]$clockSeconds } },
            [ordered]@{ Step = 'dpcisr'; Collector = 'dpcisr-trace'; Phase = 'live'; Required = $true; Background = $false; Prefix = ''; Arguments = [ordered]@{ DurationSeconds = $DurationSeconds } },
            [ordered]@{ Step = 'frames'; Collector = 'presentmon-frames'; Phase = 'live'; Required = $true; Background = $false; Prefix = ''; Arguments = $frames },
            # The disk activity trace runs alone, after the frame recording and
            # never beside dpcisr-trace: two NT Kernel Logger sessions at once is
            # README item 68 (run sheet V-D1). Its source ids get a prefix,
            # because dpcisr-trace also names its trace source wpr_trace. It is
            # optional in S1: its aggregate rests on facts not yet verified on
            # the PC (README items 69 to 78), and S1's question is answered by
            # the DPC trace and the frames.
            [ordered]@{ Step = 'diskio'; Collector = 'diskio-trace'; Phase = 'live'; Required = $false; Background = $false; Prefix = 'diskio_'; Arguments = [ordered]@{ DurationSeconds = $DurationSeconds } },
            [ordered]@{ Step = 'bugchecks'; Collector = 'bugcheck-history'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'whea'; Collector = 'whea-errors'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'app_errors'; Collector = 'application-errors'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'tdr'; Collector = 'tdr-events'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'reliability'; Collector = 'reliability-records'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'drivers'; Collector = 'driver-inventory'; Phase = 'history'; Required = $false; Background = $false; Prefix = ''; Arguments = [ordered]@{} },
            [ordered]@{ Step = 'state_after'; Collector = 'config-snapshot'; Phase = 'state'; Required = $false; Background = $false; Prefix = 'state_after_'; Arguments = [ordered]@{ Snapshot = 'stop' } }
        )
    }
}

# ---------------------------------------------------------------------------
# Privacy: what the runner writes never carries the profile folder, the
# account name or the output directory in clear. JSON text escapes the
# backslash, so each value is replaced in its plain, JSON escaped and forward
# slash spellings, ignoring case (Windows paths are case insensitive).
# ---------------------------------------------------------------------------
function New-WfRunnerRedactions {
    param([string]$BundleRoot, [string]$ProfilePath, [string]$AccountName)
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($pair in @(@($BundleRoot, '<bundle>'), @($ProfilePath, '<profile>'), @($AccountName, '<account>'))) {
        $value = [string]$pair[0]
        if ($value.Length -lt 3) { continue }
        $value = $value.TrimEnd('\', '/')
        foreach ($spelling in @($value.Replace('/', '\').Replace('\', '\\'), $value.Replace('/', '\'), $value.Replace('\', '/'))) {
            $list.Add(@($spelling, [string]$pair[1]))
        }
    }
    return , $list.ToArray()
}

function Protect-WfRunnerText {
    param([string]$Text, [object[]]$Redactions)
    $result = $Text
    foreach ($pair in @($Redactions)) {
        $result = [regex]::Replace($result, [regex]::Escape([string]$pair[0]), [string]$pair[1], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    return $result
}

function Test-WfPathUnder {
    # Whether Path is ProfilePath or inside it, ignoring case.
    param([string]$Path, [string]$ProfilePath)
    if (-not $Path -or -not $ProfilePath) { return $false }
    $p = $Path.Replace('/', '\').TrimEnd('\')
    $root = $ProfilePath.Replace('/', '\').TrimEnd('\')
    return ($p.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

# ---------------------------------------------------------------------------
# Preflight: read only checks before anything is started. Each check is
# {name, ok, detail}; preflight.required lists the checks that refuse the run
# when they fail. Nothing is ever fixed here: the runner reports and refuses.
# ---------------------------------------------------------------------------
function Test-WfRights {
    param([string]$Rights, $Account)
    if ($Rights -eq 'none') { return $true }
    if ($Rights -eq 'event_log_readers') { return ([bool]$Account['elevated'] -or [bool]$Account['event_log_readers']) }
    if ($Rights -eq 'administrator') { return [bool]$Account['elevated'] }
    if ($Rights -eq 'administrator_or_performance_log_users') { return ([bool]$Account['elevated'] -or [bool]$Account['performance_log_users']) }
    return $false
}

function Get-WfRightsText {
    param([string]$Rights)
    switch ($Rights) {
        'none' { return 'no group membership or elevation' }
        'event_log_readers' { return 'Event Log Readers membership or elevation' }
        'administrator' { return 'an elevated administrator token' }
        'administrator_or_performance_log_users' { return 'an elevated token, or Performance Log Users membership (whether wpr.exe accepts that group is README verification item 41)' }
    }
    return $Rights
}

function Invoke-WfScenarioPreflight {
    param(
        [System.Collections.IDictionary]$Plan,
        [string]$BundleRoot,
        [System.Collections.IDictionary]$ToolPaths,
        [int64]$MaxArtifactBytes,
        $Account,
        [string]$ProfilePath,
        [object[]]$Redactions
    )
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $required = New-Object 'System.Collections.Generic.List[string]'
    $add = {
        param([string]$Name, [bool]$Ok, [string]$Detail, [bool]$Refuses)
        $checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
        if ($Refuses) { $required.Add($Name) }
    }

    $powershell = Get-WfPowerShellHost
    $desktop = ([string]$powershell['edition'] -eq 'Desktop' -and ([string]$powershell['version']).StartsWith('5.1'))
    & $add 'interpreter' $desktop ('edition {0}, version {1}; the collectors target Windows PowerShell 5.1 (edition Desktop)' -f $powershell['edition'], $powershell['version']) $true

    $accountRead = ($null -ne $Account['elevated'])
    & $add 'account' $accountRead ('elevated: {0}; Event Log Readers (S-1-5-32-573): {1}; Performance Log Users (S-1-5-32-559): {2}; the account name is not recorded' -f $Account['elevated'], $Account['event_log_readers'], $Account['performance_log_users']) $true

    $minimum = [int64]0
    foreach ($step in @($Plan['Steps'])) {
        if ($step['Absent']) { continue }
        $entry = $step['Entry']
        $minimum += [int64]$entry['DiskCaps'] * $MaxArtifactBytes + [int64](& $entry['DiskExtra'] $MaxArtifactBytes)
        $scriptOk = (Test-Path -LiteralPath $step['ScriptPath'] -PathType Leaf)
        & $add ('script:' + $step['Step']) $scriptOk ($step['Collector'] + '.ps1 beside the runner') ([bool]$step['Required'])
        $rightsOk = Test-WfRights -Rights $entry['Rights'] -Account $Account
        & $add ('rights:' + $step['Step']) $rightsOk ($step['Collector'] + ' needs ' + (Get-WfRightsText -Rights $entry['Rights'])) ([bool]$step['Required'])
    }
    $Plan['MinimumFreeBytes'] = $minimum
    $space = Get-WfVolumeFreeSpace -Path $BundleRoot
    $spaceOk = ($null -ne $space['free_bytes'] -and [int64]$space['free_bytes'] -ge $minimum)
    $spaceText = $(if ($null -ne $space['free_bytes']) { ('{0} bytes free on {1}; the scenario needs at least {2}' -f $space['free_bytes'], $space['root'], $minimum) } else { ('the free space on {0} could not be read: {1}' -f $space['root'], $space['error']) })
    & $add 'free_space' $spaceOk $spaceText $true

    foreach ($step in @($Plan['Steps'])) {
        if ($step['Absent']) { continue }
        foreach ($tool in @($step['Entry']['Tools'])) {
            $toolRequired = $false
            foreach ($source in @($step['Entry']['Sources'])) { if ($source['Id'] -eq $tool['Source'] -and [bool]$source['Required'] -and [bool]$step['Required']) { $toolRequired = $true } }
            $path = [string]$ToolPaths[$tool['Tool']]
            $name = 'tool:' + $tool['Tool']
            if (Test-WfPathUnder -Path $path -ProfilePath $ProfilePath) {
                & $add $name $false ('the path is under the profile folder (<profile>); the collector records it in its raw files, so the runner refuses it: place the tool outside the profile, for example under C:\ProgramData\win-forensics\tools') $toolRequired
                continue
            }
            if ($tool['Tool'] -eq 'presentmon') {
                $binary = Get-WfBinaryInfo -Path $path
                $match = ($binary['exists'] -and [string]$binary['sha256'] -eq (Get-WfPresentMonPinnedSha256) -and [int64]$binary['length'] -eq (Get-WfPresentMonPinnedLength))
                $detail = $(if (-not $binary['exists']) { ('{0} does not exist; the runner never downloads it ({1})' -f $path, (Get-WfPresentMonReleaseUrl)) }
                    elseif ($match) { ('{0}: SHA-256 and size match the pinned PresentMon {1} build; version resource {2}' -f $path, (Get-WfPresentMonPinnedVersion), $binary['product_version']) }
                    else { ('{0}: SHA-256 {1} ({2} bytes) is not the pinned PresentMon {3} build {4} ({5} bytes)' -f $path, $binary['sha256'], $binary['length'], (Get-WfPresentMonPinnedVersion), (Get-WfPresentMonPinnedSha256), (Get-WfPresentMonPinnedLength)) })
                & $add $name $match $detail $toolRequired
            } else {
                if (-not $path) {
                    & $add $name $false ('no path given (-' + $tool['Parameter'] + '); source ' + $tool['Source'] + ' will be not_collected') $toolRequired
                    continue
                }
                $info = Get-WfExternalToolInfo -Path $path
                $pins = Get-WfPinnedToolBuilds -Name $tool['Tool']
                $pinned = $false
                foreach ($pin in $pins) { if ([string]$pin['Sha256'] -eq [string]$info['Sha256'] -and [string]$pin['Version'] -eq [string]$info['Version']) { $pinned = $true } }
                $detail = $(if (-not $info['Exists']) { $path + ' does not exist; the runner never downloads or installs it' }
                    elseif ($pinned) { ('{0}: SHA-256 and version {1} match a pinned build' -f $path, $info['Version']) }
                    elseif (@($pins).Count -eq 0) { ('{0}: no {1} build is pinned yet (Get-WfPinnedToolBuilds); source {2} will be not_collected' -f $path, $tool['Tool'], $tool['Source']) }
                    else { ('{0}: SHA-256 {1}, version {2} matches no pinned build' -f $path, $info['Sha256'], $info['Version']) })
                & $add $name ([bool]$info['Exists'] -and $pinned) $detail $toolRequired
            }
        }
    }

    foreach ($check in $checks) { $check['detail'] = Protect-WfRunnerText -Text ([string]$check['detail']) -Redactions $Redactions }
    $failed = @($checks | Where-Object { -not $_['ok'] -and $required.Contains([string]$_['name']) } | ForEach-Object { [string]$_['name'] })
    return [ordered]@{
        ok       = ($failed.Count -eq 0)
        at_utc   = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
        required = @($required.ToArray())
        checks   = @($checks.ToArray())
        failed   = @($failed)
    }
}

# ---------------------------------------------------------------------------
# One step: start the collector as its own process, wait for it within the
# runner's deadline, and after a stop at the deadline end its live session
# by the shared end check, then remove what it kept privately.
# ---------------------------------------------------------------------------
function New-WfStepRecord {
    param([System.Collections.IDictionary]$Step)
    $ids = @(@($Step['Entry']['Sources']) | ForEach-Object { [string]$Step['Prefix'] + [string]$_['Id'] })
    return [ordered]@{
        step             = $Step['Step']
        collector        = $Step['Collector']
        phase            = $Step['Phase']
        background       = [bool]$Step['Background']
        required         = [bool]$Step['Required']
        sources          = @($ids)
        outcome          = 'not_started'
        exit_code        = $null
        summary_status   = $null
        started_utc      = $null
        stopped_utc      = $null
        deadline_seconds = $Step['DeadlineSeconds']
        ready            = $null
        private_removed  = $null
        session_end      = $null
        detail           = $null
    }
}

function ConvertTo-WfStepArguments {
    param([System.Collections.IDictionary]$Step, [string]$StepRoot, [int64]$MaxArtifactBytes, [System.Collections.IDictionary]$ToolPaths)
    $list = New-Object 'System.Collections.Generic.List[string]'
    $list.Add('-OutputDirectory'); $list.Add($StepRoot)
    $list.Add('-MaxArtifactBytes'); $list.Add([string]$MaxArtifactBytes)
    foreach ($key in $Step['Arguments'].Keys) { $list.Add('-' + $key); $list.Add([string]$Step['Arguments'][$key]) }
    foreach ($tool in @($Step['Entry']['Tools'])) {
        $path = [string]$ToolPaths[$tool['Tool']]
        if ($path) { $list.Add('-' + $tool['Parameter']); $list.Add($path) }
    }
    return , $list.ToArray()
}

function Start-WfScenarioStep {
    param([System.Collections.IDictionary]$Step, [System.Collections.IDictionary]$Record, [string]$BundleRoot, [int64]$MaxArtifactBytes, [System.Collections.IDictionary]$ToolPaths)
    $stepRoot = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('logs/steps/' + $Step['Step'])
    $Step['StepRoot'] = $stepRoot
    $arguments = ConvertTo-WfStepArguments -Step $Step -StepRoot $stepRoot -MaxArtifactBytes $MaxArtifactBytes -ToolPaths $ToolPaths
    $Record.started_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $Step['MonotonicStart'] = Get-WfMonotonicSeconds
    $Step['Handle'] = Start-WfCollectorChild -ScriptPath $Step['ScriptPath'] -Arguments $arguments -WorkingDirectory $BundleRoot
}

function Wait-WfScenarioStepReady {
    # A background collector is ready when its ready file exists; it is not
    # when it exits first or the wait passes its bound.
    param([System.Collections.IDictionary]$Step, [System.Collections.IDictionary]$Record)
    $readyFile = $Step['Entry']['ReadyFile']
    if (-not $readyFile) { $Record.ready = $true; return }
    $readyPath = Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath $readyFile
    $deadline = (Get-WfMonotonicSeconds) + (Get-WfRunnerReadySeconds)
    while ($true) {
        if (Test-WfCollectorChildReady -Handle $Step['Handle'] -ReadyPath $readyPath) { $Record.ready = $true; return }
        if ((Test-WfCollectorChildExited -Handle $Step['Handle']) -or (Get-WfMonotonicSeconds) -ge $deadline) { $Record.ready = $false; return }
        Start-WfSleep -Seconds 1
    }
}

function Complete-WfScenarioStep {
    param([System.Collections.IDictionary]$Step, [System.Collections.IDictionary]$Record, [System.Collections.Generic.List[string]]$Log)
    $elapsed = (Get-WfMonotonicSeconds) - [double]$Step['MonotonicStart']
    $remaining = [int][math]::Max(1, [math]::Ceiling([double]$Step['DeadlineSeconds'] - $elapsed))
    $run = Wait-WfCollectorChild -Handle $Step['Handle'] -TimeoutSeconds $remaining
    $Record.stopped_utc = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
    $Step['Run'] = $run
    $Record.exit_code = $run['ExitCode']
    if (-not $run['Started']) {
        $Record.outcome = 'start_failed'
        $Record.detail = 'the collector process did not start: ' + [string]$run['Error']
    } elseif ($run['TimedOut']) {
        $Record.outcome = 'timed_out'
        $Record.detail = ('the collector did not finish within the runner''s deadline of {0} seconds (its own worst case plus {1}) and was stopped' -f $Step['DeadlineSeconds'], (Get-WfRunnerDeadlineMarginSeconds))
    } elseif ($run['Oversized']) {
        $Record.outcome = 'timed_out'
        $Record.detail = 'the collector printed more than the runner reads and was stopped: ' + [string]$run['Error']
    }
    $lines = @(([string]$run['StdOut']) -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -gt 0) {
        try {
            $summary = ConvertFrom-WfJson -Text $lines[$lines.Count - 1]
            if ($summary -is [System.Collections.IDictionary] -and $summary.Contains('status')) { $Record.summary_status = [string]$summary['status'] }
        } catch { $Log.Add(('step {0}: the last stdout line is not a summary: {1}' -f $Step['Step'], $_.Exception.Message)) }
    }
    if ([string]$run['StdErr']) { $Log.Add(('step {0} stderr: {1}' -f $Step['Step'], ([string]$run['StdErr']).Trim())) }
    $manifestPath = Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath 'manifest.json'
    $hasManifest = (Test-Path -LiteralPath $manifestPath -PathType Leaf)
    if ($Record.outcome -eq 'not_started') {
        if ($hasManifest) { $Record.outcome = 'completed' }
        else { $Record.outcome = 'no_manifest'; $Record.detail = ('the collector exited with code {0} and wrote no manifest' -f $run['ExitCode']) }
    }
    $Log.Add(('{0} step {1}: {2}, exit code {3}, status {4}' -f $Record.stopped_utc, $Step['Step'], $Record.outcome, $Record.exit_code, $Record.summary_status))
    if ($Record.outcome -ne 'completed') {
        # A collector that did not finish leaves nothing the runner can vouch
        # for. A live session it may have left is ended first by the shared
        # end check (Windows does not delete a file a recording still
        # writes), then its raw and private folders are removed (a partial
        # recording or kernel trace can carry hardware and network addresses).
        $session = $Step['Entry']['Session']
        if ($null -ne $session -and $Record.outcome -ne 'start_failed') { $Record.session_end = Invoke-WfScenarioSessionEnd -Session $session -Log $Log }
        Remove-WfScenarioStepLeftovers -Step $Step -Record $Record -Log $Log
    }
}

function Remove-WfScenarioStepLeftovers {
    param([System.Collections.IDictionary]$Step, [System.Collections.IDictionary]$Record, [System.Collections.Generic.List[string]]$Log)
    $Record.private_removed = $true
    foreach ($relative in @('raw', 'private')) {
        $leftover = Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath $relative
        if (Test-Path -LiteralPath $leftover) {
            try { Remove-Item -LiteralPath $leftover -Recurse -Force -ErrorAction Stop } catch { $Record.private_removed = $false; $Log.Add(('step {0}: {1} could not be removed: {2}' -f $Step['Step'], $relative, $_.Exception.Message)) }
        }
    }
}

function Invoke-WfScenarioSessionEnd {
    # The end check of Complete-WfLiveSession for a session whose collector
    # was stopped: read the named instance, cancel it unless it reads idle,
    # read it again. Only a fixed instance name can be addressed; the runner
    # never probes or cancels a recording it cannot name.
    param([System.Collections.IDictionary]$Session, [System.Collections.Generic.List[string]]$Log)
    $instance = [string]$Session['Instance']
    if (-not $instance) {
        return [ordered]@{ instance = $null; checked = $false; state_final = 'unknown'; confirmed = $false; cancel_issued = $false
            detail = ('the instance name ({0}<UTC start>) is chosen by the collector at its start and was not reported, so the runner could not read or cancel it; run "wpr -status -instancename <name>" at the PC and "wpr -cancel -instancename <name>" if a recording with that prefix is still in progress' -f $Session['InstancePrefix']) }
    }
    $wpr = Get-WfWprPath
    $state = @{ Instance = $instance; Wpr = $wpr; Log = $Log }
    $hooks = @{
        Confirm = {
            param($S, $Moment)
            $run = Invoke-WfProcess -FilePath $S.Wpr -Arguments ('-status -instancename ' + $S.Instance) -TimeoutSeconds 30 -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes 1048576
            $read = Get-WfWprStatusState -Run $run
            $S.Log.Add(('session {0} ({1}): wpr -status reads {2}' -f $S.Instance, $Moment, $read))
            return $read
        }
        Cancel  = {
            param($S, $Read)
            $null = $Read
            $run = Invoke-WfProcess -FilePath $S.Wpr -Arguments ('-cancel -instancename ' + $S.Instance) -TimeoutSeconds 60 -OutputEncoding (Get-WfConsoleOutputEncoding) -MaxBytes 1048576
            $S.Log.Add(('session {0}: wpr -cancel exit code {1}' -f $S.Instance, $run['ExitCode']))
            return ([bool]$run['Started'] -and -not [bool]$run['TimedOut'] -and $run['ExitCode'] -eq 0)
        }
    }
    $record = New-WfLiveSessionRecord
    $record.start_attempted = $true
    $record.start_ok = $true
    $record.may_remain = $true
    Complete-WfLiveSession -LiveHooks $hooks -LiveState $state -LiveRecord $record
    $detail = $(if ($record.confirmed) { 'the instance reads idle after the collector was stopped' } else { ('the instance could not be read as idle (state {0}); run "wpr -status -instancename {1}" at the PC' -f $record.state_final, $instance) })
    if ($record.end_error) { $detail = $detail + '; ' + $record.end_error }
    return [ordered]@{ instance = $instance; checked = $true; state_final = $record.state_final; confirmed = [bool]$record.confirmed; cancel_issued = [bool]$record.cancel_issued; detail = $detail }
}

# ---------------------------------------------------------------------------
# The merge. Each finished collector's raw/<source> folder moves to the run's
# raw/<prefix><source>; every artifact is hashed again at its new place.
# ---------------------------------------------------------------------------
function New-WfUnrunEntry {
    param([string]$Id, [string]$Kind, [bool]$Required, [string]$Reason)
    $entry = New-WfCollectorEntry -Id $Id -Kind $Kind -Required $Required
    $entry.status = 'not_collected'
    $entry.status_reason = $Reason
    return $entry
}

function Merge-WfScenarioStep {
    param(
        [System.Collections.IDictionary]$Step,
        [System.Collections.IDictionary]$Record,
        [string]$BundleRoot,
        [System.Collections.Generic.List[object]]$Entries,
        [System.Collections.Generic.HashSet[string]]$Seen,
        [System.Collections.Generic.List[string]]$Log
    )
    $manifest = $null
    if ($Record.outcome -eq 'completed') {
        try { $manifest = Read-WfJsonFile -Path (Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath 'manifest.json') }
        catch {
            $Record.outcome = 'no_manifest'
            $Record.detail = 'the collector''s manifest could not be read: ' + $_.Exception.Message
            Remove-WfScenarioStepLeftovers -Step $Step -Record $Record -Log $Log
        }
    }
    $Step['Manifest'] = $manifest
    if ($null -eq $manifest) {
        $reason = ('step {0} ({1}) {2}: {3}' -f $Step['Step'], $Step['Collector'], $Record.outcome, $Record.detail)
        foreach ($source in @($Step['Entry']['Sources'])) {
            $id = [string]$Step['Prefix'] + [string]$source['Id']
            if (-not $Seen.Add($id)) { continue }
            $Entries.Add((New-WfUnrunEntry -Id $id -Kind ([string]$source['Kind']) -Required ([bool]$Step['Required'] -and [bool]$source['Required']) -Reason $reason))
        }
        return
    }
    foreach ($entry in @($manifest['collectors'])) {
        $oldId = [string]$entry['id']
        $newId = [string]$Step['Prefix'] + $oldId
        if (-not $Seen.Add($newId)) {
            $Log.Add(('step {0}: source id {1} is already in the run; its folder stays under logs/steps and is not merged' -f $Step['Step'], $newId))
            continue
        }
        $from = Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath ('raw/' + $oldId)
        $to = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath ('raw/' + $newId)
        $problems = New-Object 'System.Collections.Generic.List[string]'
        if (Test-Path -LiteralPath $from) {
            try { [System.IO.Directory]::Move($from, $to) } catch { $problems.Add('the folder could not be moved: ' + $_.Exception.Message) }
        }
        $artifacts = New-Object 'System.Collections.Generic.List[object]'
        foreach ($artifact in @($entry['artifacts'])) {
            $path = [string]$artifact['path']
            if ($path.StartsWith('raw/' + $oldId + '/')) { $path = 'raw/' + $newId + '/' + $path.Substring(('raw/' + $oldId + '/').Length) }
            $artifact['path'] = $path
            $file = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath $path
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $problems.Add($path + ' is missing after the move') }
            elseif ((Get-WfSha256OfFile -Path $file) -ne [string]$artifact['sha256']) { $problems.Add($path + ' does not hash to what the collector recorded') }
            $artifacts.Add($artifact)
        }
        $entry['artifacts'] = @($artifacts.ToArray())
        $entry['id'] = $newId
        # In this scenario an optional step's sources are all optional.
        if (-not [bool]$Step['Required']) { $entry['required'] = $false }
        if ($problems.Count -gt 0) {
            $entry['status'] = 'capture_failed'
            $entry['status_reason'] = 'the runner could not vouch for the merged artifacts: ' + ($problems.ToArray() -join '; ') + '; the collector had reported: ' + [string]$entry['status_reason']
        }
        $Entries.Add($entry)
    }
    # The step's raw folder is empty once every source moved out of it.
    $stepRaw = Join-WfBundlePath -BundleRoot $Step['StepRoot'] -RelativePath 'raw'
    if ((Test-Path -LiteralPath $stepRaw) -and @(Get-ChildItem -LiteralPath $stepRaw -Force).Count -eq 0) { Remove-Item -LiteralPath $stepRaw -Force }
}

function Get-WfScenarioStatus {
    # failed when a source the scenario requires is not observed (the bundle
    # contract refuses a bundle whose required collector failed: the runner
    # still writes it, for the diagnosis, and exits 1); partial when only
    # optional sources are missing; ok when every source is observed.
    param([object[]]$Entries)
    $all = @($Entries)
    $missingRequired = @($all | Where-Object { [bool]$_['required'] -and -not (Test-WfObservedStatus -Status ([string]$_['status'])) })
    if ($all.Count -eq 0 -or $missingRequired.Count -gt 0) { return 'failed' }
    $missing = @($all | Where-Object { -not (Test-WfObservedStatus -Status ([string]$_['status'])) })
    if ($missing.Count -gt 0) { return 'partial' }
    return 'ok'
}

function Test-WfClockBracketsLive {
    # Whether the clock session's first and last calibration pairs lie
    # before the first live capture started and after the last one stopped
    # (the runner's own start and stop times of those steps).
    param($Calibration, [object[]]$Records)
    $live = @($Records | Where-Object { $_['phase'] -eq 'live' -and -not $_['background'] -and $_['started_utc'] -and $_['stopped_utc'] })
    $pairs = @()
    if ($null -ne $Calibration -and $Calibration.Contains('pairs')) { $pairs = @($Calibration['pairs']) }
    if ($live.Count -eq 0 -or $pairs.Count -lt 2) { return $null }
    $first = [datetime]::FromFileTimeUtc([int64]$pairs[0]['filetime_utc_100ns'])
    $last = [datetime]::FromFileTimeUtc([int64]$pairs[$pairs.Count - 1]['filetime_utc_100ns'])
    $start = ConvertFrom-WfUtcString -Text ([string]$live[0]['started_utc'])
    $stop = ConvertFrom-WfUtcString -Text ([string]$live[$live.Count - 1]['stopped_utc'])
    return ($first -le $start -and $last -ge $stop)
}

function Protect-WfScenarioStepFiles {
    # The collectors' own manifests, summaries and logs stay under
    # logs/steps/<step> for the record; the runner rewrites them with the
    # redactions (none of them is an artifact, so no hash changes).
    param([string]$BundleRoot, [object[]]$Redactions)
    $steps = Join-WfBundlePath -BundleRoot $BundleRoot -RelativePath 'logs/steps'
    if (-not (Test-Path -LiteralPath $steps)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $steps -File -Recurse)) {
        $relative = $file.FullName.Substring($steps.Length).TrimStart('\', '/') -replace '\\', '/'
        if ($relative -match '^[^/]+/(raw|private)/') { continue }
        $text = [System.IO.File]::ReadAllText($file.FullName, (New-Object System.Text.UTF8Encoding($false)))
        $protected = Protect-WfRunnerText -Text $text -Redactions $Redactions
        if ($protected -ne $text) { Write-WfTextFile -Path $file.FullName -Text $protected }
    }
}

# ---------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------
function Invoke-WfScenario {
    param(
        [string]$ScenarioId,
        [string]$OutputDirectory,
        [int]$DurationSeconds,
        [string]$ProcessName,
        [string]$PresentMonPath,
        [string]$XperfPath,
        [int64]$MaxArtifactBytes,
        [string]$CollectorRoot,
        [string]$RunnerPath,
        [int]$GameStartSeconds,
        [int]$GameCloseSeconds,
        [hashtable]$State
    )
    $bundleRoot = Resolve-WfBundleRoot -OutputDirectory $OutputDirectory
    New-WfBundleLayout -BundleRoot $bundleRoot
    $State['BundleRoot'] = $bundleRoot
    $log = New-Object 'System.Collections.Generic.List[string]'
    $State['Log'] = $log
    $start = Get-WfUtcNow
    $account = Get-WfAccountInfo
    $profilePath = Get-WfUserProfilePath
    $redactions = New-WfRunnerRedactions -BundleRoot $bundleRoot -ProfilePath $profilePath -AccountName ([string]$account['name'])
    $State['Redactions'] = $redactions
    $log.Add(('{0} {1} {2} started: scenario {3}' -f (ConvertTo-WfUtcString -Value $start), (Get-WfRunnerName), (Get-WfRunnerVersion), $ScenarioId))

    $definition = Get-WfScenarioDefinition -Id $ScenarioId -DurationSeconds $DurationSeconds -ProcessName $ProcessName
    if (-not $PresentMonPath) { $PresentMonPath = Get-WfPresentMonDefaultPath -ScriptRoot $CollectorRoot }
    $toolPaths = @{ presentmon = $PresentMonPath; xperf = $XperfPath }
    $steps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($stepDefinition in @($definition['Steps'])) {
        $step = [ordered]@{}
        foreach ($key in $stepDefinition.Keys) { $step[$key] = $stepDefinition[$key] }
        $step['Entry'] = Get-WfRegistryEntry -Name $step['Collector']
        $step['ScriptPath'] = [System.IO.Path]::Combine($CollectorRoot, $step['Collector'] + '.ps1')
        # A step whose registry entry declares no sources is a reserved slot:
        # nothing runs and nothing is claimed for it.
        $step['Absent'] = (@($step['Entry']['Sources']).Count -eq 0)
        $step['DeadlineSeconds'] = [int](& $step['Entry']['WorstCase'] $step['Arguments']) + (Get-WfRunnerDeadlineMarginSeconds)
        $steps.Add($step)
    }
    $plan = [ordered]@{ Steps = @($steps.ToArray()); MinimumFreeBytes = [int64]0 }

    $preflight = Invoke-WfScenarioPreflight -Plan $plan -BundleRoot $bundleRoot -ToolPaths $toolPaths -MaxArtifactBytes $MaxArtifactBytes -Account $account -ProfilePath $profilePath -Redactions $redactions
    $log.Add(('{0} preflight: {1}' -f $preflight['at_utc'], $(if ($preflight['ok']) { 'ok' } else { 'refused: ' + ($preflight['failed'] -join ', ') })))

    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($step in $steps) {
        $record = New-WfStepRecord -Step $step
        if ($step['Absent']) { $record.outcome = 'absent'; $record.detail = $step['Collector'] + ' is not registered with the runner yet; the slot is kept so the order does not change when it is' }
        $step['Record'] = $record
        $records.Add($record)
    }

    # The game windows. The state snapshot is taken with the game and its
    # anti-cheat closed (README verification item 60), and the live captures
    # need the game running, so the runner asks the owner on stderr to start
    # the game before the first live step and to close it after the last
    # one, and waits a fixed time. It never checks whether the game runs;
    # the snapshot's own process list records what was running.
    $gameNotes = New-Object 'System.Collections.Generic.List[string]'
    $liveStarted = $false
    $closeAsked = $null

    if ($preflight['ok']) {
        $background = New-Object 'System.Collections.Generic.List[object]'
        $phase = $null
        foreach ($step in $steps) {
            if ($step['Absent']) { continue }
            # Background collectors of a phase are waited for before the next phase starts.
            if ($phase -ne $step['Phase']) {
                if ($phase -eq 'live') {
                    $closeAsked = Get-WfMonotonicSeconds
                    $at = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
                    Write-WfStderrLine -Text ('{0}: the live captures are over; close the game and its anti-cheat now. The next state snapshot starts in {1} seconds or later.' -f (Get-WfRunnerName), $GameCloseSeconds)
                    $log.Add(('{0} game window: asked the owner to close the game, {1} seconds before the next state snapshot' -f $at, $GameCloseSeconds))
                    $gameNotes.Add(('At {0} the runner asked the owner on stderr to close the game and its anti-cheat and allowed {1} seconds before the next state snapshot.' -f $at, $GameCloseSeconds))
                }
                foreach ($running in $background) { Complete-WfScenarioStep -Step $running -Record $running['Record'] -Log $log }
                $background.Clear()
                if ($step['Phase'] -eq 'live' -and -not $liveStarted) {
                    $liveStarted = $true
                    $at = ConvertTo-WfUtcString -Value (Get-WfUtcNow)
                    Write-WfStderrLine -Text ('{0}: start the game now; the live captures start in {1} seconds.' -f (Get-WfRunnerName), $GameStartSeconds)
                    $log.Add(('{0} game window: asked the owner to start the game, {1} seconds before the first live step' -f $at, $GameStartSeconds))
                    $gameNotes.Add(('At {0} the runner asked the owner on stderr to start the game and waited {1} seconds before the first live step.' -f $at, $GameStartSeconds))
                    Start-WfSleep -Seconds $GameStartSeconds
                }
                if ($step['Phase'] -eq 'state' -and $null -ne $closeAsked) {
                    $left = [int][math]::Ceiling([double]$GameCloseSeconds - ((Get-WfMonotonicSeconds) - [double]$closeAsked))
                    if ($left -gt 0) { Start-WfSleep -Seconds $left }
                    $closeAsked = $null
                }
                $phase = $step['Phase']
            }
            $record = $step['Record']
            $log.Add(('{0} step {1}: {2} starts, deadline {3} s' -f (ConvertTo-WfUtcString -Value (Get-WfUtcNow)), $step['Step'], $step['Collector'], $step['DeadlineSeconds']))
            Start-WfScenarioStep -Step $step -Record $record -BundleRoot $bundleRoot -MaxArtifactBytes $MaxArtifactBytes -ToolPaths $toolPaths
            if ($step['Background']) {
                Wait-WfScenarioStepReady -Step $step -Record $record
                $log.Add(('step {0}: ready {1}' -f $step['Step'], $record.ready))
                if ($step['Collector'] -eq 'clock-calibration') {
                    # The owner marks a moment from a second console into this step's session.
                    Write-WfStderrLine -Text ('{0}: to mark a moment, run in a second console: powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "{1}" -OutputDirectory "{2}" -Mark "<what you noticed>"' -f (Get-WfRunnerName), $step['ScriptPath'], $step['StepRoot'])
                }
                $background.Add($step)
                continue
            }
            Complete-WfScenarioStep -Step $step -Record $record -Log $log
        }
        foreach ($running in $background) { Complete-WfScenarioStep -Step $running -Record $running['Record'] -Log $log }
    }

    # Merge in step order, so the manifest lists sources in the scenario's order.
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $refusal = 'the scenario runner refused to start; nothing ran. Failed preflight checks: ' + ($preflight['failed'] -join ', ')
    foreach ($step in $steps) {
        if ($step['Absent']) { continue }
        if (-not $preflight['ok']) {
            foreach ($source in @($step['Entry']['Sources'])) {
                $id = [string]$step['Prefix'] + [string]$source['Id']
                if ($seen.Add($id)) { $entries.Add((New-WfUnrunEntry -Id $id -Kind ([string]$source['Kind']) -Required ([bool]$step['Required'] -and [bool]$source['Required']) -Reason $refusal)) }
            }
            $step['Manifest'] = $null
            continue
        }
        Merge-WfScenarioStep -Step $step -Record $step['Record'] -BundleRoot $bundleRoot -Entries $entries -Seen $seen -Log $log
    }

    $machineInfo = Get-WfMachineInfo
    $machine = $machineInfo['machine']
    $calibration = $null
    $marks = @()
    $targetProcess = $(if ($ProcessName) { $ProcessName } else { $null })
    $tools = New-Object 'System.Collections.Generic.List[object]'
    $toolKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    # Get-WfToolInventory returns its list wrapped (return , $list): assigned, not collected with @().
    $inventory = Get-WfToolInventory -CollectorName (Get-WfRunnerName) -CollectorVersion (Get-WfRunnerVersion) -CollectorPath $RunnerPath
    foreach ($tool in $inventory) {
        if ($toolKeys.Add(([string]$tool['name'] + '|' + [string]$tool['path']))) { $tools.Add($tool) }
    }
    $libraryPath = [System.IO.Path]::Combine($CollectorRoot, '_scenarios.ps1')
    $tools.Add((Get-WfScriptToolRecord -Name 'scenario-runner-library:_scenarios.ps1' -Version (Get-WfRunnerVersion) -Path $libraryPath))
    foreach ($step in $steps) {
        $child = $step['Manifest']
        if ($null -eq $child) { continue }
        foreach ($tool in @($child['tools'])) {
            if ($toolKeys.Add(([string]$tool['name'] + '|' + [string]$tool['path']))) { $tools.Add($tool) }
        }
        if ($step['Collector'] -eq 'clock-calibration') {
            $calibration = $child['calibration']
            $marks = @($child['scenario']['marks'])
        }
        if ($step['Collector'] -eq 'presentmon-frames' -and $null -ne $child['scenario']['target_process']) { $targetProcess = [string]$child['scenario']['target_process'] }
        if ($step['Collector'] -eq 'driver-inventory') { $machine['drivers'] = @($child['machine']['drivers']) }
    }
    if ($null -eq $calibration) {
        $calibration = [ordered]@{
            status           = 'not_collected'
            method           = 'the clock-calibration step did not finish with a manifest, so this run has no calibration pairs (run.steps says why)'
            qpc_frequency_hz = $machineInfo['qpc_frequency_hz']
            expected_pairs   = 0
            pairs            = @()
            missing_pairs    = 0
            time_adjustment  = [ordered]@{ start = $null; stop = $null }
            boot_time_utc    = $machineInfo['boot_time_utc']
        }
    }

    $summaryStatus = Get-WfScenarioStatus -Entries @($entries.ToArray())
    $stop = Get-WfUtcNow
    $artifactCount = 0
    foreach ($entry in $entries) { $artifactCount += @($entry['artifacts']).Count }
    $clockBrackets = Test-WfClockBracketsLive -Calibration $calibration -Records @($records.ToArray())

    $notes = New-Object 'System.Collections.Generic.List[string]'
    $notes.Add(('Scenario runner {0}, scenario {1} version {2}: {3}' -f (Get-WfRunnerVersion), $definition['Id'], $definition['Version'], $definition['Question']))
    $notes.Add(('Ran as the collector account (its name is not recorded); elevated: {0}; member of Event Log Readers (S-1-5-32-573): {1}; member of Performance Log Users (S-1-5-32-559): {2}.' -f $account['elevated'], $account['event_log_readers'], $account['performance_log_users']))
    $notes.Add('Each collector ran as its own Windows PowerShell process, one after another, except the clock session, which ran in the background across the live captures. Each collector''s own manifest, summary and log are kept under logs/steps/<step>/ with the profile folder written as <profile>, the account as <account> and this directory as <bundle>; raw/ holds every source the runner merged, under its own id or with the step''s prefix (state_before_, state_after_, diskio_).')
    $notes.Add('In this scenario the history steps and the state snapshots are optional: their sources are listed with required false whatever the collector marked.')
    foreach ($note in $gameNotes) { $notes.Add($note) }
    if ($gameNotes.Count -gt 0) { $notes.Add('The runner does not check whether the game ran or was closed: the processes source of each state snapshot (state_before_processes, state_after_processes) lists what was running when it was taken.') }
    if (-not $preflight['ok']) { $notes.Add($refusal) }
    foreach ($record in $records) {
        $notes.Add(('Step {0} ({1}): {2}{3}' -f $record.step, $record.collector, $record.outcome, $(if ($record.detail) { '; ' + $record.detail } else { '' })))
    }
    $notes.Add('This bundle holds capture output only. Decoded tables, evidence rows and a verdict are written later, off the machine.')

    $runSection = [ordered]@{
        runner_version           = Get-WfRunnerVersion
        scenario                 = $definition['Id']
        scenario_version         = $definition['Version']
        minimum_free_bytes       = [int64]$plan['MinimumFreeBytes']
        clock_brackets_live      = $clockBrackets
        steps                    = @($records.ToArray())
    }
    $preflightSection = [ordered]@{ ok = [bool]$preflight['ok']; at_utc = $preflight['at_utc']; required = @($preflight['required']); checks = @($preflight['checks']) }

    $manifest = [ordered]@{
        manifest_version   = Get-WfRunnerManifestVersion
        bundle_id          = ('{0}_{1}_{2}' -f (ConvertTo-WfCompactUtc -Value $start), $definition['Id'], $machineInfo['machine_id_short'])
        created_utc        = ConvertTo-WfUtcString -Value $stop
        scenario           = [ordered]@{
            id                   = $definition['Id']
            version              = $definition['Version']
            requested_duration_s = [int64]($steps | Where-Object { $_['Collector'] -eq 'clock-calibration' } | ForEach-Object { $_['Arguments']['DurationSeconds'] } | Select-Object -First 1)
            target_process       = $targetProcess
            marks                = @($marks)
        }
        capture            = [ordered]@{
            start_utc            = ConvertTo-WfUtcString -Value $start
            stop_utc             = ConvertTo-WfUtcString -Value $stop
            orchestrator         = 'wf-runner:' + $definition['Id']
            orchestrator_version = Get-WfRunnerVersion
            elevated             = $account['elevated']
            incomplete           = ($summaryStatus -ne 'ok')
        }
        machine            = $machine
        collectors         = @($entries.ToArray())
        calibration        = $calibration
        tools              = @($tools.ToArray())
        symbols            = [ordered]@{ symbol_path = $null; cache_path = $null; dbghelp_version = $null }
        checksum_algorithm = 'sha256'
        notes              = @($notes.ToArray())
        preflight          = $preflightSection
        run                = $runSection
    }

    Protect-WfScenarioStepFiles -BundleRoot $bundleRoot -Redactions $redactions
    $log.Add(('{0} manifest written: bundle {1}, status {2}, {3} artifacts' -f (ConvertTo-WfUtcString -Value $stop), $manifest.bundle_id, $summaryStatus, $artifactCount))
    $summaryLine = ConvertTo-WfSummaryLine -Collector (Get-WfRunnerName) -Status $summaryStatus -Bundle $OutputDirectory -Artifacts $artifactCount
    Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'logs/summary.json') -Text ((Protect-WfRunnerText -Text $summaryLine -Redactions $redactions) + "`n")
    Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'logs/collector.log') -Text ((Protect-WfRunnerText -Text ($log.ToArray() -join "`n") -Redactions $redactions) + "`n")
    # The manifest is the last file written: a directory without one is not a bundle.
    Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $bundleRoot -RelativePath 'manifest.json') -Text ((Protect-WfRunnerText -Text (ConvertTo-WfJson -Value $manifest -Indent 0) -Redactions $redactions) + "`n")
    $State['Written'] = $true
    return [ordered]@{ Status = $summaryStatus; SummaryLine = $summaryLine }
}

function Invoke-WfScenarioScript {
    # The runner's entry point: one JSON line on stdout, diagnostics on
    # stderr, exit code 0 for ok or partial and 1 otherwise.
    param(
        [string]$ScenarioId,
        [string]$OutputDirectory,
        [int]$DurationSeconds,
        [string]$ProcessName,
        [string]$PresentMonPath,
        [string]$XperfPath,
        [int64]$MaxArtifactBytes,
        [string]$CollectorRoot,
        [string]$RunnerPath,
        [int]$GameStartSeconds = 120,
        [int]$GameCloseSeconds = 60
    )
    $state = @{}
    $exitCode = 1
    $line = $null
    try {
        $output = @(Invoke-WfScenario -ScenarioId $ScenarioId -OutputDirectory $OutputDirectory -DurationSeconds $DurationSeconds -ProcessName $ProcessName `
                -PresentMonPath $PresentMonPath -XperfPath $XperfPath -MaxArtifactBytes $MaxArtifactBytes -CollectorRoot $CollectorRoot -RunnerPath $RunnerPath `
                -GameStartSeconds $GameStartSeconds -GameCloseSeconds $GameCloseSeconds -State $state)
        $result = $output[$output.Count - 1]
        $line = [string]$result['SummaryLine']
        if ($result['Status'] -ne 'failed') { $exitCode = 0 }
    } catch {
        $message = (Get-WfRunnerName) + ' failed: ' + $_.Exception.Message
        if ($state.ContainsKey('Redactions')) { $message = Protect-WfRunnerText -Text $message -Redactions $state['Redactions'] }
        Write-WfStderrLine -Text $message
        $line = ConvertTo-WfSummaryLine -Collector (Get-WfRunnerName) -Status 'failed' -Bundle $OutputDirectory -Artifacts 0
        if ($state.ContainsKey('BundleRoot') -and -not $state.ContainsKey('Written')) {
            try {
                $logText = (@($state['Log']) + @($message)) -join "`n"
                if ($state.ContainsKey('Redactions')) { $logText = Protect-WfRunnerText -Text $logText -Redactions $state['Redactions'] }
                Write-WfTextFile -Path (Join-WfBundlePath -BundleRoot $state['BundleRoot'] -RelativePath 'logs/collector.log') -Text ($logText + "`n")
            } catch { Write-WfStderrLine -Text ('the log could not be written: ' + $_.Exception.Message) }
        }
    }
    Write-WfStdoutLine -Text $line
    return $exitCode
}
