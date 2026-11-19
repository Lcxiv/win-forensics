# Logic and Windows adapters for gpu-affinity-1a.ps1, step 1a of the undo
# order: the display adapter's interrupt Affinity Policy back to its state
# before 12 November, restored from the single matching Originals rows of
# Stutter Guard's journal. Dot sourced by the entry script and by the tests.
#
# The file has two halves, like collectors/windows/_common.ps1 (which this
# file does not load). The first half is portable logic and is what the
# Pester suite in tests/ exercises off Windows. The second half, at the
# bottom, holds the adapters that touch Windows; the tests replace them with
# tests/SyntheticGpuAffinity1a.ps1. Only two adapters change anything:
# Set-Wf1aRegistryValue and Remove-Wf1aRegistryValue.
#
# Every Windows fact relied on is cited next to the code and in
# changes/windows/README.md, which also lists what is not verified yet.
#
# Target: Windows PowerShell 5.1, run by hand by the operator in an elevated
# console. Plain ASCII.

if (Get-Command -Name 'Invoke-Wf1aMain' -CommandType Function -ErrorAction SilentlyContinue) { return }

. (Join-Path -Path $PSScriptRoot -ChildPath '_stutter-guard-journal.ps1')

# ---------------------------------------------------------------------------
# Constants. Functions, not variables: this file is dot sourced into other
# scopes.
# ---------------------------------------------------------------------------

function Get-Wf1aChangeName { return 'gpu-affinity-1a' }

# The values the Stutter Guard affinity tweak writes, in the order this step
# restores them. DevicePolicy goes first: with DevicePolicy gone the mask is
# not used (Learn: the mask applies "If DevicePolicy is 0x04"), so a stop
# between the two writes never leaves policy 4 without its mask.
# https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority
# AffinityTweak.Apply at the pinned commit writes exactly these two:
# https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Tweaks/Interrupts.cs
function Get-Wf1aChangedValueNames { return @('DevicePolicy', 'AssignmentSetOverride') }

# Read and saved for the record, never written: the 17 Nov tool also wrote
# DevicePriority, which no journal row covers and the current Learn page does
# not document.
function Get-Wf1aWatchedValueNames { return @('DevicePriority') }

# What the PC evidence of 2026-11-18 reports for the live values (pinned to
# CPU 6 on 17 Nov): DevicePolicy 4 and a mask with only bit 6 set.
function Get-Wf1aExpectedLivePolicy { return [uint64]4 }
function Get-Wf1aExpectedLiveMask { return [uint64]0x40 }

# The Stutter Guard session the row must come from (local wall clock date).
function Get-Wf1aSessionDate { return [datetime]::new(2026, 11, 12) }

function Get-Wf1aBitsumBackupKey { return 'SOFTWARE\Bitsum\InterruptAffinityBackup' }

# Programs that can write these values while they run: Stutter Guard (its
# "heal" button re-applies drifted tweaks), and Bitsum's Interrupt Affinity
# Policy tool and LatencyTest, which opens it. The game and its launcher:
# nothing is changed while they run.
function Get-Wf1aWriterProcesses { return @('StutterGuard', 'IRQControl', 'LatencyTest') }
function Get-Wf1aGameProcesses { return @('Overwatch', 'Battle.net') }

# Executables whose scheduled tasks or services are examined for a
# mechanism that could put the values back.
function Get-Wf1aMechanismExecutables { return @('stutterguard.exe', 'irqcontrol.exe', 'latencytest.exe', 'dpctimerres.exe') }
function Get-Wf1aStutterGuardTaskFolders { return @('\Stutter Guard\', '\DPC Latency Tweaker\') }

function Get-Wf1aRestartText {
    return @(
        'Restart: needed before the change takes effect, and this script never restarts anything.',
        '  Windows hands the Affinity Policy values to the device driver when the PnP manager prepares',
        '  to allocate the device''s resources, before initial device configuration (Learn: interrupt',
        '  affinity, IRP_MN_FILTER_RESOURCE_REQUIREMENTS). For the display adapter that is the next',
        '  restart (inference; Bitsum documents the same for display adapters). Restart by hand, then',
        '  run -Readback.'
    )
}

# ---------------------------------------------------------------------------
# Output. Every line goes through Protect-Wf1aText before it is written, so a
# device instance path or the operator's profile folder never reaches the
# console even if a message carried one by mistake.
# ---------------------------------------------------------------------------

function Protect-Wf1aText {
    param([string]$Text, [string[]]$Secrets)
    $out = $Text
    foreach ($s in $Secrets) {
        if ($s -and $s.Length -ge 4) {
            $out = [regex]::Replace($out, [regex]::Escape($s), 'display-adapter-1', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $profileRoot = [Environment]::GetEnvironmentVariable('USERPROFILE')
    if ($profileRoot -and $profileRoot.Length -ge 4) {
        $out = [regex]::Replace($out, [regex]::Escape($profileRoot), '<profile>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $out = [regex]::Replace($out, '(?i)[A-Z]:\\Users\\[^\\\s]+', '<profile>')
    $out = [regex]::Replace($out, '(?i)PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}[^\s|\]]*', 'display-adapter-1')
    return $out
}

function Write-Wf1aReport {
    param([string[]]$Lines, [string[]]$Secrets = @())
    foreach ($line in $Lines) { Write-Wf1aOut -Line (Protect-Wf1aText -Text $line -Secrets $Secrets) }
}

# ---------------------------------------------------------------------------
# The device and its keys.
# ---------------------------------------------------------------------------

function Test-Wf1aInstanceId {
    # A PCI instance path with the documented shape and no further key
    # separators, so it can never point outside its own Enum key.
    param([string]$InstanceId)
    return [bool]($InstanceId -match '^(?i)PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}[A-Z0-9_&]*\\[A-Z0-9_&.]+$')
}

function Get-Wf1aDeviceKeys {
    # The registry paths for one device, relative to HKLM. These are private:
    # they carry the instance path and are never printed.
    param([string]$InstanceId)
    $enum = 'SYSTEM\CurrentControlSet\Enum\' + $InstanceId
    $interrupt = $enum + '\Device Parameters\Interrupt Management'
    $vendorDevice = ''
    if ($InstanceId -match '(?i)(VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4})') { $vendorDevice = $Matches[1].ToUpperInvariant() }
    return [pscustomobject]@{
        InstanceId   = $InstanceId
        Interrupt    = $interrupt
        Affinity     = $interrupt + '\Affinity Policy'
        Msi          = $interrupt + '\MessageSignaledInterruptProperties'
        TweakId      = 'irq.' + $InstanceId
        VendorDevice = $vendorDevice
        IdSha256     = (Get-WfSha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($InstanceId.ToUpperInvariant())))
    }
}

function Get-Wf1aJournalTarget {
    param($Keys, [string]$ValueName)
    return ('HKLM\' + $Keys.Affinity + '|' + $ValueName)
}

function Get-Wf1aValueFromKey {
    param($KeyRead, [string]$Name)
    if ($null -eq $KeyRead) { return (New-WfAbsentValue) }
    foreach ($v in $KeyRead.Values) {
        if ([string]::Equals($v.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $v.Value }
    }
    return (New-WfAbsentValue)
}

function Read-Wf1aLiveValues {
    # The live values of the Affinity Policy key, changed and watched. Throws
    # when the key cannot be read; an unreadable key is unknown, never absent.
    param($Keys)
    $key = Get-Wf1aRegistryKey -SubKey $Keys.Affinity
    $values = [ordered]@{}
    foreach ($name in @((Get-Wf1aChangedValueNames) + (Get-Wf1aWatchedValueNames))) {
        $values[$name] = Get-Wf1aValueFromKey -KeyRead $key -Name $name
    }
    return [pscustomobject]@{ KeyExists = ($null -ne $key); Values = $values }
}

function Format-Wf1aLiveValue {
    param([string]$Name, $Value)
    $text = Format-WfRegValue -Value $Value
    if ($Name -eq 'AssignmentSetOverride' -and $Value.Exists) {
        $text = $text + ' (' + (Format-WfCpuList -Mask (Get-WfAffinityMask -Value $Value)) + ')'
    }
    return $text
}

# ---------------------------------------------------------------------------
# Checks. Each is @{ Id; Ok; Text }. Plan runs all of them and refuses when
# any fails.
# ---------------------------------------------------------------------------

function New-Wf1aCheck {
    param([string]$Id, [bool]$Ok, [string]$Text)
    return [pscustomobject]@{ Id = $Id; Ok = $Ok; Text = $Text }
}

function Find-Wf1aDisplayAdapter {
    # Exactly one present display adapter on the PCI bus. Learn:
    # Get-PnpDevice -Class Display -PresentOnly lists present devices of the
    # Display setup class.
    $all = @(Get-Wf1aDisplayAdapterIds)
    $pci = @($all | Where-Object { $_ -match '^(?i)PCI\\' })
    if ($pci.Count -eq 0) {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'device' -Ok $false -Text 'No present PCI display adapter was found.'); Keys = $null }
    }
    if ($pci.Count -gt 1) {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'device' -Ok $false -Text ($pci.Count.ToString() + ' present PCI display adapters match; this step is written for exactly one.')); Keys = $null }
    }
    if (-not (Test-Wf1aInstanceId -InstanceId $pci[0])) {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'device' -Ok $false -Text 'The display adapter''s instance path does not have the expected PCI shape.'); Keys = $null }
    }
    $keys = Get-Wf1aDeviceKeys -InstanceId $pci[0]
    return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'device' -Ok $true -Text 'Exactly one present PCI display adapter: display-adapter-1.'); Keys = $keys }
}

function Get-Wf1aJournalPath {
    param([string]$StutterGuardDataDirectory)
    return (Join-Path -Path $StutterGuardDataDirectory -ChildPath 'journal.json')
}

function Get-Wf1aJournalRows {
    # The journal and its two rows for this device, with checks.
    param($Keys, [string]$StutterGuardDataDirectory)
    $checks = New-Object System.Collections.Generic.List[object]
    $journal = Read-WfSgJournal -Path (Get-Wf1aJournalPath -StutterGuardDataDirectory $StutterGuardDataDirectory)
    $rows = [ordered]@{}
    if ($journal.Status -ne 'ok') {
        $checks.Add((New-Wf1aCheck -Id 'journal' -Ok $false -Text ('Stutter Guard journal ' + $journal.Status + ': ' + $journal.Reason + '.')))
        return [pscustomobject]@{ Journal = $journal; Rows = $rows; Checks = $checks.ToArray() }
    }
    $checks.Add((New-Wf1aCheck -Id 'journal' -Ok $true -Text ('Stutter Guard journal read as data: ' + $journal.Originals.Count + ' Originals rows, SHA-256 ' + $journal.Sha256 + '.')))
    $sessionDate = Get-Wf1aSessionDate
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        $selection = Select-WfSgOriginalRow -Journal $journal -Kind 'reg' -Target (Get-Wf1aJournalTarget -Keys $Keys -ValueName $name) -TweakId $Keys.TweakId
        $rows[$name] = $selection
        if ($selection.Status -ne 'ok') {
            $checks.Add((New-Wf1aCheck -Id ('row-' + $name) -Ok $false -Text ('Journal row for ' + $name + ' is ' + $selection.Status + ': ' + $selection.Reason + '.')))
            continue
        }
        $row = $selection.Row
        $whenText = $row.When.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        if ($row.When.Date -ne $sessionDate) {
            $checks.Add((New-Wf1aCheck -Id ('row-' + $name) -Ok $false -Text ('Journal row ' + $row.Index + ' for ' + $name + ' was recorded ' + $whenText + ', not in the 12 Nov session.')))
            continue
        }
        $checks.Add((New-Wf1aCheck -Id ('row-' + $name) -Ok $true -Text ('Journal row ' + $row.Index + ' for ' + $name + ' (recorded ' + $whenText + ' local): Existed ' + $row.Existed.ToString().ToLowerInvariant() + ', before 12 Nov it was ' + (Format-Wf1aLiveValue -Name $name -Value $selection.Value) + '.')))
    }
    return [pscustomobject]@{ Journal = $journal; Rows = $rows; Checks = $checks.ToArray() }
}

function Test-Wf1aRowsUsable {
    param($JournalRows)
    if ($JournalRows.Journal.Status -ne 'ok') { return $false }
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        if (-not $JournalRows.Rows.Contains($name)) { return $false }
        if ($JournalRows.Rows[$name].Status -ne 'ok') { return $false }
    }
    return $true
}

function Test-Wf1aSessionReg {
    # Cross-check 1: the reg export Stutter Guard made of the device's
    # Interrupt Management key in the session that recorded the rows,
    # parsed as text, must show the same before-state for both values.
    param($Keys, $JournalRows, [string]$StutterGuardDataDirectory)
    $first = $JournalRows.Rows[(Get-Wf1aChangedValueNames)[0]].Row
    $found = Find-WfSgSessionRegFile -DataDirectory $StutterGuardDataDirectory -ExportedKeyPath ('HKLM\' + $Keys.Interrupt) -When $first.When
    if ($found.Status -ne 'ok') {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'session-reg' -Ok $false -Text ('The 12 Nov session export of the key was not found: ' + $found.Reason + '.')); Sha256 = $null; Session = $found.Session }
    }
    $export = Read-WfRegExportFile -Path $found.Path
    if ($export.Status -ne 'ok') {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'session-reg' -Ok $false -Text ('Session ' + $found.Session + ' export is unreadable: ' + $export.Reason + '.')); Sha256 = $export.Sha256; Session = $found.Session }
    }
    $disagree = @()
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        $fromReg = Get-WfRegExportValue -Export $export -KeyPath ('HKLM\' + $Keys.Affinity) -ParentKeyPath ('HKLM\' + $Keys.Interrupt) -ValueName $name
        $fromRow = $JournalRows.Rows[$name].Value
        if ($null -eq $fromReg) {
            $disagree += ($name + ': the export does not hold the device''s Interrupt Management key')
        } elseif (-not (Test-WfRegValueEqual -A $fromReg -B $fromRow)) {
            $disagree += ($name + ': export says ' + (Format-Wf1aLiveValue -Name $name -Value $fromReg) + ', journal row says ' + (Format-Wf1aLiveValue -Name $name -Value $fromRow))
        }
    }
    if ($disagree.Count -gt 0) {
        return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'session-reg' -Ok $false -Text ('Sources disagree, session ' + $found.Session + ' export against the journal: ' + ($disagree -join '; ') + '.')); Sha256 = $export.Sha256; Session = $found.Session }
    }
    return [pscustomobject]@{ Check = (New-Wf1aCheck -Id 'session-reg' -Ok $true -Text ('Session ' + $found.Session + ' export (read as text, never imported, SHA-256 ' + $export.Sha256 + ') agrees with both rows.')); Sha256 = $export.Sha256; Session = $found.Session }
}

function Get-Wf1aSubtreeValues {
    # Every value under one key, down to a fixed depth, with its name.
    param([string]$SubKey, [int]$Depth)
    $out = New-Object System.Collections.Generic.List[object]
    $key = Get-Wf1aRegistryKey -SubKey $SubKey
    if ($null -eq $key) { return , $out.ToArray() }
    foreach ($v in $key.Values) { $out.Add($v) }
    if ($Depth -gt 0) {
        foreach ($child in $key.SubKeyNames) {
            $below = Get-Wf1aSubtreeValues -SubKey ($SubKey + '\' + $child) -Depth ($Depth - 1)
            foreach ($v in $below) { $out.Add($v) }
        }
    }
    return , $out.ToArray()
}

function Test-Wf1aBitsumBackup {
    # Cross-check 2: Bitsum's saved originals for the display adapter. The
    # PC evidence (2026-11-18) reports the entry holds the keys' existence and
    # the MSI values with "no mask recorded". Bitsum documents that the
    # originals are saved before the first change and restored byte for byte,
    # not the layout of this key, so the reader only looks for value names:
    # a recorded mask (AssignmentSetOverride or a name holding "Mask") and a
    # recorded DevicePolicy. Layout: changes/windows/README.md, item 1a.6.
    # https://bitsum.com/apps/process-lasso/docs/tools/interrupt-affinity-policy/
    # https://bitsum.com/irqcontrol/
    param($Keys, $JournalRows)
    $root = Get-Wf1aBitsumBackupKey
    $key = Get-Wf1aRegistryKey -SubKey $root
    if ($null -eq $key) {
        return (New-Wf1aCheck -Id 'bitsum-backup' -Ok $false -Text 'The Bitsum InterruptAffinityBackup key is not present, so the second cross-check cannot be made.')
    }
    $entries = @($key.SubKeyNames | Where-Object { $Keys.VendorDevice -and $_.ToUpperInvariant().Contains($Keys.VendorDevice) })
    if ($entries.Count -ne 1) {
        return (New-Wf1aCheck -Id 'bitsum-backup' -Ok $false -Text ('The Bitsum backup holds ' + $entries.Count + ' entries for the display adapter''s vendor and device; exactly one is needed.'))
    }
    # Assigned without @(): the function returns its array whole.
    $values = Get-Wf1aSubtreeValues -SubKey ($root + '\' + $entries[0]) -Depth 3
    $masks = @($values | Where-Object { $_.Name -match '^(?i)AssignmentSetOverride$' -or $_.Name -match '(?i)mask' })
    $policies = @($values | Where-Object { $_.Name -match '^(?i)DevicePolicy$' })
    $rowMask = $JournalRows.Rows['AssignmentSetOverride'].Value
    $rowPolicy = $JournalRows.Rows['DevicePolicy'].Value
    $disagree = @()
    if ($masks.Count -gt 0 -and -not $rowMask.Exists) { $disagree += 'Bitsum recorded an affinity mask, the journal row says there was none' }
    if ($masks.Count -eq 0 -and $rowMask.Exists) { $disagree += 'the journal row records a mask, Bitsum recorded none' }
    if ($masks.Count -gt 1) { $disagree += 'Bitsum holds more than one mask shaped value' }
    if ($masks.Count -eq 1 -and $rowMask.Exists -and (Get-WfAffinityMask -Value $masks[0].Value) -ne (Get-WfAffinityMask -Value $rowMask)) { $disagree += 'Bitsum and the journal record different masks' }
    if ($policies.Count -gt 0 -and -not $rowPolicy.Exists) { $disagree += 'Bitsum recorded a DevicePolicy, the journal row says there was none' }
    if ($policies.Count -eq 1 -and $rowPolicy.Exists -and -not (Test-WfRegValueEqual -A $policies[0].Value -B $rowPolicy)) { $disagree += 'Bitsum and the journal record different DevicePolicy values' }
    if ($disagree.Count -gt 0) {
        return (New-Wf1aCheck -Id 'bitsum-backup' -Ok $false -Text ('Sources disagree, Bitsum backup against the journal: ' + ($disagree -join '; ') + '.'))
    }
    $summary = 'no mask recorded'
    if ($masks.Count -eq 1) { $summary = 'mask ' + (Format-WfCpuList -Mask (Get-WfAffinityMask -Value $masks[0].Value)) }
    return (New-Wf1aCheck -Id 'bitsum-backup' -Ok $true -Text ('Bitsum backup entry for the display adapter agrees with the journal (' + $summary + ', ' + $values.Count + ' values read).'))
}

function Test-Wf1aLiveState {
    # The live values must be the ones the report expects (CPU 6). When they
    # are not, the check prints what is there instead.
    param($Live)
    $policy = $Live.Values['DevicePolicy']
    $mask = $Live.Values['AssignmentSetOverride']
    $policyOk = ($policy.Exists -and $policy.Kind -eq 'DWord' -and [uint64]$policy.Number -eq (Get-Wf1aExpectedLivePolicy))
    $maskValue = Get-WfAffinityMask -Value $mask
    $maskOk = ($mask.Exists -and $null -ne $maskValue -and [uint64]$maskValue -eq (Get-Wf1aExpectedLiveMask))
    if ($policyOk -and $maskOk) {
        return (New-Wf1aCheck -Id 'live' -Ok $true -Text 'Live values are the expected ones: DevicePolicy 4 with a mask of CPU 6 only.')
    }
    return (New-Wf1aCheck -Id 'live' -Ok $false -Text ('Live values are not the expected DevicePolicy 4 with CPU 6 only. Found: DevicePolicy ' + (Format-Wf1aLiveValue -Name 'DevicePolicy' -Value $policy) + ', AssignmentSetOverride ' + (Format-Wf1aLiveValue -Name 'AssignmentSetOverride' -Value $mask) + '.'))
}

function Get-Wf1aExecutableName {
    # The executable's file name from a task action or a service image path,
    # lower case, or '' when none can be read. The rest of the text (paths,
    # arguments) is never kept.
    param([string]$Text)
    if (-not $Text) { return '' }
    $m = [regex]::Match($Text, '(?i)([^\\/"]+\.exe)')
    if (-not $m.Success) { return '' }
    return $m.Groups[1].Value.ToLowerInvariant()
}

function Get-Wf1aMechanisms {
    # Every scheduled task, service and running program that could put the
    # values back, classified by what the pinned Stutter Guard source and
    # Bitsum's documentation say it does. Returns @{ Blocking; Known } where
    # each item is a printable line; Blocking items make Plan refuse.
    #
    # Stutter Guard creates two tasks under \Stutter Guard\: "Device power
    # saving off" runs StutterGuard.exe --agent device-power at boot, which
    # changes device power only (DevicePower.ApplyNow), and "Timer
    # resolution" runs DpcTimerRes.exe at logon. --agent drift-check only
    # reads. Re-applying a drifted affinity ("heal") happens only from the
    # app's window, on a click.
    # https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Tweaks/BootTasks.cs
    # https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.Core/Agent.cs
    # https://github.com/Kareem-Shabaka/stutter-guard/blob/8c783a478f4b511c273b3235bf745b5d64550f49/src/DpcTweaker.UI/Pages.cs
    # Bitsum documents the Interrupt Affinity Policy tool as its own program
    # (IRQControl.exe) that writes the policy Windows reads when it starts a
    # device, and the Process Governor as the engine that applies process
    # rules; neither page describes re-applying an interrupt policy at boot
    # or on a timer.
    # https://bitsum.com/apps/process-lasso/docs/tools/interrupt-affinity-policy/
    # https://bitsum.com/apps/process-lasso/docs/getting-started/how-it-works/
    $blocking = New-Object System.Collections.Generic.List[string]
    $known = New-Object System.Collections.Generic.List[string]
    $watched = Get-Wf1aMechanismExecutables
    $taskNumber = 0
    foreach ($task in @(Get-Wf1aScheduledTasks)) {
        $inFolder = $false
        foreach ($folder in (Get-Wf1aStutterGuardTaskFolders)) {
            if ([string]$task.TaskPath -and ([string]$task.TaskPath).StartsWith($folder, [System.StringComparison]::OrdinalIgnoreCase)) { $inFolder = $true }
        }
        $actions = @($task.Actions)
        $exes = @($actions | ForEach-Object { Get-Wf1aExecutableName -Text ([string]$_.Execute) })
        $relevant = $inFolder
        foreach ($e in $exes) { if ($watched -contains $e) { $relevant = $true } }
        if (-not $relevant) { continue }
        $taskNumber++
        $full = [string]$task.TaskPath + [string]$task.TaskName
        $label = 'task-' + $taskNumber
        if ($full -ieq '\Stutter Guard\Device power saving off') { $label = 'Stutter Guard task "Device power saving off"' }
        if ($full -ieq '\Stutter Guard\Timer resolution') { $label = 'Stutter Guard task "Timer resolution"' }
        $unknown = ($actions.Count -eq 0)
        $what = @()
        foreach ($a in $actions) {
            $exe = Get-Wf1aExecutableName -Text ([string]$a.Execute)
            $actionArguments = ([string]$a.Arguments).Trim()
            if ($exe -eq 'stutterguard.exe' -and $actionArguments -ceq '--agent device-power') { $what += 'device power only (DevicePower.ApplyNow), never interrupt affinity' }
            elseif ($exe -eq 'stutterguard.exe' -and $actionArguments -ceq '--agent drift-check') { $what += 'a read only drift check' }
            elseif ($exe -eq 'dpctimerres.exe' -and $actionArguments -match '^\d{1,7}$') { $what += 'the timer resolution helper only' }
            else { $unknown = $true }
        }
        if ($unknown) {
            $blocking.Add($label + ': an action this step has not reviewed (' + $task.State + '); it may write interrupt settings. Disable or remove it first (not part of this step).')
        } else {
            $known.Add($label + ' (' + $task.State + '): ' + ($what -join '; ') + '. Does not put the affinity back (pinned source).')
        }
    }
    $serviceNumber = 0
    foreach ($svc in @(Get-Wf1aServices)) {
        $exe = Get-Wf1aExecutableName -Text ([string]$svc.PathName)
        if ($exe -eq 'processgovernor.exe') {
            $known.Add('Process Lasso Governor service (' + $svc.State + '): applies process rules; Bitsum documents no interrupt affinity re-application by it.')
            continue
        }
        if ($watched -notcontains $exe) { continue }
        $serviceNumber++
        $blocking.Add('service-' + $serviceNumber + ' runs ' + $exe + ' (' + $svc.State + '); no reviewed source describes it. Deal with it first (not part of this step).')
    }
    $running = @(Get-Wf1aProcessNames)
    foreach ($name in (Get-Wf1aWriterProcesses)) {
        if (@($running | Where-Object { $_ -ieq $name }).Count -gt 0) {
            $blocking.Add($name + ' is running and can write these values; close it first.')
        }
    }
    if (@($running | Where-Object { $_ -ieq 'ProcessGovernor' }).Count -gt 0) {
        $known.Add('ProcessGovernor is running: applies process rules; Bitsum documents no interrupt affinity re-application by it.')
    }
    return [pscustomobject]@{ Blocking = $blocking.ToArray(); Known = $known.ToArray() }
}

function Test-Wf1aGameClosed {
    $running = @(Get-Wf1aProcessNames)
    $open = @((Get-Wf1aGameProcesses) | Where-Object { $n = $_; @($running | Where-Object { $_ -ieq $n }).Count -gt 0 })
    if ($open.Count -gt 0) {
        return (New-Wf1aCheck -Id 'game' -Ok $false -Text ('Close the game and its launcher first: ' + ($open -join ', ') + ' running.'))
    }
    return (New-Wf1aCheck -Id 'game' -Ok $true -Text 'The game and its launcher are closed.')
}

function Get-Wf1aTargetValues {
    # What each changed value becomes: the row's before-state.
    param($JournalRows)
    $target = [ordered]@{}
    foreach ($name in (Get-Wf1aChangedValueNames)) { $target[$name] = $JournalRows.Rows[$name].Value }
    return $target
}

function Invoke-Wf1aPlan {
    # Reads everything, changes nothing. Returns the plan object; Ready is
    # true only when every check passed.
    param([string]$StutterGuardDataDirectory)
    $checks = New-Object System.Collections.Generic.List[object]
    $plan = [pscustomobject]@{ Ready = $false; Checks = $null; Keys = $null; Live = $null; JournalRows = $null; Target = $null; Mechanisms = $null; SessionRegSha256 = $null; Session = $null; Elevated = $false }
    $plan.Elevated = [bool](Test-Wf1aElevated)
    $device = Find-Wf1aDisplayAdapter
    $checks.Add($device.Check)
    $checks.Add((Test-Wf1aGameClosed))
    if ($null -ne $device.Keys) {
        $plan.Keys = $device.Keys
        try {
            $plan.Live = Read-Wf1aLiveValues -Keys $device.Keys
            $checks.Add((Test-Wf1aLiveState -Live $plan.Live))
        } catch {
            $checks.Add((New-Wf1aCheck -Id 'live' -Ok $false -Text ('The live Affinity Policy key could not be read (' + $_.Exception.GetType().Name + '); unknown, not absent.')))
        }
        try {
            $plan.JournalRows = Get-Wf1aJournalRows -Keys $device.Keys -StutterGuardDataDirectory $StutterGuardDataDirectory
            foreach ($c in $plan.JournalRows.Checks) { $checks.Add($c) }
        } catch {
            $checks.Add((New-Wf1aCheck -Id 'journal' -Ok $false -Text ('The Stutter Guard data could not be read (' + $_.Exception.GetType().Name + ').')))
        }
        if ($null -ne $plan.JournalRows -and (Test-Wf1aRowsUsable -JournalRows $plan.JournalRows)) {
            $plan.Target = Get-Wf1aTargetValues -JournalRows $plan.JournalRows
            try {
                $sessionReg = Test-Wf1aSessionReg -Keys $device.Keys -JournalRows $plan.JournalRows -StutterGuardDataDirectory $StutterGuardDataDirectory
                $plan.SessionRegSha256 = $sessionReg.Sha256
                $plan.Session = $sessionReg.Session
                $checks.Add($sessionReg.Check)
            } catch {
                $checks.Add((New-Wf1aCheck -Id 'session-reg' -Ok $false -Text ('The session export could not be read (' + $_.Exception.GetType().Name + ').')))
            }
            try {
                $checks.Add((Test-Wf1aBitsumBackup -Keys $device.Keys -JournalRows $plan.JournalRows))
            } catch {
                $checks.Add((New-Wf1aCheck -Id 'bitsum-backup' -Ok $false -Text ('The Bitsum backup key could not be read (' + $_.Exception.GetType().Name + '); unknown, not absent.')))
            }
        } else {
            $checks.Add((New-Wf1aCheck -Id 'cross-check' -Ok $false -Text 'No cross-check was made: the journal rows are not usable.'))
        }
        if ($null -ne $plan.Target -and $null -ne $plan.Live) {
            $same = $true
            foreach ($name in (Get-Wf1aChangedValueNames)) {
                if (-not (Test-WfRegValueEqual -A $plan.Live.Values[$name] -B $plan.Target[$name])) { $same = $false }
            }
            if ($same) { $checks.Add((New-Wf1aCheck -Id 'nothing-to-do' -Ok $false -Text 'The live values already equal the journal rows; nothing to change.')) }
        }
    }
    try {
        $plan.Mechanisms = Get-Wf1aMechanisms
        if ($plan.Mechanisms.Blocking.Count -gt 0) {
            $checks.Add((New-Wf1aCheck -Id 'reapply' -Ok $false -Text ('A mechanism that could put the values back is present: ' + ($plan.Mechanisms.Blocking -join ' | '))))
        } else {
            $checks.Add((New-Wf1aCheck -Id 'reapply' -Ok $true -Text 'No scheduled task, service or running program that could put the values back was found.'))
        }
    } catch {
        $checks.Add((New-Wf1aCheck -Id 'reapply' -Ok $false -Text ('Scheduled tasks, services or processes could not be listed (' + $_.Exception.GetType().Name + '); a re-application mechanism cannot be ruled out.')))
    }
    $plan.Checks = $checks.ToArray()
    $plan.Ready = (@($plan.Checks | Where-Object { -not $_.Ok }).Count -eq 0)
    return $plan
}

function Get-Wf1aChangeLines {
    param($Plan)
    $lines = @()
    if ($null -eq $Plan.Target -or $null -eq $Plan.Live) { return @('What would change: cannot be stated (see the failed checks).') }
    $lines += 'What would change (HKLM, display-adapter-1, Device Parameters\Interrupt Management\Affinity Policy):'
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        $now = Format-Wf1aLiveValue -Name $name -Value $Plan.Live.Values[$name]
        $to = $Plan.Target[$name]
        if (-not $to.Exists) { $action = 'delete the value (absent before 12 Nov)' } else { $action = 'set ' + (Format-Wf1aLiveValue -Name $name -Value $to) }
        $lines += ('  ' + $name + ': ' + $now + ' -> ' + $action)
    }
    foreach ($name in (Get-Wf1aWatchedValueNames)) {
        $lines += ('  ' + $name + ': ' + (Format-Wf1aLiveValue -Name $name -Value $Plan.Live.Values[$name]) + ' -> left as it is (no journal row covers it)')
    }
    $lines += '  Nothing else: the MSI limit is step 1b, and no other key or value is touched.'
    return $lines
}

function Get-Wf1aPlanLines {
    param($Plan)
    $lines = @()
    $lines += ('Elevated: ' + $Plan.Elevated.ToString().ToLowerInvariant() + ' (Plan reads only; Apply and Undo need an elevated Windows PowerShell).')
    if ($null -ne $Plan.Live) {
        $lines += 'Current values:'
        foreach ($name in @((Get-Wf1aChangedValueNames) + (Get-Wf1aWatchedValueNames))) {
            $lines += ('  ' + $name + ': ' + (Format-Wf1aLiveValue -Name $name -Value $Plan.Live.Values[$name]))
        }
    }
    $lines += 'Preconditions:'
    foreach ($c in $Plan.Checks) {
        if ($c.Ok) { $state = 'PASS' } else { $state = 'FAIL' }
        $lines += ('  ' + $state + ' ' + $c.Id + ': ' + $c.Text)
    }
    if ($null -ne $Plan.Mechanisms) {
        foreach ($k in $Plan.Mechanisms.Known) { $lines += ('  note: ' + $k) }
    }
    $lines += '  note: Stutter Guard''s heal button, in its window, would re-apply its affinity tweak (CPU 8); do not press it during this step.'
    $lines += (Get-Wf1aChangeLines -Plan $Plan)
    $lines += (Get-Wf1aRestartText)
    return $lines
}

# ---------------------------------------------------------------------------
# Evidence: the saved before-state. One folder per Apply under the evidence
# root, named by the UTC time. It stays on the PC: its reg exports name the
# device's instance path.
# ---------------------------------------------------------------------------

function ConvertTo-Wf1aDataText {
    param($Value)
    if (-not $Value.Exists) { return '' }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    switch ($Value.Kind) {
        'DWord' { return ([uint64]$Value.Number).ToString($invariant) }
        'QWord' { return ([uint64]$Value.Number).ToString($invariant) }
        'String' { return ('utf8:' + (ConvertTo-WfHex -Bytes ([System.Text.Encoding]::UTF8.GetBytes([string]$Value.Text)))) }
        default { return (ConvertTo-WfHex -Bytes $Value.Bytes) }
    }
}

function ConvertFrom-Wf1aDataText {
    param([string]$Exists, [string]$Kind, [string]$Data)
    if ($Exists -ceq 'false') { return (New-WfAbsentValue) }
    if ($Exists -cne 'true') { return $null }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    switch -CaseSensitive ($Kind) {
        'DWord' {
            $n = [uint64]0
            if (-not [uint64]::TryParse($Data, [System.Globalization.NumberStyles]::None, $invariant, [ref]$n) -or $n -gt [uint32]::MaxValue) { return $null }
            return (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number $n)
        }
        'QWord' {
            $n = [uint64]0
            if (-not [uint64]::TryParse($Data, [System.Globalization.NumberStyles]::None, $invariant, [ref]$n)) { return $null }
            return (New-WfRegValueModel -Exists $true -Kind 'QWord' -Number $n)
        }
        'String' {
            if (-not $Data.StartsWith('utf8:', [System.StringComparison]::Ordinal)) { return $null }
            $b = ConvertFrom-WfHex -Text $Data.Substring(5)
            if ($null -eq $b) { return $null }
            return (New-WfRegValueModel -Exists $true -Kind 'String' -Text ([System.Text.Encoding]::UTF8.GetString($b)))
        }
        default {
            if ($Kind -notmatch '^[A-Za-z]+$') { return $null }
            $b = ConvertFrom-WfHex -Text $Data
            if ($null -eq $b) { return $null }
            return (New-WfRegValueModel -Exists $true -Kind $Kind -Bytes $b)
        }
    }
}

function Get-Wf1aCsvHeader { return 'role,value,exists,kind,data,target_exists,target_kind,target_data,device_sha256' }

function ConvertTo-Wf1aBeforeCsv {
    # role is "change" for the two values this step writes and "watch" for
    # the ones it only records. Every field is ASCII without commas.
    param($Live, $Target, [string]$DeviceSha256)
    $lines = @(Get-Wf1aCsvHeader)
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        $v = $Live.Values[$name]
        $t = $Target[$name]
        $lines += (@('change', $name, $v.Exists.ToString().ToLowerInvariant(), $v.Kind, (ConvertTo-Wf1aDataText -Value $v), $t.Exists.ToString().ToLowerInvariant(), $t.Kind, (ConvertTo-Wf1aDataText -Value $t), $DeviceSha256) -join ',')
    }
    foreach ($name in (Get-Wf1aWatchedValueNames)) {
        $v = $Live.Values[$name]
        $lines += (@('watch', $name, $v.Exists.ToString().ToLowerInvariant(), $v.Kind, (ConvertTo-Wf1aDataText -Value $v), '', '', '', $DeviceSha256) -join ',')
    }
    return (($lines -join "`r`n") + "`r`n")
}

function Read-Wf1aBeforeCsv {
    # The saved rows back, strictly: the exact header, known roles and value
    # names, decodable data. Returns $null when anything is off.
    param([string]$Path)
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII)
    $lines = @($text -split "`r`n" | Where-Object { $_.Length -gt 0 })
    if ($lines.Count -lt 1 -or $lines[0] -cne (Get-Wf1aCsvHeader)) { return $null }
    $rows = [ordered]@{}
    $device = $null
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $f = $lines[$i].Split(',')
        if ($f.Count -ne 9) { return $null }
        if ($null -eq $device) { $device = $f[8] } elseif ($device -cne $f[8]) { return $null }
        $saved = ConvertFrom-Wf1aDataText -Exists $f[2] -Kind $f[3] -Data $f[4]
        if ($null -eq $saved) { return $null }
        $target = $null
        if ($f[0] -ceq 'change') {
            if ((Get-Wf1aChangedValueNames) -cnotcontains $f[1]) { return $null }
            $target = ConvertFrom-Wf1aDataText -Exists $f[5] -Kind $f[6] -Data $f[7]
            if ($null -eq $target) { return $null }
        } elseif ($f[0] -ceq 'watch') {
            if ((Get-Wf1aWatchedValueNames) -cnotcontains $f[1]) { return $null }
        } else { return $null }
        if ($rows.Contains($f[1])) { return $null }
        $rows[$f[1]] = [pscustomobject]@{ Role = $f[0]; Saved = $saved; Target = $target }
    }
    foreach ($name in (Get-Wf1aChangedValueNames)) { if (-not $rows.Contains($name)) { return $null } }
    return [pscustomobject]@{ Rows = $rows; DeviceSha256 = $device }
}

function Write-Wf1aTextFile {
    # ASCII without a byte order mark.
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.ASCIIEncoding))
}

function Get-Wf1aFileSha256 {
    param([string]$Path)
    return (Get-WfSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path)))
}

function Get-Wf1aEvidenceFiles {
    # The files the SHA256SUMS list covers, in order; it is written last.
    return @('before-values.csv', 'evidence.txt', 'affinity-policy.reg', 'msi-properties.reg', 'bitsum-backup.reg')
}

function Save-Wf1aEvidence {
    # Saves the before-state. Returns @{ Ok; Folder; Reason; CsvSha256 }.
    # Nothing is changed unless this returns Ok.
    param($Plan, [string]$EvidenceRoot, [datetime]$NowUtc)
    $stamp = $NowUtc.ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $result = [pscustomobject]@{ Ok = $false; Folder = $null; Reason = ''; CsvSha256 = $null; Stamp = $stamp }
    try {
        if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { $null = New-Item -ItemType Directory -Path $EvidenceRoot -Force }
        $folder = Join-Path -Path $EvidenceRoot -ChildPath $stamp
        if (Test-Path -LiteralPath $folder) { $result.Reason = 'an evidence folder with this time already exists'; return $result }
        $null = New-Item -ItemType Directory -Path $folder
        $result.Folder = $folder
        $csvPath = Join-Path -Path $folder -ChildPath 'before-values.csv'
        Write-Wf1aTextFile -Path $csvPath -Text (ConvertTo-Wf1aBeforeCsv -Live $Plan.Live -Target $Plan.Target -DeviceSha256 $Plan.Keys.IdSha256)
        $info = @(
            ('change=' + (Get-Wf1aChangeName)),
            ('saved_utc=' + $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)),
            ('device=display-adapter-1'),
            ('device_sha256=' + $Plan.Keys.IdSha256),
            ('journal_sha256=' + $Plan.JournalRows.Journal.Sha256),
            ('journal_rows=' + (((Get-Wf1aChangedValueNames) | ForEach-Object { $_ + ':' + $Plan.JournalRows.Rows[$_].Row.Index }) -join ';')),
            ('session=' + $Plan.Session),
            ('session_reg_sha256=' + $Plan.SessionRegSha256),
            ('stutter_guard_source=' + (Get-WfSgPinnedCommit))
        )
        Write-Wf1aTextFile -Path (Join-Path -Path $folder -ChildPath 'evidence.txt') -Text (($info -join "`r`n") + "`r`n")
        $exports = @(
            @{ File = 'affinity-policy.reg'; Key = 'HKLM\' + $Plan.Keys.Affinity },
            @{ File = 'msi-properties.reg'; Key = 'HKLM\' + $Plan.Keys.Msi },
            @{ File = 'bitsum-backup.reg'; Key = 'HKLM\' + (Get-Wf1aBitsumBackupKey) }
        )
        foreach ($e in $exports) {
            $target = Join-Path -Path $folder -ChildPath $e.File
            $code = Export-Wf1aRegistryKey -Key $e.Key -File $target
            if ($code -ne 0 -or -not (Test-Path -LiteralPath $target -PathType Leaf) -or (Get-Item -LiteralPath $target).Length -eq 0) {
                $result.Reason = 'reg export of ' + $e.File + ' failed (exit ' + $code + ')'
                return $result
            }
        }
        $sums = @()
        foreach ($f in (Get-Wf1aEvidenceFiles)) { $sums += ((Get-Wf1aFileSha256 -Path (Join-Path -Path $folder -ChildPath $f)) + '  ' + $f) }
        Write-Wf1aTextFile -Path (Join-Path -Path $folder -ChildPath 'SHA256SUMS') -Text (($sums -join "`r`n") + "`r`n")
        $readBack = Read-Wf1aBeforeCsv -Path $csvPath
        if ($null -eq $readBack) { $result.Reason = 'the saved values could not be read back'; return $result }
        foreach ($name in (Get-Wf1aChangedValueNames)) {
            if (-not (Test-WfRegValueEqual -A $readBack.Rows[$name].Saved -B $Plan.Live.Values[$name])) {
                $result.Reason = 'the saved value of ' + $name + ' does not read back as the live value'
                return $result
            }
        }
        $result.CsvSha256 = Get-Wf1aFileSha256 -Path $csvPath
        $result.Ok = $true
        return $result
    } catch {
        $result.Reason = 'saving the before-state failed (' + $_.Exception.GetType().Name + ')'
        return $result
    }
}

function Test-Wf1aEvidenceFolder {
    # Whether a folder holds a complete, intact before-state. Returns the
    # parsed rows or $null with a reason.
    param([string]$Folder)
    $sumsPath = Join-Path -Path $Folder -ChildPath 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { return [pscustomobject]@{ Ok = $false; Reason = 'no SHA256SUMS: the save did not finish'; Before = $null } }
    $expected = @{}
    foreach ($line in ([System.IO.File]::ReadAllText($sumsPath) -split "`r`n")) {
        if ($line -match '^([0-9A-F]{64})  (\S+)$') { $expected[$Matches[2]] = $Matches[1] }
    }
    foreach ($f in (Get-Wf1aEvidenceFiles)) {
        $p = Join-Path -Path $Folder -ChildPath $f
        if (-not $expected.ContainsKey($f) -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return [pscustomobject]@{ Ok = $false; Reason = ($f + ' is missing'); Before = $null } }
        if ((Get-Wf1aFileSha256 -Path $p) -cne $expected[$f]) { return [pscustomobject]@{ Ok = $false; Reason = ($f + ' does not match its SHA-256'); Before = $null } }
    }
    $before = Read-Wf1aBeforeCsv -Path (Join-Path -Path $Folder -ChildPath 'before-values.csv')
    if ($null -eq $before) { return [pscustomobject]@{ Ok = $false; Reason = 'before-values.csv is malformed'; Before = $null } }
    return [pscustomobject]@{ Ok = $true; Reason = ''; Before = $before }
}

function Find-Wf1aEvidenceFolder {
    # The named folder, or the newest complete one under the root.
    param([string]$EvidenceRoot, [string]$Name)
    if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { return $null }
    if ($Name) {
        if ($Name -notmatch '^\d{8}T\d{6}Z$') { return $null }
        $p = Join-Path -Path $EvidenceRoot -ChildPath $Name
        if (Test-Path -LiteralPath $p -PathType Container) { return $p }
        return $null
    }
    $dirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory | Where-Object { $_.Name -match '^\d{8}T\d{6}Z$' } | Sort-Object -Property Name -Descending)
    foreach ($d in $dirs) {
        if (Test-Path -LiteralPath (Join-Path -Path $d.FullName -ChildPath 'SHA256SUMS') -PathType Leaf) { return $d.FullName }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Writing and reading back.
# ---------------------------------------------------------------------------

function Set-Wf1aValueTo {
    # Puts one value into the given state: delete when absent, otherwise
    # write the recorded kind and data. Only the Affinity Policy key of the
    # one display adapter is ever passed here.
    param($Keys, [string]$Name, $Value)
    if (-not $Value.Exists) {
        Remove-Wf1aRegistryValue -SubKey $Keys.Affinity -Name $Name
    } else {
        Set-Wf1aRegistryValue -SubKey $Keys.Affinity -Name $Name -Value $Value
    }
}

function Get-Wf1aReadbackLines {
    # PASS or FAIL per value, live against expected. Returns @{ Ok; Lines }.
    param($Keys, $Expected, [string[]]$Names)
    $lines = @()
    $ok = $true
    try {
        $live = Read-Wf1aLiveValues -Keys $Keys
    } catch {
        return [pscustomobject]@{ Ok = $false; Lines = @('  FAIL the Affinity Policy key could not be read back (' + $_.Exception.GetType().Name + ')') }
    }
    foreach ($name in $Names) {
        $now = $live.Values[$name]
        if (Test-WfRegValueEqual -A $now -B $Expected[$name]) {
            $lines += ('  PASS ' + $name + ': ' + (Format-Wf1aLiveValue -Name $name -Value $now))
        } else {
            $ok = $false
            $lines += ('  FAIL ' + $name + ': live ' + (Format-Wf1aLiveValue -Name $name -Value $now) + ', expected ' + (Format-Wf1aLiveValue -Name $name -Value $Expected[$name]))
        }
    }
    return [pscustomobject]@{ Ok = $ok; Lines = $lines }
}

function Invoke-Wf1aApply {
    param([string]$StutterGuardDataDirectory, [string]$EvidenceRoot)
    $secrets = @()
    if (-not (Test-Wf1aElevated)) {
        Write-Wf1aReport -Lines @('REFUSED: Apply needs an elevated Windows PowerShell (Run as administrator). Nothing changed.')
        return 2
    }
    $plan = Invoke-Wf1aPlan -StutterGuardDataDirectory $StutterGuardDataDirectory
    if ($null -ne $plan.Keys) { $secrets = @($plan.Keys.InstanceId) }
    Write-Wf1aReport -Lines (Get-Wf1aPlanLines -Plan $plan) -Secrets $secrets
    if (-not $plan.Ready) {
        Write-Wf1aReport -Lines @('REFUSED: a precondition failed (above). Nothing changed.') -Secrets $secrets
        return 2
    }
    $saved = Save-Wf1aEvidence -Plan $plan -EvidenceRoot $EvidenceRoot -NowUtc (Get-Wf1aNowUtc)
    if (-not $saved.Ok) {
        Write-Wf1aReport -Lines @(('REFUSED: the before-state could not be saved: ' + $saved.Reason + '. Nothing changed.')) -Secrets $secrets
        return 2
    }
    Write-Wf1aReport -Lines @(('Saved the before-state: evidence folder ' + $saved.Stamp + ' under ' + $EvidenceRoot), ('  before-values.csv SHA-256 ' + $saved.CsvSha256)) -Secrets $secrets
    # Guard against a change between the plan and the write.
    try {
        $again = Read-Wf1aLiveValues -Keys $plan.Keys
    } catch {
        Write-Wf1aReport -Lines @('REFUSED: the key could not be read again before writing. Nothing changed.') -Secrets $secrets
        return 2
    }
    foreach ($name in @((Get-Wf1aChangedValueNames) + (Get-Wf1aWatchedValueNames))) {
        if (-not (Test-WfRegValueEqual -A $again.Values[$name] -B $plan.Live.Values[$name])) {
            Write-Wf1aReport -Lines @(('REFUSED: ' + $name + ' changed after it was saved. Nothing changed; run -Plan again.')) -Secrets $secrets
            return 2
        }
    }
    $written = @()
    $failure = $null
    foreach ($name in (Get-Wf1aChangedValueNames)) {
        try {
            Set-Wf1aValueTo -Keys $plan.Keys -Name $name -Value $plan.Target[$name]
            $written += $name
        } catch {
            $failure = $name + ' could not be written (' + $_.Exception.GetType().Name + ')'
            break
        }
    }
    $readback = Get-Wf1aReadbackLines -Keys $plan.Keys -Expected $plan.Target -Names (Get-Wf1aChangedValueNames)
    $lines = @('Readback after Apply (live against the journal rows):') + $readback.Lines
    $resultText = @(('applied_utc=' + (Get-Wf1aNowUtc).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)), ('written=' + ($written -join ';')), ('readback=' + $(if ($readback.Ok -and $null -eq $failure) { 'PASS' } else { 'FAIL' })))
    try { Write-Wf1aTextFile -Path (Join-Path -Path $saved.Folder -ChildPath 'apply-result.txt') -Text (($resultText -join "`r`n") + "`r`n") } catch { $lines += ('  note: apply-result.txt could not be written (' + $_.Exception.GetType().Name + ')') }
    if ($null -ne $failure) {
        $lines += ('FAILED: ' + $failure + '. Written before the failure: ' + $(if ($written.Count -gt 0) { $written -join ', ' } else { 'nothing' }) + '.')
        $lines += ('Do not restart. Run this script with -Undo now; it restores folder ' + $saved.Stamp + ' exactly.')
        Write-Wf1aReport -Lines $lines -Secrets $secrets
        return 1
    }
    if (-not $readback.Ok) {
        $lines += ('FAILED: the readback does not match. Do not restart. Run -Undo to restore folder ' + $saved.Stamp + '.')
        Write-Wf1aReport -Lines $lines -Secrets $secrets
        return 1
    }
    $lines += 'APPLIED: both values now hold their state before 12 Nov.'
    $lines += (Get-Wf1aRestartText)
    Write-Wf1aReport -Lines $lines -Secrets $secrets
    return 0
}

function Invoke-Wf1aUndo {
    param([string]$EvidenceRoot, [string]$EvidenceFolder)
    if (-not (Test-Wf1aElevated)) {
        Write-Wf1aReport -Lines @('REFUSED: Undo needs an elevated Windows PowerShell (Run as administrator). Nothing changed.')
        return 2
    }
    $folder = Find-Wf1aEvidenceFolder -EvidenceRoot $EvidenceRoot -Name $EvidenceFolder
    if ($null -eq $folder) {
        Write-Wf1aReport -Lines @('REFUSED: no complete evidence folder was found to restore from. Nothing changed.')
        return 2
    }
    $name = Split-Path -Leaf $folder
    $check = Test-Wf1aEvidenceFolder -Folder $folder
    if (-not $check.Ok) {
        Write-Wf1aReport -Lines @(('REFUSED: evidence folder ' + $name + ' is not usable: ' + $check.Reason + '. Nothing changed.'))
        return 2
    }
    $device = Find-Wf1aDisplayAdapter
    if (-not $device.Check.Ok) {
        Write-Wf1aReport -Lines @(('REFUSED: ' + $device.Check.Text + ' Nothing changed.'))
        return 2
    }
    $keys = $device.Keys
    $secrets = @($keys.InstanceId)
    if ($keys.IdSha256 -cne $check.Before.DeviceSha256) {
        Write-Wf1aReport -Lines @(('REFUSED: evidence folder ' + $name + ' was saved for another display adapter. Nothing changed.')) -Secrets $secrets
        return 2
    }
    try {
        $live = Read-Wf1aLiveValues -Keys $keys
    } catch {
        Write-Wf1aReport -Lines @('REFUSED: the Affinity Policy key could not be read. Nothing changed.') -Secrets $secrets
        return 2
    }
    $lines = @(('Restoring from evidence folder ' + $name + ' (SHA-256 checked).'))
    $toRestore = @()
    $saved = [ordered]@{}
    foreach ($n in (Get-Wf1aChangedValueNames)) {
        $row = $check.Before.Rows[$n]
        $saved[$n] = $row.Saved
        $now = $live.Values[$n]
        if (Test-WfRegValueEqual -A $now -B $row.Saved) {
            $lines += ('  ' + $n + ': already ' + (Format-Wf1aLiveValue -Name $n -Value $now) + ', left as it is')
        } elseif (Test-WfRegValueEqual -A $now -B $row.Target) {
            $toRestore += $n
            $lines += ('  ' + $n + ': ' + (Format-Wf1aLiveValue -Name $n -Value $now) + ' -> ' + (Format-Wf1aLiveValue -Name $n -Value $row.Saved))
        } else {
            $lines += ('REFUSED: ' + $n + ' is ' + (Format-Wf1aLiveValue -Name $n -Value $now) + ', neither the saved value nor what Apply wrote; something else changed it. Nothing changed.')
            Write-Wf1aReport -Lines $lines -Secrets $secrets
            return 2
        }
    }
    # The reverse of Apply's order: the mask first, then DevicePolicy, so a
    # stop between the two never leaves policy 4 without its mask.
    $order = @(Get-Wf1aChangedValueNames)
    [array]::Reverse($order)
    $failure = $null
    foreach ($n in $order) {
        if ($toRestore -notcontains $n) { continue }
        try {
            Set-Wf1aValueTo -Keys $keys -Name $n -Value $saved[$n]
        } catch {
            $failure = $n + ' could not be written (' + $_.Exception.GetType().Name + ')'
            break
        }
    }
    $readback = Get-Wf1aReadbackLines -Keys $keys -Expected $saved -Names (Get-Wf1aChangedValueNames)
    $lines += 'Readback after Undo (live against the saved before-state):'
    $lines += $readback.Lines
    try {
        $stamp = (Get-Wf1aNowUtc).ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        Write-Wf1aTextFile -Path (Join-Path -Path $folder -ChildPath ('undo-result-' + $stamp + '.txt')) -Text ('restored=' + ($toRestore -join ';') + "`r`nreadback=" + $(if ($readback.Ok -and $null -eq $failure) { 'PASS' } else { 'FAIL' }) + "`r`n")
    } catch {
        $lines += ('  note: the undo result could not be written (' + $_.Exception.GetType().Name + ')')
    }
    if ($null -ne $failure) {
        $lines += ('FAILED: ' + $failure + '. Run -Undo again; report the output if it fails again.')
        Write-Wf1aReport -Lines $lines -Secrets $secrets
        return 1
    }
    if (-not $readback.Ok) {
        $lines += 'FAILED: the readback does not match the saved before-state.'
        Write-Wf1aReport -Lines $lines -Secrets $secrets
        return 1
    }
    $lines += 'UNDONE: the values are back to the saved before-state.'
    $lines += (Get-Wf1aRestartText)
    Write-Wf1aReport -Lines $lines -Secrets $secrets
    return 0
}

function Invoke-Wf1aReadback {
    param([string]$StutterGuardDataDirectory, [string]$EvidenceRoot)
    $device = Find-Wf1aDisplayAdapter
    if (-not $device.Check.Ok) {
        Write-Wf1aReport -Lines @(('CANNOT READ BACK: ' + $device.Check.Text))
        return 2
    }
    $keys = $device.Keys
    $secrets = @($keys.InstanceId)
    $rows = Get-Wf1aJournalRows -Keys $keys -StutterGuardDataDirectory $StutterGuardDataDirectory
    if (-not (Test-Wf1aRowsUsable -JournalRows $rows)) {
        $lines = @('CANNOT READ BACK: the expected state comes from the journal rows, which are not usable:')
        foreach ($c in $rows.Checks) { if (-not $c.Ok) { $lines += ('  ' + $c.Text) } }
        Write-Wf1aReport -Lines $lines -Secrets $secrets
        return 2
    }
    $expected = Get-Wf1aTargetValues -JournalRows $rows
    $readback = Get-Wf1aReadbackLines -Keys $keys -Expected $expected -Names (Get-Wf1aChangedValueNames)
    $lines = @('Readback (live against the journal rows, state before 12 Nov):') + $readback.Lines
    try {
        $live = Read-Wf1aLiveValues -Keys $keys
        foreach ($n in (Get-Wf1aWatchedValueNames)) { $lines += ('  info ' + $n + ': ' + (Format-Wf1aLiveValue -Name $n -Value $live.Values[$n]) + ' (not covered by this step)') }
    } catch {
        $lines += '  info: the watched values could not be read'
    }
    $folder = Find-Wf1aEvidenceFolder -EvidenceRoot $EvidenceRoot -Name ''
    $boot = Get-Wf1aLastBootUtc
    if ($null -ne $folder -and (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'apply-result.txt') -PathType Leaf)) {
        $applied = $null
        foreach ($line in ([System.IO.File]::ReadAllText((Join-Path -Path $folder -ChildPath 'apply-result.txt')) -split "`r`n")) {
            if ($line -match '^applied_utc=(.+)$') { $applied = [datetime]::ParseExact($Matches[1], 'yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
        }
        if ($null -ne $applied -and $null -ne $boot) {
            if ($boot -gt $applied) { $lines += ('Restart: done since Apply (last boot ' + $boot.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + 'Z, after Apply at ' + $applied.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + 'Z).') }
            else { $lines += 'Restart: NOT done since Apply. The values are in the registry, but Windows has not reconfigured the device yet. Restart by hand, then run -Readback again.' }
        }
        if (@(Get-ChildItem -LiteralPath $folder -Filter 'undo-result-*.txt' -File).Count -gt 0) {
            $lines += ('Undo ran after Apply (evidence folder ' + (Split-Path -Leaf $folder) + '): a FAIL against the journal rows is expected; the Undo output read the values back against the saved before-state.')
        }
    }
    try {
        $mech = Get-Wf1aMechanisms
        foreach ($b in $mech.Blocking) { $lines += ('  warning: ' + $b) }
        if (-not $readback.Ok -and $mech.Blocking.Count -eq 0) { $lines += '  A FAIL with no mechanism listed means something not reviewed here wrote the value: stop and report it.' }
    } catch {
        $lines += '  note: tasks, services or processes could not be listed'
    }
    if ($readback.Ok) { $lines += 'READBACK PASS' } else { $lines += 'READBACK FAIL: a value is not its state before 12 Nov. If Apply had passed, something put it back: do not re-apply in a loop, stop and report.' }
    Write-Wf1aReport -Lines $lines -Secrets $secrets
    if ($readback.Ok) { return 0 }
    return 1
}

function Invoke-Wf1aMain {
    # The entry point. Exactly one verb; none means Plan. Exit codes: 0 done
    # (Plan: ready), 1 a write or a readback failed, 2 refused or cannot
    # tell, nothing changed.
    param([string]$Verb, [string]$StutterGuardDataDirectory, [string]$EvidenceRoot, [string]$EvidenceFolder)
    Write-Wf1aReport -Lines @(('win-forensics change ' + (Get-Wf1aChangeName) + ': display adapter interrupt affinity back to its state before 12 Nov (undo order step 1a).'), ('Verb: ' + $Verb))
    switch ($Verb) {
        'Plan' {
            $plan = Invoke-Wf1aPlan -StutterGuardDataDirectory $StutterGuardDataDirectory
            $secrets = @()
            if ($null -ne $plan.Keys) { $secrets = @($plan.Keys.InstanceId) }
            $lines = @('Plan reads only and changes nothing.') + (Get-Wf1aPlanLines -Plan $plan)
            if ($plan.Ready) { $lines += 'READY: every precondition holds. Apply only on the captain''s own Yes at the PC: gpu-affinity-1a.ps1 -Apply' }
            else { $lines += ('REFUSED: ' + @($plan.Checks | Where-Object { -not $_.Ok }).Count + ' precondition(s) failed (above). Nothing would be changed.') }
            Write-Wf1aReport -Lines $lines -Secrets $secrets
            if ($plan.Ready) { return 0 }
            return 2
        }
        'Apply' { return (Invoke-Wf1aApply -StutterGuardDataDirectory $StutterGuardDataDirectory -EvidenceRoot $EvidenceRoot) }
        'Undo' { return (Invoke-Wf1aUndo -EvidenceRoot $EvidenceRoot -EvidenceFolder $EvidenceFolder) }
        'Readback' { return (Invoke-Wf1aReadback -StutterGuardDataDirectory $StutterGuardDataDirectory -EvidenceRoot $EvidenceRoot) }
        default {
            Write-Wf1aReport -Lines @('REFUSED: unknown verb. Nothing changed.')
            return 2
        }
    }
}

# ---------------------------------------------------------------------------
# Windows adapters. Everything below touches Windows and is replaced by
# changes/windows/tests/SyntheticGpuAffinity1a.ps1 in the test suite. Only
# Set-Wf1aRegistryValue and Remove-Wf1aRegistryValue change anything.
# ---------------------------------------------------------------------------

function Write-Wf1aOut {
    param([string]$Line)
    [Console]::Out.WriteLine($Line)
}

function Get-Wf1aNowUtc { return [datetime]::UtcNow }

function Test-Wf1aElevated {
    # https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Wf1aLastBootUtc {
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem (LastBootUpTime)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
        return ([datetime]$os.LastBootUpTime).ToUniversalTime()
    } catch {
        return $null
    }
}

function Get-Wf1aDisplayAdapterIds {
    # Present devices of the Display setup class, instance ids only.
    # https://learn.microsoft.com/powershell/module/pnpdevice/get-pnpdevice
    return @(Get-PnpDevice -Class Display -PresentOnly -ErrorAction Stop | ForEach-Object { [string]$_.InstanceId })
}

function ConvertFrom-Wf1aRegistryData {
    # A value read through Microsoft.Win32.RegistryKey as a model. DWORD comes
    # back as Int32, QWORD as Int64, REG_BINARY as byte[].
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.getvalue
    param([string]$Kind, $Data)
    switch ($Kind) {
        'DWord' { return (New-WfRegValueModel -Exists $true -Kind 'DWord' -Number ([uint64][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$Data), 0))) }
        'QWord' { return (New-WfRegValueModel -Exists $true -Kind 'QWord' -Number ([BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$Data), 0))) }
        'String' { return (New-WfRegValueModel -Exists $true -Kind 'String' -Text ([string]$Data)) }
        'ExpandString' { return (New-WfRegValueModel -Exists $true -Kind 'ExpandString' -Bytes ([System.Text.Encoding]::Unicode.GetBytes([string]$Data))) }
        'MultiString' { return (New-WfRegValueModel -Exists $true -Kind 'MultiString' -Bytes ([System.Text.Encoding]::Unicode.GetBytes((@($Data) -join "`n")))) }
        default {
            if ($Data -is [byte[]]) { return (New-WfRegValueModel -Exists $true -Kind $Kind -Bytes $Data) }
            return (New-WfRegValueModel -Exists $true -Kind $Kind -Bytes (New-Object byte[] 0))
        }
    }
}

function Get-Wf1aRegistryKey {
    # One key under HKLM in the 64 bit view, opened for reading: $null when
    # it does not exist, otherwise its values (name and model) and subkey
    # names. A refused or failed open throws; it is unknown, never absent.
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.openbasekey
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.opensubkey
    # The device's hardware key is opened by its Enum path here, the path
    # Stutter Guard's journal and reg.exe name; Learn directs applications to
    # the device key API instead (README, item 1a.2).
    param([string]$SubKey)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey($SubKey, $false)
        if ($null -eq $key) { return $null }
        try {
            $values = New-Object System.Collections.Generic.List[object]
            foreach ($name in $key.GetValueNames()) {
                $kind = [string]$key.GetValueKind($name)
                $data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $values.Add([pscustomobject]@{ Name = $name; Value = (ConvertFrom-Wf1aRegistryData -Kind $kind -Data $data) })
            }
            return [pscustomobject]@{ Values = $values.ToArray(); SubKeyNames = @($key.GetSubKeyNames()) }
        } finally {
            $key.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}

function Set-Wf1aRegistryValue {
    # Writes one value of an existing key; never creates a key.
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.setvalue
    param([string]$SubKey, [string]$Name, $Value)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey($SubKey, $true)
        if ($null -eq $key) { throw [System.InvalidOperationException]::new('the key does not exist') }
        try {
            switch ($Value.Kind) {
                'DWord' { $key.SetValue($Name, [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Value.Number), 0), [Microsoft.Win32.RegistryValueKind]::DWord) }
                'QWord' { $key.SetValue($Name, [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$Value.Number), 0), [Microsoft.Win32.RegistryValueKind]::QWord) }
                'Binary' { $key.SetValue($Name, [byte[]]$Value.Bytes, [Microsoft.Win32.RegistryValueKind]::Binary) }
                default { throw [System.InvalidOperationException]::new('kind ' + $Value.Kind + ' is not written by this step') }
            }
        } finally {
            $key.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}

function Remove-Wf1aRegistryValue {
    # Deletes one value of an existing key; a value already absent is fine,
    # the readback decides.
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.registrykey.deletevalue
    param([string]$SubKey, [string]$Name)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey($SubKey, $true)
        if ($null -eq $key) { throw [System.InvalidOperationException]::new('the key does not exist') }
        try {
            $key.DeleteValue($Name, $false)
        } finally {
            $key.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}

function Export-Wf1aRegistryKey {
    # reg export <key> <file> /y; returns the exit code (0 success, 1 failure).
    # https://learn.microsoft.com/windows-server/administration/windows-commands/reg-export
    param([string]$Key, [string]$File)
    $reg = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'reg.exe'
    $null = & $reg export $Key $File /y 2>&1
    return [int]$LASTEXITCODE
}

function Get-Wf1aScheduledTasks {
    # Every registered task with its folder, name, state and actions.
    # https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtask
    return @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                TaskPath = [string]$_.TaskPath
                TaskName = [string]$_.TaskName
                State    = [string]$_.State
                Actions  = @($_.Actions | ForEach-Object { [pscustomobject]@{ Execute = [string]$_.Execute; Arguments = [string]$_.Arguments } })
            }
        })
}

function Get-Wf1aServices {
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service
    return @(Get-CimInstance -ClassName Win32_Service -Property Name, PathName, State -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; PathName = [string]$_.PathName; State = [string]$_.State }
        })
}

function Get-Wf1aProcessNames {
    # Process names only.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process
    return @(Get-Process -ErrorAction Stop | ForEach-Object { [string]$_.ProcessName })
}
