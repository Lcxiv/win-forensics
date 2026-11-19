# Changes to the gaming PC

Everything else in this repository reads the PC. This directory holds the few scripts that change it, one self contained script per change, each run only by the captain at the PC with a verb named explicitly. Nothing the SSH dispatcher, the scenario runner or a collector does calls a script here, and no file under `collectors/`, `remote-access/` or `scripts/` names this directory (`tests/test_changes_area.py` checks it). An agent never runs a change script against the PC; it may print the command for the captain.

## The rules every change script follows

The shape is the dump change's: save, check the preconditions, apply, read back, and a separate undo.

- Four verbs, exactly one per run, as switches: `-Plan` (the default when none is named, read only) prints the current state, exactly what would change, and every precondition with PASS or FAIL, and refuses with the reason when one fails; `-Apply` saves, checks, applies and reads back; `-Undo` restores the saved before state; `-Readback` is read only and compares the live state with the expected one. Only `-Apply` and `-Undo` change anything, and neither prompts.
- Save before change, and refuse without it: `-Apply` first writes a time stamped evidence folder under `<Desktop>\latency-evidence\` with the values as a CSV and its SHA-256 beside it, plus any export; when any of that fails it refuses and changes nothing.
- `-Undo` restores exactly what was saved: a value that was absent is removed again, and nothing else is touched. It takes the newest saved before state whose hash still matches, and it refuses when the live state is not the one `-Apply` left.
- Every `-Apply` and `-Undo` ends with a readback, PASS or FAIL per value. Exit codes: 0 every value PASS, 1 a change or a readback failed, 2 refused before anything changed.
- No game handle, injection or overlay; no installs or downloads; no persistent elevation (no elevated task, no service). Where a change needs an administrator, the captain runs it elevated by hand.
- Windows PowerShell 5.1, plain ASCII, nothing written with a byte order mark. Every Windows fact cites Microsoft Learn; what Learn does not state is on this file's "Facts to verify on the PC".
- Output and saved files carry no user name, SID, profile path (`<profile>`), command line argument or address.
- The Windows adapters sit at the bottom of each script and are replaced in the tests by a synthetic backend under `tests/`; nothing in the tests touches a real registry, task store or Desktop.

## `session-bracket-task.ps1`

Registers, reads back and removes the per user logon task that starts the read only `session-bracket` collector's baseline (`collectors/windows/README.md`, "The session-bracket sources"), so a play session never depends on anyone announcing it first. Run it from a normal Windows PowerShell window, not "Run as administrator", in the repository checkout the task should use:

```
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\changes\windows\session-bracket-task.ps1            # -Plan
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\changes\windows\session-bracket-task.ps1 -Apply
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\changes\windows\session-bracket-task.ps1 -Readback
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\changes\windows\session-bracket-task.ps1 -Undo
```

The task, in the root folder of the Task Scheduler library:

| Field | Value |
|---|---|
| Name | `win-forensics-session-bracket-baseline` |
| Trigger | At logon of the account that ran `-Apply`, nobody else |
| Principal | That account, logon type Interactive (no password stored), run level Limited |
| Action | `<System32>\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "<repository>\collectors\windows\session-bracket.ps1" -Phase baseline -ToEvidenceFolder` |
| Settings | Stop after 10 minutes; a second start while one runs is ignored |
| Description | Names the undo command |

Why it can carry no more than the account's standard token: Microsoft documents that a user who is not an administrator may register a task for their own account with the interactive logon type and no password, that from a process that is not elevated only the low run level (LUA, Limited) can be registered, and that members of Users can read, change, delete and run only the tasks they created ([Security Contexts for Tasks](https://learn.microsoft.com/windows/win32/taskschd/security-contexts-for-running-tasks)). The same page says the run level is ignored for the built in Administrator account and when UAC is turned off, so the task would then run elevated; the preconditions refuse both.

Preconditions, each printed by `-Plan` and checked again by `-Apply`:

| Check | Why |
|---|---|
| `not_elevated` | `WindowsPrincipal.IsInRole(Administrator)` is false until the process is elevated under UAC ([IsInRole](https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole)); an elevated shell is refused so nothing elevated is registered. |
| `not_builtin_administrator` | The built in Administrator has RID 500 (same page); its tasks ignore the run level. |
| `uac_on` | `EnableLUA` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` is 1 ([UAC settings](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration)); 0, absent or unreadable is refused. |
| `task_absent` | `-Apply` registers a new task only; an existing one is read with `-Readback` and removed with `-Undo`. A task list that cannot be read is refused. |
| `collector_present`, `helper_present`, `powershell_present` | The files the task runs exist. |
| `path_quotable` | The collector path holds no double quote, so it passes quoted to `-File`. |
| `collector_not_blocked`, `helper_not_blocked` | No `Zone.Identifier` stream: `RemoteSigned` refuses a script downloaded from the internet until `Unblock-File` removes the stream ([about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies), [Unblock-File](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/unblock-file)). A stream that cannot be listed is refused. |
| `execution_policy_machinepolicy`, `execution_policy_userpolicy` | Group Policy scopes override `-ExecutionPolicy` on the command line (same page); `Restricted` or `AllSigned` there would stop the unsigned collector, so they are refused. |
| `desktop_resolved` | The evidence folder is `Environment.SpecialFolder.DesktopDirectory` ([SpecialFolder](https://learn.microsoft.com/dotnet/api/system.environment.specialfolder)), never a hard coded profile path. |

What `-Apply` saves, in `<Desktop>\latency-evidence\session-bracket-task-<UTC>\`, each file with its `.sha256`: `before.csv` (the task absent), `collector-hashes.csv` (the SHA-256 of the collector and `_common.ps1` it registers), `apply-started.txt`, then `after.csv` and `task-after.xml` (the `Export-ScheduledTask` XML with the account written `<user>`, its SID `<sid>`, the profile `<profile>`). `-Undo` saves `undo-before-<UTC>.csv` before it removes anything, removes the task only when its definition is the expected one or the one saved in `after.csv` (so a partial `-Apply` can be undone), and never touches a task with this name that changed since. `-Readback` also prints the last run time and result (`0` the collector exited 0, `1` its bundle failed, `0x41303` not yet run, `0x41301` running: [Task Scheduler error and success constants](https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-error-and-success-constants)) and whether the collector or the helper changed since `-Apply`.

The cmdlets: [Register-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/register-scheduledtask), [New-ScheduledTaskPrincipal](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal), [New-ScheduledTaskTrigger](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasktrigger), [New-ScheduledTaskSettingsSet](https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasksettingsset), [Unregister-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/unregister-scheduledtask), [Export-ScheduledTask](https://learn.microsoft.com/powershell/module/scheduledtasks/export-scheduledtask), [Get-ScheduledTaskInfo](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtaskinfo).

### If a game starts at logon

The task does not wait for anything: Microsoft documents that logon tasks also run when the Task Scheduler service starts and enumerates the users already logged on ([LogonTrigger](https://learn.microsoft.com/windows/win32/taskschd/logontrigger)), so the baseline can start after a launcher has already started a game. The collector's first source is its game guard: it reads the `Name` of each process from `Win32_Process`, compares them with the game names, and when a game is running reads nothing else and writes a `partial` bundle that says so. It never opens, injects into, overlays, suspends or reprioritises a process. The after read then subtracts against the newest earlier baseline of the same boot, or says there is none. Whether the WMI provider opens process handles to fill `Name` is not documented (collectors README item 92).

## Facts to verify on the PC

| # | Unverified | How to check at the PC | If it fails |
|---|---|---|---|
| T1 | `powershell.exe -WindowStyle Hidden` started by Task Scheduler at logon shows no window, or only a brief flash, over a full screen game. | Watch the Desktop at a logon after `-Apply`. | Accept the flash at logon (no game is in front yet), or start through a launcher the captain approves. |
| T2 | Task Scheduler reports the trigger and principal user as `COMPUTER\name` or as `name`; the change script compares the part after the last backslash, ignoring case. | `session-bracket-task.ps1 -Readback` after `-Apply` shows PASS for `trigger_user` and `principal_user`. | Adjust `Get-SbtComparable` to the reported form. |
| T3 | `Get-ScheduledTask` returns `Settings.ExecutionTimeLimit` as `PT10M` and `Triggers[0].CimClass.CimClassName` as `MSFT_TaskLogonTrigger` for the task as registered. | `-Readback` PASS for `execution_time_limit` and `trigger`. | Normalize the reported spelling in `Get-SbtLiveTask`. |
| T4 | `LastTaskResult` after a baseline run is 0, or 1 when the collector's bundle failed, and 0x41303 before the first run (Task Scheduler constants). | `-Readback` after the next logon. | Read the result text the readback prints; the evidence folder still holds the bundle and its summary. |
| T5 | A standard account reads `EnableLUA` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. | `-Plan` shows PASS for `uac_on`. | The plan refuses with the reason; the captain checks UAC in Control Panel and the precondition is reworded. |

## Testing

```
pytest tests/test_changes_area.py
```

It checks that no reader names this directory, that every script is plain ASCII with the four verbs and an entry here, and that the logon task registers only the low run level with the interactive logon type. With `pwsh` (`scripts/fetch_pwsh.sh`, or `WF_PWSH` and `WF_PSMODULES`) it runs `tests/Invoke-Checks.ps1`: PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility rules, and the Pester suite, which runs every verb against `tests/SessionBracketTaskBackend.ps1`: each refused precondition, a save that fails, a register call that fails after leaving a partial task, a readback that differs, undo after a partial apply, undo refused for a changed task or a tampered saved state, an unregister that fails, and the privacy rule. Without `pwsh` that test is skipped, so run it before claiming the scripts pass.
