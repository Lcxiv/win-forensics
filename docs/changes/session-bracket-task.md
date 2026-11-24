# Session bracket logon task: start the baseline read at logon

This page is for the person at the PC. It covers what the logon task change does, when to run it, the exact sequence, what happens when a game starts at logon, and what to record. The script is `changes/windows/session-bracket-task.ps1`; the task definition, every precondition with its source, what each verb saves and the facts still to verify are in [changes/windows/README.md](../../changes/windows/README.md).

What the change does: it registers one scheduled task, `win-forensics-session-bracket-baseline`, for the account that runs `-Apply` and nobody else. At that account's logon the task runs the read only `session-bracket` collector's baseline read, so a play session never depends on anyone announcing it first. The task stores no password and runs with the account's standard token, never elevated. Nothing else changes: no setting, service, driver or registry value, and the script never restarts anything. What the collector reads is in `collectors/windows/README.md`, "The session-bracket sources".

## When to run

- Only on the captain's own Yes for this change, given after reading the Plan output. A Yes for another change does not carry over.
- As the account that plays, in a normal Windows PowerShell window, not "Run as administrator". The script refuses when elevated, as the built in Administrator, or with UAC off.
- With every game and launcher closed. `-Apply` and `-Undo` refuse while one runs, or when the process names cannot be read.
- From the repository checkout the task should use, at a pinned commit (record the full commit ID). The task holds the full path to the collector in that checkout, so the checkout stays where it is while the task exists.

## The sequence

The commands run in Windows PowerShell 5.1 at the PC, from the root of the checkout. Each run prints PASS or FAIL per value and never prompts.

1. **Plan.** `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\changes\windows\session-bracket-task.ps1` (or `-Plan`). It prints the task it would register, every precondition with PASS or FAIL, and ends with "every precondition passes" or REFUSED with the first failed check. On REFUSED, stop and report the output; nothing changed.
2. **The captain's Yes,** given after reading that Plan output.
3. **Apply.** The same command with `-Apply`. It checks the preconditions again, saves the before state (the task absent) to `<Desktop>\latency-evidence\session-bracket-task-<UTC>\`, registers the task, saves the after state and reads the task back. It ends with "PASS: the task is registered". On a FAIL line, run `-Readback` to see the state, then `-Undo`, and report both outputs.
4. **Readback.** The same command with `-Readback`, at any time. It prints PASS or FAIL per field of the task, the last run time and result, and whether the collector or its helper changed since Apply. Before the first logon the last result reads as not yet run.
5. **Log off and on** (or restart) when convenient. The script never does either. After the logon, a new `session-baseline-<UTC>` folder appears in `<Desktop>\latency-evidence`, and `-Readback` shows the last result.
6. **After a play session,** with the game and launcher closed, run the after read by hand: `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\collectors\windows\session-bracket.ps1 -Phase after -ToEvidenceFolder`. It subtracts against the newest baseline of the same boot and writes a `session-after-<UTC>` folder beside it. After a restart there is no baseline of that boot to subtract from until the task has run again.

**To go back** at any time, with every game and launcher closed: the same command with `-Undo`. It saves the state before the undo, removes the task only when it is still the one Apply registered, and ends with "PASS: the task is removed". A task with this name that changed since is never touched; the output says to remove it by hand in Task Scheduler if it is not wanted. The evidence folders stay on the Desktop.

## If a game starts at logon

The task does not wait for anything: Microsoft documents that logon tasks also run when the Task Scheduler service starts and enumerates the users already logged on ([LogonTrigger](https://learn.microsoft.com/windows/win32/taskschd/logontrigger)), so the baseline can start after a launcher has already started a game. The collector's first source is its game guard: it reads the `Name` of each process from `Win32_Process`, compares them with the game names, and when a game is running reads nothing else and writes a `partial` bundle that says so. It never opens, injects into, overlays, suspends or reprioritises a process. The after read then subtracts against the newest earlier baseline of the same boot, or says there is none. Whether the WMI provider opens process handles to fill `Name` is not documented (collectors README item 112).

## What to record

- The date, the full commit ID of the checkout, and the captain's Yes.
- The Plan output, the Apply output and the name of the `session-bracket-task-<UTC>` folder Apply printed.
- The Readback output after the first logon: the result per field, the last run time and the last result.
- Whether a window showed at logon, and for how long (item S1).
- Per play session: the names of the `session-baseline-<UTC>` and `session-after-<UTC>` folders, and whether the baseline was `partial` because a game was already running.
- If the task is removed: the Undo output and the date.

## Follow-up

- The facts in the README's list (`S1` to `S6`) are confirmed or corrected from the first real Plan, Apply and Readback output, with the date and "reported, not reproduced".
- A change to the collector or its helper after Apply shows as FAIL in Readback's comparison of their hashes. Moving the task to another checkout or commit is `-Undo` first, then Plan, the captain's Yes and `-Apply` from the new one, since `-Apply` registers only when no task with this name exists.
