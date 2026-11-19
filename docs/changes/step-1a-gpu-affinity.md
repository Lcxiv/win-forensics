# Step 1a: graphics card interrupt affinity back to its state before 12 November

This page is for the person at the PC. It covers when to run step 1a of the undo order, the exact sequence, what to write in the play log, and when to move on. The script is `changes/windows/gpu-affinity-1a.ps1`; its checks, sources and the facts still to verify are in [changes/windows/README.md](../../changes/windows/README.md).

What the step does: on 12 November Stutter Guard pinned the graphics card's interrupts to CPU 8 by writing two values, `DevicePolicy` and `AssignmentSetOverride`, under the card's `Interrupt Management\Affinity Policy` key; on 17 November Process Lasso's Interrupt Affinity Policy tool pinned them to CPU 6. Step 1a puts both values back to what Stutter Guard's journal recorded before its change. The journal says they were not set, so the expected result is that both values are deleted and Windows uses its default policy, which is what Microsoft recommends where it applies ([Interrupt affinity and priority](https://learn.microsoft.com/windows-hardware/drivers/kernel/interrupt-affinity-and-priority)). Nothing else changes: `DevicePriority` stays, and the MSI limit is step 1b.

## When to run

- Only after step 0: the baseline of 10 hours of play at TdrLevel 3 over at least 3 days, or until 3 episodes, whichever came first, has set the episode rate r0, and at least one episode happened.
- Only on the captain's own Yes for step 1a, given for this step. A Yes for another step does not carry over.
- With the game, its launcher, Stutter Guard and Process Lasso's Interrupt Affinity Policy tool (and LatencyTest) closed.
- Never together with another step. One change at a time.

## The sequence

The commands run in Windows PowerShell 5.1 at the PC, from a checkout of a pinned commit of this repository (record the full commit ID). Plan and Readback can run in a normal console; Apply and Undo need "Run as administrator".

1. **Plan.** `.\changes\windows\gpu-affinity-1a.ps1` (or `-Plan`). Run it elevated for the complete scheduled task listing. It prints the current values, every precondition with PASS or FAIL, what would change, and the restart note, and ends with READY or REFUSED. On REFUSED, stop and report the output; nothing changed. The expected change is `DevicePolicy` and `AssignmentSetOverride` (CPU 6) to "delete the value".
2. **The captain's Yes,** given after reading that Plan output.
3. **Apply.** In an elevated console, `.\changes\windows\gpu-affinity-1a.ps1 -Apply`. It runs Plan again, saves the before-state to `%ProgramData%\win-forensics\changes\gpu-affinity-1a\<UTC time>` (refusing if any export fails), writes `DevicePolicy` first and then `AssignmentSetOverride`, and reads both back. It ends with APPLIED and PASS per value. On FAILED it says not to restart: run `-Undo` at once and report.
4. **Restart** Windows by hand. The new values reach the driver only when the device is configured again ([IRP_MN_FILTER_RESOURCE_REQUIREMENTS](https://learn.microsoft.com/windows-hardware/drivers/kernel/irp-mn-filter-resource-requirements)); the script never restarts anything.
5. **Readback.** `.\changes\windows\gpu-affinity-1a.ps1 -Readback` after the restart. It prints PASS or FAIL per value, "Restart: done since Apply", and any mechanism that could write the values. READBACK PASS starts the play window. READBACK FAIL after a passing Apply means something put a value back: stop and report; do not apply again in a loop.

Also read back, as for every step, TdrLevel and the Process Lasso rules, and keep TdrLevel 3, CrashDumpEnabled 7, LogEvent 1 and the five WER values unchanged throughout.

**To go back** to today's state (CPU 6) at any time: elevated `.\changes\windows\gpu-affinity-1a.ps1 -Undo`, then restart, then `-Readback`, which then reads FAIL against the journal rows and says Undo ran after Apply, as expected after an undo; the Undo output itself shows PASS against the saved state. Undo uses the newest complete evidence folder, or the one named with `-EvidenceFolder <yyyyMMddTHHmmssZ>`, checks its hashes, and refuses if a value is neither what was saved nor what Apply wrote.

Do not use Stutter Guard's "heal" button, `undo-all.ps1` or a session `undo.ps1`, a `.reg` import, or Bitsum's Restore All, Reset Configuration or uninstall during this step: each would change more than this one step, and the heal button would pin the card to CPU 8 again.

## Play log

One entry per play session, kept by the captain or the PC session:

- the date, start and end time (local), and the session length;
- the step (1a), the commit ID, and the evidence folder name from Apply;
- the Readback result after the restart (READBACK PASS or FAIL, and the restart line);
- TdrLevel as read back;
- each episode: its time and kind (hard freeze, a WATCHDOG or video live kernel report, a graphics driver or Display 4101 event, or a crash to desktop with a black screen), and its code when there is one;
- if stutter is being judged too, which of the matched sessions this is;
- anything else that changed on the PC that day (a driver or Windows update, a new program), which ends the window as a separate change would.

## Advance criteria

From the report's undo order:

- **Play hours:** T = 3/r0 hours (about 5 hours at the step 0 rate), over at least 3 sessions on different days. Add 3 matched sessions if stutter is also being judged.
- **An episode** with the affinity verified at default (READBACK PASS after the restart) ends the window: preserve the artifacts, read the code, and move to step 1b with the evidence kept. Step 1a stays applied unless the captain decides otherwise.
- **No episode in T:** keep the change and extend toward 15 hours before any further step.
- **Any FAIL** in a readback ends the window too: a value that came back is itself a finding.

## Follow-up

Not part of this step, each for its own decision:

- If Plan names a scheduled task, service or running program that could put the values back, disabling or removing it is a separate change with its own Plan, Yes and saved undo. This script refuses until it is dealt with and never disables anything itself.
- Step 1b (the graphics card's MSI limit) and step 4a (the network adapter's affinity) reuse the journal reader `_stutter-guard-journal.ps1` with their own targets.
- The facts in the README's list (`1a.1` to `1a.9`) are confirmed or corrected from the first real Plan output, with the date and "reported, not reproduced".
