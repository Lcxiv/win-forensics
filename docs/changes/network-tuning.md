# Network tuning: the wired adapter's idle power down restriction

This page is for the person at the PC. It covers what the network tuning script changes and why, when to run it, the exact sequence, and what to record before and after. The script is `changes/windows/network-tuning.ps1`; its checks, sources and the facts still to verify are in [changes/windows/README.md](../../changes/windows/README.md), and the verdict on every setting that tools like TCP Optimizer change is in [the research document](network-tuning-research.md).

## What it changes

One setting, `idle-restriction`: the wired Realtek adapter's `*IdleRestriction` property, shown in Device Manager as "idle power down restriction", from 0 ("No Restriction") to 1 ("Only idle when user not present").

Why: Windows can power the adapter down when it is idle, and a powered down adapter has to wake before it passes packets again (Microsoft's guideline for that wake is up to 10 ms; [NetAdapterCx power management](https://learn.microsoft.com/windows-hardware/drivers/netcx/configuring-power-management)). The value 1 allows that only when nobody is using the PC ([power keywords](https://learn.microsoft.com/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management)). The value was 1 before the Realtek driver install of 19 November, and the install reset it to 0, so this also takes one of the install's side effects out of the comparison.

What to expect: a small effect at most. Microsoft documents that the driver framework keeps the adapter powered while the connection is in use, so steady play should already keep it awake; the case is the quiet moments (menus, queues, the first packets after a pause). A clear change in felt lag from this alone would be a surprise worth writing down either way.

What it does not change: nothing in the TCP/IP stack (game traffic is UDP, and every stack setting TCP Optimizer changes is TCP only, read only on Windows 11, obsolete or already a default), no QoS or DSCP rule, no DNS, IPv6 or MTU, and none of the values already on the PC from earlier tools (they are present and harmless, and left alone). Interrupt affinity and the MSI limit are step 4a, USB power is step 4b, ExitLag is step 7.

## When to run

- After the Realtek driver install (step 4a.1) has had its own play window, as its own step. Never together with another change: a change made at the same time makes both results unreadable.
- Only on the captain's own Yes for this change, given after reading the Plan output.
- With Overwatch and Battle.net closed; the script refuses while either runs.

## The sequence

The commands run in Windows PowerShell 5.1 at the PC, from a checkout of a pinned commit of this repository (record the full commit ID). Plan and Readback run in a normal console; Apply and Undo need "Run as administrator".

1. **Record the before state** (below), with the PC as it is today.
2. **Plan.** `.\changes\windows\network-tuning.ps1` (or `-Plan`). It prints every check with ok or FAIL, the live and proposed value, the reason, the restart need and the other adapter properties, and ends with READY, NOTHING TO DO or REFUSED. On REFUSED, stop and report the output; nothing changed.
3. **The captain's Yes,** given after reading that Plan output.
4. **Apply.** In an elevated console, `.\changes\windows\network-tuning.ps1 -Apply`. It runs Plan again, saves the before-state to `%ProgramData%\win-forensics\changes\network-tuning\<UTC time>` (refusing if the save fails), writes the value with no adapter restart, and reads it back: PASS, then "Apply done". On FAIL it names what changed and the `-Undo -EvidenceFolder <time>` to run.
5. **Restart the adapter** by hand, with the game closed: Device Manager, Network adapters, the Realtek adapter, Disable device, then Enable device (the network drops for a few seconds). Restarting the PC does the same. The script never restarts anything; Microsoft notes that many advanced properties take effect only after the adapter restarts ([Set-NetAdapterAdvancedProperty](https://learn.microsoft.com/powershell/module/netadapter/set-netadapteradvancedproperty), [Restart-NetAdapter](https://learn.microsoft.com/powershell/module/netadapter/restart-netadapter)).
6. **Readback.** `.\changes\windows\network-tuning.ps1 -Readback`. PASS starts the play window. FAIL after a passing Apply means something put the value back: stop and report; do not apply again in a loop.
7. **Record the after state** over the same kind of sessions.

## Several settings and attribution

The script has one setting today. If later research adds more, `-Only <name>` applies one at a time. Applying several in one run cannot tell which one made a difference, so judge one setting per play window and add the next only after recording it. The measure first items in the research document (Green Ethernet, Power Saving Mode, Gigabit Lite, LTR/OBFF, Flow Control, and "Allow the computer to turn off this device" on the Power Management tab) are not in the script; each would be its own decision and its own step, one at a time, never together with this one.

## What to record

Before the change and again after it, in comparable sessions (same game mode, similar time of day, wired, nothing else changed that day):

- **Felt lag,** in the captain's words, per session: none, occasional, frequent; when it happens (fights, menus, after a pause).
- **The in game network graph.** Shift+Ctrl+N in Overwatch shows the minimum, average and maximum of LAT (latency), IND (interpolation delay), LOSS IN and LOSS OUT (Blizzard support, read from a search snippet only). Note them at a quiet moment and right after a lag moment, or take a screenshot.
- **Adapter statistics** before and after a session, from a normal PowerShell: `Get-NetAdapterStatistics -Name <adapter> | Format-List ReceivedDiscardedPackets, ReceivedPacketErrors, OutboundDiscardedPackets, OutboundPacketErrors` ([Get-NetAdapterStatistics](https://learn.microsoft.com/powershell/module/netadapter/get-netadapterstatistics)). Record only the counts; never paste addresses or the adapter's full listing anywhere.
- The step name, the commit ID, the evidence folder name from Apply, and the Readback result.
- Anything else that changed on the PC that day (a Windows or driver update, a new program), which ends the window as a separate change would.

## Undo

To go back at any time: elevated `.\changes\windows\network-tuning.ps1 -Undo`, then restart the adapter as in step 5. Undo uses the newest complete evidence folder, or the one named with `-EvidenceFolder <yyyyMMddTHHmmssZ>`, checks its hashes and that it was saved for this adapter, and refuses if the live value is neither what was saved nor what Apply wrote. Its own readback shows PASS against the saved value; a later `-Readback` reads FAIL, as expected after an undo, because it compares with the applied value.

Setting the value by hand in Device Manager (Advanced tab, "idle power down restriction") does the same change and the same undo, without the saved before-state; prefer the script so the record exists.
