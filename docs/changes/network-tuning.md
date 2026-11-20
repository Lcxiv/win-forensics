# Network tuning: the wired adapter's power properties

This page is for the person at the PC. It covers what the network tuning script changes and why, when to run it, the exact sequence, and what to record before and after. The script is `changes/windows/network-tuning.ps1`; its checks, sources and the facts still to verify are in [changes/windows/README.md](../../changes/windows/README.md), and the verdict on every setting that tools like TCP Optimizer change is in [the research document](network-tuning-research.md).

## What it changes

By default, one setting, `idle-restriction`: the wired Realtek adapter's `*IdleRestriction` property, shown in Device Manager as "idle power down restriction", from 0 ("No Restriction") to 1 ("Only idle when user not present").

Why: Windows can power the adapter down when it is idle, and a powered down adapter has to wake before it passes packets again (Microsoft's guideline for that wake is up to 10 ms; [NetAdapterCx power management](https://learn.microsoft.com/windows-hardware/drivers/netcx/configuring-power-management)). The value 1 allows that only when nobody is using the PC ([power keywords](https://learn.microsoft.com/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management)). The value was 1 before the Realtek driver install of 19 November, and the install reset it to 0, so this also takes one of the install's side effects out of the comparison.

What to expect: a small effect at most. Microsoft documents that the driver framework keeps the adapter powered while the connection is in use, so steady play should already keep it awake; the case is the quiet moments (menus, queues, the first packets after a pause). A clear change in felt lag from this alone would be a surprise worth writing down either way.

Opt in experiments: five more entries, `green-ethernet`, `power-saving-mode`, `gigabit-lite`, `ltr-obff` and `flow-control`, the properties the install reset (and Flow Control). None has a cited latency case either way (the research document's verdict is measure first), so none is in the default run: each runs only when named alone with `-Only`, as one experiment with the same saved before-state, Undo and Readback, and the Plan output labels it "measure first, no cited latency case". Each proposes the driver's own off value, the valid value it shows as "Disabled", read live; Plan refuses when the driver shows no such value, which today means `ltr-obff` is refused while the driver keeps it hidden.

What it does not change: nothing in the TCP/IP stack (game traffic is UDP, and every stack setting TCP Optimizer changes is TCP only, read only on Windows 11, obsolete or already a default), no QoS or DSCP rule, no DNS, IPv6 or MTU, and none of the values already on the PC from earlier tools (they are present and harmless, and left alone). Interrupt affinity and the MSI limit are step 4a, USB power is step 4b, ExitLag is step 7.

## When to run

- After the Realtek driver install (step 4a.1) has had its own play window, as its own step. Never together with another change: a change made at the same time makes both results unreadable.
- Only on the captain's own Yes for this change, given after reading the Plan output.
- With Overwatch and Battle.net closed; the script refuses while either runs.

## The sequence

The commands run in Windows PowerShell 5.1 at the PC, from a checkout of a pinned commit of this repository (record the full commit ID). Plan and Readback run in a normal console; Apply and Undo need "Run as administrator".

1. **Record the before state** (below), with the PC as it is today.
2. **Plan.** `.\changes\windows\network-tuning.ps1` (or `-Plan`); for an experiment, `.\changes\windows\network-tuning.ps1 -Only <name>`. It prints every check with ok or FAIL, the live and proposed value, the reason, the restart need and the other adapter properties, and ends with READY, NOTHING TO DO or REFUSED. On REFUSED, stop and report the output; nothing changed.
3. **The captain's Yes,** given after reading that Plan output.
4. **Apply.** In an elevated console, `.\changes\windows\network-tuning.ps1 -Apply` (for an experiment, `-Apply -Only <name>`). It runs Plan again, saves the before-state to `%ProgramData%\win-forensics\changes\network-tuning\<UTC time>` (refusing if the save fails), writes the value with no adapter restart, and reads it back: PASS, then "Apply done". On FAIL it names what changed and the `-Undo -EvidenceFolder <time>` to run.
5. **Restart the adapter** by hand, with the game closed: Device Manager, Network adapters, the Realtek adapter, Disable device, then Enable device (the network drops for a few seconds). Restarting the PC does the same. The script never restarts anything; Microsoft notes that many advanced properties take effect only after the adapter restarts ([Set-NetAdapterAdvancedProperty](https://learn.microsoft.com/powershell/module/netadapter/set-netadapteradvancedproperty), [Restart-NetAdapter](https://learn.microsoft.com/powershell/module/netadapter/restart-netadapter)).
6. **Readback.** `.\changes\windows\network-tuning.ps1 -Readback`. PASS starts the play window. FAIL after a passing Apply means something put the value back: stop and report; do not apply again in a loop.
7. **Record the after state** over the same kind of sessions.

## Experiments

The default change (`idle-restriction`) comes first, on its own, with its own play window. After that, each opt in entry is one experiment, in this order unless the captain chooses another: `green-ethernet`, `power-saving-mode`, `gigabit-lite`, `flow-control`, `ltr-obff` (the last only if a later driver shows it with a "Disabled" value). Applying several at once cannot tell which one made a difference, so the script refuses to run an experiment together with anything else.

For each experiment:

1. Plan, the captain's Yes, then `-Apply -Only <name>` in an elevated console, then restart the adapter and run `-Readback`, exactly as in the sequence above.
2. Play the matched sessions and record them (below), the same kind and number as for the session before the experiment.
3. Decide: keep it, or put it back with elevated `-Undo -EvidenceFolder <the folder this experiment's Apply printed>`, restart the adapter, and record the Undo output.
4. Only then try the next one. A kept experiment stays in place under the next; to take an older one back later, name its own evidence folder with `-Undo -EvidenceFolder`.

**Allow the computer to turn off this device** is a separate experiment by hand, because it is owned by the driver framework and has no documented way to set it from a script. Never in the same window as `idle-restriction` or another experiment.

1. With the game closed, open Device Manager (right-click Start, Device Manager).
2. Expand **Network adapters**, right-click **Realtek Gaming 2.5GbE Family Controller**, choose **Properties**, and open the **Power Management** tab.
3. **Record the before value**: whether **Allow the computer to turn off this device to save power** is checked (the 19 November transcription says it is). Also note the two wake check boxes below it, and leave them as they are.
4. Clear **Allow the computer to turn off this device to save power** and select **OK**. Device Manager sends the change to the driver when the box changes ([WMI and the Power Management tab](https://learn.microsoft.com/windows-hardware/drivers/kernel/wmi-and-the-power-management-tab)); whether it applies at once on this driver is unverified, so restart the PC before the play window.
5. Run `.\changes\windows\network-tuning.ps1` (Plan): its report line "Allow the computer to turn off this device" should now read Disabled. Write that line in the log.
6. Play and record as for any experiment. To put it back, check the box again, select **OK**, restart, and confirm the Plan line reads Enabled.

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
