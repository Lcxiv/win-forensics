# Keyboard crash dump: ending a hard freeze with a stop code

This page is for the person at the gaming PC. It covers one change, `changes/windows/kbd-crash-dump.ps1`, which lets a hard freeze be ended from the keyboard with a stop error that Windows records, instead of with the power button. A power off leaves only a Kernel-Power 41 record with no code. A keyboard initiated stop error leaves a stop code in the System log and, if the dump path works, a memory dump of what the processors and drivers were doing at that moment.

The change is applied only on the captain's own word, at the PC, by hand. Nothing in this repository runs it for him: not the collectors, not the scenario runner, not the SSH front door. The rules for change scripts are in [changes/windows/README.md](../../changes/windows/README.md).

Every Windows fact below comes from Microsoft Learn and is cited where it is used. Anything Learn does not say is marked unverified, and the things only the PC can show are on the list in [changes/windows/README.md](../../changes/windows/README.md), "Facts to verify on the PC".

## What the change is

Microsoft documents a keyboard initiated crash for USB and PS/2 keyboards ([Forcing a system crash from the keyboard][kbd]):

| Keyboard | Key | Value | Set by `-Apply` | Undo |
|---|---|---|---|---|
| USB | `HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters` | `CrashOnCtrlScroll`, REG_DWORD | 1 | the saved before-state: deleted if it was absent, its old REG_DWORD if it existed |
| PS/2 | `HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters` | `CrashOnCtrlScroll`, REG_DWORD | 1 | the same |

Both are set: Microsoft suggests both where a machine may use either driver (its example is a laptop with a PS/2 built in keyboard and an external HID keyboard), and its freeze troubleshooting guide sets both ([keyboard crash][kbd], [freeze troubleshooting][freeze]). The Hyper-V keyboard key (`hyperkbd`) is not touched; this is a physical PC. Nothing else changes: no service, no driver, no dump setting, no page file.

**It works only after a restart.** Microsoft: "You must restart the system for these settings to take effect" ([keyboard crash][kbd]). The script never restarts anything; `-Plan`, `-Apply` and `-Readback` all say so, and `-Readback` reports whether the PC has booted since the newest apply or undo that reached its writes (a refused run does not count).

A dump is written only if crash dumps are on: "If you want a crash dump file to be written, you must enable such dump files" ([keyboard crash][kbd]). `CrashDumpEnabled` 0 means no dump ([recovery options][recovery]); the script refuses when it is 0 or missing. Whether the dump fits this PC's page file is a separate question that only a stop error answers; see "What it cannot do".

## How to apply it

At the PC, with the game, its launcher and anti-cheat closed:

1. Open **Windows PowerShell** (5.1) with **Run as administrator**, signed in as the account that plays.
2. From the folder that holds the pinned commit of this repository (a checkout, or that commit's GitHub source ZIP, with the full commit ID and the ZIP's SHA-256 written in the run notes), run the plan. `-ExecutionPolicy Bypass` applies only to that one PowerShell session and is not stored ([about_Execution_Policies][execpolicy]):

   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Plan
   ```

   It changes nothing. It prints the current values, exactly what `-Apply` would change, every precondition with OK or FAIL, and ends with `READY` or `REFUSED`. On `REFUSED`, stop and send the output to firstmate.
3. Only on the captain's Yes, apply:

   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Apply
   ```

   It checks the preconditions again, then saves the before-state to a new folder `Desktop\wf-changes\kbd-crash-dump\<UTC time>-apply` (a values CSV, a `reg export` of each affected key, and `SHA256SUMS.txt`), and stops without changing anything if any of that fails. Then it writes the two values and prints `PASS` or `FAIL` for each. Exit code 0 is all `PASS`; 1 is refused with nothing changed; 2 means a write or the readback failed, and `-Undo` is the next step.
4. Make the normal restart.
5. After the restart, read it back:

   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Readback
   ```

   Expect `PASS` on both values, `Restart done: the PC booted at ..., after the newest apply at ...`, and `RESULT: PASS`.

To undo, in the same kind of window:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Undo
```

It restores the newest apply folder's before-state exactly: a value that was absent is deleted, a value that existed gets its saved REG_DWORD back, and nothing else is touched. It refuses if the saved CSV does not match its SHA-256, if the CSV names any key or value other than the documented ones, or if something other than this script changed a value since the apply. It saves the state it is about to undo to its own `<UTC time>-undo` folder first. Make a restart after it too (that the removal also waits for a restart is an inference from Microsoft's restart note, not a documented fact).

## The key sequence during a freeze

When the screen is frozen and the PC no longer responds:

**Hold down the right CTRL key, and press SCROLL LOCK twice.**

That is Microsoft's documented sequence: "Hold down the rightmost CTRL key, and press the SCROLL LOCK key two times" ([keyboard crash][kbd], [freeze troubleshooting][freeze]). It must be the right CTRL key: Microsoft names the rightmost one, and the left one is not documented for this sequence. Then take your hands off the keyboard and wait.

### If the keyboard has no SCROLL LOCK key

Microsoft documents an alternative: two REG_DWORD values under a `crashdump` subkey of each keyboard service, `Dump1Keys` (a bitmap of the first key) and `Dump2Key` (the second key's index in the driver's scan code table) ([keyboard crash][kbd], "Defining alternate keyboard shortcuts"). The script sets them behind an explicit option with its own save and undo:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Plan -AlternateKeys
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Apply -AlternateKeys
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\changes\windows\kbd-crash-dump.ps1 -Readback -AlternateKeys
```

| Key | Value | Set by `-Apply -AlternateKeys` |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\crashdump` | `Dump1Keys`, REG_DWORD | 0x02 (right CTRL), or the `-Dump1Keys` value |
| the same | `Dump2Key`, REG_DWORD | 0x3d |
| `HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\crashdump` | `Dump1Keys` and `Dump2Key` | the same two values |

The sequence is then **hold the right CTRL key and press the SPACEBAR twice**. These values are Microsoft's own example, which it describes as "holding the rightmost control key and pressing the spacebar twice"; the second key is fixed to that example because Learn names no other index's key. `-Dump1Keys` can choose another first key from Microsoft's table: 0x01 right SHIFT, 0x02 right CTRL, 0x04 right ALT, 0x10 left SHIFT, 0x20 left CTRL, 0x40 left ALT, or a combination of them, for which Microsoft writes: "You can assign `Dump1Keys` a value that enables one or more keys as the first key used in the keyboard shortcut sequence. For example, assign `Dump1Keys` a value of 0x11 to define both the rightmost and leftmost SHIFT keys as the first key in the keyboard shortcut sequence." (https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard, "Dump1Keys"). The script then prints the sequence as holding one of the enabled first keys. The `-Readback -AlternateKeys` command needs the same `-Dump1Keys` value.

Two rules from Microsoft and this script:

- "If you define alternate keyboard shortcuts ... you must either set the `CrashOnCtrlScroll` registry value to 0 or remove it from the registry" ([keyboard crash][kbd]). The script never does both at once: `-Apply -AlternateKeys` refuses while `CrashOnCtrlScroll` is 1, and the plain `-Apply` refuses while alternate values exist. To switch, run `-Undo` first.
- The spacebar is a common game key. Holding the right CTRL key while pressing the spacebar twice in a game would crash the PC at once. Prefer SCROLL LOCK when the keyboard has it; with the alternative, pick a first key the games in use never hold.

## What you should see

- Windows stops at once with a stop error screen. Microsoft: the system "calls `KeBugCheck` and issues Bug check 0xE2: MANUALLY_INITIATED_CRASH" ([keyboard crash][kbd]); 0xE2 "indicates that the user deliberately initiated a crash dump from either the kernel debugger or the keyboard" ([bug check 0xE2][e2]). Microsoft describes the stop screen for another stop code as "Your PC ran into a problem and needs to restart" with the error code on it ([NMI stop][nmi]); expect the same here with MANUALLY_INITIATED_CRASH (inference).
- "Unless crash dumps are disabled, a crash dump file is then written" ([keyboard crash][kbd]). Writing a dump of more than 2 GB "may take a long time" ([generate a dump][generate]). Do not power off while it writes. Microsoft warns, about hardware restart features, that "The restart can interrupt the dump process" ([freeze troubleshooting][freeze]); an interrupted dump is most likely lost (inference).
- With "Automatically restart" on (`AutoReboot` 1, on by default) Windows then restarts by itself ([recovery options][recovery]). `-Plan` and `-Readback` print the `AutoReboot` value. With it off, the stop error screen stays until you power off; Learn gives no sign on that screen that the dump has finished, so wait a long while before doing so (unverified how long).
- If nothing happens after the sequence, the freeze has blocked the keyboard path (see the next section). Power off as before, and say in the report that the keys were pressed and nothing happened; that is evidence too.

## After the reboot

1. Change nothing, and do not open, copy or upload the dump. A memory dump holds the contents of kernel memory at the time of the stop; the project never copies one, and later reads list only names, sizes and codes.
2. Tell firstmate, or the agent session on the PC, that a keyboard crash was used, at about what time, and whether the PC restarted by itself.
3. The main firstmate home then relays the post crash read (read only) to the PC session. It looks for:
   - a System log record from `WER-SystemErrorReporting`, event 1001, "The computer has rebooted from a bugcheck. The bugcheck was: 0x000000e2 (...). A dump was saved in: C:\Windows\MEMORY.DMP" ([unexpected reboots][reboots]);
   - Kernel-Power 41 with `BugcheckCode` 226, which is 0xE2: Event 41 "includes the bug check code in decimal format" ([Event 41][event41]);
   - the dump file's name, size and time only, at the path in `CrashControl\DumpFile` (by default `%SystemRoot%\MEMORY.DMP`, [freeze troubleshooting][freeze]).

   The `bugcheck-history` collector in `collectors/windows/` reads the same System events (41 and 1001) read only, if the PC session runs it from a pinned commit.
4. What the result means:
   - **Stop code 0xE2 and a dump file:** the keys worked and the dump path works. The stop code itself only says the keys caused the stop; what was hung is in the dump, which is read in a later, separate step, never by this change.
   - **Stop code 0xE2 and no dump file:** the stop happened but the dump was not written. Keep every record from that boot and change nothing; the page file question below is then the lead.
   - **A stop code other than 0xE2:** Windows stopped by itself before or instead of the keys; that code is the finding.
   - **No stop code (Kernel-Power 41 with `BugcheckCode` 0 and no 1001):** the keys did not get through, or the power went off before the code was written.

## What it cannot do

- **It cannot end every freeze.** Microsoft: "It's possible but rare for a system to freeze in such a way that the keyboard shortcut sequence doesn't work", and "Forcing a system crash from the keyboard doesn't work if the computer stops responding at a high interrupt request level (IRQL). This limitation exists because the Kbdhid.sys driver, which allows the memory dump process to run, operates at a lower IRQL than the i8042prt.sys driver" ([keyboard crash][kbd]). So a USB keyboard is the more limited of the two. The same page says the sequence "works even in many instances where CTRL+ALT+DELETE doesn't work".
- **Whether a GPU hang freeze responds is unverified.** Learn says nothing about the keyboard crash during a graphics hang, nor at what IRQL a hang of this kind leaves the processors. Only a freeze will show it.
- **Whether this keyboard goes through `kbdhid` is unverified.** Learn documents USB keyboards through `kbdhid` and PS/2 through `i8042prt`. A wireless receiver, a Bluetooth keyboard, or a vendor filter driver is not covered there; a SCROLL LOCK reached through an Fn layer is not covered either.
- **Whether the dump fits is unproven.** Microsoft documents that the page file must be large enough for the dump type, and the worst case for a 64-bit kernel dump as the size of RAM plus 128 MB ([recovery options][recovery]). Only a stop error proves the path on this PC.
- **It does not prevent or diagnose a freeze by itself.** It turns a power off into a stop code and, at best, a dump.
- **Pressing the sequence when nothing is frozen crashes the PC on purpose.** Microsoft: "Forcing a system crash immediately stops your system and might result in data loss" ([keyboard crash][kbd]). There is no confirmation and no undo for the crash itself.

## Follow-up: a deliberate test crash (a separate captain decision, not proposed here)

The dump path on this PC stays unproven until a stop error happens. Pressing the sequence once on purpose, with nothing frozen, would prove it end to end. That is a decision for the captain alone, and this change does not propose it.

| For | Against |
|---|---|
| Proves in minutes that the keys reach Windows through this keyboard and its driver, that a dump fits the page file and is written, and that the 1001 and Event 41 records carry 0xE2, before a real freeze depends on it. | It is a crash on purpose: everything unsaved is lost and Microsoft warns of "data loss" ([keyboard crash][kbd]). |
| A failure (no dump) points at the page file before a real freeze is lost to it, while nothing else is going on. | It adds a 0xE2 to the machine's history that every later read must label as the test. |
| | It does not show whether a real GPU hang freeze responds; only a real freeze shows that. |

## Sources

- [kbd]: Forcing a system crash from the keyboard, https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard
- [e2]: Bug check 0xE2 MANUALLY_INITIATED_CRASH, https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0xe2--manually-initiated-crash
- [freeze]: Advanced troubleshooting for Windows freezes, https://learn.microsoft.com/troubleshoot/windows-client/performance/windows-based-computer-freeze-troubleshooting
- [recovery]: Configure system failure and recovery options in Windows, https://learn.microsoft.com/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options
- [generate]: Generate a kernel or complete crash dump, https://learn.microsoft.com/troubleshoot/windows-client/performance/generate-a-kernel-or-complete-crash-dump
- [reboots]: Troubleshoot unexpected reboots using system event logs, https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
- [event41]: Advanced troubleshooting for Event ID 41, https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart
- [execpolicy]: about_Execution_Policies, https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies
- [nmi]: NMI_HARDWARE_FAILURE error when an NMI is triggered on Windows, https://learn.microsoft.com/troubleshoot/windows-client/performance/nmi-hardware-failure-error

[kbd]: https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard
[e2]: https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0xe2--manually-initiated-crash
[freeze]: https://learn.microsoft.com/troubleshoot/windows-client/performance/windows-based-computer-freeze-troubleshooting
[recovery]: https://learn.microsoft.com/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options
[generate]: https://learn.microsoft.com/troubleshoot/windows-client/performance/generate-a-kernel-or-complete-crash-dump
[reboots]: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
[event41]: https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart
[execpolicy]: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies
[nmi]: https://learn.microsoft.com/troubleshoot/windows-client/performance/nmi-hardware-failure-error
