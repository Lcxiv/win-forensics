# Front door checklist: letting the Mac reach the gaming PC

This sets up one narrow, read only way for the Mac to ask the gaming PC for diagnostic data over the home network. When you are done:

- The PC accepts SSH connections from the Mac's address only, and only on a network marked Private.
- The Mac signs in as a separate standard account (not an administrator, not your account) using a key, never a password.
- That account cannot open a terminal or run commands. It can only ask a small script, the dispatcher, for a fixed list of things: a health check, a named read only collector, and a finished bundle.
- Nothing is installed into, injected into, or overlaid on any game. Nothing here repairs, deletes, or clears anything on the PC.

Three actions, with the one manual step (the router) between the first two. About 15 minutes of your own time. Not counted: copying the kit to a stick and walking it over, and the minutes Windows Update needs to download the OpenSSH Server feature at the PC (usually under 10).

| Action | Where | What | Your minutes |
|---|---|---|---|
| 1 | Mac | One command: key, connection entry, and the kit | 3 |
| Router | Router page | Reserve the two addresses (manual; no script can do it) | 5 to 10 |
| 2 | PC | Double click one file on the USB stick, or the checked manual path for a kit that came any other way | 3, plus waiting |
| 3 | Mac | One command: pin the PC's identity and check everything | 2 |

Afterwards, when you have a moment: a restart test and a check from another device (5 minutes, see "Two checks for later").

## Three rules

1. Never paste, send, or type a private key or a passphrase anywhere except into the `ssh-keygen` and keychain prompts on your own Mac. Never into chat, never into a file, never onto the PC. The only key file that leaves the Mac is the one whose name ends in `.pub`, and action 1 refuses to pack anything else.
2. Close every game before action 2. The setup touches no game, but it installs a Windows feature and restarts a service, and the standing rule for this machine is that nothing of ours runs while a game is running.
3. If anything says FAIL, INCOMPLETE, or STOPPED, stop and read "If an action fails" below. Every command and the double click are safe to repeat as often as you like.

## Before you start: find the PC's address (1 minute)

On the PC: Settings, Network & internet, then your connection's properties, and read "IPv4 address". It looks like four numbers separated by dots. That is `<PC_LAN_ADDRESS>`. Wherever this checklist shows `<PC_LAN_ADDRESS>`, type your own value instead, without the angle brackets.

The Mac's own address, `<MAC_LAN_ADDRESS>`, is found by action 1 and printed. (If it cannot find it: System Settings, Network, your connection, Details, and give it with `--mac-address`.)

## Action 1. Mac: one command (3 minutes)

In Terminal, from the `win-forensics` folder:

```
sh remote-access/mac/wf-start.sh --pc-address <PC_LAN_ADDRESS>
```

What happens, in order:

- If the dedicated key does not exist yet, `ssh-keygen` creates a new Ed25519 key used for this and nothing else, in `~/.ssh/id_ed25519_winforensics`. It asks you to choose a passphrase, twice. Pick one and type it there; nothing is shown while you type. Do not leave it empty: a key without a passphrase is refused. If the key already exists it is reused and nothing is asked.
- The key is added to the macOS ssh-agent and the passphrase is stored in your keychain, so you are asked once.
- A `Host gaming-pc` entry is put at the top of `~/.ssh/config`: connect to `<PC_LAN_ADDRESS>` as `wfcollector`, use only this key, never a password, never forward anything, and refuse to connect unless the PC proves it is the PC (`StrictHostKeyChecking yes` with its own known hosts file). Your existing config is kept below it and backed up once as `~/.ssh/config.wf-backup`.
- The kit folder `wf-frontdoor` is written on your Desktop (or where `--kit` says, for example straight onto a stick: `--kit /Volumes/<stick name>/wf-frontdoor`): `SETUP-PC.cmd` (the file you double click at the PC), `Start-FrontDoorSetup.ps1` (what it runs), `wf-frontdoor-kit.zip` (the setup script, the dispatcher, any collectors, your public key, and the two values the setup needs), and `READ-ME-FIRST.txt`. There is no secret in it.

The command ends by printing two values. Write both down or photograph them. They are deliberately not in the kit: a value that travels with the file it checks would prove nothing.

- The **kit code**: 8 groups of 4 characters, digits and the letters a to f, such as `3fa9 07c2 b1e4 0d58 9c11 e7a0 5b2d 44f6`. The double click launcher asks for it (USB stick only).
- The **full SHA-256** of the zip: 8 groups of 8 characters in capitals. Windows' own `Get-FileHash` checks the zip against it on the manual path (any other way in).

## The router step: reserve the two addresses (5 to 10 minutes)

The PC will accept the key only from `<MAC_LAN_ADDRESS>`, and the Mac looks for the PC at `<PC_LAN_ADDRESS>`. Home routers hand out addresses with DHCP and may hand out different ones next week, so tell the router to always give these two machines the addresses they have now. Reserve both, not only the PC.

This is the one step no script can do: every router's page is different, and there is no common way to tell a home router to reserve an address. The general shape:

1. Open the router's page in a browser. Its address is the "Router" or "Default gateway" shown next to the addresses above, and the sign in details are often printed on the router.
2. Find the list of connected devices, or a page called DHCP, LAN, Address reservation, Static leases, or similar.
3. Find the PC and the Mac in the list (by name, or by the address you wrote down).
4. For each, choose "reserve", "always use this address", "static lease", or similar, keeping the address it already has. Save. Some routers restart.

Two settings can quietly undo a reservation, because a router recognises a device by its hardware address:

- On the Mac, if it uses Wi-Fi: System Settings, Wi-Fi, Details next to your home network, "Private Wi-Fi Address". Set it to Fixed or Off, not Rotating. A rotating address "rotates to a different private address every 2 weeks" (Apple, https://support.apple.com/en-us/102509, macOS Sequoia 15 or later), and the router would then see a new device.
- On the PC, only if it uses Wi-Fi: Settings, Network & internet, Wi-Fi, Manage known networks, your network, and turn "Random hardware addresses" off for it (Microsoft, https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc).

If your router cannot reserve addresses, carry on anyway. If an address changes later, the connection simply stops working (it fails closed). The fix is in "Housekeeping" below.

## Action 2. PC: the kit arrives and runs (3 minutes, plus waiting)

How the kit gets to the PC decides which of the two ways below you take. The double click launcher travels next to the zip, so it cannot prove it was not changed on the way. That is fine on a USB stick that stayed in your hands and not fine anywhere else, and the launcher enforces it: on anything but a removable drive it refuses before it checks, unpacks, or runs anything.

**Way A: a USB stick that stayed in your hands (the one double click).** Copy the whole `wf-frontdoor` folder to the stick (or write it there in action 1). At the PC:

1. Close any game. Open the folder on the stick and double click `SETUP-PC.cmd`. If Windows warns that the publisher is unknown or that it "protected your PC", choose More info and Run anyway: it is the launcher you just made on the Mac. Windows then asks whether the program may make changes to your device: choose Yes. A second window opens and everything else happens there.
2. Type the kit code when asked (spaces optional, capitals optional). A typo is pointed out and you get two more tries. If it says the code does not match after three tries, stop: this copy is not the kit the Mac made. Copy the folder from the Mac again.
3. The launcher then unpacks the kit into a private folder of its own, checks that the network the Mac is on is marked Private (if not, it stops and shows the exact setting and the exact command to fix it; do that, then double click again), and runs the setup script. That script works through thirteen steps, printing `ok`, a warning, or `FAILED` for each, and ends with a summary. Step S2 downloads the OpenSSH Server feature from Windows Update and can take a few minutes; the rest is quick. Appendix B says what each step does.
4. The last lines say `DONE: RESULT: PASS`, `DONE: RESULT: INCOMPLETE`, or `DONE: RESULT: FAIL`. Only PASS means done. INCOMPLETE means nothing failed but something essential could not be checked (the summary says which "not verified" line); fix what it names and double click again. FAIL means a step failed; find its row in Appendix B, fix it, and double click again. When a failed step concerns the firewall or `sshd`, the script leaves `sshd` switched off, so the PC is not reachable until you fix the step and run again.
5. Whatever the result, the launcher copies the setup script's summary, `wf-frontdoor-report.txt`, next to the zip on the stick. On PASS it also writes `pc-host-key.pub` there (the PC's public identity, not a secret) and prints the PC's host key fingerprint, a line starting with `SHA256:`. Take the stick back to the Mac. Then close the window.

**Way B: any other way (cloud folder, network share, download, a copy on the PC).** Do not double click anything; the launcher would refuse anyway. Windows itself checks the zip before any file from the kit runs:

1. Close any game. Right click the Start button and choose "Terminal (Admin)" (on some versions "Windows PowerShell (Admin)"). Say yes to the permission prompt. The prompt should start with `PS`; if not, type `powershell` and press Enter. Go to the folder holding the zip, for example `cd $HOME\Desktop\wf-frontdoor`.
2. Type this line with the 64 characters of the full SHA-256 from the Mac screen in place of the dots, without the spaces (action 1 also printed the whole line ready to type):

```
(Get-FileHash .\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '................................................................'
```

   It must print `True`. `False` means this copy is not the kit the Mac made: stop and copy it again. Nothing from the kit has run yet, and nothing will until this prints `True`.
3. Unpack it, go in, and check the network is Private:

```
Expand-Archive .\wf-frontdoor-kit.zip -DestinationPath . -Force
cd .\wf-frontdoor-kit
Get-NetConnectionProfile
```

   `NetworkCategory` for your home connection must say `Private`. If it says `Public` and this really is your own home network: Settings, Network & internet, your connection's properties, "Network profile type", Private network; or `Set-NetConnectionProfile -InterfaceIndex <number> -NetworkCategory Private` with the `InterfaceIndex` shown. Private lets other devices at home see the PC, so only do this for your own network.
4. Run the one line in `RUN-AT-PC.txt` (it is the setup script with your Mac's address filled in):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\remote-access\windows\Install-FrontDoor.ps1 -MacIpAddress <MAC_LAN_ADDRESS> -MacPublicKeyFile .\mac-public-key.pub
```

   The steps and results are the same as in way A, step 3 and 4. The summary is saved as `wf-frontdoor-report.txt` next to `Install-FrontDoor.ps1`.
5. On PASS the summary prints the host key fingerprint, a line starting with `SHA256:`. Write it down or photograph it: action 3 needs it typed, because a file coming back the same way could have been changed too.

Things you may notice afterwards:

- A new account named `wfcollector` exists. It may or may not show up on the sign in screen; Microsoft's documentation does not say. Nobody can sign in with it, because its password is random and was never shown or saved. Do not give it a password.
- The PC no longer goes to sleep on its own while plugged in. The screen can still turn off. Nothing else about power was changed.

## Action 3. Mac: one command (2 minutes)

Way A: plug the stick in and run, from the `win-forensics` folder:

```
sh remote-access/mac/wf-finish.sh
```

It reads `pc-host-key.pub` from the stick (a disk mounted under `/Volumes` that macOS reports as external and removable or ejectable). It does not read that file from anywhere else, on purpose: on the Desktop, in a cloud folder, on a network share (even one mounted under `/Volumes`), or on the Mac's own disk, whoever controls the place could have replaced it.

Way B, or a stick you no longer have: give the line from the PC screen instead:

```
sh remote-access/mac/wf-finish.sh --fingerprint SHA256:<the rest of the line from the PC>
```

What happens:

1. It asks the PC for its host key over the network and compares the fingerprint with the expected one. Only if they are identical is the key pinned: from then on the Mac refuses to talk to anything else that answers on that address. If they differ, nothing is pinned, the command ends in FAIL, and no check is sent. Never work around that. (With neither a stick nor `--fingerprint`, it stops and says so; `--by-eye` is the last resort: it shows the fingerprint it received and asks you to compare it with the PC screen yourself and type `yes`.)
2. It runs every acceptance check. Each line starts with PASS, FAIL, WARN, INFO, or TODO. A copy is saved in your home folder as `wf-frontdoor-acceptance-<time>.txt`; it holds facts about your PC and no secret, so keep it out of any repository.
3. It ends with a short list and one line: `RESULT: PASS`, `RESULT: FAIL`, or `RESULT: INCOMPLETE` (a check could not run, for example the PC did not answer; not a pass).

| Check | What it proves |
|---|---|
| A1 | The Mac will only talk to the pinned PC: strict checking is on and an Ed25519 key is pinned |
| A2 | `ping` returns the dispatcher's health report. The PC's name appears only as a hash. It also confirms the dispatcher on the PC is the same file as in your checkout |
| A3 | Anything outside the allowlist is refused rather than run: `whoami`, commands chained after `ping`, PowerShell, `cmd`, path tricks, an interactive shell, file transfer, and a forced terminal request (`-tt`), which must get neither a terminal nor a shell. A refusal that arrives with the wrong exit code (even zero) is a warning about the transport, not a failure |
| A4 | The PC refuses password sign in; it offers key sign in only |
| A5 | If the PC's identity does not match the pinned key, or no key is pinned, the connection stops before anything is sent |
| A6 | `collect-<name>` answers "unknown collector". That is the expected answer until the collectors are installed by a later kit; after that, `ping` lists them |
| A7 | A measurement, not a pass or fail of the design: what the account can see of the Windows Security log. The output records the log's access string and whether the account can read it |
| A8 | The outbox listing works. With `wf-acceptance.sh --fetch-newest` it also fetches the newest bundle and verifies its SHA-256; there is nothing to fetch until collectors exist |
| A9 | Not testable from the Mac: see "Two checks for later" |
| A10 | Only with `--after-reboot`: see "Two checks for later" |

Tell firstmate the RESULT lines from action 2 and action 3 and any FAIL or WARN line. None of that is secret.

## Two checks for later (5 minutes)

Restart test. Restart the PC and do not sign in; leave it at the sign in screen. Within 30 minutes, on the Mac:

```
sh remote-access/mac/wf-finish.sh --after-reboot
```

All checks run again, and A10 confirms from the PC's own report that it started recently and that nobody is signed in at its screen. This shows the front door comes back on its own after a restart.

Other address check (A9). The Mac cannot test that other addresses are refused, because it is the one allowed address. From any other device on your home network (another computer, or a phone with a network tool app), try to reach port 22 of `<PC_LAN_ADDRESS>`. From a computer with a terminal:

```
nc -vz -w 5 <PC_LAN_ADDRESS> 22
```

It must time out. If it connects, stop and run action 2 again. If you have no second device, rely on step S3 of the setup script, which read the firewall rules back at the PC itself.

## If an action fails

| Action | What it said | Likely reason | What to do |
|---|---|---|---|
| 1 | "give the PC's address" or "not an IPv4 address" | The option is missing or holds something that is not four numbers from 0 to 255 | Look the address up again ("Before you start") and run the command again |
| 1 | "could not detect this Mac's address" | The Mac has no default network route right now | Check Wi-Fi or Ethernet is connected, or give `--mac-address <MAC_LAN_ADDRESS>` |
| 1 | "the same" | You gave the PC's address as the Mac's, or the other way round | Check both and run again |
| 1 | "has no passphrase" | The existing key was made without one | Set one with the command it prints, then run again |
| 1 | "the kit could not be built" | The lines above it say why (usually the public key file) | Fix what they name and run again |
| 2 | Windows warns about an unknown publisher | The files were downloaded or synced through a program that marks them | On a stick: choose to run it; the kit code check comes next. Any other way: you should be on way B, not double clicking |
| 2 | "STOPPED: ... not on a removable one" | The kit folder is on the PC's own disk, a network drive, or a cloud folder, where the launcher cannot vouch for itself | Nothing was checked or changed. Either copy the folder from the Mac to a USB stick and double click it there, or take way B |
| 2 | "STOPPED: the permission prompt was declined" | No was chosen at the "make changes" prompt, or it was closed | Nothing was changed. Double click `SETUP-PC.cmd` again and choose Yes |
| 2 | "STOPPED: ... not running as Administrator" | `Start-FrontDoorSetup.ps1` was run directly | Double click `SETUP-PC.cmd` instead |
| 2 | "STOPPED: ... wf-frontdoor-kit.zip is missing" | Single files were copied, or the folder is on a network drive the administrator window cannot see | Copy the whole `wf-frontdoor` folder to a stick and double click again, or take way B |
| 2 | "The code does not match this kit" three times | A group was mistyped, or this copy of the kit is damaged or is not the one the Mac made | Nothing was unpacked or changed. Compare each group with the Mac screen; if you are sure of the code, copy the folder from the Mac again |
| 2 | "STOPPED: no staging folder could be made" | The launcher could not create its private working folder under `C:\ProgramData` (a link in the way, or the disk is full) | Nothing was unpacked or changed. The message names the folder; free space or remove the link, and double click again |
| 2 | "STOPPED: the kit could not be unpacked" or "kit-parameters.txt" | The zip is damaged, holds something it should not, or was made by another version | Nothing ran. Run action 1 again and copy the folder over again |
| 2 | "STOPPED: ... is set to Public, not Private" | Windows marks new networks Public, and the firewall rule only applies on a Private network | Nothing was changed. If this really is your own home network, mark it Private: Settings, Network & internet, your connection's properties, "Network profile type", Private network; or run the `Set-NetConnectionProfile` line the launcher printed in a Windows PowerShell window opened as Administrator. Private lets other devices at home see the PC, so only do this for your own network. Then double click again |
| 2 | "STOPPED: Windows could not look up a route" or "no network route" | The Mac's address in the kit is not reachable from this PC | Nothing was changed. Check the PC is on the home network, and that action 1 used the Mac's real address; redo action 1 if not |
| 2 | `RESULT: FAIL` with a step number | One of the thirteen setup steps failed | Find the row for that step in Appendix B, fix it, and run again. The summary is in `wf-frontdoor-report.txt` next to the zip (way A) or next to `Install-FrontDoor.ps1` (way B) |
| 2 | `RESULT: INCOMPLETE` | A step could not verify what it set up | The "not verified" line and its row in Appendix B say what to fix. Not a pass; do not go on to action 3. The report is saved as for FAIL |
| 2 | "exit code could not be read" | The launcher could not read how the setup script ended | Not a pass, whatever the summary says. Double click again; if it repeats, take way B, whose result is the setup script's own |
| 2 | "report could not be copied" or "left no report" | The stick is write protected or full, or the setup stopped before writing its summary | Photograph the summary on screen; the fingerprint, if any, is on screen too |
| 2 | "pc-host-key.pub could not be written" | The stick is write protected or full | The fingerprint is on screen: photograph it and use `--fingerprint` in action 3 |
| 3 | "INCOMPLETE  host key: no SSH answer" | PC asleep or off, wrong `<PC_LAN_ADDRESS>`, or the Mac's address is not the one given in action 1 | Wake the PC; check both addresses; if the Mac's address changed, redo actions 1 and 2 |
| 3 | "INCOMPLETE  host key: no pc-host-key.pub on any disk" | The stick is not plugged in, or the kit did not travel on one | Plug in the stick and run again, or give `--fingerprint SHA256:...` from the PC screen |
| 3 | "INCOMPLETE  host key: ... does not exist" | The `--kit` folder holds no `pc-host-key.pub` (the setup did not PASS, or the file could not be written) | Plug in the right stick, or give `--fingerprint SHA256:...` from the PC screen |
| 3 | "INCOMPLETE  host key: ... is not on a removable disk" | The file is on this Mac, in a cloud folder, on a network share (also one mounted under `/Volumes`), or on a disk macOS does not report as external and removable or ejectable; the reason in brackets says which | Give `--fingerprint SHA256:...` from the PC screen (it is also in `wf-frontdoor-report.txt`), or plug in the stick and name its folder |
| 3 | "FAIL  host key: more than one pc-host-key.pub" | Two sticks with kits are plugged in | Say which one with `--kit /Volumes/<stick name>/wf-frontdoor` |
| 3 | "FAIL  host key: NOT pinned ... DIFFER" | A typing mistake in `--fingerprint`, a stale `pc-host-key.pub` from an earlier setup, or something else is answering on that address | Read the line at the PC again (`wf-frontdoor-report.txt` has it too). Never pin a fingerprint that differs |
| 3 | "FAIL  host key: ... DIFFERENT host key is already pinned" | The PC's key changed (Windows or OpenSSH reinstalled), or the wrong PC answered | Only if you know the PC was reinstalled: compare the fingerprint at the PC again and rerun with `--replace` |
| 3 | "INCOMPLETE  acceptance: the checks did not finish" | The checks stopped before their result line (for example the report file could not be written in your home folder) | The last lines above the list say what stopped them. Fix that and run again |
| 3 | "FAIL  acceptance" | One or more checks failed; the FAIL lines above the list say which | Find the check in "If an acceptance check fails" below |

### If an acceptance check fails

| Check | Likely reason | What to do |
|---|---|---|
| A1 | No host entry or no pin | Redo action 1 or action 3 |
| A2, exit code 255, "Permission denied (publickey)" | The key in the kit is not the key the Mac uses, or the Mac's address differs from the one the PC was given | On the Mac: `ssh-add -l` should list the key. Then redo actions 1 and 2 |
| A2, exit code 255, "timed out" | PC asleep, on another network, or its address changed | See "Housekeeping" |
| A2 WARN "differs from this checkout" | The checkout changed after the kit was made | Redo actions 1 and 2 when convenient |
| A3 FAIL | The forced command is not in effect, or a terminal request got a terminal or a shell | Stop. At the PC run `Stop-Service sshd` in a Windows PowerShell window opened as Administrator, then action 2 again, and tell firstmate |
| A3 WARN "instead of 64" | The refusal arrived, but its exit code did not | Nothing to do; the answer is in the JSON. Mention it to firstmate |
| A4 FAIL | Password sign in is still offered | Redo action 2 |
| A5 FAIL | The Mac accepted an unknown host | Redo action 1 so the host entry is first in `~/.ssh/config` |
| A10 FAIL | The PC was not restarted recently, or somebody is signed in | Restart, do not sign in, and rerun within 30 minutes |

If something goes wrong in a way the tables do not cover, `Stop-Service sshd` at the PC (in a Windows PowerShell window opened as Administrator) closes the door until it is sorted out, and harms nothing. Between steps S4 and S9 the setup script keeps `sshd` stopped itself, and it stops it again whenever a firewall or `sshd` check fails, so a run that stops halfway leaves nothing listening.

## Housekeeping

- After a big Windows update, run action 2 again with the kit you have. It puts back anything the update reset, and changes nothing that is already right. The kit code and the full SHA-256 are the same as before.
- When collectors are ready, redo action 1 (new kit, new code) and action 2. The installed collectors always match the kit you ran last. Then `ping` lists them. Action 3 is only needed again if the PC's host key changed, which a Windows update does not do.
- If the Mac's address changes, redo actions 1 and 2. If the PC's address changes, redo action 1 only; nothing at the PC needs to change.
- Finished bundles wait in `C:\ProgramData\win-forensics\outbox` until fetched. The dispatcher stops collecting when 50 bundles or 2 GB are waiting there. The 2 GB also counts `outbox\.staging`, where runs that failed or timed out leave their output. To clear it, delete old folders in that directory and in `.staging` from an admin terminal at the PC. They are copies made by the collectors, not the PC's own logs.
- The sshd log is `C:\ProgramData\ssh\logs\sshd.log`. It grows slowly and is safe to delete while `sshd` is stopped.

## How to turn it all off

Each level is done at the PC in a Windows PowerShell window opened as Administrator (right click Start, "Terminal (Admin)"). Pick the smallest one that does what you want.

Pause (seconds, easy to undo). Every connection is refused while the account is disabled:

```
Disable-LocalUser -Name wfcollector
```

To confirm it took effect, `sh remote-access/mac/wf-acceptance.sh` on the Mac must now fail at A2 with "Permission denied". Undo with `Enable-LocalUser -Name wfcollector`, or by running action 2 again.

Revoke the Mac's key. Remove the key line, then restart the service:

```
Clear-Content C:\ProgramData\win-forensics\remote\authorized_keys
Restart-Service sshd
```

Undo by running action 2 again.

Remove everything:

```
Stop-Service sshd
Disable-LocalUser -Name wfcollector
Remove-NetFirewallRule -Name win-forensics-ssh-in
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Remove-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue
Remove-LocalUser -Name wfcollector
Remove-Item C:\ProgramData\win-forensics -Recurse
```

Notes on removing everything:

- `Remove-WindowsCapability` only applies if this setup installed OpenSSH Server. `C:\ProgramData\win-forensics\remote\install-state.json` records that (`capability_installed_by_this_script`), so read it before the last line deletes it. If OpenSSH Server was there before, keep it and put its original settings back instead: copy `C:\ProgramData\ssh\sshd_config.wf-original` over `sshd_config` and run `Restart-Service sshd`.
- Microsoft's uninstall steps add: "If the service was in use when you uninstalled it, you should restart Windows."
- The last line also deletes any bundles you have not fetched.
- The PC's sleep setting stays at never. Change it back in Settings, System, Power if you want.
- Host keys and the log stay in `C:\ProgramData\ssh`, and an empty profile folder `C:\Users\wfcollector` may remain. Both are harmless and can be deleted. The launcher's staging folders under `C:\ProgramData` (named `win-forensics-kit-` and 32 characters) are removed by the launcher itself; one left by a crash is safe to delete.

On the Mac, delete the block between the two `win-forensics front door` marker lines in `~/.ssh/config`, delete `~/.ssh/known_hosts_winforensics`, and run `ssh-add -d ~/.ssh/id_ed25519_winforensics`. Delete the two key files if you will not use them again. Delete the `wf-frontdoor` folder from the Desktop and the stick.

## Appendix A. The same thing, one script at a time

Every script the three actions run can be run on its own. This is the long way, for troubleshooting, for anyone who prefers typing, and, from L3 on, the mandatory path for a kit that did not travel on a USB stick (action 2, way B). Each script says what it does with `--help`. The step ids here (L1 to L8) are not the acceptance check ids (A1 to A10) of action 3.

| Step | Where | Command | Replaces |
|---|---|---|---|
| L1 | Mac | `sh remote-access/mac/wf-mac-setup.sh --pc-address <PC_LAN_ADDRESS>` | The key and `~/.ssh/config` part of action 1. Ends by printing the public key's fingerprint and the Mac's address |
| L2 | Mac | `sh remote-access/mac/wf-make-kit.sh --mac-address <MAC_LAN_ADDRESS>` | The kit part of action 1. Writes `wf-frontdoor-kit.zip` to the Desktop and prints the kit code, the full SHA-256 as eight groups of eight, and the exact `Get-FileHash` line for L3 |
| L3 | PC | In "Terminal (Admin)", in the folder holding the zip: `(Get-FileHash .\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '<the 64 characters from the Mac screen>'` | The kit check, done by Windows itself against the value you carry, before any file from the kit runs. It must print `True`. This is the only check that does not trust anything that travelled with the kit |
| L4 | PC | `Expand-Archive .\wf-frontdoor-kit.zip -DestinationPath . -Force` then `cd .\wf-frontdoor-kit` | The unpacking the launcher does (the launcher also refuses zip entries that would land outside its folder and unblocks the files; on this path the one line in L6 uses Bypass instead, once, for a zip that L3 has just checked) |
| L5 | PC | `Get-NetConnectionProfile`; if your home connection shows `Public`: `Set-NetConnectionProfile -InterfaceIndex <number> -NetworkCategory Private` | The Private check of action 2. Only do this for your own network |
| L6 | PC | The one line in `RUN-AT-PC.txt`, in the admin terminal inside the `wf-frontdoor-kit` folder: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\remote-access\windows\Install-FrontDoor.ps1 -MacIpAddress <MAC_LAN_ADDRESS> -MacPublicKeyFile .\mac-public-key.pub` | The setup script itself. On PASS the summary prints the host key fingerprint; the summary is saved as `wf-frontdoor-report.txt` next to the script |
| L7 | Mac | `sh remote-access/mac/wf-pin-host-key.sh --fingerprint SHA256:<from the PC>`, or without the option to compare by eye and type `yes` | The pinning part of action 3. Add `--replace` only when the PC's key really changed and you compared again |
| L8 | Mac | `sh remote-access/mac/wf-acceptance.sh` (`--after-reboot` for the restart test, `--fetch-newest` to also fetch a bundle) | The checks part of action 3 |

The line from the setup script's summary that begins `SHA256:` is the host key fingerprint; it is public, not a secret.

## Appendix B. The setup script's thirteen steps, and what to do when one fails

The setup script `Install-FrontDoor.ps1` (run by the launcher in action 2 way A, or by hand in way B and Appendix A) does this:

| Step | What it does | What "ok" means |
|---|---|---|
| S1 | Checks before changing anything: administrator, Windows PowerShell 5.1, a valid address and public key, the network is Private, the firewall is on | Nothing was changed yet, and nothing will be unless these hold |
| S2 | Installs the OpenSSH Server feature if it is missing | The `sshd` service exists |
| S3 | Creates one firewall rule: SSH from `<MAC_LAN_ADDRESS>` only, Private networks only. Then looks at every enabled inbound allow rule on the PC and disables each one that would let SSH in from anywhere else, whatever it is called (the install creates one that is open to everyone) | Read back from the firewall: no other rule lets SSH in. If a rule cannot be disabled, the script stops with `sshd` switched off |
| S4 | Starts `sshd` once so it creates its identity key and its default settings file, then stops it again. Nothing listens until step S9 | Host key and settings file exist, `sshd` is stopped |
| S5 | Makes sure `sshd` hands the forced command to `cmd.exe` | The default shell setting is absent or names `cmd.exe` |
| S6 | Creates the standard account `wfcollector`, adds it to Event Log Readers, and checks every group on the PC: the account must be in that one group and no other | Enabled, not an administrator, in no unexpected group, password never expires |
| S7 | Copies the dispatcher and collectors to `C:\ProgramData\win-forensics` and locks the folders | Only Administrators and SYSTEM can change what the account runs |
| S8 | Installs your Mac's public key, limited to the dispatcher and to the Mac's address | One key line, read back exactly, with strict permissions |
| S9 | Edits `sshd_config`: keys only, only this account may connect, forced command, file logging. Validates before applying, restores the old file if validation fails, asks `sshd` what now applies to the account, and only then starts `sshd` and sets it to start with Windows | `sshd` itself confirms the settings, is running, and starts with Windows |
| S10 | Sets "sleep when plugged in" to never | Read back as never |
| S11 | Reads the Security log's access settings, for the record | Shown, nothing changed |
| S12 | Shows the PC's host key fingerprint | The launcher copies the key into the kit folder; by hand, you copy the line |
| S13 | Self test: connects to the PC from the PC itself as `wfcollector` with a throwaway key, asks for the health check, asks for `whoami`, asks for a terminal, then removes the throwaway key | The health check came back, `whoami` was refused, and the terminal request got neither a terminal nor a shell |

### If a step fails

The summary names the step. Find its row. After fixing, double click `SETUP-PC.cmd` again (way A) or rerun the command from L6 (way B).

| Step | Likely reason | What to do |
|---|---|---|
| S1 | "not running as Administrator" | Close the window. Double click `SETUP-PC.cmd` and choose Yes at the prompt (by hand: right click Start, "Terminal (Admin)") |
| S1 | "must run in Windows PowerShell 5.1" | The launcher always uses it. By hand, use the exact line from `RUN-AT-PC.txt`; it starts with `powershell.exe` |
| S1 | "is set to Public, not Private" | See the "not Private" row under "If an action fails", then run again |
| S1 | "Windows Firewall is turned off" | Turn it on in Windows Security, Firewall & network protection. If another security product manages the firewall, stop and ask firstmate |
| S1 | "that is a hardware (MAC) address" or "not an IPv4 address" | The Mac's address in the kit is wrong; redo action 1 with `--mac-address` and the four numbers from System Settings |
| S1 | "this PC's own address" | The kit holds the PC's address as the Mac's. Redo action 1 |
| S1 | "PRIVATE key" | The wrong file reached the PC. Delete that copy everywhere except the Mac, make a new key on the Mac (delete the two key files, redo action 1), and redo action 2. Tell firstmate |
| S1 | "no network route" | The address is wrong or the Mac is on another network (guest Wi-Fi, for example) |
| S2 | The feature will not install | The PC needs internet access to Windows Update. Check Settings, Windows Update works, restart, and run again. If Windows asks for a restart, restart and run again |
| S3 | "cannot be limited to the Mac", "still admit inbound SSH", or "not as intended" | The script switched `sshd` off before stopping. The message names the rule. If it is a rule you or a program added, disable it in Windows Security, Firewall & network protection, Advanced settings, and run again. If it says the rule comes from policy, this PC is managed in a way this setup does not handle: stop and ask firstmate. Send `wf-frontdoor-report.txt` either way |
| S4 | `sshd` did not create its key or settings, or would not stop | Restart the PC and run again. `sshd` is left stopped, so nothing is reachable meanwhile |
| S5 | Cannot remove the default shell value | Send the report |
| S6 | "already exists and was not created by this script" | Another account has that name. Redo action 1 with `--account wfcollector2` (the kit then carries that name), copy the new kit over, and run again |
| S6 | "is a member of Administrators" | Somebody added it to that group. Remove it from Administrators and run again |
| S6 | "does not match the group baseline" naming another group | The account, or a well known name such as Everyone or Authenticated Users, is in a group the design does not allow. The message names the group by its SID. Open Computer Management, Local Users and Groups, Groups, find the group whose properties show that SID (or run `Get-LocalGroup` and look for it), remove the entry the message names, and run again. Do not add the account anywhere |
| S6 | "could not be enumerated" or "Failed to compare" | Windows could not list one group's members (a group holding an entry for a deleted account does this). Send the report. The setup will not continue on a partial list |
| S7 | "unsafe permissions" | Send the report. Run `Stop-Service sshd` meanwhile |
| S8 | Key line or permissions wrong | Run again. If it repeats, send the report |
| S9 | "sshd rejected the new configuration" | Your old `sshd_config` is untouched, and `sshd` is still stopped. Send the report, which holds sshd's message |
| S9 | "effective sshd configuration ... is not as intended" | Something else in `sshd_config` overrides the settings. `sshd` was not started. Send the report |
| S9 | "did not start" | The previous settings file was put back and `sshd` is left stopped. Restart the PC, run again, and send the report if it repeats |
| S9 | INCOMPLETE, "sshd -T did not report" | `sshd` could not print what applies to the account, so that check did not run. `sshd` is running with the new settings, but the run is not a pass. Send the report; S13's result says whether the door works |
| S10 | Sleep timeout not zero, or INCOMPLETE "could not be read back" | Set "When plugged in, put my device to sleep after" to Never in Settings, System, Power, and run again |
| S11 | A warning only | Nothing to do |
| S12 | No Ed25519 host key | Restart the PC and run again |
| S13 | INCOMPLETE, "ssh.exe or ssh-keygen.exe was not found" or "skipped" | The self test could not run, so nothing proved the door works. Install the OpenSSH Client feature (Settings, System, Optional features) and run again |
| S13 | "did not return the health JSON" with "Permission denied" | The report holds ssh's message, the last lines of the sshd log, and the two user rights `SeNetworkLogonRight` and `SeDenyNetworkLogonRight` as lists of SIDs, with the account's own SID. Windows allows a network sign in (which is what a key sign in is) only to accounts covered by the first and not named in the second. By default the first holds Everyone (S-1-1-0), Users (S-1-5-32-545), Administrators, and Backup Operators, and the second holds only Guest. If the account is not covered, or is named in the deny list, a security setting on this PC changed them. To inspect and repair: on Windows Pro, open `secpol.msc`, Local Policies, User Rights Assignment, and edit "Access this computer from the network" (add the `wfcollector` account itself) and "Deny access to this computer from the network" (remove anything covering it). On Windows Home, which has no `secpol.msc`, run `secedit /export /cfg $env:TEMP\rights.inf /areas USER_RIGHTS` to see the lines, and send the report; do not add the account to any group as a workaround. Otherwise, if the rights look normal, send the report |
| S13 | "did not return the health JSON" without "Permission denied" | The report holds ssh's message and the last lines of the sshd log. Send it. The throwaway key is already removed |
| S13 | "was NOT refused" | Stop. Run `Stop-Service sshd` and send the report. This must not happen |
| S13 | "granted a terminal" | The setting that refuses terminals is not in effect on this build. Stop. Run `Stop-Service sshd` and send the report |

"Send the report" means `wf-frontdoor-report.txt`: the launcher puts it in the kit folder next to the zip whatever the result; by hand it is saved next to `Install-FrontDoor.ps1`. It holds no secret.

### What the checks settle that documentation could not

Some behaviour could not be tested before you ran this, because no Windows machine was available to the builder, and Microsoft's documentation is silent or thin on it. Each has a check that you just ran, and a fallback.

| Question | Settled by | If it turns out wrong |
|---|---|---|
| Does Windows report the USB stick as a removable drive, so the launcher agrees to run from it? (Some USB hard disks and some enclosures report as fixed, and the launcher refuses those on purpose) | Action 2, way A, its first line after the header | It says "not on a removable one". Take way B, or use a plain USB flash stick |
| Does double clicking a `.cmd` on a USB stick start Windows PowerShell with its own folder, and does `-Verb RunAs` show the permission prompt and start the elevated copy with the paths intact (spaces included)? | Action 2 reaching the kit code question in a new window | Take way B |
| Does declining the permission prompt produce the plain "STOPPED" message rather than an error page? | Choose No once, if you like | Cosmetic; way B's result is the setup script's own |
| Can the elevated launcher create its private staging folder under `C:\ProgramData` with the access list it asks for, and is nothing on that path a link? | Action 2 reaching "[2] ... ok: unpacked" | It says "no staging folder could be made"; take way B |
| Are files unpacked from a zip that carried the "downloaded from the internet" mark accepted after the launcher unblocks them, so RemoteSigned runs the setup script? | Action 2 reaching step S1 | The launcher shows "not digitally signed". Take way B, whose one line uses Bypass |
| Does the elevated launcher see the kit folder on the stick, can it write `pc-host-key.pub` and the report there, and can it read the setup script's exit code? | Action 2, its last lines | It says it could not write, or that the exit code could not be read; use `--fingerprint` in action 3, or take way B |
| Does key sign in work for an account that has never signed in and has no profile folder? The key file is deliberately kept under `C:\ProgramData`, not in a profile, for this reason | S13 and A2 | S13 fails with "Permission denied". Send `wf-frontdoor-report.txt`; the last lines of the sshd log are in it |
| Can the account start Windows PowerShell without being added to the Users group? It should: Windows puts every signed in account into Users through "Authenticated Users", and the setup checks that this is the only group the account gets beyond Event Log Readers | S13 and A2 | S13 fails and the log mentions access denied. Do not add the account to any group; send the report |
| Is the account allowed to sign in over the network at all? Windows grants that through the user right "Access this computer from the network", normally held by Everyone and Users, and refuses it to anyone named under "Deny access to this computer from the network" | S13 | S13 fails with "Permission denied" and prints both rights. Follow row S13 in "If a step fails" |
| Does `PermitTTY no` really refuse a terminal on this Windows build? | S13 and A3 (the `-tt` checks) | S13 or A3 fails with "granted a terminal" or "reached a shell". Stop, run `Stop-Service sshd` at the PC, and report it |
| Do the dispatcher's exit codes reach the Mac? | S13 and A3 (a WARN, not a FAIL) | Nothing to do; the answer is also in the JSON |
| Does `sshd -T` print the effective settings on Windows? | S9 (a warning if not) | S13 is the check that counts |
| Does the firewall read its rule back in the form the script expects? | S3 | S3 fails although the rule is right. Send the report |
| Does the account's list of collectors arrive as a proper list from Windows PowerShell 5.1? | A2 and A6 lines | Report the `ping` line |
| What can the account read of the Security log? | S11 and A7 | This is a measurement. The answer decides a later step, not this one |
