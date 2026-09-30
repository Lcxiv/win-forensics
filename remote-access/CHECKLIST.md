# Front door checklist: letting the Mac reach the gaming PC

This sets up one narrow, read only way for the Mac to ask the gaming PC for diagnostic data over the home network. When you are done:

- The PC accepts SSH connections from the Mac's address only, and only on a network marked Private.
- The Mac signs in as a separate standard account (not an administrator, not your account) using a key, never a password.
- That account cannot open a terminal or run commands. It can only ask a small script, the dispatcher, for a fixed list of things: a health check, a named read only collector, and a finished bundle.
- Nothing is installed into, injected into, or overlaid on any game. Nothing here repairs, deletes, or clears anything on the PC.

Plan for about 45 minutes, most of it waiting. Every step says roughly how long it takes.

| Step | Where | What | Minutes |
|---|---|---|---|
| 1 | Mac | Create the key and the connection entry | 5 |
| 2 | Router | Reserve the two addresses | 10 |
| 3 | Mac | Build the kit | 2 |
| 4 | PC | Move the kit over and check it | 5 |
| 5 | PC | Check the network is Private | 2 |
| 6 | PC | Run the setup script | 10 |
| 7 | Mac | Pin the PC's host key | 3 |
| 8 | Mac | Run the acceptance checks | 3 |
| 9 | Both | Restart test, and the check from another device | 5 |

## Three rules

1. Never paste, send, or type a private key or a passphrase anywhere except into the `ssh-keygen` and keychain prompts on your own Mac. Never into chat, never into a file, never onto the PC. The only key file that leaves the Mac is the one whose name ends in `.pub`.
2. Close every game before step 6. The setup touches no game, but it installs a Windows feature and restarts a service, and the standing rule for this machine is that nothing of ours runs while a game is running.
3. If anything says FAIL, stop and read "If a step fails" below. The setup script is safe to run again as often as you like.

## Before you start: find the two addresses (2 minutes, part of step 1)

You need the address each machine has on the home network. They look like four numbers separated by dots.

- On the Mac: System Settings, Network, pick Wi-Fi or Ethernet, Details. Or in Terminal: `ipconfig getifaddr en0` (if that prints nothing, try `en1`). This is `<MAC_LAN_ADDRESS>`.
- On the PC: Settings, Network & internet, then your connection's properties, and read "IPv4 address". Or in a terminal: `ipconfig`. This is `<PC_LAN_ADDRESS>`.

Write both down. Wherever this checklist shows `<MAC_LAN_ADDRESS>` or `<PC_LAN_ADDRESS>`, type your own value instead, without the angle brackets.

## Step 1. Mac: create the key and the connection entry (5 minutes)

In Terminal, from the `win-forensics` folder:

```
sh remote-access/mac/wf-mac-setup.sh --pc-address <PC_LAN_ADDRESS>
```

What happens:

- `ssh-keygen` creates a new Ed25519 key that is used for this and nothing else, in `~/.ssh/id_ed25519_winforensics`. It asks you to choose a passphrase, twice. Pick one and type it there; nothing is shown while you type. Do not leave it empty: the script refuses a key without a passphrase.
- The key is added to the macOS ssh-agent and the passphrase is stored in your keychain, so you are asked once.
- A `Host gaming-pc` entry is put at the top of `~/.ssh/config`. It says: connect to `<PC_LAN_ADDRESS>` as `wfcollector`, use only this key, never a password, never forward anything, and refuse to connect unless the PC proves it is the PC (`StrictHostKeyChecking yes` with its own known hosts file). Your existing config is kept below it and backed up once as `~/.ssh/config.wf-backup`.

The script ends by printing the public key's fingerprint and the Mac's address. Two files now exist: `id_ed25519_winforensics` is the private key and never leaves the Mac; `id_ed25519_winforensics.pub` is the public key and is the only one that goes to the PC.

## Step 2. Router: reserve the two addresses (10 minutes)

The PC will accept the key only from `<MAC_LAN_ADDRESS>`, and the Mac looks for the PC at `<PC_LAN_ADDRESS>`. Home routers hand out addresses with DHCP and may hand out different ones next week, so tell the router to always give these two machines the addresses they have now. Reserve both, not only the PC.

Router pages all look different. The general shape:

1. Open the router's page in a browser. Its address is the "Router" or "Default gateway" shown next to the addresses you looked up above, and the sign in details are often printed on the router.
2. Find the list of connected devices, or a page called DHCP, LAN, Address reservation, Static leases, or similar.
3. Find the PC and the Mac in the list (by name, or by the address you wrote down).
4. For each, choose "reserve", "always use this address", "static lease", or similar, keeping the address it already has. Save. Some routers restart.

Two settings can quietly undo a reservation, because a router recognises a device by its hardware address:

- On the Mac, if it uses Wi-Fi: System Settings, Wi-Fi, Details next to your home network, "Private Wi-Fi Address". Set it to Fixed or Off, not Rotating. A rotating address "rotates to a different private address every 2 weeks" (Apple, https://support.apple.com/en-us/102509, macOS Sequoia 15 or later), and the router would then see a new device.
- On the PC, only if it uses Wi-Fi: Settings, Network & internet, Wi-Fi, Manage known networks, your network, and turn "Random hardware addresses" off for it (Microsoft, https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc).

If your router cannot reserve addresses, carry on anyway. If an address changes later, the connection simply stops working (it fails closed). The fix is in "Housekeeping" below.

## Step 3. Mac: build the kit (2 minutes)

```
sh remote-access/mac/wf-make-kit.sh --mac-address <MAC_LAN_ADDRESS>
```

This writes `wf-frontdoor-kit.zip` to your Desktop. Inside: the setup script, the dispatcher, any collectors that exist yet, this checklist, your public key, and `RUN-AT-PC.txt` with the exact command for step 6. There is no secret in it.

The script prints the zip's SHA-256 as eight groups of eight characters. Keep that on the Mac's screen, or take a photo of it. You will compare it at the PC.

## Step 4. PC: move the kit over and check it (5 minutes)

Copy `wf-frontdoor-kit.zip` to the PC's Desktop. A USB stick is simplest. Any other way you normally move a file between the two machines is fine too, because the next check tells you whether the file arrived unchanged.

On the PC, right click the Start button and choose "Terminal (Admin)" (on some versions it is called "Windows PowerShell (Admin)"). Say yes to the permission prompt. The prompt should start with `PS`; if it does not, type `powershell` and press Enter first. Then:

```
cd ([Environment]::GetFolderPath('Desktop'))
((Get-FileHash .\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -split '(.{8})' -ne '') -join ' '
```

Compare the eight groups with the ones the Mac printed. All eight must be identical. If they are not, stop: copy the file again and recheck. Do not run a kit whose hash differs.

Then unpack it and go into the folder:

```
Expand-Archive .\wf-frontdoor-kit.zip -DestinationPath . -Force
cd .\wf-frontdoor-kit
```

## Step 5. PC: check the network is Private (2 minutes)

Windows marks each network as Public or Private, and new networks usually start as Public. The firewall rule this setup creates only applies on a Private network, so the setup script stops, before changing anything, if your home network is marked Public.

In the same admin terminal:

```
Get-NetConnectionProfile
```

Look at `NetworkCategory` for your home connection. If it says `Private`, go on. If it says `Public` and this really is your own home network, change it: Settings, Network & internet, your connection's properties, "Network profile type", Private network. The wording of that page differs between Windows versions; this command does the same, using the `InterfaceIndex` number shown by the command above:

```
Set-NetConnectionProfile -InterfaceIndex <number> -NetworkCategory Private
```

Private means Windows treats the network as one you trust, which also lets other devices at home see the PC. Only do this for your own network.

## Step 6. PC: run the setup script (10 minutes)

Close any game first. Open `RUN-AT-PC.txt` in the kit folder and run the one line in it, in the admin terminal, inside the `wf-frontdoor-kit` folder. It looks like this, with your Mac's address already filled in:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\remote-access\windows\Install-FrontDoor.ps1 -MacIpAddress <MAC_LAN_ADDRESS> -MacPublicKeyFile .\mac-public-key.pub
```

It works through thirteen steps, printing `ok`, a warning, or `FAILED` for each, and ends with a summary. Step S2 downloads the OpenSSH Server feature from Windows Update and can take a few minutes; the rest is quick.

| Step | What it does | What "ok" means |
|---|---|---|
| S1 | Checks before changing anything: administrator, Windows PowerShell 5.1, a valid address and public key, the network is Private, the firewall is on | Nothing was changed yet, and nothing will be unless these hold |
| S2 | Installs the OpenSSH Server feature if it is missing | The `sshd` service exists |
| S3 | Creates one firewall rule: SSH from `<MAC_LAN_ADDRESS>` only, Private networks only. Disables the rule the install created, which is open to everyone, under whatever name it has | Read back from the firewall: no other rule lets SSH in |
| S4 | Starts `sshd` and sets it to start with Windows | Running, automatic, host key created |
| S5 | Makes sure `sshd` hands the forced command to `cmd.exe` | The default shell setting is absent or names `cmd.exe` |
| S6 | Creates the standard account `wfcollector`, adds it to Event Log Readers and nothing else | Enabled, not an administrator, password never expires |
| S7 | Copies the dispatcher and collectors to `C:\ProgramData\win-forensics` and locks the folders | Only Administrators and SYSTEM can change what the account runs |
| S8 | Installs your Mac's public key, limited to the dispatcher and to the Mac's address | One key line, read back exactly, with strict permissions |
| S9 | Edits `sshd_config`: keys only, only this account may connect, forced command, file logging. Validates before applying, restores the old file if validation fails | `sshd` itself confirms the settings that apply to this account |
| S10 | Sets "sleep when plugged in" to never | Read back as never |
| S11 | Reads the Security log's access settings, for the record | Shown, nothing changed |
| S12 | Shows the PC's host key fingerprint | You will copy this line |
| S13 | Self test: connects to the PC from the PC itself as `wfcollector` with a throwaway key, asks for the health check, asks for `whoami`, then removes the throwaway key | The health check came back and `whoami` was refused |

The last lines are either `RESULT: PASS` or `RESULT: FAIL`.

On PASS, the summary shows a line starting with `SHA256:`. That is the PC's host key fingerprint. It is public, not a secret. Get it to the Mac any way you like: type it, photograph it, or take the file `wf-frontdoor-report.txt` (saved in the kit folder under `remote-access\windows`) back on the USB stick.

Things you may notice afterwards:

- A new account named `wfcollector` exists. It may or may not show up on the sign in screen; Microsoft's documentation does not say. Nobody can sign in with it, because its password is random and was never shown or saved. Do not give it a password.
- The PC no longer goes to sleep on its own while plugged in. The screen can still turn off. Nothing else about power was changed.

## Step 7. Mac: pin the PC's host key (3 minutes)

Pinning means the Mac remembers the PC's identity and refuses to talk to anything else that answers on that address.

If you have the fingerprint as text:

```
sh remote-access/mac/wf-pin-host-key.sh --fingerprint SHA256:<the rest of the line from the PC>
```

If you only have it on the PC's screen or in a photo, run it without the option. It shows the fingerprint it received and asks you to compare it, character by character, with the line on the PC, and to type `yes` only if they are identical:

```
sh remote-access/mac/wf-pin-host-key.sh
```

If it says the fingerprints differ, nothing is pinned. Read the line at the PC again. Do not work around it.

## Step 8. Mac: run the acceptance checks (3 minutes)

```
sh remote-access/mac/wf-acceptance.sh
```

Each line starts with PASS, FAIL, WARN, INFO, or TODO, and the last line is the result. A copy is saved in your home folder as `wf-frontdoor-acceptance-<time>.txt`. It holds facts about your PC and no secret; keep it out of any repository.

| Check | What it proves |
|---|---|
| A1 | The Mac will only talk to the pinned PC: strict checking is on and an Ed25519 key is pinned |
| A2 | `ping` returns the dispatcher's health report. The PC's name appears only as a hash. It also confirms the dispatcher on the PC is the same file as in your checkout |
| A3 | Anything outside the allowlist is refused rather than run: `whoami`, commands chained after `ping`, PowerShell, `cmd`, path tricks, an interactive shell, and file transfer |
| A4 | The PC refuses password sign in; it offers key sign in only |
| A5 | If the PC's identity does not match the pinned key, or no key is pinned, the connection stops before anything is sent |
| A6 | `collect-<name>` answers "unknown collector". That is the expected answer until the collectors are installed by a later kit; after that, `ping` lists them |
| A7 | A measurement, not a pass or fail of the design: what the account can see of the Windows Security log. The output records the log's access string and whether the account can read it |
| A8 | The outbox listing works. With `--fetch-newest` it also fetches the newest bundle and verifies its SHA-256; there is nothing to fetch until collectors exist |
| A9 | Not testable from the Mac: see step 9 |
| A10 | Only with `--after-reboot`: see step 9 |

## Step 9. Restart test, and the check from another device (5 minutes)

Restart test. Restart the PC and do not sign in; leave it at the sign in screen. Within 30 minutes, on the Mac:

```
sh remote-access/mac/wf-acceptance.sh --after-reboot
```

All checks run again, and A10 confirms from the PC's own report that it started recently and that nobody is signed in at its screen. This shows the front door comes back on its own after a restart.

Other address check (A9). The Mac cannot test that other addresses are refused, because it is the one allowed address. From any other device on your home network (another computer, or a phone with a network tool app), try to reach port 22 of `<PC_LAN_ADDRESS>`. From a computer with a terminal:

```
nc -vz -w 5 <PC_LAN_ADDRESS> 22
```

It must time out. If it connects, stop and run the setup script again at the PC. If you have no second device, rely on step S3 of the setup script, which read the firewall rules back at the PC itself.

Tell firstmate the two RESULT lines and any FAIL or WARN line. None of that is secret.

## What the checks settle that documentation could not

Some behaviour could not be tested before you ran this, because no Windows machine was available to the builder, and Microsoft's documentation is silent or thin on it. Each has a check that you just ran, and a fallback.

| Question | Settled by | If it turns out wrong |
|---|---|---|
| Does key sign in work for an account that has never signed in and has no profile folder? The key file is deliberately kept under `C:\ProgramData`, not in a profile, for this reason | S13 and A2 | S13 fails with "Permission denied". Send `wf-frontdoor-report.txt`; the last lines of the sshd log are in it |
| Can the account start Windows PowerShell without being a member of the Users group? It should, because Windows counts every signed in account as a user | S13 and A2 | S13 fails and the log mentions access denied. At the PC: `Add-LocalGroupMember -SID S-1-5-32-545 -Member wfcollector`, then run the setup script again, and report it |
| Do the dispatcher's exit codes reach the Mac? | S13 and A3 (a WARN, not a FAIL) | Nothing to do; the answer is also in the JSON |
| Does `sshd -T` print the effective settings on Windows? | S9 (a warning if not) | S13 is the check that counts |
| Does the firewall read its rule back in the form the script expects? | S3 | S3 fails although the rule is right. Send the report |
| Does the account's list of collectors arrive as a proper list from Windows PowerShell 5.1? | A2 and A6 lines | Report the `ping` line |
| What can the account read of the Security log? | S11 and A7 | This is a measurement. The answer decides a later step, not this one |

## If a step fails

The summary names the step. Find its row. After fixing, run the same command again.

| Step | Likely reason | What to do |
|---|---|---|
| S1 | "not running as Administrator" | Close the window. Right click Start, "Terminal (Admin)", and run the command again |
| S1 | "must run in Windows PowerShell 5.1" | Use the exact line from `RUN-AT-PC.txt`; it starts with `powershell.exe` |
| S1 | "is set to Public, not Private" | Do step 5, then run again |
| S1 | "Windows Firewall is turned off" | Turn it on in Windows Security, Firewall & network protection. If another security product manages the firewall, stop and ask firstmate |
| S1 | "that is a hardware (MAC) address" or "not an IPv4 address" | `-MacIpAddress` wants the four numbers from "Before you start" |
| S1 | "this PC's own address" | You gave the PC's address. Give the Mac's |
| S1 | "PRIVATE key" | The wrong file reached the PC. Delete that copy everywhere except the Mac, make a new key on the Mac (delete the two key files, redo step 1), and rebuild the kit. Tell firstmate |
| S1 | "no network route" | The address is wrong or the Mac is on another network (guest Wi-Fi, for example) |
| S2 | The feature will not install | The PC needs internet access to Windows Update. Check Settings, Windows Update works, restart, and run again. If Windows asks for a restart, restart and run again |
| S3 | "still allow inbound SSH" or "not as intended" | Send `wf-frontdoor-report.txt`. Until it is fixed, run `Stop-Service sshd` so nothing is listening |
| S4 | `sshd` is not running | Restart the PC and run again |
| S5 | Cannot remove the default shell value | Send the report |
| S6 | "already exists and was not created by this script" | Another account has that name. Run again adding `-AccountName wfcollector2` to the command, and use `--account wfcollector2` in step 1 on the Mac |
| S6 | "is a member of Administrators" | Somebody added it to that group. Remove it from Administrators and run again |
| S7 | "unsafe permissions" | Send the report. Run `Stop-Service sshd` meanwhile |
| S8 | Key line or permissions wrong | Run again. If it repeats, send the report |
| S9 | "sshd rejected the new configuration" | Your old `sshd_config` is untouched or was restored. Send the report, which holds sshd's message |
| S9 | "effective sshd configuration ... is not as intended" | Something else in `sshd_config` overrides the settings. Send the report |
| S10 | Sleep timeout not zero | Set "When plugged in, put my device to sleep after" to Never in Settings, System, Power, and run again |
| S11 | A warning only | Nothing to do |
| S12 | No Ed25519 host key | Restart the PC and run again |
| S13 | "did not return the health JSON" | The report holds ssh's message and the last lines of the sshd log. Send it. The throwaway key is already removed |
| S13 | "was NOT refused" | Stop. Run `Stop-Service sshd` and send the report. This must not happen |

If something goes wrong in a way the table does not cover, `Stop-Service sshd` closes the door until it is sorted out, and harms nothing.

## If a Mac side check fails

| Check | Likely reason | What to do |
|---|---|---|
| Step 7: "no SSH answer" | PC asleep or off, wrong `<PC_LAN_ADDRESS>`, or the Mac's address is not the one given to the setup script | Wake the PC; check both addresses again; if the Mac's address changed, redo steps 3 to 6 |
| Step 7: "fingerprints DIFFER" | A typing mistake, or something else is answering on that address | Read the line at the PC again. Never pin a fingerprint that differs |
| A1 | No host entry or no pin | Redo step 1 or step 7 |
| A2, exit code 255, "Permission denied (publickey)" | The key in the kit is not the key the Mac uses, or the Mac's address differs from the one the PC was given | On the Mac: `ssh-add -l` should list the key. Then rebuild the kit and rerun step 6 |
| A2, exit code 255, "timed out" | PC asleep, on another network, or its address changed | See "Housekeeping" |
| A2 WARN "differs from this checkout" | The checkout changed after the kit was made | Make a new kit and rerun step 6 when convenient |
| A3 FAIL | The forced command is not in effect | Stop. At the PC run `Stop-Service sshd`, then the setup script again, and tell firstmate |
| A4 FAIL | Password sign in is still offered | Rerun the setup script at the PC |
| A5 FAIL | The Mac accepted an unknown host | Redo step 1 so the host entry is first in `~/.ssh/config` |
| A10 FAIL | The PC was not restarted recently, or somebody is signed in | Restart, do not sign in, and rerun within 30 minutes |

## Housekeeping

- After a big Windows update, run the setup script again at the PC. It puts back anything the update reset, and changes nothing that is already right.
- When collectors are ready, make a new kit (step 3), move it over (step 4), and run the setup script again (step 6). The installed collectors always match the kit you ran last. Then `ping` lists them.
- If the Mac's address changes, redo steps 3 to 6 with the new `<MAC_LAN_ADDRESS>`. If the PC's address changes, rerun step 1 with the new `<PC_LAN_ADDRESS>`; nothing at the PC needs to change.
- Finished bundles wait in `C:\ProgramData\win-forensics\outbox` until fetched. The dispatcher stops collecting when 50 bundles or 2 GB are waiting there. To clear it, delete old folders in that directory from an admin terminal at the PC. They are copies made by the collectors, not the PC's own logs.
- The sshd log is `C:\ProgramData\ssh\logs\sshd.log`. It grows slowly and is safe to delete while `sshd` is stopped.

## How to turn it all off

Each level is done at the PC in an admin terminal. Pick the smallest one that does what you want.

Pause (seconds, easy to undo). Every connection is refused while the account is disabled:

```
Disable-LocalUser -Name wfcollector
```

To confirm it took effect, `sh remote-access/mac/wf-acceptance.sh` on the Mac must now fail at A2 with "Permission denied". Undo with `Enable-LocalUser -Name wfcollector`, or by running the setup script again.

Revoke the Mac's key. Remove the key line, then restart the service:

```
Clear-Content C:\ProgramData\win-forensics\remote\authorized_keys
Restart-Service sshd
```

Undo by running the setup script again.

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
- Host keys and the log stay in `C:\ProgramData\ssh`, and an empty profile folder `C:\Users\wfcollector` may remain. Both are harmless and can be deleted.

On the Mac, delete the block between the two `win-forensics front door` marker lines in `~/.ssh/config`, delete `~/.ssh/known_hosts_winforensics`, and run `ssh-add -d ~/.ssh/id_ed25519_winforensics`. Delete the two key files if you will not use them again.
