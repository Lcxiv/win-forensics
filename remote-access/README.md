# remote-access: the SSH front door

Milestone G2-M2 of the gaming PC access plan: a way for the captain's Mac to reach his Windows 11 gaming PC over the home network as a standard account that can run only named, read only collectors. The person at the PC follows [CHECKLIST.md](CHECKLIST.md). This document is for whoever maintains the code: what each file does, why each decision was made, which documentation it rests on, and what could not be proven without a Windows machine.

Nothing in this directory is ever run against the PC by an agent. The captain runs the setup script himself, at the PC. The Mac side scripts are for him, or for a later, separately authorised step.

## Files

```
remote-access/
  CHECKLIST.md                 the three actions with the router step between the first two (about 15 minutes of
                               the person's time); the script by script procedure and the setup steps are its appendices
  windows/
    SETUP-PC.cmd               the file the person double clicks at the PC, from a USB stick; starts the launcher below
    Start-FrontDoorSetup.ps1   the launcher: refuses anything but a removable drive, elevates through the UAC prompt,
                               checks the kit code, unpacks into a private staging folder and unblocks, checks the
                               network is Private, runs the setup script, writes the report and the PC's host key
                               back onto the stick
    Install-FrontDoor.ps1      elevated, idempotent setup script; thirteen verified steps and a summary
    WfSetupLib.ps1             its decisions and text rendering as pure functions
    dispatch.ps1               the forced command: an exact allowlist of verbs
    WfCommon.ps1               helpers shared by the two scripts above
  mac/
    wf-start.sh                action 1: wf-mac-setup.sh, then wf-make-kit.sh, then the kit folder, the kit code,
                               and the full SHA-256 with the manual check spelled out
    wf-finish.sh               action 3: wf-pin-host-key.sh from pc-host-key.pub on a removable disk or a typed
                               fingerprint, then wf-acceptance.sh, then one PASS, FAIL, or INCOMPLETE list
    wf-mac-setup.sh            dedicated key, ssh-agent, and the Host block in ~/.ssh/config
    wf-make-kit.sh             one zip to carry to the PC, with its SHA-256, the kit code, and the Get-FileHash line
    wf-pin-host-key.sh         pin the PC's host key after comparing fingerprints
    wf-acceptance.sh           the G2-M2 acceptance checks
    wf-fetch.sh                bring a bundle back and verify its SHA-256
    wf-common.sh               shared by the scripts above (including the kit code derivation)
  tests/                       Pester tests, analyzer settings, and fixtures/sshd_config_default, the default
                               sshd_config Win32-OpenSSH ships (contrib/win32/openssh/sshd_config at the pinned commit)
tests/test_remote_access.py    pytest: Mac scripts against a stand-in ssh, documents, and the Pester bridge
```

The two entry points on the Mac and the launcher on the PC are thin orchestration over the scripts below them; every script stays callable on its own (CHECKLIST.md, Appendix A).

## The three actions

| Action | Runs | Does |
|---|---|---|
| 1, Mac: `wf-start.sh --pc-address <PC>` | `wf-mac-setup.sh`, then `wf-make-kit.sh --out <kit>/wf-frontdoor-kit.zip` | Checks both addresses are four numbers 0 to 255 with no leading zero (`wf_is_ipv4`), detects the Mac's address from the default route (`route -n get default`, `ipconfig getifaddr`; `--mac-address` overrides), makes or reuses the passphrase protected key, writes the `Host` block, builds the zip, copies `SETUP-PC.cmd` and `Start-FrontDoorSetup.ps1` next to it in `~/Desktop/wf-frontdoor` (or `--kit <folder>`, for example a USB stick), removes a `pc-host-key.pub` or report left by an earlier trip, writes `READ-ME-FIRST.txt` (which names neither value), and prints the kit code, the full SHA-256 in upper case as eight groups of eight, the exact `Get-FileHash` comparison to type, and both ways in |
| the router step | nobody | Address reservation. It cannot be automated safely: every router's interface is different and there is no standard way to reserve a lease from a client, so this stays a manual step with the generic shape written out in the checklist |
| 2, PC, way A: double click `SETUP-PC.cmd` on the USB stick | `Start-FrontDoorSetup.ps1`, which runs `Install-FrontDoor.ps1` | See "The launcher" below. Allowed only from a removable drive |
| 2, PC, way B: any other transport | Windows' own `Get-FileHash`, then `Expand-Archive`, then `Install-FrontDoor.ps1` by hand | The mandatory non circular path: the person types the full SHA-256 from the Mac screen into `(Get-FileHash .\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '<64 characters>'` before any file from the kit runs; `True` or stop. Checklist action 2 way B and Appendix A from L3 |
| 3, Mac: `wf-finish.sh` | `wf-pin-host-key.sh --fingerprint <expected>`, then `wf-acceptance.sh` | Finds the expected host key under the rule in "Threat model", pins only on a match, runs every acceptance check (captured to a file first, so its real exit code is known), and prints one list: `PASS`, `FAIL`, `WARN`, `INFO`, `TODO` lines and a `RESULT` of PASS (exit 0), FAIL (1), or INCOMPLETE (2, a check could not run, for example no SSH answer or no trusted source for the host key; not a pass, the same meaning the setup script gives it) |

`wf-make-kit.sh` gained one file inside the zip, `kit-parameters.txt` (`mac_address=`, `account=`), which the launcher reads instead of asking a person to type an address at the PC, and it prints the kit code and the `Get-FileHash` line next to the full digest; its `RUN-AT-PC.txt` points at way B. Nothing that travels with the kit carries the code or the digest; a test checks every file in the folder and every zip member.

### The launcher

`SETUP-PC.cmd` and `Start-FrontDoorSetup.ps1` sit next to the zip, outside it, and so cannot vouch for themselves (see "Threat model"). What they rely on, and where it is documented:

| Behaviour | Source |
|---|---|
| Removable drive only. Both runs take the root of the kit folder by shape (`E:\`, or a UNC prefix) and ask `System.IO.DriveInfo` for its `DriveType`; only `Removable` ("a removable storage device, such as a USB flash drive") is accepted. A UNC root is reported as `Network` without asking. Anything else stops the launcher before `Get-FileHash`, `Read-Host`, staging, `Expand-Archive`, `Unblock-File`, dot sourcing, or the setup script, with the manual path named. `Fixed` is what Windows reports for the PC's own disks and for some USB hard disks and enclosures; those are refused on purpose and go through way B. | https://learn.microsoft.com/en-us/dotnet/api/system.io.driveinfo.drivetype and https://learn.microsoft.com/en-us/dotnet/api/system.io.drivetype |
| `SETUP-PC.cmd` starts `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` (Windows PowerShell 5.1, never PowerShell 7) with `-NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-FrontDoorSetup.ps1" -KitFolder "%~dp0."`. `%~dp0` is the drive and folder the `.cmd` is in, so the kit works from any folder or stick. `pause` keeps that first window open so a message in it can be read. | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/call and https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pause |
| The trailing `.` in `"%~dp0."`: `%~dp0` ends with a backslash, and on a Windows command line a backslash right before a closing quote escapes the quote. The launcher quotes every path it passes on the same way (`ConvertTo-WfQuotedPath` doubles trailing backslashes; a double quote cannot occur in a Windows path). This is the same rule `WfCommon.ps1` already applies for the dispatcher, and the reason the forced command itself stays free of spaces is unchanged (the Win32-OpenSSH problem with spaces in executable paths, cited under "Default shell"). | https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments |
| `-ExecutionPolicy` on the `powershell.exe` command line sets the policy for that process only (the Process scope, kept in `$Env:PSExecutionPolicyPreference`, gone when the process ends) and never touches the registry. The unelevated and the elevated launcher run with `Bypass` because they may carry the "downloaded" mark themselves; the setup script is run as a child with `RemoteSigned`, the narrowest policy that runs the unblocked files. | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1 and https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1 |
| Elevation: the unelevated copy calls `Start-Process powershell.exe -Verb RunAs` (the "Run as administrator" verb, Learn's own example), passing `-NoExit` so the elevated window stays open with the result, `-File` with the launcher's own path, `-KitFolder`, and `-Elevated`. A declined or closed UAC prompt makes `Start-Process` throw (Windows reports `ERROR_CANCELLED`, 1223, "The operation was canceled by the user"); the launcher catches it and prints a plain STOPPED line saying nothing was changed. | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1 and https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299- |
| The elevated copy checks it really is elevated (`WindowsPrincipal.IsInRole(Administrator)`, as S1 does) and in Windows PowerShell, and stops otherwise. | Same checks as S1 |
| Kit code: the zip is read from the stick once, `Get-FileHash -InputStream -Algorithm SHA256` runs over those bytes, and the result is compared with what the person types (up to three tries, spaces and case ignored, the full 64 characters accepted too). Nothing is unpacked before it matches, and what is unpacked is those same bytes, written into the staging folder, never a second read of the stick. | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1 and https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/read-host?view=powershell-5.1 |
| Staging. After elevation the launcher creates a fresh folder `win-forensics-kit-<32 hex>` under `ProgramData` (`Environment.GetFolderPath(CommonApplicationData)`), the 16 random bytes coming from `RandomNumberGenerator.Create()`. It is created together with its access list in one `Directory.CreateDirectory(path, DirectorySecurity)` call: owner Administrators, SYSTEM and Administrators full control, inheritance off, nobody else, so the unelevated user's processes have no access. A path that already exists is refused, never emptied or reused; every ancestor is checked for the reparse point attribute before creation and the new folder after it; every zip entry name is checked before unpacking (relative, forward slashes, no `..`, no drive, no leading separator) and every unpacked item is checked for the reparse point attribute after it. Everything from unpacking to the end runs inside `try/finally`; the `finally` copies the report next to the zip and removes the staging folder, whatever happened, including the parameter and Private network stops. | https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator.create , https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createdirectory , https://learn.microsoft.com/en-us/dotnet/api/system.io.fileattributes (ReparsePoint) |
| Unpacking into that folder with `Expand-Archive -Force`, then `Unblock-File` on every unpacked file. The Mark of the Web is the `Zone.Identifier` alternate data stream a browser, and some cloud clients, add to a file; `Unblock-File` removes it, which is what lets `RemoteSigned` run an unsigned script, and it is a no-op on a file that is not marked. It happens only after the kit code matched, on files from the verified zip. A FAT32 stick cannot carry the mark at all. Whether `Expand-Archive` copies the mark from the zip to the unpacked files is not documented, which is why the launcher unblocks them regardless. | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/expand-archive?view=powershell-5.1 , https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1 , and (Mark of the Web, zones, FAT32) https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked |
| Network profile: `Find-NetRoute -RemoteIPAddress <Mac>` returns two objects, the local address and the route, both carrying `InterfaceIndex`; the first with one is used. The call is guarded: a lookup that throws, an empty result, and a missing profile are each a plain STOPPED reason, never a raw error. `Get-NetConnectionProfile -InterfaceIndex` gives the `NetworkCategory`. Anything but `Private` stops the launcher, before the setup script, with the Settings path and the exact `Set-NetConnectionProfile -InterfaceIndex <n> -NetworkCategory Private` line. The launcher does not change the profile itself: marking a network Private makes the PC visible to that network, and the brief asked for a stop with guidance. Before any of this the address from the kit is checked by shape and range (`Test-WfIPv4Text`, every octet 0 to 255) and by the loaded library's `Get-WfIPv4Info`. | https://learn.microsoft.com/en-us/powershell/module/nettcpip/find-netroute , https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile , https://learn.microsoft.com/en-us/powershell/module/netconnection/set-netconnectionprofile |
| The setup script runs as `Start-Process powershell.exe -NoNewWindow -Wait -PassThru` with one pre-quoted argument string (`-NoProfile -ExecutionPolicy RemoteSigned -File "<Install-FrontDoor.ps1>" -MacIpAddress <a> -MacPublicKeyFile "<pub>" -AccountName <n>`), so its coloured step output appears in the same window and its exit code (0, 2, 1) is read from the process object. A process object without an exit code yields `$null`, which the launcher reports as INCOMPLETE (exit 2) and never as a pass; any other value than 0, 1, 2 is FAIL. Learn: "For the best results, use a single ArgumentList value containing all the arguments and any needed quote characters." | Start-Process page above |
| Whatever the result, the `finally` copies `wf-frontdoor-report.txt` (which the setup script writes next to itself in the staging folder) next to the zip before the staging folder is removed, and the launcher says separately whether the report was copied, could not be copied, or was never written. After exit code 0 only, it reads `C:\ProgramData\ssh\ssh_host_ed25519_key.pub` (public; the same file S12 reads), writes `pc-host-key.pub` (`ssh-ed25519 <key> win-forensics-pc`, ASCII, no byte order mark) next to the zip, and prints the SHA256 fingerprint; a file it could not write is said so, with the fingerprint on screen as the fallback. | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement |
| An elevated process may not see drive letters mapped in the unelevated session, so a kit on a mapped network drive can be invisible to the elevated launcher; the checklist says to copy the folder to the Desktop first, and the launcher's "zip is missing" message says the same. | https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command |
| Address and account never come from the command line or from a person at the PC: they are read from `kit-parameters.txt` inside the verified zip and checked against the same patterns S1 applies (`Read-WfKitParameters`). | S1 |

## Threat model of the two integrity checks

**The kit.** The kit travels from the Mac to the PC, and whoever can write to the way it travels can alter it. The launcher (`SETUP-PC.cmd` and `Start-FrontDoorSetup.ps1`) travels next to the zip, so a check performed by the launcher cannot prove the kit against anyone who could replace the launcher too: such a launcher would print "the code matches" whatever is typed and run whatever it likes as administrator. The design therefore has two paths, and which one applies is decided by the transport, not by the person's judgement of the moment:

- Way A, a removable drive that stayed in the person's hands, is treated as a trusted transport. The launcher checks that the kit folder is on a drive Windows reports as `Removable` before it hashes, unpacks, unblocks, dot sources, or runs anything, and refuses otherwise. On that path the kit code protects against a damaged or truncated copy and against a payload altered without the launcher (a cloud client or a helper rewriting a `.ps1`), and it replaces a by eye comparison with one the machine does. The code is the left-most 32 hex characters (128 bits) of the zip's SHA-256, printed in 8 groups of 4 in lower case hex (an alphabet without the look-alike pairs `0`/`O` and `1`/`l`). Why that length: a digest truncated to its left-most λ bits keeps a preimage and second preimage resistance of λ bits (NIST SP 800-107 Rev. 1, section 5.1, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf), and what an attacker who alters the kit needs is a second preimage: a different zip whose truncated digest equals the one the person will type. 128 bits is the smallest security strength NIST rates "Acceptable" beyond 2030 (SP 800-57 Part 1 Rev. 5, Table 4, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf). Collision resistance (λ/2 bits) is not the relevant number, because the original zip is built on the Mac from the checkout, not chosen by the attacker. A typo is reported as a typo, a well formed code that differs stops the run before anything is unpacked.
- Way B, every other transport (a cloud folder, a network share, a download, a copy on the PC's own disk), is untrusted, and the launcher is not used at all. The person types the full 64 character SHA-256 from the Mac screen into Windows' own `Get-FileHash` comparison in an administrator terminal, `(Get-FileHash .\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '<64 characters>'`, before any file from the kit runs, and continues only on `True`, then unpacks and runs `Install-FrontDoor.ps1` by hand (checklist action 2 way B, Appendix A from L3). Nothing that travelled with the kit takes part in that check; the Mac prints the digest in upper case as eight groups of eight, the way `Get-FileHash` prints it, next to the exact line to type. This path is mandatory, not an alternative: the launcher enforces it by refusing, and the checklist, the Mac's output, and the read me in the kit all say so.

Neither the code nor the digest is written into anything that travels with the kit; `tests/test_remote_access.py` checks every file in the kit folder and every member of the zip for both. A tampered kit is a compromised PC side by construction, which is also why the acceptance check A2 compares the installed dispatcher's SHA-256 with the checkout after the fact. What remains outside both paths: an attacker who alters the kit on a removable drive that the person believed was in their hands the whole time. That is a physical custody assumption, stated in the checklist, not a property the software can enforce.

**The host key.** A first connection is never trusted silently: `StrictHostKeyChecking yes` with a dedicated known hosts file, and pinning only after a fingerprint comparison, are unchanged. What changed is where the expected fingerprint comes from, under the same transport rule. The launcher writes the PC's host public key into the kit folder as `pc-host-key.pub`, next to the zip, and `wf-finish.sh` uses that file automatically only when the folder is on a removable disk (`--kit <folder>`, or, with no option, exactly one `/Volumes/*/wf-frontdoor/pc-host-key.pub`; more than one is refused rather than guessed). The folder is resolved first with `pwd -P` (POSIX, https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pwd.html ), so a link or a `/Volumes/..` path is judged by where it really leads; `/Volumes/Macintosh HD` is a link to `/` and resolves out of `/Volumes`. The resolved folder must lie under `/Volumes`, where macOS mounts other disks (Apple, File System Programming Guide, "File System Basics", https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html ), and `diskutil info` on its mount point (diskutil(8), https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man8/diskutil.8.html ) must report a disk mounted exactly there, over no network protocol (SMB, AFP, NFS, WebDAV), with `Device Location: External`, and with `Removable Media: Removable` or `Ejectable: Yes`. A network share mounted through Connect to Server also appears under `/Volumes`, but it has no disk, so `diskutil info` reports none and the file is not used. A pc-host-key.pub that is itself a link is not used either. A file anywhere else (the Desktop, a cloud folder, a network share, the boot disk, an internal disk) is never used: `wf-finish.sh` ends INCOMPLETE and asks for `--fingerprint` typed from the PC screen (the fingerprint is also in `wf-frontdoor-report.txt`), because whoever controls that place could have replaced the file. From the file, the fingerprint is computed with `ssh-keygen -l -E sha256` and handed to `wf-pin-host-key.sh --fingerprint`, which fetches the key the PC offers over the network with `ssh-keyscan` and pins it only when the two fingerprints are identical; an attacker on the network cannot forge a file on a stick. With no file found and no `--fingerprint`, the script stops INCOMPLETE and says to plug the stick in and run again, or to type the fingerprint; only with `--by-eye` does it fall back to `wf-pin-host-key.sh` showing the fingerprint it received for a comparison by the person, with the source named as such. On any difference nothing is pinned, `wf-finish.sh` ends in FAIL, and no acceptance check is sent. A stale `pc-host-key.pub` from an earlier trip cannot survive: `wf-start.sh` deletes it when it builds a new kit.

## What the setup script does, and why

Sources are Microsoft Learn, the Win32-OpenSSH project (its wiki and the source of `PowerShell/openssh-portable`, pinned to commit `e581929`, branch `latestw_all`, read on 2026-09-30), and the OpenSSH manual pages. The OpenSSH build inside Windows can be older than that source; that is one reason the script ends with a real connection to itself rather than trusting this reading.

| Step | Decision | Source |
|---|---|---|
| S1 | Refuse to start unless elevated, in 64 bit Windows PowerShell 5.1, with a valid IPv4 address and a bare `ssh-ed25519` public key, on a network whose profile is Private, with the firewall on for that profile. Nothing is changed before these pass. | Profiles and `Get-NetConnectionProfile`: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/ . The LocalAccounts module "isn't available in 32-bit PowerShell on a 64-bit system": https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1 |
| S2 | `Add-WindowsCapability -Online` for `OpenSSH.Server`, skipped when an `sshd` service already exists. | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse |
| S3 | While nothing listens: create one rule (`win-forensics-ssh-in`: inbound, TCP 22, remote address the Mac, profile Private). Then take a complete inventory of every enabled inbound allow rule in effect (the ActiveStore, policy delivered rules included) with its port, application, service, and address filters, and disable every rule that would admit TCP 22 to sshd: any protocol of TCP or Any with a local port of 22, a range holding 22, or Any, unless the rule is scoped to another program, to a packaged app, or to another service. Names play no part, so a renamed default rule is caught. A rule that admits SSH but cannot be disabled (delivered by policy) or cannot be read fails the run closed: sshd is stopped and set to manual start. The read back uses the same complete inventory. | The install "creates and enables a firewall rule named `OpenSSH-Server-In-TCP`" (https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse). Any matching allow rule admits traffic and there is no rule ordering: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules . Filter objects belong one to one to their rule: https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps |
| S4 | `Start-Service` once, so that sshd creates its host keys and the default `sshd_config`, then `Stop-Service` and `Set-Service -StartupType Manual`. Nothing listens with the stock configuration (password authentication on, every account allowed) while S5 to S8 prepare the hardened one. | "By default, you need to start sshd manually": https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement . "If the file is missing, sshd generates one with the default configuration when the service is started": https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration |
| S5 | The default shell must be `cmd.exe`. If `HKLM\SOFTWARE\OpenSSH\DefaultShell` names anything else, the three DefaultShell values are removed (and recorded), which restores the documented default. | See "Default shell" below. |
| S6 | `New-LocalUser` with a random password held only as a SecureString, `-PasswordNeverExpires`, `-UserMayNotChangePassword`; membership of Event Log Readers (S-1-5-32-573) by SID. Then every local group's complete membership is read and checked against the exact baseline below; any other membership, direct or through a well known SID, and any group that could not be enumerated, fails the step. | See "The account and its password" below. |
| S7 | `C:\ProgramData\win-forensics` with whole access lists written, not edited. | See "Installed layout" below. |
| S8 | One `authorized_keys` line with `command="..."`, `restrict`, `from="<Mac address>"`, in a file under ProgramData. | See "Where the key lives" below. sshd(8), AUTHORIZED_KEYS FILE FORMAT: https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT |
| S9 | Two managed blocks in `sshd_config`. The new text is validated with `sshd -t -f` on a copy before the live file is touched; the first original is kept as `sshd_config.wf-original`; the previous file is restored if validation fails. `sshd -T -C user=<account>,host=<Mac>,addr=<Mac>` is then asked what applies to the account, before anything listens. Only then is sshd started, for the first time since S4, and set to start with Windows. If it will not start, the previous file is restored and sshd stays stopped. | See "sshd_config" below. https://man.openbsd.org/sshd#t and https://man.openbsd.org/sshd#C |
| S10 | `powercfg /change standby-timeout-ac 0`, read back by position from `powercfg /query`. If the read back cannot be parsed the step is INCOMPLETE. Nothing else about power is changed. | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options and https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout |
| S11 | `wevtutil gl Security`, printed. A measurement for the plan's open question; nothing is changed. | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil |
| S12 | Print the SHA256 fingerprint of `ssh_host_ed25519_key.pub`. A public key fingerprint is not a secret. | Host keys live in `C:\ProgramData\ssh`: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement |
| S13 | Loopback self test: a throwaway key authorised only from 127.0.0.1, then as `wfcollector@127.0.0.1`: `ping` must return the health JSON, `whoami` must be refused, and a forced terminal request (`ssh -tt`) must be refused a terminal (the client reports "PTY allocation request failed"), reach the dispatcher, and show no prompt or account name. The key is removed again whatever happened. If `ping` is denied, the two network logon user rights are read with `secedit` and printed for the checklist's repair path. Without the OpenSSH client tools, or with `-SkipSelfTest`, the step is INCOMPLETE. | See "Not verified off Windows" below for what this settles. PTY: https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config#forcecommand |

Every step throws on failure, the steps after a failure are not run, and the summary prints the result with the checklist row to read. A copy goes to `wf-frontdoor-report.txt` next to the script. It holds no secret, and `.gitignore` keeps it out of the repository.

Three results are possible, and only one of them is success:

| Result | Exit code | Meaning |
|---|---|---|
| PASS | 0 | Every step ran and verified what it set up. The summary then prints the host key fingerprint and the two Mac commands. |
| INCOMPLETE | 2 | No step failed, but at least one essential verification could not be performed: the self test was skipped or the OpenSSH client tools are missing (S13), `sshd -T` could not report the effective configuration (S9), or the sleep timeout could not be read back (S10). Not success: no Mac handoff is printed, and the checklist says to fix the cause and run again. |
| FAIL | 1 | A step failed; the steps after it did not run. Where the failure concerns the firewall or sshd, the script leaves sshd stopped and set to manual start (fail closed). |

Warnings never change the result; they are printed with the step and in the summary.

### Where the key lives

The plan, following Microsoft Learn, put the key in `C:\Users\<account>\.ssh\authorized_keys`. That path does not work for an account that has never signed in. A relative `AuthorizedKeysFile` is resolved against the account's profile directory, and when the account has no profile yet sshd falls back to the Windows directory, so it would look in `C:\Windows\.ssh`:

- https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/pwd.c#L266-L276
- https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/auth.c#L406-L411

So the Match block sets `AuthorizedKeysFile __PROGRAMDATA__/win-forensics/remote/authorized_keys`. `__PROGRAMDATA__` is the token the default Windows `sshd_config` uses for `administrators_authorized_keys`, and sshd treats such a path as absolute. This also keeps the key line out of any directory the account owns.

Permissions on that file: owner Administrators; SYSTEM and Administrators full control, the account read, nobody else, no inheritance. Win32-OpenSSH refuses a key file whose owner is anyone but Administrators, SYSTEM, or the account, or that anyone else can write; the wiki words it more strictly ("should not be owned by, nor provide access to any other user"), so nobody else is granted anything:

- https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-sshfileperm.c#L65-L160
- https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH

The file is written whole and without a byte order mark. Windows PowerShell 5.1's `Set-Content -Encoding UTF8` would add one, and sshd would read it as part of `command=`.

### sshd_config

```
# BEGIN win-forensics front door (global) ...
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers wfcollector
SyslogFacility LOCAL0
LogLevel VERBOSE
# END win-forensics front door (global)

... the file as it was ...

# BEGIN win-forensics front door (match) ...
Match User wfcollector
    AuthorizedKeysFile __PROGRAMDATA__/win-forensics/remote/authorized_keys
    ForceCommand C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File C:\ProgramData\win-forensics\remote\dispatch.ps1
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
# END win-forensics front door (match)

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

- The global block goes first because "for each keyword, the first obtained value will be used" (https://man.openbsd.org/sshd_config). The Match block goes directly before the first existing `Match` line, so it is the first Match block evaluated and nothing after it is swallowed into it.
- Only keywords Win32-OpenSSH supports are used. Microsoft lists the unavailable ones on https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration ; a test checks the rendered blocks against that list.
- `AllowUsers` in lower case, as the same page requires. It decides who may connect, not what they may run; the forced command does that.
- `SyslogFacility LOCAL0` sends the log to `%programdata%\ssh\logs\sshd.log` (same page). `LogLevel VERBOSE` adds the key fingerprint and the "Starting session: forced-command" line for each session; sshd_config(5) advises against the DEBUG levels.
- `PermitTTY no` matters on Windows. The wiki says ForceCommand is "Enforced only on non-PTY sessions. To block PTY access, use PermitTTY="no"": https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config . The key's `restrict` option refuses a terminal as well.
- The forced command is named twice on purpose: `ForceCommand` in the Match block and `command=` on the key. If both are present sshd uses the one from the configuration file (https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/session.c#L645-L652); they are the same string.
- Allow lists add up rather than "first wins", so an `AllowUsers` line that was already in the file keeps those accounts allowed. The script warns about it, and about `Include` files, a non default `Port`, and `Match All`.

### Default shell

The plan proposed setting PowerShell as sshd's default shell so that PowerShell pipelines sent from the Mac would not be mangled by `cmd.exe`. With a forced command that reason disappears: the client's text is never run by any shell, it only arrives in `SSH_ORIGINAL_COMMAND`. What the shell does run is one fixed line, and for that `cmd.exe`, the documented initial default, is the better choice:

- sshd runs `"cmd.exe" /c "<forced command>"` and the dispatcher's exit code reaches the client. With PowerShell as the default shell it would run `powershell.exe -c "<forced command>"`, and `-Command` turns every exit code other than 0 into 1 (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1), which would hide the dispatcher's codes.
- How the shell is chosen and invoked: https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/pwd.c#L76-L99 and https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-doexec.c#L307-L404 . Registry values: https://github.com/PowerShell/Win32-OpenSSH/wiki/DefaultShell
- The forced command names Windows PowerShell 5.1 by full path in System32 and the dispatcher by full path under ProgramData. Neither contains a space. Win32-OpenSSH has a documented problem with spaces in executable paths, which is what rules out PowerShell 7 under `C:\Program Files` (https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell). Windows PowerShell 5.1 is also the interpreter the collector seam names.
- `-ExecutionPolicy RemoteSigned` applies to that one process and changes nothing on the machine. The default policy on Windows client is Restricted, which would refuse the script. RemoteSigned is the narrowest value that runs it: it "doesn't require digital signatures on scripts that are written on the local computer and not downloaded from the internet", and the setup script runs `Unblock-File` on everything it installs. The dispatcher starts collectors the same way. A policy set by Group Policy cannot be overridden from the command line, so S1 stops if one is set to Restricted or AllSigned (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1). The one line the captain types to run the setup script itself uses `Bypass` instead, once, for a kit he has just checked by SHA-256, because whether the unpacked files carry the "downloaded" mark depends on how the zip travelled.

### The account and its password

A local account must have a password, or be created with none. Neither is attractive, so the choice is a password nobody knows:

- Generated from the system random number generator, 40 characters with all four character classes, held only as a SecureString, passed to `New-LocalUser`, disposed. It is never printed, logged, or written anywhere. Re-running the script does not touch it.
- It is never used. Sign in over SSH is by key: sshd builds the session token itself with an S4U network logon that involves no password (https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/win32_usertoken_utils.c#L171-L215), and password authentication is off in `sshd_config`. Learn states the consequence: "A remote session opened via key-based authentication doesn't have associated user credentials."
- `-PasswordNeverExpires`, because the documentation does not say whether an expired password stops the S4U logon, and a front door that stops working after the local maximum password age would be a miserable thing to debug.
- A blank password was rejected. The policy "Accounts: Limit local account use of blank passwords to console logon only" (on by default) still lets such an account sign in at the keyboard, so anyone in the room could use it; and nothing documents how key sign in behaves for it (https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions).
- Groups: the exact baseline, enforced by `Test-WfAccountGroupBaseline` against the complete membership of every local group, is: direct membership of Event Log Readers (S-1-5-32-573) and of no other group; and membership through a well known SID in Users (S-1-5-32-545) only. Windows puts Authenticated Users (S-1-5-11) and INTERACTIVE into Users by default, so every signed in account holds Users' rights whether or not anyone added it, and that is what lets the account start `powershell.exe` from System32; `New-LocalUser` adds the account to nothing. Any other group holding the account, or holding Everyone, Authenticated Users, NETWORK, Local account, or another SID a network logon token carries, fails S6: the group's rights would become the account's without anyone having granted them. If any group cannot be enumerated (through ADSI first, `Get-LocalGroupMember` second) the step fails rather than reasoning from a partial list. The Users membership through Authenticated Users rests on Windows' default group membership rather than on a page that can be cited for this exact case, so it is on the unverified list and the self test settles it.
- Network logon right: an SSH key logon is a network logon (the S4U call above uses logon type Network), and Windows grants those only to accounts that hold the "Access this computer from the network" right (`SeNetworkLogonRight`) and are not named by "Deny access to this computer from the network" (`SeDenyNetworkLogonRight`), which overrides it (https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants). On a default Windows client the allow right is held by Everyone, Users, Administrators, and Backup Operators, and the deny right by Guest, so the account qualifies through Everyone and Users. A hardened machine may differ. The script does not change these rights. When the self test's `ping` is denied it reads both rights with `secedit /export /areas USER_RIGHTS` and prints them, and the checklist (row S13) gives the inspection and repair steps, which add the account itself to the allow right rather than adding it to a group.

### Installed layout

```
C:\ProgramData\win-forensics\        SYSTEM, Administrators: full.  Account: read and traverse this folder only
  remote\                            SYSTEM, Administrators: full.  Account: read and execute (inherited)
    dispatch.ps1
    WfCommon.ps1
    collectors\<name>.ps1            plus any helper .ps1 the collectors load (never a verb)
    authorized_keys                  SYSTEM, Administrators: full.  Account: read.  No inheritance
    install-state.json               what earlier runs did (for turning it off again)
  outbox\                            SYSTEM, Administrators: full.  Account: modify (inherited)
    <bundle dir>\                    one directory per finished collector run (exit code 0)
    .staging\                        runs in progress, runs that failed or timed out, and zip files while a fetch streams
```

Every directory has inheritance from its parent switched off and its access list written whole, because `C:\ProgramData` lets every user create files in new subdirectories. All three are owned by Administrators. After copying, the script reads the owner and the rules of every directory and file under `remote\` back and fails if anyone other than SYSTEM and Administrators holds a write, delete, change permissions, or take ownership right. The account therefore cannot modify the dispatcher, a collector, the key file, or any directory on the path to them; the PowerShell executable it runs is in System32.

## The dispatcher

`dispatch.ps1` is what sshd runs for the account. The client's request reaches it only as the `SSH_ORIGINAL_COMMAND` environment variable (sshd(8): "The command originally supplied by the client is available in the SSH_ORIGINAL_COMMAND environment variable"; Win32-OpenSSH sets it in `session.c` and copies the environment into the child in `w32-doexec.c`, links in the script header). The script has no parameters and reads no other variable; Win32-OpenSSH supports neither `AcceptEnv` nor `PermitUserEnvironment`, so the client cannot set any.

The request is compared, never executed. It must equal one of these exactly, case sensitively, with nothing before or after:

| Verb | Does | Output |
|---|---|---|
| `ping` | Nothing on the machine | One line of JSON: `ok`, `verb`, `protocol`, `time_utc`, `host_id` (16 hex characters of the SHA-256 of the lower case host name; the name itself never leaves), `account`, `os` (version, build, UBR, display version), `openssh_server` (file version of sshd.exe), `powershell`, `dispatcher_sha256`, `collectors` (installed names), `outbox` (count, bytes, limits), `boot_time_utc`, `console_user` (true, false, or null; never a name) |
| `list-bundles` | Lists the outbox | JSON with `bundles`: `bundle_dir`, file count, bytes |
| `collect-<name>` | Runs `collectors\<name>.ps1` into `outbox\.staging\<bundle dir>` and moves that directory into the outbox only when the collector exits 0 | JSON: `bundle_dir`, the collector's exit code, its checked summary, file count, bytes, and the `fetch-` verb to use |
| `fetch-<bundle dir>` | Zips that outbox directory and streams it | The framed transfer below |
| `security-log-access` | Runs `wevtutil gl Security` and `wevtutil gli Security` | JSON: the channel's access string (SDDL), whether it has a read entry for Event Log Readers, and whether each query succeeded for this account. Neither query returns an event |

`<name>` must match `^[a-z][a-z0-9-]{1,40}$` and `<bundle dir>` must match `^[0-9]{8}T[0-9]{6}Z_[a-z][a-z0-9-]{1,40}_[0-9a-f]{8}$`. Those two are the only parts of the request that travel any further, and neither pattern admits a separator, a dot, a space, or a quote. Everything else is refused with a JSON line on standard output, a message on standard error, and exit code 64. The request is not echoed back.

| Exit code | Meaning |
|---|---|
| 0 | ok |
| 64 | refused: not on the allowlist |
| 65 | unknown collector (the expected answer to `collect-<name>` until collectors are installed) |
| 66 | unknown bundle |
| 70 | internal error |
| 71 | the collector exited non zero (its partial output stays in `outbox\.staging` at the PC and is never listed or fetched) |
| 72 | the collector ran past 15 minutes and was stopped, with every process it started (`taskkill /T /F`); its output stays in `outbox\.staging` |
| 73 | outbox full: 50 bundles or 2 GB are waiting |
| 75 | busy: the same collector was started in the same second three times running |

Standard output is written as UTF-8 bytes with line feeds, ASCII only, straight to the stream, so it does not depend on a console code page.

### Collectors

The seam, fixed between this work and the collector work:

- The dispatcher starts `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File <collectors>\<name>.ps1 -OutputDirectory <outbox>\.staging\<bundle dir>` as its own process, with standard input closed, as the collector account.
- `<bundle dir>` is `<yyyymmddThhmmssZ>_<name>_<first 8 hex of host_id>`. The dispatcher chooses that name and creates the directory under `.staging`; the collector writes its bundle into it, and the dispatcher renames it into the outbox after a run that exits 0, so `list-bundles`, `ping`, and `fetch-` never see a bundle still being written or one from a failed run. The name is only the dispatcher's handle for `list-bundles` and `fetch-`. The `bundle_id` inside the bundle's `manifest.json` is the authoritative id and may differ from it, which is why the wire field is called `bundle_dir`.
- The collector's last line of standard output is its summary, `{"collector":"<name>","status":"ok|partial|failed","bundle":"<OutputDirectory>","artifacts":<count>}`. The dispatcher treats it as data: it must parse, name this collector, carry a known status and a non negative count, or it is reported as `summary_valid: false`. The `bundle` path in it is ignored; the dispatcher knows the directory.
- Standard error is passed on to the SSH client (the last 8 KB, printable characters only). Exit code 0 means the bundle is complete; a collector reporting status `partial` exits 0 (a complete bundle in which some source could not be read, with the reason in the manifest), and one reporting `failed` exits non zero, which the dispatcher turns into exit code 71.
- The setup script installs every `.ps1` file directly in the kit's `collectors/windows`, never its subdirectories (the collectors' tests live in one), and removes installed files the kit no longer holds. A file whose name matches the collector pattern becomes a verb. Any other, such as the collectors' shared helper `_common.ps1`, is installed next to them so they can load it, and can never be asked for by name because its name fails the pattern.

### Transfer

A forced command blocks scp and sftp, so a bundle comes back on standard output of `fetch-<bundle dir>`:

```
WF-BUNDLE-BEGIN v1 dir=<bundle dir> bytes=<zip byte count> sha256=<lower case hex>
<base64 of the zip, 76 characters per line>
WF-BUNDLE-END v1 dir=<bundle dir>
```

The zip's entries are written with forward slashes and the bundle directory name as the top directory. `mac/wf-fetch.sh` decodes the stream and keeps the zip only if the end marker is present and the byte count and SHA-256 equal the header; otherwise it exits 3 and keeps nothing. With `--extract` it needs `unzip` (checked before anything is fetched; `WF_UNZIP` names another one), and it first refuses any entry that is not under `<bundle dir>/` and any symbolic link entry. The dispatcher never writes link entries; the check is there because what comes back is data from another machine and is never run or followed.

The checksum protects against damage and truncation in transit. It does not make the content trustworthy: a compromised PC can send a well formed bundle of false data with a correct checksum. The bundle contract's own manifest and validation are the next layer.

## What this does not do

- It does not change firewall rules delivered by policy. They are in the inventory S3 inspects, and one that would admit SSH fails the run closed with sshd stopped, because the script cannot disable it. S1 already stops on a Group Policy execution policy; a home PC has neither.
- It does not change the network logon user rights. If they exclude the account, S13 fails and reports them, and the checklist says how to repair them by hand.
- It does not rotate or cap `sshd.log`, and it does not prune the outbox. The dispatcher refuses new collections when the outbox is full rather than deleting anything; clearing it is a step at the PC (checklist, "Housekeeping"). A retention verb is a candidate for the scheduled health check milestone.
- It offers no elevation over SSH. Anything that needs administrator rights on the PC is a later milestone with its own controls; the launcher's UAC prompt is the person elevating at the keyboard, once, for the setup.
- It does not let the launcher vouch for a kit that did not come on a removable drive. See "Threat model"; way B is the path there, and the launcher refuses rather than warns.
- It does not change the network profile. The launcher stops with the exact command when the network is Public; marking a network Private is the person's decision.
- It does not reserve router addresses. See "The three actions", action 2.
- It adds no CI. See "Tests".

## Where this departs from the plan

| Plan | What was built | Why |
|---|---|---|
| Key in `C:\Users\<account>\.ssh\authorized_keys` | Key in `C:\ProgramData\win-forensics\remote\authorized_keys`, named by `AuthorizedKeysFile` in the Match block | For an account with no profile sshd resolves the relative path against the Windows directory (source above). The documentation wins. |
| Default shell set to PowerShell | Default shell left at, or returned to, `cmd.exe` | Exit codes survive `cmd /c` and not `powershell -c`; with a forced command the plan's reason no longer applies. |
| Scope the default firewall rule with `Set-NetFirewallRule -Name OpenSSH-Server-In-TCP` | A rule of our own, and every other rule that opens TCP 22 disabled | The task asked for the rule to be handled under whatever name it has; an update that re-creates or resets the default rule then cannot widen the scope unnoticed until the next run. |
| Acceptance: `collect-bugcheck` returns a bundle | `collect-<name>` returns "unknown collector" (exit 65) until the collectors land | The collectors are the sibling task. The transfer path is exercised end to end against the real dispatcher with a stand-in collector in the tests. |
| Not in the plan | `PermitTTY no`, and a forced terminal request in the self test and the acceptance checks; `list-bundles`; the loopback self test; the `console_user` and `boot_time_utc` fields; an outbox limit; sshd stopped between its first start and the hardened start; fail closed (sshd stopped, manual start) when the firewall cannot be narrowed; an INCOMPLETE result | The wiki's note on ForceCommand and terminals; a bundle's directory name has to be discoverable; first time success at the PC; the "after a reboot with nobody logged in" acceptance made measurable; the plan's own risk table asks for a cap; nothing may listen with the stock configuration; a run that could not verify itself must not read as a pass. |

## Not verified off Windows

There was no Windows machine and no Windows PowerShell 5.1 available when this was built. The following rest on documentation or source reading only. Each has a step that proves it on the real machine, and the checklist names the fallback.

1. The whole of `Install-FrontDoor.ps1` has never run on Windows. Its step logic is tested with every Windows cmdlet mocked; the cmdlets, parameters, and .NET members it uses were checked against PSScriptAnalyzer's Windows PowerShell 5.1 profile, not against a machine.
2. Key sign in for an account with no profile, using a key file under ProgramData with the permissions above. Settled by S13, then A2.
3. That the account, a member of Event Log Readers only, can start `powershell.exe` and read its own layout. Settled by S13.
4. That `cmd.exe /c` runs the forced command line unchanged and that exit codes 64 and 65 reach the client. Settled by S13 and A3 (a warning, not a failure, because the JSON carries the result too).
5. That `sshd -T -C` works on the Windows build and prints what `Test-WfSshdEffectiveConfig` expects. If it cannot run, S9 is INCOMPLETE and the run is not a pass.
6. How `Get-NetFirewallAddressFilter` prints a single remote address (bare or with a mask; both are accepted); that the `-All` filter queries and the `InstanceID` join return a filter for every rule in the ActiveStore (a rule without one is asked directly, and one that still has none fails the run closed); and that `PolicyStoreSourceType` reads `Local` for rules the script may disable. Settled by S3's read back.
7. That `powercfg /query` ends with the AC and DC values in that order on every display language. If not, S10 is INCOMPLETE.
8. The ADSI enumeration of every local group's members in `Get-WfLocalGroupMembership`, including the `objectSid` of well known members such as Authenticated Users, and its `Get-LocalGroupMember` fallback. Either failing makes S6 fail; neither can make it pass on a partial list.
9. That `PermitTTY no` refuses a terminal on the Windows build, and that the Windows `ssh.exe` reports it with "PTY allocation request failed on channel 0" as the OpenSSH client does. Settled by S13's `-tt` request and by A3.
10. That the account holds `SeNetworkLogonRight` and is not named by `SeDenyNetworkLogonRight` on this machine, and that `secedit /export /areas USER_RIGHTS` prints them in the `Name = *SID,*SID` form the script parses. S13 settles the first; the second only matters when S13 fails.
11. That stopping sshd between S4 and S9 and starting it in S9 behaves as `Stop-Service` and `Start-Service` report (the service is asked and its status read back each time).
12. `dispatch.ps1` under Windows PowerShell 5.1 specifically: the tests run it under PowerShell 7 on macOS. Known differences were coded around (JSON arrays, encodings, zip entry separators, culture dependent dates), but only S13, A2, and a first real collector prove it. The same goes for two collect details: that `taskkill /T /F` ends a timed out collector together with every process it started, and that the account can rename its finished directory from `outbox\.staging` into the outbox. A first real collector run settles the rename; the timeout path is settled only if a collector ever reaches exit code 72, when Task Manager should show none of its processes left.
13. `wevtutil gl Security` and `wevtutil gli Security` as the standard account. This is a measurement (S11, A7), whatever it returns.
14. Whether `Disable-LocalUser` stops key sign in, as the plan states. The checklist's "turn it off" section says to confirm with a `ping` that must fail.
15. Whether the account appears on the Windows sign in screen. Cosmetic; the checklist says it may.
16. The behaviour of the in-box OpenSSH version where it differs from the source commit cited here.
17. The whole of `SETUP-PC.cmd` and `Start-FrontDoorSetup.ps1` has never run on Windows. The launcher's decisions are tested with the drive type, `Start-Process`, `Read-Host`, `Unblock-File`, `Find-NetRoute`, `Get-NetConnectionProfile`, and the private directory creation mocked; `Get-FileHash`, `Expand-Archive`, the zip entry check, the reparse point checks, and the random name run for real under PowerShell 7, not under 5.1. Settled by action 2 way A reaching the kit code question in a new window; the fallback is way B.
18. That Windows reports the captain's USB stick as `DriveType` `Removable`. A stick that reports `Fixed` (some USB hard disks and enclosures do) is refused by design and goes through way B. Settled by the launcher's "[0]" line.
19. That double clicking a `.cmd` on a USB stick (or a folder with spaces in its path) starts Windows PowerShell with `%~dp0` intact, that `Start-Process -Verb RunAs` shows the UAC prompt and starts the elevated copy with the quoted paths intact, and that a declined prompt surfaces as an exception the unelevated copy can catch and explain. Settled by action 2; a declined prompt can be tried on purpose.
20. That `Directory.CreateDirectory(path, DirectorySecurity)` under `ProgramData` creates the staging folder with the access list asked for, that the unelevated user's processes then cannot read, rename, or remove it (the default access list of `ProgramData` lets users create their own subfolders, not touch an administrator's), and that no ancestor of `ProgramData` is a reparse point on this machine. Settled by "[2] ... ok: unpacked"; the fallback is way B, and a staging folder left behind is safe to delete.
21. That files unpacked by `Expand-Archive` from a zip carrying the Mark of the Web, once passed through `Unblock-File`, run under `-ExecutionPolicy RemoteSigned`. Settled by action 2 reaching step S1. If not, the launcher shows "not digitally signed" and way B's one line (Bypass) is the fallback.
22. That the elevated launcher can read and write the kit folder on the stick, and that `Start-Process -Wait -PassThru` returns a process object with `ExitCode` for the child `powershell.exe`. Settled by action 2's last lines; `--fingerprint` in action 3 is the fallback for the write, and an unreadable exit code is reported INCOMPLETE.
23. That `Find-NetRoute` returns the documented two objects and that `Get-NetConnectionProfile -InterfaceIndex` on their index names the profile the person sees in Settings. Settled by the launcher's "[4]" line naming the network; S1 repeats the check.
24. `route -n get default` and `ipconfig getifaddr` on the captain's macOS version for the Mac's address (they are what `wf-mac-setup.sh` already used to print it); `--mac-address` is the fallback.
25. That `diskutil info` on the captain's macOS version reports the captain's USB stick with `Device Location: External` and `Removable Media: Removable` or `Ejectable: Yes`, and reports no disk for a mounted network share; the field names were read from this Mac's `diskutil info /` and diskutil(8), and the stick's own values are unverified. A stick it does not report that way is refused, never trusted, and action 3 ends INCOMPLETE asking for `--fingerprint` typed from the PC screen, which is the fallback.

A one off check on a Windows runner would remove most of this list. It is proposed as a follow up rather than added here, because `AGENTS.md` allows no CI beyond the Process Monitor job before phase 2.

## Tests

```
pytest tests/test_remote_access.py
```

- Always run: document hygiene for this directory (no em or en dashes, none of the denylisted strings, scripts are ASCII, the `.cmd` is ASCII with CRLF, no address or key hard coded), the checklist's coverage of every acceptance check in its acceptance table, the L1 to L8 appendix, every launcher and finish stop, and the three actions with the router step, `SETUP-PC.cmd`'s one command line, `wf_is_ipv4` against out of range octets and leading zeros, the kit code derived identically by `wf-common.sh` and (with PowerShell) `Start-FrontDoorSetup.ps1` against a Python oracle, `sh -n` and shellcheck on the Mac scripts, and the Mac scripts against a stand-in `ssh` that plays a correct PC, a PC that runs `whoami`, a PC that offers passwords, a client that trusts a wrong host key, and damaged transfers. `wf-finish.sh` runs against that stand-in, with `WF_VOLUMES_DIR` standing in for `/Volumes`: a `pc-host-key.pub` on a stick that matches (found alone, or named with `--kit`), one that does not (nothing pinned, no check sent), the same file on the Desktop (INCOMPLETE, never used, and not looked at), on a volume the stand-in `diskutil` reports as an SMB share or an internal disk, behind a `/Volumes/..` path, and behind a `Macintosh HD` style link to a folder outside the volumes directory (each INCOMPLETE, nothing pinned), no stick (INCOMPLETE, saying to plug it in before `--fingerprint` before `--by-eye`), `--by-eye` naming its source and needing a terminal, a typed fingerprint, two sticks (refused), an unreachable PC (INCOMPLETE), an acceptance run that dies before its result line (INCOMPLETE with the real exit code), failing checks, `--after-reboot`, and warnings carried into the final list.
- With OpenSSH client tools present: `wf-mac-setup.sh` checked through a real `ssh -G`, `wf-make-kit.sh`, `wf-pin-host-key.sh`, and `wf-start.sh` end to end (key reuse, the `Host` block, the kit folder with the launcher pair byte for byte, `kit-parameters.txt` in the zip, no private key anywhere, a stale `pc-host-key.pub` removed, the printed code and full digest equal to the zip's digest and the `Get-FileHash` line printed, and neither the code nor the digest in any file of the folder or member of the zip; out of range addresses refused before anything is touched), all with throwaway keys in a temporary home.
- With a PowerShell 7 available: the Pester suite in `remote-access/tests` (verb parsing and refusal, the dispatcher run as a real process, `authorized_keys` and `sshd_config` rendering against the upstream default file in `tests/fixtures`, idempotency decisions, the mocked setup steps, a checklist row for every step id a run reports, and the launcher: kit code check, parameter parsing with the octet range, path quoting and the kit path shape, zip entry names, the removable drive rule in both runs, the elevation request, the guarded route lookup with the documented two objects and a thrown lookup, a fresh private staging folder never reused and refused under a reparse point, a zip that climbs out, cleanup on the parameter, address, network, and unpack stops, a null exit code reported INCOMPLETE, the report kept on FAIL and INCOMPLETE, the host key only on PASS, and the elevated run end to end with a real zip built from this checkout, the helper libraries loaded by the launcher itself and not by the suite), PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility rules over every `.ps1` including the launcher, and the Mac scripts driving the real dispatcher end to end (collect, fetch, verify, extract).

PowerShell is found in `$WF_PWSH`, on `PATH`, or in `tools/pwsh/pwsh` (the `tools/` directory is ignored by git). Pester 5.5 or later and PSScriptAnalyzer are found the usual way, or in `$WF_PSMODULES`, or in `tools/psmodules`. These are the same locations the collector tests use, so one copy serves both. To set that up by hand without installing anything system wide:

```
mkdir -p tools/pwsh tools/psmodules
# unpack a PowerShell 7 release archive from https://github.com/PowerShell/PowerShell/releases into tools/pwsh
tools/pwsh/pwsh -NoProfile -Command "Save-Module Pester, PSScriptAnalyzer -Path tools/psmodules"
```

Without PowerShell those tests are skipped, and say so.
