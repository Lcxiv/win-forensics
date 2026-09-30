# remote-access: the SSH front door

Milestone G2-M2 of the gaming PC access plan: a way for the captain's Mac to reach his Windows 11 gaming PC over the home network as a standard account that can run only named, read only collectors. The person at the PC follows [CHECKLIST.md](CHECKLIST.md). This document is for whoever maintains the code: what each file does, why each decision was made, which documentation it rests on, and what could not be proven without a Windows machine.

Nothing in this directory is ever run against the PC by an agent. The captain runs the setup script himself, at the PC. The Mac side scripts are for him, or for a later, separately authorised step.

## Files

```
remote-access/
  CHECKLIST.md                 the step by step for the person at the PC (about 45 minutes)
  windows/
    Install-FrontDoor.ps1      elevated, idempotent setup script; thirteen verified steps and a summary
    WfSetupLib.ps1             its decisions and text rendering as pure functions
    dispatch.ps1               the forced command: an exact allowlist of verbs
    WfCommon.ps1               helpers shared by the two scripts above
  mac/
    wf-mac-setup.sh            dedicated key, ssh-agent, and the Host block in ~/.ssh/config
    wf-make-kit.sh             one zip to carry to the PC, with its SHA-256
    wf-pin-host-key.sh         pin the PC's host key after comparing fingerprints
    wf-acceptance.sh           the G2-M2 acceptance checks
    wf-fetch.sh                bring a bundle back and verify its SHA-256
    wf-common.sh               shared by the scripts above
  tests/                       Pester tests, analyzer settings, and fixtures/sshd_config_default, the default
                               sshd_config Win32-OpenSSH ships (contrib/win32/openssh/sshd_config at the pinned commit)
tests/test_remote_access.py    pytest: Mac scripts against a stand-in ssh, documents, and the Pester bridge
```

The collectors themselves live in `collectors/windows/<name>.ps1` and belong to the G2-M3 work. The only contract between the two is the seam described under "Collectors" below.

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
    <bundle dir>\                    one directory per collector run
    .staging\                        zip files while a fetch is streaming; removed afterwards
```

Every directory has inheritance from its parent switched off and its access list written whole, because `C:\ProgramData` lets every user create files in new subdirectories. All three are owned by Administrators. After copying, the script reads the owner and the rules of every directory and file under `remote\` back and fails if anyone other than SYSTEM and Administrators holds a write, delete, change permissions, or take ownership right. The account therefore cannot modify the dispatcher, a collector, the key file, or any directory on the path to them; the PowerShell executable it runs is in System32.

## The dispatcher

`dispatch.ps1` is what sshd runs for the account. The client's request reaches it only as the `SSH_ORIGINAL_COMMAND` environment variable (sshd(8): "The command originally supplied by the client is available in the SSH_ORIGINAL_COMMAND environment variable"; Win32-OpenSSH sets it in `session.c` and copies the environment into the child in `w32-doexec.c`, links in the script header). The script has no parameters and reads no other variable; Win32-OpenSSH supports neither `AcceptEnv` nor `PermitUserEnvironment`, so the client cannot set any.

The request is compared, never executed. It must equal one of these exactly, case sensitively, with nothing before or after:

| Verb | Does | Output |
|---|---|---|
| `ping` | Nothing on the machine | One line of JSON: `ok`, `verb`, `protocol`, `time_utc`, `host_id` (16 hex characters of the SHA-256 of the lower case host name; the name itself never leaves), `account`, `os` (version, build, UBR, display version), `openssh_server` (file version of sshd.exe), `powershell`, `dispatcher_sha256`, `collectors` (installed names), `outbox` (count, bytes, limits), `boot_time_utc`, `console_user` (true, false, or null; never a name) |
| `list-bundles` | Lists the outbox | JSON with `bundles`: `bundle_dir`, file count, bytes |
| `collect-<name>` | Runs `collectors\<name>.ps1` into a new outbox directory | JSON: `bundle_dir`, the collector's exit code, its checked summary, file count, bytes, and the `fetch-` verb to use |
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
| 71 | the collector exited non zero (the partial bundle is kept and can be fetched) |
| 72 | the collector ran past 15 minutes and was stopped |
| 73 | outbox full: 50 bundles or 2 GB are waiting |
| 75 | busy: the same collector was started in the same second three times running |

Standard output is written as UTF-8 bytes with line feeds, ASCII only, straight to the stream, so it does not depend on a console code page.

### Collectors

The seam, fixed between this work and the collector work:

- The dispatcher starts `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File <collectors>\<name>.ps1 -OutputDirectory <outbox>\<bundle dir>` as its own process, with standard input closed, as the collector account.
- `<bundle dir>` is `<yyyymmddThhmmssZ>_<name>_<first 8 hex of host_id>`. The dispatcher chooses that name and creates the directory; the collector writes its bundle into it. The name is only the dispatcher's handle for `list-bundles` and `fetch-`. The `bundle_id` inside the bundle's `manifest.json` is the authoritative id and may differ from it, which is why the wire field is called `bundle_dir`.
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
- It offers no elevation. Anything that needs administrator rights is a later milestone with its own controls.
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
12. `dispatch.ps1` under Windows PowerShell 5.1 specifically: the tests run it under PowerShell 7 on macOS. Known differences were coded around (JSON arrays, encodings, zip entry separators, culture dependent dates), but only S13, A2, and a first real collector prove it.
13. `wevtutil gl Security` and `wevtutil gli Security` as the standard account. This is a measurement (S11, A7), whatever it returns.
14. Whether `Disable-LocalUser` stops key sign in, as the plan states. The checklist's "turn it off" section says to confirm with a `ping` that must fail.
15. Whether the account appears on the Windows sign in screen. Cosmetic; the checklist says it may.
16. The behaviour of the in-box OpenSSH version where it differs from the source commit cited here.

A one off check on a Windows runner would remove most of this list. It is proposed as a follow up rather than added here, because `AGENTS.md` allows no CI beyond the Process Monitor job before phase 2.

## Tests

```
pytest tests/test_remote_access.py
```

- Always run: document hygiene for this directory (no em or en dashes, none of the denylisted strings, scripts are ASCII, no address or key hard coded), the checklist's coverage of every setup step and acceptance check, `sh -n` and shellcheck on the Mac scripts, and the Mac scripts against a stand-in `ssh` that plays a correct PC, a PC that runs `whoami`, a PC that offers passwords, a client that trusts a wrong host key, and damaged transfers.
- With OpenSSH client tools present: `wf-mac-setup.sh` checked through a real `ssh -G`, `wf-make-kit.sh`, and `wf-pin-host-key.sh`, all with throwaway keys in a temporary home.
- With a PowerShell 7 available: the Pester suite in `remote-access/tests` (verb parsing and refusal, the dispatcher run as a real process, `authorized_keys` and `sshd_config` rendering against the upstream default file in `tests/fixtures`, idempotency decisions, the mocked setup steps), PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility rules, and the Mac scripts driving the real dispatcher end to end (collect, fetch, verify, extract).

PowerShell is found in `$WF_PWSH`, on `PATH`, or in `tools/pwsh/pwsh` (the `tools/` directory is ignored by git). Pester 5.5 or later and PSScriptAnalyzer are found the usual way, or in `$WF_PSMODULES`, or in `tools/psmodules`. These are the same locations the collector tests use, so one copy serves both. To set that up by hand without installing anything system wide:

```
mkdir -p tools/pwsh tools/psmodules
# unpack a PowerShell 7 release archive from https://github.com/PowerShell/PowerShell/releases into tools/pwsh
tools/pwsh/pwsh -NoProfile -Command "Save-Module Pester, PSScriptAnalyzer -Path tools/psmodules"
```

Without PowerShell those tests are skipped, and say so.
