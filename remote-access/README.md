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
| S3 | Before `sshd` is first started: create one rule (`win-forensics-ssh-in`: inbound, TCP 22, remote address the Mac, profile Private), then disable every other enabled inbound allow rule that covers TCP 22 or is scoped to `sshd.exe`, found by what it allows rather than by name, and read the result back. | The install "creates and enables a firewall rule named `OpenSSH-Server-In-TCP`" (same page). Any matching allow rule admits traffic and there is no rule ordering: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules |
| S4 | `Set-Service -StartupType Automatic`, `Start-Service`. The first start creates the host keys and the default `sshd_config`. | "By default, you need to start sshd manually": https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement . "If the file is missing, sshd generates one with the default configuration when the service is started": https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration |
| S5 | The default shell must be `cmd.exe`. If `HKLM\SOFTWARE\OpenSSH\DefaultShell` names anything else, the three DefaultShell values are removed (and recorded), which restores the documented default. | See "Default shell" below. |
| S6 | `New-LocalUser` with a random password held only as a SecureString, `-PasswordNeverExpires`, `-UserMayNotChangePassword`; membership of Event Log Readers (S-1-5-32-573) by SID and nothing else; verified not to be in Administrators. | See "The account and its password" below. |
| S7 | `C:\ProgramData\win-forensics` with whole access lists written, not edited. | See "Installed layout" below. |
| S8 | One `authorized_keys` line with `command="..."`, `restrict`, `from="<Mac address>"`, in a file under ProgramData. | See "Where the key lives" below. sshd(8), AUTHORIZED_KEYS FILE FORMAT: https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT |
| S9 | Two managed blocks in `sshd_config`. The new text is validated with `sshd -t -f` on a copy before the live file is touched; the first original is kept as `sshd_config.wf-original`; the previous file is restored if validation or the restart fails. Then `sshd -T -C` is asked what applies to the account. | See "sshd_config" below. https://man.openbsd.org/sshd#t and https://man.openbsd.org/sshd#C |
| S10 | `powercfg /change standby-timeout-ac 0`, read back by position from `powercfg /query`. Nothing else about power is changed. | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options and https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout |
| S11 | `wevtutil gl Security`, printed. A measurement for the plan's open question; nothing is changed. | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil |
| S12 | Print the SHA256 fingerprint of `ssh_host_ed25519_key.pub`. A public key fingerprint is not a secret. | Host keys live in `C:\ProgramData\ssh`: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement |
| S13 | Loopback self test: a throwaway key authorised only from 127.0.0.1, `ssh wfcollector@127.0.0.1 ping`, then `whoami`, then the key is removed again whatever happened. | See "Not verified off Windows" below for what this settles. |

Every step throws on failure, the steps after a failure are not run, and the summary prints PASS or FAIL with the checklist row to read. A copy goes to `wf-frontdoor-report.txt` next to the script. It holds no secret.

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
- Groups: Event Log Readers only, as the plan requires. `New-LocalUser` does not add the account to Users. It should not need to: a signed in account is an authenticated user, and those are members of the built in Users group by default. That last point rests on general Windows behaviour rather than a page that can be cited for this exact case, so it is on the unverified list and the self test settles it.

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

The zip's entries are written with forward slashes and the bundle directory name as the top directory. `mac/wf-fetch.sh` decodes the stream and keeps the zip only if the end marker is present and the byte count and SHA-256 equal the header; otherwise it exits 3 and keeps nothing. With `--extract` it first refuses any entry that is not under `<bundle dir>/`. What comes back is data from another machine and is never run.

The checksum protects against damage and truncation in transit. It does not make the content trustworthy: a compromised PC can send a well formed bundle of false data with a correct checksum. The bundle contract's own manifest and validation are the next layer.

## What this does not do

- It does not inspect firewall rules delivered by Group Policy. On a managed machine such a rule could open port 22 without this script seeing it. S1 already stops on a Group Policy execution policy; a home PC has neither.
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
| Not in the plan | `PermitTTY no`; `list-bundles`; the loopback self test; the `console_user` and `boot_time_utc` fields; an outbox limit | The wiki's note on ForceCommand and terminals; a bundle's directory name has to be discoverable; first time success at the PC; the "after a reboot with nobody logged in" acceptance made measurable; the plan's own risk table asks for a cap. |

## Not verified off Windows

There was no Windows machine and no Windows PowerShell 5.1 available when this was built. The following rest on documentation or source reading only. Each has a step that proves it on the real machine, and the checklist names the fallback.

1. The whole of `Install-FrontDoor.ps1` has never run on Windows. Its step logic is tested with every Windows cmdlet mocked; the cmdlets, parameters, and .NET members it uses were checked against PSScriptAnalyzer's Windows PowerShell 5.1 profile, not against a machine.
2. Key sign in for an account with no profile, using a key file under ProgramData with the permissions above. Settled by S13, then A2.
3. That the account, a member of Event Log Readers only, can start `powershell.exe` and read its own layout. Settled by S13.
4. That `cmd.exe /c` runs the forced command line unchanged and that exit codes 64 and 65 reach the client. Settled by S13 and A3 (a warning, not a failure, because the JSON carries the result too).
5. That `sshd -T -C` works on the Windows build and prints what `Test-WfSshdEffectiveConfig` expects. If it cannot run, S9 warns and S13 decides.
6. How `Get-NetFirewallAddressFilter` prints a single remote address (bare or with a mask; both are accepted) and that the port filter to rule association finds the default rule. Settled by S3's read back.
7. That `powercfg /query` ends with the AC and DC values in that order on every display language. If not, S10 warns.
8. The ADSI group enumeration in `Get-WfAccountGroupSid`, and its fallback.
9. `dispatch.ps1` under Windows PowerShell 5.1 specifically: the tests run it under PowerShell 7 on macOS. Known differences were coded around (JSON arrays, encodings, zip entry separators, culture dependent dates), but only S13, A2, and a first real collector prove it.
10. `wevtutil gl Security` and `wevtutil gli Security` as the standard account. This is a measurement (S11, A7), whatever it returns.
11. Whether `Disable-LocalUser` stops key sign in, as the plan states. The checklist's "turn it off" section says to confirm with a `ping` that must fail.
12. Whether the account appears on the Windows sign in screen. Cosmetic; the checklist says it may.
13. The behaviour of the in-box OpenSSH version where it differs from the source commit cited here.

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
