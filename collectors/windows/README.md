# Windows collectors

Named, read only PowerShell collectors, one per question. Each writes one bundle that follows [docs/contracts/bundle.md](../../docs/contracts/bundle.md) and records measurement status the way [docs/contracts/measurement-status.md](../../docs/contracts/measurement-status.md) requires: a source the account could not read becomes a status with a reason, never an empty result that could be read as "nothing happened".

They run on the Windows PC as a dedicated standard account that is a member of Event Log Readers, started over SSH by a forced command dispatcher. The dispatcher, the setup script, and the transport belong to the front door work and live outside this directory. Nothing here needs or asks for Administrator. The questions that do are listed under "Needs elevation" and wait for the elevated scheduled task.

Version 1.0.0 (`Get-WfCollectorsVersion` in `_common.ps1`; each collector also carries its own version, recorded in the manifest as the scenario version).

## Interface

A collector is a standalone script for Windows PowerShell 5.1:

```
powershell.exe -NoProfile -NonInteractive -File <install directory>\<name>.ps1 -OutputDirectory <path>
```

- `<name>` matches `^[a-z][a-z0-9-]{1,40}$`. The shared helper `_common.ps1` must be installed next to the collectors; its name starts with an underscore so it can never match that pattern and can never be dispatched. Every file a collector needs at run time is a `.ps1` file directly in this directory. The `tests` subdirectory is not needed on the PC.
- `-OutputDirectory` is the one parameter the dispatcher passes. The collector writes the bundle into it (creating it when it does not exist) and writes nowhere else, not even to the temp folder. It refuses a directory that already holds a `manifest.json` or a `raw` directory, because `raw/` is immutable after capture.
- It never prompts. `-OutputDirectory` is deliberately not declared `Mandatory`, because a missing mandatory parameter makes an interactive session prompt; a missing value is reported as a failure instead.
- The last and only line on stdout is the summary: `{"collector":"<name>","status":"ok|partial|failed","bundle":"<OutputDirectory>","artifacts":<count>}`. It is plain ASCII (other characters are written as JSON escapes), so console code pages cannot damage it. `bundle` is the `-OutputDirectory` value exactly as given and `artifacts` is the number of files listed in the manifest. The same line is stored in `logs/summary.json`, also when the run fails after the directory was laid out (then `logs/collector.log` says what happened and no manifest exists). A directory the collector refuses, or cannot create, gets nothing.
- Diagnostics go to stderr and to `logs/collector.log`.
- The exit code is the script's own `exit`, which `powershell.exe -File` returns as the process exit code ([about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)). A dispatcher that uses `-Command` instead would flatten every failure to 1 and must add `exit $LASTEXITCODE` itself.

| Summary status | Exit code | Meaning |
|---|---|---|
| `ok` | 0 | The bundle is complete and every source is `observed` or `observed_zero`. |
| `partial` | 0 | The bundle is complete as a container (manifest written, every artifact checksummed). At least one source is `observed` or `observed_zero` and at least one is not; the manifest says which and why, and `capture.incomplete` is true. |
| `failed` | 1 | No source is `observed` or `observed_zero`, or the bundle could not be written. When a manifest could be written it is still there and still valid, and it records the reason per source. |

Optional parameters, for a person running a collector by hand (the dispatcher passes none, so the defaults are what runs):

| Parameter | Default | Meaning |
|---|---|---|
| `-WindowDays` | 30 | How far back to read, 1 to 365. Not on `driver-inventory`, which is a snapshot. |
| `-MaxEvents` | 5000 (20000 for `driver-inventory`) | Cap on records per source, 1 to 100000. |
| `-MaxArtifactBytes` | 67108864 (64 MiB) | Cap on the size of one export, 1 MiB to 1 GiB. It is enforced against the bytes actually written, never estimated. |
| `-TimeoutSeconds` | 300 | Deadline for reading one source, 1 to 3600. Every read runs under it: the event log query, the oldest record probe, the WMI query with its operation timeout, and `wevtutil`. A read that does not finish in time is `capture_failed`. |
| `-SkipEvtx` | off | Event log collectors only: do not attempt the binary `wevtutil` export. |

A value outside its range produces a `failed` summary and no bundle.

## Collectors

| Collector | Question | Reads | Why a standard account in Event Log Readers can read it |
|---|---|---|---|
| `bugcheck-history` | Did Windows stop with a bug check or shut down uncleanly, and what changed around it? | System channel, event ids 41, 46, 1001, 1074, 6006, 6008, 6009, 7045 ([restart history](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs), [event 41](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart)) | The default System log descriptor ends `(A;;0x1;;;S-1-5-32-573)`, read for Event Log Readers ([Eventlog key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)) |
| `whea-errors` | Did the Windows Hardware Error Architecture report corrected or uncorrected hardware errors? | System channel, provider `Microsoft-Windows-WHEA-Logger`, every event id ([querying hardware error events](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/querying-the-system-event-log-for-hardware-error-events)) | Same System log descriptor |
| `application-errors` | Which applications crashed or stopped responding, and with what fault? | Application channel: `Application Error` 1000, `Application Hang` 1002, `Windows Error Reporting` 1001, `.NET Runtime` 1026 ([Microsoft's crash and hang query](https://learn.microsoft.com/en-us/azure/azure-local/manage/disconnected-operations-security), [crash troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior), [.NET Runtime 1026](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/site-behavior-performance/process-termination-crash)) | The default Application log descriptor ends `(A;;0x1;;;S-1-5-32-573)` (same page) |
| `tdr-events` | Did the GPU driver time out, and did Windows recover the display or stop with a bug check? | System channel, two sources: provider `Display` (recovered timeouts, see the verification list) and event ids 41 and 1001 (bug check 0x116 VIDEO_TDR_FAILURE, [documented here](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x116---video-tdr-failure)) | Same System log descriptor |
| `reliability-records` | What does Reliability Monitor hold: failures, installs, and the stability index over time? | WMI classes [Win32_ReliabilityRecords](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/racwmiprov/win32-reliabilityrecords) and [Win32_ReliabilityStabilityMetrics](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/racwmiprov/win32-reliabilitystabilitymetrics) in `root\cimv2` | Authenticated Users have Enable Account (read) on WMI namespaces by default ([Access to WMI namespaces](https://learn.microsoft.com/en-us/windows/win32/wmisdk/access-to-wmi-namespaces)); see the verification list |
| `driver-inventory` | Which drivers are installed, in which versions, from which providers, and which kernel drivers are running? | WMI classes [Win32_PnPSignedDriver](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394354(v=vs.85)) and [Win32_SystemDriver](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemdriver) in `root\cimv2` | Same WMI default |

Event Log Readers is the documented grant: "Members of this group can read event logs from local computers" ([security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)). An SSH session keeps the privileges of the account that authenticated and adds none ([SSH remoting](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell)), so the group membership is the whole authorisation. A machine can carry a different descriptor than the documented default (a `CustomSD` value or a policy), which is why each event log source also records the channel's actual security descriptor when the account may read it.

Deliberate omissions inside those questions: event ids 12, 13 and 19 from Microsoft's restart history list are left out of `bugcheck-history` because many providers share them; the `Microsoft-Windows-Kernel-WHEA` channels are not read because Microsoft Learn documents neither their content nor their access; per application crash dumps belong to the later step that sets the Windows Error Reporting dump keys.

## What a bundle contains

`-OutputDirectory` is the bundle root. The dispatcher creates and names that directory, so its name need not be the bundle id; `bundle_id` in the manifest is authoritative (`<UTC start>_<collector name with underscores>_<first 8 characters of the machine id>`).

```
<OutputDirectory>/
  manifest.json                  schemas/manifest.schema.json; one collectors[] entry per source
  raw/<source id>/query.xml      event log source: the exact structured query (role config)
  raw/<source id>/channel_state.json   what the channel held and how it is configured (role report)
  raw/<source id>/events.json    structured export, a JSON array, oldest record first (role primary)
  raw/<source id>/events.evtx    binary export from wevtutil, when it succeeds (role other)
  raw/<source id>/query.json     WMI source: class, namespace, properties, WQL filter, window, caps (role config)
  raw/<source id>/records.json   WMI export, a JSON array (role primary)
  logs/collector.log             what the collector did
  logs/summary.json              the stdout line
```

A collector writes capture output only. It never writes `decoded/`, `evidence.jsonl`, `verdict.json`, or `validation.json`.

Every file under `raw/` is listed in the manifest with its byte count and SHA-256. The list is built by reading the directory after the source finishes, not from what the code meant to write, so an unlisted raw file cannot occur.

`events.json` elements carry the columns of `schemas/decoded/eventlog_events.schema.json` under the same names (`record_id`, `log_name`, `provider_name`, `event_id`, `version`, `level`, `level_display`, `task`, `task_display`, `opcode`, `keywords`, `time_created_utc`, `machine_name`, `user_id`, `process_id`, `thread_id`, `message`, `properties`) plus `xml`, the complete event XML from `EventRecord.ToXml()`. `time_created_utc` is the `SystemTime` attribute of that XML, cut to seven fractional digits. `message`, `level_display` and `task_display` depend on publisher metadata and locale and are null when Windows cannot render them. The XML is complete for every element of a successful primary export: a record whose XML cannot be produced stops the source, which becomes `capture_failed` and leaves no `events.json`. `scripts/decode_eventlog.py` turns these files into the `eventlog_events` table with `index:<n>;record:<id>` provenance; it decodes only primary artifacts the manifest lists for an observed event log collector, refuses a path that is missing, unlisted, or outside the bundle, and writes nothing in that case.

`records.json` elements are the requested properties of the WMI instance under their WMI names (only the documented properties the collector names are requested, so the provider hands over nothing else), with dates as ISO 8601 UTC text and string arrays kept as arrays. The driver export is shaped so a later decoder can emit `config_snapshot` rows of category `driver` (one row per device and property, `index:<n>` provenance), and `driver-inventory` also fills `machine.drivers` in the manifest from `Win32_PnPSignedDriver`.

`channel_state.json` holds the record count, the oldest retained record's number and time, the file size, the log mode, the maximum size, the isolation, and the security descriptor, each null when the account may not read it, plus which of the requested providers are registered on the machine.

The manifest's machine section is filled from `Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, `Win32_Processor`, `Win32_VideoController`, `Win32_BIOS` and `Win32_BaseBoard`, null where a value cannot be read. `machine_id` is cut from a SHA-256 of the SMBIOS UUID (or of the host name when the UUID is unreadable), so it is stable and carries no readable identifier. The real host name is written, as the bundle contract decides; redaction is a later step. `tools[]` lists the PowerShell host, `wevtutil.exe`, the collector script and the helper, each with the SHA-256 of the bytes on disk, which is how a bundle states which version of a collector wrote it.

## How status is decided

Each source gets exactly one measurement status, decided by the collector from what it saw.

| Status | When |
|---|---|
| `observed` | The read finished within the deadline and the caps, every record was exported completely, and there is at least one. |
| `observed_zero` | The read finished, zero records matched, and a record at or before the window start is known to be retained (for a channel, its oldest record; for a WMI history, one row found by a separate bounded probe). That condition is the proof of a quiet window: a log that wrapped or was cleared looks exactly like a quiet one. |
| `not_collected` | The source could not be opened: the account lacks read access, or the preflight failed another way. The entry carries the message from Windows. No export file is written. |
| `unsupported` | The channel or class does not exist on this machine. |
| `capture_failed` | The read started and failed; or it did not finish before the deadline; or it stopped at a record that could not be exported completely; or the export reached a cap; or zero records matched and there is no proof of coverage (the channel is empty, the probe did not complete); or zero records matched on a source whose provider Microsoft does not document (`tdr-events`, provider `Display`, until verified); or a snapshot class returned no instances. |

A failed source leaves no primary export behind, with one exception: an export cut at a cap is kept, because it is a complete set as far as it goes, and the status reason says it was capped. Nothing under `raw/` can therefore be read as "zero records" unless the source is `observed_zero`. A read that timed out or stopped at an incomplete record has its partial export removed.

The range a status speaks for is `raw_time_range` in the manifest entry. It starts at the requested window start, or at the oldest retained record when the log does not reach back that far. In that second case `enabled.options.window_start_utc` differs from `requested.options.window_start_utc`, a note in the manifest and on stderr says so, and nothing is claimed before that time. This is an interpretation of the contract worth stating: the status describes what the collector saw over the range it names, and the later validator's adequacy check ("raw time ranges cover the scenario window") is what refuses a bundle whose range is too short for the question asked of it.

The query interval is fixed before the query runs. The collector takes one end time, `window_end_utc`, and writes it into the query as a FILETIME literal: `timediff(@SystemTime, <end>) >= 0 and timediff(@SystemTime, <end>) <= <window in ms>` selects exactly the interval from `window_end_utc` minus the window to `window_end_utc`. `timediff` with a literal second argument is the documented form ([Consuming events](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)); the same page says a result set also receives matching events raised while it is enumerated, which is why the interval has an upper bound. `requested.options.window_start_utc` and `window_end_utc` are that interval, and `raw_time_range` ends at `window_end_utc`. For a WMI history the same interval is a WQL filter on the time property with CIM DATETIME literals, and the coverage probe asks for one row before the window start.

Every read is bounded. Event log records are pulled one at a time with `EventLogReader.ReadEvent(TimeSpan)` carrying the time left before the source deadline; the oldest record probe uses the same call once. A pull that returns nothing after the deadline has passed is treated as a timeout, not as end of stream, because the two cannot be told apart. WMI reads run under `Get-CimInstance -OperationTimeoutSec` and are streamed through the caps, so a provider that never stops producing is cut at `-MaxEvents` or `-MaxArtifactBytes`; a producer stopped that way is `capture_failed` with the capped rows kept.

The binary `.evtx` export is secondary. When `wevtutil epl` fails or exceeds the byte cap, the file is removed, the failure is recorded in `enabled.options` and in the notes, and the source's status is unchanged, because `events.json` already holds the complete XML of every record.

## Needs elevation

Not implemented here. Each of these is for the later elevated scheduled task, which runs a fixed script and copies specific files into a directory the collector account can read.

| Question | What it needs | Evidence that it needs elevation |
|---|---|---|
| Kernel crash dumps | `%SystemRoot%\Minidump\*.dmp` and `%SystemRoot%\MEMORY.DMP`, the locations Microsoft documents ([memory dump collection](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/stop-code-error-troubleshooting)) | Microsoft Learn documents the locations but not their access control list. The approved plan treats them as Administrator only. Verify with `icacls C:\Windows\Minidump` and `icacls C:\Windows\MEMORY.DMP` at the PC before building the task. |
| Live kernel dumps for GPU timeouts | `%SystemRoot%\LiveKernelReports` (codes 0x117, 0x141, 0x142 are live dump codes; [reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/kernel-live-dump-code-reference)) | The directory "is managed by the OS and will be created ... with the proper permissions" ([DTrace live dump](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace-live-dump)); those permissions are not documented. Verify with `icacls C:\Windows\LiveKernelReports`. |
| Security log | The Security channel | "users can read and clear the Security log if they have been granted the SE_SECURITY_NAME privilege" ([Event logging security](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)); Event Log Readers is not documented as enough. It also carries the owner's logon history, so reading it is a privacy decision, not only a technical one. |
| Storage reliability counters | `Get-PhysicalDisk \| Get-StorageReliabilityCounter` (`MSFT_StorageReliabilityCounter` in `Root\Microsoft\Windows\Storage`; [cmdlet](https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter)) | Microsoft Learn does not state the rights the cmdlet needs. The approved plan treats it as Administrator only. Verify by running that line as the collector account; if it returns counters, a non elevated `storage-health` collector can be added here. |
| Disk check | `chkdsk` | "Membership in the local Administrators group, or equivalent, is the minimum required to run chkdsk" ([chkdsk](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk)). With `/f` or `/r` it also repairs, which is outside read only collection. |
| System file check | `sfc /verifyonly` | "You must be logged on as a member of the Administrators group to run this command" ([sfc](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sfc)). |
| Per application crash dumps | Keys under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<process>.exe`, and read access to the dump folder | "Enabling the feature requires administrator privileges" ([Collecting user-mode dumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps)). The default folder is `%LOCALAPPDATA%\CrashDumps` in the crashing user's profile, which another standard account cannot read. Out of scope until the front door has landed. |

## Facts to verify on the PC

Nothing in this directory has run on Windows. The scripts pass PSScriptAnalyzer's Windows PowerShell 5.1 compatibility rules and the portable logic is tested with synthetic data, but each item below can only be settled at the PC. None of them needs an agent to touch the machine: the captain runs the step and reads the result.

| # | Unverified | How to check at the PC | If it fails |
|---|---|---|---|
| 1 | The scripts run under Windows PowerShell 5.1 as written. Only static analysis covers 5.1 here. | Run one collector by hand as the collector account: `powershell.exe -NoProfile -NonInteractive -File <install directory>\whea-errors.ps1 -OutputDirectory <empty directory>`. Expect one JSON line and exit code 0. Then run `python scripts/verify_bundle.py <bundle>` on the Mac copy. | The error on stderr names the line. Report it; it is a bug in this directory. |
| 2 | The collector account, in an SSH key session, holds Event Log Readers and can read System and Application. The default descriptors grant it; this machine's may differ. | Over SSH as that account: `whoami /groups` lists `BUILTIN\Event Log Readers`. As an administrator: `wevtutil gl System` and `wevtutil gl Application` show a `channelAccess` containing `(A;;0x1;;;S-1-5-32-573)`. After a run, `raw/<source>/channel_state.json` shows `readable: true`. | The source is `not_collected` with the message from Windows and the collector exits 1. Group membership takes effect at the next logon, so reconnect first; then compare `channelAccess` with the default. |
| 3 | `wevtutil epl <query file> <file> /sq:true /ow:true` works for a non administrator writing into the output directory, with a query file in UTF-8 without a byte order mark, and accepts the `timediff(@SystemTime, <FILETIME>)` form in the file. Microsoft documents the syntax, not the rights. | After a run, `enabled.options.evtx_exported` is true and `events.evtx` is listed. | Nothing is lost: `events.json` holds the full XML and the status is unchanged. The note in the manifest carries `wevtutil`'s exit code and message. |
| 4 | Recovered GPU timeouts are logged in the System log by a provider named `Display`. Microsoft documents that the message is logged, not where. | As an administrator: `wevtutil gp Display /ge:true /gm:true` lists the publisher and an event whose message says the display driver stopped responding and has recovered. Or, in Event Viewer, filter the System log by source Display. | Until it is confirmed, `tdr-events` reports an empty Display result as `capture_failed` and the summary as `partial`; bug check 0x116 is still covered by the second source. When it is confirmed, set `QuietClaimVerified = $true` in `tdr-events.ps1`. If the provider has another name, change the predicate and the citation. |
| 5 | `Win32_ReliabilityRecords` and `Win32_ReliabilityStabilityMetrics` can be read by a standard account, the policy "Configure Reliability WMI Providers" is on (the documented default on Windows client), and the provider accepts the WQL filter on `TimeGenerated` with CIM DATETIME literals (Microsoft documents the literal format, not this provider's filter support; WMI applies a filter the provider cannot when it can). | As the collector account: `Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '20260101000000.000000+000'" -Property TimeGenerated -OperationTimeoutSec 60 \| Select-Object -First 1`. Then run `reliability-records` by hand and time it. | The source is `not_collected`, `unsupported`, or `capture_failed` with the provider's message; a filter the provider rejects shows as `capture_failed` on both sources. The question then moves to the elevated task. |
| 6 | `Win32_PnPSignedDriver` and `Win32_SystemDriver` can be read by a standard account in an SSH session with only the named properties requested, and how long `Win32_PnPSignedDriver` takes on this machine. | Run `driver-inventory` by hand and time it. | Same as 5; a property name the class does not have shows as `capture_failed` with the provider's message. |
| 7 | The standard account may read channel configuration (`EventLogConfiguration`: log mode, maximum size, security descriptor) and the provider list (`EventLogSession.GetProviderNames`). | `channel_state.json` shows non null `log_mode` and `security_descriptor`, and the manifest shows `enabled.providers`. | Those fields are null. No status depends on them. |
| 8 | The registry values `UBR`, `DisplayVersion` and `EditionID` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` exist. Microsoft Learn does not document these names. | The manifest's `machine.os` shows them. | They are null; nothing else changes. |
| 9 | Through `sshd`, stdout carries exactly the one summary line with no byte order mark or wrapping. | From the Mac: `ssh <host> collect-whea-errors \| python3 -c "import json,sys; print(json.loads(sys.stdin.read()))"`. | The summary is also in `logs/summary.json` inside the bundle. |
| 10 | Exporting the default cap of 5000 records finishes within the default `-TimeoutSeconds` of 300 under 5.1 (the JSON writer is PowerShell code and every record is serialised as it is read). | Time `application-errors` and `reliability-records` on the PC. | A source that runs out of time is `capture_failed` with the count it had reached. Lower `-MaxEvents` or `-WindowDays`, or raise `-TimeoutSeconds`, in the dispatcher's call. |
| 12 | What `EventLogReader.ReadEvent(TimeSpan)` does when its time runs out: Microsoft documents the argument as the maximum time before the operation is cancelled, not whether the call then returns null or throws. The collector treats both as a timeout. | Nothing to check unless a source reports a timeout; then `logs/collector.log` and the status reason show which form it took. | Both forms give `capture_failed`; neither can produce a false quiet window. |
| 13 | `Get-CimInstance -OperationTimeoutSec` ends a read of a provider that does not answer, and the error it raises is classified as a timeout. | Nothing to check unless a WMI source reports a failure. | An unclassified error is `capture_failed` with the provider's message, which is the same outcome. |
| 11 | Rendered messages are available in a session started by `sshd`. | `events.json` elements have a non null `message`. | `message` is null; the XML and `properties` are complete. |

Two further decisions belong to the front door, not to this directory, and the collectors only depend on them: the dispatcher must start a collector with `-File` so the exit code survives, and the scripts are unsigned, so the dispatcher's execution policy choice must allow them.

## Read only posture

The collectors read event channels, read WMI classes, read a few registry values, and hash files. They change no setting, clear no log, start no service, open no network connection, and touch no process. The only program they start is `wevtutil.exe` with the `epl` (export) verb, directly and without a shell. The only files they delete are their own exports inside the output directory (an `.evtx` that failed or exceeded the cap, a `records.json` that exceeded the cap). `tests/test_collectors_static.py` enforces this list. They do not inspect, attach to, or enumerate game processes; nothing here interacts with a running game or its anti-cheat.

## Testing

No test here touches a Windows machine.

```
pytest                         schema, layout, checksum and decoder tests over fixtures/collector-bundles
scripts/fetch_pwsh.sh          one time: a pinned PowerShell 7 plus Pester and PSScriptAnalyzer into tools/ (ignored by git)
pytest tests/test_collectors_pwsh.py
```

- `tests/test_collector_bundles.py` validates the committed synthetic bundles against `schemas/manifest.schema.json`, checks every artifact's size and SHA-256, and decodes the event exports into `eventlog_events`.
- `tests/test_collectors_static.py` checks the interface, the read only posture, the ASCII rule (Windows PowerShell 5.1 reads a script without a byte order mark in the ANSI code page), and that this document covers every collector.
- `tests/test_collectors_pwsh.py` needs `pwsh` and skips without it. It runs PSScriptAnalyzer with the 5.1 compatibility rules, the Pester suite in `tests/Collectors.Tests.ps1`, a fresh generation of the fixture bundles compared with the committed ones, and the unmodified scripts as processes on a machine with no Windows API, where every source must fail closed.
- The Pester suite replaces the Windows adapters at the bottom of `_common.ps1` with `tests/SyntheticBackend.ps1`. Everything above the adapters (layout, manifest, checksums, status, summary, exit code) is exercised as it will run; the adapters themselves are not.

After changing a collector or the helper, regenerate the fixtures from the repository root:

```
tools/pwsh/pwsh -NoProfile -File collectors/windows/tests/New-FixtureBundles.ps1
```

The fixture content is invented in `tests/SyntheticScenarios.ps1`. Nothing captured from a real machine is ever committed.
