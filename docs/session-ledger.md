# The session and incident ledger

One table puts every play session and every incident of one machine on one timeline, and a second table sums them per configuration period: hours played, sessions, and incidents by type, each count beside its denominator and its coverage. The point is to judge a change to the PC by hours played under it, not by memory. This document is the method; the tables are sections 5.23 and 5.24 of [decoded-tables.md](contracts/decoded-tables.md), and what the collector reads, with its citations, is "The session-ledger sources" in [collectors/windows/README.md](../collectors/windows/README.md).

## The split between the PC and the Mac

The PC side is one collector, `session-ledger`, read only and history only. It lists the names, sizes and times of the game and launcher log files, the live kernel dump, minidump and Windows Error Reporting folders, reads the display adapters' driver service names and that driver's System log records, and reads the WerKernel channel. It never opens a log or a dump, never waits for a game, and never touches a game process: it is run between sessions, as the account that plays, and finishes in seconds.

Everything else happens on the Mac, in `scripts/build_session_ledger.py`:

- joining several bundles (the ledger bundle with the `bugcheck-history`, `tdr-events`, `application-errors` and `whea-errors` bundles) and several runs of each;
- removing the duplicates two collectors or two runs produce;
- placing every entry in an operator's configuration period;
- deciding whether a rate may be given.

The reasons for the split:

1. The rules that turn file times into sessions, and the rules for when a rate is honest, will change as the PC answers the verification items. On the Mac they change with a rebuild of the committed bundles; on the PC each change would need a new pinned commit and a new run.
2. The collector stays inside the interface every collector shares (one summary line, a status per source, a bundle that verifies), so the SSH dispatcher and the bundle checks need nothing new.
3. A join across bundles needs all of them at once. Only the Mac has them all.
4. Nothing the ledger needs is read twice on the PC. The history collectors already export Kernel-Power 41, bug check 1001, the `Display` provider, application crashes and hangs, Windows Error Reporting 1001 and WHEA records; the ledger joins their exports.

## What was joined and what was read anew

| Incident type | From | Joined or new |
|---|---|---|
| `kernel_power_41` (with `bugcheck_code` from the named `BugcheckCode` item) | `bugcheck-history` `system_restart_events`, `tdr-events` `system_bugcheck_events` | joined |
| `bugcheck_1001` | the same two sources, provider `Microsoft-Windows-WER-SystemErrorReporting` | joined |
| `display_4101`, `display_event` | `tdr-events` `system_display_events` | joined |
| `app_crash_1000`, `app_hang_1002`, `wer_1001`, `dotnet_1026` | `application-errors` `application_error_events` | joined |
| `whea_event` | `whea-errors` `system_whea_events` | joined |
| `display_driver_event` | `session-ledger` `display_driver_events` | new |
| `werkernel_event` | `session-ledger` `werkernel_events` | new |
| `live_kernel_report`, `minidump` | `session-ledger` `live_kernel_reports`, `minidumps` | new (names, sizes and times only) |
| `wer_report_queued`, `wer_report_archived` | `session-ledger` `wer_report_queue`, `wer_report_archive` | new (folder names as pseudonyms, the kind word, times) |

The other records `bugcheck-history` exports (6006, 6008, 6009, 1074, 46, 7045) are not incidents here; they stay in that bundle. `reliability-records` is not joined: it repeats the records above under another key, with no field to deduplicate on.

## Play sessions

A session is one log file of a game or launcher (Overwatch, Fortnite, the Battle.net desktop app, the Epic Games Launcher), from its file times. No source here records a session; the times are inferences, and the row says so:

- `start_utc` is the file's creation time, `start_basis` `file_creation_time`, `start_inferred` true. Whether a log is created at launch is verification item 94.
- `end_utc` is the file's last write time, `end_basis` `file_last_write_time`, `end_inferred` true. A game stops writing before it exits, and a session that ends in a freeze ends at the last write before it; either way the end is not a recorded exit.
- `duration_s` is the difference, set only when both are known and `session_check` is `ok`.

Only `.log` files at the top of a title's folder count. Overwatch's `Errors` folder and `.txt` files are listed in the bundle and not counted as sessions.

`session_check` takes three other values, each of which leaves the start and the duration null:

- `creation_shared`: two logs of one title in one bundle have the same creation time. File name tunnelling gives a file created under a name that was just renamed or deleted the old file's creation time ([MS-FSA, tunnel cache](https://learn.microsoft.com/openspecs/windows_protocols/ms-fsa/69f1cc34-20d8-4889-8108-e871065cf9f9); [FsRtlAddToTunnelCache](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtladdtotunnelcache)), which is what a game that renames its log to a backup and opens a new one under the old name would see (item 95). The decision is taken over every bundle, not per bundle, so a purged backup cannot hand its start to the next log: the log written first among all the bundles keeps its start; the others lose it.
- `replaced_in_place`: a later bundle shows the same log (the identity below) smaller, or last written earlier, than an earlier bundle did. It is not the same file grown, so its start cannot be trusted.
- `end_before_start`: the two times disagree.

Across bundles, one log is one row: the identity is the title and the creation time, plus the last write time when two logs of that title share the creation time in any bundle. The name is not part of it, because a game that renames its log to a backup between two runs keeps the file's times and changes its name, and a pseudonym is salted per run. The row shows the latest bundle's observation, its file name included, and `observations` counts the bundles that saw it. Its `entry_id` is a hash of that identity, an event's by log, record id, provider, event id and time, a dump file's by kind, folder, extension, size and creation time, and a report folder's by kind, name prefix and creation time. Ids are stable across rebuilds except for a session whose creation time first becomes shared when a bundle is added: that log is re-keyed with its last write time, so its id changes.

A known limitation follows from the same rule. A log that grew between two runs and was later renamed beside a tunnelled successor (a launcher left open across a collector run, then restarted) is matched by its last write time once its creation time is shared, so it can appear as an `ok` row ending at the earlier observation plus a `creation_shared` row for the same file: its session can end early and appear twice. A game rotates its log at launch, while it is closed, so the hours of a tracked game should not be affected, only launcher rows; whether that holds for Fortnite and the Epic Games Launcher is item 95, and a fix is under Follow-up.

Process Lasso's log is not read. Bitsum does not document its line format ([logging](https://bitsum.com/apps/process-lasso/docs/interface/logging/)), and an allowlist parser needs one; it is under Follow-up.

## Incidents

An event row is identified by its log, record id, provider, event id and time, so a Kernel-Power 41 exported by both `bugcheck-history` and `tdr-events`, or by two runs, is one row with `observations` 2. A dump is identified by its kind, its component folder (when kept), its extension, its size and its creation time; a report folder by its kind, its kind word and its creation time.

`bugcheck_code` is read only from the record's named `BugcheckCode` data item, decimal as Windows writes it ([event 41](https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart)); a record without the name leaves it null rather than trusting a position. Learn says a 41 with `BugcheckCode` 0 and `PowerButtonTimestamp` 0 is a power cut or a hang the machine did not report, which is the freeze this ledger is for.

`image_name` is copied only when a crash or hang record names one of the four game and launcher images on the allowlist in the builder (item 105); any other program's name stays out, and its crash is still counted.

## Configuration periods

The operator writes the periods file (`schemas/input/config_periods.schema.json`; example `fixtures/session-ledger/periods.json`): a format and version, a `revision` raised at every edit, optionally the `machine_id` of the bundles, the tracked games (`overwatch`, `fortnite`; their hours are every rate's denominator), and the periods in order, each with an id, a label such as "TdrLevel 0" or "TdrLevel 3 plus WER on", a start and an end with an explicit offset, and an optional note. Periods do not overlap; only the last may be open, and an open period ends at the capture start of the latest `session-ledger` bundle (`end_is_as_of`). The builder copies the file byte for byte into its output, so the summary's provenance names the exact revision it used.

An entry belongs to the period that holds its start, or its end when the start is unknown, start inclusive.

## The period summary and when a rate is given

Each period row carries the hours played by the tracked games (the parts of sessions with a known duration that fall inside the period), the sessions, the sessions without a duration, and per title the play coverage: the span from the oldest log that title's folder still holds to the bundle's capture start, unioned over bundles. Per incident type it carries the count, the count basis, the incident coverage, the hours played beside it, and `per_hour` or the reason it is withheld.

Count basis:

- `complete`: the source's provider is documented and the collector proves its coverage (the event sources' `raw_time_range`), so a count over a fully covered period is a count of everything Windows logged.
- `found_only`: the provider is a working assumption (`Display`, the driver's service name, WerKernel), so the records found are real and the records not found are not proven absent. Never a rate.
- `snapshot`: files present when the collector ran. Windows may have removed earlier dumps and reports, so never a rate.
- `not_measured`: no input covers the period. The count is null, never zero.

A rate is given only when the count basis is `complete`, the incident coverage of the period is full, every tracked game's play coverage is full, no session in the period lacks a duration, and the hours played are above zero. Otherwise `per_hour` is null and `withheld_reason` says which condition failed. The count and the hours stand beside the rate either way, so a reader can see that one freeze in nine hours is not a measured rate of 0.11 per hour with any confidence; the ledger reports the numbers and makes no claim about their spread.

## Refusals

The builder writes nothing (`decode_failed`, exit code 2) when:

- an input bundle does not match its manifest (`scripts/verify_bundle.py`);
- an input is from a collector it does not join;
- two bundles share an id, or the bundles come from more than one machine;
- the periods file fails its schema, names another machine, repeats an id, has a period that ends before it starts, periods out of order or overlapping, or an open period before the last;
- the output directory exists and is not empty.

Without a `session-ledger` bundle there are no sessions to place, and the result is `not_collected` with nothing written. A ledger with no rows is `observed_zero` only when some input was observed, and `not_collected` otherwise.

## Privacy

The collector never writes a resolved profile path, the profile name or the account name: folders are written as tokens (`<MyDocuments>\Overwatch\Logs`), names outside a plain pattern become salted `name-<12 hex>` pseudonyms, the helper records the running account only as two booleans (elevated, member of Event Log Readers), never its name, and an exception's text is never copied. The ledger copies only the artifacts it read and adds no name the bundles did not hold. `tests/test_session_ledger.py` checks that the profile name of the synthetic scenario reaches neither the bundles nor the ledger.

## Running it

```
python scripts/build_session_ledger.py \
    --bundle <session-ledger bundle> [--bundle <another session-ledger bundle> ...] \
    --bundle <bugcheck-history bundle> --bundle <tdr-events bundle> \
    --bundle <application-errors bundle> --bundle <whea-errors bundle> \
    --periods <periods.json> --out <empty output directory>
```

The output holds `inputs.json` (each bundle with its manifest SHA-256 and source statuses), `raw/config_periods/periods.json`, `raw/inputs/<bundle id>/` (each manifest and the artifacts read, byte copies, so every row's provenance points inside the output and its hash can be checked there), and the two tables with their sidecars.

## Follow-up

- Process Lasso's log through an allowlist parser, once Bitsum documents the line format or a committed synthetic sample is accepted as the format fixture.
- A `collect-session-ledger` route in the SSH dispatcher. The dispatcher runs as the collector account, whose profile holds no game logs, so it needs a design that runs as the player without storing the player's credential; until then the collector is run by hand at the PC.
- Fortnite session starts when item 95 shows tunnelling: a source that records the launch itself (a line inside the log, which would need a reader of the log text and its own privacy review).
- A log that grew between runs and was later renamed beside a tunnelled successor: match it to its earlier observation by name and size growth instead of its last write time, once item 95 shows how the Fortnite and Epic Games Launcher rotation behaves.
- An analyzer that compares periods: the summary gives counts and hours; a judgement of whether a change helped needs a stated model for rare events and enough hours, and belongs in an analyzer with its own contract.
- Reliability Monitor records, once a key to deduplicate them against the event exports is settled.
