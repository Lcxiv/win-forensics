# win-forensics

Capture, decode, and correlate Windows performance evidence to root-cause gaming stutters and hitches, with every analysis step testable off the gaming PC.

Three layers, connected by a bundle contract:

- capture: thin Windows-only collectors (WPR, counters, event log, powercfg, process inventory, PresentMon, Process Monitor) that start, stop, verify, and checksum their own artifacts.
- decode: Windows-only decoders (TraceProcessing, wpaexporter, xperf, cdb, Process Monitor export) that emit versioned typed tables with provenance.
- analyze: portable correlation and reporting that consumes decoded tables and never re-derives meaning from raw traces.

The contract between them is the bundle: manifest, immutable raw artifacts, decoded tables, evidence rows, and a verdict with a coverage table. Measurement status is kept separate from evidence, so a subsystem that was not observed can never be cleared.

Bundles captured from a real machine are never committed here; only schemas, code, synthetic fixtures, and format fixtures live in this repository.

## Where this repository is in the build

This is phase 0a of the build order in the captain's implementation plan (kept outside this repository under `firstmate/data/win-opt-framework/implementation-plan.md`, with the research and review history in `plan.md` next to it). Phase 0a writes the four contracts everything else depends on, settles three Process Monitor facts with committed runner fixtures, and lays out one example bundle. Apart from the three live captures and the clock calibration session described below, there are no live capture collectors, analyzers, or correlator yet; those are phases 1 to 4. The only CI job is the Process Monitor fact finding workflow.

One set of collectors exists ahead of that order, because the captain's plan for reaching the gaming PC over SSH needs it: `collectors/windows/` holds named, read only PowerShell collectors that read history the machine already keeps (bug check and restart events, hardware error events, application crashes and hangs, GPU driver timeouts, reliability records, the driver inventory) as a standard account in Event Log Readers. Each writes a bundle to this contract with every source's measurement status, and `scripts/decode_eventlog.py` decodes the event exports into the `eventlog_events` table. [collectors/windows/README.md](collectors/windows/README.md) records what has run on the PC so far, lists what is still to be verified there, and names what needs Administrator and is therefore left for a later elevated task.

It also holds the first live capture, `dpcisr-trace`: one bounded Windows Performance Recorder session from a committed profile (kernel Interrupt, DPC and Loader events, no stacks, no process or thread events), under its own WPR instance name, stopped and confirmed on every exit path, with the final events lost and buffers lost read from the saved trace by the inbox `tracerpt` and, when the operator names a hash pinned `xperf.exe`, the `xperf -a dpcisr` report that `scripts/decode_dpcisr.py` turns into the per CPU, per module tables. The trace itself never leaves the PC: a kernel trace carries the machine's hardware and network addresses in its configuration events, so it is read on the machine and removed. `scripts/decode_tracestats.py` decodes the status text and the summary into the `tracestats` table so the loss is readable without the tools' wording, and null never becomes zero. Kernel tracing needs an elevated account, so the collector refuses the front door's standard account and says so; the report half that needs the Windows Performance Toolkit on the PC waits for a decision on which build to pin ([collectors/windows/README.md](collectors/windows/README.md), "The dpcisr-trace sources").

It also holds a second live capture, `presentmon-frames`: Windows Performance Recorder records the ETW providers and event ids PresentMon needs into a file on the PC for a bounded window, under the collector's own instance name (stopped on every exit path, any loss from the controller or the file failing the capture), and an operator supplied, pinned PresentMon console binary (verified by SHA-256 before the recording and again before it runs) reads that file offline with `--etl_file` and prints the CSV the bundle keeps; the recording is deleted on the PC because a merged trace can carry network addresses. PresentMon as run opens no process; whether WPR does is a verification item, not a claim. `scripts/decode_presentmon.py` decodes the CSV and the recording record into the `presentmon_frames` table. The pinned version, every option and provider with its citation, why PresentMon never runs live, the elevation question, and the anti-cheat position are in the same README.

A third live capture, `diskio-trace`, answers what reads from and writes to disk while the PC is in use: one bounded Windows Performance Recorder session from its own profile (kernel DiskIO, Filename, HardFaults and ProcessThread events, no stacks, no FileIO until a pilot measures its volume), under its own instance name, stopped and confirmed on every exit path, any lost event failing the capture. The trace is read on the PC by the inbox `tracerpt`, aggregated there into one second bins per process, directory, disk and operation, and deleted with its dump: file paths, command lines and the machine's addresses never leave the PC, directories keep a fixed root and one level below it in clear and become per run salted pseudonyms deeper down, and the bundle keeps only the aggregate, the rules and the hashes that show the trace existed and was removed. `scripts/decode_diskio.py` decodes it into the `diskio_activity` table. It runs alone until a second kernel session beside `dpcisr-trace` is verified, and it needs an elevated account ([collectors/windows/README.md](collectors/windows/README.md), "The diskio-trace sources").

The same directory holds `clock-calibration`, the clock session collector: for a bounded session it records the calibration triples the timestamp contract asks for (performance counter, system time, performance counter, at the start, every 5 s and at the stop), and it gives the person at the PC a mark command for a second console that stamps "I felt it here" with the same counter the kernel trace uses, without touching the game. `scripts/decode_clock.py` fits the contract's piecewise model on the Mac, writes the `clock_pairs`, `clock_segments` and `operator_marks` tables, and is the library a correlator uses to place a system time stamp on the master clock with its error bound and to refuse a join the calibration cannot support. Method, the deviation from the contract's named precise time API and the limits are in [docs/clock-calibration.md](docs/clock-calibration.md).

The same directory holds `rf-survey`, a read only survey of the 2.4 GHz band around the desk for a PC that is on Ethernet but drives a wireless mouse and headset: which adapter carries the traffic, which networks are on the air on which channels, where the receivers sit on the USB tree, and which radios are on. Network names and hardware addresses are pseudonymised before anything is written. `scripts/decode_rf_survey.py` decodes it into five typed tables and `scripts/analyze_rf_survey.py` writes evidence rows and a plain language report with a cited recommendation for the router channel, the receiver ports and the unused radios. The method, its limits (a packet capture cannot see RF noise), and the before and after test the owner runs are in [docs/rf-survey.md](docs/rf-survey.md).

It also holds `config-snapshot`, the first piece of the live latency capture: the machine configuration that confounds every run, read before and after a capture (`-Snapshot start`, `-Snapshot stop`). It records each PCI function's interrupt affinity policy and MSI mode as the registry holds them, read through the documented device key API (type and bytes, decoded alongside, never reconciled with the routing a trace shows), the GPU timeout detection values, the CPU counts and caches with the SMT sibling map from `GetLogicalProcessorInformationEx`, the active power scheme with the AC and DC processor and idle settings, and the state of two third party tuning tools (installed files with versions and hashes, running components by process name, protected copies of their configuration and journal, and a summary of the vendor log that carries none of its text). Two questions it cannot answer with a documented read only path (which power mode overlay is active, the current timer resolution) are recorded `not_collected` with their reasons rather than guessed. `scripts/decode_config_snapshot.py` decodes a bundle into `config_snapshot`, `powercfg` and `process_inventory`.

## Changes to the PC

`changes/windows/` holds the only code in this repository that changes a Windows machine, kept apart from the read only collectors: one self-contained script per change, run by hand at the PC, elevated, only on the captain's own word for that change. Each script has explicit verbs (`-Plan`, the default, and `-Readback` only read; `-Apply` and `-Undo` change, and only when named), saves every affected key with `reg export`, a values CSV and their SHA-256 before it writes and refuses without that, restores exactly the saved before-state on undo, and ends every apply and undo with a PASS or FAIL readback per value. Nothing in `collectors/`, the scenario runner or `remote-access/` may reference the area or call a change script, and a test enforces it. The rules, the facts still to verify on the PC and the tests are in [changes/windows/README.md](changes/windows/README.md).

The first change, `kbd-crash-dump`, sets Microsoft's documented keyboard initiated crash (`CrashOnCtrlScroll` for USB and PS/2 keyboards, or the alternate `Dump1Keys` and `Dump2Key` for a keyboard without SCROLL LOCK), so a hard freeze can be ended with stop error 0xE2 and a memory dump instead of a power off. It takes effect after a restart, which the script never makes. The operator page, with the key sequence, what to expect, what to do after the reboot and what it cannot do, is [docs/kbd-crash-dump.md](docs/kbd-crash-dump.md).

## The four contracts

| Contract | Document | Schemas |
|---|---|---|
| Timestamps: clock domain per source, calibration pairs, per source affine model with error bounds, ETW QPC as master, per playbook alignment tolerance and refused joins | [docs/contracts/timestamps.md](docs/contracts/timestamps.md) | calibration section of `schemas/manifest.schema.json`, `clock_fit` and `join` in `schemas/common.schema.json` |
| Decoded tables: one versioned schema per table with a required structured provenance column | [docs/contracts/decoded-tables.md](docs/contracts/decoded-tables.md) | `schemas/decoded/*.schema.json` |
| Measurement status, evidence, and verdict: the status vocabulary, the rule that only `observed_zero` with adequate coverage may support absence, the evidence row, the verdict with its coverage table | [docs/contracts/measurement-status.md](docs/contracts/measurement-status.md) | `schemas/common.schema.json`, `schemas/evidence.schema.json`, `schemas/verdict.schema.json` |
| Bundle: layout, manifest, and the two validation levels (container integrity, evidentiary adequacy) | [docs/contracts/bundle.md](docs/contracts/bundle.md) | `schemas/manifest.schema.json` |

Process Monitor facts settled on the GitHub hosted Windows runner, with the fixtures they rest on: [docs/contracts/procmon-facts.md](docs/contracts/procmon-facts.md) and `fixtures/procmon/`.

## Layout

```
docs/contracts/          the contracts above plus procmon-facts.md
docs/rf-survey.md        the RF survey: method, limits, citations, and the before and after test
docs/clock-calibration.md  the clock calibration session and operator marks: how the clocks are read, the fit, the limits
docs/kbd-crash-dump.md   operator page for the keyboard crash dump change: the key sequence, what to expect, the limits
schemas/                 JSON Schema (draft 2020-12), one file per table, plus manifest, evidence, verdict, common,
                         and analysis/ for an analyzer's structured result
collectors/windows/      read only PowerShell collectors for the PC, their shared helper _common.ps1, and README.md;
                         tests/ holds the Pester suite, the synthetic backend, and the fixture generator
changes/windows/         the change scripts that write to the PC (run by hand, elevated, on the captain's word), their
                         README.md with the rules and the facts to verify, and tests/ with each one's synthetic backend
scripts/                 wf_schema.py (schema registry and validation), decode_dpcisr.py, decode_pdh.py, decode_eventlog.py,
                         decode_tracestats.py (trace loss from the recorder's status text and the tracerpt summary),
                         decode_presentmon.py (the presentmon_frames table from a presentmon-frames bundle),
                         decode_diskio.py (the diskio_activity table from a diskio-trace bundle),
                         decode_rf_survey.py and analyze_rf_survey.py (the RF survey tables, evidence rows and report),
                         decode_config_snapshot.py (config_snapshot, powercfg and process_inventory from a config-snapshot bundle),
                         decode_clock.py (the clock calibration tables, the fitted model, alignment and join refusal),
                         verify_bundle.py (manifest, checksums, no unlisted raw file), fetch_pwsh.sh (PowerShell 7 into tools/),
                         make_procmon_pmc.py, procmon_facts.ps1 and procmon_facts_summarize.py (runner harness)
fixtures/example-bundle/ one bundle laid out to the contract from two win-opt format fixtures
fixtures/collector-bundles/  synthetic bundles written by the collectors against the synthetic backend, one per case
fixtures/procmon/        committed .pmc test configurations and the runner's facts and export heads
fixtures/presentmon/     the first buffer of a PresentMon regression recording (the one .etl git keeps), with its
                         provenance and licence
tests/                   pytest: schemas, decoders, the example bundle, collector bundles and scripts, documentation
                         hygiene, procmon fixtures
.github/workflows/       procmon-facts.yml only
```

## Running the checks

Python 3.12 or later.

```
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The decoders are plain scripts:

```
python scripts/decode_dpcisr.py --bundle fixtures/example-bundle --source raw/dpcisr/xperf_analysis.txt --decoded-at 2026-09-03T00:00:00Z
python scripts/decode_pdh.py --bundle fixtures/example-bundle --source raw/pdh/percpu_dpc_20260424_slow.csv --decoded-at 2026-09-03T00:00:00Z
```

`tests/test_decoders.py` fails when the committed decoded tables in the example bundle differ from a fresh decode, so re-run the two commands after changing a decoder.

A bundle a collector wrote on the PC is checked and decoded on the Mac with:

```
python scripts/verify_bundle.py <bundle directory>
python scripts/decode_eventlog.py --bundle <bundle directory>
```

A `dpcisr-trace` bundle is decoded with:

```
python scripts/decode_tracestats.py --bundle <bundle directory>
python scripts/decode_dpcisr.py --bundle <bundle directory> --source raw/dpcisr_report/dpcisr.txt
```

The first reads the final trace loss out of the tracerpt summary and the recorder's status text; the second needs the report a pinned `xperf` produced on the PC, and refuses a source the manifest does not list.

An `rf-survey` bundle is decoded and analysed with:

```
python scripts/decode_rf_survey.py --bundle <bundle directory>
python scripts/decode_eventlog.py --bundle <bundle directory>
python scripts/analyze_rf_survey.py --bundle <bundle directory> [--own-network <your Wi-Fi network's name as saved on the PC>]
```

The result is `reports/rf-survey.md` inside the bundle, with its evidence rows in `evidence.jsonl`. Without `--own-network` the report describes the airspace and recommends nothing about the router, because the analysis never guesses which network is yours; with it, every access point of that network is aggregated and a channel is recommended.

A `presentmon-frames` bundle is decoded with:

```
python scripts/decode_presentmon.py --bundle <bundle directory>
```

It reads the collector's record of the recording (clock, loss counts, the confirmed stop) and PresentMon's CSV for the frames, writes `decoded/presentmon_frames.jsonl` with its sidecar, or reports `not_collected` and writes nothing when the capture did not happen.

A `diskio-trace` bundle is decoded with:

```
python scripts/decode_tracestats.py --bundle <bundle directory>
python scripts/decode_diskio.py --bundle <bundle directory>
```

The first reads the trace loss as for `dpcisr-trace`; the second checks the aggregate against the manifest and the collector's record (zero loss, a confirmed stop, the performance counter clock, the trace and dump removed, every event read) and writes `decoded/diskio_activity.jsonl` with its sidecar, or reports `not_collected` and writes nothing when no aggregate was made.

A `clock-calibration` bundle is fitted with:

```
python scripts/decode_clock.py --bundle <bundle directory> [--align 2026-03-01T12:00:17Z --source-resolution-100ns 10000 --tolerance-100ns 100000]
```

which writes the three clock tables and prints the master clock, and with `--align` places a UTC stamp on it with its bound or says why it cannot.

A `config-snapshot` bundle is decoded with:

```
python scripts/decode_config_snapshot.py --bundle <bundle directory>
```

The collector checks that need PowerShell (PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility rules, the Pester suite, fixture freshness) run from `tests/test_collectors_pwsh.py` and skip when no `pwsh` is found; the change scripts' checks run the same way from `tests/test_change_kbd_crash_dump.py`. `scripts/fetch_pwsh.sh` fetches a pinned PowerShell 7 and the two modules into `tools/`, which git ignores.

## What the fixtures are and are not

The bundles in `fixtures/collector-bundles/` are synthetic from end to end: the real collector scripts wrote them, but every event, record, driver, and machine detail in them is invented in `collectors/windows/tests/SyntheticScenarios.ps1`. They exist to prove the layout, the manifest, the checksums, and the status rules, and they are regenerated, not edited.

The two raw files in `fixtures/example-bundle/raw/` are win-opt's recorded `xperf -a dpcisr` report and per CPU PDH counter CSV. They are format fixtures: they prove that the readers parse those shapes and that provenance can point at a real line and cell. No number, module name, or conclusion inside them is treated as a finding, and none is used as an example or threshold in the contracts. Thresholds in later playbooks come from Microsoft and tool documentation only.

The one file in `fixtures/presentmon/` is a format fixture from the PresentMon project's own regression tests, not a capture from any machine this project measures; [fixtures/presentmon/PROVENANCE.md](fixtures/presentmon/PROVENANCE.md) records where it comes from and its licence.

## Reaching the gaming PC

`remote-access/` holds the SSH front door from the captain's plan for reaching the gaming PC from his Mac: an elevated, idempotent setup script he runs once at the PC, the dispatcher that is the only thing the dedicated standard account can run (an exact allowlist: a health check, named collectors, and fetching a finished bundle with its SHA-256), the Mac side scripts for the key, the host key pin, the acceptance checks, and the transfer, the three action flow (one Mac command, one double click at the PC, one Mac command) that orchestrates them, and the checklist he follows. No agent runs any of it against the PC. Start with [remote-access/README.md](remote-access/README.md), which carries the design, its sources, and the list of what is still unverified on Windows; the person at the PC follows [remote-access/CHECKLIST.md](remote-access/CHECKLIST.md). `tests/test_remote_access.py` covers it and skips its PowerShell parts when no `pwsh` is found.
