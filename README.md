# win-forensics

Capture, decode, and correlate Windows performance evidence to root-cause gaming stutters and hitches, with every analysis step testable off the gaming PC.

Three layers, connected by a bundle contract:

- capture: thin Windows-only collectors (WPR, counters, event log, powercfg, process inventory, PresentMon, Process Monitor) that start, stop, verify, and checksum their own artifacts.
- decode: Windows-only decoders (TraceProcessing, wpaexporter, xperf, cdb, Process Monitor export) that emit versioned typed tables with provenance.
- analyze: portable correlation and reporting that consumes decoded tables and never re-derives meaning from raw traces.

The contract between them is the bundle: manifest, immutable raw artifacts, decoded tables, evidence rows, and a verdict with a coverage table. Measurement status is kept separate from evidence, so a subsystem that was not observed can never be cleared.

Bundles captured from a real machine are never committed here; only schemas, code, synthetic fixtures, and format fixtures live in this repository.

## Where this repository is in the build

This is phase 0a of the build order in the captain's implementation plan (kept outside this repository under `firstmate/data/win-opt-framework/implementation-plan.md`, with the research and review history in `plan.md` next to it). Phase 0a writes the four contracts everything else depends on, settles three Process Monitor facts with committed runner fixtures, and lays out one example bundle. There are no live capture collectors, analyzers, or correlator yet; those are phases 1 to 4. The only CI job is the Process Monitor fact finding workflow.

One set of collectors exists ahead of that order, because the captain's plan for reaching the gaming PC over SSH needs it: `collectors/windows/` holds named, read only PowerShell collectors that read history the machine already keeps (bug check and restart events, hardware error events, application crashes and hangs, GPU driver timeouts, reliability records, the driver inventory) as a standard account in Event Log Readers. Each writes a bundle to this contract with every source's measurement status, and `scripts/decode_eventlog.py` decodes the event exports into the `eventlog_events` table. They have never run on Windows; [collectors/windows/README.md](collectors/windows/README.md) lists what is still to be verified on the PC, and what needs Administrator and is therefore left for a later elevated task.

The same directory holds `rf-survey`, a read only survey of the 2.4 GHz band around the desk for a PC that is on Ethernet but drives a wireless mouse and headset: which adapter carries the traffic, which networks are on the air on which channels, where the receivers sit on the USB tree, and which radios are on. Network names and hardware addresses are pseudonymised before anything is written. `scripts/decode_rf_survey.py` decodes it into five typed tables and `scripts/analyze_rf_survey.py` writes evidence rows and a plain language report with a cited recommendation for the router channel, the receiver ports and the unused radios. The method, its limits (a packet capture cannot see RF noise), and the before and after test the owner runs are in [docs/rf-survey.md](docs/rf-survey.md).

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
schemas/                 JSON Schema (draft 2020-12), one file per table, plus manifest, evidence, verdict, common,
                         and analysis/ for an analyzer's structured result
collectors/windows/      read only PowerShell collectors for the PC, their shared helper _common.ps1, and README.md;
                         tests/ holds the Pester suite, the synthetic backend, and the fixture generator
scripts/                 wf_schema.py (schema registry and validation), decode_dpcisr.py, decode_pdh.py, decode_eventlog.py,
                         decode_rf_survey.py and analyze_rf_survey.py (the RF survey tables, evidence rows and report),
                         verify_bundle.py (manifest, checksums, no unlisted raw file), fetch_pwsh.sh (PowerShell 7 into tools/),
                         make_procmon_pmc.py, procmon_facts.ps1 and procmon_facts_summarize.py (runner harness)
fixtures/example-bundle/ one bundle laid out to the contract from two win-opt format fixtures
fixtures/collector-bundles/  synthetic bundles written by the collectors against the synthetic backend, one per case
fixtures/procmon/        committed .pmc test configurations and the runner's facts and export heads
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

An `rf-survey` bundle is decoded and analysed with:

```
python scripts/decode_rf_survey.py --bundle <bundle directory>
python scripts/decode_eventlog.py --bundle <bundle directory>
python scripts/analyze_rf_survey.py --bundle <bundle directory>
```

The result is `reports/rf-survey.md` inside the bundle, with its evidence rows in `evidence.jsonl`.

The collector checks that need PowerShell (PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility rules, the Pester suite, fixture freshness) run from `tests/test_collectors_pwsh.py` and skip when no `pwsh` is found. `scripts/fetch_pwsh.sh` fetches a pinned PowerShell 7 and the two modules into `tools/`, which git ignores.

## What the fixtures are and are not

The bundles in `fixtures/collector-bundles/` are synthetic from end to end: the real collector scripts wrote them, but every event, record, driver, and machine detail in them is invented in `collectors/windows/tests/SyntheticScenarios.ps1`. They exist to prove the layout, the manifest, the checksums, and the status rules, and they are regenerated, not edited.

The two raw files in `fixtures/example-bundle/raw/` are win-opt's recorded `xperf -a dpcisr` report and per CPU PDH counter CSV. They are format fixtures: they prove that the readers parse those shapes and that provenance can point at a real line and cell. No number, module name, or conclusion inside them is treated as a finding, and none is used as an example or threshold in the contracts. Thresholds in later playbooks come from Microsoft and tool documentation only.

## Reaching the gaming PC

`remote-access/` holds the SSH front door from the captain's plan for reaching the gaming PC from his Mac: an elevated, idempotent setup script he runs once at the PC, the dispatcher that is the only thing the dedicated standard account can run (an exact allowlist: a health check, named collectors, and fetching a finished bundle with its SHA-256), the Mac side scripts for the key, the host key pin, the acceptance checks, and the transfer, the three action flow (one Mac command, one double click at the PC, one Mac command) that orchestrates them, and the checklist he follows. No agent runs any of it against the PC. Start with [remote-access/README.md](remote-access/README.md), which carries the design, its sources, and the list of what is still unverified on Windows; the person at the PC follows [remote-access/CHECKLIST.md](remote-access/CHECKLIST.md). `tests/test_remote_access.py` covers it and skips its PowerShell parts when no `pwsh` is found.
