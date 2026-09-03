# win-forensics

Capture, decode, and correlate Windows performance evidence to root-cause gaming stutters and hitches, with every analysis step testable off the gaming PC.

Three layers and one contract:

- capture: thin Windows-only collectors (WPR, counters, event log, powercfg, process inventory, PresentMon, Process Monitor) that start, stop, verify, and checksum their own artifacts.
- decode: Windows-only decoders (TraceProcessing, wpaexporter, xperf, cdb, Process Monitor export) that emit versioned typed tables with provenance.
- analyze: portable correlation and reporting that consumes decoded tables and never re-derives meaning from raw traces.

The contract between them is the bundle: manifest, immutable raw artifacts, decoded tables, evidence rows, and a verdict with a coverage table. Measurement status is kept separate from evidence, so a subsystem that was not observed can never be cleared.

Bundles captured from a real machine are never committed here; only schemas, code, synthetic fixtures, and format fixtures live in this repository.

## Where this repository is in the build

This is phase 0a of the build order in the captain's implementation plan (kept outside this repository under `firstmate/data/win-opt-framework/implementation-plan.md`, with the research and review history in `plan.md` next to it). Phase 0a writes the four contracts everything else depends on, settles three Process Monitor facts with committed runner fixtures, and lays out one example bundle. There are no collectors, analyzers, or correlator yet; those are phases 1 to 4. The only CI job is the Process Monitor fact finding workflow.

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
schemas/                 JSON Schema (draft 2020-12), one file per table, plus manifest, evidence, verdict, common
scripts/                 wf_schema.py (schema registry and validation), decode_dpcisr.py, decode_pdh.py,
                         make_procmon_pmc.py, procmon_facts.ps1 and procmon_facts_summarize.py (runner harness)
fixtures/example-bundle/ one bundle laid out to the contract from two win-opt format fixtures
fixtures/procmon/        committed .pmc test configurations and the runner's facts and export heads
tests/                   pytest: schemas, decoders, the example bundle, documentation hygiene, procmon fixtures
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

## What the fixtures are and are not

The two raw files in `fixtures/example-bundle/raw/` are win-opt's recorded `xperf -a dpcisr` report and per CPU PDH counter CSV. They are format fixtures: they prove that the readers parse those shapes and that provenance can point at a real line and cell. No number, module name, or conclusion inside them is treated as a finding, and none is used as an example or threshold in the contracts. Thresholds in later playbooks come from Microsoft and tool documentation only.
