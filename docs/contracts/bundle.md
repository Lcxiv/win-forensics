# Bundle contract

Status: phase 0a, version 1.0.0. Schema: `schemas/manifest.schema.json`. Companion contracts: [timestamps.md](timestamps.md), [decoded-tables.md](decoded-tables.md), [measurement-status.md](measurement-status.md).

## 1. Layout

A bundle is one directory named by its id, `<yyyymmddThhmmssZ>_<scenario>_<machine id short>`, with the UTC capture start first so bundles sort by time.

```
<bundle_id>/
  manifest.json          written once by the orchestrator when the privileged session closes
  raw/                   immutable; one subdirectory per collector id; every file listed in the manifest with sha256 and byte count
    wpr/trace.etl
    wpr/tracestats.txt
    wpr/dpcisr.txt
    pdh/counters.csv
    eventlog/system.json
    procmon/capture.pml
    procmon/capture.csv
    procmon/filter.pmc
    ...
  decoded/               written by decoders after capture; one <table>.jsonl (or .parquet) plus <table>.meta.json per table
  evidence.jsonl         written by analyzers
  verdict.json           written by the correlator
  validation.json        written by the validator; copied into verdict.json
  logs/                  collector and decoder stdout and stderr, one file per step
```

Rules:

- `raw/` is append only during capture and read only afterwards. A decoder that needs a derived file writes it under `decoded/`, never under `raw/`. Re running a decoder replaces its own outputs and nothing else.
- Every file under `raw/` appears in the manifest under exactly one collector, with its role (`primary`, `log`, `config`, `report`, `other`), byte count, and sha256. A file under `raw/` that the manifest does not list fails container integrity.
- Committed configuration that shaped a capture (a `.wprp` profile, a `.pmc` filter, a counter list) is copied into `raw/<collector>/` at capture time and hashed, so the bundle carries the exact bytes that ran, not a path into a repository at some later revision.
- Bundles captured from a real machine are never committed to this repository. `.gitignore` excludes `bundles/`, `captures/`, and raw trace, dump, and log extensions. `fixtures/` holds synthetic bundles and format fixtures only.

## 2. The manifest

`manifest.json` is the capture time record. It never changes after the orchestrator writes it; decode and analysis results go into sidecars, `evidence.jsonl`, and `verdict.json`. Its sections, all required:

- `manifest_version`, `bundle_id`, `created_utc`.
- `scenario`: id and version of the scenario file, requested duration, target process name, and the hotkey marks recorded during capture (label, UTC time, and the QPC reading at the mark).
- `capture`: start and stop, orchestrator and version, whether the session was elevated, and `incomplete` (true when an optional collector failed).
- `machine`: an opaque stable `machine_id`, hostname (may be null when redacted), the exact OS (caption, version, build, UBR, display version, architecture, edition), CPU name, logical processor count and `QueryPerformanceFrequency`, memory, every GPU with driver version and date, BIOS vendor and version and release date, board, the driver inventory the scenario asked for (name, version, provider, class), and the time zone with its UTC offset and DST state at capture time.
- `collectors[]`: one entry per collector the scenario listed, whether or not it ran. Each entry records: id and kind; whether it was required; its measurement status and reason; the preflight result with each check; the exact command line; start and stop; exit code; configuration and filter hashes; requested versus enabled providers, keywords, stack walking, counters, and options, with `enabled.verified_by` naming the tool output that proved it (for example `wpr -profiledetails` or `xperf -a tracestats`); events lost; buffer configuration; the artifacts it produced; the raw time range in its native domain; the scenario expectation it was held to and whether it met it; and the target process lifetime when it was scoped to one.
- `calibration`: status, method text, QPC frequency, the expected number of pairs, the pairs themselves (sequence, phase, `qpc_before`, `qpc_after`, `filetime_utc_100ns`), the count of missing pairs, the system time adjustment record at start and stop, and the boot time.
- `tools[]`: every tool that ran, with version, path, and sha256 of the executable when it could be read.
- `symbols`: symbol path, cache path, and dbghelp version.
- `checksum_algorithm`: `sha256`.
- `notes[]`: free text written by the operator or the orchestrator.

The manifest schema requires most fields to be present even when unknown, with null as the value, so that a reader can tell "the orchestrator did not know" from "the orchestrator did not try".

## 3. Two validation levels

`Validate-Bundle` (a later phase) writes `validation.json` with two independent results, and the verdict copies both.

Container integrity asks whether the bundle is what it says it is:

1. `manifest.json` validates against the manifest schema.
2. Every artifact listed exists with the listed byte count and sha256; no file under `raw/` is unlisted.
3. Every decoded table has a sidecar; both validate; the sidecar's source files match manifest artifacts by path and hash; the row count matches the file.
4. Every decoded row validates against its table schema, and its provenance names a manifest artifact and the table it sits in (provenance completeness).
5. `evidence.jsonl` validates; every provenance entry points at an existing decoded row; every link resolves.
6. `verdict.json` validates, and every hypothesis evidence id resolves.

Evidentiary adequacy asks whether what was captured is good enough to draw conclusions from, collector by collector, using the definition of adequate coverage in [measurement-status.md](measurement-status.md) section 3:

1. Required collectors are `observed` or `observed_zero`; any other status refuses the bundle.
2. Preflight ok for every collector that ran.
3. Requested settings equal enabled settings, as verified from tool output.
4. Events lost is zero or within the scenario's declared bound.
5. Calibration has at least two pairs, the expected count within the scenario's tolerance for missing pairs, and no segment flagged as a clock step inside the scenario window.
6. Raw time ranges cover the scenario window.
7. Target processes were alive across the window where required.
8. Each collector's expectation (for example a minimum sample count, the presence of expected CPUs in the per CPU table, at least one present per second while a presenting process exists, at least one Process Monitor event per second on the filtered paths) was met.

Outcomes: `refused` when integrity fails or a required collector fails adequacy; `incomplete` when only optional collectors fail adequacy; `complete` otherwise. A refused bundle is never analyzed for a verdict; the failure is the finding, and `verdict.json` is written with `outcome = refused` and an empty hypothesis list so the report has something to render.

## 4. The example bundle

`fixtures/example-bundle/` is a bundle laid out to this contract using two of win-opt's recorded files as format fixtures: an `xperf -a dpcisr` report and a PDH per CPU counter CSV. Its manifest is hand written and marks every other collector `not_collected` with the reason that this is a format fixture assembled on a Mac, not a capture; its calibration section has status `not_collected` and no pairs, so every `system_time` table in it is unaligned and its verdict is `no_verdict`. The decoded tables were produced by `scripts/decode_dpcisr.py` and `scripts/decode_pdh.py`, and `tests/` validates every file in the bundle against the committed schemas. Nothing in that bundle is a finding: the numbers and module names inside the raw files are whatever the tools printed on the day they were run, kept only to prove that the readers parse those shapes.

## 5. Open questions

1. Hostname and machine identity in a public repository. The manifest schema allows `hostname` to be null and requires an opaque `machine_id`. Decision: collectors write the real hostname on the capture machine, and a `Redact-Bundle` step (later phase) nulls it before a bundle leaves the machine, so a synced bundle never carries a hostname unless the operator asks for it.
2. Parquet in `decoded/`. Allowed by the decoded tables contract but not exercised by any fixture; the manifest does not need to change when it arrives because decoded outputs are described by sidecars, not by the manifest.
3. Where the scenario's expectations live. The manifest records the expectation text and whether it was met, but the scenario file that defines it is a phase 2 deliverable; until then, `expectation.declared` is free text and `met` may be null.
