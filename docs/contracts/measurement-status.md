# Measurement status, evidence, and verdict contract

Status: phase 0a, version 1.0.0. Schemas: `schemas/common.schema.json` (the status vocabulary), `schemas/evidence.schema.json`, `schemas/verdict.schema.json`. Companion contracts: [timestamps.md](timestamps.md), [decoded-tables.md](decoded-tables.md), [bundle.md](bundle.md).

## 1. The separation this contract enforces

Measurement status answers "did the pipeline watch this subsystem in this window, and how well". Evidence answers "what did the instruments see". The two never share a field. A collector that did not run produces no evidence row of any kind, and in particular it never produces an absence row, because a pipeline that failed to look cannot report that it saw nothing. Every verdict renders its coverage table before its findings so that the first thing a reader learns is what was and was not measured.

## 2. Status vocabulary

Every collector, every decoder, and every analyzer reports exactly one of the following values, in the manifest (collectors), the table sidecar (decoders), and the verdict's coverage table (all three).

| Status | Collector meaning | Decoder meaning | Analyzer meaning |
|---|---|---|---|
| `observed` | Ran with preflight ok, produced its artifact, met its scenario expectation, and the artifact contains at least one event or sample for the window | Consumed the artifact and emitted at least one row | Ran over its inputs and emitted at least one evidence row |
| `observed_zero` | Ran with preflight ok, met every coverage requirement in section 3, and the artifact contains zero events or samples for the window (a genuine quiet window) | Consumed the artifact and emitted zero rows because the artifact was legitimately empty | Ran over adequate inputs and found no signal; emitted zero rows or absence rows only |
| `not_applicable` | The scenario did not request this collector, or its target does not exist on this machine by design (for example a GPU vendor tool on a machine without that vendor's GPU) | The table is not defined for this bundle's collectors | No playbook selected this analyzer, or a required join was refused for alignment (the reason names the join) |
| `not_collected` | The scenario requested it but it was not started: preflight failed, a required collector aborted the run, or the orchestrator skipped it | The decoder's input artifact is absent from the bundle | The analyzer's input table is absent from the bundle |
| `capture_failed` | Started but did not produce a usable artifact: non zero exit, zero bytes, checksum mismatch, events lost above the declared bound, expectation not met, requested settings not enabled, target process not alive across the window | Not used | Not used |
| `decode_failed` | Not used | The tool or decoder failed, the report failed its own consistency check, or the output failed schema validation | Not used |
| `unsupported` | The tool or OS does not support the requested setting on this machine (recorded with the tool's own message) | The decoder does not support this artifact version or tool version | The analyzer does not support this schema version of its input |
| `analyzer_failed` | Not used | Not used | The analyzer raised, exceeded its budget, or emitted rows that failed validation |

Rules:

1. A status is a fact about the pipeline. It is never adjusted to make a verdict possible.
2. `observed_zero` is a claim that requires proof; section 3 says what proof.
3. A collector's status is decided by its own `verify` step, before any decoder runs. A decoder cannot upgrade a collector from `capture_failed` to `observed` by finding some rows.
4. When a status is anything other than `observed` or `observed_zero`, the entry carries `status_reason` text and, where a tool produced one, the tool's exit code or message verbatim.
5. Required collectors that end in `not_collected`, `capture_failed`, or `unsupported` cause bundle validation to refuse the bundle (see [bundle.md](bundle.md)). Optional collectors in those states mark the bundle incomplete and their subsystems unobserved.

## 3. Adequate coverage and the absence rule

A window is adequately covered by a collector when all of the following hold, and the verdict's coverage entry shows each one:

- status is `observed` or `observed_zero`;
- preflight ok;
- requested settings equal enabled settings for providers, keywords, and stack walking (WPR), counters (PDH), filter and column configuration (Process Monitor), and command options (everything else), as verified from the tool's own output, not from the request;
- events lost equal to zero, or below the bound the scenario declares for that collector, with the number recorded;
- no truncation of the raw artifact;
- the raw time range covers the window with margin on both sides;
- the target process, when the collector is scoped to one, was alive for the whole window;
- the collector's clock fit for the window is within the tolerance of every join that uses it (see the timestamp contract), or the analyzer making the claim uses no cross source join.

The absence rule: an evidence row with `evidence_kind = absent` is valid only when its `coverage_ref` names an analyzer and window whose status is `observed_zero` under adequate coverage, and the row's own window lies inside that coverage window. The collector named by the same reference must separately be `observed` or `observed_zero` for the analyzer to have adequate input. Validation rejects any absence row that fails this test. Any other status forbids every exculpatory statement about that subsystem in that window: the report may say "not measured", never "nothing happened".

The same rule applies to inferred rows that rest on absence: an inference whose `links` include an absence row inherits that row's coverage requirement, and the verdict's disconfirmer check for the hypothesis records which coverage it relied on.

## 4. The evidence row

`evidence.jsonl` holds one JSON object per line validating against `schemas/evidence.schema.json`. The row is win-opt's v0 evidence bus row, kept as tooling history, plus the fields the plan adds: `metric` and `payload` so `value` never carries mixed units, a master time with an error bound from the timestamp contract, a `coverage_ref` for absence, and structured provenance instead of a path.

| Field | Type | Meaning |
|---|---|---|
| `row_id` | string | Unique within the bundle |
| `ts_utc` | ISO 8601 UTC | When the signal occurred, in the source's own domain converted to UTC; for an absence row, the start of its window |
| `window` | object or null | `start_utc` and `end_utc`; required for absence rows |
| `t_master_100ns` | integer or null | Master clock time from the correlator's fit; null when the source is unaligned |
| `clock_error_bound_100ns` | integer or null | The bound `e_S` of the source at this timestamp |
| `collected_ts_utc` | ISO 8601 UTC | When the analyzer wrote the row |
| `source` | identifier | The collector id that produced the underlying data |
| `subsystem` | enum | `cpu_dpc`, `gpu`, `storage`, `network`, `power`, `memory`, `display`, `input`, `firmware`, `process`, `scheduling`, `audio`, `crash`, `system` |
| `signal` | identifier | Controlled vocabulary owned by the playbooks; each playbook lists the signals it emits |
| `metric` | identifier | What `value` measures, one unit per metric, listed by the playbook next to the signal |
| `unit` | enum | `100ns`, `us`, `ms`, `s`, `count`, `pct`, `bytes`, `hz`, `ratio`, `bool`, `none` |
| `value` | number, boolean, or null | The measurement in `unit` |
| `severity` | enum | `info`, `warn`, `error`, `critical` |
| `faulting_module` | string or null | Attribution when the source itself names a module; never inferred by the analyzer into this field |
| `cpu` | integer or null | Per CPU index where the signal is per CPU |
| `confidence` | 0 to 1 | Exactly 1 for observed and absent rows; below 1 for inferred rows |
| `evidence_kind` | enum | `observed`, `inferred`, `absent` |
| `coverage_ref` | object or null | `collector_id`, `analyzer_id`, `window`, `status`; required for absence rows |
| `provenance` | array of provenance objects | At least one for observed rows: the decoded rows the observation came from |
| `links` | array of row ids | At least one for inferred rows: the rows the inference rests on |
| `incident_id` | string or null | Groups rows into one incident |
| `analyzer` | object | `id` and `version` of the analyzer that wrote the row |
| `playbook` | identifier or null | The playbook whose rule produced the row |
| `payload` | object | Source specific fields, free form but documented by the playbook |

Validation rules beyond the schema: `provenance[].source_file` must exist in the manifest; `links` must resolve to rows in the same file; `coverage_ref.analyzer_id` must exist in the verdict coverage table with the stated status, and `coverage_ref.collector_id` must exist there with its own `observed` or `observed_zero` status; `metric` and `unit` must match the playbook's declared pairing.

## 5. The verdict and its coverage table

`verdict.json` validates against `schemas/verdict.schema.json`. Its top level is: `outcome` (`verdict`, `no_verdict`, or `refused`), the two validation results copied from the validator, the master clock description, the coverage table, the playbooks evaluated with their disconfirmers, the joins with their tolerances, the ranked hypotheses, the unconsumed data list, and versions.

The coverage table has one entry per collector and one per analyzer. Per collector it records, in this order, exactly the items the plan lists (section 4b, item 4):

1. measurement status and reason;
2. preflight result;
3. applicability;
4. requested versus enabled settings and whether they match;
5. filter hash and configuration hash;
6. target process lifetime;
7. raw and decoded time ranges;
8. row counts at every transformation stage, as an ordered list (raw events, decoded rows, filtered rows, evidence rows);
9. events lost;
10. truncation;
11. stack resolution rate;
12. clock fit: model, offset, rate, largest residual, error bound, pairs used, clock step segments;
13. decoder, decoder version, schema version, tool version;
14. the reason for any unconsumed data.

Per analyzer it records the status and reason, version, input tables with row counts, rows emitted, which playbooks it served, which disconfirmers it checked and their result, which joins it relied on (by id into the verdict's `joins` list, where each join carries the tolerance used and the achieved bound), and unconsumed data.

A hypothesis carries its rank, playbook, subsystem, the symptom subsystem when it differs, the claim, confidence, window, the evidence row ids that support it, and the disconfirmer that was checked with its result. A hypothesis without a checked disconfirmer is not allowed in a `verdict` outcome; it can only appear as a note in a `no_verdict`.

Handoff rule, from the plan: read validation and the coverage table first, then the hypotheses. A verdict that names a cause in a window whose relevant collector is not `observed` is invalid by construction, and the validator enforces it by checking every hypothesis window against the coverage entries of the collectors its evidence rows cite.

## 6. Open questions

1. Analyzer status when a join is refused. The plan's vocabulary has no value for "input present, join refused by alignment". Decision: `not_applicable` with a reason naming the join and its achieved bound, because the analyzer was not wrong and the data was not missing; the refusal is visible in the `joins` list. This keeps status separate from evidence, since no row is written for the refused join.
2. Per window status. The vocabulary is per collector and per analyzer for the bundle; a long capture with a transient loss of events would want a status per window. Decision: a collector whose events lost is non zero reports `capture_failed` for the bundle unless the scenario declared a bound, and the verdict's `unconsumed_data` names the affected span. Finer windows come with the correlator in phase 4, and would add a `windows` array to the coverage entry as a minor schema bump.
3. `faulting_module` on inferred rows. Win-opt's rows put an inferred attribution into `faulting_module`. Decision: only sources that name a module (a bugcheck bucket, a DPC report row) fill it; an analyzer's attribution goes into `payload.attributed_module` with the inference's confidence, so a query on `faulting_module` returns instrument statements only.
