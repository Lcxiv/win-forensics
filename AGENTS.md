# Project agent memory

win-forensics: capture, decode, and correlate Windows performance evidence. Read `README.md` first; it names the four contracts under `docs/contracts/` and the build order the repository follows (phase 0a is done; collectors, decoders for the other tables, analyzers, and the correlator come in later phases and must be built against the contracts, not around them).

## Working rules that are not obvious from the code

- Measurement status and evidence never share a field. A collector that did not run produces no evidence row, not even an absence row; see `docs/contracts/measurement-status.md` section 3 before writing any analyzer or validator logic.
- Every decoded row and every observed evidence row carries the structured provenance object from `schemas/decoded/provenance.schema.json`. Decoders self validate their rows with `scripts/wf_schema.py` before writing; keep that pattern.
- Schemas are hand maintained JSON under `schemas/`, registered by `$id` (see `wf_schema.load_schemas`). Bump `x-schema-version` and the matching `const` in the table's provenance pin together; `tests/test_schemas.py` checks the pin.
- The example bundle under `fixtures/example-bundle/` is regenerated, not edited: run the two decoder commands in `README.md` with `--decoded-at 2026-09-03T00:00:00Z` after changing a decoder, or `tests/test_decoders.py` fails on the stale comparison. `manifest.json`, `verdict.json`, and `evidence.jsonl` there are hand written examples; the tests cross check them against the decoded tables.
- Win-opt (the captain's earlier toolkit, registered read only) is tooling history. Its recorded files are format fixtures only; its findings, numbers, driver names, and causes never appear in prose, schemas, scripts, or tests (`tests/test_docs.py` enforces a denylist). Thresholds cite Microsoft or tool documentation.
- Documents are plain prose with no em or en dashes (also enforced by `tests/test_docs.py`).
- Nothing captured from a real machine is committed; `.gitignore` excludes bundles, captures, and trace, dump, and log extensions. Only `fixtures/` holds synthetic bundles and format fixtures.

## Process Monitor facts to rely on

Settled on the GitHub hosted Windows runner with committed fixtures; read `docs/contracts/procmon-facts.md` before touching anything Process Monitor related. Short form: only `/Runtime` bounds a run and its expiry exits with code 1; stack capture is unconditional and has no `.pmc` setting; the CSV column set is exactly the loaded configuration's column selection in its order, `TID` and `Duration` appear only when selected, `Sequence` is `n/a` in exports, stacks are XML only; configuration is sticky in the registry, so always pass `/LoadConfig`. The committed `.pmc` files come from `scripts/make_procmon_pmc.py` (needs the `procmon-parser` dev extra).

## Environment

Python 3.12 or later (`python3.12 -m venv .venv`, `pip install -e ".[dev]"`, `pytest`). The only CI job is `.github/workflows/procmon-facts.yml`; do not add other CI before phase 2.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
