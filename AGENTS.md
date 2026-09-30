# Project agent memory

win-forensics: capture, decode, and correlate Windows performance evidence. Read `README.md` first; it names the four contracts under `docs/contracts/` and the build order the repository follows (phase 0a is done, and the read only history collectors for the gaming PC are in `collectors/windows/`; the live capture collectors, decoders for the other tables, analyzers, and the correlator come in later phases and must be built against the contracts, not around them).

## Working rules that are not obvious from the code

- Measurement status and evidence never share a field. A collector that did not run produces no evidence row, not even an absence row; see `docs/contracts/measurement-status.md` section 3 before writing any analyzer or validator logic.
- Every decoded row and every observed evidence row carries the structured provenance object from `schemas/decoded/provenance.schema.json`. Decoders self validate their rows with `scripts/wf_schema.py` before writing; keep that pattern.
- Schemas are hand maintained JSON under `schemas/`, registered by `$id` (see `wf_schema.load_schemas`). Bump `x-schema-version` and the matching `const` in the table's provenance pin together; `tests/test_schemas.py` checks the pin.
- The example bundle under `fixtures/example-bundle/` is regenerated, not edited: run the two decoder commands in `README.md` with `--decoded-at 2026-09-03T00:00:00Z` after changing a decoder, or `tests/test_decoders.py` fails on the stale comparison. `manifest.json`, `verdict.json`, and `evidence.jsonl` there are hand written examples; the tests cross check them against the decoded tables.
- Win-opt (the captain's earlier toolkit, registered read only) is tooling history. Its recorded files are format fixtures only; its findings, numbers, driver names, and causes never appear in prose, schemas, scripts, or tests (`tests/test_docs.py` enforces a denylist). Thresholds cite Microsoft or tool documentation.
- Documents are plain prose with no em or en dashes (also enforced by `tests/test_docs.py`).
- Nothing captured from a real machine is committed; `.gitignore` excludes bundles, captures, and trace, dump, and log extensions. Only `fixtures/` holds synthetic bundles and format fixtures.

## Collectors that run on the PC

`collectors/windows/README.md` is the authority: the interface shared with the SSH dispatcher, what each collector reads with its Microsoft citation, how status is decided, what needs elevation, and the list of facts nobody has verified on Windows yet. No agent ever runs anything against the captain's PC. Rules that are easy to break:

- The scripts target Windows PowerShell 5.1 and have only ever run under PowerShell 7 with the Windows adapters replaced (`collectors/windows/tests/SyntheticBackend.ps1`). A change to an adapter at the bottom of `_common.ps1` is untested by construction; add the fact it relies on, with its citation, to the README's verification list.
- Keep every `.ps1` plain ASCII (5.1 reads a file without a byte order mark in the ANSI code page), never use `ConvertTo-Json` in the helper (its default depth is 2, and Windows PowerShell writes a wrapped array as an object with `value` and `Count`, which cannot be tested here; use `ConvertTo-WfJson`), and never use `$script:` variables there (the helper is dot sourced into other files).
- A collector prints one JSON line on stdout and nothing else, stays read only, and records an unreadable source as a status with a reason, never as an empty export. `tests/test_collectors_static.py` holds the forbidden command list.
- After changing a collector or the helper, regenerate `fixtures/collector-bundles/` with `collectors/windows/tests/New-FixtureBundles.ps1`; the content is invented in `SyntheticScenarios.ps1`. `scripts/fetch_pwsh.sh` puts PowerShell 7, Pester and PSScriptAnalyzer under `tools/` (ignored), and `tests/test_collectors_pwsh.py` skips without them, so run it before claiming the collectors pass.

## Process Monitor facts to rely on

Settled on the GitHub hosted Windows runner with committed fixtures; read `docs/contracts/procmon-facts.md` before touching anything Process Monitor related. Short form: only `/Runtime` bounds a run and its expiry exits with code 1; stack capture is unconditional and has no `.pmc` setting; the CSV column set is exactly the loaded configuration's column selection in its order, `TID` and `Duration` appear only when selected, `Sequence` is `n/a` in exports, stacks are XML only; configuration is sticky in the registry, so always pass `/LoadConfig`. The committed `.pmc` files come from `scripts/make_procmon_pmc.py` (needs the `procmon-parser` dev extra).

## SSH front door

`remote-access/README.md` is the authority for the path from the captain's Mac to the PC: the setup script's steps with their citations, the dispatcher's verbs, exit codes and transfer framing, where it departs from the plan, and the facts nobody has verified on Windows. No agent ever runs any of it against the PC. Rules that are easy to break:

- `dispatch.ps1` takes no parameters, reads no variable but `SSH_ORIGINAL_COMMAND`, and compares the client's string against an exact allowlist; it never evaluates it or hands it to a shell. `remote-access/tests/Dispatch.Tests.ps1` checks this by running it as sshd would, with injected requests, arguments, and environment variables.
- The wire protocol has four readers that must change together: `dispatch.ps1`, `mac/wf-fetch.sh`, `mac/wf-acceptance.sh`, and the stand-in `ssh` in `tests/test_remote_access.py`. The outbox directory name travels as `bundle_dir`; the `bundle_id` in a bundle's manifest is the authoritative id and can differ.
- The setup script's result is PASS, INCOMPLETE (a verification could not run; exit 2; no Mac handoff), or FAIL (exit 1). Firewall and sshd failures fail closed: sshd stopped and set to manual start. Keep that shape; a warning never stands in for a check that did not run.
- Every setup step id (`S1`...) needs a row in `CHECKLIST.md` under "If a step fails", and every acceptance check (`A1`...) an explanation there; a test enforces both. A new assumption about Windows goes on the README's "Not verified off Windows" list with a step that proves it on the PC.
- The Windows scripts target Windows PowerShell 5.1 and have only run under PowerShell 7 here: keep them ASCII, write files sshd reads without a byte order mark (`Write-WfTextFile`), collect function output with `@(...)` before `ConvertTo-Json`, and format dates with the invariant culture. `pytest tests/test_remote_access.py` skips the Pester suite and the analyzer when no `pwsh` is found (`$WF_PWSH`, `PATH`, `tools/pwsh`), so make sure they ran before claiming the scripts pass.
- The captain facing flow is three actions (`mac/wf-start.sh`, double click `windows/SETUP-PC.cmd`, `mac/wf-finish.sh`) that only orchestrate the scripts above; keep new behaviour in the underlying script and the entry points thin. The kit code (left-most 32 hex characters of the zip's SHA-256, 8 groups of 4) has two implementations that must agree, `wf_kit_code` in `mac/wf-common.sh` and `Get-WfKitCode` in `windows/Start-FrontDoorSetup.ps1`, checked against one oracle in `tests/test_remote_access.py`. `SETUP-PC.cmd` is the one CRLF file; the launcher must work before anything from the zip is trusted, so it loads `WfCommon.ps1` and `WfSetupLib.ps1` only after the code matched. The README's "Threat model of the two integrity checks" states what the launcher's check does not prove; do not describe it as stronger than that.

## Environment

Python 3.12 or later (`python3.12 -m venv .venv`, `pip install -e ".[dev]"`, `pytest`). The only CI job is `.github/workflows/procmon-facts.yml`; do not add other CI before phase 2.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
