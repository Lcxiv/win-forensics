# Decoded tables contract

Status: phase 0a, version 1.0.0. Companion contracts: [timestamps.md](timestamps.md), [measurement-status.md](measurement-status.md), [bundle.md](bundle.md). Schemas live under `schemas/decoded/`.

## 1. What a decoded table is

A decoded table is the only form in which trace, counter, log, and dump content reaches the analysis layer. Windows tools (TraceProcessing, wpaexporter, xperf actions, cdb, Process Monitor export) read the raw artifacts; a decoder script turns one tool output into one or more typed tables; analyzers and the correlator read tables and never the raw artifacts. Every row carries a structured provenance object that points back at the exact raw line, row, record, or byte offset it came from, so any number in a verdict can be traced to a raw file without re-running a tool.

## 2. Encoding and naming

- File: `decoded/<table>.jsonl`, one JSON object per line, UTF-8, no byte order mark. Rows are independent; order is the raw order unless the table says otherwise.
- Sidecar: `decoded/<table>.meta.json` validating against `schemas/decoded/table_meta.schema.json`. It records the decoder, its version, the schema version, the raw files consumed, the row count, the time domain of the table (see the timestamp contract), the native time range, and the decoder's measurement status.
- Large tables: a decoder may write `decoded/<table>.parquet` with exactly the same columns, `provenance` as a struct column, and the same sidecar. A bundle holds one encoding per table, never both. Phase 0a fixtures use JSONL only.
- CSV is a raw encoding (PDH, PresentMon, Process Monitor export) and never a decoded encoding, because a CSV cell cannot hold the provenance object without a second, undocumented convention.
- Column names are lower snake case. Physical units are suffixes: `_100ns`, `_us`, `_ms`, `_s`, `_bytes`, `_pct`, `_hz`. A column without a unit suffix is a count, an identifier, a name, or a string kept verbatim.
- Missing values are JSON `null`. A decoder never substitutes zero, an empty string, or a sentinel for a value it could not read; the sidecar's status and the row's null say what happened.
- Verbatim columns keep the raw text exactly, including case and whitespace, so that a reader can grep the raw file for it.

## 3. Versioning

Each schema carries `x-schema-version`, a semantic version. A change that adds an optional column is a minor bump; a change that renames, removes, retypes, or changes the meaning of a column is a major bump; a decoder bug fix that changes emitted values without changing the schema bumps `decoder_version` only. Rows repeat the schema version inside `provenance.schema_version`, and the schema pins that value with a constant, so a row from an older decoder fails validation against a newer major schema instead of being silently misread.

Table schemas are identified by `$id` under `https://github.com/Lcxiv/win-forensics/schemas/decoded/`. The identifier is a name, not a URL to fetch; validators load the files from the repository and register them by `$id`.

## 4. The provenance object

Every table has a required `provenance` column, the structured `raw_ref` of the plan (section 4b, item 4). Schema: `schemas/decoded/provenance.schema.json`.

| Field | Type | Meaning |
|---|---|---|
| `source_file` | string | Path of the raw artifact relative to the bundle root, for example `raw/dpcisr/report.txt`. Must appear in the manifest's artifact list. |
| `row_id_or_offset` | string | Where in that file the row came from, using the grammar below. |
| `decoded_table` | string | The table id, equal to the file stem of the table. |
| `decoder_version` | string | Semantic version of the decoder that emitted the row. |
| `schema_version` | string | Semantic version of the table schema the row was validated against. |

Grammar for `row_id_or_offset`: one or more `kind:value` items separated by `;`. Kinds:

- `line:<n>` the 1-based line number in a text file; `line:<a>-<b>` an inclusive range for multi line records.
- `row:<n>` the 1-based data row of a CSV, not counting the header line; `col:<m>` the 1-based column, used with `row` when one CSV cell yields one decoded row.
- `event:<n>` the 0-based event index in an ETL or PML as enumerated by the decoder.
- `record:<id>` the event log RecordId.
- `index:<n>` the 0-based element index in a JSON array.
- `offset:<bytes>` a byte offset in a binary file, with an optional `len:<bytes>`.

Provenance completeness is a validation gate: every row must carry all five fields, `source_file` must exist in the manifest with a matching checksum, and `decoded_table` must equal the table the row sits in. An analyzer that emits an evidence row without provenance fails validation (see the evidence schema).

## 5. Table catalog

The columns below are the phase 0a contract. `Req` marks required columns. A decoder that cannot fill an optional column emits null. Tables marked provisional have schemas whose optional columns are expected to change once a phase 0b fixture exists; their required columns are the ones that any decoder of that tool can always produce.

### 5.1 `dpcisr_module_cpu`

Per module, per CPU DPC and ISR time from the `CPU Usage Summing By Module For the Whole Trace` tables in an `xperf -i trace.etl -a dpcisr` text report. Decoder: `scripts/decode_dpcisr.py`. One row per `(kind, module, cpu)` cell, including zero cells, because a zero on a CPU is an observation that the module ran no DPC there, not a missing value. Time domain: `etw_qpc_relative` (the report's range header gives the trace span in microseconds from trace start).

| Column | Type | Req | Notes |
|---|---|---|---|
| `kind` | `dpc` or `isr` | yes | From the `DPC Info` or `Interrupt Info` section header |
| `module` | string | yes | Verbatim module name from the row's last field |
| `cpu` | integer | yes | 0-based CPU index from the column header `CPU n Usage` |
| `usec` | integer | yes | Microseconds of DPC or ISR time for that module on that CPU |
| `percent` | number | yes | The printed percentage of the CPU's time over the trace span |
| `trace_span_start_us` | integer | yes | From `CPU Usage from A us to B us` |
| `trace_span_end_us` | integer | yes | Same |
| `provenance` | object | yes | `line:<n>` of the module row; `col` is not used because the whole row is one raw line |

The decoder also checks the report's own reconciliation line (`All Module = X, Total = Y, EQUAL`) and records the result in the sidecar as `consistency_check`; a report that fails its own reconciliation decodes with status `decode_failed`.

### 5.2 `dpcisr_interval`

Per CPU DPC and ISR usage per interval from the `Usage From ... Summing In N second intervals` tables of the same report. Decoder: `scripts/decode_dpcisr.py`. One row per `(kind, interval, cpu)`. Time domain: `etw_qpc_relative` in milliseconds from trace start.

| Column | Type | Req | Notes |
|---|---|---|---|
| `kind` | `dpc` or `isr` | yes | |
| `interval_start_ms` | integer | yes | Left edge of the interval as printed |
| `interval_end_ms` | integer | yes | Right edge as printed; the last interval may be shorter than the others |
| `cpu` | integer | yes | |
| `usec` | integer | yes | |
| `percent` | number | yes | |
| `provenance` | object | yes | `line:<n>` of the interval row |

### 5.3 `tracestats` (provisional)

Session statistics from `xperf -i trace.etl -a tracestats -timezone utc` (with `-timespan actual` and `-detail` when available). Decoder: `scripts/decode_tracestats.py` (later phase). One row per reported key, because the report's exact keys vary by tool version and no committed fixture exists yet; a normalized subset is required so that validation can read events lost without knowing the tool's wording.

| Column | Type | Req | Notes |
|---|---|---|---|
| `section` | string | yes | Report section the key appeared in, verbatim |
| `key` | string | yes | Verbatim key text |
| `value_text` | string | yes | Verbatim value text |
| `normalized_key` | string or null | yes | One of `events_lost`, `buffers_lost`, `buffer_size_kb`, `buffer_count`, `session_start_utc`, `session_end_utc`, `first_event_utc`, `last_event_utc`, `perf_freq_hz`, `clock_type`, `cpu_count`, `os_version`, `trace_file`, or null when the key is not one the contract normalizes |
| `value_number` | number or null | yes | Numeric parse of `value_text` when `normalized_key` is numeric |
| `provenance` | object | yes | `line:<n>` |

A bundle with a kernel trace must decode `tracestats` and it must contain a row with `normalized_key = events_lost`; the manifest's `events_lost` for the `wpr` collector must equal it.

### 5.4 `pdh_counters`

Long form counter samples from a PDH CSV written by `Get-Counter | Export-Counter -FileFormat csv`, `typeperf -f CSV`, or `logman` with CSV output. Decoder: `scripts/decode_pdh.py`. One row per `(sample, counter path)` cell. Time domain: `system_time`, local time in the CSV with the zone and bias from the header.

| Column | Type | Req | Notes |
|---|---|---|---|
| `sample_index` | integer | yes | 1-based data row index |
| `timestamp_local` | string | yes | Verbatim first column, for example `04/24/2026 13:23:48.245` |
| `timestamp_utc` | string or null | yes | ISO 8601 UTC with milliseconds, computed from `timestamp_local` and `tz_bias_minutes` |
| `tz_name` | string | yes | From the header, verbatim |
| `tz_bias_minutes` | integer | yes | From the header; minutes added to local time to obtain UTC |
| `counter_path` | string | yes | Verbatim header cell, for example `\\host\processor(0)\% dpc time` |
| `machine` | string or null | yes | Parsed from the path |
| `object` | string | yes | Parsed from the path, for example `processor` |
| `instance` | string or null | yes | Parsed from the path, for example `0` or `_total`; null when the object has no instance |
| `counter` | string | yes | Parsed from the path, for example `% dpc time` |
| `value` | number or null | yes | Parsed number; null when the cell is blank or a space, which PDH writes for the first sample of rate counters |
| `provenance` | object | yes | `row:<n>;col:<m>` where the row is the data row and the column is the 1-based CSV column of the cell |

The decoder records in the sidecar the header line verbatim, the number of samples, the number of counter columns, and the count of null cells per column, which is what the `pdh` collector's expectation check reads.

### 5.5 `presentmon_frames` (provisional)

One row per frame from a PresentMon console CSV. Decoder: `scripts/decode_presentmon.py` (later phase). Time domain: `etw_qpc` when `cpu_start_qpc` is present, otherwise `relative_monotonic`. Column names follow PresentMon's documented CSV columns in snake case; columns that PresentMon writes as `NA` decode to null.

Required: `application`, `process_id`, `swap_chain_address`, `present_runtime`, `sync_interval`, `present_flags`, `allows_tearing`, `present_mode`, `ms_between_presents`, `ms_in_present_api`, `cpu_start_qpc` (integer or null), `cpu_start_time_s` (number or null; exactly one of the two start columns is non-null), `provenance` (`row:<n>`).

Optional: `ms_cpu_busy`, `ms_cpu_wait`, `ms_gpu_latency`, `ms_gpu_time`, `ms_gpu_busy`, `ms_gpu_wait`, `display_latency_ms`, `displayed_time_ms`, `ms_animation_error`, `animation_time_ms`, `ms_click_to_photon_latency`, `ms_all_input_to_photon_latency`, `instrumented_latency_ms`, `ms_between_display_change`, `ms_until_displayed`, `ms_render_present_latency`, `ms_between_simulation_start`, `ms_between_app_start`, `frame_type`, `video_busy_ms`, `ms_pc_latency`, and `raw_columns` (object holding any column the decoder did not map, verbatim, so no data is dropped when PresentMon adds columns).

### 5.6 `eventlog_events`

One row per record from the JSON export the `eventlog` collector writes with `Get-WinEvent`. Decoder: `scripts/decode_eventlog.py` (later phase). Time domain: `system_time`, UTC.

| Column | Type | Req | Notes |
|---|---|---|---|
| `record_id` | integer | yes | `RecordId` |
| `log_name` | string | yes | |
| `provider_name` | string | yes | |
| `event_id` | integer | yes | |
| `version` | integer or null | yes | |
| `level` | integer or null | yes | |
| `level_display` | string or null | yes | |
| `task` | integer or null | yes | |
| `task_display` | string or null | yes | |
| `opcode` | integer or null | yes | |
| `keywords` | integer or null | yes | The keyword mask as a number |
| `time_created_utc` | string | yes | ISO 8601 UTC with seven fractional digits, from `SystemTime` |
| `machine_name` | string or null | yes | |
| `user_id` | string or null | yes | SID text |
| `process_id` | integer or null | yes | |
| `thread_id` | integer or null | yes | |
| `message` | string or null | yes | Rendered message when available |
| `properties` | array | yes | The event data values in order, as strings or numbers |
| `provenance` | object | yes | `index:<n>;record:<id>` |

### 5.7 `process_inventory`

One row per process per snapshot from the `process_inventory` collector, which joins `Get-Process` and `Win32_Process`. Decoder: `scripts/decode_process_inventory.py` (later phase). Time domain: `system_time` for `captured_at_utc` and `start_time_utc`.

Required: `snapshot` (`start` or `stop`), `captured_at_utc`, `pid`, `name`, `provenance` (`index:<n>`). Optional: `parent_pid`, `image_path`, `command_line`, `priority_class`, `affinity_mask_hex`, `session_id`, `start_time_utc`, `user`, `cpu_time_s`, `working_set_bytes`, `handle_count`, `thread_count`.

### 5.8 `config_snapshot`

One row per setting from the configuration collector: interrupt affinity policy and MSI mode per device, hardware accelerated GPU scheduling, MMCSS, power scheme and core parking policy, driver and BIOS versions. Decoder: `scripts/decode_config_snapshot.py` (later phase).

Required: `category` (one of `interrupt_affinity`, `msi_mode`, `hags`, `mmcss`, `power_scheme`, `core_parking`, `driver`, `bios`, `os`, `other`), `key`, `value_text`, `source_command`, `captured_at_utc`, `provenance` (`index:<n>`). Optional: `device_instance_id`, `device_name`, `value_number`, `registry_path`.

### 5.9 `powercfg`

One row per setting or request from `powercfg` output. Decoder: `scripts/decode_powercfg.py` (later phase). The `kind` column separates the sub commands: `setting` rows come from `/query` or `/qh`, `request` rows from `/requests`, `report` rows point at an HTML or XML report file produced by `/energy`, `/sleepstudy`, or `/systempowerreport` without decoding it.

Required: `kind`, `command`, `captured_at_utc`, `provenance` (`line:<n>` or `line:<a>-<b>`). Optional for `setting`: `scheme_guid`, `scheme_name`, `subgroup_guid`, `subgroup_name`, `setting_guid`, `setting_name`, `ac_value_hex`, `dc_value_hex`, `possible_values` (array), `unit`. Optional for `request`: `request_type` (`display`, `system`, `awaymode`, `execution`, `perfboost`, `activelockscreen`), `requester`, `requester_type`, `reason`. Optional for `report`: `report_path`.

### 5.10 `cdb_analyze`

One row per dump from the text of `cdb -z dump.dmp -c "!analyze -v; q"`. Decoder: `scripts/decode_cdb.py` (later phase). The row keeps the fields that the analysis prints as labeled lines; the full text stays in the raw artifact.

Required: `dump_file`, `bugcheck_code_hex`, `bugcheck_args_hex` (array of four strings), `symbol_status` (`resolved`, `partial`, `unresolved`, or `unknown`), `provenance` (`line:<a>-<b>` spanning the analysis block). Optional: `bucket_id`, `failure_bucket_id`, `module_name`, `image_name`, `process_name`, `faulting_ip_hex`, `stack_frames` (array of verbatim frame lines), `dump_time_utc`, `os_build_text`, `debugger_version`.

### 5.11 `procmon_events`

One row per event from a Process Monitor CSV export made with `/OpenLog capture.pml /SaveAs capture.csv`. Decoder: `scripts/decode_procmon.py` (later phase). The `.pml` in `raw/` stays the authoritative record; anything the CSV lacks is decoded from the `.pml` on Windows. The column set an export can contain is settled in [procmon-facts.md](procmon-facts.md) with committed fixtures; the schema below names every column the export can produce and requires only the documented default seven.

Required: `time_of_day` (verbatim, `h:mm:ss.fffffff AM` or `PM`), `process_name`, `pid`, `operation`, `path`, `result`, `detail`, `provenance` (`row:<n>`). Optional, present only when the capture configuration selected the column: `sequence` (the export writes `n/a`, which decodes to null), `date_and_time` (verbatim, `M/d/yyyy h:mm:ss AM` or `PM`), `relative_time` (verbatim, `hh:mm:ss.fffffff` from the first event), `duration_s` (seconds with seven decimals, equal to completion time minus time of day), `tid`, `parent_pid`, `image_path`, `command_line`, `company`, `description`, `version`, `user`, `session`, `authentication_id`, `integrity`, `architecture`, `virtualized`, `category`, `event_class`, `completion_time` (verbatim, same format as `time_of_day`). Derived: `time_utc` (ISO 8601 UTC computed from `time_of_day`, the date from `date_and_time` when present or from the sidecar otherwise, and the manifest time zone; null when the date is ambiguous). Stacks never appear in a CSV export with any column set; they come from the XML export (`/SaveAs1` or `/SaveAs2`), and a `.pml` or XML decoder in a later phase adds a `procmon_stacks` table.

## 6. Sidecar metadata

`decoded/<table>.meta.json` fields: `decoded_table`, `schema_version`, `decoder`, `decoder_version`, `tool` (name and version of the Windows tool whose output was decoded, or null for pure text parsing), `source_files` (array of bundle relative paths with sha256), `row_count`, `time_domain` (from the timestamp contract), `native_time_range` (start and end in the table's native unit, or null), `status` (a measurement status from [measurement-status.md](measurement-status.md)), `status_reason`, `checks` (array of named decoder self checks with results), and `decoded_at_utc`.

## 7. Open questions

1. Parquet provenance layout. A struct column is the natural mapping, but DuckDB and pandas differ in how they surface nested structs. Decision for phase 0a: JSONL only; when the first large table arrives (a full `FileIO` event table), the decoder that writes it adds a test that a Parquet round trip through both readers preserves the five provenance fields byte for byte, and this contract gets a minor bump naming the layout.
2. `tracestats` keys. The schema keeps verbatim key and value with a normalized subset, which keeps decoding honest before a fixture exists at the cost of a less convenient shape. Once the phase 0b fixture is committed the normalized subset becomes the table and the verbatim rows move to a `tracestats_raw` companion.
3. `procmon_events.time_utc` derivation. The export's `Time of Day` has no date; the sidecar carries the capture date from the collector's own start record, and a capture that crosses midnight is detected by a non monotonic `time_of_day` sequence and handled by adding a day at the wrap. That is enough for a bounded capture (the collector enforces a runtime cap) and is recorded here so nobody assumes the export carries a date.
