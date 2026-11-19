# Decoded tables contract

Status: phase 0a, version 1.3.0 (1.2.0 plus `presentmon_frames` at schema version 0.2.0 in section 5.5, decoded from the CSV and recording record the `presentmon-frames` collector keeps, the recording itself staying on the PC, and the three `clock-calibration` tables in sections 5.17 to 5.19; 1.2.0 was 1.1.0 plus the first fixtured source of the `tracestats` table in section 5.3 and the manifest check of the `dpcisr` decoder in section 5.1, and gave `process_inventory`, `config_snapshot` and `powercfg` their first decoder, `scripts/decode_config_snapshot.py`, taking each to schema version 1.1.0 with the optional columns that decoder fills; 1.1.0 was 1.0.0 plus the five `rf-survey` tables in sections 5.12 to 5.16; `netsh_fields` and `pnp_device` are at schema version 1.1.0 after the saved profile mapping and the Bluetooth peer node rename). Companion contracts: [timestamps.md](timestamps.md), [measurement-status.md](measurement-status.md), [bundle.md](bundle.md). Schemas live under `schemas/decoded/`.

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

The report a live capture produces is `raw/dpcisr_report/dpcisr.txt`, written on the PC by the `dpcisr-trace` collector from a hash pinned `xperf`; the trace itself never leaves the machine ([collectors/windows/README.md](../../collectors/windows/README.md), privacy). The decoder (1.1.0) requires the bundle's `manifest.json` (without it the result is `decode_failed` and nothing is written), accepts only a normalised bundle relative path that the manifest lists as the primary artifact of an `xperf` collector, and records that collector's measurement status in the sidecar as the `collector_status` check without letting it change the decoder's own status: a report made from a trace that lost events still yields rows, the check says `capture_failed` and why, and the manifest and the `tracestats` table are where the loss is read. A decoder never upgrades a collector's status ([measurement-status.md](measurement-status.md) section 2, rule 3).

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

Session statistics from `xperf -i trace.etl -a tracestats -timezone utc` (with `-timespan actual` and `-detail` when available). Decoder: `scripts/decode_tracestats.py` (this `xperf` source is a later phase; the sources it reads today are at the end of this section). One row per reported key, because the report's exact keys vary by tool version and no committed fixture exists yet; a normalized subset is required so that validation can read events lost without knowing the tool's wording.

| Column | Type | Req | Notes |
|---|---|---|---|
| `section` | string | yes | Report section the key appeared in, verbatim |
| `key` | string | yes | Verbatim key text |
| `value_text` | string | yes | Verbatim value text |
| `normalized_key` | string or null | yes | One of `events_lost`, `buffers_lost`, `buffer_size_kb`, `buffer_count`, `session_start_utc`, `session_end_utc`, `first_event_utc`, `last_event_utc`, `perf_freq_hz`, `clock_type`, `cpu_count`, `os_version`, `trace_file`, or null when the key is not one the contract normalizes |
| `value_number` | number or null | yes | Numeric parse of `value_text` when `normalized_key` is numeric |
| `provenance` | object | yes | `line:<n>` |

A bundle with a kernel trace must decode `tracestats` and it must contain a row with `normalized_key = events_lost`; the manifest's `events_lost` for the `wpr` collector must equal it.

The first fixtured sources are not the `xperf` action but the two texts the `dpcisr-trace` collector writes for its `wpr` source: `raw/wpr_trace/status.txt`, the output of `wpr -status profiles collectors -details` read right after the session started (a live snapshot, whose shape Microsoft documents on [WPR Command-Line Options, Status](https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options#status)), and `raw/wpr_trace/tracerpt-summary.txt`, the summary `tracerpt` wrote for the saved trace after the stop (the final figures; Microsoft documents that the tool writes a summary report and nothing about its text, so the labels the reader uses are a verification item). Decoder: `scripts/decode_tracestats.py` (1.1.0), which reads the manifest and decodes both artifacts of every `wpr` collector that has them, whatever its status, because a lossy trace is exactly the one whose loss must be visible in a table. `section` is `recording` for the status lines before the first `Collector Name` line, the collector's name after it, and `summary` for every summary line; `key` is the verbatim label of a labelled line (`Label : value` or `Label   value` with two or more spaces), or the list header (`System Keywords`, `System Stacks`) for a bare item under it, whose `value_text` is the item. Normalized: labels that read `Events Lost` (with or without a `Total` prefix) or `Dropped event` to `events_lost`, `Buffers Lost` (with or without a `Total` prefix) or `Log Buffers Lost` to `buffers_lost` (the plural forms only; `Log Buffers Lost` is the name the tracelog display gives the `LogBuffersLost` member of [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties), [Tracelog Properties Display](https://learn.microsoft.com/windows-hardware/drivers/devtest/tracelog-properties-display)), `Buffer Size (KB)` to `buffer_size_kb`, `Number of Buffers` to `buffer_count`; every other key is null. `value_number` is set only when the whole value is a decimal integer: `1,234` or `n/a` decodes to null, never to a number (section 2). The rule above is checked in the sidecar on the final figures: the `summary` rows must state exactly one whole number for `events_lost` and one for `buffers_lost`, equal to the manifest's `events_lost` and `buffers_lost` for that collector, else `decode_failed`; the status rows are the snapshot and carry no gate. The `xperf -a tracestats` form of the same table waits for a fixture; when it arrives the same decoder gains a third source and the normalized subset is reviewed as open question 2 says.

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

One row per frame from the CSV the pinned PresentMon console application prints when it reads an ETW recording with `--etl_file`, `--output_stdout` and `--qpc_time`. The `presentmon-frames` collector records the providers and event ids PresentMon enables with Windows Performance Recorder on the PC, runs PresentMon over the file there, keeps the CSV as `raw/presentmon_frames/frames.csv` (the primary artifact) and the facts read from the recording as `raw/presentmon_frames/recording.json` (role report: the log file header with its clock, loss counters, start and end, the file's size and SHA-256, the settings `wpr -status` listed, PresentMon's warnings), and deletes the recording, which never leaves the PC because a merged WPR trace can carry network adapter addresses (the pin, the providers, the options, the status rules and the privacy reasoning are in `collectors/windows/README.md`). PresentMon never runs live and never opens a process. Schema version 0.2.0: `cpu_start_qpc` is required and is the frame's `CPUStartQPC` in the recording's own clock, `time_in_qpc` and `ms_flip_delay` are the two further columns the 2.6.0 source writes for its default options, and the former `cpu_start_time_s` is gone (0.1.0 described a seconds column; PresentMon writes `CPUStartTime` only under `--v2_metrics`, in milliseconds, and the collector never asks for it). Decoder: `scripts/decode_presentmon.py`, which reads the manifest and decodes every `presentmon` collector that is `observed`, and reports `not_collected` without writing a table when there is none. The collector never reports `observed_zero`: with the pinned binary an empty output cannot be told from a read that stopped early, so zero frames is `capture_failed` and an observed capture always has at least one frame row (a CSV without one is `decode_failed`). Time domain: from the recording record, not the CSV. `clock_type` `qpc` (the header's `ReservedFlags` 1, the performance counter) gives `etw_qpc` with `native_time_range` in `qpc_ticks`, `system_time` (2) gives `system_time` with the values as FILETIME units, and the CPU cycle counter (3) or a header the collector could not read is `decode_failed`; the decoder also refuses a record that reports lost events or buffers, overflowed presents, an unconfirmed stop or a session that did not run to the stop, and a manifest that disagrees with the record or the CSV: the entry's `events_lost` and `buffers_lost`, and in `enabled.options` `clock_type`, `events_lost`, `buffers_lost`, the four counters of `events_lost_sources`, `presentmon_overflowed_presents`, `etl_bytes`, `stop_confirmed`, `session_ended_early` and `recording_in_progress` (the record's `in_progress_at_end`) must equal the record's values, and `records` and `unknown_application_frames` must equal the number of frame rows decoded and the number of them whose application is `<unknown>`, or the result is `decode_failed` with a reason naming both values. A CSV whose start column is anything but `CPUStartQPC` (`CPUStartTime`, `CPUStartTimeInMs`, `CPUStartQPCTime`, `CPUStartDateTime`) is `decode_failed`, because those are relative or converted values the table does not place in a domain. Column names follow the PresentMon 2.6.0 console README's CSV column list and the header its source writes (`CsvOutput.cpp` `WriteCsvHeader<FrameMetrics>`) in snake case, with the `Ms` prefix kept where the vendor writes it and a `_ms` suffix added where it does not; a column the decoder does not know (for example the three `--write_display_metadata` columns) is kept verbatim under `raw_columns` so nothing is dropped when PresentMon adds columns. Cells PresentMon writes as `NA` decode to null. Converting `native_time_range` to system time needs the header's `PerfFreq` (in `recording.json` and `enabled.options.perf_freq_hz`; also `machine.cpu.qpc_frequency_hz` in the manifest) and the calibration pairs of the clock collector, which this decoder never applies. The table stays provisional until a capture from a real machine has been decoded: the synthetic fixtures are shaped from the header the 2.6.0 source writes and from the first buffer of the vendor's own regression recording (`fixtures/presentmon/gold-test_case_0.first-buffer.etl`), and the facts that only the PC can settle are on the collector README's verification list.

Required: `application`, `process_id`, `swap_chain_address`, `present_runtime`, `sync_interval`, `present_flags`, `allows_tearing`, `present_mode`, `ms_between_presents`, `ms_in_present_api`, `cpu_start_qpc` (integer), `provenance` (`row:<n>`).

Optional: `time_in_qpc` (integer or null), `ms_cpu_busy`, `ms_cpu_wait`, `ms_gpu_latency`, `ms_gpu_time`, `ms_gpu_busy`, `ms_gpu_wait`, `display_latency_ms`, `displayed_time_ms`, `ms_animation_error`, `animation_time_ms`, `ms_flip_delay`, `ms_click_to_photon_latency`, `ms_all_input_to_photon_latency`, `instrumented_latency_ms`, `ms_between_display_change`, `ms_until_displayed`, `ms_render_present_latency`, `ms_between_simulation_start`, `ms_between_app_start`, `frame_type`, `video_busy_ms`, `ms_pc_latency`, and `raw_columns` (object holding any column the decoder did not map, verbatim, so no data is dropped when PresentMon adds columns).

### 5.6 `eventlog_events`

One row per record from the JSON export an event log collector writes as `raw/<collector id>/events.json` (the collectors under `collectors/windows/` read the records with `System.Diagnostics.Eventing.Reader`, the API behind `Get-WinEvent`; the export format is in `collectors/windows/README.md`). Decoder: `scripts/decode_eventlog.py`, which reads the exports of every event log collector in the bundle that is `observed` or `observed_zero` and reports `not_collected` without writing a table when there is none. Each raw element also carries the complete event XML, which stays in the raw artifact. Time domain: `system_time`, UTC.

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

One row per process per snapshot. Schema version 1.1.0. Decoder: `scripts/decode_config_snapshot.py`, from the `processes` source of the `config-snapshot` collector (`raw/processes/records.json`, a `Win32_Process` export with the properties the system process list carries and no command line or image path; see `collectors/windows/README.md`). `snapshot` is the collector's `-Snapshot` value, recorded in the manifest entry's `requested.options.snapshot`; a run sheet takes one `start` and one `stop` bundle around a capture. Time domain: `system_time` for `captured_at_utc` and `start_time_utc` (`CreationDate`). `cpu_time_s` is `KernelModeTime` plus `UserModeTime` divided by ten million, both documented in 100 nanosecond units.

Required: `snapshot` (`start` or `stop`), `captured_at_utc`, `pid`, `name`, `provenance` (`index:<n>`). Optional: `parent_pid`, `image_path`, `command_line`, `priority_class`, `affinity_mask_hex`, `session_id`, `start_time_utc`, `user`, `cpu_time_s`, `working_set_bytes`, `handle_count`, `thread_count`, `base_priority` (1.1.0: `Win32_Process.Priority`, 0 to 31), `page_faults` (1.1.0), `source_id` (1.1.0: the manifest source the row came from). `image_path` and `command_line` are null for every row the general list produces; the timer helper's command line, read by a query filtered to that one process name, lands in `config_snapshot` instead.

### 5.8 `config_snapshot`

One row per setting from the `config-snapshot` collector. Schema version 1.1.0. Decoder: `scripts/decode_config_snapshot.py`, which reads every observed source and writes nothing for a source that is `not_collected` or failed: the two questions the collector cannot answer with a documented read only path (the power mode overlay, the current timer resolution) are statuses in the manifest and never rows here, and so is a topology or device key read that did not succeed.

Required: `category`, `key`, `value_text`, `source_command`, `captured_at_utc`, `provenance`. Categories (1.1.0 adds `processor_power`, `tdr`, `cpu_topology`, `timer`, `process_lasso`, `stutter_guard`): `interrupt_affinity`, `msi_mode`, `hags`, `mmcss`, `power_scheme`, `processor_power`, `core_parking`, `tdr`, `cpu_topology`, `timer`, `process_lasso`, `stutter_guard`, `driver`, `bios`, `os`, `other`. Optional: `device_instance_id`, `device_name`, `value_number`, `registry_path`, and in 1.1.0 `present` (true when the value, file or program exists; false only when the read answered that it is not there, for a registry value when the device key API reported the hardware key, the subkey or the value missing under a key it had opened and enumerated completely; null when it could not be looked at, when the derivation is unverified, or when presence is not what the row is about), `registry_value_kind` (the RegistryValueKind name), `raw_bytes_hex` (the bytes the registry holds, little endian for the numeric kinds), `decoded` (the decoder's reading where Microsoft documents the meaning, else null), `documented_by` (the Microsoft or vendor page that names the key, value or class; null for a value kept verbatim because no page documents it), `device_status`, `device_problem_code`, `source_id`.

What the rows say, by source:

- `interrupt_policy` (`raw/interrupt_policy/keys.json`, `index:<n>` the device element): per selected PCI function, `interrupt_management_key` present, absent or unknown; under `interrupt_affinity`, every value present in `Affinity Policy` with its registry kind and bytes, `DevicePolicy` decoded by IRQ_DEVICE_POLICY and `AssignmentSetOverride` decoded to the processors whose bits are set (bit i is logical processor i of the device's group, as Microsoft defines KAFFINITY; `value_number` is the exact mask), the two recorded absent only when the leaf was enumerated completely without them or the API reported the leaf or the hardware key missing, and any other value kept verbatim with `documented_by` null (a string typed value arrives omitted); under `msi_mode`, `MSISupported` and `MessageNumberLimit` likewise (`decoded.msi_enabled_in_configuration` is true for a `REG_DWORD` of 1, false for a `REG_DWORD` of 0, and null, unknown, for any other kind or data). `registry_path` is the locator the collector used, `SetupDiOpenDevRegKey(DICS_FLAG_GLOBAL, DIREG_DEV, KEY_READ)` plus the relative subkey, never a physical path the API did not return. Every row carries the device's status and problem code. A device whose key refused, disappeared or failed at a native stage has one row saying so with the stage, and `present` null; a leaf whose enumeration was cut short has its unvisited documented values as unknown rows, `present` null. **The mask is the requested set, never the processor that services the interrupt**: effective routing comes from the trace, and nothing in this table reconciles the two.
- `graphics_tdr` (`index:<n>` the key element): one `tdr` row per documented value, present with `TdrLevel` and `TdrDebugMode` named by their enumerations or absent (Windows default).
- `processors` and `cpu_caches` (`index:<n>` the instance): `cpu_topology` rows per documented property, the derived `smt_enabled` (cores less than logical processors, a count only) and one `cache` row per `Win32_CacheMemory` instance. None of these rows names a sibling pair or a processor group; both come from the next source.
- `logical_processor_map` (`raw/logical_processor_map/topology.json`, `index:<n>` the record): `cpu_topology` rows `core:<n>` (the logical processors of one `RelationProcessorCore` record, its SMT flag and efficiency class), `logical_processor:<group>:<i>` (its core, its siblings, which are the other processors of that same record, and the caches whose masks include it with the processors they are shared with), `cache:<n>` (level, type, size, line size, associativity, masks), `group:<g>` (active and maximum processor counts, the active mask) and `package:<n>`. `documented_by` is the GetLogicalProcessorInformationEx page. A failed read produces no row: the sidecar's checks say so.
- `power_active_scheme` and `power_settings` (`line:<n>`): `power_scheme` rows `active_scheme_guid` and the derived `active_overlay` ("none evident" with `present` null when the `/query` header is the active scheme's GUID, because whether that header carries an overlay GUID is a verification item; with `present` true when the header carries another GUID: the documented overlay name for one of the three overlay GUIDs the power slider page documents, Better Performance for the Balanced scheme's GUID, else the unknown GUID verbatim); `processor_power` and `core_parking` rows for the settings whose aliases Microsoft documents (`PROCTHROTTLEMIN`, `PROCTHROTTLEMAX`, `PERFBOOSTMODE`, `PERFBOOSTPOL`, `PERFEPP`, `IDLEDISABLE`, `CPMINCORES`, `CPMAXCORES`) with the AC and DC indices in `decoded`, one row per alias per listing (`power_settings`, `power_settings_hidden`).
- `processes` (`index:<n>`, or `offset:0` for a component not in the list): `process_lasso` rows `running:gui`, `running:governor`, `running:session_agent` by the executable names Bitsum documents, process names and ids only.
- `timer_helper_process`: the `stutter_guard` row `timer_helper_running` with the helper's command line, image path and creation time in `decoded` (protected by the collector: a user profile folder name, e-mail shaped token, UNC host or hardware address in them is already a pseudonym), or present false.
- `process_lasso_install`, `stutter_guard_install`: `install_folder` present or not, cited as `offset:0` of the source's `result.json` (the report that carries the folder's facts, a consumed source in the sidecar), and one `file:<name>` row per element of the `listing.json` array (`index:<n>`) with version, hash and size in `decoded`.
- `process_lasso_config`, `stutter_guard_journal`: `config_copied`, `journal_copied`, cited as `offset:0` of the source's `result.json`, with the original's SHA-256 and size, `copy_is_verbatim`, the replacement counts and the source encoding in `decoded`, and the copy's path in `decoded.copy` (`decoded.summary` is null).
- `process_lasso_log`: `log_summarised`, never `log_copied`. The collector summarises the vendor log because its lines can carry command line arguments that no shape rule reliably removes, whatever `IncludeCommandLines` says now. `present` is true, `value_text` says the file was summarised and not copied, `value_number` is the size, and `decoded` holds `copy` (null), `summary` (the summary artifact), `source_sha256`, `source_bytes`, `creation_time_utc`, `last_write_time_utc`, `lines` and `note` (the collector's reason, from `result.json`). The row is cited as `offset:0` of the source's `result.json`.
- A file source's key follows what its `result.json` says: `mode` `copy` gives `<stem>_copied`, `mode` `summary` gives `<stem>_summarised`. A summary is never labelled a copy; a report whose `mode`, `copied` and `summarised` disagree fails the table. The copies and summaries themselves stay raw artifacts (both files are consumed sources in the sidecar).
- `process_lasso_config` also yields `command_line_logging` in the `process_lasso` category, read from the copied INI: `present` true with `value_text` `IncludeCommandLines=<value>` and provenance `line:<n>` of the copy when the line exists, `present` false with provenance `offset:0` of the copy when it does not. `decoded` holds `setting`, `value`, `enabled` (true for `true` or `1`, false for `false` or `0`, null otherwise) and a note. It is an observation about the configuration at capture time ([logging](https://bitsum.com/apps/process-lasso/docs/interface/logging/)); it says nothing about lines already in the log and nothing is decided on it.

The power rows here derive from the `powercfg` table (5.9), so whenever that table is `decode_failed` this table is `decode_failed` too, with a `status_reason` naming the powercfg failure, a `power_rows` check that is not ok and no rows, however many other sources decoded: a partial table is never presented as complete.

### 5.9 `powercfg`

One row per scheme, alias, setting, request, or report reference from `powercfg` output. Schema version 1.1.0. Decoder: `scripts/decode_config_snapshot.py`, from the five listings the `config-snapshot` collector writes as `raw/<source id>/output.txt`. The `kind` column separates them: `scheme` rows from `/getactivescheme` and `/list` (1.1.0; `is_active` from the `/getactivescheme` origin or the trailing active marker of `/list`, `overlay` when the GUID is one of the three overlay GUIDs the power slider page documents for the default slider mode; the Balanced scheme's GUID, which that page also lists as the INF GUID of Better Performance, is a scheme and gets no overlay name), `alias` rows from `/aliases` (1.1.0; scheme, subgroup or setting by indentation and the `SCHEME_` prefix), `setting` rows from `/query` and `/qh` (one per setting GUID, `line:<a>-<b>` spanning the setting's block; a `scheme` row for each listing's header, `is_active` true because `/query` without arguments lists the active scheme or active overlay), `request` rows from `/requests` and `report` rows pointing at a report file (neither produced by this collector; the schema keeps them for the elevated task).

The listings are localized. Schemes, subgroups and settings are found by the GUID each line carries and its indentation; the AC and DC indices by their English labels (`classified_by = label`) or, when the labels are unknown, by the shape and order of the two hex lines after the possible settings, AC first then DC as powercfg prints them (`classified_by = value`); names in parentheses stay verbatim; the alias comes from the setting's `GUID Alias` line or from the `/aliases` map. `hidden` is true for a setting the `/qh` listing carries and the `/query` listing does not, false for one in `/query`, null when `/qh` was not observed.

Required: `kind`, `command`, `captured_at_utc`, `provenance` (`line:<n>` or `line:<a>-<b>`). Optional for `scheme`: `scheme_guid`, `scheme_name`, `is_active`, `alias`, `overlay`. Optional for `alias`: `scheme_guid` or `subgroup_guid` or `setting_guid`, `alias`. Optional for `setting`: `scheme_guid`, `scheme_name`, `subgroup_guid`, `subgroup_name`, `setting_guid`, `setting_name`, `alias`, `ac_value_hex`, `dc_value_hex`, `min_value_hex`, `max_value_hex`, `possible_values` (array of `<index>: <friendly name>`), `unit`, `hidden`, `classified_by`. Optional for `request`: `request_type` (`display`, `system`, `awaymode`, `execution`, `perfboost`, `activelockscreen`), `requester`, `requester_type`, `reason`. Optional for `report`: `report_path`. Every row carries `source_id`.

### 5.10 `cdb_analyze`

One row per dump from the text of `cdb -z dump.dmp -c "!analyze -v; q"`. Decoder: `scripts/decode_cdb.py` (later phase). The row keeps the fields that the analysis prints as labeled lines; the full text stays in the raw artifact.

Required: `dump_file`, `bugcheck_code_hex`, `bugcheck_args_hex` (array of four strings), `symbol_status` (`resolved`, `partial`, `unresolved`, or `unknown`), `provenance` (`line:<a>-<b>` spanning the analysis block). Optional: `bucket_id`, `failure_bucket_id`, `module_name`, `image_name`, `process_name`, `faulting_ip_hex`, `stack_frames` (array of verbatim frame lines), `dump_time_utc`, `os_build_text`, `debugger_version`.

### 5.11 `procmon_events`

One row per event from a Process Monitor CSV export made with `/OpenLog capture.pml /SaveAs capture.csv`. Decoder: `scripts/decode_procmon.py` (later phase). The `.pml` in `raw/` stays the authoritative record; anything the CSV lacks is decoded from the `.pml` on Windows. The column set an export can contain is settled in [procmon-facts.md](procmon-facts.md) with committed fixtures; the schema below names every column the export can produce and requires only the documented default seven.

Required: `time_of_day` (verbatim, `h:mm:ss.fffffff AM` or `PM`), `process_name`, `pid`, `operation`, `path`, `result`, `detail`, `provenance` (`row:<n>`). Optional, present only when the capture configuration selected the column: `sequence` (the export writes `n/a`, which decodes to null), `date_and_time` (verbatim, `M/d/yyyy h:mm:ss AM` or `PM`), `relative_time` (verbatim, `hh:mm:ss.fffffff` from the first event), `duration_s` (seconds with seven decimals, equal to completion time minus time of day), `tid`, `parent_pid`, `image_path`, `command_line`, `company`, `description`, `version`, `user`, `session`, `authentication_id`, `integrity`, `architecture`, `virtualized`, `category`, `event_class`, `completion_time` (verbatim, same format as `time_of_day`). Derived: `time_utc` (ISO 8601 UTC computed from `time_of_day`, the date from `date_and_time` when present or from the sidecar otherwise, and the manifest time zone; null when the date is ambiguous). Stacks never appear in a CSV export with any column set; they come from the XML export (`/SaveAs1` or `/SaveAs2`), and a `.pml` or XML decoder in a later phase adds a `procmon_stacks` table.

### 5.12 `netsh_fields`

One row per labelled line of the `netsh wlan show interfaces`, `show drivers` and `show profiles` outputs the `rf-survey` collector writes as `raw/<source id>/output.txt` (format and pseudonyms in `collectors/windows/README.md`). Decoder: `scripts/decode_rf_survey.py`. The label and value are verbatim; `normalized_key` names the field when the English label is known (`classified_by = label`) or when the value's shape identifies it (`classified_by = value`: a GUID, an `802.11x` radio type, a `GHz` band, a percentage, a channel number after the band line, a `mac-` or `ssid-` pseudonym), and is null otherwise, so a display language the decoder has not seen loses names, not numbers. Time domain: `system_time` (the capture moment).

Saved profile names are the owner's own and stay readable in `value_text`; for those rows `value_pseudonym` carries the pseudonym the same name has in `wlan_bss`, which is how an explicit owner selection is matched.

Required: `command` (`interfaces`, `drivers`, `profiles`), `block` (0-based index of the unindented block), `line` (1-based), `indent`, `label_text`, `value_text`, `value_pseudonym` (string or null), `normalized_key` (string or null), `value_number` (number or null), `classified_by` (`label`, `value`, or null), `provenance` (`line:<n>`).

### 5.13 `wlan_bss`

One row per access point in a `netsh wlan show networks mode=bssid` output. Names and addresses are the collector's pseudonyms (`ssid-<12 hex>`, `mac-<12 hex>`), consistent inside one bundle. Decoder: `scripts/decode_rf_survey.py`. The band is read from the Band line when Windows prints one and inferred from the channel otherwise, as a convenience bound: 1 to 14 is the 2.4 GHz numbering, 36 to 165 the 5 GHz UNII-1 to UNII-3 channels Cisco lists in its [Wireless RF Reference Guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/technical-reference/wireless-rf-reference-guide.html), anything else is unknown; 6 GHz reuses these numbers, so the sidecar counts the inferred rows and a 6 GHz access point without a Band line would be misread as 5 GHz. `signal_dbm_estimate` follows Microsoft's documented mapping of the signal quality percentage (0 is minus 100 dBm, 100 is minus 50 dBm, linear between). `is_known_profile` is true when the network's name pseudonym is one of this PC's saved profiles and null when the profiles were not readable; it says the PC has a profile for the network, not that the network is the owner's (profiles go stale).

Required: `interface_name`, `network_index`, `ssid_pseudonym` (null for a hidden network), `bssid_pseudonym`, `signal_pct`, `signal_dbm_estimate`, `radio_type`, `band_text`, `band_ghz` (2.4, 5, 6 or null), `channel`, `channel_source` (`label`, `value`, or null), `network_type`, `authentication`, `encryption` (the last three by English label only, else null), `is_known_profile`, `labels_recognised`, `provenance` (`line:<a>-<b>`, the access point's lines).

### 5.14 `pnp_device`

One row per device in a `pnp` source export (`raw/<source id>/devices.json`), with the chain to the host controller resolved inside the same export. Decoder: `scripts/decode_rf_survey.py`. `usb_stack` follows the controller's service as Microsoft documents the driver stacks (`USBXHCI` is `usb3_xhci`, `usbehci` is `usb2_ehci`, `usbohci` and `usbuhci` are `usb1_ohci_uhci`); it says which controller type serves the port, never the speed a device negotiated, which Windows does not expose. `is_receiver_candidate` is a name match (receiver, dongle, wireless, Unifying, Lightspeed and the like on a USB device that is not a Bluetooth radio) and is a hint, not an identification. `is_bluetooth_peer_node` marks a present `BTHENUM` or `BTHLE` node, a remembered peer whose name and address are the collector's pseudonyms; pairing and connection state are not measured.

Required: `source_id`, `instance_id`, `class`, `name`, `description`, `manufacturer`, `service`, `status`, `problem_code`, `is_seed`, `parent_instance_id`, `location_path`, `location_info`, `bus_reported_description`, `vendor_id`, `product_id`, `controller_instance_id`, `controller_service`, `usb_stack`, `hub_chain` (ancestor instance ids, nearest first), `is_root_hub`, `is_receiver_candidate`, `is_bluetooth_radio`, `is_bluetooth_peer_node`, `provenance` (`index:<n>`).

### 5.15 `net_adapter`

One row per `MSFT_NetAdapter` instance from the `net_adapters` source, with the documented enumerations spelled out next to their numbers (`physical_medium_text`, `operational_status_text`, `media_connect_state_text`, `pnp_state_text`). Decoder: `scripts/decode_rf_survey.py`. Hardware addresses are not requested by the collector and are not in the table.

Required: `name`, `interface_description`, `interface_index`, `interface_guid`, `physical_medium`, `physical_medium_text`, `operational_status`, `operational_status_text`, `media_connect_state`, `media_connect_state_text`, `pnp_state`, `pnp_state_text`, `status`, `virtual`, `hidden`, `hardware_interface`, `receive_link_speed_bps`, `transmit_link_speed_bps`, `driver_description`, `driver_version`, `driver_provider`, `pnp_device_id`, `provenance` (`index:<n>`).

### 5.16 `net_route`

One row per `MSFT_NetRoute` instance from the `default_routes` source (the `0.0.0.0/0` and `::/0` routes). Decoder: `scripts/decode_rf_survey.py`. The interface behind the default route with the lowest metric, across both address families, is the one that carries the machine's traffic; the analyzer lists IPv4 first on an equal metric and reports when the families use different interfaces.

Required: `destination_prefix`, `next_hop`, `interface_index`, `interface_alias`, `route_metric`, `protocol`, `protocol_text`, `address_family`, `address_family_text` (`IPv4`, `IPv6`, or null), `store`, `provenance` (`index:<n>`).

### 5.17 `clock_pairs`

One row per calibration pair from `raw/clock_calibration/samples.jsonl`, the primary artifact of the `clock-calibration` collector (which also lists the same pairs in the manifest's `calibration.pairs`; the decoder refuses a bundle in which the two disagree). Decoder: `scripts/decode_clock.py`. The readings are verbatim, including whether the pair was taken at a change of the coarse system clock (`edge`) and the size of that change (`system_time_step_100ns`); the derived columns are the pair's counter midpoint and its half width from [timestamps.md](timestamps.md) section 3, `ceil((qpc_after - qpc_before) / 2 + 1 tick)` in 100 ns units. Time domain: `system_time` for the native range (the pairs live in both domains by construction).

Required: `seq`, `phase` (`start`, `interval`, `stop`), `qpc_before`, `qpc_after`, `filetime_utc_100ns`, `filetime_utc` (ISO 8601 UTC, seven fractional digits), `qpc_mid`, `bracket_ticks`, `half_width_100ns`, `edge`, `system_time_step_100ns` (integer or null), `provenance` (`line:<n>`).

### 5.18 `clock_segments`

One row per pair of consecutive calibration pairs: the piecewise affine model of [timestamps.md](timestamps.md) section 4.3 for `system_time` sources, as the Mac fits it. Decoder: `scripts/decode_clock.py`. `rate_ticks_per_100ns` is the counter span over the file time span and `rate` the same in master 100 ns per source 100 ns; `anchor_filetime_100ns` and `anchor_master_100ns` give the exact anchor form of the model and `offset_100ns` the contract's rounded offset. `error_bound_100ns` is the calibration's own bound for the segment: the larger half width of its two pairs, plus `system_time_increment_100ns` (zero when both pairs were taken at a change of the system clock, else the larger of the largest clock step the collector recorded and the documented 15.625 ms real time clock period, because the increment can change during a session, see [timestamps.md](timestamps.md) section 4.3), plus the largest interior residual (zero between consecutive pairs); a `system_time` source adds its own resolution to get `e_S`. `quantisation_limit_ppm` is `2 * (system_time_increment_100ns + half_width_max_100ns) / span_100ns` in parts per million, the deviation the two pairs' own uncertainty can explain over the segment. A segment whose `rate_deviation_ppm` exceeds 1000 plus `quantisation_limit_ppm` is a `clock_step`: `step_kind` says whether the system clock gained (`forward`) or lost (`backward`) time against the counter, the bound also carries the larger of `span_100ns` and `qpc_span_100ns`, and for a backward step `ambiguous_from_100ns` to `ambiguous_to_100ns` is the range of file times the clock may have shown twice, which the model refuses in every other segment. The range runs from `filetime_from_100ns - (qpc_span_100ns - span_100ns)` to `filetime_from_100ns + qpc_span_100ns` and carries on both ends the segment's own uncertainty: `half_width_max_100ns` (the larger half width of its two pairs) plus `system_time_increment_100ns`. The master epoch is the first pair's `qpc_before` (`epoch_source` is always `first_calibration_pair`). The decoder never writes a master time for any other source; `decode_clock.py`'s `ClockModel` computes those on demand for the correlator.

Required: `segment`, `seq_from`, `seq_to`, `phase_from`, `phase_to`, `qpc_from`, `qpc_to`, `filetime_from_100ns`, `filetime_to_100ns`, `span_100ns`, `qpc_span_ticks`, `qpc_span_100ns`, `qpc_frequency_hz`, `epoch_qpc`, `epoch_source`, `rate_ticks_per_100ns`, `nominal_rate_ticks_per_100ns`, `rate_deviation_ppm`, `quantisation_limit_ppm`, `clock_step`, `step_kind`, `ambiguous_from_100ns` (integer or null), `ambiguous_to_100ns` (integer or null), `anchor_filetime_100ns`, `anchor_master_100ns`, `rate`, `offset_100ns`, `half_width_max_100ns`, `system_time_increment_100ns`, `residual_max_100ns`, `error_bound_100ns`, `provenance` (`line:<a>-<b>`, the two pairs' lines).

### 5.19 `operator_marks`

One row per mark from `raw/operator_marks/marks.jsonl`: what the person at the PC typed, with the counter bracket the mark command took in its own process. Decoder: `scripts/decode_clock.py`. A mark is in the `etw_qpc` domain and needs no calibration to be placed next to kernel events; its instrument uncertainty is its half width, and the person's reaction time is not measured. Time domain: `etw_qpc`.

Required: `mark_index`, `label`, `qpc_before`, `qpc_after`, `filetime_utc_100ns`, `at_utc`, `qpc_mid`, `bracket_ticks`, `half_width_100ns`, `process_id`, `provenance` (`line:<n>`).

## 6. Sidecar metadata

`decoded/<table>.meta.json` fields: `decoded_table`, `schema_version`, `decoder`, `decoder_version`, `tool` (name and version of the Windows tool whose output was decoded, or null for pure text parsing), `source_files` (array of bundle relative paths with sha256), `row_count`, `time_domain` (from the timestamp contract), `native_time_range` (start and end in the table's native unit, or null), `status` (a measurement status from [measurement-status.md](measurement-status.md)), `status_reason`, `checks` (array of named decoder self checks with results), and `decoded_at_utc`.

## 7. Open questions

1. Parquet provenance layout. A struct column is the natural mapping, but DuckDB and pandas differ in how they surface nested structs. Decision for phase 0a: JSONL only; when the first large table arrives (a full `FileIO` event table), the decoder that writes it adds a test that a Parquet round trip through both readers preserves the five provenance fields byte for byte, and this contract gets a minor bump naming the layout.
2. `tracestats` keys. The schema keeps verbatim key and value with a normalized subset, which keeps decoding honest before a fixture exists at the cost of a less convenient shape. Once the phase 0b fixture is committed the normalized subset becomes the table and the verbatim rows move to a `tracestats_raw` companion.
3. `procmon_events.time_utc` derivation. The export's `Time of Day` has no date; the sidecar carries the capture date from the collector's own start record, and a capture that crosses midnight is detected by a non monotonic `time_of_day` sequence and handled by adding a day at the wrap. That is enough for a bounded capture (the collector enforces a runtime cap) and is recorded here so nobody assumes the export carries a date.
