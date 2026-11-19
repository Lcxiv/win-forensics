# Provenance of the vendor format fixture

`gold-test_case_0.first-buffer.etl` is the only `.etl` file git keeps in this repository. It is a format fixture: the first buffer of a recording the PresentMon project ships for its own regression tests. It was not captured on any machine this project measures.

| Fact | Value |
|---|---|
| Source repository | https://github.com/GameTechDev/PresentMon |
| Tag | v2.6.0 (commit e13fce6) |
| Original path | `Tests/Gold/test_case_0.etl` |
| SHA-256 of the full original file | `7127ed1325fd9d179604df2a7356dc3c4cb805cb15220175e34b4faf918a31be` |
| What is kept here | the first 4096 bytes of that file, unchanged |
| SHA-256 of the 4096 byte slice | `d7d2463ec3f97c59db6815fb936a73ecbdaae5b782ec81e597b1946b97a4a8fc` |
| Copyright | Copyright (C) 2017-2024 Intel Corporation |
| License | MIT (SPDX-License-Identifier: MIT); the full text is in `LICENSE-PresentMon.txt` next to this file |

The slice is used to check the log file header reader of `collectors/windows/presentmon-frames.ps1` and the synthetic recording of the collector tests against a recording the vendor made (`tests/test_presentmon.py` checks the slice's hash and reads it).

To reproduce the slice, fetch `Tests/Gold/test_case_0.etl` at the tag, check the full file's SHA-256 above, and keep its first 4096 bytes.
