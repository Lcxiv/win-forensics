# win-forensics

Capture, decode, and correlate Windows performance evidence to root-cause gaming stutters and hitches, with every analysis step testable off the gaming PC.

Three layers and one contract:

- capture: thin Windows-only collectors (WPR, counters, event log, powercfg, process inventory, PresentMon, Process Monitor) that start, stop, verify, and checksum their own artifacts.
- decode: Windows-only decoders (TraceProcessing, wpaexporter, xperf, cdb, Process Monitor export) that emit versioned typed tables with provenance.
- analyze: portable correlation and reporting that consumes decoded tables and never re-derives meaning from raw traces.

The contract between them is the bundle: manifest, immutable raw artifacts, decoded tables, evidence rows, and a verdict with a coverage table. Measurement status is kept separate from evidence, so a subsystem that was not observed can never be cleared.

Bundles captured from a real machine are never committed here; only schemas, code, synthetic fixtures, and format fixtures live in this repository.
