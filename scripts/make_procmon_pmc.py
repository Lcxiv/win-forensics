#!/usr/bin/env python3
"""Generate the committed Process Monitor test configurations under fixtures/procmon/.

Process Monitor has no command line switch that writes a configuration file; the
GUI's File, Export Configuration does that. These two files are built with the
procmon-parser library from a reverse engineered but round trip tested layout
(the same twenty records the GUI exports), so that the phase 0a runner workflow
can load them with ``/LoadConfig`` and settle three facts with fixtures:

* ``wf-default-columns.pmc``: the documented default seven columns, one include
  rule on the path prefix the runner's load generator writes under, and the
  usual exclusions for Process Monitor's own processes.
* ``wf-all-columns.pmc``: the same filter with every column Process Monitor
  offers selected, so the CSV export shows the full column set.

Both use non destructive filtering (``DestructiveFilter`` 0), no thread
profiling, no symbol resolution, and ``HistoryDepth`` 200, the value an
unmodified export carries. Regenerating must be byte for byte reproducible;
``tests/test_procmon_fixtures.py`` checks that when procmon-parser is installed.

Usage: ``python scripts/make_procmon_pmc.py [--out fixtures/procmon]``
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path

from procmon_parser import Column, Rule, RuleAction, RuleRelation, dumps_configuration, loads_configuration
from procmon_parser.configuration import Font

LOAD_PATH_PREFIX = "C:\\wf-procmon-facts"

DEFAULT_COLUMNS = [Column.TIME_OF_DAY, Column.PROCESS_NAME, Column.PID, Column.OPERATION, Column.PATH,
                   Column.RESULT, Column.DETAIL]

ALL_COLUMNS = [Column.SEQUENCE, Column.TIME_OF_DAY, Column.DATE_AND_TIME, Column.RELATIVE_TIME, Column.DURATION,
               Column.COMPLETION_TIME, Column.PROCESS_NAME, Column.PID, Column.TID, Column.PARENT_PID,
               Column.OPERATION, Column.PATH, Column.RESULT, Column.DETAIL, Column.EVENT_CLASS, Column.CATEGORY,
               Column.IMAGE_PATH, Column.COMMAND_LINE, Column.COMPANY, Column.DESCRIPTION, Column.VERSION,
               Column.USER, Column.SESSION, Column.AUTHENTICATION_ID, Column.INTEGRITY, Column.ARCHITECTURE,
               Column.VIRTUALIZED]

FILTER_RULES = [
    Rule(Column.PATH, RuleRelation.BEGINS_WITH, LOAD_PATH_PREFIX, RuleAction.INCLUDE),
    Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon64.exe", RuleAction.EXCLUDE),
    Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon.exe", RuleAction.EXCLUDE),
]


def build(columns: list[Column]) -> "OrderedDict[str, object]":
    slots = 64
    widths = [100] * len(columns) + [0] * (slots - len(columns))
    column_map = list(columns) + [Column.NONE] * (slots - len(columns))
    return OrderedDict([
        ("Columns", widths),
        ("ColumnCount", len(columns)),
        ("ColumnMap", column_map),
        ("DbgHelpPath", "C:\\Windows\\SYSTEM32\\dbghelp.dll"),
        ("Logfile", ""),
        ("HighlightFG", 0),
        ("HighlightBG", 16777088),
        ("LogFont", Font(weight=400)),
        ("BoookmarkFont", Font(weight=700)),
        ("AdvancedMode", 0),
        ("Autoscroll", 0),
        ("HistoryDepth", 200),
        ("Profiling", 0),
        ("DestructiveFilter", 0),
        ("AlwaysOnTop", 0),
        ("ResolveAddresses", 0),
        ("SourcePath", ""),
        ("SymbolPath", "srv*https://msdl.microsoft.com/download/symbols"),
        ("FilterRules", list(FILTER_RULES)),
        ("HighlightRules", []),
    ])


CONFIGS = {
    "wf-default-columns.pmc": DEFAULT_COLUMNS,
    "wf-all-columns.pmc": ALL_COLUMNS,
}


def render(name: str) -> bytes:
    data = dumps_configuration(build(CONFIGS[name]))
    parsed = loads_configuration(data)
    assert parsed["ColumnCount"] == len(CONFIGS[name]), "round trip lost the column count"
    assert list(parsed["FilterRules"]) == FILTER_RULES, "round trip lost the filter rules"
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "fixtures" / "procmon")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in CONFIGS:
        data = render(name)
        (args.out / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes, {len(CONFIGS[name])} columns, {len(FILTER_RULES)} filter rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
