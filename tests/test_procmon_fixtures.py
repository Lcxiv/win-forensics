"""Committed Process Monitor fixtures are reproducible and self consistent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

procmon_parser = pytest.importorskip("procmon_parser", reason="procmon-parser (dev extra) not installed")


def test_committed_pmc_files_match_the_generator(repo_root):
    import make_procmon_pmc
    for name in make_procmon_pmc.CONFIGS:
        committed = (repo_root / "fixtures" / "procmon" / name).read_bytes()
        assert committed == make_procmon_pmc.render(name), f"{name} is stale; run scripts/make_procmon_pmc.py"


def test_committed_pmc_files_load_with_expected_records(repo_root):
    from procmon_parser import load_configuration
    from procmon_parser.consts import Column
    for name, expected_count in (("wf-default-columns.pmc", 7), ("wf-all-columns.pmc", 27)):
        with (repo_root / "fixtures" / "procmon" / name).open("rb") as fh:
            cfg = load_configuration(fh)
        assert list(cfg.keys()) == ["Columns", "ColumnCount", "ColumnMap", "DbgHelpPath", "Logfile", "HighlightFG",
                                    "HighlightBG", "LogFont", "BoookmarkFont", "AdvancedMode", "Autoscroll",
                                    "HistoryDepth", "Profiling", "DestructiveFilter", "AlwaysOnTop",
                                    "ResolveAddresses", "SourcePath", "SymbolPath", "FilterRules", "HighlightRules"]
        assert cfg["ColumnCount"] == expected_count
        assert len([c for c in cfg["ColumnMap"] if c != Column.NONE]) == expected_count
        assert cfg["DestructiveFilter"] == 0
        assert "stack" not in " ".join(cfg.keys()).lower(), "a .pmc carries no stack capture setting"
        assert str(cfg["FilterRules"][0]).startswith('If Path begins_with "C:\\wf-procmon-facts"')


def test_facts_json_if_present_is_consistent(repo_root):
    facts_path = repo_root / "fixtures" / "procmon" / "facts.json"
    if not facts_path.exists():
        pytest.skip("runner facts not yet committed")
    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    assert facts["runner"]["image_os"], "runner image must be recorded"
    assert facts["procmon"]["file_version"], "Process Monitor version must be recorded"
    for name, info in facts["csv_exports"].items():
        if "columns" in info:
            head = repo_root / "fixtures" / "procmon" / info["head_fixture"]
            assert head.exists(), name
            first = head.read_text(encoding="utf-8").splitlines()[0]
            assert first.strip('"').split('","') == info["columns"], name
