"""Documentation hygiene: plain prose, no em or en dashes, no win-opt findings quoted as examples."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

DASHES = re.compile("[\u2013\u2014]")

# Strings from win-opt's recorded findings that must never appear in this repository's prose,
# schemas, scripts, or tests as examples or thresholds. Raw format fixtures under fixtures/ are
# exempt because they are verbatim tool output.
FINDING_TOKENS = ["nvlddmkm", "0x133", "97.7", "8,512", "8512", "SearchIndexer", "camsvc",
                  "MsMpEng", "GpuControl.CreateCommandBuffer"]


def prose_files(repo_root: Path) -> list[Path]:
    files = [repo_root / "README.md", *(repo_root / "docs").rglob("*.md")]
    return [f for f in files if f.exists()]


def guarded_files(repo_root: Path) -> list[Path]:
    out = prose_files(repo_root)
    out += list((repo_root / "schemas").rglob("*.json"))
    out += list((repo_root / "scripts").glob("*.py"))
    out += list((repo_root / "scripts").glob("*.ps1"))
    out += list((repo_root / "tests").glob("*.py"))
    out += list((repo_root / ".github").rglob("*.yml"))
    return out


def test_no_em_or_en_dashes_in_prose(repo_root):
    offenders = []
    for f in prose_files(repo_root):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), start=1):
            if DASHES.search(line):
                offenders.append(f"{f.relative_to(repo_root)}:{i}")
    assert not offenders, offenders


def test_no_win_opt_findings_quoted(repo_root):
    offenders = []
    for f in guarded_files(repo_root):
        if f.name == "test_docs.py":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for token in FINDING_TOKENS:
            if token in text:
                offenders.append(f"{f.relative_to(repo_root)}: {token}")
    assert not offenders, offenders


@pytest.mark.parametrize("name", ["timestamps.md", "decoded-tables.md", "measurement-status.md", "bundle.md", "procmon-facts.md"])
def test_contract_exists_with_open_questions(repo_root, name):
    doc = repo_root / "docs" / "contracts" / name
    assert doc.exists(), name
    assert "## " in doc.read_text(encoding="utf-8")
    if name != "procmon-facts.md":
        assert "Open questions" in doc.read_text(encoding="utf-8")
