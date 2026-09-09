"""Shared paths for the phase 0a test suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

EXAMPLE_BUNDLE = REPO_ROOT / "fixtures" / "example-bundle"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def example_bundle() -> Path:
    return EXAMPLE_BUNDLE
