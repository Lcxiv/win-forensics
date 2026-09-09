"""Schema loading and validation helpers shared by decoders and tests.

Loads every ``schemas/**/*.schema.json`` file, registers it by ``$id`` so that
relative ``$ref`` values resolve, and exposes validators for tables, sidecars,
manifests, evidence rows, and verdicts.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_ROOT = REPO_ROOT / "schemas"
SCHEMA_BASE = "https://github.com/Lcxiv/win-forensics/schemas/"


def schema_files() -> list[Path]:
    return sorted(SCHEMA_ROOT.rglob("*.schema.json"))


@lru_cache(maxsize=1)
def load_schemas() -> dict[str, dict[str, Any]]:
    """Return every schema keyed by its ``$id``."""
    out: dict[str, dict[str, Any]] = {}
    for path in schema_files():
        schema = json.loads(path.read_text(encoding="utf-8"))
        out[schema["$id"]] = schema
    return out


@lru_cache(maxsize=1)
def registry() -> Registry:
    resources = [(sid, Resource.from_contents(schema)) for sid, schema in load_schemas().items()]
    return Registry().with_resources(resources)


def schema_id(relative: str) -> str:
    """``decoded/pdh_counters.schema.json`` -> its ``$id``."""
    return SCHEMA_BASE + relative


def schema(relative: str) -> dict[str, Any]:
    return load_schemas()[schema_id(relative)]


def validator(relative: str) -> Draft202012Validator:
    return Draft202012Validator(schema(relative), registry=registry())


def table_schema_version(table: str) -> str:
    return schema(f"decoded/{table}.schema.json")["x-schema-version"]


def validate_object(obj: Any, relative: str) -> list[str]:
    """Return a list of human readable validation errors (empty when valid)."""
    v = validator(relative)
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in v.iter_errors(obj)]


def validate_rows(rows: Iterable[Any], relative: str, limit: int = 20) -> list[str]:
    v = validator(relative)
    errors: list[str] = []
    for i, row in enumerate(rows):
        for e in v.iter_errors(row):
            errors.append(f"row {i}: {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}")
            if len(errors) >= limit:
                return errors
    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    return n


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
