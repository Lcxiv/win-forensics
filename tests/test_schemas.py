"""Every committed schema is a valid draft 2020-12 schema and every $ref resolves."""
from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

import wf_schema

SCHEMA_IDS = sorted(wf_schema.load_schemas())


@pytest.mark.parametrize("schema_id", SCHEMA_IDS)
def test_schema_is_valid_draft_2020_12(schema_id):
    Draft202012Validator.check_schema(wf_schema.load_schemas()[schema_id])


@pytest.mark.parametrize("schema_id", SCHEMA_IDS)
def test_schema_id_matches_path(schema_id):
    relative = schema_id.removeprefix(wf_schema.SCHEMA_BASE)
    path = wf_schema.SCHEMA_ROOT / relative
    assert path.exists(), f"{schema_id} does not match a file under schemas/"
    assert json.loads(path.read_text(encoding="utf-8"))["$id"] == schema_id


@pytest.mark.parametrize("schema_id", SCHEMA_IDS)
def test_schema_declares_version(schema_id):
    schema = wf_schema.load_schemas()[schema_id]
    assert "x-schema-version" in schema


def test_every_decoded_table_schema_requires_provenance():
    for schema_id, schema in wf_schema.load_schemas().items():
        if "/decoded/" not in schema_id or schema_id.endswith(("provenance.schema.json", "table_meta.schema.json")):
            continue
        assert "provenance" in schema["required"], schema_id
        table = schema["x-decoded-table"]
        assert schema_id.endswith(f"/{table}.schema.json")
        pinned = schema["properties"]["provenance"]["allOf"][1]["properties"]
        assert pinned["decoded_table"]["const"] == table
        assert pinned["schema_version"]["const"] == schema["x-schema-version"]


def test_refs_resolve_by_validating_a_minimal_provenance():
    good = {"source_file": "raw/x/y.txt", "row_id_or_offset": "line:1", "decoded_table": "pdh_counters",
            "decoder_version": "1.0.0", "schema_version": "1.0.0"}
    assert wf_schema.validate_object(good, "decoded/provenance.schema.json") == []
    bad = dict(good, row_id_or_offset="somewhere")
    assert wf_schema.validate_object(bad, "decoded/provenance.schema.json")


def test_status_vocabulary_is_exactly_the_contract():
    status = wf_schema.schema("common.schema.json")["$defs"]["measurement_status"]["enum"]
    assert status == ["observed", "observed_zero", "not_applicable", "not_collected", "capture_failed",
                      "decode_failed", "unsupported", "analyzer_failed"]


def test_absent_evidence_requires_adequate_coverage_ref():
    base = {
        "row_id": "r1", "ts_utc": "2026-01-01T00:00:00Z", "window": {"start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T00:00:10Z"},
        "t_master_100ns": None, "clock_error_bound_100ns": None, "collected_ts_utc": "2026-01-01T00:00:00Z",
        "source": "pdh", "subsystem": "cpu_dpc", "signal": "example_signal", "metric": "example_metric", "unit": "count",
        "value": 0, "severity": "info", "faulting_module": None, "cpu": None, "confidence": 1.0, "evidence_kind": "absent",
        "coverage_ref": {"collector_id": "pdh", "analyzer_id": "example", "window": {"start_utc": "2026-01-01T00:00:00Z", "end_utc": "2026-01-01T00:00:10Z"}, "status": "observed_zero"},
        "provenance": [], "links": [], "incident_id": None, "analyzer": {"id": "example", "version": "0.0.0"}, "playbook": None, "payload": {},
    }
    assert wf_schema.validate_object(base, "evidence.schema.json") == []
    for bad_status in ("not_collected", "capture_failed", "not_applicable", "decode_failed", "unsupported", "analyzer_failed"):
        row = json.loads(json.dumps(base))
        row["coverage_ref"]["status"] = bad_status
        assert wf_schema.validate_object(row, "evidence.schema.json"), bad_status
    row = json.loads(json.dumps(base))
    row["coverage_ref"] = None
    assert wf_schema.validate_object(row, "evidence.schema.json")


def test_observed_evidence_needs_provenance_and_full_confidence():
    row = {
        "row_id": "r1", "ts_utc": "2026-01-01T00:00:00Z", "window": None, "t_master_100ns": None, "clock_error_bound_100ns": None,
        "collected_ts_utc": "2026-01-01T00:00:00Z", "source": "pdh", "subsystem": "cpu_dpc", "signal": "s", "metric": "m",
        "unit": "pct", "value": 1.5, "severity": "info", "faulting_module": None, "cpu": 1, "confidence": 1.0,
        "evidence_kind": "observed", "coverage_ref": None,
        "provenance": [{"source_file": "raw/pdh/c.csv", "row_id_or_offset": "row:1;col:2", "decoded_table": "pdh_counters", "decoder_version": "1.0.0", "schema_version": "1.0.0"}],
        "links": [], "incident_id": None, "analyzer": {"id": "a", "version": "0.0.0"}, "playbook": None, "payload": {},
    }
    assert wf_schema.validate_object(row, "evidence.schema.json") == []
    assert wf_schema.validate_object(dict(row, provenance=[]), "evidence.schema.json")
    assert wf_schema.validate_object(dict(row, confidence=0.9), "evidence.schema.json")
    inferred = dict(row, evidence_kind="inferred", confidence=0.9, links=["r0"])
    assert wf_schema.validate_object(inferred, "evidence.schema.json") == []
    assert wf_schema.validate_object(dict(inferred, links=[]), "evidence.schema.json")
    assert wf_schema.validate_object(dict(inferred, confidence=1.0), "evidence.schema.json")
