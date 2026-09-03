"""The example bundle validates end to end against the committed schemas and its own provenance."""
from __future__ import annotations

import json

import pytest

import wf_schema

DECODED_TABLES = ["dpcisr_module_cpu", "dpcisr_interval", "pdh_counters"]


@pytest.fixture(scope="module")
def manifest(example_bundle):
    return json.loads((example_bundle / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def verdict(example_bundle):
    return json.loads((example_bundle / "verdict.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def evidence(example_bundle):
    return wf_schema.read_jsonl(example_bundle / "evidence.jsonl")


def artifacts_by_path(manifest):
    return {a["path"]: a for c in manifest["collectors"] for a in c["artifacts"]}


def test_manifest_validates(manifest):
    assert wf_schema.validate_object(manifest, "manifest.schema.json") == []


def test_manifest_artifacts_exist_with_matching_hashes(example_bundle, manifest):
    listed = artifacts_by_path(manifest)
    assert listed, "manifest lists no artifacts"
    for path, art in listed.items():
        f = example_bundle / path
        assert f.exists(), path
        assert f.stat().st_size == art["bytes"], path
        assert wf_schema.sha256_of(f) == art["sha256"], path
    on_disk = {str(p.relative_to(example_bundle)).replace("\\", "/") for p in (example_bundle / "raw").rglob("*") if p.is_file()}
    assert on_disk == set(listed), "every file under raw/ must be listed exactly once"


def test_manifest_status_separation(manifest):
    for c in manifest["collectors"]:
        if c["status"] in ("observed", "observed_zero"):
            assert c["artifacts"], f"{c['id']} is observed but has no artifact"
        else:
            assert c["status_reason"], f"{c['id']} has status {c['status']} without a reason"
    assert manifest["calibration"]["status"] == "not_collected"
    assert manifest["calibration"]["pairs"] == []


@pytest.mark.parametrize("table", DECODED_TABLES)
def test_decoded_table_and_sidecar_validate(example_bundle, manifest, table):
    rows = wf_schema.read_jsonl(example_bundle / "decoded" / f"{table}.jsonl")
    assert rows
    assert wf_schema.validate_rows(rows, f"decoded/{table}.schema.json") == []
    meta = json.loads((example_bundle / "decoded" / f"{table}.meta.json").read_text())
    assert wf_schema.validate_object(meta, "decoded/table_meta.schema.json") == []
    assert meta["row_count"] == len(rows)
    listed = artifacts_by_path(manifest)
    for src in meta["source_files"]:
        assert src["path"] in listed and listed[src["path"]]["sha256"] == src["sha256"]
    for row in rows:
        p = row["provenance"]
        assert p["decoded_table"] == table
        assert p["source_file"] in listed
        assert p["schema_version"] == meta["schema_version"]


def test_evidence_rows_validate_and_resolve(example_bundle, manifest, evidence):
    assert evidence, "example bundle should carry at least one evidence row"
    assert wf_schema.validate_rows(evidence, "evidence.schema.json") == []
    listed = artifacts_by_path(manifest)
    ids = {r["row_id"] for r in evidence}
    assert len(ids) == len(evidence)
    tables = {t: wf_schema.read_jsonl(example_bundle / "decoded" / f"{t}.jsonl") for t in DECODED_TABLES}
    for row in evidence:
        for link in row["links"]:
            assert link in ids
        for p in row["provenance"]:
            assert p["source_file"] in listed
            matches = [d for d in tables[p["decoded_table"]] if d["provenance"]["row_id_or_offset"] == p["row_id_or_offset"]]
            assert matches, f"{row['row_id']}: provenance {p} does not resolve to a decoded row"
            if row["evidence_kind"] == "observed" and row["value"] is not None:
                field = row["payload"]["decoded_column"]
                extra = {k: v for k, v in row["payload"].get("decoded_match", {}).items()}
                chosen = [d for d in matches if all(d.get(k) == v for k, v in extra.items())]
                assert chosen, f"{row['row_id']}: decoded_match {extra} selects no row"
                assert chosen[0][field] == row["value"], f"{row['row_id']}: value differs from the decoded row"
        if row["evidence_kind"] == "absent":
            pytest.fail("the example bundle has no adequately covered window, so it may not carry absence rows")


def test_verdict_validates_and_is_consistent(manifest, verdict, evidence):
    assert wf_schema.validate_object(verdict, "verdict.schema.json") == []
    assert verdict["bundle_id"] == manifest["bundle_id"]
    assert verdict["outcome"] == "no_verdict" and verdict["hypotheses"] == []
    cov = {c["collector_id"]: c for c in verdict["coverage"]["collectors"]}
    for c in manifest["collectors"]:
        assert c["id"] in cov, f"coverage table lacks collector {c['id']}"
        assert cov[c["id"]]["measurement_status"] == c["status"]
    for c in cov.values():
        if c["measurement_status"] != "observed":
            assert c["clock_fit"] is None or c["clock_fit"]["model"] == "unaligned"
    assert all(not j["aligned"] for j in verdict["joins"]), "no join can be aligned without calibration pairs"
    analyzers = {a["analyzer_id"] for a in verdict["coverage"]["analyzers"]}
    for row in evidence:
        assert row["analyzer"]["id"] in analyzers
    assert verdict["validation"]["container_integrity"]["ok"] is True
    assert verdict["validation"]["evidentiary_adequacy"]["ok"] is False
    assert verdict["versions"]["manifest_schema"] == manifest["manifest_version"]
