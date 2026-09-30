#!/usr/bin/env python3
"""Check the capture half of a bundle's container integrity.

This is what the Mac runs on a bundle a collector wrote before anything
decodes it: items 1 and 2 of docs/contracts/bundle.md section 3.

1. ``manifest.json`` validates against the manifest schema.
2. Every artifact the manifest lists exists with the listed byte count and
   SHA-256, no artifact is listed twice, and no file under ``raw/`` is
   unlisted.

It also checks the rule from docs/contracts/measurement-status.md that a
collector reports either an observation or a reason, never both and never
neither. Decoded tables, evidence, and the verdict are outside its scope;
the full ``Validate-Bundle`` is a later phase.

Usage::

    python scripts/verify_bundle.py <bundle directory>

Prints one JSON object and exits 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_schema  # noqa: E402

OBSERVED = ("observed", "observed_zero")


def check(name: str, ok: bool, detail: str | None = None) -> dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail}


def verify(bundle: Path) -> dict[str, Any]:
    """Return ``{"ok": bool, "bundle_id": str | None, "checks": [...]}``."""
    checks: list[dict[str, Any]] = []
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        return {"ok": False, "bundle_id": None, "checks": [check("manifest_present", False, "manifest.json is missing")]}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"ok": False, "bundle_id": None, "checks": [check("manifest_parses", False, str(exc))]}
    errors = wf_schema.validate_object(manifest, "manifest.schema.json")
    checks.append(check("manifest_schema", not errors, "; ".join(errors[:5]) or None))
    if errors:
        return {"ok": False, "bundle_id": manifest.get("bundle_id") if isinstance(manifest, dict) else None, "checks": checks}

    listed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    problems: list[str] = []
    root = bundle.resolve()
    for collector in manifest["collectors"]:
        for artifact in collector["artifacts"]:
            path = artifact["path"]
            if path in listed:
                duplicates.append(path)
                continue
            listed[path] = artifact
            target = (bundle / path).resolve()
            if root not in target.parents:
                problems.append(f"{path}: resolves outside the bundle")
            elif not target.is_file():
                problems.append(f"{path}: missing")
            elif target.stat().st_size != artifact["bytes"]:
                problems.append(f"{path}: {target.stat().st_size} bytes on disk, {artifact['bytes']} listed")
            elif wf_schema.sha256_of(target) != artifact["sha256"]:
                problems.append(f"{path}: sha256 differs from the manifest")
    checks.append(check("artifacts_listed_once", not duplicates, "; ".join(duplicates) or None))
    checks.append(check("artifacts_match_manifest", not problems, "; ".join(problems[:10]) or f"{len(listed)} artifacts"))

    raw = bundle / "raw"
    on_disk = {p.relative_to(bundle).as_posix() for p in raw.rglob("*") if p.is_file()} if raw.is_dir() else set()
    unlisted = sorted(on_disk - set(listed))
    checks.append(check("no_unlisted_raw_file", not unlisted, "; ".join(unlisted[:10]) or None))

    status_problems = []
    for collector in manifest["collectors"]:
        if collector["status"] in OBSERVED:
            if not collector["artifacts"]:
                status_problems.append(f"{collector['id']}: {collector['status']} without an artifact")
        elif not collector["status_reason"]:
            status_problems.append(f"{collector['id']}: {collector['status']} without a reason")
    checks.append(check("status_has_artifact_or_reason", not status_problems, "; ".join(status_problems) or None))

    return {"ok": all(c["ok"] for c in checks), "bundle_id": manifest["bundle_id"], "checks": checks}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", type=Path)
    args = ap.parse_args(argv)
    result = verify(args.bundle)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
