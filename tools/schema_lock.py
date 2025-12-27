#!/usr/bin/env python3
"""
Schema Lock Script
Performs:
 - Existence checks for canonical schemas
 - Syntax validation (JSON Schema Draft-07+)
 - Parity check: compare OpenAPI components/schemas/CanonicalEnvelope to canonical file

Exit codes:
 0 = OK
 1 = Missing files / syntax errors
 2 = Parity mismatch

Usage: python tools/schema_lock.py
"""
from __future__ import annotations
import sys
import json
from pathlib import Path
from typing import Any, Dict
import difflib
import subprocess
from jsonschema import validate, ValidationError

try:
    import jsonschema
except Exception as e:
    print("Missing dependency: jsonschema. Install with: pip install jsonschema")
    raise

ROOT = Path(__file__).resolve().parents[1]
AURA_SCHEMAS = ROOT.parent / "aura" / "schemas"
CANONICAL_ENVELOPE = AURA_SCHEMAS / "CanonicalEnvelope.json"
CANONICAL_EXECUTION_PROOF = AURA_SCHEMAS / "execution_proof.schema.json"
OPENAPI = ROOT / "openapi.json"


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise


def normalize_schema(s: Any) -> Any:
    """Remove non-structural fields that are allowed to differ (description, title, examples, default, $comment).
    Returns a deep-copied normalized structure suitable for structural comparison.
    """
    if isinstance(s, dict):
        out = {}
        for k, v in s.items():
            if k in ("description", "title", "examples", "default", "$comment", "examples"):
                continue
            out[k] = normalize_schema(v)
        return out
    if isinstance(s, list):
        return [normalize_schema(x) for x in s]
    return s


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def diff_objects(a: Any, b: Any) -> str:
    a_s = pretty_json(a).splitlines(keepends=True)
    b_s = pretty_json(b).splitlines(keepends=True)
    return ''.join(difflib.unified_diff(a_s, b_s, fromfile='canonical', tofile='openapi'))


def main() -> int:
    errors = 0

    # Existence
    missing = []
    for p in (CANONICAL_ENVELOPE, CANONICAL_EXECUTION_PROOF, OPENAPI):
        if not p.exists():
            missing.append(str(p))
    if missing:
        print("Missing required files:")
        for m in missing:
            print(" -", m)
        return 1

    # Load canonical envelope
    try:
        canonical = load_json(CANONICAL_ENVELOPE)
    except Exception as e:
        print(f"Failed to load canonical envelope: {e}")
        return 1

    # Validate schema syntax
    try:
        jsonschema.Draft7Validator.check_schema(canonical)
    except Exception as e:
        print(f"Canonical envelope is not a valid Draft-07+ JSON Schema: {e}")
        return 1

    # Load openapi and find components/schemas/CanonicalEnvelope
    # Regenerate openapi.json via the gen_openapi binary (feature-gated)
    try:
        regen = subprocess.run([
            "cargo",
            "run",
            "--quiet",
            "--bin",
            "gen_openapi",
            "--",
        ], cwd=str(ROOT), capture_output=True, text=True, check=True)
        # Write the regenerated openapi JSON to the expected path so subsequent tooling sees it
        with OPENAPI.open("w", encoding="utf-8") as f:
            f.write(regen.stdout)
    except subprocess.CalledProcessError as e:
        print("Failed to regenerate openapi.json via gen_openapi:")
        print(e.stderr)
        return 1
    try:
        openapi = load_json(OPENAPI)
    except Exception as e:
        print(f"Failed to load openapi.json: {e}")
        return 1

    openapi_schema = None
    try:
        openapi_schema = openapi.get("components", {}).get("schemas", {}).get("CanonicalEnvelope")
    except Exception:
        openapi_schema = None

    if not openapi_schema:
        print("OpenAPI does not contain components.schemas.CanonicalEnvelope")
        return 2

    # Normalize both schemas for structural comparison
    norm_canonical = normalize_schema(canonical)
    norm_openapi = normalize_schema(openapi_schema)

    if norm_canonical != norm_openapi:
        print("Schema parity mismatch detected between aura CanonicalEnvelope and OpenAPI CanonicalEnvelope.")
        d = diff_objects(norm_canonical, norm_openapi)
        print(d)
        return 2

    # Rust parity check: run cargo-run binary schema_dump -- envelope and validate its JSON output
    print("Running Rust parity check (schema_dump)...")
    try:
        result = subprocess.run(
            ["cargo", "run", "--quiet", "--bin", "schema_dump", "--", "envelope"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print("Failed to execute Rust schema_dump:")
        print(e.stderr)
        return 2

    try:
        rust_json = json.loads(result.stdout)
    except Exception as e:
        print(f"Failed to parse JSON output from Rust schema_dump: {e}")
        return 2

    try:
        validate(instance=rust_json, schema=canonical)
    except ValidationError as e:
        print("Rust struct output does not validate against canonical schema:")
        print(e)
        return 2

    print("Schema lock: OK — canonical envelope matches OpenAPI's CanonicalEnvelope and Rust parity verified.")
    return 0


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
