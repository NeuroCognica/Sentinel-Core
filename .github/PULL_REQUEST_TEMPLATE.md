## Purpose
Brief description of the change and which part of the system it affects.

## Summary of Changes
- List the files and modules modified.
- Note any schema or API changes and point to `aura/schemas` canonical sources.

## Schema Authority Check
This repository enforces the Schema Authority Lock. All PRs must pass the `Schema Authority Lock` workflow. The workflow runs `sentinel-core/tools/schema_lock.py` which:
- validates `aura/schemas/CanonicalEnvelope.json` and `aura/schemas/execution_proof.schema.json`
- regenerates `sentinel-core/openapi.json` and ensures its `components.schemas.CanonicalEnvelope` matches the canonical file
- runs `cargo run --bin schema_dump -- envelope` and validates the serialized Rust `CanonicalEnvelope` against the canonical schema

If your changes update any data contracts, update the authoritative JSON schema files in `aura/schemas/` first, then adjust Rust/Python code and re-run `tools/schema_lock.py` locally before pushing.

## Testing
- How to run unit/integration tests locally
- How to run the schema lock script locally:
```powershell
python sentinel-core\tools\schema_lock.py
```

## Notes for Reviewers
- Point to any intentional deviations and provide rationale.
