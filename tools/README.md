Schema Lock Tool
=================

Purpose
-------
Enforce the Law of Shape: ensure canonical schemas in `aura/schemas` are authoritative and that `sentinel-core/openapi.json` aligns with them.

Files created
-------------
- `tools/schema_lock.py` — script that checks existence, validates canonical schema syntax, and compares `components.schemas.CanonicalEnvelope` in `openapi.json` to `aura/schemas/CanonicalEnvelope.json`.

Requirements
------------
- Python 3.8+
- `jsonschema` Python package (install with `pip install jsonschema`)

Quick usage
-----------
From `c:\sentinel-core` run:

```powershell
python tools\schema_lock.py
```

Exit codes
----------
- `0` = success (parity)
- `1` = missing files or syntax/load errors
- `2` = parity mismatch (drift)

CI snippet (GitHub Actions)
---------------------------
Add this job as an early step in your pipeline to enforce schema parity:

```yaml
name: Schema Lock
on: [push, pull_request]

jobs:
  schema-lock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install deps
        run: python -m pip install --upgrade pip && pip install jsonschema
      - name: Run Schema Lock
        working-directory: sentinel-core
        run: python tools/schema_lock.py
```

Rust parity test (recommended)
------------------------------
Add a small Rust test/binary (`schema_check`) that serializes the production `CanonicalEnvelope` struct and prints the JSON to stdout. The CI step can run `cargo run --bin schema_check` and pipe that output to a JSON Schema validator to confirm parity.

Example (CI) step to run Rust parity check (after building):

```yaml
- name: Rust parity check
  working-directory: sentinel-core
  run: |
    cargo build --bins --release
    cargo run --bin schema_check > /tmp/rust_envelope.json
    python -c "import json,sys; from jsonschema import validate; s=json.load(open('/tmp/rust_envelope.json')); schema=json.load(open('../aura/schemas/CanonicalEnvelope.json')); validate(instance=s, schema=schema); print('Rust parity OK')"
```

Notes
-----
- The script currently performs a structural comparison that ignores non-structural metadata (descriptions, titles, examples). This reduces false positives while keeping strict shape parity.
- If you want stricter comparison rules (e.g., exact titles or examples), the script can be adjusted.

Workflow
--------
The repository includes a GitHub Actions workflow that enforces the Schema Authority Lock on `push`/`pull_request` to `main`/`master`.
- Workflow path: [.github/workflows/schema-lock.yml](.github/workflows/schema-lock.yml)
- The workflow runs `python sentinel-core/tools/schema_lock.py` as its enforcement step.

Please ensure you run `schema_lock.py` locally before opening a PR to avoid CI noise.
