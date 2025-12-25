# Sentinel Core

This repository is a governed, append-only, event-sourced framework for secure, auditable, and policy-driven application logic. It uses Rust as the canonical source of truth and Python 3.12 as the UI/orchestration layer.

## Quick Start

### Prerequisites
- Rust (latest stable)
- Python 3.12 (not 3.13+)

### Build and Run (Rust)

```
cargo build
cargo run -p sentinel_api
```

### Python UI Health Check

```
cd python_ui
python health_check.py
```

## Workspace Structure
- crates/sentinel_core: Core types, policy, guard logic
- crates/sentinel_store: Append-only event log, state store
- crates/sentinel_identity: Users, roles, sessions, events
- crates/sentinel_api: HTTP API (login, register, health, guard)
- crates/sentinel_cli: CLI for admin/dev
- python_ui: Python 3.12 client and UI harness

## Laws
- Forever Law: All actions are logged before completion
- Sentinel Law: No bypass of guard boundary
- Never Boring: All faults are visible and queryable

## License
MIT
