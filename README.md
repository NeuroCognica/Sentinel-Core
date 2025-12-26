
cargo build
cargo run -p sentinel_api

# Sentinel Core

This repository implements Sentinel Core: a governed, append-only, event-sourced framework for secure, auditable, and policy-driven application logic. It is built in strict constitutional phases, with all privileged actions cryptographically attributable, all audit events immutable, and all failures visible and queryable. Rust is the canonical source of truth; Python 3.12 is used for UI/orchestration only.

---

## Quick Start
### Prerequisites
- Rust (latest stable)

### Build and Run (Rust)
```
cargo build
cargo run -p sentinel_api
```
### Python UI Health Check
```
python health_check.py
```

## Laws (Summary)
- Forever Law: All actions are logged before completion
- Sentinel Law: No bypass of guard boundary
- Never Boring: All faults are visible and queryable

## License
MIT
**Adversarial and Constitutional Test Coverage**
