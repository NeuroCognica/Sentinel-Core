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
- crates/sentinel_identity: Users, keys, identity events, event-sourced reducer
- crates/sentinel_capabilities: Capability model, reducer, and event-sourced state (Phase 3+)
- crates/sentinel_api: HTTP API (login, register, health, guard, genesis, capability)
- crates/sentinel_cli: CLI for admin/dev
- python_ui: Python 3.12 client and UI harness

## Laws
- Forever Law: All actions are logged before completion
- Sentinel Law: No bypass of guard boundary
- Never Boring: All faults are visible and queryable
## Phase 3: Capabilities (Constitutional Privilege)

- **Canonical Capability Model**: Capabilities are cryptographically signed, time-bounded, and scope-limited tokens with:
  - `capability_id` (UUID)
  - `actor_id` (who receives it)
  - `issued_at_utc`, `expires_at_utc`
  - `scope` (e.g. system, aura:memory)
  - `actions` (strict list)
  - `constraints` (optional, e.g. artifact digests, rate limits)
  - `issued_by` (Sentinel service identity)
  - `token_signature` (Ed25519 signature over canonical fields)

- **Capability Events**:
  - `CapabilityIssued`: Capability is created, signed, and logged
  - `CapabilityRevoked`: Capability is revoked and cannot be used
  - `CapabilityConsumed`: (Optional) Capability is used and logged as consumed

- **Event-Sourced Enforcement**:
  - All capability state is derived from the append-only ledger (no RAM truth)
  - Capabilities are only valid if present, active, and unexpired in the ledger
  - Revocation and consumption are logged as events and enforced by the reducer

- **No Trusted Tokens**: A stolen or expired token is powerless unless the ledger says it is valid and active.

- **Separation of Concerns**: Capability lifecycle is managed in `sentinel_capabilities`, not in identity or API logic. This prevents privilege escalation and keeps the system constitutional.

---

## License
MIT

# Sentinel Core: Immutable Ledger & Cryptographic Authority

## Overview
Sentinel Core is a governed, append-only ledger and authority engine designed for high-integrity, enterprise-grade audit and authorization. It enforces strict, law-driven invariants at every layer, ensuring that every privileged action is cryptographically attributable and every audit event is immutable, tamper-evident, and forever verifiable.

## Phase 1: Immutable Audit Spine (Ledger)
- **Canonical Event Log**: All events are recorded in an append-only, file-backed ledger (not a mutable log).
- **SHA-256 Hash Chain**: Each event is chained to the previous by a SHA-256 hash, forming an unbreakable chain of custody.
- **Full-Chain Verification**: On startup, the entire chain is verified. Any tampering (edit, deletion, reorder) is detected deterministically.
- **Loud Failure**: On any integrity violation, Sentinel fails closed with a visible, themed error message. No silent corruption is possible.
- **No Amendments**: Once committed, the audit spine is sacred. No rebases, no quick fixes, no retroactive edits.

## Phase 2: Identity & Cryptographic Authority
- **Canonical Envelope**: All privileged requests must be wrapped in a constitutional envelope containing:
  - `actor_id`: Stable identity (UUID)
  - `key_id`: Key used to sign
  - `nonce`: Unique per request (replay protection)
  - `timestamp_utc`: Request time (freshness window)
  - `payload`: The requested action (generic, e.g., AuthorizationRequest)
  - `signature`: Ed25519 signature over all fields except itself
- **Minimal Authorization Payload**: The first payload is a simple struct:
  - `action`: e.g., "health_check"
  - `scope`: e.g., "system"
  - `intent`: Free text, logged verbatim
- **Signature Enforcement**: All privileged endpoints require a valid, signed envelope. Missing, invalid, replayed, or stale requests are rejected.
- **Replay Protection**: In-memory LRU of (actor_id, nonce) pairs prevents duplicate requests.
- **Request Digest Logging**: Before any authorization decision, the canonical envelope is hashed and logged as an `AuthorizationRequestReceived` event. If logging fails, the request fails.
- **No Policy Yet**: Step 1 is about identity, proof, and record—not allow/deny logic.

## Dev/Test Instrumentation
- **make_envelope Helper**: A dev-only tool to generate valid signed envelopes for verification. Uses a fixed, inline keypair matching the server's dev root. Strictly quarantined from production.

## Law-Driven Guarantees
- **FOREVER LAW**: All audit and authorization records are immutable and verifiable for the life of the system.
- **SENTINEL LAW**: No privileged action exists without cryptographic proof of origin.
- **NEVER BORING**: All failures are visible, attributable, and themed—no silent errors.

## Verification & Commit
- All phases are verified by explicit, adversarial tests (tamper, replay, signature, and freshness attacks).
- Only after passing all tests is a canonical commit made, establishing the ledger as the root of trust.

## Next Steps
- Phase 2 Step 2: Real key management, persistent replay protection, and policy enforcement.
- All future authority and policy will be built on this immutable, identity-bound ledger.

---

**This document is the constitutional record of what Sentinel Core enforces and guarantees as of this commit.**
