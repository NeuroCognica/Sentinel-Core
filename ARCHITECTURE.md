# Sentinel Core Architecture

## Technical Overview
Sentinel Core is a governed, append-only, event-sourced security substrate for high-integrity systems. All privileged actions are cryptographically attributable, all audit events are immutable, and all failures are visible and queryable. Rust is the canonical source of truth; Python is for UI/orchestration only.

## Crate Structure
- crates/sentinel_core: Core types, policy, guard logic
- crates/sentinel_store: Append-only event log, state store
- crates/sentinel_identity: Users, keys, identity events, event-sourced reducer
- crates/sentinel_capabilities: Capability model, reducer, and event-sourced state
- crates/sentinel_api: HTTP API (login, register, health, guard, genesis, capability)
- crates/sentinel_cli: CLI for admin/dev
- python_ui: Python 3.12 client and UI harness

## Event Flow
- All system truth is derived from a hash-chained, file-backed event log (append-only ledger).
- State is rebuilt by replaying events from the ledger.
- Privileged requests use canonical envelopes and are logged before any action.
- No mutable state as truth; all state is event-sourced.

## Phase Descriptions
### Phase 1: Immutable Audit Spine
- Append-only, file-backed event log (SHA-256 hash chain, full-chain verification).
- Loud failure on tampering or integrity violation.
- No mutable state as truth; all system state is derived from the event log.

### Phase 2: Identity & Cryptographic Authority
- Canonical envelope for all privileged requests (actor_id, key_id, nonce, timestamp_utc, payload, signature).
- Ed25519 signature enforcement and persistent, event-sourced replay protection (nonce registry).
- All privileged actions require a valid, signed envelope; missing, invalid, replayed, or stale requests are rejected.
- Identity lifecycle (actor registration, key registration/revocation/rotation, nonce consumption) is fully event-sourced.

### Phase 3: Capabilities & Guard Enforcement
- Canonical Capability model: cryptographically signed, time-bounded, scope-limited, and strictly event-sourced.
- CapabilityIssued, CapabilityRevoked, and CapabilityConsumed events; all state is derived from the ledger.
- Event-sourced reducer for capabilities (no issuance for unknown actor, no revoking unknown, strict replay, single-use).
- /auth/challenge, /auth/login, /auth/logout, /whoami endpoints: all events logged before response, strict guard enforcement.

## Event Flow Diagrams
- [ ] Sequence diagram for challenge → login → whoami → logout
- [ ] System architecture diagram (crate dependencies, data flow)
- [ ] State machine diagram for capability lifecycle
- Use Mermaid or PlantUML for diagrams.

---

This document is the technical architecture record for Sentinel Core.
