## Sentinel Core — AI Coding Agent Instructions

**Purpose:**
Sentinel Core is a governed, append-only, event-sourced security substrate for high-integrity systems. All privileged actions are cryptographically attributable, all audit events are immutable, and all failures are visible and queryable. Rust is the canonical source of truth; Python is for UI/orchestration only.

---

### Constitutional Laws (Non-Negotiable)
- **FOREVER LAW:** All actions of consequence are immutably logged before completion. No mutable “truth” stores, silent overwrites, or retroactive edits. If an event cannot be logged, the action must fail.
- **SENTINEL LAW:** No privileged action may bypass the guard boundary. All authority flows through canonical envelopes and verified identity. No hidden admin paths, debug backdoors, or trust-by-assumption.
- **NEVER BORING LAW:** All failures must be visible, attributable, and queryable. No swallowed errors or ambiguous states. Fail closed, fail loud, fail honestly.

---

### Architecture & Major Components
- **Append-only event ledger:** All system truth is derived from a hash-chained, file-backed event log (`crates/sentinel_store`). No mutable state as truth; all state is rebuilt by replaying events.
- **Identity & Authority:** All privileged requests use a canonical envelope (`actor_id`, `key_id`, `nonce`, `timestamp_utc`, `payload`, `signature`). Identity lifecycle (registration, key management, nonce consumption) is fully event-sourced (`crates/sentinel_identity`).
- **Capabilities:** Capabilities are cryptographically signed, time-bounded, scope-limited, and strictly event-sourced (`crates/sentinel_capabilities`).
- **API:** HTTP interface (`crates/sentinel_api`) enforces guard boundaries and logs all privileged actions as events before any decision.
- **CLI & UI:** `crates/sentinel_cli` is for admin/dev only (never bypasses Sentinel). `python_ui` is a client harness, never an authority.

---

### Developer Workflows
- **Build:** `cargo build` (Rust stable required)
- **Run API:** `cargo run -p sentinel_api` (serves HTTP on 127.0.0.1:8080)
- **Python UI Health Check:** `python health_check.py` (requires Python 3.12, see `python_ui/SETUP_VENV.txt`)
- **Dev envelope generation:** Use `crates/sentinel_identity/src/bin/make_envelope.rs` for generating signed envelopes in dev/test (never ship dev keys to production).
- **Testing:** All features must be covered by adversarial tests (tamper, replay, signature, revocation, ordering, fail-closed on storage failure). See `crates/sentinel_identity/src/replay_tests.rs` for replay protection tests.

---

### Project-Specific Conventions
- **No cross-crate shortcuts:** Each crate enforces strict separation (core, store, identity, capabilities, api, cli, python_ui). Never collapse boundaries.
- **Event ordering:** For privileged requests: verify envelope → append AuthorizationRequestReceived → append NonceConsumed → return decision. If any append fails, the request fails.
- **No mutable sessions:** All session/capability state is derived from the ledger, never RAM.
- **No UI/business logic in Sentinel:** Sentinel only authorizes; execution is external.
- **All authority is event-sourced:** No identity, key, or capability fact may exist outside the ledger.

---

### Key Files & Patterns
- `crates/sentinel_core/src/lib.rs`: Canonical types, envelope, event, and capability models
- `crates/sentinel_store/src/lib.rs`: Append-only event store, hash chain, corruption detection
- `crates/sentinel_identity/src/lib.rs`: Identity lifecycle, key registry, replay protection
- `crates/sentinel_capabilities/src/lib.rs`: Capability reducer, event-sourced state
- `crates/sentinel_api/src/main.rs`: HTTP API, guard enforcement, event logging
- `python_ui/SETUP_VENV.txt`: Python 3.12 setup (strict version)

---

### Integration & External Points
- **API endpoints:** `/auth/challenge`, `/auth/login`, `/auth/logout`, `/whoami`, `/genesis`, `/health` (see `sentinel_api`)
- **OpenAPI/Swagger:** Use the provided task to generate OpenAPI spec and host Swagger UI for docs.
- **Dev/test keys:** Strictly quarantined; never default-on in production.

---

### Example: Canonical Envelope (Rust)
```rust
pub struct CanonicalEnvelopeAuthorizationRequest {
	pub actor_id: Uuid,
	pub key_id: Uuid,
	pub nonce: Uuid,
	pub timestamp_utc: DateTime<Utc>,
	pub payload: AuthorizationRequest,
	pub signature: Vec<u8>,
}
```

---

**This file is constitutional. Do not soften, summarize, or bypass these instructions.**

Sentinel does not store mutable state as truth.

All system truth is derived from an append-only, hash-chained event ledger.

If current state is required (e.g., active users, valid keys, used nonces), it must be:

deterministically rebuilt by replaying events

optionally cached only if the cache is fully rebuildable

invalidated on any integrity anomaly

Separation of Concerns (Strict)

The workspace is intentionally separated:

sentinel_core
Canonical types, envelopes, events, laws, invariants

sentinel_store
Append-only event persistence, hash chaining, verification

sentinel_identity
Identity lifecycle, key registry, replay protection (derived from events)

sentinel_api
HTTP interface enforcing guard boundaries

sentinel_cli
Admin/dev tooling only (never bypassing Sentinel)

python_ui
Client / UI harness only (never authority)

Never collapse these layers.
If a feature “needs access” across boundaries, it is designed wrong.

Identity Model (Phase 2 · Step 2)

Identity is cryptographic, not social.

An identity is defined as:

An actor capable of producing signatures Sentinel can verify.

Identity Lifecycle Is Event-Sourced

All identity operations must be represented as immutable events, including:

actor registration

key registration

key revocation

key rotation
# Sentinel Core — Copilot / AI Agent Instructions (concise)

## Purpose
Sentinel is an append-only, event-sourced security substrate. Rust is the canonical source of truth; Python is a client/orchestration layer only.

## Quick start
- Build: `cargo build`
- Run API: `cargo run -p sentinel_api` (127.0.0.1:8080)
- Generate OpenAPI: use the VS Code task `Generate OpenAPI Spec` or run `cargo run -p sentinel_api --features openapi > openapi.json`
- Python health check: `python python_ui/health_check.py` (see `python_ui/SETUP_VENV.txt`)

## Architecture snapshot
- `crates/sentinel_store`: append-only, hash-chained event ledger (single source of truth).
- `crates/sentinel_identity`: actor/key lifecycle and replay protection (event-sourced).
- `crates/sentinel_capabilities`: capability reducer; state derived from events.
- `crates/sentinel_api`: guard enforcement; emits events before decisions.
- `crates/sentinel_core`: canonical types (envelope, event, capability).

## Must-follow conventions
- Immutable audit-first: append events before responding. If append fails, fail the request.
- Canonical envelope required: `actor_id`, `key_id`, `nonce`, `timestamp_utc`, `payload`, `signature`.
- Privileged request ordering: verify envelope → append AuthorizationRequestReceived → append NonceConsumed → return decision.
- No authoritative mutable RAM state: all facts must be reconstructable by replay.

## Where to look (examples/tests)
- Replay tests: `crates/sentinel_identity/src/replay_tests.rs`
- API enforcement & OpenAPI: `crates/sentinel_api/src/main.rs` and `crates/sentinel_api/src/openapi.rs`
- Store implementation: `crates/sentinel_store/src/lib.rs`

## Testing & CI
- Tests must be adversarial: tamper, replay, invalid signatures, revoked keys, ordering, and fail-closed on storage failure.
- Use `cargo test`; use the provided tasks for integration/bench and OpenAPI generation.

## Developer cautions
- Do not add cross-crate shortcuts that bypass guard boundaries.
- Dev/test keys must be quarantined; never shipped or enabled by default.
- Sentinel crates authorize only; business execution and UI state belong outside the sentinel crates.

---
If you want this expanded into a contributor checklist, sequence diagrams for the envelope flow, or a short PR checklist, tell me which to add next.