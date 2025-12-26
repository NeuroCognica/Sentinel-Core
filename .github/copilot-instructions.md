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

nonce consumption (replay protection)

No identity fact may exist outside the ledger.

Key Management Rules

Multiple keys per actor are allowed.

Keys have explicit status: Active or Revoked.

Revoked keys must never verify successfully.

Key reuse without explicit rotation is forbidden.

Dev/test keys must be quarantined behind explicit flags and never default-on.

Canonical Envelope (Mandatory)

All privileged requests must use a canonical, deterministic envelope.

An envelope minimally includes:

actor_id

key_id

nonce

timestamp_utc

payload

signature

Rules:

Signature covers all unsigned fields.

Serialization is deterministic.

Missing or malformed envelope → reject.

Invalid signature → reject.

Stale timestamp → reject.

Replayed nonce → reject.

No envelope → no authority.

Replay Protection (Persistent)

Replay protection must persist across restarts.

A nonce is considered used only if a corresponding immutable event exists in the ledger.

In-memory caches are allowed only as performance optimizations derived from events.

Event Ordering (Critical)

For valid privileged requests, the following ordering is mandatory:

Verify envelope (signature, freshness, replay)

Append AuthorizationRequestReceived (or equivalent)

Append NonceConsumed

Return decision

If any append fails, the request must fail.

For invalid requests:

Append nothing

Return rejection

Do not pollute the ledger

Testing Doctrine

Tests must be adversarial, not cosmetic.

Minimum expectations for any feature touching authority:

tamper detection tests

replay tests (including restart simulation)

invalid signature tests

revoked key tests

ordering tests (log before respond)

fail-closed behavior on storage failure

A test that “passes” without asserting invariants is insufficient.

What Sentinel Is Not (Do Not Implement Here)

Unless explicitly instructed, Sentinel must not include:

UI state

business logic

LLM reasoning

policy DSLs beyond minimal authorization

mutable user sessions as truth

side-effect execution logic

Sentinel authorizes. Others execute.

Contribution Standard

When generating or modifying code:

Prefer explicitness over convenience.

Prefer rejection over assumption.

Prefer determinism over flexibility.

Prefer evidence over inference.

If you are unsure whether a change violates a law, it does.

Stop and redesign.

Canonical Intent

Sentinel exists to make systems incapable of lying about what happened.

Any code that weakens that guarantee is incorrect, regardless of intent or elegance.

This file is constitutional.
Do not soften it.
Do not summarize it.
Do not bypass it.