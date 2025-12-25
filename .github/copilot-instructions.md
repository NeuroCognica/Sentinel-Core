Sentinel Core — Copilot & Contributor Instructions
Purpose

This repository implements Sentinel Core, a constitutional security substrate for high-integrity systems (including cognitive frameworks like AURA).

Sentinel is not a feature library, not an LLM agent, and not a UI system.

Sentinel is a gatekeeping authority whose sole mandate is:

No action of consequence may occur without explicit authorization, cryptographic accountability, and immutable evidence.

Any contribution that violates this mandate is incorrect by definition.

Foundational Laws (Non-Negotiable)

All code generated, suggested, or modified in this repository must comply with the following laws.

FOREVER LAW

All actions of consequence are recorded immutably before completion.

No mutable “truth” stores

No silent overwrites

No retroactive edits

No best-effort logging

If an event cannot be logged, the action must fail.

SENTINEL LAW

No privileged action may bypass the guard boundary.

No hidden admin paths

No “internal” shortcuts

No debug backdoors

No trust-by-assumption

All authority flows through canonical envelopes and verified identity.

NEVER BORING LAW

All failures must be visible, attributable, and queryable.

No swallowed errors

No silent fallbacks

No ambiguous states

Fail closed. Fail loud. Fail honestly.

Architectural Doctrine
Append-Only Truth

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