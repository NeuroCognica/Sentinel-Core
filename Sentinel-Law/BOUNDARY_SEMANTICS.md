Sentinel Boundary Semantics

The Language of Permission and Refusal

Sentinel does not merely accept or reject requests. It recognizes, verifies, considers, and remembers.

Every interaction at the system boundary is a claim about reality:
- who is acting,
- what is being requested,
- why it should be allowed,
- whether the system can truthfully comply.

This document defines the semantic contract of Sentinel's boundary: the meanings of its refusals, the guarantees of its permissions, and the laws that govern both.

Core Principles

- Sentinel never guesses.
- Sentinel never lies.
- Sentinel never acts without consent.
- Sentinel prefers refusal to ambiguity.
- Sentinel preserves truth across time, restart, and failure.

Boundary Choreography (Authoritative Order)

1. The envelope is canonicalized.
2. Its digest is verified.
3. Its author is cryptographically proven.
4. Policy is deterministically evaluated.
5. Consent is explicitly granted or denied.
6. Authority is enforced.
7. Effects may occur.
8. Provenance is sealed.

At any step, Sentinel may refuse. Every refusal has a name. Every name has a meaning. Every meaning has a guarantee.

Error Codes — States of Truth

Each error below is defined as a stable state the system entered. Each entry includes: Machine Code, Sentinel Name, One-line meaning, Common causes, Truth Contract, and Sentinel's stance.

400 — MALFORMED_ENVELOPE
Sentinel Name: Broken Form
Meaning: The request could not be interpreted as a canonical envelope.
Common causes: invalid JSON, missing envelope fields, canonical digest mismatch, tampered body.
Truth Contract:
- ❌ No policy evaluated
- ❌ No consent recorded
- ❌ No events appended
- ❌ No state changed
Sentinel’s stance: “I could not understand what you were asking. I refused to guess.”

401 — UNPROVEN_IDENTITY
Sentinel Name: Unspoken Name
Meaning: The request claimed an identity but failed cryptographic authorship.
Common causes: missing signature, invalid signature, unknown actor_id, signature mismatch to envelope digest.
Truth Contract:
- ❌ No policy evaluated
- ❌ No consent recorded
- ❌ No events appended
- ❌ No state changed
Sentinel’s stance: “You spoke, but you did not prove you were the one who may speak.”

403 — WITHHELD_AUTHORITY
Sentinel Name: Closed Gate
Meaning: The request was understood and authenticated, but authority was denied.
Common causes: policy decision = Deny, capability constraint violation, artifact not bound to capability.
Truth Contract:
- ✅ PolicyEvaluated event appended
- ✅ ConsentDenied event appended
- ❌ No effects executed
- ❌ No Codex Seal created
Sentinel’s stance: “I heard you. I knew who you were. I chose not to allow this.”

409 — TEMPORAL_VIOLATION
Sentinel Name: Broken Time
Meaning: The request violated temporal integrity.
Common causes: nonce reuse, expired or consumed nonce, replay attempt.
Truth Contract:
- ❌ No effects executed
- ❌ No Codex Seal created
- ❌ No state mutation
- (Optional) Replay evidence event recorded if configured
Sentinel’s stance: “This moment has already passed. I will not relive it.”

500 — INVARIANT_BREACH
Sentinel Name: Refusal to Lie
Meaning: An internal law could not be upheld safely.
Common causes: ledger append failure, invariant violation, corruption risk, unexpected reducer state.
Truth Contract:
- ❌ Partial effects are forbidden
- ❌ No Codex Seal created
- ⚠️ System chose failure over inconsistency
Sentinel’s stance: “Something went wrong. I chose silence over falsehood.”

429 — MEASURE_EXCEEDED (reserved)
Sentinel Name: Too Much, Too Fast
Meaning: Rate limit or abuse threshold reached; reserved for future H3 enforcement.

Response Shape

All error responses follow a compact envelope:
- `code` (HTTP status)
- `error` (machine code string)
- `name` (sentinel name)
- `message` (brief human text)
- `details` (optional diagnostic object)
- `trace_id` (optional correlation id)

Example:

{
  "code": 403,
  "error": "WITHHELD_AUTHORITY",
  "name": "Closed Gate",
  "message": "policy denied: action not permitted",
  "details": { "policy_digest": "..." },
  "trace_id": "..."
}

Authentication & Consent Flow (Ritual)

Describe the request lifecycle as a choreography — a ritual that must succeed in order.

- Client composes a canonical envelope containing: `actor_id`, `key_id`, `nonce`, `timestamp_utc`, `payload`, `signature`.
- Server canonicalizes the envelope, computes canonical digest, and verifies client-provided digest.
- Server validates signature against canonical digest and actor's registered key.
- Server checks nonce freshness and replay state (ledger-derived `NonceConsumed`).
- Server builds `PolicyInput` which MUST include the envelope digest in `envelope_digest`.
- Policy evaluator deterministically decides Allow or Deny and emits `PolicyEvaluated` (with `policy_digest`, `input_digest`, `decision`, `rationale`).
- Consent event (`ConsentGranted` or `ConsentDenied`) is appended before any effects.
- If allowed, effects are executed and `EffectExecuted` is appended with provenance (policy + input digest).
- A Codex Seal may be created for provenance bundling.

OpenAPI Annotations (Intent)

This project includes an OpenAPI components fragment that clearly documents:
- the required canonical envelope schema
- the error response shapes with `x-sentinel-name` and `x-truth-contract` extensions
- which endpoints are observational, authenticated, consent-gated, or provenance-sealing

Purpose & Guarantees

This document is a compact constitution for the boundary. It is intentionally short, precise, and durable.

By freezing these semantics now we:
- make refusal legible and stable for clients
- allow downstream tooling (UI, CLI, SDKs) to treat refusals as contract states
- prevent accidental drift in how the system speaks when it says “no”

Next actions

- Add OpenAPI components fragment to `docs/api/boundary_semantics_openapi.yaml` (contains response objects, envelope schema, examples).
- Annotate consent-gated endpoints in the codebase (OpenAPI generation) to reference these responses.
- Publish `Sentinel-Law/BOUNDARY_SEMANTICS.md` as the canonical boundary contract.


