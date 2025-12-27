Recent Implementation Note (2025-12-26)

Change: Applied H1 — canonical envelope digest enforcement at the API boundary and wired it globally.

- What was done: Implemented an Actix middleware that canonicalizes incoming envelope payloads, computes a SHA-256 digest over the canonical payload (v=1, method, path, nonce, body), validates it against the client-provided digest, and replaces the request payload with the inner `body` for downstream handlers. The middleware injects a `VerifiedEnvelopeMeta` (contains `envelope_digest` and `nonce`) into the request extensions.
- Where wired: Global Actix app middleware (`crates/sentinel_api/src/main.rs`) so all mutating API routes are validated at the boundary.
- Policy wiring: Consent-gated handlers now populate `PolicyInput.envelope_digest` from the `VerifiedEnvelopeMeta` before any policy evaluation or ledger append.
- Tests updated: Updated/added API tests to submit the nonce/digest/body envelope and to register the middleware in test apps (integration tests under `crates/sentinel_api/tests/`).
- Invariant preserved: Envelope integrity is verified *before* any policy evaluation or ledger append; mismatches are rejected with HTTP 400.

Commit: [LAW:SENTINEL] Apply canonical envelope digest enforcement globally

Notes: This file is a supplemental update because the primary roadmap file append encountered an editor tooling error; the content is identical to the intended roadmap insertion. If you prefer I can retry in-place edit of `Sentinel-Law/IMPLEMENTATION_ROADMAP.md` next.
