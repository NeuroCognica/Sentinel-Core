# PolicyEvaluated event (canonical)

This document defines the canonical `PolicyEvaluated` event shape and append semantics.

Event name: `PolicyEvaluated`

Fields (non-negotiable):

- `policy_digest` (hex): SHA-256 hex digest of the canonical policy bytes.
- `policy_version` (string): semantic version label from the policy artifact.
- `input_digest` (hex): SHA-256 hex digest of the canonical policy input bytes.
- `decision` (Allow | Deny): deterministic decision produced by the evaluator.
- `matched_statement_index` (Option<usize>): index into the policy's `statements` vector, if any.
- `rationale` (string): verbatim rationale from matched statement or default rationale.
- `evaluated_at_utc` (timestamp): evaluator's UTC timestamp for determinism/audit.
- `evaluator_version` (string): version string of the evaluator; bump on semantic changes.

Rules:

- Canonicalization: policy and input canonical bytes are produced via compact JSON serialization
  of the schema (no maps in v0). The digest is `sha256(canonical_bytes)` encoded as hex.
- Determinism: evaluation must be pure — no IO, randomness, or clock-dependent logic inside the evaluator.
- Append order: `PolicyEvaluated` MUST be appended to the ledger before returning a response to callers.
- Immutability: any semantic change in policy/evaluator must produce a new policy digest or evaluator
  version, respectively; historical events are authoritative and never rewritten.

Testing guidance (must be enforced by unit/integration tests):

- Same policy + same input + fixed timestamp → byte-identical `PolicyEvaluated` payload.
- Any trivial change to policy or input → digest must change.
- Rationale must match the statement text verbatim.
