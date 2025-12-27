# Minimum Completed Sentinel (MCS)

**Status:** ✅ Achieved (see handler tests)

## Definition

A Minimum Completed Sentinel is a system in which at least one real execution path permanently records:

- **What** occurred (artifact digest),
- **Why** it was allowed (policy digest + input digest),
- **Who** authorized it (actor/subject),
- **That consent was granted**, and
- **That this explanation survives replay, restart, and system failure.

## Achieved Guarantees

- Deterministic policy evaluation for the path
- Explicit consent recorded before any effect
- Capability authorization bound to the artifact
- Immutable provenance via Codex Seal
- Fail-closed semantics on missing data or append failure

## Proof Artifacts

- Events: `PolicyEvaluated`, `ConsentGranted`/`ConsentDenied`, `CapabilityConsumed { artifact_digest }`, `CodexSealCreated`
- Tests: `crates/sentinel_api/tests/artifact_use.rs`, `crates/sentinel_capabilities/tests/artifact_binding.rs`
- Reducers: `ArtifactRegistry`, `CapabilityState`

This document canonizes the Minimum Completed Sentinel: further work is expansion, not completion.
