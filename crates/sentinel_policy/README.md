# Sentinel Policy (Phase 4 scaffold)

This crate provides a minimal policy representation and deterministic evaluator stub to scaffold Phase 4.

Current status:

- Basic `Policy`, `PolicyInput`, and `PolicyDecision` types.
- `evaluate()` stub that allows `action == "read"`.
- Unit test included.

Next steps:

- Define policy schema (YAML/JSON) and versioning
- Add digest calculation for policy immutability
- Implement evaluation provenance and deterministic rationale
- Expose `/policy/evaluate` in `sentinel_api` (stubbed)
