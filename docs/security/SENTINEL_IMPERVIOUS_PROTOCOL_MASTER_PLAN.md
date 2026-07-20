# Sentinel Impervious Protocol Master Plan

Canonical source: `C:\NRI\Sentinel\SENTINEL_IMPERVIOUS_PROTOCOL_MASTER_PLAN.md`
Repository copy: `C:\sentinel-core\docs\security\SENTINEL_IMPERVIOUS_PROTOCOL_MASTER_PLAN.md`
Product: `sentinel-core`

## Carved Law

Let there be no gate before the Sentinel.

This repository follows the canonical NeuroCognica / 90 Degree Robotics Sentinel plan from `C:\NRI\Sentinel`.

The canonical law for all product repositories:

- No protected action executes before Sentinel.
- Sentinel unavailable means deny.
- Unknown action means deny.
- Malformed envelope means deny.
- Ledger failure means deny.
- Shadow-only Sentinel mode is forbidden for release.
- Production bypass flags are forbidden.
- Stubs in the protection path are forbidden.
- Deny-all policy must paralyze protected work.
- Handler-level deny tests are required for protected routes.
- Strict certification must pass before release.

## Local Scope

`sentinel-core` is the root implementation of the Sentinel authority. Its local obligations are stricter than downstream products:

- Maintain the canonical protected-action registry.
- Provide deterministic guard authorization.
- Provide deny-all fail-closed behavior.
- Ledger every guard decision in API paths.
- Provide the `sentinel certify` release gate.
- Emit deterministic Markdown and JSON certification reports.
- Keep all Sentinel protection code free of executable stubs and production bypass flags.

## Release Rule

No Sentinel, no ship.

