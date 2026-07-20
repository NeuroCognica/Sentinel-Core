# Sentinel Adoption Status

Product: `sentinel-core`
Repository: `C:\sentinel-core`
Canonical Sentinel plan source: `C:\NRI\Sentinel\SENTINEL_IMPERVIOUS_PROTOCOL_MASTER_PLAN.md`
Local plan copy: `docs/security/SENTINEL_IMPERVIOUS_PROTOCOL_MASTER_PLAN.md`
Protected action inventory: `docs/security/SENTINEL_PROTECTED_ACTIONS.md`
Certification report path: `docs/security/SENTINEL_CERTIFICATION_REPORT.md`
Required release mode: `enforce`

## Current State

Status: Implemented, not release-certified until `sentinel certify --strict` passes from a clean tree.

Implemented footholds:

- Canonical protected-action registry exists in `sentinel_core::PROTECTED_ACTIONS`.
- `DeterministicSentinelGuard` denies malformed requests, unknown actions, deny-all policy, and unmatched explicit policy requests.
- Guard decisions classify authorization as `Allow`, `AllowWithMonitoring`, `Deny`, `Lockdown`, and other non-authorizing states.
- Non-authorizing decision classes cannot execute effects directly.
- `/guard/authorize` ledgers allow and deny decisions.
- Handler tests verify deny-all returns `403`, ledgers the decision, and spawns no effect.
- CLI certification harness is implemented as `sentinel certify`.

Open execution work:

- Policy signing lifecycle is not complete.
- Release artifact signing is not complete.
- Full SDK distribution is not complete.
- Downstream repositories still require full protected-action coverage.

## Required Certification Command

```powershell
cargo run -p sentinel_cli --bin sentinel -- certify --repo C:\sentinel-core --product sentinel-core --strict --output-dir C:\sentinel-core\docs\security
```

