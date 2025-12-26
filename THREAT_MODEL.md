# Sentinel Core Threat Model

## In-Scope Threats
- Replay attacks
- Signature forgery
- Key theft
- Event log tampering
- Privilege escalation

## Out-of-Scope Threats
- Side-channel attacks
- Physical attacks
- Quantum attacks
- Compiler backdoors

## Threats and Mitigations
| Threat                | Mitigation                                                      |
|----------------------|----------------------------------------------------------------|
| Replay attacks       | Nonce registry, NonceConsumed events, event-sourced replay check |
| Signature forgery    | Ed25519 signatures, canonical envelope, strict verification      |
| Key theft            | Key revocation, event-sourced key status, multi-key support      |
| Log tampering        | Hash-chained event log, full-chain verification, loud failure    |
| Privilege escalation | Guard boundaries, event-sourced capabilities, strict separation  |

## Residual Risks & Tradeoffs
- Residual risk: If the event log is deleted or irreparably corrupted, system must fail closed and require manual recovery.
- Tradeoff: Strict event-sourcing may increase recovery time after catastrophic failure.

## Frameworks Referenced
- STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- MITRE ATT&CK (for mapping adversarial techniques)

---

This document is the constitutional threat model for Sentinel Core.
