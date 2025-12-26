# Sentinel Core: Immediate Phase Automation Requirements & Script

This document compares the Immediate Phase checklist against a fully orchestrated automation script for VS Code on Windows. It defines automation requirements and provides a step-by-step script to enable full automation of the Immediate Phase build process.

---

## Automation Requirements (Immediate Phase)

### 1. Documentation Consolidation
- Remove duplicate phase descriptions from README.md
- Split documentation into:
  - README.md (overview, quick start, laws)
  - ARCHITECTURE.md (technical depth, crate structure, event flow)
  - ROADMAP.md (phases 4-8, milestones, deliverables)
- Add visual diagrams:
  - Sequence diagram for challenge → login → whoami → logout
  - System architecture diagram (crate dependencies, data flow)
  - State machine diagram for capability lifecycle
  - Use Mermaid or PlantUML for diagrams

### 2. Threat Model Document
- Create THREAT_MODEL.md
- List in-scope and out-of-scope threats
- Map threats to architectural mitigations
- Document residual risks and accepted tradeoffs
- Reference STRIDE or ATT&CK framework

### 3. Persistent Nonce Registry
- Ensure all consumed nonces are logged as NonceConsumed events
- Remove any in-memory-only nonce tracking
- Add nonce expiration policy (e.g., expire after 24h)
- Add nonce cleanup job
- Document replay protection logic and test cases

### 4. Comprehensive API Documentation
- Generate OpenAPI 3.0 spec from Rust code (utoipa or similar)
- Host Swagger UI or ReDoc for interactive docs
- Include example requests/responses for all endpoints
- Document error codes and meanings
- Add authentication and rate limiting details

### 5. Performance Benchmarks for Ledger Operations
- Document expected event volume and storage growth
- Benchmark full-chain verification time (10K, 100K, 1M events)
- Benchmark event-sourced state rebuild time
- Add performance tests to CI pipeline
- Document results and optimization opportunities

---

## Automation Script (VS Code Tasks, Windows)

### Prerequisites
- Rust (latest stable)
- Python 3.12
- PlantUML, Mermaid CLI (for diagrams)
- Docker (for Swagger UI)

### VS Code Tasks (tasks.json)

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build Rust Workspace",
      "type": "shell",
      "command": "cargo build",
      "group": "build"
    },
    {
      "label": "Run Sentinel API",
      "type": "shell",
      "command": "cargo run -p sentinel_api",
      "group": "test"
    },
    {
      "label": "Generate OpenAPI Spec",
      "type": "shell",
      "command": "cargo run -p sentinel_api --features openapi > openapi.json",
      "group": "build"
    },
    {
      "label": "Host Swagger UI",
      "type": "shell",
      "command": "docker run -d -p 8080:8080 -v ${workspaceFolder}/openapi.json:/openapi.json swaggerapi/swagger-ui",
      "group": "test"
    },
    {
      "label": "Generate Diagrams",
      "type": "shell",
      "command": "mermaid-cli -i docs/diagrams/sequence.mmd -o docs/diagrams/sequence.svg && plantuml docs/diagrams/architecture.puml",
      "group": "build"
    },
    {
      "label": "Run Performance Benchmarks",
      "type": "shell",
      "command": "cargo test -- --ignored --bench",
      "group": "test"
    }
  ]
}
```

### Automation Steps
1. Build Rust workspace: `cargo build`
2. Run Sentinel API: `cargo run -p sentinel_api`
3. Generate OpenAPI spec: `cargo run -p sentinel_api --features openapi > openapi.json`
4. Host Swagger UI: `docker run -d -p 8080:8080 -v ${workspaceFolder}/openapi.json:/openapi.json swaggerapi/swagger-ui`
5. Generate diagrams: `mermaid-cli` and `plantuml` commands
6. Run performance benchmarks: `cargo test -- --ignored --bench`

---

## Checklist Comparison Table
| Checklist Item | Automation Step | Script/Task |
|---------------|-----------------|-------------|
| Documentation consolidation | Manual + Diagrams | Generate Diagrams task |
| Threat model document | Manual | N/A (recommend markdown template) |
| Persistent nonce registry | Code + Tests | Build/Run/Bench tasks |
| API documentation | OpenAPI + Swagger | Generate OpenAPI Spec, Host Swagger UI |
| Performance benchmarks | Rust tests | Run Performance Benchmarks |

---

**Note:** Manual steps (e.g., writing markdown docs, updating diagrams) should be tracked and scripted where possible. All automation tasks are designed for VS Code on Windows and can be extended for future phases.

**Record progress, commit often, and verify each law and invariant. This automation script is your constitutional roadmap to Sentinel Core Immediate Phase production readiness.**
