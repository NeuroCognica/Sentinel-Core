# Sentinel Core: Short-Term Phase Automation Requirements & Script

This document compares the Short-Term Phase checklist against a fully orchestrated automation script for VS Code on Windows. It defines automation requirements and provides a step-by-step script to enable full automation of the Short-Term Phase build process.

---

## Automation Requirements (Short-Term Phase)

### 1. Policy Schema and Evaluation Engine
- Specify policy schema format (YAML, Rego, custom DSL)
- Add versioning and digest calculation for policies
- Implement policy evaluation engine with deterministic output
- Add PolicyEvaluated event type
- Build policy regression test suite
- Create policy authoring guide
- Deliver /policy/evaluate endpoint

### 2. Artifact Registry Taxonomy and Provenance Metadata
- Define explicit artifact types
- Specify required provenance fields
- Clarify context-binding and operational constraints
- Define artifact lifecycle states
- Show example of capability with artifact digest constraints
- Deliver /artifacts/register and /artifacts/verify endpoints

### 3. Ledger Backup and Recovery Procedures
- Define backup strategy
- Specify recovery procedures
- Document multi-region replication and consistency guarantees
- Add ledger corruption scenarios and recovery playbooks
- Implement Ledger Health Check endpoint

### 4. Monitoring and Observability Instrumentation
- Define structured logging format
- Specify key metrics
- Add health check endpoints
- Document alerting rules
- Integrate OpenTelemetry

### 5. Docker Compose Development Environment
- Write Dockerfiles for all core services
- Create docker-compose.yml for local development
- Add sample data and scripts
- Document setup, troubleshooting, and teardown steps

---

## Automation Script (VS Code Tasks, Windows)

### Prerequisites
- Rust (latest stable)
- Python 3.12
- Docker
- OpenTelemetry Collector

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
      "label": "Run Policy Regression Tests",
      "type": "shell",
      "command": "cargo test --test policy_regression",
      "group": "test"
    },
    {
      "label": "Run Artifact Registry Tests",
      "type": "shell",
      "command": "cargo test --test artifact_registry",
      "group": "test"
    },
    {
      "label": "Run Ledger Health Check",
      "type": "shell",
      "command": "cargo run -p sentinel_api -- ledger-health-check",
      "group": "test"
    },
    {
      "label": "Start Docker Compose Environment",
      "type": "shell",
      "command": "docker-compose up -d",
      "group": "build"
    },
    {
      "label": "Run OpenTelemetry Collector",
      "type": "shell",
      "command": "docker run -d --name otel-collector -p 4317:4317 otel/opentelemetry-collector",
      "group": "test"
    }
  ]
}
```

### Automation Steps
1. Build Rust workspace: `cargo build`
2. Run Sentinel API: `cargo run -p sentinel_api`
3. Run policy regression tests: `cargo test --test policy_regression`
4. Run artifact registry tests: `cargo test --test artifact_registry`
5. Run ledger health check: `cargo run -p sentinel_api -- ledger-health-check`
6. Start Docker Compose environment: `docker-compose up -d`
7. Run OpenTelemetry Collector: `docker run -d --name otel-collector -p 4317:4317 otel/opentelemetry-collector`

---

## Checklist Comparison Table
| Checklist Item | Automation Step | Script/Task |
|---------------|-----------------|-------------|
| Policy schema/evaluation | Regression tests, endpoint | Run Policy Regression Tests |
| Artifact registry | Registry tests, endpoints | Run Artifact Registry Tests |
| Ledger backup/recovery | Health check, backup scripts | Run Ledger Health Check |
| Monitoring/observability | OpenTelemetry, health endpoints | Run OpenTelemetry Collector |
| Docker Compose env | Compose up, Dockerfiles | Start Docker Compose Environment |

---

**Note:** Manual steps (e.g., writing markdown docs, updating guides) should be tracked and scripted where possible. All automation tasks are designed for VS Code on Windows and can be extended for future phases.

**Record progress, commit often, and verify each law and invariant. This automation script is your constitutional roadmap to Sentinel Core Short-Term Phase production readiness.**
