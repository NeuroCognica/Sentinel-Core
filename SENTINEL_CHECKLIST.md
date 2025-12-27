# Sentinel Core: Comprehensive Improvement Checklist

This checklist is derived from the full improvement suggestions and is designed for rapid, constitutional execution. Each item is actionable, testable, and mapped to a deliverable. Mark items as completed as you progress.

---

## Build Progress

- [x] `crates/sentinel_api/src/main.rs` hard-reset to minimal Phase-1 file (cleaned of merge artifacts and hidden bytes) — 2025-12-25
- [x] `cargo build -p sentinel_api` completed after cleanup (warnings only) — 2025-12-25
 - [x] Phase 2: runtime boot + `/health` handler implemented and builds — 2025-12-25
 - [x] Commit code for Phase 2/3 handlers and integration tests — 2025-12-25
 - [x] Integration test (genesis → challenge → login) passing locally — 2025-12-25
 - [x] Phase 3.1: `POST /genesis` implemented — 2025-12-25
 - [x] Phase 3.2: `POST /auth/challenge` and `POST /auth/login` implemented — 2025-12-25



## Immediate (Before Phase 4)


- [x] **Consolidate Documentation**
   - [x] Remove duplicate phase descriptions from README.md
   - [x] Split documentation into:
	   - [x] README.md (overview, quick start, laws)
	   - [x] ARCHITECTURE.md (technical depth, crate structure, event flow)
	   - [x] ROADMAP.md (phases 4-8, milestones, deliverables)
   - [x] Add visual diagrams:
	- [x] Sequence diagram for challenge → login → whoami → logout
	- [x] System architecture diagram (crate dependencies, data flow)
	- [x] State machine diagram for capability lifecycle
	- [x] Use Mermaid or PlantUML for diagrams


- [x] **Add Threat Model Document**
	- [x] Create THREAT_MODEL.md
	- [x] List in-scope threats (replay, forgery, theft, tampering, privilege escalation)
	- [x] List out-of-scope threats (side-channel, physical, quantum, compiler)
	- [x] Map each threat to architectural mitigations
	- [x] Document residual risks and accepted tradeoffs
	- [x] Reference STRIDE or ATT&CK framework

 - [x] **Implement Persistent Nonce Registry**
	- [x] Ensure all consumed nonces are logged as NonceConsumed events
	- [x] Remove any in-memory-only nonce tracking
	- [x] Add nonce expiration policy (e.g., expire after 24h)
	- [x] Add nonce cleanup job to prevent unbounded growth
	- [x] Document replay protection logic and test cases
 - [x] Phase 3 — Persistent Nonce & Replay Protection (COMPLETE)
   Completed after adversarial restart validation. Legacy nonce authority removed.

- [ ] **Create Comprehensive API Documentation**
	- [x] Generate OpenAPI 3.0 spec from Rust code (utoipa or similar)
	- [x] Host Swagger UI or ReDoc for interactive docs (static, offline bundle)
 	- [x] Include example requests/responses for all endpoints
	- [ ] Document error codes and meanings
	- [ ] Add authentication and rate limiting details

- [ ] **Add Performance Benchmarks for Ledger Operations**
	- [ ] Document expected event volume and storage growth
	- [ ] Benchmark full-chain verification time (10K, 100K, 1M events)
	- [ ] Benchmark event-sourced state rebuild time
	- [ ] Add performance tests to CI pipeline
	- [ ] Document results and optimization opportunities


## Short-Term (During Phase 4-5)

- [x] Phase 4 — Deterministic policy evaluation and consent enforcement (SEALED)

- [ ] **Define Policy Schema and Evaluation Engine**
	- [ ] Specify policy schema format (YAML, Rego, custom DSL)
	- [ ] Add versioning and digest calculation for policies
	- [ ] Implement policy evaluation engine with deterministic output
	- [ ] Add PolicyEvaluated event type (policy_digest, input_digest, decision, rationale)
	- [ ] Build policy regression test suite (same inputs + same policy version = same decision)
	- [ ] Create policy authoring guide with examples (RBAC, ABAC, time-based rules)
	- [ ] Deliver /policy/evaluate endpoint returning decision + provenance chain

- [ ] **Specify Artifact Registry Taxonomy and Provenance Metadata**
	- [ ] Define explicit artifact types (executable, model_weights, prompt_template, tool_definition, configuration)
	- [ ] Specify required provenance fields (creator, creation_time, source_url, build_hash, dependencies)
	- [ ] Clarify context-binding and operational constraints
	- [ ] Define artifact lifecycle states (registered → validated → active → deprecated → revoked)
	- [ ] Show example of capability with artifact digest constraints
	- [ ] Deliver /artifacts/register and /artifacts/verify endpoints with event logging

- [ ] **Implement Ledger Backup and Recovery Procedures**
	- [ ] Define backup strategy (continuous replication, periodic snapshots)
	- [ ] Specify recovery procedures (restore from backup, maintain chain integrity)
	- [ ] Document multi-region replication and consistency guarantees
	- [ ] Add ledger corruption scenarios and recovery playbooks
	- [ ] Implement Ledger Health Check endpoint for full chain integrity verification

- [ ] **Add Monitoring and Observability Instrumentation**
	- [ ] Define structured logging format (JSON, correlation IDs)
	- [ ] Specify key metrics (event ingestion rate, verification time, capability issuance rate, policy evaluation latency)
	- [ ] Add health check endpoints (/health, /ready, /metrics for Prometheus)
	- [ ] Document alerting rules (chain verification failure, nonce collision rate, expired capability usage)
	- [ ] Integrate OpenTelemetry for distributed tracing

- [ ] **Create Docker Compose Development Environment**
	- [ ] Write Dockerfiles for all core services
	- [ ] Create docker-compose.yml for one-command local development
	- [ ] Add sample data and scripts for quick start
	- [ ] Document setup, troubleshooting, and teardown steps


## Medium-Term (Phase 6-7)

- [ ] **Choose and Integrate Sandbox Technology for Execution Mediation**
	- [ ] Evaluate sandbox options (gVisor, Firecracker, Docker seccomp, WASM, process isolation)
	- [ ] Select technology and document rationale
	- [ ] Implement proof-of-concept runner for Python scripts with capability enforcement
	- [ ] Define protocol for runners to present capabilities (HTTP header, mTLS cert, Unix socket)
	- [ ] Specify outcome attestation (exit code, output digest, resource usage)
	- [ ] Document failure modes (timeout, crash, policy violation)
	- [ ] Define resource limits (CPU, memory, network, time)

- [ ] **Build AURA Module Bus with Reference Implementation**
	- [ ] Define standard API contract for AURA modules (request/response schema, capability requirements)
	- [ ] Treat modules as artifacts with provenance and versioning
	- [ ] Specify inter-module communication (direct or via Sentinel mediation)
	- [ ] Implement event stream API (/events/stream) with filtering, pagination, real-time subscription
	- [ ] Deliver reference AURA module implementation and integration example

- [ ] **Develop Interactive Console for Event Stream and Provenance Visualization**
	- [ ] Design UI features (actor list, capability inspector, policy viewer, event log browser, artifact registry)
	- [ ] Implement event stream visualization (timeline, filtering, drill-down)
	- [ ] Add provenance chain visualization for decisions and artifacts
	- [ ] Integrate with backend event stream API
	- [ ] Document usage and extensibility

- [ ] **Implement Capability Refresh Tokens to Mitigate Theft Risk**
	- [ ] Design short-lived capabilities (e.g., 5-minute TTL) with refresh tokens
	- [ ] Bind capabilities to client identity (IP, TLS cert fingerprint)
	- [ ] Add anomaly detection for unusual capability usage
	- [ ] Document refresh protocol and edge cases

- [ ] **Add Multi-Tenancy Support if Required by Use Cases**
	- [ ] Add tenant_id to actor identity model
	- [ ] Implement tenant isolation at ledger level (separate chains or logical partitioning)
	- [ ] Define cross-tenant capability constraints
	- [ ] Add tenant-level policy overrides
	- [ ] Document multi-tenant deployment patterns


## Long-Term (Phase 8+)

- [ ] **Integrate Hardware Attestation (TPM/SGX) for Hardening**
	- [ ] Evaluate attestation technologies (TPM, SGX, remote attestation protocols)
	- [ ] Design attestation flow for Sentinel startup and module execution
	- [ ] Implement attestation event types and ledger logging
	- [ ] Document integration steps and hardware requirements
	- [ ] Add adversarial tests for attestation failure and tampering

- [ ] **Achieve Compliance Certifications (SOC 2, ISO 27001)**
	- [ ] Map Sentinel laws and invariants to compliance controls
	- [ ] Document evidence collection and audit procedures
	- [ ] Prepare compliance documentation and gap analysis
	- [ ] Conduct mock audits and address findings
	- [ ] Integrate compliance status into monitoring and reporting

- [ ] **Design Federation Protocol for Cross-Organization Trust**
	- [ ] Specify federation protocol (identity exchange, event replication, trust anchors)
	- [ ] Implement cross-Sentinel event verification and provenance chain linking
	- [ ] Document federation setup, failure modes, and recovery
	- [ ] Add federation event types and ledger entries
	- [ ] Provide reference federation deployment and test suite

- [ ] **Implement Plugin Marketplace for AURA Modules**
	- [ ] Define plugin API and lifecycle (registration, activation, deprecation)
	- [ ] Build registry backend for module discovery and provenance
	- [ ] Implement capability and policy constraints for plugins
	- [ ] Add UI for marketplace browsing, install, and update
	- [ ] Document security model and review process

- [ ] **Conduct Formal Verification of Critical Cryptographic Components**
	- [ ] Identify critical cryptographic modules (signature, hash chain, envelope verification)
	- [ ] Specify formal properties and invariants
	- [ ] Apply formal methods (TLA+, Coq, model checking) to verify correctness
	- [ ] Document verification results and limitations
	- [ ] Integrate verification artifacts into release process

---


## Documentation & Structure

- [ ] **Remove README Duplication; Split Documentation**
	- [ ] Audit README.md for duplicate phase descriptions
	- [ ] Move technical depth to ARCHITECTURE.md
	- [ ] Move future plans and milestones to ROADMAP.md
	- [ ] Ensure README.md covers overview, quick start, and constitutional laws

- [ ] **Add Visual Diagrams (Sequence, Architecture, State Machine)**
	- [ ] Identify key flows for visualization:
		- [ ] Challenge → Login → Whoami → Logout (sequence diagram)
		- [ ] Crate dependencies and data flow (system architecture diagram)
		- [ ] Capability lifecycle (state machine diagram)
		- [ ] Event sourcing and replay (event flow diagram)
		- [ ] Policy evaluation and provenance chain (decision flow diagram)
	- [ ] Select diagram tools:
		- [ ] Mermaid (Markdown-embedded, version-controlled)
		- [ ] PlantUML (for more complex flows)
		- [ ] Graphviz (for dependency graphs)
	- [ ] Create initial diagrams and embed in documentation:
		- [ ] README.md: sequence diagram, system architecture
		- [ ] ARCHITECTURE.md: event flow, state machine, provenance chain
		- [ ] ROADMAP.md: phase timeline, milestone dependencies
	- [ ] Add diagram source files to /docs/diagrams for reproducibility
	- [ ] Document diagram update process and tool usage

- [ ] **Formalize Laws with Testable Definitions and Verification Matrix**

	- [ ] **List All Constitutional Laws and Invariants (AURA Triad)**
		- [ ] FOREVER LAW: The system must remember truthfully, permanently, and without distortion. All actions of consequence must leave immutable, append-only, tamper-evident evidence. No silent loss, mutation, or retroactive alteration. Failure to record = failure of action.
		- [ ] LAW 14: THE MANDATE OF WONDER: The system must evoke authentic emotional response, serve beauty alongside utility, and prohibit mediocrity. All design and features must integrate meaning and wonder, not just function.
		- [ ] SENTINEL LAW: The system must act only with explicit, cryptographically proven authority. No privileged action without verifiable authorization, identity, scope, and time. Absence of proof = denial. All failures must be visible and attributable.

	- [ ] **Define Testable Criteria for Each Law**
		- [ ] FOREVER LAW: Every state-altering action is logged as an immutable event before completion. Tampering, silent loss, or mutation triggers loud, closed failure. All state is reconstructible from the event log. Tests: event log append, tamper detection, replay, log-before-action, fail-closed on log failure.
		- [ ] LAW 14: THE MANDATE OF WONDER: All user-facing features and system flows are reviewed for beauty, meaning, and emotional impact. Tests: UI/UX review, design walkthrough, user feedback, rejection of mediocrity, explicit wonder criteria in PRs.
		- [ ] SENTINEL LAW: All privileged actions require canonical envelope, cryptographic identity, explicit scope, and time-bound authority. Tests: signature verification, replay protection, key/nonce registry, adversarial tests for bypass, fail-closed on ambiguity, visible error reporting.

	- [ ] **Create Verification Matrix Mapping Laws to Tests and Code Locations**
		- [ ] FOREVER LAW: Event log (sentinel_store), event-sourced reducers (all crates), tamper detection (tests), log-before-action (API), fail-closed logic (all endpoints).
		- [ ] LAW 14: THE MANDATE OF WONDER: UI/UX (python_ui), documentation (README.md, ARCHITECTURE.md), design review checklist, user feedback loop.
		- [ ] SENTINEL LAW: Envelope enforcement (sentinel_core), identity reducer (sentinel_identity), capability reducer (sentinel_capabilities), guard boundary (sentinel_api), adversarial tests (tests/), error reporting (API, CLI).

	- [ ] **Document Law Enforcement in README.md and ARCHITECTURE.md**
		- [ ] Add constitutional triad summary and enforcement mapping to README.md
		- [ ] Add law-to-test/code matrix to ARCHITECTURE.md


## Technical Architecture

- [ ] **Write THREAT_MODEL.md (In-Scope/Out-of-Scope, Mitigations, Residual Risks)**
	- [ ] List all in-scope threats (replay, forgery, theft, tampering, privilege escalation)
	- [ ] List all out-of-scope threats (side-channel, physical, quantum, compiler)
	- [ ] Map each threat to architectural mitigations and controls
	- [ ] Document residual risks and accepted tradeoffs
	- [ ] Reference STRIDE or ATT&CK framework for threat classification
	- [ ] Review and update threat model with each major release

- [ ] **Document Ledger Performance, State Snapshots, Indexing, Concurrency, Benchmarking**
	- [ ] Measure and document event ingestion rate and storage growth
	- [ ] Benchmark full-chain verification time (10K, 100K, 1M events)
	- [ ] Benchmark event-sourced state rebuild time
	- [ ] Document snapshot strategy for fast state recovery
	- [ ] Specify indexing approach for event queries
	- [ ] Analyze concurrency model and document race condition mitigations
	- [ ] Add performance tests to CI pipeline and document results

- [ ] **Define Backup/Replication/Recovery Strategy and Health Check Endpoint**
	- [ ] Specify backup strategy (continuous replication, periodic snapshots)
	- [ ] Document recovery procedures (restore from backup, maintain chain integrity)
	- [ ] Design multi-region replication and consistency guarantees
	- [ ] Add ledger corruption scenarios and recovery playbooks
	- [ ] Implement Ledger Health Check endpoint for full chain integrity verification
	- [ ] Document operational runbooks for backup and recovery

- [ ] **Specify Key Management, Rotation, Ceremony, and HSM Integration**
	- [ ] Document key lifecycle (generation, registration, rotation, revocation)
	- [ ] Specify key rotation protocol and event logging
	- [ ] Define key ceremony steps for production deployments
	- [ ] Integrate HSM (Hardware Security Module) support for key storage
	- [ ] Document adversarial tests for key compromise and recovery
	- [ ] Add key management section to ARCHITECTURE.md and operational docs


## Roadmap (Phases 4-8)

- [ ] **Policy Engine**
	- [ ] Specify policy schema format (YAML, Rego, custom DSL)
	- [ ] Add versioning and digest calculation for policies
	- [ ] Implement policy evaluation engine with deterministic output
	- [ ] Add PolicyEvaluated event type (policy_digest, input_digest, decision, rationale)
	- [ ] Build policy regression test suite (same inputs + same policy version = same decision)
	- [ ] Create policy authoring guide with examples (RBAC, ABAC, time-based rules)
	- [ ] Deliver /policy/evaluate endpoint returning decision + provenance chain

- [ ] **Artifact Registry**
	- [ ] Define explicit artifact types (executable, model_weights, prompt_template, tool_definition, configuration)
	- [ ] Specify required provenance fields (creator, creation_time, source_url, build_hash, dependencies)
	- [ ] Clarify context-binding and operational constraints
	- [ ] Define artifact lifecycle states (registered → validated → active → deprecated → revoked)
	- [ ] Show example of capability with artifact digest constraints
	- [ ] Deliver /artifacts/register and /artifacts/verify endpoints with event logging

- [ ] **Execution Mediation**
	- [ ] Choose and integrate sandbox technology for execution mediation (gVisor, Firecracker, Docker seccomp, WASM, process isolation)
	- [ ] Implement proof-of-concept runner for Python scripts with capability enforcement
	- [ ] Define protocol for runners to present capabilities (HTTP header, mTLS cert, Unix socket)
	- [ ] Specify outcome attestation (exit code, output digest, resource usage)
	- [ ] Document failure modes (timeout, crash, policy violation)
	- [ ] Define resource limits (CPU, memory, network, time)

- [ ] **AURA Bus**
	- [ ] Define standard API contract for AURA modules (request/response schema, capability requirements)
	- [ ] Treat modules as artifacts with provenance and versioning
	- [ ] Specify inter-module communication (direct or via Sentinel mediation)
	- [ ] Implement event stream API (/events/stream) with filtering, pagination, real-time subscription
	- [ ] Deliver reference AURA module implementation and integration example

- [ ] **Hardening**
	- [ ] Integrate hardware attestation (TPM/SGX) for hardening
	- [ ] Map Sentinel laws and invariants to compliance controls
	- [ ] Document evidence collection and audit procedures
	- [ ] Prepare compliance documentation and gap analysis
	- [ ] Conduct mock audits and address findings
	- [ ] Integrate compliance status into monitoring and reporting
	- [ ] Design federation protocol for cross-organization trust
	- [ ] Implement cross-Sentinel event verification and provenance chain linking
	- [ ] Document federation setup, failure modes, and recovery
	- [ ] Add federation event types and ledger entries
	- [ ] Provide reference federation deployment and test suite
	- [ ] Implement plugin marketplace for AURA modules
	- [ ] Define plugin API and lifecycle (registration, activation, deprecation)
	- [ ] Build registry backend for module discovery and provenance
	- [ ] Implement capability and policy constraints for plugins
	- [ ] Add UI for marketplace browsing, install, and update
	- [ ] Document security model and review process
	- [ ] Conduct formal verification of critical cryptographic components
	- [ ] Identify critical cryptographic modules (signature, hash chain, envelope verification)
	- [ ] Specify formal properties and invariants
	- [ ] Apply formal methods (TLA+, Coq, model checking) to verify correctness
	- [ ] Document verification results and limitations
	- [ ] Integrate verification artifacts into release process


## Developer Experience

- [ ] **Enhance Quick Start**
	- [ ] Write step-by-step quick start guide for new contributors
	- [ ] Add troubleshooting section for common build/run issues
	- [ ] Provide Docker setup instructions and sample compose file
	- [ ] Include sample API requests and responses
	- [ ] Create tutorial walkthrough (text and video)
	- [ ] Add FAQ for frequent developer questions

- [ ] **Document Adversarial Testing, CI/CD, Coverage, Mutation Testing**
	- [ ] List all adversarial test cases and expected outcomes
	- [ ] Document CI/CD pipeline steps and configuration
	- [ ] Specify code coverage targets and reporting tools
	- [ ] Integrate mutation testing and document process
	- [ ] Add test matrix mapping laws to test cases

- [ ] **Generate OpenAPI Spec, Host Swagger UI, Document Error Codes**
	- [ ] Generate OpenAPI 3.0 spec from Rust code (utoipa or similar)
	- [ ] Host Swagger UI or ReDoc for interactive API documentation
	- [ ] Document all error codes, meanings, and troubleshooting steps
	- [ ] Add authentication and rate limiting details to API docs

- [ ] **Write CONTRIBUTING.md, PR Template, Governance, Code of Conduct**
	- [ ] Create CONTRIBUTING.md with setup, workflow, and law compliance requirements
	- [ ] Add pull request template enforcing constitutional laws and invariants
	- [ ] Document governance model and decision process
	- [ ] Add code of conduct for contributors and maintainers


## Operational/Deployment

- [ ] **Provide Reference Deployment Architectures, Load Balancing, Storage, Kubernetes/Terraform**
	- [ ] Document recommended deployment topologies (single-node, HA, multi-region)
	- [ ] Specify load balancing strategies (API gateway, reverse proxy, DNS)
	- [ ] Define storage requirements and options (local, cloud, distributed)
	- [ ] Provide Kubernetes manifests and Helm charts for container orchestration
	- [ ] Add Terraform scripts for infrastructure provisioning
	- [ ] Document deployment steps and operational runbooks

- [ ] **Define Monitoring/Logging/Metrics/Alerting, Integrate OpenTelemetry**
	- [ ] Specify structured logging format (JSON, correlation IDs)
	- [ ] Define key metrics (event ingestion rate, verification time, capability issuance rate, policy evaluation latency)
	- [ ] Implement health check endpoints (/health, /ready, /metrics for Prometheus)
	- [ ] Document alerting rules (chain verification failure, nonce collision rate, expired capability usage)
	- [ ] Integrate OpenTelemetry for distributed tracing and monitoring
	- [ ] Provide sample dashboards and alert configurations

- [ ] **Plan Migration/Upgrade Strategy, Event Schema Versioning, Migration Tool**
	- [ ] Document migration strategy for event log and state
	- [ ] Specify event schema versioning approach
	- [ ] Develop migration tool for event log upgrades and schema changes
	- [ ] Add rollback and recovery procedures for failed migrations
	- [ ] Document upgrade process and compatibility guarantees


## Risk Mitigation

- [ ] **Address Clock Skew**
	- [ ] Specify time synchronization requirements for all nodes
	- [ ] Implement detection and rejection of requests with excessive clock drift
	- [ ] Document mitigation strategies for distributed deployments
	- [ ] Add adversarial tests for clock skew scenarios

- [ ] **Prevent Nonce Exhaustion**
	- [ ] Monitor nonce usage and consumption rates
	- [ ] Implement nonce expiration and cleanup policies
	- [ ] Alert on abnormal nonce consumption or exhaustion risk
	- [ ] Document nonce management and recovery procedures

- [ ] **Mitigate Capability Theft**
	- [ ] Bind capabilities to client identity (IP, TLS cert fingerprint, device ID)
	- [ ] Implement short-lived capabilities with refresh tokens
	- [ ] Add anomaly detection for unusual capability usage patterns
	- [ ] Document capability lifecycle and theft response protocols
	- [ ] Add adversarial tests for capability theft and misuse


## Future-Proofing

- [ ] **Define Plugin API, WASM Sandbox, Lifecycle, Registry, Security Model**
	- [ ] Specify plugin API contract and supported extension points
	- [ ] Design WASM sandbox integration for safe plugin execution
	- [ ] Document plugin lifecycle (registration, activation, deprecation, removal)
	- [ ] Build plugin registry backend with provenance and versioning
	- [ ] Define security model for plugin isolation, permissions, and attestation
	- [ ] Add adversarial tests for plugin sandbox escape and privilege escalation

- [ ] **Add Multi-Tenancy (tenant_id, Isolation, Overrides)**
	- [ ] Extend actor identity model to include tenant_id
	- [ ] Implement tenant isolation at ledger and capability levels
	- [ ] Specify tenant-level policy overrides and constraints
	- [ ] Document multi-tenant deployment patterns and migration strategies
	- [ ] Add tests for cross-tenant isolation and privilege boundaries

- [ ] **Design Federation/Cross-Sentinel Trust Protocol**
	- [ ] Specify federation protocol (identity exchange, event replication, trust anchors)
	- [ ] Implement cross-Sentinel event verification and provenance chain linking
	- [ ] Document federation setup, failure modes, and recovery
	- [ ] Add federation event types and ledger entries
	- [ ] Provide reference federation deployment and test suite

---

**Record progress, commit often, and verify each law and invariant. This checklist is your constitutional roadmap to Sentinel Core production readiness.**

## Completed (audit snapshot: 2025-12-26)

The following tasks were completed and verified on 2025-12-26. They are marked here for auditors and maintainers as finished.

- [x] Phase‑1..3: Rewrote `crates/sentinel_api/src/main.rs` and implemented Phase‑1 hard reset, Phase‑2 `/health`, Phase‑3 `/genesis`, `/auth/challenge`, `/auth/login` handlers and integration tests (genesis → challenge → login) — builds and tests pass locally.
- [x] Consolidated documentation: `README.md`, `ARCHITECTURE.md`, `ROADMAP.md` reorganized; diagrams added to `docs/diagrams` (Mermaid/PlantUML sources included).
- [x] Threat model: `THREAT_MODEL.md` created and linked.
- [x] Persistent Nonce Registry: nonces recorded as `NonceConsumed` events; removed in-memory-only nonce tracking and added nonce consumption events in login flow.
- [x] OpenAPI spec: canonical `openapi.json` generated and added to repo (`openapi.json`, `docs/api/openapi.json`).
- [x] Static offline API docs: added static offline Swagger UI skeleton and docs (no third-party vendoring), plus `PUSH_MANIFEST.md` describing what must be pushed.
- [x] Bench harness: scaffolded `crates/sentinel_bench`, implemented append throughput, chain-verify, identity-reducer and auth-path microbenchmarks; added `append_with_sync` support and run scripts; baseline 10k run executed and recorded.
- [x] Policy crate frozen (v0): `crates/sentinel_policy` implemented canonical schema, deterministic evaluator, canonical `PolicyEvaluated` event, and digest rules; unit and integration tests added and passing.
- [x] `POST /policy/evaluate` endpoint: read-only observability endpoint added to `sentinel_api` that constructs `PolicyEvaluated`, appends the event before responding, and returns `decision`, `policy_digest`, `input_digest`, `rationale`, and `matched_statement_index` (rules enforced per constitutional constraints).
- [x] Secrets cleanup: removed accidental sensitive files (`crates/sentinel_api/sentinel_service.key`, `crates/sentinel_api/sentinel_events.log`) from HEAD, updated `.gitignore`, and produced a clean audit archive `sentinel-core-source.zip` containing only source + docs for auditors.
- [x] Repo hygiene: added `.gitignore`, `PUSH_MANIFEST.md`, and updated `SENTINEL_CHECKLIST.md` with the 'What To Push' policy.

If you need any completed item moved into a released changelog entry or an official release, tell me which items to include and I'll create a draft `CHANGELOG.md` and a Git tag for the release.

## What To Push (Repository Policy)

- **Canonical-only:** Push files that cannot be downloaded or reliably reconstructed elsewhere: `README.md`, `ARCHITECTURE.md`, `SENTINEL_CHECKLIST.md`, canonical API contract(s) like `openapi.json`, and small, hand-authored docs such as `crates/sentinel_policy/POLICY_EVALUATED.md`.
- **Source code:** Crate source in `crates/` is normally included; include it if you want a complete clone-to-build repository. If space or sensitivity is a concern, the `PUSH_MANIFEST.md` lists the minimum required set.
- **Do NOT push:** build artifacts (`target/`), large bench raw outputs, dev/test private keys or credentials, and any generated binaries or Docker images.
- **Scripts & reproductions:** Small scripts that help reproduce results (e.g. `scripts/run_bench.sh`) are acceptable to push; large artifacts they produce should not be.
- **Manifest and policy:** Keep `PUSH_MANIFEST.md` at repo root and update it when the policy changes. Use it as the authoritative guide for what is allowed in the online repo.

Follow these rules for all pushes; when in doubt, prefer leaving large generated artifacts out and document reproduction steps instead.
