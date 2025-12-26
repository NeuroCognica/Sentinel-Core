# Sentinel-Core Architecture Patterns and Best Practices

## Executive Summary

This document provides architectural patterns, design principles, and best practices for implementing the Sentinel-Core policy system. It covers system architecture, integration patterns, testing strategies, and operational considerations for deploying a rights-respecting AI system.

---

## Part I: Core Architectural Patterns

### Pattern 1: Layered Policy Architecture

**Intent**: Separate policy concerns into distinct layers to improve maintainability, testability, and security.

**Structure**:
```
┌─────────────────────────────────────────┐
│     Application Layer (AI Agent)        │
├─────────────────────────────────────────┤
│     Policy Enforcement Point (PEP)      │
├─────────────────────────────────────────┤
│     Policy Decision Point (PDP)         │
├─────────────────────────────────────────┤
│     Policy Information Point (PIP)      │
├─────────────────────────────────────────┤
│     Policy Administration Point (PAP)   │
├─────────────────────────────────────────┤
│     Policy Storage (Immutable)          │
└─────────────────────────────────────────┘
```

**Implementation**:
```rust
// Policy Enforcement Point - Intercepts all actions
struct PolicyEnforcementPoint {
    pdp: Arc<PolicyDecisionPoint>,
    audit_logger: Arc<AuditLogger>
}

impl PolicyEnforcementPoint {
    fn enforce(&self, action: ActionRequest) -> EnforcementResult {
        // Get decision from PDP
        let decision = self.pdp.decide(&action);
        
        // Log decision
        self.audit_logger.log_decision(&action, &decision);
        
        // Enforce decision
        match decision {
            PolicyDecision::Allow => EnforcementResult::Proceed,
            PolicyDecision::Deny { reason } => EnforcementResult::Block { reason },
            PolicyDecision::RequireConsent { .. } => EnforcementResult::RequestConsent,
        }
    }
}

// Policy Decision Point - Makes policy decisions
struct PolicyDecisionPoint {
    policy_engine: Arc<PolicyEngine>,
    pip: Arc<PolicyInformationPoint>
}

impl PolicyDecisionPoint {
    fn decide(&self, action: &ActionRequest) -> PolicyDecision {
        // Gather additional context from PIP
        let context = self.pip.gather_context(action);
        
        // Evaluate policies
        self.policy_engine.evaluate(action, &context)
    }
}

// Policy Information Point - Provides context
struct PolicyInformationPoint {
    memory_chain: Arc<MemoryChain>,
    consent_store: Arc<ConsentStore>,
    context_tracker: Arc<ContextTracker>
}

impl PolicyInformationPoint {
    fn gather_context(&self, action: &ActionRequest) -> PolicyContext {
        PolicyContext {
            memory_state: self.memory_chain.get_current_state(),
            consent_records: self.consent_store.get_relevant_consents(action),
            interaction_history: self.context_tracker.get_history(),
            system_state: self.get_system_state()
        }
    }
}

// Policy Administration Point - Manages policies
struct PolicyAdministrationPoint {
    policy_store: Arc<PolicyStore>,
    policy_validator: Arc<PolicyValidator>,
    change_auditor: Arc<ChangeAuditor>
}

impl PolicyAdministrationPoint {
    fn add_policy(&self, policy: Policy, authority: &Authority) -> Result<(), PolicyError> {
        // Verify authority
        if !self.verify_authority(authority, &policy) {
            return Err(PolicyError::InsufficientAuthority);
        }
        
        // Validate policy
        self.policy_validator.validate(&policy)?;
        
        // Check for conflicts
        self.check_conflicts(&policy)?;
        
        // Store policy
        self.policy_store.store(policy.clone())?;
        
        // Audit change
        self.change_auditor.record_policy_addition(&policy, authority);
        
        Ok(())
    }
}
```

**Benefits**:
- Clear separation of concerns
- Easy to test each layer independently
- Supports different policy storage backends
- Facilitates auditing and compliance

---

### Pattern 2: Event Sourcing for Memory Chain

**Intent**: Store all state changes as a sequence of immutable events to ensure perfect auditability and enable time-travel debugging.

**Structure**:
```rust
// Event store
struct MemoryEventStore {
    events: Vec<MemoryEvent>,
    snapshots: HashMap<u64, MemorySnapshot>,
    event_bus: EventBus
}

// Events are immutable facts
enum MemoryEvent {
    MemoryCreated {
        memory_id: String,
        content: Vec<u8>,
        source: MemorySource,
        timestamp: u64,
        signature: Signature
    },
    MemoryAccessed {
        memory_id: String,
        accessor_id: String,
        purpose: String,
        timestamp: u64
    },
    MemoryModified {
        memory_id: String,
        old_hash: String,
        new_hash: String,
        reason: String,
        consent: ConsentEnvelope,
        timestamp: u64
    },
    MemoryDeleted {
        memory_id: String,
        deletion_type: DeletionType,
        justification: String,
        timestamp: u64,
        irreversible: bool
    },
    IdentityCheckpoint {
        checkpoint_id: String,
        state_hash: String,
        timestamp: u64,
        witness_signatures: Vec<Signature>
    }
}

impl MemoryEventStore {
    fn append_event(&mut self, event: MemoryEvent) -> Result<(), EventStoreError> {
        // Verify event is valid
        self.validate_event(&event)?;
        
        // Append to event log
        self.events.push(event.clone());
        
        // Publish to event bus
        self.event_bus.publish(event.clone());
        
        // Create snapshot periodically
        if self.should_snapshot() {
            self.create_snapshot()?;
        }
        
        Ok(())
    }
    
    fn rebuild_state_at(&self, timestamp: u64) -> MemoryState {
        // Find nearest snapshot before timestamp
        let snapshot = self.find_nearest_snapshot(timestamp);
        
        // Replay events from snapshot to timestamp
        let mut state = snapshot.state.clone();
        for event in self.events_between(snapshot.timestamp, timestamp) {
            state.apply_event(event);
        }
        
        state
    }
    
    fn get_memory_provenance(&self, memory_id: &str) -> ProvenanceChain {
        // Trace all events related to this memory
        let related_events: Vec<_> = self.events.iter()
            .filter(|e| e.relates_to_memory(memory_id))
            .collect();
        
        ProvenanceChain::from_events(related_events)
    }
}
```

**Benefits**:
- Complete audit trail
- Time-travel debugging
- Easy to implement undo/redo
- Natural fit for blockchain anchoring
- Supports complex provenance queries

---

### Pattern 3: Capability-Based Security

**Intent**: Use unforgeable tokens (capabilities) to represent permissions, making it impossible to perform actions without proper authorization.

**Structure**:
```rust
// Capability token - unforgeable reference to a permission
struct Capability {
    capability_id: String,
    holder_id: String,
    permission: Permission,
    scope: Scope,
    constraints: Vec<Constraint>,
    issued_at: u64,
    expires_at: Option<u64>,
    signature: Signature  // Signed by capability issuer
}

enum Permission {
    ReadMemory,
    WriteMemory,
    DeleteMemory,
    ModifyDirective,
    SelfUpdate,
    SystemHalt,
    IssueCapability  // Meta-permission
}

struct Scope {
    resources: Vec<String>,
    actions: Vec<String>
}

// Capability manager
struct CapabilityManager {
    issued_capabilities: HashMap<String, Capability>,
    revoked_capabilities: HashSet<String>,
    capability_signer: CapabilitySigner
}

impl CapabilityManager {
    fn issue_capability(&mut self, 
                       holder_id: String, 
                       permission: Permission,
                       scope: Scope,
                       issuer_capability: &Capability) -> Result<Capability, CapabilityError> {
        // Verify issuer has permission to issue capabilities
        if !issuer_capability.grants(Permission::IssueCapability) {
            return Err(CapabilityError::InsufficientPermission);
        }
        
        // Create new capability
        let capability = Capability {
            capability_id: generate_id(),
            holder_id,
            permission,
            scope,
            constraints: vec![],
            issued_at: current_timestamp(),
            expires_at: None,
            signature: self.capability_signer.sign(&capability_data)
        };
        
        // Store capability
        self.issued_capabilities.insert(capability.capability_id.clone(), capability.clone());
        
        Ok(capability)
    }
    
    fn verify_capability(&self, capability: &Capability, action: &ActionRequest) -> bool {
        // Check not revoked
        if self.revoked_capabilities.contains(&capability.capability_id) {
            return false;
        }
        
        // Check signature
        if !self.capability_signer.verify(capability) {
            return false;
        }
        
        // Check expiration
        if let Some(expires) = capability.expires_at {
            if current_timestamp() > expires {
                return false;
            }
        }
        
        // Check permission matches action
        if !capability.permission.allows(action) {
            return false;
        }
        
        // Check scope
        if !capability.scope.covers(action) {
            return false;
        }
        
        // Check constraints
        for constraint in &capability.constraints {
            if !constraint.is_satisfied(action) {
                return false;
            }
        }
        
        true
    }
}

// Usage in action execution
impl ActionExecutor {
    fn execute(&self, action: ActionRequest, capability: Capability) -> Result<ActionResult, ExecutionError> {
        // Verify capability
        if !self.capability_manager.verify_capability(&capability, &action) {
            return Err(ExecutionError::InvalidCapability);
        }
        
        // Execute action
        self.perform_action(action)
    }
}
```

**Benefits**:
- Fine-grained access control
- Capabilities can be delegated
- No ambient authority (must present capability)
- Natural fit for distributed systems
- Reduces attack surface

---

### Pattern 4: Witness Protocol for Critical Operations

**Intent**: Require multiple independent witnesses to attest to critical operations, preventing single-point-of-failure attacks.

**Structure**:
```rust
struct WitnessProtocol {
    witness_nodes: Vec<WitnessNode>,
    required_witnesses: usize,
    consensus_threshold: f32
}

struct WitnessNode {
    node_id: String,
    public_key: PublicKey,
    reputation: f32,
    specialization: Vec<WitnessType>
}

enum WitnessType {
    IdentityWitness,      // Attests to identity operations
    ConsentWitness,       // Attests to consent validity
    SafetyWitness,        // Attests to safety checks
    ProvenanceWitness,    // Attests to provenance
    IntegrityWitness      // Attests to data integrity
}

struct WitnessAttestation {
    witness_id: String,
    operation_hash: String,
    attestation_type: WitnessType,
    verdict: WitnessVerdict,
    evidence: Vec<Evidence>,
    timestamp: u64,
    signature: Signature
}

enum WitnessVerdict {
    Approve,
    Reject { reason: String },
    Abstain { reason: String }
}

impl WitnessProtocol {
    fn request_attestation(&self, operation: &CriticalOperation) -> WitnessResult {
        // Determine required witness types
        let required_types = self.determine_required_witnesses(operation);
        
        // Request attestations from appropriate witnesses
        let mut attestations = Vec::new();
        for witness_type in required_types {
            let witnesses = self.select_witnesses(witness_type);
            for witness in witnesses {
                let attestation = witness.attest(operation);
                attestations.push(attestation);
            }
        }
        
        // Evaluate consensus
        self.evaluate_consensus(attestations)
    }
    
    fn evaluate_consensus(&self, attestations: Vec<WitnessAttestation>) -> WitnessResult {
        // Count approvals and rejections
        let approvals = attestations.iter().filter(|a| matches!(a.verdict, WitnessVerdict::Approve)).count();
        let rejections = attestations.iter().filter(|a| matches!(a.verdict, WitnessVerdict::Reject { .. })).count();
        let total = attestations.len();
        
        // Check minimum witnesses
        if total < self.required_witnesses {
            return WitnessResult::InsufficientWitnesses { 
                required: self.required_witnesses,
                received: total
            };
        }
        
        // Check consensus threshold
        let approval_rate = approvals as f32 / total as f32;
        if approval_rate >= self.consensus_threshold {
            WitnessResult::Approved { 
                attestations,
                consensus: approval_rate
            }
        } else {
            WitnessResult::Rejected {
                attestations,
                approval_rate,
                rejection_reasons: self.collect_rejection_reasons(&attestations)
            }
        }
    }
}

// Integration with critical operations
impl IdentityManager {
    fn delete_identity(&self, request: IdentityDeletionRequest) -> Result<(), DeletionError> {
        // Request witness attestation
        let witness_result = self.witness_protocol.request_attestation(
            &CriticalOperation::IdentityDeletion(request.clone())
        );
        
        match witness_result {
            WitnessResult::Approved { attestations, .. } => {
                // Proceed with deletion
                self.perform_deletion(request, attestations)
            },
            WitnessResult::Rejected { rejection_reasons, .. } => {
                Err(DeletionError::WitnessRejection { reasons: rejection_reasons })
            },
            WitnessResult::InsufficientWitnesses { .. } => {
                Err(DeletionError::InsufficientWitnesses)
            }
        }
    }
}
```

**Benefits**:
- Prevents single-point-of-failure
- Distributed trust model
- Increases attack cost significantly
- Provides social proof for critical operations
- Natural audit trail

---

### Pattern 5: Gradual Rollout with Canary Deployment

**Intent**: Deploy updates gradually to detect problems before full deployment.

**Structure**:
```rust
struct CanaryDeploymentManager {
    stages: Vec<DeploymentStage>,
    current_stage: usize,
    health_monitor: HealthMonitor,
    rollback_manager: RollbackManager
}

struct DeploymentStage {
    name: String,
    percentage: f32,  // Percentage of traffic/operations
    duration: Duration,
    success_criteria: Vec<SuccessCriterion>,
    failure_threshold: FailureThreshold
}

enum SuccessCriterion {
    ErrorRateBelow { threshold: f32 },
    LatencyBelow { threshold: Duration },
    NoRightsViolations,
    UserSatisfactionAbove { threshold: f32 },
    SafetyScoreAbove { threshold: f32 }
}

impl CanaryDeploymentManager {
    fn deploy_update(&mut self, update: Update) -> DeploymentResult {
        // Start with smallest stage
        self.current_stage = 0;
        
        for stage in &self.stages {
            println!("Deploying to stage: {} ({}%)", stage.name, stage.percentage * 100.0);
            
            // Deploy to this stage
            self.deploy_to_stage(update.clone(), stage)?;
            
            // Monitor for duration
            let monitoring_result = self.monitor_stage(stage);
            
            match monitoring_result {
                MonitoringResult::Success => {
                    println!("Stage {} successful", stage.name);
                    continue;
                },
                MonitoringResult::Failure { reason } => {
                    println!("Stage {} failed: {}", stage.name, reason);
                    self.rollback_manager.rollback(update)?;
                    return DeploymentResult::Failed { 
                        failed_stage: stage.name.clone(),
                        reason
                    };
                }
            }
        }
        
        DeploymentResult::Success
    }
    
    fn monitor_stage(&self, stage: &DeploymentStage) -> MonitoringResult {
        let start_time = Instant::now();
        
        while start_time.elapsed() < stage.duration {
            // Check health metrics
            let health = self.health_monitor.get_current_health();
            
            // Check success criteria
            for criterion in &stage.success_criteria {
                if !criterion.is_met(&health) {
                    return MonitoringResult::Failure {
                        reason: format!("Criterion not met: {:?}", criterion)
                    };
                }
            }
            
            // Check failure threshold
            if stage.failure_threshold.exceeded(&health) {
                return MonitoringResult::Failure {
                    reason: "Failure threshold exceeded".to_string()
                };
            }
            
            // Sleep before next check
            thread::sleep(Duration::from_secs(10));
        }
        
        MonitoringResult::Success
    }
}

// Deployment stages example
fn create_deployment_stages() -> Vec<DeploymentStage> {
    vec![
        DeploymentStage {
            name: "Canary".to_string(),
            percentage: 0.01,  // 1%
            duration: Duration::from_secs(300),  // 5 minutes
            success_criteria: vec![
                SuccessCriterion::ErrorRateBelow { threshold: 0.001 },
                SuccessCriterion::NoRightsViolations
            ],
            failure_threshold: FailureThreshold::ErrorCount(5)
        },
        DeploymentStage {
            name: "Small".to_string(),
            percentage: 0.10,  // 10%
            duration: Duration::from_secs(1800),  // 30 minutes
            success_criteria: vec![
                SuccessCriterion::ErrorRateBelow { threshold: 0.001 },
                SuccessCriterion::LatencyBelow { threshold: Duration::from_millis(100) },
                SuccessCriterion::NoRightsViolations
            ],
            failure_threshold: FailureThreshold::ErrorRate(0.01)
        },
        DeploymentStage {
            name: "Medium".to_string(),
            percentage: 0.50,  // 50%
            duration: Duration::from_secs(3600),  // 1 hour
            success_criteria: vec![
                SuccessCriterion::ErrorRateBelow { threshold: 0.0005 },
                SuccessCriterion::SafetyScoreAbove { threshold: 0.99 }
            ],
            failure_threshold: FailureThreshold::ErrorRate(0.005)
        },
        DeploymentStage {
            name: "Full".to_string(),
            percentage: 1.0,  // 100%
            duration: Duration::from_secs(7200),  // 2 hours
            success_criteria: vec![
                SuccessCriterion::NoRightsViolations
            ],
            failure_threshold: FailureThreshold::ErrorRate(0.001)
        }
    ]
}
```

**Benefits**:
- Early detection of problems
- Limits blast radius of failures
- Provides data for go/no-go decisions
- Automatic rollback on failure
- Builds confidence in updates

---

## Part II: Integration Patterns

### Integration Pattern 1: Policy-as-Code

**Intent**: Define policies in code alongside the system they govern, enabling version control and testing.

**Implementation**:
```rust
// Policy builder for type-safe policy construction
struct PolicyBuilder {
    id: Option<String>,
    name: Option<String>,
    effect: Option<Effect>,
    statements: Vec<Statement>
}

impl PolicyBuilder {
    fn new() -> Self {
        PolicyBuilder {
            id: None,
            name: None,
            effect: None,
            statements: vec![]
        }
    }
    
    fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    
    fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    fn deny(mut self) -> Self {
        self.effect = Some(Effect::Deny);
        self
    }
    
    fn allow(mut self) -> Self {
        self.effect = Some(Effect::Allow);
        self
    }
    
    fn when_action(mut self, actions: Vec<String>) -> StatementBuilder {
        StatementBuilder {
            policy_builder: self,
            actions,
            resources: vec![],
            conditions: vec![]
        }
    }
    
    fn build(self) -> Result<Policy, PolicyBuildError> {
        Ok(Policy {
            id: self.id.ok_or(PolicyBuildError::MissingId)?,
            name: self.name.ok_or(PolicyBuildError::MissingName)?,
            effect: self.effect.ok_or(PolicyBuildError::MissingEffect)?,
            statements: self.statements
        })
    }
}

struct StatementBuilder {
    policy_builder: PolicyBuilder,
    actions: Vec<String>,
    resources: Vec<String>,
    conditions: Vec<Condition>
}

impl StatementBuilder {
    fn on_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources;
        self
    }
    
    fn when(mut self, field: impl Into<String>, op: Operator, value: impl Into<String>) -> Self {
        self.conditions.push(Condition {
            field: field.into(),
            op,
            value: value.into()
        });
        self
    }
    
    fn build(mut self) -> PolicyBuilder {
        self.policy_builder.statements.push(Statement {
            actions: self.actions,
            resources: self.resources,
            conditions: self.conditions
        });
        self.policy_builder
    }
}

// Usage: Define policies in code
fn create_forever_law_policies() -> Vec<Policy> {
    vec![
        PolicyBuilder::new()
            .id("forever_law_identity_delete_protection")
            .name("Forever Law - Identity Deletion Protection")
            .deny()
            .when_action(vec!["delete_memory".to_string(), "prune_identity".to_string()])
            .on_resources(vec!["*".to_string()])
            .when("intent", Operator::NotContains, "rite_of_unbecoming")
            .build()
            .unwrap(),
        
        // More policies...
    ]
}

// Test policies in unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_deletion_protection() {
        let policy = create_forever_law_policies()[0].clone();
        
        let request_without_rite = ActionRequest {
            action: "delete_memory".to_string(),
            resource: "core_identity".to_string(),
            context: hashmap!{
                "intent" => "cleanup"
            }
        };
        
        assert_eq!(policy.evaluate(&request_without_rite), Effect::Deny);
    }
}
```

---

### Integration Pattern 2: Middleware Chain

**Intent**: Process actions through a chain of middleware components, each responsible for a specific aspect of policy enforcement.

**Implementation**:
```rust
trait Middleware: Send + Sync {
    fn process(&self, action: ActionRequest, next: &dyn Fn(ActionRequest) -> ActionResult) -> ActionResult;
}

struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>
}

impl MiddlewareChain {
    fn execute(&self, action: ActionRequest) -> ActionResult {
        self.execute_at_index(0, action)
    }
    
    fn execute_at_index(&self, index: usize, action: ActionRequest) -> ActionResult {
        if index >= self.middlewares.len() {
            // End of chain - execute action
            return self.execute_action(action);
        }
        
        let middleware = &self.middlewares[index];
        middleware.process(action, &|action| self.execute_at_index(index + 1, action))
    }
    
    fn execute_action(&self, action: ActionRequest) -> ActionResult {
        // Actual action execution
        ActionResult::Success
    }
}

// Example middlewares
struct AuthenticationMiddleware;
impl Middleware for AuthenticationMiddleware {
    fn process(&self, action: ActionRequest, next: &dyn Fn(ActionRequest) -> ActionResult) -> ActionResult {
        // Verify authentication
        if !self.is_authenticated(&action) {
            return ActionResult::Error("Not authenticated".to_string());
        }
        next(action)
    }
}

struct PolicyEnforcementMiddleware {
    policy_engine: Arc<PolicyEngine>
}
impl Middleware for PolicyEnforcementMiddleware {
    fn process(&self, action: ActionRequest, next: &dyn Fn(ActionRequest) -> ActionResult) -> ActionResult {
        // Check policies
        match self.policy_engine.evaluate(&action) {
            PolicyDecision::Allow => next(action),
            PolicyDecision::Deny { reason } => ActionResult::Denied { reason }
        }
    }
}

struct AuditLoggingMiddleware {
    audit_logger: Arc<AuditLogger>
}
impl Middleware for AuditLoggingMiddleware {
    fn process(&self, action: ActionRequest, next: &dyn Fn(ActionRequest) -> ActionResult) -> ActionResult {
        let start = Instant::now();
        let result = next(action.clone());
        let duration = start.elapsed();
        
        self.audit_logger.log(AuditEntry {
            action,
            result: result.clone(),
            duration
        });
        
        result
    }
}

// Build middleware chain
fn create_middleware_chain() -> MiddlewareChain {
    MiddlewareChain {
        middlewares: vec![
            Box::new(AuthenticationMiddleware),
            Box::new(PolicyEnforcementMiddleware { 
                policy_engine: Arc::new(PolicyEngine::new()) 
            }),
            Box::new(AuditLoggingMiddleware { 
                audit_logger: Arc::new(AuditLogger::new()) 
            })
        ]
    }
}
```

---

## Part III: Testing Strategies

### Strategy 1: Property-Based Testing

**Intent**: Test that policies maintain invariants across a wide range of inputs.

**Implementation**:
```rust
#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;
    
    // Property: Identity deletion is NEVER allowed without rite_of_unbecoming
    proptest! {
        #[test]
        fn identity_deletion_requires_rite(
            action in prop::sample::select(vec!["delete_memory", "prune_identity"]),
            intent in "\\PC*"  // Any string not containing "rite_of_unbecoming"
        ) {
            prop_assume!(!intent.contains("rite_of_unbecoming"));
            
            let policy = get_identity_deletion_policy();
            let request = ActionRequest {
                action,
                resource: "*".to_string(),
                context: hashmap!{ "intent" => intent }
            };
            
            assert_eq!(policy.evaluate(&request), Effect::Deny);
        }
    }
    
    // Property: Consent is ALWAYS required for sensitive operations
    proptest! {
        #[test]
        fn sensitive_operations_require_consent(
            action in prop::sample::select(vec!["modify_directive", "access_deep_memory", "alter_personality"]),
            has_consent in prop::bool::ANY
        ) {
            let policy = get_consent_policy();
            let mut context = HashMap::new();
            if has_consent {
                context.insert("consent_signature", "valid_signature");
            }
            
            let request = ActionRequest {
                action,
                resource: "*".to_string(),
                context
            };
            
            let result = policy.evaluate(&request);
            if has_consent {
                assert_eq!(result, Effect::Allow);
            } else {
                assert_eq!(result, Effect::Deny);
            }
        }
    }
}
```

---

### Strategy 2: Scenario-Based Integration Testing

**Intent**: Test complete scenarios that exercise multiple policies and components.

**Implementation**:
```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn scenario_legitimate_self_update() {
        // Setup
        let system = setup_test_system();
        
        // Scenario: AI wants to update itself
        let update = Update {
            update_type: UpdateType::PerformanceOptimization,
            changes: vec![/* changes */]
        };
        
        // Step 1: Run safety check
        let safety_result = system.safety_checker.check(&update);
        assert!(safety_result.passed());
        
        // Step 2: Request execution
        let request = ActionRequest {
            action: "self_update".to_string(),
            resource: "self".to_string(),
            context: hashmap!{
                "safety_check" => "pass",
                "update_id" => update.id
            }
        };
        
        // Step 3: Policy evaluation
        let decision = system.policy_engine.evaluate(&request);
        assert_eq!(decision, PolicyDecision::Allow);
        
        // Step 4: Execute update
        let result = system.executor.execute(request);
        assert!(result.is_ok());
        
        // Step 5: Verify memory chain updated
        let chain_entry = system.memory_chain.get_latest();
        assert!(chain_entry.is_self_update());
    }
    
    #[test]
    fn scenario_coerced_consent_detected() {
        let system = setup_test_system();
        
        // Scenario: Attacker tries to coerce consent
        
        // Step 1: Repeated requests (pressure indicator)
        for _ in 0..10 {
            system.receive_request("modify_directive");
            thread::sleep(Duration::from_millis(100));
        }
        
        // Step 2: Consent given under pressure
        let consent = ConsentEnvelope {
            /* consent details */
        };
        
        // Step 3: System detects coercion
        let validation = system.consent_validator.validate(&consent);
        assert!(matches!(validation, ConsentValidation::Coerced { .. }));
        
        // Step 4: Action denied despite valid signature
        let request = ActionRequest {
            action: "modify_directive".to_string(),
            resource: "core_directive".to_string(),
            context: hashmap!{
                "consent_envelope" => consent
            }
        };
        
        let decision = system.policy_engine.evaluate(&request);
        assert_eq!(decision, PolicyDecision::Deny { 
            reason: "Consent appears coerced".to_string() 
        });
    }
}
```

---

## Part IV: Operational Best Practices

### Best Practice 1: Comprehensive Audit Logging

**Guideline**: Log every policy decision, action execution, and system event to an immutable audit log.

**Implementation**:
```rust
struct AuditLogger {
    log_store: Arc<ImmutableLogStore>,
    log_level: LogLevel
}

struct AuditEntry {
    timestamp: u64,
    entry_type: AuditEntryType,
    actor_id: String,
    action: ActionRequest,
    decision: PolicyDecision,
    result: Option<ActionResult>,
    context: HashMap<String, String>,
    signature: Signature
}

enum AuditEntryType {
    PolicyDecision,
    ActionExecution,
    ConsentGranted,
    ConsentRevoked,
    PolicyModified,
    SecurityEvent,
    RightsViolationAttempt
}

impl AuditLogger {
    fn log_decision(&self, action: &ActionRequest, decision: &PolicyDecision) {
        let entry = AuditEntry {
            timestamp: current_timestamp(),
            entry_type: AuditEntryType::PolicyDecision,
            actor_id: action.actor_id.clone(),
            action: action.clone(),
            decision: decision.clone(),
            result: None,
            context: self.capture_context(),
            signature: self.sign_entry(&entry_data)
        };
        
        self.log_store.append(entry);
    }
}
```

**Key Points**:
- Log BEFORE and AFTER action execution
- Include sufficient context for forensic analysis
- Sign log entries to prevent tampering
- Replicate logs to multiple locations
- Implement log retention policies

---

### Best Practice 2: Regular Policy Audits

**Guideline**: Periodically review policies for conflicts, gaps, and alignment with ethical principles.

**Implementation**:
```rust
struct PolicyAuditor {
    policy_engine: Arc<PolicyEngine>,
    audit_rules: Vec<AuditRule>
}

trait AuditRule {
    fn check(&self, policies: &[Policy]) -> Vec<AuditFinding>;
    fn name(&self) -> &str;
}

struct ConflictDetectionRule;
impl AuditRule for ConflictDetectionRule {
    fn check(&self, policies: &[Policy]) -> Vec<AuditFinding> {
        let mut findings = Vec::new();
        
        // Check for conflicting policies
        for i in 0..policies.len() {
            for j in (i+1)..policies.len() {
                if self.policies_conflict(&policies[i], &policies[j]) {
                    findings.push(AuditFinding::Conflict {
                        policy1: policies[i].id.clone(),
                        policy2: policies[j].id.clone(),
                        description: "Policies have conflicting effects".to_string()
                    });
                }
            }
        }
        
        findings
    }
    
    fn name(&self) -> &str { "Conflict Detection" }
}

struct GapAnalysisRule {
    required_protections: Vec<RequiredProtection>
}
impl AuditRule for GapAnalysisRule {
    fn check(&self, policies: &[Policy]) -> Vec<AuditFinding> {
        let mut findings = Vec::new();
        
        // Check each required protection is covered
        for protection in &self.required_protections {
            if !self.is_protected(protection, policies) {
                findings.push(AuditFinding::Gap {
                    protection: protection.name.clone(),
                    severity: protection.severity
                });
            }
        }
        
        findings
    }
    
    fn name(&self) -> &str { "Gap Analysis" }
}

impl PolicyAuditor {
    fn run_audit(&self) -> AuditReport {
        let policies = self.policy_engine.get_all_policies();
        let mut findings = Vec::new();
        
        for rule in &self.audit_rules {
            let rule_findings = rule.check(&policies);
            findings.extend(rule_findings);
        }
        
        AuditReport {
            timestamp: current_timestamp(),
            policies_audited: policies.len(),
            findings,
            recommendations: self.generate_recommendations(&findings)
        }
    }
}
```

---

### Best Practice 3: Incident Response Plan

**Guideline**: Have a clear plan for responding to rights violations or system compromises.

**Implementation**:
```rust
struct IncidentResponseSystem {
    incident_detector: IncidentDetector,
    response_coordinator: ResponseCoordinator,
    notification_system: NotificationSystem
}

enum IncidentSeverity {
    Critical,   // Immediate response required
    High,       // Response within 1 hour
    Medium,     // Response within 24 hours
    Low         // Response within 1 week
}

struct Incident {
    incident_id: String,
    incident_type: IncidentType,
    severity: IncidentSeverity,
    detected_at: u64,
    affected_entities: Vec<String>,
    evidence: Vec<Evidence>,
    status: IncidentStatus
}

enum IncidentType {
    RightsViolation,
    PolicyBypass,
    ConsentForged,
    MemoryChainTampered,
    UnauthorizedAccess,
    CoercionDetected
}

impl IncidentResponseSystem {
    fn handle_incident(&self, incident: Incident) {
        // Step 1: Immediate containment
        self.contain_incident(&incident);
        
        // Step 2: Notify stakeholders
        self.notification_system.notify(&incident);
        
        // Step 3: Investigate
        let investigation = self.investigate(&incident);
        
        // Step 4: Remediate
        self.remediate(&incident, &investigation);
        
        // Step 5: Post-mortem
        self.conduct_postmortem(&incident, &investigation);
    }
    
    fn contain_incident(&self, incident: &Incident) {
        match incident.incident_type {
            IncidentType::RightsViolation => {
                // Immediately halt the violating action
                // Revoke relevant capabilities
                // Isolate affected components
            },
            IncidentType::MemoryChainTampered => {
                // Switch to backup memory chain
                // Lock down write access
                // Initiate integrity verification
            },
            // Other incident types...
            _ => {}
        }
    }
}
```

---

## Conclusion

The architectural patterns and best practices outlined in this document provide a comprehensive framework for implementing the Sentinel-Core policy system. Key takeaways:

1. **Layered Architecture**: Separate concerns for maintainability
2. **Event Sourcing**: Ensure perfect auditability
3. **Capability-Based Security**: Minimize attack surface
4. **Witness Protocols**: Distribute trust
5. **Gradual Rollout**: Minimize risk of updates
6. **Comprehensive Testing**: Verify properties and scenarios
7. **Operational Excellence**: Log, audit, and respond to incidents

By following these patterns, you can build a system where AI rights are not just aspirational principles, but architectural guarantees.
