/// Capability model and events for append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub capability_id: Uuid,
    pub actor_id: Uuid,
    pub issued_at_utc: DateTime<Utc>,
    pub expires_at_utc: DateTime<Utc>,
    pub scope: String,
    pub actions: Vec<String>,
    pub constraints: Option<CapabilityConstraints>,
    pub issued_by: String,        // Sentinel service identity
    pub token_signature: Vec<u8>, // Ed25519 signature over canonical fields
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityConstraints {
    pub allowed_artifact_digests: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityEvent {
    CapabilityIssued(CapabilityIssued),
    CapabilityRevoked(CapabilityRevoked),
    CapabilityConsumed(CapabilityConsumed),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityIssued {
    pub capability: Capability,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRevoked {
    pub capability_id: Uuid,
    pub revoked_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityConsumed {
    pub capability_id: Uuid,
    pub consumed_at: DateTime<Utc>,
    pub envelope_digest: String, // SHA-256 of the envelope that used it
    pub artifact_digest: Option<String>,
}
/// Identity lifecycle events for append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityEvent {
    ActorRegistered(ActorRegistered),
    KeyRegistered(KeyRegistered),
    KeyRevoked(KeyRevoked),
    KeyRotated(KeyRotated), // Optional, can be stubbed for now
    NonceConsumed(NonceConsumed),
    GenesisCompleted(GenesisCompleted),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisCompleted {
    pub completed_at: DateTime<Utc>,
    pub admin_actor_id: Uuid,
    pub admin_key_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRegistered {
    pub actor_id: Uuid,
    pub human_handle: Option<String>, // Optional, for display only
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRegistered {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub public_key: Vec<u8>, // Ed25519 public key bytes
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRevoked {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotated {
    pub actor_id: Uuid,
    pub old_key_id: Uuid,
    pub new_key_id: Uuid,
    pub new_public_key: Vec<u8>,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceConsumed {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub nonce: Uuid,
    pub envelope_digest: String, // hex-encoded SHA-256 of canonical envelope
    pub consumed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthChallengeIssued {
    pub challenge: String,
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub issued_at_utc: DateTime<Utc>,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthChallengeConsumed {
    pub challenge: String,
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub consumed_at_utc: DateTime<Utc>,
}
// sentinel_core: types, policy engine interfaces, guard logic, error types

use serde::{Deserialize, Serialize};
// ...existing code...
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Canonical constitutional envelope for all privileged requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalEnvelopeAuthorizationRequest {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub nonce: Uuid,
    pub timestamp_utc: DateTime<Utc>,
    pub payload: AuthorizationRequest,
    pub signature: Vec<u8>, // Signature bytes (algorithm is fixed for now)
}

/// Minimal authorization payload for Step 1
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub action: String,
    pub scope: String,
    pub intent: String,
}

// No defaults, no optionals, no best effort. This is the constitutional artifact.

/// Actions that must never execute without Sentinel authorization.
pub const PROTECTED_ACTIONS: &[&str] = &[
    "agent.spawn",
    "artifact.register",
    "artifact.export",
    "artifact.use",
    "browser.navigate_external",
    "capability.issue",
    "capability.consume",
    "chat.respond",
    "effect.execute",
    "external_message.send",
    "file.delete",
    "file.read_sensitive",
    "file.write",
    "game.respond",
    "game.share",
    "hardware.activate_camera",
    "hardware.activate_microphone",
    "identity.genesis",
    "identity.register",
    "identity.rebind",
    "identity.key.register",
    "identity.key.revoke",
    "identity.key.rotate",
    "installer.update",
    "memory.write",
    "memory.delete",
    "model.generate",
    "network.egress",
    "network.request",
    "payment.or_commitment",
    "plugin.install",
    "plugin.execute",
    "policy.evaluate",
    "process.spawn",
    "profile.generate",
    "robot.command",
    "shell.execute",
    "system.install",
    "tool.invoke",
    "tool.run",
];

pub fn is_protected_action(action: &str) -> bool {
    PROTECTED_ACTIONS.contains(&action)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentinelGuardRequest {
    pub envelope_version: String,
    pub action: String,
    pub resource: String,
    pub actor_id: Uuid,
    pub actor_class: String,
    pub subject_system: String,
    pub request_origin: String,
    pub timestamp_utc: DateTime<Utc>,
    pub nonce: Uuid,
    pub payload_hash: String,
    pub context_digest: String,
    pub requested_capability: Option<String>,
    pub consent_reference: Option<String>,
    pub declared_intent: String,
    pub irreversible_side_effect: bool,
    pub external_impact: bool,
    pub envelope_digest: String,
}

impl SentinelGuardRequest {
    pub fn validation_errors(&self) -> Vec<SentinelGuardViolation> {
        let mut errors = Vec::new();
        push_required(&mut errors, "envelope_version", &self.envelope_version);
        push_required(&mut errors, "action", &self.action);
        push_required(&mut errors, "resource", &self.resource);
        push_required(&mut errors, "actor_class", &self.actor_class);
        push_required(&mut errors, "subject_system", &self.subject_system);
        push_required(&mut errors, "request_origin", &self.request_origin);
        push_required(&mut errors, "payload_hash", &self.payload_hash);
        push_required(&mut errors, "context_digest", &self.context_digest);
        push_required(&mut errors, "declared_intent", &self.declared_intent);
        push_required(&mut errors, "envelope_digest", &self.envelope_digest);

        if self.actor_id.is_nil() {
            errors.push(SentinelGuardViolation::new(
                "actor_id",
                "actor_id must not be nil",
            ));
        }
        if self.nonce.is_nil() {
            errors.push(SentinelGuardViolation::new(
                "nonce",
                "nonce must not be nil",
            ));
        }

        errors
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentinelGuardViolation {
    pub field: String,
    pub reason: String,
}

impl SentinelGuardViolation {
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuardDecisionClass {
    Allow,
    AllowWithMonitoring,
    RequireConsent,
    RequireWitness,
    Sandbox,
    Sanitize,
    RateShape,
    Deny,
    Quarantine,
    Lockdown,
    Halt,
}

impl GuardDecisionClass {
    pub fn authorizes_effect(&self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithMonitoring)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentinelGuardDecision {
    pub trace_id: Uuid,
    pub class: GuardDecisionClass,
    pub allowed: bool,
    pub monitoring_required: bool,
    pub rationale: String,
    pub policy_id: String,
    pub policy_version: String,
    pub matched_rule_id: Option<String>,
    pub violations: Vec<SentinelGuardViolation>,
    pub ledger_event_hash: Option<String>,
}

impl SentinelGuardDecision {
    pub fn authorizes_effect(&self) -> bool {
        self.allowed && self.class.authorizes_effect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuardPolicyMode {
    DenyAll,
    ExplicitRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardPolicy {
    pub policy_id: String,
    pub policy_version: String,
    pub mode: GuardPolicyMode,
    pub rules: Vec<GuardRule>,
}

impl GuardPolicy {
    pub fn deny_all(policy_id: impl Into<String>, policy_version: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            policy_version: policy_version.into(),
            mode: GuardPolicyMode::DenyAll,
            rules: Vec::new(),
        }
    }

    pub fn explicit(
        policy_id: impl Into<String>,
        policy_version: impl Into<String>,
        rules: Vec<GuardRule>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            policy_version: policy_version.into(),
            mode: GuardPolicyMode::ExplicitRules,
            rules,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardRule {
    pub rule_id: String,
    pub action: String,
    pub resource: String,
    pub actor_class: String,
    pub subject_system: String,
    pub decision: GuardDecisionClass,
    pub rationale: String,
}

impl GuardRule {
    pub fn allow(
        rule_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        actor_class: impl Into<String>,
        subject_system: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            action: action.into(),
            resource: resource.into(),
            actor_class: actor_class.into(),
            subject_system: subject_system.into(),
            decision: GuardDecisionClass::Allow,
            rationale: rationale.into(),
        }
    }

    pub fn deny(
        rule_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        actor_class: impl Into<String>,
        subject_system: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            action: action.into(),
            resource: resource.into(),
            actor_class: actor_class.into(),
            subject_system: subject_system.into(),
            decision: GuardDecisionClass::Deny,
            rationale: rationale.into(),
        }
    }

    fn matches(&self, request: &SentinelGuardRequest) -> bool {
        self.action == request.action
            && self.resource == request.resource
            && self.actor_class == request.actor_class
            && self.subject_system == request.subject_system
    }
}

pub trait SentinelGuard {
    fn authorize(&self, request: &SentinelGuardRequest) -> SentinelGuardDecision;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicSentinelGuard {
    pub policy: GuardPolicy,
}

impl DeterministicSentinelGuard {
    pub fn new(policy: GuardPolicy) -> Self {
        Self { policy }
    }
}

impl SentinelGuard for DeterministicSentinelGuard {
    fn authorize(&self, request: &SentinelGuardRequest) -> SentinelGuardDecision {
        let trace_id = guard_trace_id(request);
        let violations = request.validation_errors();
        if !violations.is_empty() {
            return self.decision(
                trace_id,
                GuardDecisionClass::Lockdown,
                false,
                false,
                "malformed guard request; protected action is locked down",
                None,
                violations,
            );
        }

        if !is_protected_action(&request.action) {
            return self.decision(
                trace_id,
                GuardDecisionClass::Deny,
                false,
                false,
                "action is not in the protected-action registry",
                None,
                Vec::new(),
            );
        }

        if self.policy.mode == GuardPolicyMode::DenyAll {
            return self.decision(
                trace_id,
                GuardDecisionClass::Deny,
                false,
                false,
                "deny-all policy is active",
                None,
                Vec::new(),
            );
        }

        let Some(rule) = self.policy.rules.iter().find(|rule| rule.matches(request)) else {
            return self.decision(
                trace_id,
                GuardDecisionClass::Deny,
                false,
                false,
                "no explicit matching guard rule; default deny",
                None,
                Vec::new(),
            );
        };

        let mut class = rule.decision.clone();
        let mut monitoring_required = false;
        if class == GuardDecisionClass::Allow
            && (request.irreversible_side_effect || request.external_impact)
        {
            class = GuardDecisionClass::AllowWithMonitoring;
            monitoring_required = true;
        }

        self.decision(
            trace_id,
            class.clone(),
            class.authorizes_effect(),
            monitoring_required,
            &rule.rationale,
            Some(rule.rule_id.clone()),
            Vec::new(),
        )
    }
}

impl DeterministicSentinelGuard {
    fn decision(
        &self,
        trace_id: Uuid,
        class: GuardDecisionClass,
        allowed: bool,
        monitoring_required: bool,
        rationale: impl Into<String>,
        matched_rule_id: Option<String>,
        violations: Vec<SentinelGuardViolation>,
    ) -> SentinelGuardDecision {
        SentinelGuardDecision {
            trace_id,
            class,
            allowed,
            monitoring_required,
            rationale: rationale.into(),
            policy_id: self.policy.policy_id.clone(),
            policy_version: self.policy.policy_version.clone(),
            matched_rule_id,
            violations,
            ledger_event_hash: None,
        }
    }
}

fn guard_trace_id(request: &SentinelGuardRequest) -> Uuid {
    let seed = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        request.envelope_version,
        request.action,
        request.resource,
        request.actor_id,
        request.actor_class,
        request.nonce,
        request.envelope_digest
    );
    Uuid::new_v5(&Uuid::NAMESPACE_OID, seed.as_bytes())
}

fn push_required(errors: &mut Vec<SentinelGuardViolation>, field: &str, value: &str) {
    if value.trim().is_empty() {
        errors.push(SentinelGuardViolation::new(
            field,
            format!("{field} must not be empty"),
        ));
    }
}

#[cfg(test)]
mod sentinel_guard_tests {
    use super::*;

    fn valid_request(action: &str) -> SentinelGuardRequest {
        SentinelGuardRequest {
            envelope_version: "sentinel.guard.v1".to_string(),
            action: action.to_string(),
            resource: "workspace://chronos/protected".to_string(),
            actor_id: Uuid::new_v4(),
            actor_class: "chronosophia.runtime".to_string(),
            subject_system: "chronosophia".to_string(),
            request_origin: "unit-test".to_string(),
            timestamp_utc: Utc::now(),
            nonce: Uuid::new_v4(),
            payload_hash: "sha256:payload".to_string(),
            context_digest: "sha256:context".to_string(),
            requested_capability: Some("capability:unit-test".to_string()),
            consent_reference: None,
            declared_intent: "prove Sentinel fail-closed behavior".to_string(),
            irreversible_side_effect: false,
            external_impact: false,
            envelope_digest: "sha256:envelope".to_string(),
        }
    }

    #[test]
    fn deny_all_paralyzes_every_protected_action() {
        let guard = DeterministicSentinelGuard::new(GuardPolicy::deny_all(
            "constitutional-deny-all",
            "test",
        ));

        for action in PROTECTED_ACTIONS {
            let decision = guard.authorize(&valid_request(action));
            assert_eq!(decision.class, GuardDecisionClass::Deny);
            assert!(!decision.allowed);
            assert!(!decision.authorizes_effect());
            assert_eq!(decision.rationale, "deny-all policy is active");
        }
    }

    #[test]
    fn malformed_request_locks_down_before_policy_match() {
        let guard = DeterministicSentinelGuard::new(GuardPolicy::explicit(
            "allow-policy",
            "test",
            vec![GuardRule::allow(
                "allow-effect",
                "effect.execute",
                "workspace://chronos/protected",
                "chronosophia.runtime",
                "chronosophia",
                "allowed for test",
            )],
        ));
        let mut request = valid_request("effect.execute");
        request.envelope_digest.clear();

        let decision = guard.authorize(&request);

        assert_eq!(decision.class, GuardDecisionClass::Lockdown);
        assert!(!decision.authorizes_effect());
        assert_eq!(decision.violations[0].field, "envelope_digest");
    }

    #[test]
    fn exact_allow_rule_authorizes_only_exact_subject_and_resource() {
        let guard = DeterministicSentinelGuard::new(GuardPolicy::explicit(
            "allow-policy",
            "test",
            vec![GuardRule::allow(
                "allow-effect",
                "effect.execute",
                "workspace://chronos/protected",
                "chronosophia.runtime",
                "chronosophia",
                "allowed for test",
            )],
        ));

        let allowed = guard.authorize(&valid_request("effect.execute"));
        assert_eq!(allowed.class, GuardDecisionClass::Allow);
        assert!(allowed.authorizes_effect());
        assert_eq!(allowed.matched_rule_id.as_deref(), Some("allow-effect"));

        let mut wrong_resource = valid_request("effect.execute");
        wrong_resource.resource = "workspace://chronos/other".to_string();
        let denied = guard.authorize(&wrong_resource);
        assert_eq!(denied.class, GuardDecisionClass::Deny);
        assert!(!denied.authorizes_effect());
        assert_eq!(
            denied.rationale,
            "no explicit matching guard rule; default deny"
        );
    }

    #[test]
    fn irreversible_or_external_impact_promotes_allow_to_monitored_allow() {
        let guard = DeterministicSentinelGuard::new(GuardPolicy::explicit(
            "allow-policy",
            "test",
            vec![GuardRule::allow(
                "allow-spawn",
                "process.spawn",
                "workspace://chronos/protected",
                "chronosophia.runtime",
                "chronosophia",
                "allowed for supervised test",
            )],
        ));
        let mut request = valid_request("process.spawn");
        request.external_impact = true;

        let decision = guard.authorize(&request);

        assert_eq!(decision.class, GuardDecisionClass::AllowWithMonitoring);
        assert!(decision.monitoring_required);
        assert!(decision.authorizes_effect());
    }

    #[test]
    fn non_authorizing_decision_classes_cannot_execute_effects() {
        for class in [
            GuardDecisionClass::RequireConsent,
            GuardDecisionClass::RequireWitness,
            GuardDecisionClass::Sandbox,
            GuardDecisionClass::Sanitize,
            GuardDecisionClass::RateShape,
            GuardDecisionClass::Deny,
            GuardDecisionClass::Quarantine,
            GuardDecisionClass::Lockdown,
            GuardDecisionClass::Halt,
        ] {
            assert!(
                !class.authorizes_effect(),
                "{class:?} must not execute directly"
            );
        }
    }

    #[test]
    fn unregistered_action_is_denied_even_under_allowing_policy() {
        let guard = DeterministicSentinelGuard::new(GuardPolicy::explicit(
            "allow-policy",
            "test",
            vec![GuardRule::allow(
                "allow-unknown",
                "unknown.execute",
                "workspace://chronos/protected",
                "chronosophia.runtime",
                "chronosophia",
                "should never authorize unregistered actions",
            )],
        ));

        let decision = guard.authorize(&valid_request("unknown.execute"));

        assert_eq!(decision.class, GuardDecisionClass::Deny);
        assert!(!decision.authorizes_effect());
        assert_eq!(
            decision.rationale,
            "action is not in the protected-action registry"
        );
    }
}
