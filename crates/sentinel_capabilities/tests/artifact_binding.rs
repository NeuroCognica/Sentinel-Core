use chrono::Utc;
use sentinel_capabilities::CapabilityState;
use sentinel_core::{Capability, CapabilityConstraints, CapabilityEvent, CapabilityIssued, CapabilityConsumed};
use std::collections::HashSet;
use uuid::Uuid;

fn make_issued(cap: &Capability) -> CapabilityEvent {
    CapabilityEvent::CapabilityIssued(CapabilityIssued { capability: cap.clone(), issued_at: Utc::now() })
}

fn make_consumed(cap_id: Uuid, artifact: Option<&str>) -> CapabilityEvent {
    CapabilityEvent::CapabilityConsumed(CapabilityConsumed {
        capability_id: cap_id,
        consumed_at: Utc::now(),
        envelope_digest: "deadbeef".to_string(),
        artifact_digest: artifact.map(|s| s.to_string()),
    })
}

#[test]
fn test_allow_path() {
    let actor = Uuid::new_v4();
    let cap_id = Uuid::new_v4();
    let cap = Capability {
        capability_id: cap_id,
        actor_id: actor,
        issued_at_utc: Utc::now(),
        expires_at_utc: Utc::now(),
        scope: "test".to_string(),
        actions: vec![],
        constraints: Some(CapabilityConstraints { allowed_artifact_digests: Some(vec!["A".to_string()]) }),
        issued_by: "tester".to_string(),
        token_signature: vec![],
    };

    let events = vec![make_issued(&cap), make_consumed(cap_id, Some("A"))];
    let mut valid = HashSet::new();
    valid.insert(actor);
    let s = CapabilityState::reduce(events.into_iter(), &valid).expect("reduce should succeed");
    assert!(s.consumed.contains(&cap_id));
    assert!(!s.active.contains_key(&cap_id));
}

#[test]
fn test_deny_mismatched_digest() {
    let actor = Uuid::new_v4();
    let cap_id = Uuid::new_v4();
    let cap = Capability {
        capability_id: cap_id,
        actor_id: actor,
        issued_at_utc: Utc::now(),
        expires_at_utc: Utc::now(),
        scope: "test".to_string(),
        actions: vec![],
        constraints: Some(CapabilityConstraints { allowed_artifact_digests: Some(vec!["A".to_string()]) }),
        issued_by: "tester".to_string(),
        token_signature: vec![],
    };

    let events = vec![make_issued(&cap), make_consumed(cap_id, Some("B"))];
    let mut valid = HashSet::new();
    valid.insert(actor);
    let res = CapabilityState::reduce(events.into_iter(), &valid);
    assert!(res.is_err(), "expected deny for mismatched digest");
}

#[test]
fn test_deny_missing_artifact_digest() {
    let actor = Uuid::new_v4();
    let cap_id = Uuid::new_v4();
    let cap = Capability {
        capability_id: cap_id,
        actor_id: actor,
        issued_at_utc: Utc::now(),
        expires_at_utc: Utc::now(),
        scope: "test".to_string(),
        actions: vec![],
        constraints: Some(CapabilityConstraints { allowed_artifact_digests: Some(vec!["A".to_string()]) }),
        issued_by: "tester".to_string(),
        token_signature: vec![],
    };

    let events = vec![make_issued(&cap), make_consumed(cap_id, None)];
    let mut valid = HashSet::new();
    valid.insert(actor);
    let res = CapabilityState::reduce(events.into_iter(), &valid);
    assert!(res.is_err(), "expected deny when artifact_digest missing");
}

#[test]
fn test_deny_absence_of_constraints() {
    let actor = Uuid::new_v4();
    let cap_id = Uuid::new_v4();
    let cap = Capability {
        capability_id: cap_id,
        actor_id: actor,
        issued_at_utc: Utc::now(),
        expires_at_utc: Utc::now(),
        scope: "test".to_string(),
        actions: vec![],
        constraints: None,
        issued_by: "tester".to_string(),
        token_signature: vec![],
    };

    let events = vec![make_issued(&cap), make_consumed(cap_id, Some("X"))];
    let mut valid = HashSet::new();
    valid.insert(actor);
    let res = CapabilityState::reduce(events.into_iter(), &valid);
    assert!(res.is_err(), "expected deny when capability lacks constraints");
}
