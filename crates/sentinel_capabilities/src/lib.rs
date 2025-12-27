use chrono::{DateTime, Utc};
use sentinel_core::{
    Capability, CapabilityConsumed, CapabilityEvent, CapabilityIssued, CapabilityRevoked,
};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct CapabilityState {
    pub active: HashMap<Uuid, Capability>, // capability_id -> Capability
    pub by_actor: HashMap<Uuid, HashSet<Uuid>>, // actor_id -> set of capability_ids
    pub revoked: HashSet<Uuid>,
    pub consumed: HashSet<Uuid>,
}

impl CapabilityState {
    pub fn reduce<I: IntoIterator<Item = CapabilityEvent>>(
        events: I,
        valid_actors: &HashSet<Uuid>,
    ) -> Result<Self, String> {
        let mut state = CapabilityState::default();
        for event in events {
            match event {
                CapabilityEvent::CapabilityIssued(CapabilityIssued { capability, .. }) => {
                    if !valid_actors.contains(&capability.actor_id) {
                        return Err(format!(
                            "Cannot issue capability for unknown actor: {}",
                            capability.actor_id
                        ));
                    }
                    if state.active.contains_key(&capability.capability_id) {
                        return Err(format!(
                            "Duplicate capability_id: {}",
                            capability.capability_id
                        ));
                    }
                    state
                        .by_actor
                        .entry(capability.actor_id)
                        .or_default()
                        .insert(capability.capability_id);
                    state.active.insert(capability.capability_id, capability);
                }
                CapabilityEvent::CapabilityRevoked(CapabilityRevoked { capability_id, .. }) => {
                    if !state.active.contains_key(&capability_id) {
                        return Err(format!(
                            "Cannot revoke unknown capability: {}",
                            capability_id
                        ));
                    }
                    state.revoked.insert(capability_id);
                    state.active.remove(&capability_id);
                }
                CapabilityEvent::CapabilityConsumed(CapabilityConsumed { capability_id, artifact_digest, .. }) => {
                    if !state.active.contains_key(&capability_id) {
                        return Err(format!(
                            "Cannot consume unknown or revoked capability: {}",
                            capability_id
                        ));
                    }
                    // Enforce artifact-binding constraints: absence of constraints or allowed_artifact_digests is a DENY
                    let cap = state.active.get(&capability_id).expect("checked presence above");
                    // If there are no constraints at all, deny consumption (absence != wildcard)
                    if cap.constraints.is_none() {
                        return Err(format!("Capability {} has no constraints; consumption denied", capability_id));
                    }
                    let constraints = cap.constraints.as_ref().unwrap();
                    // If allowed_artifact_digests is absent, deny as well
                    let allowed = match &constraints.allowed_artifact_digests {
                        Some(a) => a,
                        None => return Err(format!("Capability {} has no allowed_artifact_digests; consumption denied", capability_id)),
                    };
                    // If capability has allowed_artifact_digests, the consume event MUST include an artifact_digest
                    match &artifact_digest {
                        Some(ad) => {
                            if !allowed.contains(ad) {
                                return Err(format!("Capability {} not allowed for artifact {}", capability_id, ad));
                            }
                        }
                        None => {
                            return Err(format!("Capability {} requires artifact_digest in consume event", capability_id));
                        }
                    }
                    if state.consumed.contains(&capability_id) {
                        return Err(format!("Double-consume forbidden: {}", capability_id));
                    }
                    state.consumed.insert(capability_id);
                    state.active.remove(&capability_id);
                }
            }
        }
        Ok(state)
    }
}
