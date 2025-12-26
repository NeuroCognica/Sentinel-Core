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
                CapabilityEvent::CapabilityConsumed(CapabilityConsumed {
                    capability_id, ..
                }) => {
                    if !state.active.contains_key(&capability_id) {
                        return Err(format!(
                            "Cannot consume unknown or revoked capability: {}",
                            capability_id
                        ));
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
