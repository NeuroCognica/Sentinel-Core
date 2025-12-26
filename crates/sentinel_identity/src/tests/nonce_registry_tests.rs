use crate::super::*;
use chrono::Utc;
use sentinel_core::NonceConsumed;
use uuid::Uuid;

#[test]
fn nonce_registry_from_events_detects_consumed() {
    let actor = Uuid::new_v4();
    let key = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let now = Utc::now();
    let events = vec![IdentityEvent::NonceConsumed(NonceConsumed {
        actor_id: actor,
        key_id: key,
        nonce,
        envelope_digest: "abc".to_string(),
        consumed_at: now,
    })];
    let reg = crate::nonce_registry::NonceRegistry::from_events(events);
    assert!(reg.is_consumed(actor, nonce));
}
