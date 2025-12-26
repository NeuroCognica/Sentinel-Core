//! Adversarial tests for persistent replay protection and event-sourced identity

use crate::*;
use chrono::Utc;
use sentinel_core::*;
use uuid::Uuid;

#[test]
fn duplicate_nonce_detection_in_reducer() {
    let actor_id = Uuid::new_v4();
    let key_id = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let digest = "deadbeef".to_string();
    let now = Utc::now();
    let events = vec![
        IdentityEvent::ActorRegistered(ActorRegistered {
            actor_id,
            human_handle: None,
            timestamp_utc: now,
        }),
        IdentityEvent::KeyRegistered(KeyRegistered {
            actor_id,
            key_id,
            public_key: vec![1, 2, 3, 4],
            timestamp_utc: now,
        }),
        IdentityEvent::NonceConsumed(NonceConsumed {
            actor_id,
            key_id,
            nonce,
            envelope_digest: digest.clone(),
            consumed_at: now,
        }),
        IdentityEvent::NonceConsumed(NonceConsumed {
            actor_id,
            key_id,
            nonce,
            envelope_digest: digest,
            consumed_at: now,
        }),
    ];
    let result = IdentityState::reduce(events);
    assert!(result.is_err(), "Reducer must fail on duplicate nonce");
}
