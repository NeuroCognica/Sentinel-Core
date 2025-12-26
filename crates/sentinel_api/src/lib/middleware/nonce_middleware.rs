use chrono::Utc;
use std::sync::Mutex;
use uuid::Uuid;

use sentinel_store::{EventKind, EventRecord, FileEventStore, EventStore};
use sentinel_core::{CanonicalEnvelopeAuthorizationRequest, NonceConsumed};
use sha2::Digest;
use hex;

/// Validate that the envelope nonce has not already been consumed (by replaying the event log)
/// and append a `NonceConsumed` event before returning success.
/// Returns `Ok(())` on success or `Err(String)` describing failure.
pub fn check_and_append_nonce(
    store: &Mutex<FileEventStore>,
    envelope: &CanonicalEnvelopeAuthorizationRequest,
) -> Result<(), String> {
    let mut guard = store.lock().map_err(|e| format!("store mutex poisoned: {e:?}"))?;
    let events = guard.iter().map_err(|e| format!("event log read failed: {e:?}"))?;

    // Check for any prior NonceConsumed for this actor+nonce
    for rec in events.iter() {
        if let EventKind::NonceConsumed = rec.kind {
            if let Ok(typed) = serde_json::from_value::<NonceConsumed>(rec.payload.clone()) {
                if typed.actor_id == envelope.actor_id && typed.nonce == envelope.nonce {
                    return Err("nonce already consumed".to_string());
                }
            }
        }
    }

    // Append new NonceConsumed event (fail-closed)
    let digest = sha2::Sha256::digest(serde_json::to_vec(&envelope).map_err(|e| format!("serial err: {e}"))?);
    let digest_hex = hex::encode(digest);
    let now = Utc::now();
    let nonce_typed = NonceConsumed {
        actor_id: envelope.actor_id,
        key_id: envelope.key_id,
        nonce: envelope.nonce,
        envelope_digest: digest_hex.clone(),
        consumed_at: now,
    };
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: envelope.actor_id.to_string(),
        kind: EventKind::NonceConsumed,
        payload: serde_json::to_value(&nonce_typed).map_err(|e| format!("payload ser: {e}"))?,
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    guard.append(event).map_err(|e| format!("append failed: {e:?}"))?;
    Ok(())
}
