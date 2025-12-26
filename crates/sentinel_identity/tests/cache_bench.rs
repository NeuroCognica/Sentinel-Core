use std::time::Instant;
use uuid::Uuid;
use chrono::Utc;
use sentinel_core::NonceConsumed;
use sentinel_identity::NonceRegistry;

#[test]
#[ignore]
fn bench_nonce_registry_cold_vs_warm() {
    // prepare data
    let actor = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut events = Vec::new();
    for _ in 0..10_000 {
        let n = Uuid::new_v4();
        events.push(sentinel_core::IdentityEvent::NonceConsumed(NonceConsumed {
            actor_id: actor,
            key_id: key,
            nonce: n,
            envelope_digest: "d".to_string(),
            consumed_at: Utc::now(),
        }));
    }

    // Cold: rebuild registry from events then lookup
    let start = Instant::now();
    let reg_cold = NonceRegistry::from_events(events.clone());
    let duration_replay = start.elapsed();

    // Warm: pick one entry and do many lookups
    let sample_nonce = match events.get(5000) {
        Some(sentinel_core::IdentityEvent::NonceConsumed(nc)) => nc.nonce,
        _ => Uuid::new_v4(),
    };

    let start = Instant::now();
    for _ in 0..100_000 {
        let _ = reg_cold.is_consumed(actor, sample_nonce);
    }
    let duration_lookup = start.elapsed();

    println!("replay: {:?}, lookups(100k): {:?}", duration_replay, duration_lookup);
}
