use chrono::Utc;
use serde_json::json;
use sentinel_store::{EventRecord, EventKind, FileEventStore, EventStore};
use sentinel_identity::{load_identity_state_from_event_log, Keystore, SignedEnvelope};
use std::fs::{create_dir_all, remove_file};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

fn make_event(actor: &str, kind: EventKind, payload: serde_json::Value) -> EventRecord {
    EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: actor.to_string(),
        kind,
        payload,
        prev_hash: None,
        hash: String::new(),
    }
}

fn bench_append(path: &PathBuf, n: usize) -> Result<(), String> {
    // ensure clean file
    if path.exists() {
        let _ = remove_file(path);
    }
    let mut store = FileEventStore::open(path).map_err(|e| format!("open: {:?}", e))?;
    let start = Instant::now();
    for i in 0..n {
        let payload = json!({"i": i, "note": "benchmark"});
        let ev = make_event("bench_actor", EventKind::CapabilityIssued, payload);
        store.append(ev).map_err(|e| format!("append: {:?}", e))?;
    }
    let dur = start.elapsed();
    println!("append: {} events in {:?} => {:.2} ev/sec", n, dur, (n as f64) / dur.as_secs_f64());
    Ok(())
}

fn bench_verify(path: &PathBuf) -> Result<(), String> {
    let start = Instant::now();
    let store = FileEventStore::open(path).map_err(|e| format!("open: {:?}", e))?;
    // iter() performs chain verification
    let evs = store.iter().map_err(|e| format!("iter: {:?}", e))?;
    let dur = start.elapsed();
    println!("verify: {} events verified in {:?} => {:.2} ev/sec", evs.len(), dur, (evs.len() as f64) / dur.as_secs_f64());
    Ok(())
}

fn bench_identity_reduce(path: &PathBuf) -> Result<(), String> {
    let start = Instant::now();
    let _state = load_identity_state_from_event_log(path.to_str().ok_or("bad path")?)
        .map_err(|e| format!("reduce: {}", e))?;
    let dur = start.elapsed();
    println!("identity reduce: completed in {:?}", dur);
    Ok(())
}

fn bench_auth_latency() -> Result<(), String> {
    // Test signing and verification latency using Keystore
    let tmp_dir = std::env::temp_dir().join("sentinel_bench_keystore");
    let _ = create_dir_all(&tmp_dir);
    let keyfile = tmp_dir.join("bench_key.bin");
    let ks = Keystore::load_or_create(keyfile).map_err(|e| format!("keystore: {}", e))?;
    // prepare envelope
    let actor = sentinel_identity::ActorId(Uuid::new_v4());
    let nonce = Uuid::new_v4();
    let ts = Utc::now();
    let payload = json!({"op": "auth_test"});

    let runs = 1000usize;
    let start = Instant::now();
    for _ in 0..runs {
        let _sig = ks.sign(&payload, &actor, &nonce, &ts).map_err(|e| format!("sign: {}", e))?;
    }
    let sign_dur = start.elapsed();
    println!("sign: {} runs in {:?} => {:.2} ops/sec", runs, sign_dur, (runs as f64) / sign_dur.as_secs_f64());

    // verify: construct a SignedEnvelope and verify
    let sig = ks.sign(&payload, &actor, &nonce, &ts).map_err(|e| format!("sign2: {}", e))?;
    let envelope = SignedEnvelope {
        actor_id: actor.clone(),
        key_id: ks.key_id.clone(),
        nonce,
        timestamp_utc: ts,
        payload: payload.clone(),
        signature: sig,
    };
    // public key
    let pk = ks.public_key();
    let start2 = Instant::now();
    for _ in 0..runs {
        sentinel_identity::verify_signature(&envelope, &pk).map_err(|e| format!("verify: {}", e))?;
    }
    let verify_dur = start2.elapsed();
    println!("verify: {} runs in {:?} => {:.2} ops/sec", runs, verify_dur, (runs as f64) / verify_dur.as_secs_f64());
    Ok(())
}

fn main() -> Result<(), String> {
    // defaults
    let sizes = vec![10_000usize, 100_000usize];
    let data_dir = PathBuf::from("target/bench_data");
    let _ = create_dir_all(&data_dir);
    for &n in &sizes {
        let path = data_dir.join(format!("events_{}.log", n));
        println!("--- Running benchmarks for {} events (file: {:?}) ---", n, path);
        bench_append(&path, n)?;
        bench_verify(&path)?;
        bench_identity_reduce(&path)?;
        println!("--- auth latency ---");
        bench_auth_latency()?;
        println!("--- Completed run for {} events ---\n", n);
    }
    println!("Benchmarks complete. Results printed above.");
    Ok(())
}
