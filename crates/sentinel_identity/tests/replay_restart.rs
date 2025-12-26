use std::sync::Mutex;
use std::fs::{self, File};
use std::path::PathBuf;
use chrono::Utc;
use uuid::Uuid;

use sentinel_store::{FileEventStore, EventRecord, EventKind, EventStore};
use sentinel_core::{ActorRegistered, KeyRegistered, IdentityEvent, CanonicalEnvelopeAuthorizationRequest, AuthorizationRequest};

/// Helper to build event records
fn make_event(actor: &Uuid, kind: EventKind, payload: serde_json::Value) -> EventRecord {
    EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: actor.to_string(),
        kind,
        payload,
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    }
}

#[test]
fn replay_across_restart_is_denied_and_no_append_on_replay() {
    // Temp path
    let mut path = std::env::temp_dir();
    path.push(format!("sentinel_events_{}.log", Uuid::new_v4()));

    // Instance A: setup and consume nonce via canonical middleware
    {
        let mut store = FileEventStore::open(&path).expect("open store A");

        let actor_id = Uuid::new_v4();
        let key_id = Uuid::new_v4();

        // append actor and key
        let actor_event = make_event(&actor_id, EventKind::Identity, serde_json::to_value(IdentityEvent::ActorRegistered(ActorRegistered {
            actor_id,
            human_handle: None,
            timestamp_utc: Utc::now(),
        })).unwrap());
        store.append(actor_event).expect("append actor");

        let key_event = make_event(&actor_id, EventKind::Identity, serde_json::to_value(IdentityEvent::KeyRegistered(KeyRegistered {
            actor_id,
            key_id,
            public_key: vec![1,2,3],
            timestamp_utc: Utc::now(),
        })).unwrap());
        store.append(key_event).expect("append key");

        // Build envelope and call canonical middleware to append NonceConsumed
        let envelope = CanonicalEnvelopeAuthorizationRequest {
            actor_id,
            key_id,
            nonce: Uuid::new_v4(),
            timestamp_utc: Utc::now(),
            payload: AuthorizationRequest { action: "test".to_string(), scope: "x".to_string(), intent: "y".to_string() },
            signature: vec![],
        };

        // Use the middleware to append (simulate request)
        let store_mutex = Mutex::new(FileEventStore::open(&path).expect("open store mutex"));
        let res = sentinel_api::middleware::nonce_middleware::check_and_append_nonce(&store_mutex, &envelope);
        assert!(res.is_ok(), "initial nonce append should succeed");

        // ensure NonceConsumed exists (stored as Identity::NonceConsumed)
        let events = store_mutex.lock().unwrap().iter().expect("iter");
        let found = events.iter().any(|rec| {
            if let EventKind::Identity = rec.kind {
                if let Ok(v) = serde_json::from_value::<IdentityEvent>(rec.payload.clone()) {
                    if let IdentityEvent::NonceConsumed(_) = v {
                        return true;
                    }
                }
            }
            false
        });
        assert!(found, "nonce consumed missing in initial append");
    }

    // Instance B: fresh process, rebuild registry from ledger and reject same nonce
    {
        let store_b = FileEventStore::open(&path).expect("open store B");
        let before = store_b.iter().expect("iter before");
        let count_before = before.len();

        let store_b_mutex = Mutex::new(FileEventStore::open(&path).expect("open store B mutex"));

        // Recreate envelope with same nonce as before by reading the NonceConsumed event
        let events = store_b_mutex.lock().unwrap().iter().expect("iter2");
        let maybe_nonce = events.iter().find_map(|rec| {
            if let EventKind::Identity = rec.kind {
                // try to parse payload to extract nonce
                if let Ok(v) = serde_json::from_value::<IdentityEvent>(rec.payload.clone()) {
                    if let IdentityEvent::NonceConsumed(nc) = v {
                        return Some((nc.actor_id, nc.key_id, nc.nonce));
                    }
                }
            }
            None
        });
        assert!(maybe_nonce.is_some(), "nonce consumed missing");
        let (actor_id, key_id, nonce) = maybe_nonce.unwrap();

        let envelope_b = CanonicalEnvelopeAuthorizationRequest {
            actor_id,
            key_id,
            nonce,
            timestamp_utc: Utc::now(),
            payload: AuthorizationRequest { action: "test".to_string(), scope: "x".to_string(), intent: "y".to_string() },
            signature: vec![],
        };

        // Attempt to consume same nonce again
        let res = sentinel_api::middleware::nonce_middleware::check_and_append_nonce(&store_b_mutex, &envelope_b);
        assert!(res.is_err(), "replay must be denied");

        // Ensure no new events appended (ledger length unchanged)
        let after = store_b_mutex.lock().unwrap().iter().expect("iter after");
        assert_eq!(count_before, after.len(), "ledger must not grow on replay attempt");
    }

    // cleanup
    let _ = fs::remove_file(path);
}

#[test]
fn append_failure_aborts_request_and_no_partial_success() {
    // create temp path and a read-only file to cause append failure
    let mut path = std::env::temp_dir();
    path.push(format!("sentinel_events_ro_{}.log", Uuid::new_v4()));

    // create empty file
    File::create(&path).expect("create file");
    // Open the store first, then make the underlying file read-only so
    // subsequent append attempts fail on open/append (Windows semantics).
    let store = FileEventStore::open(&path).expect("open ro store");
    // make it read-only
    let mut perms = fs::metadata(&path).expect("meta").permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms).expect("set perms");
    let store_mutex = Mutex::new(store);

    // prepare envelope
    let envelope = CanonicalEnvelopeAuthorizationRequest {
        actor_id: Uuid::new_v4(),
        key_id: Uuid::new_v4(),
        nonce: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        payload: AuthorizationRequest { action: "x".to_string(), scope: "x".to_string(), intent: "x".to_string() },
        signature: vec![],
    };

    let res = sentinel_api::middleware::nonce_middleware::check_and_append_nonce(&store_mutex, &envelope);
    assert!(res.is_err(), "append should fail on read-only ledger");

    // ledger must remain empty (or unchanged)
    let events = store_mutex.lock().unwrap().iter().expect("iter ro");
    assert!(events.is_empty(), "no events must be appended on append failure");

    // cleanup: make file writable then remove
    let mut perms = fs::metadata(&path).expect("meta2").permissions();
    perms.set_readonly(false);
    fs::set_permissions(&path, perms).ok();
    let _ = fs::remove_file(path);
}
