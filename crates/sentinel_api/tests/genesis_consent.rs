use actix_web::{test, App};
use serde_json::json;
use tempfile::TempDir;
use sentinel_store::EventStore;

#[actix_rt::test]
async fn test_genesis_allow_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::genesis),
    )
    .await;

    let pk = hex::encode(vec![0u8; 32]);
    let req = test::TestRequest::post()
        .uri("/genesis")
        .set_json(&json!({ "actor_id": "00000000-0000-0000-0000-000000000001", "key_id": "00000000-0000-0000-0000-000000000002", "public_key": pk }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    let mut found_genesis = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentGranted => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            sentinel_store::EventKind::Identity => {
                if let Ok(ev) = serde_json::from_value::<sentinel_core::IdentityEvent>(rec.payload.clone()) {
                    if let sentinel_core::IdentityEvent::GenesisCompleted(_) = ev {
                        found_genesis = true;
                    }
                }
            }
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(found_effect);
    assert!(found_genesis);
}

#[actix_rt::test]
async fn test_genesis_deny_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::genesis),
    )
    .await;

    let policy = json!({
        "id": "deny_genesis",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "genesis" }], "effect": "Deny", "rationale": "deny genesis" }
        ]
    });

    let pk = hex::encode(vec![1u8; 32]);
    let req = test::TestRequest::post()
        .uri("/genesis")
        .set_json(&json!({ "actor_id": "00000000-0000-0000-0000-000000000010", "key_id": "00000000-0000-0000-0000-000000000011", "public_key": pk, "policy": policy }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    let mut found_genesis = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentDenied => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            sentinel_store::EventKind::Identity => {
                if let Ok(ev) = serde_json::from_value::<sentinel_core::IdentityEvent>(rec.payload.clone()) {
                    if let sentinel_core::IdentityEvent::GenesisCompleted(_) = ev {
                        found_genesis = true;
                    }
                }
            }
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(!found_effect);
    assert!(!found_genesis);
}

#[actix_rt::test]
async fn test_genesis_append_failure_aborts() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::genesis),
    )
    .await;

    let pk = hex::encode(vec![2u8; 32]);
    let req = test::TestRequest::post()
        .uri("/genesis")
        .set_json(&json!({ "actor_id": "00000000-0000-0000-0000-000000000020", "key_id": "00000000-0000-0000-0000-000000000021", "public_key": pk, "simulate_append_failure": true }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());

    // Ensure no genesis identity or effect recorded
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::EffectExecuted)));
    assert!(!events.iter().any(|r| {
        if let sentinel_store::EventKind::Identity = r.kind {
            if let Ok(ev) = serde_json::from_value::<sentinel_core::IdentityEvent>(r.payload.clone()) {
                return matches!(ev, sentinel_core::IdentityEvent::GenesisCompleted(_));
            }
        }
        false
    }));
}
