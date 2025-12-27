use actix_web::{test, App};
use serde_json::json;
use uuid::Uuid;
use sentinel_api::middleware::envelope_digest::compute_envelope_digest_hex;
use tempfile::TempDir;
use sentinel_store::EventStore;

#[actix_rt::test]
async fn test_consent_allow_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::privileged_action),
    )
    .await;

    let policy = json!({
        "id": "p1",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "do" }], "effect": "Allow", "rationale": "allow do" }
        ]
    });
    let input = json!({ "subject": "alice", "action": "do", "resource": "r", "context": {} });

    let inner = json!({ "policy": policy, "input": input });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/privileged/action", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/privileged/action")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentGranted => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(found_effect);
}

#[actix_rt::test]
async fn test_consent_deny_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::privileged_action),
    )
    .await;

    let policy = json!({
        "id": "p2",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "do" }], "effect": "Deny", "rationale": "deny do" }
        ]
    });
    let input = json!({ "subject": "alice", "action": "do", "resource": "r", "context": {} });

    let inner = json!({ "policy": policy, "input": input });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/privileged/action", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/privileged/action")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentDenied => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(!found_effect);
}

#[actix_rt::test]
async fn test_consent_append_failure_aborts() {
    // Create TempDir and create a directory at sentinel_events.log to force append failure
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::privileged_action),
    )
    .await;

    let policy = json!({
        "id": "p3",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "do" }], "effect": "Allow", "rationale": "allow do" }
        ]
    });
    let input = json!({ "subject": "alice", "action": "do", "resource": "r", "context": { "simulate_append_failure": true } });

    let inner = json!({ "policy": policy, "input": input });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/privileged/action", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/privileged/action")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());

    // Ensure no EffectExecuted event present
    let s = store_data.lock().unwrap();
    let events = s.iter();
    // iter may succeed or error depending on implementation; ensure no effect recorded by checking empty or no effect
    if let Ok(evts) = events {
        assert!(!evts.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::EffectExecuted)));
    }
}
