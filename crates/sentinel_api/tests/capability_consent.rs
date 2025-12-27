use actix_web::{test, App};
use serde_json::json;
use uuid::Uuid;
use sentinel_api::middleware::envelope_digest::compute_envelope_digest_hex;
use tempfile::TempDir;
use sentinel_store::EventStore;

#[actix_rt::test]
async fn test_capability_allow_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::capability_issue),
    )
    .await;

    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000001", "subject": "00000000-0000-0000-0000-000000000002", "scope": "session", "actions": ["whoami"] });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    let mut found_cap = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentGranted => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            sentinel_store::EventKind::CapabilityIssued => found_cap = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(found_effect);
    assert!(found_cap);
}

#[actix_rt::test]
async fn test_capability_deny_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::capability_issue),
    )
    .await;

    let policy = json!({
        "id": "deny_cap",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "capability_issue" }], "effect": "Deny", "rationale": "deny cap" }
        ]
    });

    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000010", "subject": "00000000-0000-0000-0000-000000000011", "scope": "session", "actions": ["whoami"], "policy": policy });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_effect = false;
    let mut found_cap = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentDenied => found_consent = true,
            sentinel_store::EventKind::EffectExecuted => found_effect = true,
            sentinel_store::EventKind::CapabilityIssued => found_cap = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(!found_effect);
    assert!(!found_cap);
}

#[actix_rt::test]
async fn test_capability_append_failure_aborts() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::capability_issue),
    )
    .await;

    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000020", "subject": "00000000-0000-0000-0000-000000000021", "scope": "session", "actions": ["whoami"], "simulate_append_failure": true });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());

    // Ensure no capability or effect recorded
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::EffectExecuted)));
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::CapabilityIssued)));
}
