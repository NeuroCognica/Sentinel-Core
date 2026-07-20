use actix_web::{test, App};
use chrono::Utc;
use sentinel_api::middleware::envelope_digest::compute_envelope_digest_hex;
use sentinel_store::EventStore;
use serde_json::{json, Value};
use tempfile::TempDir;
use uuid::Uuid;

fn guard_request(action: &str, nonce: &str) -> Value {
    json!({
        "envelope_version": "sentinel.guard.v1",
        "action": action,
        "resource": "workspace://chronos/protected",
        "actor_id": Uuid::new_v4(),
        "actor_class": "chronosophia.runtime",
        "subject_system": "chronosophia",
        "request_origin": "handler-test",
        "timestamp_utc": Utc::now(),
        "nonce": nonce,
        "payload_hash": "sha256:payload",
        "context_digest": "sha256:context",
        "requested_capability": "capability:test",
        "consent_reference": null,
        "declared_intent": "handler-level guard authorization test",
        "irreversible_side_effect": false,
        "external_impact": false,
        "envelope_digest": "bound-by-middleware"
    })
}

fn envelope_for(inner: Value, nonce: &str) -> Value {
    let digest = compute_envelope_digest_hex("POST", "/guard/authorize", nonce, &inner);
    json!({
        "nonce": nonce,
        "digest": digest,
        "body": inner
    })
}

#[actix_rt::test]
async fn deny_all_guard_returns_403_ledgers_decision_and_spawns_no_effect() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::guard_authorize),
    )
    .await;

    let nonce = Uuid::new_v4().to_string();
    let inner = json!({
        "policy": {
            "policy_id": "constitutional-deny-all",
            "policy_version": "test",
            "mode": "DenyAll",
            "rules": []
        },
        "request": guard_request("process.spawn", &nonce)
    });
    let envelope = envelope_for(inner, &nonce);

    let req = test::TestRequest::post()
        .uri("/guard/authorize")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body.get("class").and_then(|v| v.as_str()), Some("Deny"));
    assert_eq!(body.get("allowed").and_then(|v| v.as_bool()), Some(false));
    assert!(body
        .get("ledger_event_hash")
        .and_then(|v| v.as_str())
        .is_some());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(events
        .iter()
        .any(|r| matches!(r.kind, sentinel_store::EventKind::SentinelGuardDecision)));
    assert!(!events
        .iter()
        .any(|r| matches!(r.kind, sentinel_store::EventKind::EffectExecuted)));
}

#[actix_rt::test]
async fn explicit_allow_returns_hash_chained_authorization() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::guard_authorize),
    )
    .await;

    let nonce = Uuid::new_v4().to_string();
    let inner = json!({
        "policy": {
            "policy_id": "chronos-test-policy",
            "policy_version": "test",
            "mode": "ExplicitRules",
            "rules": [{
                "rule_id": "allow-effect-execute",
                "action": "effect.execute",
                "resource": "workspace://chronos/protected",
                "actor_class": "chronosophia.runtime",
                "subject_system": "chronosophia",
                "decision": "Allow",
                "rationale": "handler test exact allow"
            }]
        },
        "request": guard_request("effect.execute", &nonce)
    });
    let envelope = envelope_for(inner, &nonce);

    let req = test::TestRequest::post()
        .uri("/guard/authorize")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body.get("class").and_then(|v| v.as_str()), Some("Allow"));
    assert_eq!(body.get("allowed").and_then(|v| v.as_bool()), Some(true));
    assert!(body
        .get("ledger_event_hash")
        .and_then(|v| v.as_str())
        .is_some());
}

#[actix_rt::test]
async fn nonce_mismatch_locks_down_and_ledgers_denial() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::guard_authorize),
    )
    .await;

    let outer_nonce = Uuid::new_v4().to_string();
    let request_nonce = Uuid::new_v4().to_string();
    let inner = json!({
        "policy": {
            "policy_id": "chronos-test-policy",
            "policy_version": "test",
            "mode": "ExplicitRules",
            "rules": [{
                "rule_id": "allow-effect-execute",
                "action": "effect.execute",
                "resource": "workspace://chronos/protected",
                "actor_class": "chronosophia.runtime",
                "subject_system": "chronosophia",
                "decision": "Allow",
                "rationale": "handler test exact allow"
            }]
        },
        "request": guard_request("effect.execute", &request_nonce)
    });
    let envelope = envelope_for(inner, &outer_nonce);

    let req = test::TestRequest::post()
        .uri("/guard/authorize")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body.get("class").and_then(|v| v.as_str()), Some("Lockdown"));
    assert_eq!(body.get("allowed").and_then(|v| v.as_bool()), Some(false));

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(events
        .iter()
        .any(|r| matches!(r.kind, sentinel_store::EventKind::SentinelGuardDecision)));
}
