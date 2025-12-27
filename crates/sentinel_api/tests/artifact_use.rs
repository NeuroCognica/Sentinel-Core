use actix_web::{test, App};
use serde_json::json;
use uuid::Uuid;
use sentinel_api::middleware::envelope_digest::compute_envelope_digest_hex;
use tempfile::TempDir;
use sentinel_store::EventStore;
use sentinel_artifacts::ArtifactEvent;

#[actix_rt::test]
async fn artifact_use_allow_emits_codex_seal() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register)
            .service(sentinel_api::capability_issue)
            .service(sentinel_api::artifact_use),
    )
    .await;

    // register artifact
    let inner = json!({ "artifact_digest": "ad:deadbeef", "artifact_type": "executable", "subject": "actor-1" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/register", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // issue capability bound to artifact
    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000001", "subject": "actor-1", "scope": "session", "actions": ["use"], "allowed_artifact_digests": ["ad:deadbeef"] });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cap: serde_json::Value = test::read_body_json(resp).await;
    let cap_id = cap.get("capability_id").and_then(|v| v.as_str()).expect("cap id");

    // call artifact_use
    let inner = json!({ "capability_id": cap_id, "artifact_digest": "ad:deadbeef", "subject": "actor-1" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/use", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/use")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // inspect ledger for CapabilityConsumed and CodexSealCreated
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_consumed = false;
    let mut found_seal = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::CapabilityConsumed => found_consumed = true,
            sentinel_store::EventKind::CodexSealCreated => {
                found_seal = true;
                if let Ok(ae) = serde_json::from_value::<ArtifactEvent>(rec.payload.clone()) {
                    if let ArtifactEvent::CodexSealCreated { seal } = ae {
                        assert_eq!(seal.artifact_digest, "ad:deadbeef");
                        assert_eq!(seal.actor_id, "actor-1");
                    }
                }
            }
            _ => {}
        }
    }
    assert!(found_consumed);
    assert!(found_seal);
}

#[actix_rt::test]
async fn artifact_use_denied_without_artifact_binding() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register)
            .service(sentinel_api::capability_issue)
            .service(sentinel_api::artifact_use),
    )
    .await;

    // register artifact
    let inner = json!({ "artifact_digest": "ad:beefdead", "artifact_type": "executable", "subject": "actor-2" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/register", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // issue capability WITHOUT binding
    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000010", "subject": "actor-2", "scope": "session", "actions": ["use"] });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cap: serde_json::Value = test::read_body_json(resp).await;
    let cap_id = cap.get("capability_id").and_then(|v| v.as_str()).expect("cap id");

    // attempt artifact_use
    let inner = json!({ "capability_id": cap_id, "artifact_digest": "ad:beefdead", "subject": "actor-2" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/use", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/use")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::CodexSealCreated)));
}

#[actix_rt::test]
async fn artifact_use_missing_digest_fails_closed() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_use)
            .service(sentinel_api::capability_issue),
    )
    .await;

    // issue a capability directly (we don't need binding)
    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000020", "subject": "actor-3", "scope": "session", "actions": ["use"] });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cap: serde_json::Value = test::read_body_json(resp).await;
    let cap_id = cap.get("capability_id").and_then(|v| v.as_str()).expect("cap id");

    // call artifact_use without artifact_digest
    let inner = json!({ "capability_id": cap_id, "subject": "actor-3" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/use", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/use")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::CodexSealCreated)));
}

#[actix_rt::test]
async fn artifact_use_append_failure_fails_closed() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register)
            .service(sentinel_api::capability_issue)
            .service(sentinel_api::artifact_use),
    )
    .await;

    // register artifact
    let inner = json!({ "artifact_digest": "ad:deadbeef2", "artifact_type": "executable", "subject": "actor-4" });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/register", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // issue capability bound to artifact
    let inner = json!({ "issuer": "00000000-0000-0000-0000-000000000030", "subject": "actor-4", "scope": "session", "actions": ["use"], "allowed_artifact_digests": ["ad:deadbeef2"] });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/capabilities/issue", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cap: serde_json::Value = test::read_body_json(resp).await;
    let cap_id = cap.get("capability_id").and_then(|v| v.as_str()).expect("cap id");

    // call artifact_use with simulate_append_failure
    let inner = json!({ "capability_id": cap_id, "artifact_digest": "ad:deadbeef2", "subject": "actor-4", "simulate_append_failure": true });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/artifacts/use", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/artifacts/use")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::CodexSealCreated)));
}
