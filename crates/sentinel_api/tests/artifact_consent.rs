use actix_web::{test, App};
use serde_json::json;
use tempfile::TempDir;
use sentinel_store::EventStore;

#[actix_rt::test]
async fn test_artifact_allow_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&json!({ "artifact_digest": "deadbeef", "artifact_type": "executable", "subject": "actor-1" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_art = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentGranted => found_consent = true,
            sentinel_store::EventKind::ArtifactRegistered => found_art = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(found_art);
}

#[actix_rt::test]
async fn test_artifact_deny_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register),
    )
    .await;

    let policy = json!({
        "id": "deny_art",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "artifact_register" }], "effect": "Deny", "rationale": "deny art" }
        ]
    });

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&json!({ "artifact_digest": "deadbeef", "artifact_type": "executable", "subject": "actor-2", "policy": policy }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    let mut found_pe = false;
    let mut found_consent = false;
    let mut found_art = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentDenied => found_consent = true,
            sentinel_store::EventKind::ArtifactRegistered => found_art = true,
            _ => {}
        }
    }
    assert!(found_pe);
    assert!(found_consent);
    assert!(!found_art);
}

#[actix_rt::test]
async fn test_artifact_append_failure_aborts() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&json!({ "artifact_digest": "deadbeef", "artifact_type": "executable", "subject": "actor-3", "simulate_append_failure": true }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());

    // Ensure no artifact or effect recorded
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    assert!(!events.iter().any(|r| matches!(r.kind, sentinel_store::EventKind::ArtifactRegistered)));
}

#[actix_rt::test]
async fn test_artifact_idempotence() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::artifact_register),
    )
    .await;

    let req1 = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&json!({ "artifact_digest": "deadbeef", "artifact_type": "executable", "subject": "actor-4" }))
        .to_request();
    let resp1 = test::call_service(&app, req1).await;
    assert!(resp1.status().is_success());
    let body1: serde_json::Value = test::read_body_json(resp1).await;

    let req2 = test::TestRequest::post()
        .uri("/artifacts/register")
        .set_json(&json!({ "artifact_digest": "deadbeef", "artifact_type": "executable", "subject": "actor-4" }))
        .to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert!(resp2.status().is_success());
    let body2: serde_json::Value = test::read_body_json(resp2).await;

    assert_eq!(body1["artifact_id"], body2["artifact_id"]);
}
