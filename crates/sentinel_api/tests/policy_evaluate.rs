use actix_web::{test, App};
use serde_json::json;
use tempfile::TempDir;
use sentinel_store::EventStore;
use uuid::Uuid;
use sentinel_api::middleware::envelope_digest::compute_envelope_digest_hex;

#[actix_rt::test]
async fn test_policy_evaluate_golden_path() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .wrap(sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware)
            .app_data(store_data.clone())
            .service(sentinel_api::policy_evaluate),
    )
    .await;

    let policy = json!({
        "id": "p1",
        "version": "v0",
        "statements": [
            { "when": [{ "field": "action", "op": "Eq", "value": "read" }], "effect": "Allow", "rationale": "allow reads" }
        ]
    });
    let input = json!({ "subject": "alice", "action": "read", "resource": "r", "context": {} });
    let inner = json!({ "policy": policy, "input": input });
    let nonce = Uuid::new_v4().to_string();
    let digest = compute_envelope_digest_hex("POST", "/policy/evaluate", &nonce, &inner);
    let envelope = json!({ "nonce": nonce, "digest": digest, "body": inner });

    let req = test::TestRequest::post()
        .uri("/policy/evaluate")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!("unexpected response {status}: {}", std::str::from_utf8(&body).unwrap_or("<binary>"));
    }
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body.get("decision").and_then(|v| v.as_str()).unwrap(), "Allow");

    // Verify events appended to store
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");
    // Expect at least PolicyEvaluated and ConsentGranted
    let mut found_pe = false;
    let mut found_consent = false;
    for rec in events {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => found_pe = true,
            sentinel_store::EventKind::ConsentGranted => found_consent = true,
            _ => {}
        }
    }
    assert!(found_pe, "PolicyEvaluated event missing");
    assert!(found_consent, "ConsentGranted event missing");
}
