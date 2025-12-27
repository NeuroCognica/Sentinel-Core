use actix_web::{test, App};
use serde_json::json;
use tempfile::TempDir;
use sentinel_store::EventStore;

// Adversarial seal test: exercise effectful handlers and ensure every EffectExecuted
// has a prior PolicyEvaluated (Allow) and a ConsentGranted with matching digests.
#[actix_rt::test]
async fn test_phase4_effects_have_consent_and_evaluation() {
    let tmpdir = TempDir::new().expect("tempdir");
    let log_path = tmpdir.path().join("sentinel_events.log");
    let store = sentinel_store::FileEventStore::open(&log_path).expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::genesis)
            .service(sentinel_api::capability_issue)
            .service(sentinel_api::privileged_action)
            .service(sentinel_api::policy_evaluate),
    )
    .await;

    // 1) Genesis (allow)
    let pk = hex::encode(vec![3u8; 32]);
    let req = test::TestRequest::post()
        .uri("/genesis")
        .set_json(&json!({ "actor_id": "00000000-0000-0000-0000-000000000101", "key_id": "00000000-0000-0000-0000-000000000102", "public_key": pk }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // 2) Capability issue (allow)
    let req = test::TestRequest::post()
        .uri("/capabilities/issue")
        .set_json(&json!({ "issuer": "00000000-0000-0000-0000-000000000201", "subject": "00000000-0000-0000-0000-000000000202", "scope": "session", "actions": ["whoami"] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // 3) Privileged action (allow)
    let policy = json!({
        "id": "p-allow-do",
        "version": "v0",
        "statements": [ { "when": [{ "field": "action", "op": "Eq", "value": "do" }], "effect": "Allow", "rationale": "allow do" } ]
    });
    let input = json!({ "subject": "alice", "action": "do", "resource": "r", "context": {} });
    let req = test::TestRequest::post()
        .uri("/privileged/action")
        .set_json(&json!({ "policy": policy, "input": input }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Now inspect the ledger and verify ordering: for each EffectExecuted, a prior PolicyEvaluated (Allow)
    // and a prior ConsentGranted must exist with matching policy_digest/input_digest.
    let s = store_data.lock().unwrap();
    let events = s.iter().expect("iter");

    // Collect consent granted digests and policy evaluated map
    let mut consent_granted = std::collections::HashSet::<(String,String)>::new();
    let mut policy_allows = std::collections::HashSet::<(String,String)>::new();

    for rec in events.iter() {
        match rec.kind {
            sentinel_store::EventKind::PolicyEvaluated => {
                if let Ok(pe) = serde_json::from_value::<sentinel_policy::event::PolicyEvaluated>(rec.payload.clone()) {
                    if matches!(pe.decision, sentinel_policy::event::Decision::Allow) {
                        policy_allows.insert((pe.policy_digest.clone(), pe.input_digest.clone()));
                    }
                }
            }
            sentinel_store::EventKind::ConsentGranted => {
                if let Ok(ce) = serde_json::from_value::<sentinel_policy::event::ConsentEvent>(rec.payload.clone()) {
                    consent_granted.insert((ce.policy_digest.clone(), ce.input_digest.clone()));
                }
            }
            sentinel_store::EventKind::EffectExecuted => {
                // parse effect payload for digests
                if let Some(pd) = rec.payload.get("policy_digest").and_then(|v| v.as_str()) {
                    if let Some(id) = rec.payload.get("input_digest").and_then(|v| v.as_str()) {
                        let key = (pd.to_string(), id.to_string());
                        assert!(policy_allows.contains(&key), "EffectExecuted without prior PolicyEvaluated Allow: {:?}", key);
                        assert!(consent_granted.contains(&key), "EffectExecuted without prior ConsentGranted: {:?}", key);
                    }
                }
            }
            _ => {}
        }
    }
}
