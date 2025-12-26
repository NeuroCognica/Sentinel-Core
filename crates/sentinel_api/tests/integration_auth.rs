use actix_web::{test, App};
use serde_json::json;

#[actix_rt::test]
async fn test_challenge_login_happy_path() {
    // Ensure a clean event log
    let _ = std::fs::remove_file("./sentinel_events.log");

    // Create store and app data
    let store = sentinel_store::FileEventStore::open("./sentinel_events.log").expect("open store");
    let store_data = actix_web::web::Data::new(std::sync::Mutex::new(store));

    let app = test::init_service(
        App::new()
            .app_data(store_data.clone())
            .service(sentinel_api::health)
            .service(sentinel_api::genesis)
            .service(sentinel_api::auth_challenge)
            .service(sentinel_api::auth_login),
    )
    .await;

    // 1) Create deterministic actor keypair (no RNG) for test
    let seed = [42u8; 32];
    let secret = ed25519_dalek::SecretKey::from_bytes(&seed).expect("secret key");
    let public = ed25519_dalek::PublicKey::from(&secret);
    let kp = ed25519_dalek::Keypair { secret, public };
    let pub_hex = hex::encode(kp.public.to_bytes());
    let actor_id = uuid::Uuid::new_v4();
    let key_id = uuid::Uuid::new_v4();

    // 2) POST /genesis
    let req = test::TestRequest::post()
        .uri("/genesis")
        .set_json(&json!({
            "actor_id": actor_id.to_string(),
            "key_id": key_id.to_string(),
            "public_key": pub_hex,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    if !resp.status().is_success() {
        let body_bytes = test::read_body(resp).await;
        panic!("genesis failed: {}", String::from_utf8_lossy(&body_bytes));
    }

    // 3) POST /auth/challenge
    let req = test::TestRequest::post()
        .uri("/auth/challenge")
        .set_json(&json!({
            "actor_id": actor_id.to_string(),
            "key_id": key_id.to_string(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    if !resp.status().is_success() {
        let body_bytes = test::read_body(resp).await;
        panic!("challenge failed: {}", String::from_utf8_lossy(&body_bytes));
    }
    let body: serde_json::Value = test::read_body_json(resp).await;
    let challenge = body.get("challenge").and_then(|v| v.as_str()).unwrap().to_string();

    // 4) Build canonical envelope and sign
    let payload = sentinel_core::AuthorizationRequest {
        action: "login".to_string(),
        scope: "session".to_string(),
        intent: challenge.clone(),
    };
    let nonce = uuid::Uuid::new_v4();
    let timestamp = chrono::Utc::now();
    use sentinel_identity::{ActorId, KeyId};
    use ed25519_dalek::Signer;
    let data = serde_json::to_vec(&(ActorId(actor_id), KeyId(key_id), nonce, timestamp, &payload)).unwrap();
    let sig = kp.sign(&data);

    let envelope = sentinel_core::CanonicalEnvelopeAuthorizationRequest {
        actor_id,
        key_id,
        nonce,
        timestamp_utc: timestamp,
        payload,
        signature: sig.to_bytes().to_vec(),
    };

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&envelope)
        .to_request();
    let resp = test::call_service(&app, req).await;
    if !resp.status().is_success() {
        let body_bytes = test::read_body(resp).await;
        panic!("login failed: {}", String::from_utf8_lossy(&body_bytes));
    }
    let cap: sentinel_core::Capability = test::read_body_json(resp).await;
    assert_eq!(cap.actor_id, actor_id);
}
