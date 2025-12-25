use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse};
use std::panic;
use std::sync::Mutex;
use sentinel_store::{FileEventStore, EventStore, EventRecord, EventKind};
use sentinel_core::CanonicalEnvelopeAuthorizationRequest;
use sha2::Digest;
use sentinel_identity::{verify_signature, ActorId, KeyId, load_identity_state_from_event_log, IdentityState};
use ed25519_dalek::PublicKey;
// ...existing code...
// ...existing code...
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;


#[get("/health")]
async fn health(store: web::Data<Mutex<FileEventStore>>) -> impl Responder {
    let mut store = store.lock().unwrap();
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: "system".to_string(),
        kind: EventKind::HealthCheck,
        payload: json!({}),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    match store.append(event) {
        Ok(_) => HttpResponse::Ok().body("ok"),
        Err(e) => HttpResponse::InternalServerError().body(format!("event append failed: {e:?}")),
    }
}



#[post("/authz")]
async fn authz(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<CanonicalEnvelopeAuthorizationRequest>,
) -> impl Responder {
    // 1. Envelope presence
    let env = req.into_inner();

    // 2. Signature verification (event-sourced, constitutional)
    let identity_state = match load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    let key_info = identity_state.keys.get(&(env.actor_id, env.key_id));
    if key_info.is_none() || key_info.unwrap().status != sentinel_identity::KeyStatus::Active {
        return HttpResponse::Unauthorized().body("unknown or revoked key");
    }
    let pubkey_bytes = &key_info.unwrap().public_key;
    let pubkey = match PublicKey::from_bytes(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("invalid public key bytes"),
    };
    let sig_result = verify_signature(
        &sentinel_identity::SignedEnvelope {
            actor_id: ActorId(env.actor_id),
            key_id: KeyId(env.key_id),
            nonce: env.nonce,
            timestamp_utc: env.timestamp_utc,
            payload: env.payload.clone(),
            signature: sentinel_identity::SignatureBytes {
                algorithm: sentinel_identity::SignatureAlgorithm::Ed25519,
                bytes: env.signature.clone(),
            },
        },
        &pubkey,
    );
    if sig_result.is_err() {
        return HttpResponse::Unauthorized().body("invalid signature");
    }

    // 3. Timestamp freshness (±300s)
    let now = Utc::now();
    let diff = (now.timestamp() - env.timestamp_utc.timestamp()).abs();
    if diff > 300 {
        return HttpResponse::Unauthorized().body("timestamp outside freshness window");
    }


    // 4. Replay protection (event-sourced)
    let identity_state = match load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    if identity_state.used_nonces.iter().any(|(aid, _, n, _)| *aid == env.actor_id && *n == env.nonce) {
        return HttpResponse::Unauthorized().body("replayed nonce (event-sourced)");
    }

    // 5. Log the request digest before decision
    let digest = sha2::Sha256::digest(
        serde_json::to_vec(&env).expect("canonical serialization")
    );
    let digest_hex = hex::encode(digest);
    let mut store = store.lock().unwrap();

    // 5. Log the request digest before decision
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: env.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived,
        payload: json!({
            "request_hash": digest_hex.clone(),
            "actor_id": env.actor_id.to_string(),
        }),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store.append(event) {
        return HttpResponse::InternalServerError().body(format!("event append failed: {e:?}"));
    }

    // 6. Append NonceConsumed event
    let nonce_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: env.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived, // Optionally define a new EventKind for NonceConsumed
        payload: json!(
            serde_json::to_value(sentinel_core::IdentityEvent::NonceConsumed(
                sentinel_core::NonceConsumed {
                    actor_id: env.actor_id,
                    key_id: env.key_id,
                    nonce: env.nonce,
                    envelope_digest: digest_hex.clone(),
                    consumed_at: Utc::now(),
                }
            )).expect("nonce event serialization")
        ),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store.append(nonce_event) {
        return HttpResponse::InternalServerError().body(format!("nonce event append failed: {e:?}"));
    }

    // 6. Deterministic response
    HttpResponse::Ok().json(json!({"result": "accepted"}))
}

#[actix_web::main]
async fn main() {
    // Set a panic hook to log any panics
    panic::set_hook(Box::new(|info| {
        eprintln!("FATAL: panic occurred: {info}");
    }));

    println!("sentinel_api booting");
    let store = match FileEventStore::open("./sentinel_events.log") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: could not open event log: {e:?}");
            std::process::exit(1);
        }
    };
    let store = web::Data::new(Mutex::new(store));


    let server = HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
            .service(health)
            .service(authz)
    })
    .bind(("127.0.0.1", 8080));

    let server = match server {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: failed to bind 127.0.0.1:8080: {e}");
            std::process::exit(1);
        }
    };

    println!("sentinel_api listening on 127.0.0.1:8080");
    if let Err(e) = server.run().await {
        eprintln!("FATAL: server crashed: {e}");
        std::process::exit(1);
    }
}
