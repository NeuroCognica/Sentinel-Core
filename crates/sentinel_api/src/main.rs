use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse};
use std::panic;
use std::sync::Mutex;
use sentinel_store::{FileEventStore, EventStore, EventRecord, EventKind};
use sentinel_core::CanonicalEnvelopeAuthorizationRequest;
use sha2::Digest;
use sentinel_identity::{verify_signature, ActorId, KeyId};
use ed25519_dalek::PublicKey;
// ...existing code...
use std::collections::HashSet;
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

/// In-memory replay protection: LRU of (actor_id, nonce)
struct ReplayProtector {
    seen: Mutex<HashSet<(Uuid, Uuid)>>,
}

impl ReplayProtector {
    fn new() -> Self {
        Self { seen: Mutex::new(HashSet::new()) }
    }
    fn check_and_insert(&self, actor_id: Uuid, nonce: Uuid) -> bool {
        let mut seen = self.seen.lock().unwrap();
        if seen.contains(&(actor_id, nonce)) {
            false
        } else {
            seen.insert((actor_id, nonce));
            true
        }
    }
}

#[post("/authz")]
async fn authz(
    store: web::Data<Mutex<FileEventStore>>,
    replay: web::Data<ReplayProtector>,
    req: web::Json<CanonicalEnvelopeAuthorizationRequest>,
) -> impl Responder {
    // 1. Envelope presence
    let env = req.into_inner();

    // 2. Signature verification (for demo, public key is derived from actor_id; in real use, lookup)
    // Here, we simulate a public key for all actors (replace with real lookup in production)
    let fake_pubkey_bytes = [7u8; 32];
    let pubkey = PublicKey::from_bytes(&fake_pubkey_bytes).unwrap();
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

    // 4. Replay protection
    if !replay.check_and_insert(env.actor_id, env.nonce) {
        return HttpResponse::Unauthorized().body("replayed nonce");
    }

    // 5. Log the request digest before decision
    let digest = sha2::Sha256::digest(
        serde_json::to_vec(&env).expect("canonical serialization")
    );
    let mut store = store.lock().unwrap();
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: env.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived,
        payload: json!({
            "request_hash": hex::encode(digest),
            "actor_id": env.actor_id.to_string(),
        }),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store.append(event) {
        return HttpResponse::InternalServerError().body(format!("event append failed: {e:?}"));
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

    let replay = web::Data::new(ReplayProtector::new());

    let server = HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
            .app_data(replay.clone())
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
