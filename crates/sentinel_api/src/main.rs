#[post("/auth/logout")]
async fn auth_logout(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<Capability>,
) -> impl Responder {
    // 1. Verify capability signature (using issued_by/service key)
    let cap = req.into_inner();
    let keystore = match Keystore::load_or_create(PathBuf::from("./sentinel_service.key")) {
        Ok(ks) => ks,
        Err(e) => return HttpResponse::InternalServerError().body(format!("service key load failed: {e}")),
    };
    let sig_ok = keystore
        .public_key()
        .verify(
            &serde_json::to_vec(&Capability {
                token_signature: vec![],
                ..cap.clone()
            })
            .expect("canonical cap serialization"),
            &ed25519_dalek::Signature::from_bytes(&cap.token_signature).unwrap_or_default(),
        )
        .is_ok();
    if !sig_ok {
        return HttpResponse::Unauthorized().body("invalid capability signature");
    }
    // 2. Event-sourced capability state: must be present, active, unexpired
    let store_guard = store.lock().unwrap();
    let store_events = match store_guard.iter() {
        Ok(evts) => evts,
        Err(e) => return HttpResponse::InternalServerError().body(format!("event log read failed: {e:?}")),
    };
    let mut cap_events = Vec::new();
    for rec in store_events.iter() {
        if let Ok(ev) = serde_json::from_value::<sentinel_core::CapabilityEvent>(rec.payload.clone()) {
            cap_events.push(ev);
        }
    }
    let valid_actors = std::iter::once(cap.actor_id).collect();
    let cap_state = match CapabilityState::reduce(cap_events, &valid_actors) {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("capability state error: {e}")),
    };
    let now = Utc::now();
    let found = cap_state.active.get(&cap.capability_id);
    if found.is_none() {
        return HttpResponse::Unauthorized().body("capability not active");
    }
    if now > cap.expires_at_utc {
        return HttpResponse::Unauthorized().body("capability expired");
    }
    // 3. Log CapabilityRevoked event before response
    let mut store = store.lock().unwrap();
    let revoke_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: cap.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived, // Should be CapabilityRevoked, but using generic kind for now
        payload: json!(
            serde_json::to_value(sentinel_core::CapabilityEvent::CapabilityRevoked(
                sentinel_core::CapabilityRevoked {
                    capability_id: cap.capability_id,
                    revoked_at: now,
                    reason: Some("logout".to_string()),
                }
            )).expect("capability revoke event serialization")
        ),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store.append(revoke_event) {
        return HttpResponse::InternalServerError().body(format!("capability revoke event append failed: {e:?}"));
    }
    HttpResponse::Ok().json(json!({"result": "logout completed"}))
}
use sentinel_identity::Keystore;
use std::path::PathBuf;
#[post("/auth/login")]
async fn auth_login(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<sentinel_core::CanonicalEnvelopeAuthorizationRequest>,
) -> impl Responder {
    // 1. Envelope presence and signature verification (reuse logic from /authz)
    let env = req.into_inner();
    let identity_state = match sentinel_identity::load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    let key_info = identity_state.keys.get(&(env.actor_id, env.key_id));
    if key_info.is_none() || key_info.unwrap().status != sentinel_identity::KeyStatus::Active {
        return HttpResponse::Unauthorized().body("unknown or revoked key");
    }
    let pubkey_bytes = &key_info.unwrap().public_key;
    let pubkey = match ed25519_dalek::PublicKey::from_bytes(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("invalid public key bytes"),
    };
    let sig_result = sentinel_identity::verify_signature(
        &sentinel_identity::SignedEnvelope {
            actor_id: sentinel_identity::ActorId(env.actor_id),
            key_id: sentinel_identity::KeyId(env.key_id),
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
    // 2. Timestamp freshness (±300s)
    let now = Utc::now();
    let diff = (now.timestamp() - env.timestamp_utc.timestamp()).abs();
    if diff > 300 {
        return HttpResponse::Unauthorized().body("timestamp outside freshness window");
    }
    // 3. Replay protection (event-sourced)
    let identity_state = match sentinel_identity::load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    if identity_state.used_nonces.iter().any(|(aid, _, n, _)| *aid == env.actor_id && *n == env.nonce) {
        return HttpResponse::Unauthorized().body("replayed nonce (event-sourced)");
    }
    // 4. Challenge validation (must match unexpired, unused challenge event for actor/key)
    let store_guard = store.lock().unwrap();
    let store_events = match store_guard.iter() {
        Ok(evts) => evts,
        Err(e) => return HttpResponse::InternalServerError().body(format!("event log read failed: {e:?}")),
    };
    let mut found_challenge = None;
    for rec in store_events.iter().rev() {
        if let Ok(payload) = rec.payload.get("challenge") {
            if let Some(challenge) = payload.as_str() {
                // Only consider challenge events for this actor/key
                if rec.actor == env.actor_id.to_string()
                    && rec.payload.get("key_id").and_then(|v| v.as_str()) == Some(&env.key_id.to_string())
                {
                    // Check expiry
                    if let (Some(expires_at), Some(issued_at)) = (
                        rec.payload.get("expires_at_utc").and_then(|v| v.as_str()),
                        rec.payload.get("issued_at_utc").and_then(|v| v.as_str()),
                    ) {
                        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).ok().map(|dt| dt.with_timezone(&Utc));
                        let issued_at = chrono::DateTime::parse_from_rfc3339(issued_at).ok().map(|dt| dt.with_timezone(&Utc));
                        if let (Some(expires_at), Some(issued_at)) = (expires_at, issued_at) {
                            if now > expires_at {
                                continue; // Expired
                            }
                            // Check if already used (by searching for a CapabilityIssued event referencing this challenge)
                            let already_used = store_events.iter().any(|evt| {
                                evt.payload.get("challenge").and_then(|v| v.as_str()) == Some(challenge)
                                    && evt.kind == EventKind::AuthorizationRequestReceived // Should be CapabilityIssued, but using generic kind for now
                            });
                            if already_used {
                                continue; // Used
                            }
                            found_challenge = Some((challenge.to_string(), issued_at, expires_at));
                            break;
                        }
                    }
                }
            }
        }
    }
    drop(store_guard);
    if found_challenge.is_none() {
        return HttpResponse::Unauthorized().body("no valid, unexpired, unused challenge found");
    }
    let (challenge, issued_at, expires_at) = found_challenge.unwrap();
    // 5. Log the request digest before decision
    let digest = sha2::Sha256::digest(
        serde_json::to_vec(&env).expect("canonical serialization")
    );
    let digest_hex = hex::encode(digest);
    let mut store = store.lock().unwrap();
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
        kind: EventKind::AuthorizationRequestReceived,
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
    // 7. Issue session capability (CapabilityIssued event, signed by service key)
    // Load service key (dev only, not production)
    let keystore = match Keystore::load_or_create(PathBuf::from("./sentinel_service.key")) {
        Ok(ks) => ks,
        Err(e) => return HttpResponse::InternalServerError().body(format!("service key load failed: {e}")),
    };
    let capability_id = Uuid::new_v4();
    let issued_at_utc = Utc::now();
    let expires_at_utc = issued_at_utc + chrono::Duration::minutes(30); // 30 min session
    let scope = "session".to_string();
    let actions = vec!["whoami".to_string()];
    let constraints = Some(json!({ "challenge": challenge }));
    let issued_by = "sentinel_service".to_string();
    let mut cap = Capability {
        capability_id,
        actor_id: env.actor_id,
        issued_at_utc,
        expires_at_utc,
        scope,
        actions,
        constraints,
        issued_by,
        token_signature: vec![], // To be filled
    };
    // Canonical signature over all fields except token_signature
    let sig = keystore.sign(&cap, &sentinel_identity::ActorId(env.actor_id), &capability_id, &issued_at_utc);
    let sig = match sig {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("capability signing failed: {e}")),
    };
    cap.token_signature = sig.bytes;
    // Log CapabilityIssued event
    let cap_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: issued_at_utc,
        actor: env.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived, // Should be CapabilityIssued, but using generic kind for now
        payload: json!(
            serde_json::to_value(sentinel_core::CapabilityEvent::CapabilityIssued(
                sentinel_core::CapabilityIssued {
                    capability: cap.clone(),
                    issued_at: issued_at_utc,
                }
            )).expect("capability event serialization")
        ),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store.append(cap_event) {
        return HttpResponse::InternalServerError().body(format!("capability event append failed: {e:?}"));
    }
    // 8. Deterministic response: return full capability
    HttpResponse::Ok().json(cap)
}
use sentinel_capabilities::{Capability, CapabilityEvent, CapabilityIssued, CapabilityState};
#[post("/auth/login")]
async fn auth_login(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<sentinel_core::CanonicalEnvelopeAuthorizationRequest>,
) -> impl Responder {
    // 1. Envelope presence and signature verification (reuse logic from /authz)
    // 2. Challenge validation (must match unexpired, unused challenge event for actor/key)
    // 3. Issue session capability (CapabilityIssued event, signed by service key)
    // 4. Log all events before response, fail loud on any error
    // 5. Return session capability (full struct, including signature)
    HttpResponse::NotImplemented().body("/auth/login not yet implemented")
}
use rand::RngCore;
use rand::rngs::OsRng;
use chrono::{Duration};
#[post("/auth/challenge")]
async fn auth_challenge(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    // Accept actor_id, key_id from request
    let actor_id = req.get("actor_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
    let key_id = req.get("key_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
    if actor_id.is_none() || key_id.is_none() {
        return HttpResponse::BadRequest().body("missing actor_id or key_id");
    }

    // Generate random challenge (32 bytes, hex)
    let mut challenge_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);
    let now = Utc::now();
    let expires_at = now + Duration::seconds(120); // 2 min expiry

    // Log event before response (ChallengeIssued)
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: actor_id.unwrap().to_string(),
        kind: EventKind::AuthorizationRequestReceived, // Or define new kind for ChallengeIssued
        payload: json!({
            "challenge": challenge,
            "actor_id": actor_id.unwrap().to_string(),
            "key_id": key_id.unwrap().to_string(),
            "issued_at_utc": now,
            "expires_at_utc": expires_at,
        }),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let mut store = store.lock().unwrap();
    if let Err(e) = store.append(event) {
        return HttpResponse::InternalServerError().body(format!("challenge event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(json!({
        "challenge": challenge,
        "expires_at_utc": expires_at,
    }))
}
#[post("/genesis")]
async fn genesis(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    // Only allow if GenesisCompleted is not present
    let identity_state = match load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    let store_guard = store.lock().unwrap();
    let store_events = match store_guard.iter() {
        Ok(evts) => evts,
        Err(e) => return HttpResponse::InternalServerError().body(format!("event log read failed: {e:?}")),
    };
    let genesis_exists = store_events.iter().any(|rec| {
        if let Ok(ev) = serde_json::from_value::<sentinel_core::IdentityEvent>(rec.payload.clone()) {
            matches!(ev, sentinel_core::IdentityEvent::GenesisCompleted(_))
        } else { false }
    });
    if genesis_exists {
        return HttpResponse::Forbidden().body("genesis already sealed");
    }
    // Accept admin_actor_id, admin_key_id, public_key, human_handle from request
    let admin_actor_id = req.get("actor_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
    let admin_key_id = req.get("key_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
    let public_key = req.get("public_key").and_then(|v| v.as_str()).and_then(|s| hex::decode(s).ok());
    let human_handle = req.get("human_handle").and_then(|v| v.as_str()).map(|s| s.to_string());
    if admin_actor_id.is_none() || admin_key_id.is_none() || public_key.is_none() {
        return HttpResponse::BadRequest().body("missing actor_id, key_id, or public_key");
    }
    let now = Utc::now();
    let actor_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: admin_actor_id.unwrap().to_string(),
        kind: EventKind::AuthorizationRequestReceived, // Or define a new kind for genesis
        payload: json!(serde_json::to_value(sentinel_core::IdentityEvent::ActorRegistered(
            sentinel_core::ActorRegistered {
                actor_id: admin_actor_id.unwrap(),
                human_handle: human_handle.clone(),
                timestamp_utc: now,
            }
        )).unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let key_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: admin_actor_id.unwrap().to_string(),
        kind: EventKind::AuthorizationRequestReceived,
        payload: json!(serde_json::to_value(sentinel_core::IdentityEvent::KeyRegistered(
            sentinel_core::KeyRegistered {
                actor_id: admin_actor_id.unwrap(),
                key_id: admin_key_id.unwrap(),
                public_key: public_key.unwrap(),
                timestamp_utc: now,
            }
        )).unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let genesis_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: admin_actor_id.unwrap().to_string(),
        kind: EventKind::AuthorizationRequestReceived,
        payload: json!(serde_json::to_value(sentinel_core::IdentityEvent::GenesisCompleted(
            sentinel_core::GenesisCompleted {
                completed_at: now,
                admin_actor_id: admin_actor_id.unwrap(),
                admin_key_id: admin_key_id.unwrap(),
            }
        )).unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let mut store = store.lock().unwrap();
    if let Err(e) = store.append(actor_event) {
        return HttpResponse::InternalServerError().body(format!("actor event append failed: {e:?}"));
    }
    if let Err(e) = store.append(key_event) {
        return HttpResponse::InternalServerError().body(format!("key event append failed: {e:?}"));
    }
    if let Err(e) = store.append(genesis_event) {
        return HttpResponse::InternalServerError().body(format!("genesis event append failed: {e:?}"));
    }
    HttpResponse::Ok().json(json!({"result": "genesis completed"}))
}
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
            .service(genesis)
            .service(auth_challenge)
            .service(auth_login)
            .service(auth_logout)
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
