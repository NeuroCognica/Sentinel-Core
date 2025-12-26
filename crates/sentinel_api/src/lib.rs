use actix_web::{get, post, web, App, HttpResponse, Responder};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use std::sync::Mutex;

use sentinel_store::{EventKind, EventRecord, FileEventStore, EventStore};
use sentinel_core::{IdentityEvent, ActorRegistered, KeyRegistered, GenesisCompleted, AuthChallengeIssued, AuthChallengeConsumed};
use hex;
use sentinel_identity::{load_identity_state_from_event_log, KeyStatus};
use chrono::Duration;
use sha2::Sha256;
use sha2::Digest;
use ed25519_dalek::PublicKey;
use sentinel_core::{CanonicalEnvelopeAuthorizationRequest, Capability, CapabilityEvent, CapabilityIssued, NonceConsumed};
use sentinel_identity::{ActorId, KeyId, SignedEnvelope, SignatureBytes, SignatureAlgorithm, Keystore, verify_signature};

#[get("/health")]
pub async fn health(store: web::Data<Mutex<FileEventStore>>) -> impl Responder {
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

#[post("/genesis")]
pub async fn genesis(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    // Only allow genesis if no GenesisCompleted event exists
    let mut store_guard = store.lock().unwrap();
    let events = match store_guard.iter() {
        Ok(evts) => evts,
        Err(e) => return HttpResponse::InternalServerError().body(format!("event log read failed: {e:?}")),
    };

    for rec in events.iter() {
        if let Ok(ev) = serde_json::from_value::<IdentityEvent>(rec.payload.clone()) {
            if let IdentityEvent::GenesisCompleted(_) = ev {
                return HttpResponse::Forbidden().body("genesis already sealed");
            }
        }
    }

    // Determine actor_id, key_id, public_key
    let actor_id = req
        .get("actor_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| Uuid::new_v4());

    let key_id = req
        .get("key_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| Uuid::new_v4());

    let public_key_bytes = if let Some(pk_hex) = req.get("public_key").and_then(|v| v.as_str()) {
        match hex::decode(pk_hex) {
            Ok(b) => b,
            Err(_) => return HttpResponse::BadRequest().body("invalid public_key hex"),
        }
    } else {
        return HttpResponse::BadRequest().body("public_key is required for genesis");
    };

    let now = Utc::now();

    // Build events
    let actor_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: actor_id.to_string(),
        kind: EventKind::CapabilityIssued,
        payload: json!(serde_json::to_value(IdentityEvent::ActorRegistered(ActorRegistered {
            actor_id,
            human_handle: req.get("human_handle").and_then(|v| v.as_str()).map(|s| s.to_string()),
            timestamp_utc: now,
        }))
        .unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    let key_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: actor_id.to_string(),
        kind: EventKind::CapabilityIssued,
        payload: json!(serde_json::to_value(IdentityEvent::KeyRegistered(KeyRegistered {
            actor_id,
            key_id,
            public_key: public_key_bytes.clone(),
            timestamp_utc: now,
        }))
        .unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    let genesis_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: actor_id.to_string(),
        kind: EventKind::CapabilityIssued,
        payload: json!(serde_json::to_value(IdentityEvent::GenesisCompleted(GenesisCompleted {
            completed_at: now,
            admin_actor_id: actor_id,
            admin_key_id: key_id,
        }))
        .unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    // Append events sequentially; fail-closed on any error
    if let Err(e) = store_guard.append(actor_event) {
        return HttpResponse::InternalServerError().body(format!("actor event append failed: {e:?}"));
    }
    if let Err(e) = store_guard.append(key_event) {
        return HttpResponse::InternalServerError().body(format!("key event append failed: {e:?}"));
    }
    if let Err(e) = store_guard.append(genesis_event) {
        return HttpResponse::InternalServerError().body(format!("genesis event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(json!({
        "result": "genesis completed",
        "actor_id": actor_id.to_string(),
        "key_id": key_id.to_string(),
        "public_key": hex::encode(public_key_bytes),
    }))
}

#[post("/auth/challenge")]
pub async fn auth_challenge(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    // Parse actor_id and key_id
    let actor_id = req
        .get("actor_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let key_id = req
        .get("key_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    if actor_id.is_none() || key_id.is_none() {
        return HttpResponse::BadRequest().body("missing actor_id or key_id");
    }

    // Verify actor/key exist and key is active
    let identity_state = match load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(state) => state,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };

    let actor = actor_id.unwrap();
    let key = key_id.unwrap();
    let key_info = identity_state.keys.get(&(actor, key));
    if key_info.is_none() || key_info.unwrap().status != KeyStatus::Active {
        return HttpResponse::Unauthorized().body("unknown or revoked key");
    }

    // Generate 32-byte challenge via SHA-256(Uuid + now + Uuid)
    let now = Utc::now();
    let mut hasher = Sha256::new();
    hasher.update(Uuid::new_v4().as_bytes());
    hasher.update(now.to_rfc3339().as_bytes());
    hasher.update(Uuid::new_v4().as_bytes());
    let digest = hasher.finalize();
    let challenge = hex::encode(digest);
    let expires_at = now + Duration::seconds(120);

    // Log typed AuthChallengeIssued event before responding
    let mut store_guard = store.lock().unwrap();
    let typed = AuthChallengeIssued {
        challenge: challenge.clone(),
        actor_id: actor,
        key_id: key,
        issued_at_utc: now,
        expires_at_utc: expires_at,
    };
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: actor.to_string(),
        kind: EventKind::AuthChallengeIssued,
        payload: serde_json::to_value(&typed).expect("challenge payload serialization"),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    if let Err(e) = store_guard.append(event) {
        return HttpResponse::InternalServerError().body(format!("challenge event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(json!({ "challenge": challenge, "expires_at_utc": expires_at }))
}

#[post("/auth/login")]
pub async fn auth_login(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<CanonicalEnvelopeAuthorizationRequest>,
) -> impl Responder {
    let envelope = req.into_inner();

    // 1) Identity state and key lookup
    let identity_state = match load_identity_state_from_event_log("./sentinel_events.log") {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("identity state load failed: {e}")),
    };
    let key_info = identity_state.keys.get(&(envelope.actor_id, envelope.key_id));
    if key_info.is_none() || key_info.unwrap().status != KeyStatus::Active {
        return HttpResponse::Unauthorized().body("unknown or revoked key");
    }

    // 2) Verify signature
    let pubkey_bytes = &key_info.unwrap().public_key;
    let pubkey = match PublicKey::from_bytes(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::Unauthorized().body("invalid public key bytes"),
    };

    let signed = SignedEnvelope {
        actor_id: ActorId(envelope.actor_id),
        key_id: KeyId(envelope.key_id),
        nonce: envelope.nonce,
        timestamp_utc: envelope.timestamp_utc,
        payload: envelope.payload.clone(),
        signature: SignatureBytes {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: envelope.signature.clone(),
        },
    };

    if let Err(_) = verify_signature(&signed, &pubkey) {
        return HttpResponse::Unauthorized().body("invalid signature");
    }

    // 3) Timestamp freshness
    if !sentinel_identity::verify_freshness(&envelope.timestamp_utc, 300) {
        return HttpResponse::Unauthorized().body("timestamp outside freshness window");
    }

    // 4) Challenge presence/freshness/unused
    let challenge = envelope.payload.intent.clone();
    let mut store_guard = store.lock().unwrap();
    let events = match store_guard.iter() {
        Ok(evts) => evts,
        Err(e) => return HttpResponse::InternalServerError().body(format!("event log read failed: {e:?}")),
    };

    // Find typed AuthChallengeIssued matching the challenge and actor/key, ensure not expired
    let mut found = None;
    for rec in events.iter().rev() {
        if let EventKind::AuthChallengeIssued = rec.kind {
            if let Ok(typed) = serde_json::from_value::<AuthChallengeIssued>(rec.payload.clone()) {
                if typed.challenge == challenge && typed.actor_id == envelope.actor_id && typed.key_id == envelope.key_id {
                    if Utc::now() > typed.expires_at_utc {
                        return HttpResponse::Unauthorized().body("challenge expired");
                    }
                    found = Some(typed);
                    break;
                }
            }
        }
    }
    if found.is_none() {
        return HttpResponse::Unauthorized().body("no valid challenge found");
    }

    // ensure challenge not already consumed
    if events.iter().any(|rec| matches!(rec.kind, EventKind::AuthChallengeConsumed) && serde_json::from_value::<AuthChallengeConsumed>(rec.payload.clone()).map(|c| c.challenge == challenge).unwrap_or(false)) {
        return HttpResponse::Unauthorized().body("challenge already used");
    }

    // 5) Log AuthChallengeConsumed
    let consumed_typed = AuthChallengeConsumed {
        challenge: challenge.clone(),
        actor_id: envelope.actor_id,
        key_id: envelope.key_id,
        consumed_at_utc: Utc::now(),
    };
    let consumed_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: envelope.actor_id.to_string(),
        kind: EventKind::AuthChallengeConsumed,
        payload: serde_json::to_value(&consumed_typed).expect("consume payload serialization"),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store_guard.append(consumed_event) {
        return HttpResponse::InternalServerError().body(format!("challenge consume append failed: {e:?}"));
    }

    // 6) Append NonceConsumed IdentityEvent (NonceConsumed contains envelope digest)
    let digest = sha2::Sha256::digest(serde_json::to_vec(&envelope).expect("canonical serialization"));
    let digest_hex = hex::encode(digest);
    let nonce_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: envelope.actor_id.to_string(),
        kind: EventKind::AuthorizationRequestReceived,
        payload: json!(serde_json::to_value(IdentityEvent::NonceConsumed(NonceConsumed {
            actor_id: envelope.actor_id,
            key_id: envelope.key_id,
            nonce: envelope.nonce,
            envelope_digest: digest_hex.clone(),
            consumed_at: Utc::now(),
        })).unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store_guard.append(nonce_event) {
        return HttpResponse::InternalServerError().body(format!("nonce append failed: {e:?}"));
    }

    // 7) Issue session capability (signed by service key)
    let keystore = match Keystore::load_or_create(std::path::PathBuf::from("./sentinel_service.key")) {
        Ok(ks) => ks,
        Err(e) => return HttpResponse::InternalServerError().body(format!("service key load failed: {e}")),
    };
    let capability_id = Uuid::new_v4();
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::minutes(30);
    let mut cap = Capability {
        capability_id,
        actor_id: envelope.actor_id,
        issued_at_utc: issued_at,
        expires_at_utc: expires_at,
        scope: "session".to_string(),
        actions: vec!["whoami".to_string()],
        constraints: Some(json!({"challenge": challenge})),
        issued_by: "sentinel_service".to_string(),
        token_signature: vec![],
    };
    let sig = match keystore.sign(&cap, &ActorId(envelope.actor_id), &capability_id, &issued_at) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("cap signing failed: {e}")),
    };
    cap.token_signature = sig.bytes;

    // Log CapabilityIssued event
    let cap_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: issued_at,
        actor: envelope.actor_id.to_string(),
        kind: EventKind::CapabilityIssued,
        payload: json!(serde_json::to_value(CapabilityEvent::CapabilityIssued(CapabilityIssued { capability: cap.clone(), issued_at })).unwrap()),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store_guard.append(cap_event) {
        return HttpResponse::InternalServerError().body(format!("capability event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(cap)
}
