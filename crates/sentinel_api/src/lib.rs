use actix_web::{get, post, web, App, HttpResponse, Responder};
use actix_web::rt::task::spawn_blocking;
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
use sentinel_core::{CanonicalEnvelopeAuthorizationRequest, Capability, CapabilityEvent, CapabilityIssued, CapabilityConstraints, CapabilityConsumed};
use sentinel_identity::{ActorId, KeyId, SignedEnvelope, SignatureBytes, SignatureAlgorithm, Keystore, verify_signature};
use sentinel_policy::{Policy, PolicyInput, make_policy_evaluated};
use sentinel_policy::event::Decision as PolicyDecision;
pub mod middleware;
mod consent;
use consent::{enforce_consent, ConsentContext};
use sentinel_artifacts::{ArtifactEvent, ArtifactId, ArtifactType as SAType, CodexSeal};
use time::OffsetDateTime;

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

#[post("/artifacts/register")]
pub async fn artifact_register(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    let body = req.into_inner();

    let artifact_digest = match body.get("artifact_digest").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return HttpResponse::BadRequest().body("artifact_digest is required"),
    };
    let artifact_type = match body.get("artifact_type").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return HttpResponse::BadRequest().body("artifact_type is required"),
    };
    let dependencies = body.get("dependencies").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>()).unwrap_or_else(|| vec![]);
    let metadata = body.get("metadata").and_then(|v| v.as_object()).map(|m| m.iter().map(|(k,v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect::<std::collections::BTreeMap<String,String>>()).unwrap_or_default();
    let simulate_append_failure = body.get("simulate_append_failure").and_then(|v| v.as_bool()).unwrap_or(false);

    // 1) Build PolicyInput
    let policy_input = PolicyInput {
        subject: body.get("subject").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "artifact_service".to_string()),
        action: "artifact_register".to_string(),
        resource: "artifact".to_string(),
        context: json!({ "artifact_digest": artifact_digest.clone(), "artifact_type": artifact_type.clone() }),
    };

    // default policy: allow
    let policy = if let Some(pv) = body.get("policy") {
        match serde_json::from_value::<Policy>(pv.clone()) {
            Ok(p) => p,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid policy object: {e}")),
        }
    } else {
        Policy { id: "artifact_register_allow".to_string(), version: "v0".to_string(), statements: vec![sentinel_policy::policy::Statement { when: vec![sentinel_policy::policy::Condition { field: "action".to_string(), op: sentinel_policy::policy::Op::Eq, value: "artifact_register".to_string() }], effect: sentinel_policy::policy::Effect::Allow, rationale: "allow artifact register".to_string() }] }
    };

    // 2) Enforce consent
    let consent = match enforce_consent(&store, &policy, &policy_input).await {
        Ok(ctx) => ctx,
        Err(e) => {
            if e == "policy denied" {
                return HttpResponse::Forbidden().body("policy denied");
            } else {
                return HttpResponse::InternalServerError().body(format!("consent enforcement failed: {e}"));
            }
        }
    };

    if simulate_append_failure {
        return HttpResponse::InternalServerError().body("simulated append failure");
    }

    // Deterministic artifact_id based on artifact_type + digest
    let name = format!("{}:{}", artifact_type, artifact_digest);
    let artifact_uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes());
    let artifact_id = ArtifactId(artifact_uuid);

    // Map artifact_type string to enum (basic mapping)
    let atype = match artifact_type.to_lowercase().as_str() {
        "executable" => SAType::Executable,
        "model" | "modelweights" | "model_weights" => SAType::ModelWeights,
        "prompt" | "prompttemplate" | "prompt_template" => SAType::PromptTemplate,
        "tool" | "tooldefinition" | "tool_definition" => SAType::ToolDefinition,
        "config" => SAType::Config,
        _ => return HttpResponse::BadRequest().body("unknown artifact_type"),
    };

    // 3) Append ArtifactRegistered event
    let created_at = OffsetDateTime::now_utc();
    let art_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: policy_input.subject.clone(),
        kind: sentinel_store::EventKind::ArtifactRegistered,
        payload: serde_json::to_value(&ArtifactEvent::ArtifactRegistered {
            artifact_id: artifact_id.clone(),
            artifact_digest: artifact_digest.clone(),
            artifact_type: atype,
            dependencies: dependencies.clone(),
            metadata: metadata.clone(),
            created_by: policy_input.subject.clone(),
            created_at,
        }).unwrap(),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    let mut store_guard = store.lock().unwrap();
    if let Err(e) = store_guard.append(art_event) {
        return HttpResponse::InternalServerError().body(format!("artifact event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(json!({ "artifact_id": artifact_id.0.to_string(), "artifact_digest": artifact_digest }))
}


#[post("/artifacts/use")]
pub async fn artifact_use(
    store: web::Data<Mutex<FileEventStore>>,
    req: web::Json<serde_json::Value>,
) -> impl Responder {
    let body = req.into_inner();

    let capability_id = match body.get("capability_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok()) {
        Some(u) => u,
        None => return HttpResponse::BadRequest().body("capability_id is required and must be a UUID"),
    };
    let artifact_digest = match body.get("artifact_digest").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return HttpResponse::BadRequest().body("artifact_digest is required"),
    };

    // Build policy input for consuming a capability to use an artifact
    let policy_input = PolicyInput {
        subject: body.get("subject").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "artifact_service".to_string()),
        action: "capability_consume".to_string(),
        resource: "artifact_use".to_string(),
        context: json!({ "capability_id": capability_id.to_string(), "artifact_digest": artifact_digest.clone() }),
    };

    // Default allow policy for now
    let policy = Policy { id: "capability_consume_allow".to_string(), version: "v0".to_string(), statements: vec![sentinel_policy::policy::Statement { when: vec![sentinel_policy::policy::Condition { field: "action".to_string(), op: sentinel_policy::policy::Op::Eq, value: "capability_consume".to_string() }], effect: sentinel_policy::policy::Effect::Allow, rationale: "allow capability consumption".to_string() }] };

    // Enforce consent (appends PolicyEvaluated and Consent events durably). Fail-closed.
    let consent = match enforce_consent(&store, &policy, &policy_input).await {
        Ok(ctx) => ctx,
        Err(e) => {
            if e == "policy denied" {
                return HttpResponse::Forbidden().body("policy denied");
            } else {
                return HttpResponse::InternalServerError().body(format!("consent enforcement failed: {e}"));
            }
        }
    };

    // Append CapabilityConsumed event (must include artifact_digest)
    let consumed_typed = CapabilityConsumed {
        capability_id,
        consumed_at: Utc::now(),
        envelope_digest: "N/A".to_string(),
        artifact_digest: Some(artifact_digest.clone()),
    };
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: policy_input.subject.clone(),
        kind: EventKind::CapabilityConsumed,
        payload: serde_json::to_value(&CapabilityEvent::CapabilityConsumed(consumed_typed)).unwrap(),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };

    let mut store_guard = store.lock().unwrap();
    if let Err(e) = store_guard.append(event) {
        return HttpResponse::InternalServerError().body(format!("capability consume append failed: {e:?}"));
    }

    HttpResponse::Ok().json(json!({ "result": "capability consumed", "capability_id": capability_id.to_string(), "policy_digest": consent.policy_digest, "input_digest": consent.input_digest }))
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
        kind: EventKind::Identity,
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
        kind: EventKind::Identity,
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
        kind: EventKind::Identity,
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
    // release read guard before calling consent enforcement
    drop(store_guard);

    // 1) Build PolicyInput for genesis and determine policy to evaluate.
    let is_initial_boot = req.get("is_initial_boot").and_then(|v| v.as_bool()).unwrap_or(true);
    let operator_present = req.get("operator_present").and_then(|v| v.as_bool()).unwrap_or(false);
    let simulate_append_failure = req.get("simulate_append_failure").and_then(|v| v.as_bool()).unwrap_or(false);

    let policy_input = PolicyInput {
        subject: actor_id.to_string(),
        action: "genesis".to_string(),
        resource: "system".to_string(),
        context: json!({ "is_initial_boot": is_initial_boot, "operator_present": operator_present, "simulate_append_failure": simulate_append_failure }),
    };

    // If caller provided an explicit policy object, use it; otherwise, default to a conservative allow for genesis action.
    let policy = if let Some(pv) = req.get("policy") {
        match serde_json::from_value::<Policy>(pv.clone()) {
            Ok(p) => p,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid policy object: {e}")),
        }
    } else {
        Policy {
            id: "genesis_allow".to_string(),
            version: "v0".to_string(),
            statements: vec![sentinel_policy::policy::Statement {
                when: vec![sentinel_policy::policy::Condition { field: "action".to_string(), op: sentinel_policy::policy::Op::Eq, value: "genesis".to_string() }],
                effect: sentinel_policy::policy::Effect::Allow,
                rationale: "allow genesis".to_string(),
            }],
        }
    };

    // 2) Enforce consent (this appends PolicyEvaluated and Consent events durably). Fail-closed on any error.
    let consent = match enforce_consent(&store, &policy, &policy_input).await {
        Ok(ctx) => ctx,
        Err(e) => {
            if e == "policy denied" {
                return HttpResponse::Forbidden().body("policy denied");
            } else {
                return HttpResponse::InternalServerError().body(format!("consent enforcement failed: {e}"));
            }
        }
    };

    // 3) Optional test hook: simulate append failure to ensure no side effects recorded
    if simulate_append_failure {
        return HttpResponse::InternalServerError().body("simulated append failure");
    }

    // 4) After consent granted, append actor, key, and genesis events sequentially (fail-closed on append errors)
    let mut store_guard = store.lock().unwrap();
    if let Err(e) = store_guard.append(actor_event) {
        return HttpResponse::InternalServerError().body(format!("actor event append failed: {e:?}"));
    }
    if let Err(e) = store_guard.append(key_event) {
        return HttpResponse::InternalServerError().body(format!("key event append failed: {e:?}"));
    }
    if let Err(e) = store_guard.append(genesis_event) {
        return HttpResponse::InternalServerError().body(format!("genesis event append failed: {e:?}"));
    }

    // 5) Append EffectExecuted event (non-sync append is sufficient here)
    let effect_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: actor_id.to_string(),
        kind: EventKind::EffectExecuted,
        payload: json!({ "effect": "genesis", "policy_digest": consent.policy_digest, "input_digest": consent.input_digest }),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    if let Err(e) = store_guard.append(effect_event) {
        return HttpResponse::InternalServerError().body(format!("effect event append failed: {e:?}"));
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

    // release store_guard before calling blocking append to avoid deadlock
    drop(store_guard);

    // 6) Validate + append NonceConsumed via shared middleware (fail-closed)
    // Offload durable append to blocking thread pool to avoid blocking the async executor (fsync)
    let store_clone = store.clone();
    let envelope_clone = envelope.clone();
    let append_handle = spawn_blocking(move || {
        middleware::nonce_middleware::check_and_append_nonce(&*store_clone, &envelope_clone)
    })
    .await;
    match append_handle {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return HttpResponse::InternalServerError().body(format!("nonce append failed: {e}")),
        Err(_) => return HttpResponse::InternalServerError().body("nonce append task failed"),
    }

    // 7) Build a PolicyInput for auth_login and enforce consent (fail-closed)
    let policy_input = PolicyInput {
        subject: envelope.actor_id.to_string(),
        action: "auth_login".to_string(),
        resource: "session".to_string(),
        context: json!({ "challenge": challenge }),
    };
    // Use a built-in allow policy for login (handlers may later use configured policies)
    let policy = Policy {
        id: "auth_login_allow".to_string(),
        version: "v0".to_string(),
        statements: vec![sentinel_policy::policy::Statement {
            when: vec![sentinel_policy::policy::Condition { field: "action".to_string(), op: sentinel_policy::policy::Op::Eq, value: "auth_login".to_string() }],
            effect: sentinel_policy::policy::Effect::Allow,
            rationale: "allow login".to_string(),
        }],
    };
    let consent = match enforce_consent(&store, &policy, &policy_input).await {
        Ok(ctx) => ctx,
        Err(e) => return HttpResponse::InternalServerError().body(format!("consent enforcement failed: {e}")),
    };

    // 8) Issue session capability (signed by service key) — effect happens only after consent
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
        constraints: Some(CapabilityConstraints { allowed_artifact_digests: None }),
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
    let mut store_guard = store.lock().unwrap();
    if let Err(e) = store_guard.append(cap_event) {
        return HttpResponse::InternalServerError().body(format!("capability event append failed: {e:?}"));
    }

    // Append EffectExecuted event durable
    let effect_event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: envelope.actor_id.to_string(),
        kind: EventKind::EffectExecuted,
        payload: json!({ "effect": "issue_capability", "policy_digest": consent.policy_digest, "input_digest": consent.input_digest }),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    // use append (non-sync) here to avoid double-syncing
    if let Err(e) = store_guard.append(effect_event) {
        return HttpResponse::InternalServerError().body(format!("effect event append failed: {e:?}"));
    }

    HttpResponse::Ok().json(cap)
}


    #[post("/policy/evaluate")]
    pub async fn policy_evaluate(
        store: web::Data<Mutex<FileEventStore>>,
        req: web::Json<serde_json::Value>,
    ) -> impl Responder {
        // 1) Parse input: require either `policy` (full object) or reject reference-only (no registry exists yet)
        let body = req.into_inner();

        let policy_value = body.get("policy");
        let policy_digest_ref = body.get("policy_digest").and_then(|v| v.as_str()).map(|s| s.to_string());
        let input_value = body.get("input");

        if input_value.is_none() {
            return HttpResponse::BadRequest().body("missing 'input' field");
        }

        // If caller provided only a digest reference, fail: no policy registry exists (no hidden lookup)
        if policy_value.is_none() && policy_digest_ref.is_some() {
            return HttpResponse::BadRequest().body("policy_digest reference unsupported: provide full policy object (no registry available)");
        }

        if policy_value.is_none() {
            return HttpResponse::BadRequest().body("missing 'policy' field; explicit policy required");
        }

        // Deserialize policy and input
        let policy: Policy = match serde_json::from_value(policy_value.unwrap().clone()) {
            Ok(p) => p,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid policy object: {e}")),
        };
        let input: PolicyInput = match serde_json::from_value(input_value.unwrap().clone()) {
            Ok(i) => i,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid input object: {e}")),
        };

        // 2) Build PolicyEvaluated payload (pure)
        let now = Utc::now();
        // evaluator version is locked to v0 for this frozen schema
        let evaluator_version = "v0";
        let pe = make_policy_evaluated(&policy, &input, evaluator_version, now);

        // 3) Append PolicyEvaluated event BEFORE responding (fail-closed).
        // Offload durable append to blocking thread pool to avoid executor blocking.
        let store_clone = store.clone();
        let pe_clone = pe.clone();
        let event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: now,
            actor: "policy_evaluator".to_string(),
            kind: EventKind::PolicyEvaluated,
            payload: serde_json::to_value(&pe_clone).expect("policy evaluated serialization"),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };

        let append_res = spawn_blocking(move || {
            let mut s = store_clone.lock().unwrap();
            s.append_with_sync(event, true)
        })
        .await;

        if let Err(_) = append_res {
            return HttpResponse::InternalServerError().body("policy evaluated append task failed");
        }
        if let Ok(Err(e)) = append_res {
            return HttpResponse::InternalServerError().body(format!("policy evaluated event append failed: {e:?}"));
        }

        // 4) Return explanation (read-only)
        // 4) Append Consent event (audit) BEFORE returning
        let consent_granted = matches!(pe.decision, PolicyDecision::Allow);
        let consent_event_payload = sentinel_policy::event::make_consent_event(
            &input.subject,
            &pe.policy_digest,
            &pe.input_digest,
            consent_granted,
            &pe.rationale,
            Utc::now(),
        );
        let store_clone2 = store.clone();
        let consent_event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: Utc::now(),
            actor: input.subject.clone(),
            kind: if consent_granted { EventKind::ConsentGranted } else { EventKind::ConsentDenied },
            payload: serde_json::to_value(&consent_event_payload).expect("consent serialization"),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let append_res2 = spawn_blocking(move || {
            let mut s = store_clone2.lock().unwrap();
            s.append_with_sync(consent_event, true)
        })
        .await;
        if let Err(_) = append_res2 {
            return HttpResponse::InternalServerError().body("consent append task failed");
        }
        if let Ok(Err(e)) = append_res2 {
            return HttpResponse::InternalServerError().body(format!("consent event append failed: {e:?}"));
        }

        HttpResponse::Ok().json(json!({
            "decision": match pe.decision {
                PolicyDecision::Allow => "Allow",
                PolicyDecision::Deny => "Deny",
            },
            "policy_digest": pe.policy_digest,
            "input_digest": pe.input_digest,
            "rationale": pe.rationale,
            "matched_statement_index": pe.matched_statement_index,
        }))
    }

    #[post("/privileged/action")]
    pub async fn privileged_action(
        store: web::Data<Mutex<FileEventStore>>,
        req: web::Json<serde_json::Value>,
    ) -> impl Responder {
        // Expect `policy` and `input` in body
        let body = req.into_inner();
        let policy_value = body.get("policy");
        let input_value = body.get("input");
        if policy_value.is_none() || input_value.is_none() {
            return HttpResponse::BadRequest().body("missing policy or input");
        }


        
        let policy: Policy = match serde_json::from_value(policy_value.unwrap().clone()) {
            Ok(p) => p,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid policy object: {e}")),
        };
        let input: PolicyInput = match serde_json::from_value(input_value.unwrap().clone()) {
            Ok(i) => i,
            Err(e) => return HttpResponse::BadRequest().body(format!("invalid input object: {e}")),
        };

        // 1) Evaluate (pure)
        let now = Utc::now();
        let pe = make_policy_evaluated(&policy, &input, "v0", now);

        // 2) Append PolicyEvaluated durable
        let store_clone = store.clone();
        let pe_clone = pe.clone();
        let event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: now,
            actor: "policy_evaluator".to_string(),
            kind: EventKind::PolicyEvaluated,
            payload: serde_json::to_value(&pe_clone).expect("policy evaluated serialization"),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let append_res = spawn_blocking(move || {
            let mut s = store_clone.lock().unwrap();
            s.append_with_sync(event, true)
        })
        .await;
        if let Err(_) = append_res {
            return HttpResponse::InternalServerError().body("policy evaluated append task failed");
        }
        if let Ok(Err(e)) = append_res {
            return HttpResponse::InternalServerError().body(format!("policy evaluated event append failed: {e:?}"));
        }

        // 3) Append Consent event durable
        let consent_granted = matches!(pe.decision, PolicyDecision::Allow);
        let consent_event_payload = sentinel_policy::event::make_consent_event(
            &input.subject,
            &pe.policy_digest,
            &pe.input_digest,
            consent_granted,
            &pe.rationale,
            Utc::now(),
        );
        let store_clone2 = store.clone();
        let consent_event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: Utc::now(),
            actor: input.subject.clone(),
            kind: if consent_granted { EventKind::ConsentGranted } else { EventKind::ConsentDenied },
            payload: serde_json::to_value(&consent_event_payload).expect("consent serialization"),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let append_res2 = spawn_blocking(move || {
            let mut s = store_clone2.lock().unwrap();
            s.append_with_sync(consent_event, true)
        })
        .await;
        if let Err(_) = append_res2 {
            return HttpResponse::InternalServerError().body("consent append task failed");
        }
        if let Ok(Err(e)) = append_res2 {
            return HttpResponse::InternalServerError().body(format!("consent event append failed: {e:?}"));
        }

        // 4) If allowed, perform effect (append EffectExecuted). If denied, return forbidden.
        if !consent_granted {
            return HttpResponse::Forbidden().body("policy denied");
        }

        // 4a) Optional test hook: simulate append failure if input.context.simulate_append_failure == true
        if let Some(v) = input.context.get("simulate_append_failure") {
            if v.as_bool().unwrap_or(false) {
                return HttpResponse::InternalServerError().body("simulated append failure");
            }
        }

        // Append EffectExecuted event durable
        let store_clone3 = store.clone();
        let effect_event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: Utc::now(),
            actor: input.subject.clone(),
            kind: EventKind::EffectExecuted,
            payload: json!({ "effect": "privileged_action_executed", "policy_digest": pe.policy_digest, "input_digest": pe.input_digest }),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let append_res3 = spawn_blocking(move || {
            let mut s = store_clone3.lock().unwrap();
            s.append_with_sync(effect_event, true)
        })
        .await;
        if let Err(_) = append_res3 {
            return HttpResponse::InternalServerError().body("effect append task failed");
        }
        if let Ok(Err(e)) = append_res3 {
            return HttpResponse::InternalServerError().body(format!("effect event append failed: {e:?}"));
        }

        HttpResponse::Ok().json(json!({ "result": "effect executed" }))
    }


    #[post("/capabilities/issue")]
    pub async fn capability_issue(
        store: web::Data<Mutex<FileEventStore>>,
        req: web::Json<serde_json::Value>,
    ) -> impl Responder {
        let body = req.into_inner();

        // Parse required fields
        let issuer = body.get("issuer").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "sentinel_service".to_string());
        let subject = body.get("subject").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| issuer.clone());
        let scope = body.get("scope").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "session".to_string());
        let actions = body.get("actions").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>()).unwrap_or_else(|| vec!["whoami".to_string()]);
        let ttl_minutes = body.get("ttl_minutes").and_then(|v| v.as_i64()).unwrap_or(30);
        // Accept typed allowed_artifact_digests for artifact-binding constraints
        let allowed_artifact_digests = body.get("allowed_artifact_digests").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>());
        let constraints_typed = CapabilityConstraints { allowed_artifact_digests: allowed_artifact_digests.clone() };
        let simulate_append_failure = body.get("simulate_append_failure").and_then(|v| v.as_bool()).unwrap_or(false);

        // 1) Build PolicyInput
        let policy_input = PolicyInput {
            subject: issuer.clone(),
            action: "capability_issue".to_string(),
            resource: scope.clone(),
            context: json!({ "subject": subject.clone(), "scope": scope.clone(), "actions": actions.clone(), "ttl_minutes": ttl_minutes }),
        };

        // Use provided policy or default allow for capability issuance
        let policy = if let Some(pv) = body.get("policy") {
            match serde_json::from_value::<Policy>(pv.clone()) {
                Ok(p) => p,
                Err(e) => return HttpResponse::BadRequest().body(format!("invalid policy object: {e}")),
            }
        } else {
            Policy {
                id: "capability_issue_allow".to_string(),
                version: "v0".to_string(),
                statements: vec![sentinel_policy::policy::Statement {
                    when: vec![sentinel_policy::policy::Condition { field: "action".to_string(), op: sentinel_policy::policy::Op::Eq, value: "capability_issue".to_string() }],
                    effect: sentinel_policy::policy::Effect::Allow,
                    rationale: "allow capability issuance".to_string(),
                }],
            }
        };

        // 2) Enforce consent (appends PolicyEvaluated and Consent events durably). Fail-closed.
        let consent = match enforce_consent(&store, &policy, &policy_input).await {
            Ok(ctx) => ctx,
            Err(e) => {
                if e == "policy denied" {
                    return HttpResponse::Forbidden().body("policy denied");
                } else {
                    return HttpResponse::InternalServerError().body(format!("consent enforcement failed: {e}"));
                }
            }
        };

        // 3) Optional test hook: simulate append failure
        if simulate_append_failure {
            return HttpResponse::InternalServerError().body("simulated append failure");
        }

        // 4) Execute issuance: create Capability and sign with service keystore
        let keystore = match Keystore::load_or_create(std::path::PathBuf::from("./sentinel_service.key")) {
            Ok(ks) => ks,
            Err(e) => return HttpResponse::InternalServerError().body(format!("service key load failed: {e}")),
        };
        let capability_id = Uuid::new_v4();
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::minutes(ttl_minutes);
        let mut cap = Capability {
            capability_id,
            actor_id: Uuid::nil(),
            issued_at_utc: issued_at,
            expires_at_utc: expires_at,
            scope: scope.clone(),
            actions: actions.clone(),
            constraints: Some(constraints_typed.clone()),
            issued_by: issuer.clone(),
            token_signature: vec![],
        };

        // Sign capability token; use issuer actor if it's a valid UUID else use service actor
        let issuer_actor = Uuid::parse_str(&issuer).unwrap_or_else(|_| Uuid::nil());
        let sig = match keystore.sign(&cap, &ActorId(issuer_actor), &capability_id, &issued_at) {
            Ok(s) => s,
            Err(e) => return HttpResponse::InternalServerError().body(format!("cap signing failed: {e}")),
        };
        cap.token_signature = sig.bytes;

        // 5) Append CapabilityIssued event (fail-closed on append failure)
        let cap_event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: issued_at,
            actor: issuer.clone(),
            kind: EventKind::CapabilityIssued,
            payload: json!(serde_json::to_value(CapabilityEvent::CapabilityIssued(CapabilityIssued { capability: cap.clone(), issued_at })).unwrap()),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let mut store_guard = store.lock().unwrap();
        if let Err(e) = store_guard.append(cap_event) {
            return HttpResponse::InternalServerError().body(format!("capability event append failed: {e:?}"));
        }
        // release the guard before performing a blocking append to avoid deadlock
        drop(store_guard);

        // 6) Append EffectExecuted durable with policy/input digests and capability id
        let effect_event = EventRecord {
            event_id: Uuid::new_v4(),
            timestamp_utc: Utc::now(),
            actor: issuer.clone(),
            kind: EventKind::EffectExecuted,
            payload: json!({ "action": "capability_issue", "policy_digest": consent.policy_digest, "input_digest": consent.input_digest, "capability_id": capability_id.to_string() }),
            prev_hash: None,
            hash: "UNHASHED".to_string(),
        };
        let store_clone = store.clone();
        let effect = effect_event.clone();
        let append_res = spawn_blocking(move || {
            let mut s = store_clone.lock().unwrap();
            s.append_with_sync(effect, true)
        })
        .await;
        if let Err(_) = append_res {
            return HttpResponse::InternalServerError().body("effect append task failed");
        }
        if let Ok(Err(e)) = append_res {
            return HttpResponse::InternalServerError().body(format!("effect event append failed: {e:?}"));
        }

        HttpResponse::Ok().json(cap)
    }
