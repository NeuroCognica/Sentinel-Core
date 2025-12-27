use actix_web::rt::task::spawn_blocking;
use chrono::Utc;
use serde_json::json;
use std::sync::Mutex;
use uuid::Uuid;

use sentinel_policy::{Policy, PolicyInput, make_policy_evaluated};
use sentinel_store::{EventRecord, EventKind, FileEventStore};

pub struct ConsentContext {
    pub policy_digest: String,
    pub input_digest: String,
}

pub async fn enforce_consent(
    store: &actix_web::web::Data<Mutex<FileEventStore>>,
    policy: &Policy,
    input: &PolicyInput,
) -> Result<ConsentContext, String> {
    let now = Utc::now();
    let pe = make_policy_evaluated(policy, input, "v0", now);

    // Append PolicyEvaluated durably
    let store_clone = store.clone();
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: now,
        actor: "policy_evaluator".to_string(),
        kind: EventKind::PolicyEvaluated,
        payload: serde_json::to_value(&pe).map_err(|e| format!("serialize pe: {e}"))?,
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let append_res = spawn_blocking(move || {
        let mut s = store_clone.lock().unwrap();
        s.append_with_sync(event, true)
    })
    .await
    .map_err(|_| "policy evaluated append task failed".to_string())?;
    if let Err(e) = append_res {
        return Err(format!("policy evaluated event append failed: {e:?}"));
    }

    // Append consent
    let consent_granted = matches!(pe.decision, sentinel_policy::event::Decision::Allow);
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
        payload: serde_json::to_value(&consent_event_payload).map_err(|e| format!("serialize consent: {e}"))?,
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    let append_res2 = spawn_blocking(move || {
        let mut s = store_clone2.lock().unwrap();
        s.append_with_sync(consent_event, true)
    })
    .await
    .map_err(|_| "consent append task failed".to_string())?;
    if let Err(e) = append_res2 {
        return Err(format!("consent event append failed: {e:?}"));
    }

    if consent_granted {
        Ok(ConsentContext { policy_digest: pe.policy_digest, input_digest: pe.input_digest })
    } else {
        Err("policy denied".to_string())
    }
}
