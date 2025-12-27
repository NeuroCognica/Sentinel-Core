use serde_json::json;
use std::env;
use uuid::Uuid;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use sentinel_artifacts::CanonicalEnvelope;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: schema_dump <artifact_type>\nAvailable: envelope, proof");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "envelope" => dump_envelope(),
        "proof" => dump_proof(),
        other => {
            eprintln!("Unknown artifact type: {}", other);
            std::process::exit(1);
        }
    }
}

fn iso_now() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn dump_envelope() {
    // Instantiate the real CanonicalEnvelope struct and serialize it.
    let envelope = CanonicalEnvelope {
        actor_id: Uuid::nil().to_string(),
        key_id: Uuid::nil().to_string(),
        nonce: Uuid::new_v4().to_string(),
        timestamp_utc: iso_now(),
        payload: json!({"action": "ping"}),
        signature: "deadbeefbase64==".to_string(),
    };

    println!("{}", serde_json::to_string_pretty(&envelope).expect("serialize"));
}

fn dump_proof() {
    // Produce a deterministic example matching aura/schemas/execution_proof.schema.json
    let started = iso_now();
    let completed = iso_now();
    let proof = json!({
        "version": "1.0",
        "proof_id": Uuid::new_v4().to_string(),
        "envelope_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "executor": {
            "executor_id": "executor-1",
            "executor_type": "mechanician"
        },
        "started_at_utc": started,
        "completed_at_utc": completed,
        "artifacts": [
            {
                "artifact_type": "output",
                "artifact_digest": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                "role": "output"
            }
        ],
        "outcome": {
            "status": "success"
        }
    });

    println!("{}", serde_json::to_string_pretty(&proof).expect("serialize"));
}
