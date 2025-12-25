// DEV MODE ONLY — NON-SECURE — DO NOT SHIP
// Helper to generate a canonical signed envelope for Phase 2 · Step 1 verification
// This must match the server's canonical serialization and signing rules exactly

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{Utc, DateTime};
use std::str::FromStr;
// ...existing code...

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationRequest {
    action: String,
    scope: String,
    intent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CanonicalEnvelope<T> {
    actor_id: Uuid,
    key_id: Uuid,
    nonce: Uuid,
    timestamp_utc: DateTime<Utc>,
    payload: T,
    signature: Vec<u8>,
}

// Canonical unsigned envelope for signing (matches CanonicalEnvelope minus signature)
#[derive(Serialize)]
struct UnsignedEnvelope<'a, T> {
    actor_id: &'a Uuid,
    key_id: &'a Uuid,
    nonce: &'a Uuid,
    timestamp_utc: &'a DateTime<Utc>,
    payload: &'a T,
}

fn main() {
    // === DEV KEYPAIR: DO NOT SHIP ===
    // Private key bytes (32 bytes, must match server's hardcoded public key)
    // Example: [1u8; 32] for private, [7u8; 32] for public (server expects [7u8; 32])
    let priv_bytes = [1u8; 32];
    let secret = SecretKey::from_bytes(&priv_bytes).unwrap();
    let public = PublicKey::from(&secret);
    let keypair = Keypair { secret, public };

    // Actor and key IDs (arbitrary for dev, but must be valid UUIDs)
    let actor_id = Uuid::from_str("11111111-1111-1111-1111-111111111111").unwrap();
    let key_id = Uuid::from_str("22222222-2222-2222-2222-222222222222").unwrap();
    let nonce = Uuid::new_v4();
    let timestamp_utc = Utc::now();

    let payload = AuthorizationRequest {
        action: "health_check".to_string(),
        scope: "system".to_string(),
        intent: "phase2-step1 verification".to_string(),
    };

    let unsigned = UnsignedEnvelope {
        actor_id: &actor_id,
        key_id: &key_id,
        nonce: &nonce,
        timestamp_utc: &timestamp_utc,
        payload: &payload,
    };

    let bytes = serde_json::to_vec(&unsigned).unwrap();
    let sig = keypair.sign(&bytes);
    let signature = sig.to_bytes().to_vec();

    let env = CanonicalEnvelope {
        actor_id,
        key_id,
        nonce,
        timestamp_utc,
        payload,
        signature,
    };

    println!("{}", serde_json::to_string_pretty(&env).unwrap());
    // Print public key for server mapping/debug
    println!("\nPUBLIC_KEY_HEX={}", hex::encode(public.to_bytes()));
}
