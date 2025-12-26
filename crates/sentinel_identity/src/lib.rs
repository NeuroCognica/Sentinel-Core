#[cfg(test)]
mod replay_tests;
mod nonce_registry;
pub use nonce_registry::NonceRegistry;
pub use nonce_registry::GLOBAL_NONCE_REGISTRY;
mod legacy_nonce;
pub use legacy_nonce::*;
use sentinel_store::{EventKind, EventRecord, EventStore, FileEventStore};

/// Load all IdentityEvents from the event log and reduce to current state
pub fn load_identity_state_from_event_log(event_log_path: &str) -> Result<IdentityState, String> {
    let store = FileEventStore::open(event_log_path)
        .map_err(|e| format!("Failed to open event log: {:?}", e))?;
    let records = store
        .iter()
        .map_err(|e| format!("Failed to read event log: {:?}", e))?;
    let mut events = Vec::new();
    for rec in records {
        if let EventKind::AuthorizationRequestReceived = rec.kind {
            // Not an identity event, skip
            continue;
        }
        // Try to parse as IdentityEvent
        match serde_json::from_value::<IdentityEvent>(rec.payload) {
            Ok(ev) => events.push(ev),
            Err(_) => continue, // Not an identity event, skip
        }
    }
    IdentityState::reduce(events)
}
use sentinel_core::{
    ActorRegistered, IdentityEvent, KeyRegistered, KeyRevoked, KeyRotated, NonceConsumed,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ActorInfo {
    pub actor_id: Uuid,
    pub human_handle: Option<String>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub public_key: Vec<u8>,
    pub registered_at: DateTime<Utc>,
    pub status: KeyStatus,
}

/// Nonce expiration policy: nonces older than this duration are considered expired and ignored for replay protection.
const NONCE_EXPIRATION_SECS: i64 = 24 * 60 * 60; // 24 hours

#[derive(Debug, Default, Clone)]
pub struct IdentityState {
    pub actors: HashMap<Uuid, ActorInfo>,
    pub keys: HashMap<(Uuid, Uuid), KeyInfo>, // (actor_id, key_id)
    pub public_keys: HashSet<Vec<u8>>,        // For duplicate detection
    /// (actor_id, key_id, nonce, envelope_digest, consumed_at)
    pub used_nonces: HashSet<(Uuid, Uuid, Uuid, String, DateTime<Utc>)>,
}

impl IdentityState {
    /// Reduce events to state, enforcing nonce expiration and replay protection.
    /// Nonces older than NONCE_EXPIRATION_SECS are ignored for replay protection.
    pub fn reduce<I: IntoIterator<Item = IdentityEvent>>(events: I) -> Result<Self, String> {
        let mut state = IdentityState::default();
        for event in events {
            match event {
                IdentityEvent::GenesisCompleted(_) => {
                    // No-op for reducer; genesis is not part of active identity state
                }
                IdentityEvent::ActorRegistered(e) => {
                    if state.actors.contains_key(&e.actor_id) {
                        return Err(format!("Duplicate actor registration: {}", e.actor_id));
                    }
                    state.actors.insert(
                        e.actor_id,
                        ActorInfo {
                            actor_id: e.actor_id,
                            human_handle: e.human_handle,
                            registered_at: e.timestamp_utc,
                        },
                    );
                }
                IdentityEvent::KeyRegistered(e) => {
                    if !state.actors.contains_key(&e.actor_id) {
                        return Err(format!("Key registered for unknown actor: {}", e.actor_id));
                    }
                    if state.keys.contains_key(&(e.actor_id, e.key_id)) {
                        return Err(format!(
                            "Duplicate key registration: actor {} key {}",
                            e.actor_id, e.key_id
                        ));
                    }
                    if state.public_keys.contains(&e.public_key) {
                        return Err("Duplicate public key detected".to_string());
                    }
                    state.public_keys.insert(e.public_key.clone());
                    state.keys.insert(
                        (e.actor_id, e.key_id),
                        KeyInfo {
                            actor_id: e.actor_id,
                            key_id: e.key_id,
                            public_key: e.public_key,
                            registered_at: e.timestamp_utc,
                            status: KeyStatus::Active,
                        },
                    );
                }
                IdentityEvent::KeyRevoked(e) => {
                    let key = state.keys.get_mut(&(e.actor_id, e.key_id)).ok_or_else(|| {
                        format!("Revoke unknown key: actor {} key {}", e.actor_id, e.key_id)
                    })?;
                    if key.status == KeyStatus::Revoked {
                        return Err(format!(
                            "Key already revoked: actor {} key {}",
                            e.actor_id, e.key_id
                        ));
                    }
                    key.status = KeyStatus::Revoked;
                }
                IdentityEvent::KeyRotated(e) => {
                    // Optional: implement strict rotation logic or stub
                    // For now, treat as revoke old + register new
                    let old_key =
                        state
                            .keys
                            .get_mut(&(e.actor_id, e.old_key_id))
                            .ok_or_else(|| {
                                format!(
                                    "Rotate unknown old key: actor {} key {}",
                                    e.actor_id, e.old_key_id
                                )
                            })?;
                    if old_key.status == KeyStatus::Revoked {
                        return Err(format!(
                            "Old key already revoked in rotation: actor {} key {}",
                            e.actor_id, e.old_key_id
                        ));
                    }
                    old_key.status = KeyStatus::Revoked;
                    if state.keys.contains_key(&(e.actor_id, e.new_key_id)) {
                        return Err(format!(
                            "Duplicate new key in rotation: actor {} key {}",
                            e.actor_id, e.new_key_id
                        ));
                    }
                    if state.public_keys.contains(&e.new_public_key) {
                        return Err("Duplicate public key in rotation".to_string());
                    }
                    state.public_keys.insert(e.new_public_key.clone());
                    state.keys.insert(
                        (e.actor_id, e.new_key_id),
                        KeyInfo {
                            actor_id: e.actor_id,
                            key_id: e.new_key_id,
                            public_key: e.new_public_key,
                            registered_at: e.timestamp_utc,
                            status: KeyStatus::Active,
                        },
                    );
                }
                IdentityEvent::NonceConsumed(e) => {
                    if !state.keys.contains_key(&(e.actor_id, e.key_id)) {
                        return Err(format!(
                            "Nonce for unknown key: actor {} key {}",
                            e.actor_id, e.key_id
                        ));
                    }
                    if !matches!(
                        state.keys.get(&(e.actor_id, e.key_id)).unwrap().status,
                        KeyStatus::Active
                    ) {
                        return Err(format!(
                            "Nonce for revoked key: actor {} key {}",
                            e.actor_id, e.key_id
                        ));
                    }
                    // Remove expired nonces from used_nonces (cleanup job)
                    let now = Utc::now();
                    state.used_nonces.retain(|(_, _, _, _, consumed_at)| {
                        (now.signed_duration_since(*consumed_at).num_seconds())
                            < NONCE_EXPIRATION_SECS
                    });
                    // Fail if any NonceConsumed exists for (actor_id, nonce) and is not expired (strongest replay protection)
                    if state
                        .used_nonces
                        .iter()
                        .any(|(aid, _, n, _, _)| *aid == e.actor_id && *n == e.nonce)
                    {
                        return Err(format!(
                            "Nonce reuse detected: actor {} nonce {}",
                            e.actor_id, e.nonce
                        ));
                    }
                    let nonce_tuple = (
                        e.actor_id,
                        e.key_id,
                        e.nonce,
                        e.envelope_digest.clone(),
                        e.consumed_at,
                    );
                    state.used_nonces.insert(nonce_tuple);
                }
            }
        }
        Ok(state)
    }
}

use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBytes {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope<T: Serialize> {
    pub actor_id: ActorId,
    pub key_id: KeyId,
    pub nonce: Uuid,
    pub timestamp_utc: DateTime<Utc>,
    pub payload: T,
    pub signature: SignatureBytes,
}

pub struct Keystore {
    pub keypair: Keypair,
    pub key_id: KeyId,
    pub path: PathBuf,
}

impl Keystore {
    pub fn load_or_create(path: PathBuf) -> Result<Self, String> {
        if path.exists() {
            let mut file =
                File::open(&path).map_err(|e| format!("Failed to open key file: {e}"))?;
            let mut buf = vec![];
            file.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read key file: {e}"))?;
            if buf.len() != SECRET_KEY_LENGTH {
                return Err("Invalid key length".to_string());
            }
            let secret =
                SecretKey::from_bytes(&buf).map_err(|e| format!("Invalid secret key: {e}"))?;
            let public = PublicKey::from(&secret);
            let keypair = Keypair { secret, public };
            let key_id = KeyId(Uuid::new_v4()); // For now, random; can derive from pubkey in future
            Ok(Keystore {
                keypair,
                key_id,
                path,
            })
        } else {
            let mut csprng = OsRng {};
            let keypair = Keypair::generate(&mut csprng);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| format!("Failed to create key file: {e}"))?;
            file.write_all(&keypair.secret.to_bytes())
                .map_err(|e| format!("Failed to write key: {e}"))?;
            let key_id = KeyId(Uuid::new_v4());
            Ok(Keystore {
                keypair,
                key_id,
                path,
            })
        }
    }

    pub fn sign<T: Serialize>(
        &self,
        payload: &T,
        actor_id: &ActorId,
        nonce: &Uuid,
        timestamp_utc: &DateTime<Utc>,
    ) -> Result<SignatureBytes, String> {
        let data = serde_json::to_vec(&(actor_id, &self.key_id, nonce, timestamp_utc, payload))
            .map_err(|e| format!("Failed to serialize for signing: {e}"))?;
        let sig = self.keypair.sign(&data);
        Ok(SignatureBytes {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }
}

pub fn verify_signature<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    public_key: &PublicKey,
) -> Result<(), String> {
    let data = serde_json::to_vec(&(
        &envelope.actor_id,
        &envelope.key_id,
        &envelope.nonce,
        &envelope.timestamp_utc,
        &envelope.payload,
    ))
    .map_err(|e| format!("Failed to serialize for verification: {e}"))?;
    if envelope.signature.algorithm != SignatureAlgorithm::Ed25519 {
        return Err("Unsupported signature algorithm".to_string());
    }
    let sig = Signature::from_bytes(&envelope.signature.bytes)
        .map_err(|e| format!("Invalid signature bytes: {e}"))?;
    public_key
        .verify(&data, &sig)
        .map_err(|e| format!("Signature verification failed: {e}"))
}

pub fn verify_freshness(timestamp: &DateTime<Utc>, max_skew_secs: i64) -> bool {
    let now = Utc::now();
    let diff = (now.timestamp() - timestamp.timestamp()).abs();
    diff <= max_skew_secs
}
