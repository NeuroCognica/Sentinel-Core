use sentinel_core::{IdentityEvent, ActorRegistered, KeyRegistered, KeyRevoked, KeyRotated, NonceConsumed};
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

#[derive(Debug, Default, Clone)]
pub struct IdentityState {
    pub actors: HashMap<Uuid, ActorInfo>,
    pub keys: HashMap<(Uuid, Uuid), KeyInfo>, // (actor_id, key_id)
    pub public_keys: HashSet<Vec<u8>>, // For duplicate detection
    pub used_nonces: HashSet<(Uuid, Uuid, Uuid)>, // (actor_id, key_id, nonce)
}

impl IdentityState {
    pub fn reduce<I: IntoIterator<Item = IdentityEvent>>(events: I) -> Result<Self, String> {
        let mut state = IdentityState::default();
        for event in events {
            match event {
                IdentityEvent::ActorRegistered(e) => {
                    if state.actors.contains_key(&e.actor_id) {
                        return Err(format!("Duplicate actor registration: {}", e.actor_id));
                    }
                    state.actors.insert(e.actor_id, ActorInfo {
                        actor_id: e.actor_id,
                        human_handle: e.human_handle,
                        registered_at: e.timestamp_utc,
                    });
                }
                IdentityEvent::KeyRegistered(e) => {
                    if !state.actors.contains_key(&e.actor_id) {
                        return Err(format!("Key registered for unknown actor: {}", e.actor_id));
                    }
                    if state.keys.contains_key(&(e.actor_id, e.key_id)) {
                        return Err(format!("Duplicate key registration: actor {} key {}", e.actor_id, e.key_id));
                    }
                    if state.public_keys.contains(&e.public_key) {
                        return Err("Duplicate public key detected".to_string());
                    }
                    state.public_keys.insert(e.public_key.clone());
                    state.keys.insert((e.actor_id, e.key_id), KeyInfo {
                        actor_id: e.actor_id,
                        key_id: e.key_id,
                        public_key: e.public_key,
                        registered_at: e.timestamp_utc,
                        status: KeyStatus::Active,
                    });
                }
                IdentityEvent::KeyRevoked(e) => {
                    let key = state.keys.get_mut(&(e.actor_id, e.key_id)).ok_or_else(|| format!("Revoke unknown key: actor {} key {}", e.actor_id, e.key_id))?;
                    if key.status == KeyStatus::Revoked {
                        return Err(format!("Key already revoked: actor {} key {}", e.actor_id, e.key_id));
                    }
                    key.status = KeyStatus::Revoked;
                }
                IdentityEvent::KeyRotated(e) => {
                    // Optional: implement strict rotation logic or stub
                    // For now, treat as revoke old + register new
                    let old_key = state.keys.get_mut(&(e.actor_id, e.old_key_id)).ok_or_else(|| format!("Rotate unknown old key: actor {} key {}", e.actor_id, e.old_key_id))?;
                    if old_key.status == KeyStatus::Revoked {
                        return Err(format!("Old key already revoked in rotation: actor {} key {}", e.actor_id, e.old_key_id));
                    }
                    old_key.status = KeyStatus::Revoked;
                    if state.keys.contains_key(&(e.actor_id, e.new_key_id)) {
                        return Err(format!("Duplicate new key in rotation: actor {} key {}", e.actor_id, e.new_key_id));
                    }
                    if state.public_keys.contains(&e.new_public_key) {
                        return Err("Duplicate public key in rotation".to_string());
                    }
                    state.public_keys.insert(e.new_public_key.clone());
                    state.keys.insert((e.actor_id, e.new_key_id), KeyInfo {
                        actor_id: e.actor_id,
                        key_id: e.new_key_id,
                        public_key: e.new_public_key,
                        registered_at: e.timestamp_utc,
                        status: KeyStatus::Active,
                    });
                }
                IdentityEvent::NonceConsumed(e) => {
                    if !state.keys.contains_key(&(e.actor_id, e.key_id)) {
                        return Err(format!("Nonce for unknown key: actor {} key {}", e.actor_id, e.key_id));
                    }
                    if !matches!(state.keys.get(&(e.actor_id, e.key_id)).unwrap().status, KeyStatus::Active) {
                        return Err(format!("Nonce for revoked key: actor {} key {}", e.actor_id, e.key_id));
                    }
                    let nonce_tuple = (e.actor_id, e.key_id, e.nonce);
                    if state.used_nonces.contains(&nonce_tuple) {
                        return Err(format!("Nonce reuse detected: actor {} key {} nonce {}", e.actor_id, e.key_id, e.nonce));
                    }
                    state.used_nonces.insert(nonce_tuple);
                }
            }
        }
        Ok(state)
    }
}

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

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
            let mut file = File::open(&path).map_err(|e| format!("Failed to open key file: {e}"))?;
            let mut buf = vec![];
            file.read_to_end(&mut buf).map_err(|e| format!("Failed to read key file: {e}"))?;
            if buf.len() != SECRET_KEY_LENGTH {
                return Err("Invalid key length".to_string());
            }
            let secret = SecretKey::from_bytes(&buf).map_err(|e| format!("Invalid secret key: {e}"))?;
            let public = PublicKey::from(&secret);
            let keypair = Keypair { secret, public };
            let key_id = KeyId(Uuid::new_v4()); // For now, random; can derive from pubkey in future
            Ok(Keystore { keypair, key_id, path })
        } else {
            let mut csprng = OsRng {};
            let keypair = Keypair::generate(&mut csprng);
            let mut file = OpenOptions::new().write(true).create_new(true).open(&path)
                .map_err(|e| format!("Failed to create key file: {e}"))?;
            file.write_all(&keypair.secret.to_bytes()).map_err(|e| format!("Failed to write key: {e}"))?;
            let key_id = KeyId(Uuid::new_v4());
            Ok(Keystore { keypair, key_id, path })
        }
    }

    pub fn sign<T: Serialize>(&self, payload: &T, actor_id: &ActorId, nonce: &Uuid, timestamp_utc: &DateTime<Utc>) -> Result<SignatureBytes, String> {
        let data = serde_json::to_vec(&(actor_id, &self.key_id, nonce, timestamp_utc, payload)).map_err(|e| format!("Failed to serialize for signing: {e}"))?;
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
    )).map_err(|e| format!("Failed to serialize for verification: {e}"))?;
    if envelope.signature.algorithm != SignatureAlgorithm::Ed25519 {
        return Err("Unsupported signature algorithm".to_string());
    }
    let sig = Signature::from_bytes(&envelope.signature.bytes).map_err(|e| format!("Invalid signature bytes: {e}"))?;
    public_key.verify(&data, &sig).map_err(|e| format!("Signature verification failed: {e}"))
}

pub fn verify_freshness(timestamp: &DateTime<Utc>, max_skew_secs: i64) -> bool {
    let now = Utc::now();
    let diff = (now.timestamp() - timestamp.timestamp()).abs();
    diff <= max_skew_secs
}
