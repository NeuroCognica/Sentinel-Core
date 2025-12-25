
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
