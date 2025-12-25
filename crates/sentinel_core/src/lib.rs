/// Identity lifecycle events for append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityEvent {
    ActorRegistered(ActorRegistered),
    KeyRegistered(KeyRegistered),
    KeyRevoked(KeyRevoked),
    KeyRotated(KeyRotated), // Optional, can be stubbed for now
    NonceConsumed(NonceConsumed),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRegistered {
    pub actor_id: Uuid,
    pub human_handle: Option<String>, // Optional, for display only
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRegistered {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub public_key: Vec<u8>, // Ed25519 public key bytes
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRevoked {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotated {
    pub actor_id: Uuid,
    pub old_key_id: Uuid,
    pub new_key_id: Uuid,
    pub new_public_key: Vec<u8>,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceConsumed {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub nonce: Uuid,
    pub timestamp_utc: DateTime<Utc>,
}
// sentinel_core: types, policy engine interfaces, guard logic, error types

use serde::{Serialize, Deserialize};
// ...existing code...
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Canonical constitutional envelope for all privileged requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalEnvelopeAuthorizationRequest {
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub nonce: Uuid,
    pub timestamp_utc: DateTime<Utc>,
    pub payload: AuthorizationRequest,
    pub signature: Vec<u8>, // Signature bytes (algorithm is fixed for now)
}

/// Minimal authorization payload for Step 1
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub action: String,
    pub scope: String,
    pub intent: String,
}

// No defaults, no optionals, no best effort. This is the constitutional artifact.
