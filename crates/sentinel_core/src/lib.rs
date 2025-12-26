/// Capability model and events for append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub capability_id: Uuid,
    pub actor_id: Uuid,
    pub issued_at_utc: DateTime<Utc>,
    pub expires_at_utc: DateTime<Utc>,
    pub scope: String,
    pub actions: Vec<String>,
    pub constraints: Option<serde_json::Value>, // Flexible, e.g. artifact digests, rate limits
    pub issued_by: String,                      // Sentinel service identity
    pub token_signature: Vec<u8>,               // Ed25519 signature over canonical fields
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityEvent {
    CapabilityIssued(CapabilityIssued),
    CapabilityRevoked(CapabilityRevoked),
    CapabilityConsumed(CapabilityConsumed),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityIssued {
    pub capability: Capability,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRevoked {
    pub capability_id: Uuid,
    pub revoked_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityConsumed {
    pub capability_id: Uuid,
    pub consumed_at: DateTime<Utc>,
    pub envelope_digest: String, // SHA-256 of the envelope that used it
}
/// Identity lifecycle events for append-only ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityEvent {
    ActorRegistered(ActorRegistered),
    KeyRegistered(KeyRegistered),
    KeyRevoked(KeyRevoked),
    KeyRotated(KeyRotated), // Optional, can be stubbed for now
    NonceConsumed(NonceConsumed),
    GenesisCompleted(GenesisCompleted),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisCompleted {
    pub completed_at: DateTime<Utc>,
    pub admin_actor_id: Uuid,
    pub admin_key_id: Uuid,
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
    pub envelope_digest: String, // hex-encoded SHA-256 of canonical envelope
    pub consumed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthChallengeIssued {
    pub challenge: String,
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub issued_at_utc: DateTime<Utc>,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthChallengeConsumed {
    pub challenge: String,
    pub actor_id: Uuid,
    pub key_id: Uuid,
    pub consumed_at_utc: DateTime<Utc>,
}
// sentinel_core: types, policy engine interfaces, guard logic, error types

use serde::{Deserialize, Serialize};
// ...existing code...
use chrono::{DateTime, Utc};
use uuid::Uuid;

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
