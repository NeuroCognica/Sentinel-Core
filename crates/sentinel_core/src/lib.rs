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
