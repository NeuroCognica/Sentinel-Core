use crate::policy::Policy;
use sha2::{Digest, Sha256};
use serde_json;
use hex;

/// Compute canonical bytes for a policy using serde_json compact serialization.
/// The schema avoids maps so serialization is deterministic for v0.
pub fn canonical_bytes(policy: &Policy) -> Vec<u8> {
    // Use compact (no whitespace) JSON serialization
    serde_json::to_vec(policy).expect("policy serialization should not fail")
}

/// Compute SHA-256 hex digest over canonical bytes
pub fn policy_digest(policy: &Policy) -> String {
    let bytes = canonical_bytes(policy);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let res = hasher.finalize();
    hex::encode(res)
}

use crate::policy::PolicyInput;

/// Canonical bytes for a PolicyInput (compact JSON)
pub fn canonical_input_bytes(input: &PolicyInput) -> Vec<u8> {
    serde_json::to_vec(input).expect("input serialization should not fail")
}

pub fn input_digest(input: &PolicyInput) -> String {
    let bytes = canonical_input_bytes(input);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let res = hasher.finalize();
    hex::encode(res)
}
