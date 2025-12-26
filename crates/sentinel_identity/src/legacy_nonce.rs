use uuid::Uuid;

/// Legacy nonce API stubs — intentionally fail to prevent accidental legacy authority.
/// Any attempt to call these functions signals a developer invariant breach.
pub fn consume_nonce(_actor_id: Uuid, _key_id: Uuid, _nonce: Uuid) -> Result<(), String> {
    Err("Legacy nonce validation path reached. Canonical nonce middleware required.".to_string())
}

pub fn validate_nonce(_actor_id: Uuid, _nonce: Uuid) -> Result<(), String> {
    Err("Legacy nonce validation path reached. Canonical nonce middleware required.".to_string())
}

pub fn legacy_nonce_invariant_violation<T>(context: &str) -> Result<T, String> {
    Err(format!("Legacy nonce validation path reached: {context}. Canonical nonce middleware required.", context = context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn legacy_consume_nonce_is_unreachable() {
        let r = consume_nonce(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Canonical nonce middleware required"));
    }

    #[test]
    fn legacy_validate_nonce_is_unreachable() {
        let r = validate_nonce(Uuid::new_v4(), Uuid::new_v4());
        assert!(r.is_err());
    }
}
