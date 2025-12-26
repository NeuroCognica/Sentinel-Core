use uuid::Uuid;

#[test]
fn legacy_nonce_paths_fail_loudly() {
    // The legacy stubs should fail loudly to prevent legacy authority.
    let actor = Uuid::new_v4();
    let nonce = Uuid::new_v4();

    let res = sentinel_identity::validate_nonce(actor, nonce);
    assert!(res.is_err());
    let msg = res.unwrap_err();
    assert!(msg.contains("Canonical nonce middleware required"));
}
