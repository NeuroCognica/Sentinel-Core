use sha2::{Digest, Sha256};
use serde_json::Value;
use std::fs;

fn derive_seal_hash(proof: &Value) -> String {
    let envelope_digest = proof["envelope_digest"].as_str().unwrap();
    let executor_id = proof["executor"]["executor_id"].as_str().unwrap();

    let mut artifact_digests: Vec<&str> = proof["artifacts"]
        .as_array().unwrap()
        .iter()
        .map(|a| a["artifact_digest"].as_str().unwrap())
        .collect();

    artifact_digests.sort_unstable();

    let outcome_status = proof["outcome"]["status"].as_str().unwrap();

    let mut material = String::new();
    material.push_str(envelope_digest);
    material.push_str(executor_id);
    for d in artifact_digests {
        material.push_str(d);
    }
    material.push_str(outcome_status);

    let hash = Sha256::digest(material.as_bytes());
    hex::encode(hash)
}

#[test]
fn execution_proof_seal_parity_rust() {
    // Locate the shared fixture by walking up from the crate manifest directory.
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut data = None;
    for _ in 0..8 {
        let candidate = dir.join("tests/fixtures/execution_proof.json");
        if candidate.exists() {
            data = Some(fs::read_to_string(&candidate).expect("failed to read fixture"));
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    let data = data.expect("fixture missing: tests/fixtures/execution_proof.json not found in parent paths");

    let proof: Value = serde_json::from_str(&data).unwrap();

    let seal_hash = derive_seal_hash(&proof);

    assert_eq!(
        seal_hash,
        "8776e2333c9a1f3d13e1d9efedc2f98300663d4c383286ff5204d689edd15246"
    );
}
