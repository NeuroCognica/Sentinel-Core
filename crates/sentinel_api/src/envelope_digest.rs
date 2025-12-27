use serde_json::Value;
use std::collections::BTreeMap;

pub fn canonicalize_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut btm: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                btm.insert(k, canonicalize_json(v));
            }
            let mut out = serde_json::Map::new();
            for (k, v) in btm {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

pub fn canonical_json_bytes(v: Value) -> Vec<u8> {
    let canon = canonicalize_json(v);
    serde_json::to_vec(&canon).expect("canonical json serialize")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn compute_envelope_digest_hex(
    method: &str,
    path: &str,
    nonce: &str,
    body: Value,
) -> String {
    let payload = serde_json::json!({
        "v": 1,
        "method": method,
        "path": path,
        "nonce": nonce,
        "body": canonicalize_json(body),
    });

    let bytes = canonical_json_bytes(payload);
    sha256_hex(&bytes)
}
