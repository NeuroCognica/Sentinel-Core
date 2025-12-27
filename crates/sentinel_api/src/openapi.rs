//! OpenAPI schema for Sentinel API (feature-gated)
#![cfg(feature = "openapi")]

use serde_json::Value as JsonValue;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        // Consent-gated and core handlers (listed so generator includes them)
        crate::artifact_register,
        crate::artifact_use,
        crate::capability_issue,
        crate::privileged_action,
        crate::policy_evaluate,
        crate::auth_login,
        crate::auth_challenge,
        crate::genesis,
        crate::health
    ),
    components(
        // List all request/response types here
    ),
    tags(
        (name = "Sentinel API", description = "Privileged, event-sourced endpoints")
    )
)]
pub struct SentinelApiDoc;

pub fn generate_openapi() -> utoipa::openapi::OpenApi {
    // Generate base OpenAPI from code-first definitions
    let api = SentinelApiDoc::openapi();

    // Serialize to JSON value so we can inject external component $ref links
    let mut v: JsonValue = serde_json::to_value(&api).expect("serialize openapi to json");

    // Merge components from the external boundary semantics YAML into generated OpenAPI.
    // If the YAML file is not present or fails to parse, fall back to leaving generated components intact.
    let yaml_path = "docs/api/boundary_semantics_openapi.yaml";
    if let Ok(yaml_str) = std::fs::read_to_string(yaml_path) {
        if let Ok(ext_val) = serde_yaml::from_str::<serde_json::Value>(&yaml_str) {
            if let Some(ext_components) = ext_val.get("components") {
                // Ensure v["components"] is an object
                if !v.get("components").is_some() || !v["components"].is_object() {
                    v["components"] = serde_json::json!({});
                }
                // Merge each key from ext_components into v["components"] (shallow merge)
                if let (Some(components_map), Some(ext_map)) = (v.get_mut("components"), ext_components.as_object()) {
                    for (k, vext) in ext_map.iter() {
                        components_map.as_object_mut().unwrap().insert(k.clone(), vext.clone());
                    }
                }
            }
        }
    }

    // Inject canonical schema from aura if present. This ensures the CanonicalEnvelope
    // in the generated OpenAPI exactly matches the authoritative file.
    let canonical_path = "../aura/schemas/CanonicalEnvelope.json";
    if let Ok(canon_str) = std::fs::read_to_string(canonical_path) {
        if let Ok(canon_json) = serde_json::from_str::<serde_json::Value>(&canon_str) {
            if !v.get("components").is_some() || !v["components"].is_object() {
                v["components"] = serde_json::json!({});
            }
            if !v["components"].get("schemas").is_some() || !v["components"]["schemas"].is_object() {
                v["components"]["schemas"] = serde_json::json!({});
            }
            v["components"]["schemas"]["CanonicalEnvelope"] = canon_json;
        }
    }

    // Deserialize back into OpenApi struct
    // Attempt to deserialize into `utoipa::openapi::OpenApi`.
    // If deserialization fails due to untagged enums (RefOr) or similar
    // incompatibilities introduced by merging external YAML, the caller
    // may prefer the raw merged JSON. We keep this function for
    // compatibility but panic with a helpful error when deserialization
    // fails so callers can opt to use `generate_openapi_json` instead.
    match serde_json::from_value(v.clone()) {
        Ok(merged) => merged,
        Err(e) => panic!("deserialize modified openapi: {e}"),
    }
}

/// Generate merged OpenAPI as a raw JSON `Value` by combining
/// code-first output with external YAML components. This avoids
/// deserialization back into `utoipa` types and is suitable for
/// emitting `openapi.json` directly.
pub fn generate_openapi_json() -> serde_json::Value {
    let api = SentinelApiDoc::openapi();
    let mut v: JsonValue = serde_json::to_value(&api).expect("serialize openapi to json");

    let yaml_path = "docs/api/boundary_semantics_openapi.yaml";
    if let Ok(yaml_str) = std::fs::read_to_string(yaml_path) {
        if let Ok(ext_val) = serde_yaml::from_str::<serde_json::Value>(&yaml_str) {
            if let Some(ext_components) = ext_val.get("components") {
                if !v.get("components").is_some() || !v["components"].is_object() {
                    v["components"] = serde_json::json!({});
                }
                if let (Some(components_map), Some(ext_map)) = (v.get_mut("components"), ext_components.as_object()) {
                    for (k, vext) in ext_map.iter() {
                        components_map.as_object_mut().unwrap().insert(k.clone(), vext.clone());
                    }
                }
            }
        }

            // Also inject canonical schema when generating raw JSON
            let canonical_path = "../aura/schemas/CanonicalEnvelope.json";
            if let Ok(canon_str) = std::fs::read_to_string(canonical_path) {
                if let Ok(canon_json) = serde_json::from_str::<serde_json::Value>(&canon_str) {
                    if !v.get("components").is_some() || !v["components"].is_object() {
                        v["components"] = serde_json::json!({});
                    }
                    if !v["components"].get("schemas").is_some() || !v["components"]["schemas"].is_object() {
                        v["components"]["schemas"] = serde_json::json!({});
                    }
                    v["components"]["schemas"]["CanonicalEnvelope"] = canon_json;
                }
            }
    }

    v
}
