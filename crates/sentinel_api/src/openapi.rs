//! OpenAPI schema for Sentinel API (feature-gated)
#![cfg(feature = "openapi")]

use serde_json::Value as JsonValue;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        // Consent-gated and core handlers (listed so generator includes them)
        sentinel_api::artifact_register,
        sentinel_api::artifact_use,
        sentinel_api::capability_issue,
        sentinel_api::privileged_action,
        sentinel_api::policy_evaluate,
        sentinel_api::auth_login,
        sentinel_api::auth_challenge,
        sentinel_api::genesis,
        sentinel_api::health,
        sentinel_api::auth_logout
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

    // Inject components that reference the external boundary semantics YAML
    // Use relative path to docs file so the bundler can resolve or the publisher can merge later
    let external_components = serde_json::json!({
        "schemas": {
            "CanonicalEnvelope": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/schemas/CanonicalEnvelope" }
        },
        "responses": {
            "MALFORMED_ENVELOPE_400": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/responses/MALFORMED_ENVELOPE_400" },
            "UNPROVEN_IDENTITY_401": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/responses/UNPROVEN_IDENTITY_401" },
            "WITHHELD_AUTHORITY_403": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/responses/WITHHELD_AUTHORITY_403" },
            "TEMPORAL_VIOLATION_409": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/responses/TEMPORAL_VIOLATION_409" },
            "INVARIANT_BREACH_500": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/responses/INVARIANT_BREACH_500" }
        },
        "securitySchemes": {
            "EnvelopeAuth": { "$ref": "./docs/api/boundary_semantics_openapi.yaml#/components/securitySchemes/EnvelopeAuth" }
        }
    });

    v["components"] = external_components;

    // Deserialize back into OpenApi struct
    let merged: utoipa::openapi::OpenApi = serde_json::from_value(v).expect("deserialize modified openapi");
    merged
}
