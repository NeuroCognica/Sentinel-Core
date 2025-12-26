//! OpenAPI schema for Sentinel API (feature-gated)
#![cfg(feature = "openapi")]

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        // List all actix-web handler functions here, e.g. whoami, login, challenge, logout
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
    SentinelApiDoc::openapi()
}
