//! OpenAPI specification and Swagger UI for the REST API.
//!
//! This module provides a helper that builds an `OpenApi` document from a
//! router whose handlers are annotated with `#[endpoint]`, and attaches a
//! Swagger UI frontend so that developers can explore the API interactively.

use salvo::{
    oapi::{OpenApi, swagger_ui::SwaggerUi},
    prelude::*,
};

/// Build an OpenAPI document from the given `router` and return a new router
/// that serves both the JSON spec and the Swagger UI.
///
/// # Arguments
///
/// * `router` - The router whose `#[endpoint]` handlers will be introspected to
///   produce the OpenAPI spec.
///
/// # Returns
///
/// A `Router` that serves:
///
/// * `GET /api-doc/openapi.json` - The generated OpenAPI 3.x JSON document.
/// * `GET /swagger-ui/**` - The Swagger UI single-page application.
pub fn build_openapi_router(router: &Router) -> Router {
    build_openapi_router_with_prefix(router, "")
}

/// Build docs whose schema and Swagger requests stay under the HTTP mount.
pub fn build_openapi_router_with_prefix(router: &Router, prefix: &str) -> Router {
    let prefix = prefix.trim_end_matches('/');
    let doc = OpenApi::new("Pasion REST API", env!("CARGO_PKG_VERSION"))
        .merge_router(router)
        .servers([salvo::oapi::Server::new(if prefix.is_empty() {
            "/"
        } else {
            prefix
        })]);
    Router::new()
        .push(doc.into_router("/api-doc/openapi.json"))
        .push(SwaggerUi::new(format!("{prefix}/api-doc/openapi.json")).into_router("swagger-ui"))
}
