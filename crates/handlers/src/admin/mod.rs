//! Admin API handlers.
//!
//! Provides a JSON:API-style REST interface for managing users, sessions,
//! OAuth 2.0 clients, upstream providers, and policy data. All endpoints
//! require the `urn:pasion:admin` scope (the legacy `urn:mas:admin` scope
//! is also accepted for backward compatibility).
//!
//! The API specification is available as an OpenAPI document served by the
//! [`swagger`] handler.

use crate::rest::DepotExt;
use pasion_router::UrlBuilder;
use pasion_salvo_utils::InternalError;
use pasion_templates::{ApiDocContext, Templates};
use salvo::prelude::*;

mod call_context;
mod model;
mod params;
mod response;
mod schema;
/// Version 1 of the Admin API endpoints.
pub mod v1;

pub use self::call_context::CallContext;

/// The canonical admin scope for the Pasion Admin API.
pub const ADMIN_SCOPE: &str = "urn:pasion:admin";

/// Legacy admin scope, kept for backward compatibility with existing tokens.
pub const ADMIN_SCOPE_LEGACY: &str = "urn:mas:admin";

/// Returns `true` if the given scope string contains either the current or
/// legacy admin scope.
pub fn has_admin_scope(scope: &oauth2_types::scope::Scope) -> bool {
    scope.contains(ADMIN_SCOPE) || scope.contains(ADMIN_SCOPE_LEGACY)
}

/// Render the Swagger UI page for the Admin API documentation.

#[handler]
pub async fn swagger(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = depot.url_builder()?;
    let templates = depot.templates()?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}

#[handler]
pub async fn swagger_callback(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = depot.url_builder()?;
    let templates = depot.templates()?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger_callback(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}
