//! Admin API handlers.
//!
//! Provides a JSON:API-style REST interface for managing users, sessions,
//! OAuth 2.0 clients, upstream providers, and policy data. All endpoints
//! require the `urn:mas:admin` scope.
//!
//! The API specification is available as an OpenAPI document served by the
//! [`swagger`] handler.

use salvo::prelude::*;
use pasion_salvo_utils::InternalError;
use pasion_templates::{ApiDocContext, Templates};
use pasion_router::UrlBuilder;

mod call_context;
mod model;
mod params;
mod response;
mod schema;
/// Version 1 of the Admin API endpoints.
pub mod v1;

pub use self::call_context::CallContext;

/// Render the Swagger UI page for the Admin API documentation.

#[handler]
pub async fn swagger(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = crate::rest::get_url_builder(depot)?;
    let templates = crate::rest::get_templates(depot)?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}

#[handler]
pub async fn swagger_callback(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = crate::rest::get_url_builder(depot)?;
    let templates = crate::rest::get_templates(depot)?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger_callback(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}
