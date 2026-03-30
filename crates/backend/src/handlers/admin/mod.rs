//! Admin API handlers.
//!
//! Provides a JSON:API-style REST interface for managing users, sessions,
//! OAuth 2.0 clients, upstream providers, and policy data. All endpoints
//! require the `urn:pasion:admin` scope (the legacy `urn:mas:admin` scope
//! is also accepted for backward compatibility).
//!
//! The API specification is available as an OpenAPI document served by the
//! [`swagger`] handler.

use crate::handlers::rest::DepotExt;
use crate::salvo_utils::InternalError;
use pasion_templates::{ApiDocContext, Templates};
use salvo::prelude::*;
use serde::Serialize;

mod call_context;
mod model;
mod params;
mod response;
mod schema;
/// Version 1 of the Admin API endpoints.
pub mod v1;

pub use self::call_context::CallContext;

/// Implement [`salvo::oapi::EndpointOutRegister`] for an admin `RouteError`.
///
/// Accepts a list of `(status_code, description)` tuples.  The generated
/// implementation adds each pair as an error response with a JSON error
/// body to the OpenAPI operation.
///
/// # Example
///
/// ```ignore
/// impl_endpoint_out_register!(RouteError, [
///     ("404", "Not found"),
///     ("500", "Internal server error"),
/// ]);
/// ```
macro_rules! impl_endpoint_out_register {
    ($ty:ty, [ $(($status:expr, $desc:expr)),* $(,)? ]) => {
        impl salvo::oapi::EndpointOutRegister for $ty {
            fn register(
                _components: &mut salvo::oapi::Components,
                _operation: &mut salvo::oapi::Operation,
            ) {
                use salvo::oapi::*;

                let error_schema = Object::new()
                    .property("errors", Array::new(
                        Object::new()
                            .property("title", Object::new().schema_type(BasicType::String))
                            .required("title")
                    ));

                $(
                    {
                        let response = Response::new($desc)
                            .add_content("application/json", Content::new(error_schema.clone()));
                        _operation.responses.insert($status, RefOr::Type(response));
                    }
                )*
            }
        }
    };
}

pub(crate) use impl_endpoint_out_register;

/// Common error response shape for admin API endpoints.
///
/// Individual handlers keep their own `RouteError` enums but can convert
/// to this shared shape for consistent JSON error bodies.
#[derive(Serialize)]
pub struct AdminErrorResponse {
    /// A short machine-readable error code or label.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: Option<String>,
    /// An optional request identifier for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

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

#[endpoint]
pub async fn swagger(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = depot.url_builder()?;
    let templates = depot.templates()?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}

#[endpoint]
pub async fn swagger_callback(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = depot.url_builder()?;
    let templates = depot.templates()?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger_callback(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}
