//! Admin API handlers.
//!
//! Provides a JSON:API-style REST interface for managing users, sessions,
//! OAuth 2.0 clients, upstream providers, and policy data. All endpoints
//! require the `urn:pasion:admin` scope (the legacy `urn:mas:admin` scope
//! is also accepted for backward compatibility) *and* a requester whose
//! `can_request_admin` flag is currently set, so revoking the flag cuts off
//! already-issued tokens immediately.
//!
//! The API specification is available as an OpenAPI document served by the
//! [`swagger`] handler.

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
pub(crate) use self::{
    call_context::Rejection as CallContextRejection,
    model::InconsistentPersonalSession,
    params::{PaginationRejection, UlidPathParamRejection},
    response::ErrorResponse,
};

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

/// Returns `true` if the scope token grants administrative power over Pasion
/// or the homeserver (`urn:pasion:admin`, `urn:mas:admin`,
/// `urn:palpo:admin:*`, `urn:synapse:admin:*`).
fn is_privileged_scope_token(token: &str) -> bool {
    token == ADMIN_SCOPE
        || token == ADMIN_SCOPE_LEGACY
        || token.starts_with("urn:palpo:admin")
        || token.starts_with("urn:synapse:admin")
}

/// Remove every administrative scope token from `scope` unless `is_admin`.
///
/// Used when reporting a token's scope to resource servers (introspection),
/// so a demoted user's still-valid token no longer advertises admin access.
#[must_use]
pub fn strip_admin_scope_unless(
    scope: oauth2_types::scope::Scope,
    is_admin: bool,
) -> oauth2_types::scope::Scope {
    if is_admin {
        return scope;
    }
    scope
        .iter()
        .filter(|token| !is_privileged_scope_token(token.as_str()))
        .cloned()
        .collect()
}

/// Returns `true` if the scope contains any administrative scope token.
///
/// Such scopes may only ever be held by a session whose user has
/// `can_request_admin` set, see [`may_hold_admin_scope`].
pub fn requires_admin(scope: &oauth2_types::scope::Scope) -> bool {
    scope
        .iter()
        .any(|token| is_privileged_scope_token(token.as_str()))
}

/// The single source of truth for "is this user an administrator".
///
/// Administrative scopes are granted to, and honoured for, a session only
/// when it is backed by a user whose `can_request_admin` flag is set. There
/// is deliberately no bypass for user-less sessions (client credentials):
/// the policy engine is not trusted to gate these scopes.
pub fn may_hold_admin_scope(user: Option<&pasion_data::User>) -> bool {
    user.is_some_and(|user| user.can_request_admin)
}

/// JSON response wrapper that sets HTTP 201 Created status code.
///
/// Drop-in replacement for `(StatusCode, Json<T>)` tuples that works with
/// Salvo's `#[endpoint]` macro by implementing both [`Scribe`] and
/// [`salvo::oapi::EndpointOutRegister`].
pub struct CreatedJson<T: Serialize + Send>(pub T);

impl<T: Serialize + Send> Scribe for CreatedJson<T> {
    fn render(self, res: &mut Response) {
        res.status_code(StatusCode::CREATED);
        res.render(Json(self.0));
    }
}

impl<T: Serialize + Send + salvo::oapi::ToSchema + 'static> salvo::oapi::EndpointOutRegister
    for CreatedJson<T>
{
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        let schema = T::to_schema(components);
        let response = salvo::oapi::Response::new("Created")
            .add_content("application/json", salvo::oapi::Content::new(schema));
        operation
            .responses
            .insert("201", salvo::oapi::RefOr::Type(response));
    }
}

pub(crate) mod audit_helper;

#[cfg(test)]
mod tests {
    use oauth2_types::scope::Scope;

    use super::{requires_admin, strip_admin_scope_unless};

    #[test]
    fn test_requires_admin() {
        let scope = |s: &str| s.parse::<Scope>().unwrap();
        assert!(requires_admin(&scope("urn:pasion:admin")));
        assert!(requires_admin(&scope("openid urn:mas:admin")));
        assert!(requires_admin(&scope("urn:palpo:admin:users")));
        assert!(requires_admin(&scope("urn:synapse:admin:*")));
        assert!(!requires_admin(&scope("openid")));
        assert!(!requires_admin(&scope(
            "openid urn:matrix:client:api:* urn:matrix:client:device:ABCDEF"
        )));
    }

    #[test]
    fn test_strip_admin_scope_unless() {
        let scope: Scope = "openid urn:pasion:admin urn:palpo:admin:users urn:matrix:client:api:*"
            .parse()
            .unwrap();
        assert_eq!(strip_admin_scope_unless(scope.clone(), true), scope);
        assert_eq!(
            strip_admin_scope_unless(scope, false).to_string(),
            "openid urn:matrix:client:api:*"
        );
    }
}
