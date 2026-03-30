use crate::record_error;
use pasion_data::{RepositoryAccess, upstream_oauth2::UpstreamOAuthProviderRepository};
use salvo::{http::StatusCode, prelude::*};

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UpstreamOAuthProvider,
    params::extract_ulid_param,
    response::{ErrorResponse, SingleResponse},
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Provider not found")]
    NotFound,
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
        };

        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}


impl_endpoint_out_register!(RouteError, [
    ("400", "Bad request"),
    ("401", "Unauthorized"),
    ("404", "Not found"),
    ("409", "Conflict"),
    ("500", "Internal server error"),
]);

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<UpstreamOAuthProvider>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(provider),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use pasion_data::{
        UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use pasion_iana::jose::JsonWebSignatureAlg;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_provider(state: &mut TestState) -> UpstreamOAuthProvider {
        let mut repo = state.repository().await.unwrap();

        let params = UpstreamOAuthProviderParams {
            issuer: Some("https://accounts.google.com".to_owned()),
            human_name: Some("Google".to_owned()),
            brand_name: Some("google".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "google-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 0,
        };

        let provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();

        provider
    }

    #[tokio::test]
    async fn test_get_provider() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let provider = create_test_provider(&mut state).await;

        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers/{}",
            provider.id
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        assert_eq!(body["data"]["type"], "upstream-oauth-provider");
        assert_eq!(body["data"]["id"], provider.id.to_string());
        assert_eq!(body["data"]["attributes"]["human_name"], "Google");

        insta::assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-provider",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "issuer": "https://accounts.google.com",
              "human_name": "Google",
              "brand_name": "google",
              "created_at": "2022-01-16T14:40:00Z",
              "disabled_at": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;

        let provider_id = Ulid::nil();
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers/{provider_id}"
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
