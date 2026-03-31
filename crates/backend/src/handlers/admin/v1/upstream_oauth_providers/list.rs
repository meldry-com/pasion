use pasion_data::{Page, upstream_oauth2::UpstreamOAuthProviderFilter};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UpstreamOAuthProvider},
    params::{IncludeCount, extract_pagination},
    response::PaginatedResponse,
};
use crate::JsonResult;

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UpstreamOAuthProviderFilter")]
pub struct FilterParams {
    /// Retrieve providers that are (or are not) enabled
    #[serde(rename = "filter[enabled]")]
    enabled: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(enabled) = self.enabled {
            write!(f, "{sep}filter[enabled]={enabled}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<UpstreamOAuthProvider>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = UpstreamOAuthProvider::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UpstreamOAuthProviderFilter::new();

    let filter = match params.enabled {
        Some(true) => filter.enabled_only(),
        Some(false) => filter.disabled_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            let count = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
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
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use pasion_iana::jose::JsonWebSignatureAlg;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_providers(state: &mut TestState) {
        let mut repo = state.repository().await.unwrap();

        // Create an enabled provider
        let enabled_params = UpstreamOAuthProviderParams {
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

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, enabled_params)
            .await
            .unwrap();

        // Create a disabled provider
        let disabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://appleid.apple.com".to_owned()),
            human_name: Some("Apple ID".to_owned()),
            brand_name: Some("apple".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::S256,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "apple-client-id".to_owned(),
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
            ui_order: 1,
        };

        let disabled_provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, disabled_params)
            .await
            .unwrap();

        // Disable the provider
        repo.upstream_oauth_provider()
            .disable(&state.clock, disabled_provider)
            .await
            .unwrap();

        // Create another enabled provider
        let another_enabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://login.microsoftonline.com/common/v2.0".to_owned()),
            human_name: Some("Microsoft".to_owned()),
            brand_name: Some("microsoft".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "microsoft-client-id".to_owned(),
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
            ui_order: 2,
        };

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, another_enabled_params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();
    }

    #[tokio::test]
    async fn test_list_all_providers() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        // Should return all providers
        assert_eq!(body["data"].as_array().unwrap().len(), 3);

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_enabled_true() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=true")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_enabled_false() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=false")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_pagination() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        create_test_providers(&mut state).await;

        // Test first page with limit of 2
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?page[first]=2")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=2",
            "next": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2"
          }
        }
        "#);

        // Extract the ID of the last item for pagination
        let last_item_id = body["data"][1]["id"].as_str().unwrap();
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers?page[first]=2&page[after]={last_item_id}",
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=2"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;

        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=invalid")
                .bearer(&admin_token)
                .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_count_parameter() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        create_test_providers(&mut state).await;

        // Test count=false
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?count=only")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?count=false&filter[enabled]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?count=only&filter[enabled]=false")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&count=only"
          }
        }
        "#);
    }
}
