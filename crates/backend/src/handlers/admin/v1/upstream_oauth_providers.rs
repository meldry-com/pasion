// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::{
    RepositoryAccess, UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderSource,
    audit::AdminOperation,
    upstream_oauth2::{
        UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    },
};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use url::Url;

use crate::{
    AppError, AppResult, CreatedJsonResult, JsonResult,
    handlers::{
        admin::{
            call_context::extract_call_context,
            model::{Resource, UpstreamOAuthProvider},
            params::{IncludeCount, extract_pagination, extract_ulid_param},
            response::{PaginatedResponse, SingleResponse},
        },
        common::DepotExt as _,
    },
};

/// Fetch a single upstream OAuth provider by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.get", skip_all)]
pub async fn get_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let provider_id = extract_ulid_param(req)?;

    let entry = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(entry),
    )))
}

/// Query-string filters for the provider list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UpstreamOAuthProviderFilter")]
pub struct FilterParams {
    /// When set, only return providers matching this enabled/disabled state
    #[serde(rename = "filter[enabled]")]
    enabled: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(flag) = self.enabled {
            write!(f, "{delimiter}filter[enabled]={flag}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List upstream OAuth providers with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.list", skip_all)]
pub async fn list_providers(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req
        .parse_queries()
        .map_err(|error| AppError::bad_request(format!("Invalid filter parameters: {error}")))?;

    let base_url = format!("{path}{params}", path = UpstreamOAuthProvider::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let mut filter = UpstreamOAuthProviderFilter::new();

    // Apply the enabled/disabled constraint when requested
    filter = match params.enabled {
        Some(true) => filter.enabled_only(),
        Some(false) => filter.disabled_only(),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            let total = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            PaginatedResponse::for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

/// JSON request body for creating an upstream OAuth provider.
///
/// Mirrors [`UpstreamOAuthProviderParams`] but accepts the client secret in
/// plaintext (the server encrypts it before persisting) and accepts enums as
/// strings to keep the API stable across data-layer refactors.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UpstreamOAuthProviderRequest")]
pub struct ProviderRequest {
    issuer: Option<String>,
    human_name: Option<String>,
    brand_name: Option<String>,
    /// Space-separated OAuth scope, e.g. "openid email profile"
    scope: String,
    /// One of: none, client_secret_basic, client_secret_post,
    /// client_secret_jwt, private_key_jwt, sign_in_with_apple, qq_connect,
    /// feishu, lark, dingtalk, wechat, wecom
    token_endpoint_auth_method: String,
    token_endpoint_signing_alg: Option<String>,
    /// JWS algorithm name, e.g. "RS256"
    id_token_signed_response_alg: String,
    #[serde(default)]
    fetch_userinfo: bool,
    userinfo_signed_response_alg: Option<String>,
    client_id: String,
    /// Plaintext client secret. Encrypted server-side before being persisted.
    client_secret: Option<String>,
    /// Claims-import configuration as JSON. See
    /// [`UpstreamOAuthProviderClaimsImports`].
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    claims_imports: serde_json::Value,
    authorization_endpoint_override: Option<Url>,
    token_endpoint_override: Option<Url>,
    userinfo_endpoint_override: Option<Url>,
    jwks_uri_override: Option<Url>,
    /// One of: oidc, insecure, disabled
    #[serde(default = "default_discovery_mode")]
    discovery_mode: String,
    /// One of: auto, s256, disabled
    #[serde(default = "default_pkce_mode")]
    pkce_mode: String,
    /// One of: query, form_post
    response_mode: Option<String>,
    #[serde(default)]
    additional_authorization_parameters: Vec<(String, String)>,
    #[serde(default)]
    forward_login_hint: bool,
    #[serde(default)]
    ui_order: i32,
    /// One of: do_nothing, logout_browser_only, logout_all
    #[serde(default = "default_on_backchannel_logout")]
    on_backchannel_logout: String,
}

fn default_discovery_mode() -> String {
    "oidc".to_owned()
}
fn default_pkce_mode() -> String {
    "auto".to_owned()
}
fn default_on_backchannel_logout() -> String {
    "do_nothing".to_owned()
}

fn parse_field<T>(field: &str, value: &str) -> Result<T, AppError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|e| AppError::bad_request(format!("{field}: {e}")))
}

fn parse_optional_field<T>(field: &str, value: Option<&str>) -> Result<Option<T>, AppError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.map(|v| parse_field(field, v)).transpose()
}

fn parse_claims_imports(
    value: serde_json::Value,
) -> Result<UpstreamOAuthProviderClaimsImports, AppError> {
    if value.is_null() {
        return Ok(UpstreamOAuthProviderClaimsImports::default());
    }
    serde_json::from_value(value).map_err(|e| AppError::bad_request(format!("claims_imports: {e}")))
}

fn encrypt_client_secret(
    encrypter: &pasion_keystore::Encrypter,
    secret: &str,
) -> Result<String, AppError> {
    encrypter
        .encrypt_to_string(secret.as_bytes())
        .map_err(AppError::internal)
}

fn parse_request(
    body: ProviderRequest,
    encrypter: &pasion_keystore::Encrypter,
    source: UpstreamOAuthProviderSource,
) -> Result<UpstreamOAuthProviderParams, AppError> {
    let encrypted_client_secret = body
        .client_secret
        .as_deref()
        .map(|secret| encrypt_client_secret(encrypter, secret))
        .transpose()?;

    Ok(UpstreamOAuthProviderParams {
        scope: parse_field("scope", &body.scope)?,
        token_endpoint_auth_method: parse_field(
            "token_endpoint_auth_method",
            &body.token_endpoint_auth_method,
        )?,
        token_endpoint_signing_alg: parse_optional_field(
            "token_endpoint_signing_alg",
            body.token_endpoint_signing_alg.as_deref(),
        )?,
        id_token_signed_response_alg: parse_field(
            "id_token_signed_response_alg",
            &body.id_token_signed_response_alg,
        )?,
        userinfo_signed_response_alg: parse_optional_field(
            "userinfo_signed_response_alg",
            body.userinfo_signed_response_alg.as_deref(),
        )?,
        discovery_mode: parse_field("discovery_mode", &body.discovery_mode)?,
        pkce_mode: parse_field("pkce_mode", &body.pkce_mode)?,
        response_mode: parse_optional_field("response_mode", body.response_mode.as_deref())?,
        on_backchannel_logout: parse_field("on_backchannel_logout", &body.on_backchannel_logout)?,
        claims_imports: parse_claims_imports(body.claims_imports)?,
        issuer: body.issuer,
        human_name: body.human_name,
        brand_name: body.brand_name,
        fetch_userinfo: body.fetch_userinfo,
        client_id: body.client_id,
        encrypted_client_secret,
        authorization_endpoint_override: body.authorization_endpoint_override,
        token_endpoint_override: body.token_endpoint_override,
        userinfo_endpoint_override: body.userinfo_endpoint_override,
        jwks_uri_override: body.jwks_uri_override,
        additional_authorization_parameters: body.additional_authorization_parameters,
        forward_login_hint: body.forward_login_hint,
        ui_order: body.ui_order,
        source,
    })
}

/// JSON request body for partially updating an upstream OAuth provider.
///
/// Every field is optional and omitted fields keep their current value.
/// Nullable fields (e.g. `brand_name`, endpoint overrides) can be cleared by
/// sending an explicit `null`. The same applies to `client_secret`: omit it
/// to keep the stored secret, send `null` to remove it, or send a string to
/// replace it.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UpstreamOAuthProviderPatchRequest", deny_unknown_fields)]
pub struct ProviderPatchRequest {
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    issuer: Option<Option<String>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    human_name: Option<Option<String>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    brand_name: Option<Option<String>>,
    scope: Option<String>,
    token_endpoint_auth_method: Option<String>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    token_endpoint_signing_alg: Option<Option<String>>,
    id_token_signed_response_alg: Option<String>,
    fetch_userinfo: Option<bool>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    userinfo_signed_response_alg: Option<Option<String>>,
    client_id: Option<String>,
    /// Plaintext client secret. Encrypted server-side before being persisted.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    client_secret: Option<Option<String>>,
    /// Replaces the whole claims-import configuration when present.
    #[schemars(with = "Option<serde_json::Value>")]
    claims_imports: Option<serde_json::Value>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<Url>")]
    authorization_endpoint_override: Option<Option<Url>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<Url>")]
    token_endpoint_override: Option<Option<Url>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<Url>")]
    userinfo_endpoint_override: Option<Option<Url>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<Url>")]
    jwks_uri_override: Option<Option<Url>>,
    discovery_mode: Option<String>,
    pkce_mode: Option<String>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schemars(with = "Option<String>")]
    response_mode: Option<Option<String>>,
    additional_authorization_parameters: Option<Vec<(String, String)>>,
    forward_login_hint: Option<bool>,
    ui_order: Option<i32>,
    on_backchannel_logout: Option<String>,
}

/// Apply a PATCH body on top of an existing provider, returning the full set
/// of parameters to persist together with the names of the fields that were
/// present in the request (for the audit log).
fn apply_patch(
    existing: pasion_data::UpstreamOAuthProvider,
    body: ProviderPatchRequest,
    encrypter: &pasion_keystore::Encrypter,
) -> Result<(UpstreamOAuthProviderParams, Vec<&'static str>), AppError> {
    let mut changed = Vec::new();
    let mut params = UpstreamOAuthProviderParams {
        issuer: existing.issuer,
        human_name: existing.human_name,
        brand_name: existing.brand_name,
        scope: existing.scope,
        token_endpoint_auth_method: existing.token_endpoint_auth_method,
        token_endpoint_signing_alg: existing.token_endpoint_signing_alg,
        id_token_signed_response_alg: existing.id_token_signed_response_alg,
        fetch_userinfo: existing.fetch_userinfo,
        userinfo_signed_response_alg: existing.userinfo_signed_response_alg,
        client_id: existing.client_id,
        encrypted_client_secret: existing.encrypted_client_secret,
        claims_imports: existing.claims_imports,
        authorization_endpoint_override: existing.authorization_endpoint_override,
        token_endpoint_override: existing.token_endpoint_override,
        userinfo_endpoint_override: existing.userinfo_endpoint_override,
        jwks_uri_override: existing.jwks_uri_override,
        discovery_mode: existing.discovery_mode,
        pkce_mode: existing.pkce_mode,
        response_mode: existing.response_mode,
        additional_authorization_parameters: existing.additional_authorization_parameters,
        forward_login_hint: existing.forward_login_hint,
        ui_order: existing.ui_order,
        on_backchannel_logout: existing.on_backchannel_logout,
        source: existing.source,
    };

    macro_rules! set {
        ($field:ident, $value:expr) => {{
            params.$field = $value;
            changed.push(stringify!($field));
        }};
    }

    if let Some(v) = body.issuer {
        set!(issuer, v);
    }
    if let Some(v) = body.human_name {
        set!(human_name, v);
    }
    if let Some(v) = body.brand_name {
        set!(brand_name, v);
    }
    if let Some(v) = body.scope {
        set!(scope, parse_field("scope", &v)?);
    }
    if let Some(v) = body.token_endpoint_auth_method {
        set!(
            token_endpoint_auth_method,
            parse_field("token_endpoint_auth_method", &v)?
        );
    }
    if let Some(v) = body.token_endpoint_signing_alg {
        set!(
            token_endpoint_signing_alg,
            parse_optional_field("token_endpoint_signing_alg", v.as_deref())?
        );
    }
    if let Some(v) = body.id_token_signed_response_alg {
        set!(
            id_token_signed_response_alg,
            parse_field("id_token_signed_response_alg", &v)?
        );
    }
    if let Some(v) = body.fetch_userinfo {
        set!(fetch_userinfo, v);
    }
    if let Some(v) = body.userinfo_signed_response_alg {
        set!(
            userinfo_signed_response_alg,
            parse_optional_field("userinfo_signed_response_alg", v.as_deref())?
        );
    }
    if let Some(v) = body.client_id {
        set!(client_id, v);
    }
    if let Some(v) = body.client_secret {
        params.encrypted_client_secret = v
            .as_deref()
            .map(|secret| encrypt_client_secret(encrypter, secret))
            .transpose()?;
        changed.push("client_secret");
    }
    if let Some(v) = body.claims_imports {
        set!(claims_imports, parse_claims_imports(v)?);
    }
    if let Some(v) = body.authorization_endpoint_override {
        set!(authorization_endpoint_override, v);
    }
    if let Some(v) = body.token_endpoint_override {
        set!(token_endpoint_override, v);
    }
    if let Some(v) = body.userinfo_endpoint_override {
        set!(userinfo_endpoint_override, v);
    }
    if let Some(v) = body.jwks_uri_override {
        set!(jwks_uri_override, v);
    }
    if let Some(v) = body.discovery_mode {
        set!(discovery_mode, parse_field("discovery_mode", &v)?);
    }
    if let Some(v) = body.pkce_mode {
        set!(pkce_mode, parse_field("pkce_mode", &v)?);
    }
    if let Some(v) = body.response_mode {
        set!(
            response_mode,
            parse_optional_field("response_mode", v.as_deref())?
        );
    }
    if let Some(v) = body.additional_authorization_parameters {
        set!(additional_authorization_parameters, v);
    }
    if let Some(v) = body.forward_login_hint {
        set!(forward_login_hint, v);
    }
    if let Some(v) = body.ui_order {
        set!(ui_order, v);
    }
    if let Some(v) = body.on_backchannel_logout {
        set!(
            on_backchannel_logout,
            parse_field("on_backchannel_logout", &v)?
        );
    }

    Ok((params, changed))
}

/// Create a new upstream OAuth provider. Always created with `source=manual`.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.add", skip_all)]
pub async fn add_provider(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let encrypter = depot.encrypter().map_err(AppError::internal)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: ProviderRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let params = parse_request(body, &encrypter, UpstreamOAuthProviderSource::Manual)?;

    let provider = repo
        .upstream_oauth_provider()
        .add(&mut rng, &clock, params)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({
            "action": "create",
            "source": provider.source.as_str(),
            "client_id": provider.client_id,
        }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(UpstreamOAuthProvider::from(provider)),
    ))
}

/// Partially update an existing upstream OAuth provider. Only allowed for
/// `source=manual`.
///
/// Fields omitted from the body keep their current value; see
/// [`ProviderPatchRequest`].
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.update", skip_all)]
pub async fn update_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let encrypter = depot.encrypter().map_err(AppError::internal)?;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: ProviderPatchRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let existing = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    if existing.source == UpstreamOAuthProviderSource::Config {
        return Err(AppError::conflict(
            "Provider is managed by the configuration file. Edit the config file and run \
             `pasion config sync` instead.",
        ));
    }

    let (params, changed) = apply_patch(existing, body, &encrypter)?;

    let provider = repo
        .upstream_oauth_provider()
        .upsert(&clock, id, params)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "update", "fields": changed}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(provider),
    )))
}

/// Delete an upstream OAuth provider.
///
/// `source=manual` rows can always be deleted. `source=config` rows can only
/// be deleted once they are also disabled — the expected workflow being:
/// remove the entry from the config file, restart the server (the next sync
/// run soft-disables the orphaned row), then call DELETE here to clean up.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.delete", skip_all)]
pub async fn delete_provider(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    if provider.source == UpstreamOAuthProviderSource::Config && provider.enabled() {
        return Err(AppError::conflict(
            "Provider is managed by the configuration file. Remove it from the config file and \
             restart the server first; once it shows as disabled it can be deleted.",
        ));
    }

    repo.upstream_oauth_provider().delete_by_id(id).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(id),
        serde_json::json!({"action": "delete", "source": provider.source.as_str()}),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Disable a provider (sets `disabled_at`). Allowed for both sources.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.disable", skip_all)]
pub async fn disable_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    let provider = repo
        .upstream_oauth_provider()
        .disable(&clock, provider)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "disable"}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(provider),
    )))
}

/// Re-enable a previously disabled provider. Allowed for both sources.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.enable", skip_all)]
pub async fn enable_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    let provider = repo.upstream_oauth_provider().enable(provider).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "enable"}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(provider),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data::{
        RepositoryAccess, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
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
            source: pasion_data::UpstreamOAuthProviderSource::Config,
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

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "upstream-oauth-provider",
            "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
            "attributes": {
              "issuer": "https://accounts.google.com",
              "human_name": "Google",
              "brand_name": "google",
              "created_at": "2022-01-16T14:40:00Z",
              "disabled_at": null,
              "source": "config",
              "client_id": "google-client-id",
              "has_client_secret": true,
              "scope": "openid",
              "token_endpoint_auth_method": "client_secret_post",
              "token_endpoint_signing_alg": null,
              "id_token_signed_response_alg": "RS256",
              "fetch_userinfo": true,
              "userinfo_signed_response_alg": null,
              "claims_imports": {
                "subject": {
                  "template": null
                },
                "skip_confirmation": false,
                "localpart": {
                  "action": "ignore",
                  "template": null,
                  "on_conflict": "fail"
                },
                "displayname": {
                  "action": "ignore",
                  "template": null
                },
                "email": {
                  "action": "ignore",
                  "template": null
                },
                "avatar": {
                  "action": "ignore",
                  "template": null
                },
                "account_name": {
                  "template": null
                }
              },
              "authorization_endpoint_override": null,
              "token_endpoint_override": null,
              "userinfo_endpoint_override": null,
              "jwks_uri_override": null,
              "discovery_mode": "oidc",
              "pkce_mode": "auto",
              "response_mode": null,
              "additional_authorization_parameters": [],
              "forward_login_hint": false,
              "ui_order": 0,
              "on_backchannel_logout": "do_nothing"
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
          }
        }
        "#);
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
            source: pasion_data::UpstreamOAuthProviderSource::Config,
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
            source: pasion_data::UpstreamOAuthProviderSource::Config,
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
            source: pasion_data::UpstreamOAuthProviderSource::Config,
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
              "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "google-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 0,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0E6J8AS3YVE0HPDQ1"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0EJKVNRAEHJPXJYCA",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z",
                "source": "config",
                "client_id": "apple-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "s256",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 1,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0EJKVNRAEHJPXJYCA"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0EJKVNRAEHJPXJYCA"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0F8Y98RZ6TNATF85Q",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "microsoft-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 2,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0F8Y98RZ6TNATF85Q"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0F8Y98RZ6TNATF85Q"
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
              "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "google-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 0,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0E6J8AS3YVE0HPDQ1"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0F8Y98RZ6TNATF85Q",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "microsoft-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 2,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0F8Y98RZ6TNATF85Q"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0F8Y98RZ6TNATF85Q"
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
              "id": "01FSHN9AG0EJKVNRAEHJPXJYCA",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z",
                "source": "config",
                "client_id": "apple-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "s256",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 1,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0EJKVNRAEHJPXJYCA"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0EJKVNRAEHJPXJYCA"
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
              "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "google-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 0,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0E6J8AS3YVE0HPDQ1"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0EJKVNRAEHJPXJYCA",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z",
                "source": "config",
                "client_id": "apple-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "s256",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 1,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0EJKVNRAEHJPXJYCA"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0EJKVNRAEHJPXJYCA"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=2",
            "next": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG0EJKVNRAEHJPXJYCA&page[first]=2"
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
              "id": "01FSHN9AG0F8Y98RZ6TNATF85Q",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "microsoft-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 2,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0F8Y98RZ6TNATF85Q"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0F8Y98RZ6TNATF85Q"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG0EJKVNRAEHJPXJYCA&page[first]=2",
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
              "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "google-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 0,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0E6J8AS3YVE0HPDQ1"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0EJKVNRAEHJPXJYCA",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z",
                "source": "config",
                "client_id": "apple-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "s256",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 1,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0EJKVNRAEHJPXJYCA"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0EJKVNRAEHJPXJYCA"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0F8Y98RZ6TNATF85Q",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "microsoft-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 2,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0F8Y98RZ6TNATF85Q"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0F8Y98RZ6TNATF85Q"
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
              "id": "01FSHN9AG0E6J8AS3YVE0HPDQ1",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "google-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 0,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0E6J8AS3YVE0HPDQ1"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0E6J8AS3YVE0HPDQ1"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0F8Y98RZ6TNATF85Q",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null,
                "source": "config",
                "client_id": "microsoft-client-id",
                "has_client_secret": true,
                "scope": "openid",
                "token_endpoint_auth_method": "client_secret_post",
                "token_endpoint_signing_alg": null,
                "id_token_signed_response_alg": "RS256",
                "fetch_userinfo": true,
                "userinfo_signed_response_alg": null,
                "claims_imports": {
                  "subject": {
                    "template": null
                  },
                  "skip_confirmation": false,
                  "localpart": {
                    "action": "ignore",
                    "template": null,
                    "on_conflict": "fail"
                  },
                  "displayname": {
                    "action": "ignore",
                    "template": null
                  },
                  "email": {
                    "action": "ignore",
                    "template": null
                  },
                  "avatar": {
                    "action": "ignore",
                    "template": null
                  },
                  "account_name": {
                    "template": null
                  }
                },
                "authorization_endpoint_override": null,
                "token_endpoint_override": null,
                "userinfo_endpoint_override": null,
                "jwks_uri_override": null,
                "discovery_mode": "oidc",
                "pkce_mode": "auto",
                "response_mode": null,
                "additional_authorization_parameters": [],
                "forward_login_hint": false,
                "ui_order": 2,
                "on_backchannel_logout": "do_nothing"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0F8Y98RZ6TNATF85Q"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0F8Y98RZ6TNATF85Q"
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

    fn github_provider_body() -> serde_json::Value {
        serde_json::json!({
            "human_name": "GitHub",
            "brand_name": "github",
            "client_id": "gh-client",
            "client_secret": "gh-secret",
            "scope": "read:user user:email",
            "token_endpoint_auth_method": "client_secret_post",
            "id_token_signed_response_alg": "RS256",
            "discovery_mode": "disabled",
            "authorization_endpoint_override": "https://github.com/login/oauth/authorize",
            "token_endpoint_override": "https://github.com/login/oauth/access_token",
            "userinfo_endpoint_override": "https://api.github.com/user",
            "fetch_userinfo": true,
            "additional_authorization_parameters": [["allow_signup", "false"]],
            "ui_order": 5,
        })
    }

    async fn create_manual_provider(state: &mut TestState, admin_token: &str) -> Ulid {
        let request = Request::post("/api/admin/v1/upstream-oauth-providers")
            .bearer(admin_token)
            .json(github_provider_body());
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        body["data"]["id"].as_str().unwrap().parse().unwrap()
    }

    async fn lookup_provider(state: &mut TestState, id: Ulid) -> UpstreamOAuthProvider {
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();
        Box::new(repo).save().await.unwrap();
        provider
    }

    fn decrypt_secret(state: &TestState, provider: &UpstreamOAuthProvider) -> String {
        let encrypted = provider.encrypted_client_secret.as_deref().unwrap();
        String::from_utf8(state.encrypter.decrypt_string(encrypted).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn test_add_provider_persists_all_fields() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let id = create_manual_provider(&mut state, &admin_token).await;

        let provider = lookup_provider(&mut state, id).await;
        assert_eq!(
            provider.additional_authorization_parameters,
            vec![("allow_signup".to_owned(), "false".to_owned())]
        );
        assert_eq!(provider.ui_order, 5);
        assert_eq!(decrypt_secret(&state, &provider), "gh-secret");

        // The admin API exposes the configuration, but never the secret
        let request = Request::get(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let attributes = &body["data"]["attributes"];
        assert_eq!(attributes["source"], "manual");
        assert_eq!(attributes["client_id"], "gh-client");
        assert_eq!(attributes["has_client_secret"], true);
        assert_eq!(attributes["scope"], "read:user user:email");
        assert_eq!(
            attributes["token_endpoint_auth_method"],
            "client_secret_post"
        );
        assert_eq!(attributes["discovery_mode"], "disabled");
        assert_eq!(
            attributes["token_endpoint_override"],
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            attributes["additional_authorization_parameters"],
            serde_json::json!([["allow_signup", "false"]])
        );
        assert_eq!(attributes["ui_order"], 5);
        assert!(attributes.get("client_secret").is_none());
        assert!(attributes.get("encrypted_client_secret").is_none());
        assert!(!body.to_string().contains("gh-secret"));
    }

    #[tokio::test]
    async fn test_patch_provider_is_partial() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let id = create_manual_provider(&mut state, &admin_token).await;
        let before = lookup_provider(&mut state, id).await;

        // Only the human name changes; everything else, including the secret,
        // must be preserved.
        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
            .bearer(&admin_token)
            .json(serde_json::json!({ "human_name": "GitHub Enterprise" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["human_name"],
            "GitHub Enterprise"
        );
        assert_eq!(body["data"]["attributes"]["client_id"], "gh-client");

        let after = lookup_provider(&mut state, id).await;
        assert_eq!(after.human_name.as_deref(), Some("GitHub Enterprise"));
        assert_eq!(
            UpstreamOAuthProvider {
                human_name: before.human_name.clone(),
                ..after.clone()
            },
            before
        );
        assert_eq!(decrypt_secret(&state, &after), "gh-secret");

        // Explicit null clears nullable fields; a new secret replaces the old one
        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
            .bearer(&admin_token)
            .json(serde_json::json!({
                "brand_name": null,
                "userinfo_endpoint_override": null,
                "client_secret": "rotated",
                "ui_order": 1,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let after = lookup_provider(&mut state, id).await;
        assert_eq!(after.brand_name, None);
        assert_eq!(after.userinfo_endpoint_override, None);
        assert_eq!(after.ui_order, 1);
        assert_eq!(decrypt_secret(&state, &after), "rotated");
        assert_eq!(after.human_name.as_deref(), Some("GitHub Enterprise"));
        assert_eq!(after.client_id, "gh-client");

        // `client_secret: null` removes the secret
        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
            .bearer(&admin_token)
            .json(serde_json::json!({ "client_secret": null }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["has_client_secret"], false);
    }

    #[tokio::test]
    async fn test_patch_provider_keeps_disabled_state() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let id = create_manual_provider(&mut state, &admin_token).await;

        let request = Request::post(format!(
            "/api/admin/v1/upstream-oauth-providers/{id}/disable"
        ))
        .bearer(&admin_token)
        .empty();
        state.request(request).await.assert_status(StatusCode::OK);

        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
            .bearer(&admin_token)
            .json(serde_json::json!({ "scope": "read:user" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert!(body["data"]["attributes"]["disabled_at"].is_string());
        assert!(!lookup_provider(&mut state, id).await.enabled());
    }

    #[tokio::test]
    async fn test_patch_provider_rejects_bad_input() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let id = create_manual_provider(&mut state, &admin_token).await;

        for body in [
            serde_json::json!({ "pkce_mode": "bogus" }),
            serde_json::json!({ "not_a_field": true }),
            serde_json::json!({ "authorization_endpoint_override": "not a url" }),
        ] {
            let request = Request::patch(format!("/api/admin/v1/upstream-oauth-providers/{id}"))
                .bearer(&admin_token)
                .json(body);
            state
                .request(request)
                .await
                .assert_status(StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn test_patch_config_provider_is_rejected() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        let provider = create_test_provider(&mut state).await;

        let request = Request::patch(format!(
            "/api/admin/v1/upstream-oauth-providers/{}",
            provider.id
        ))
        .bearer(&admin_token)
        .json(serde_json::json!({ "human_name": "Renamed" }));
        state
            .request(request)
            .await
            .assert_status(StatusCode::CONFLICT);
    }
}
