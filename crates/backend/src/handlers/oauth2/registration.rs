use std::sync::LazyLock;

use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    oidc::ApplicationType,
    registration::{
        ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
        VerifiedClientMetadata,
    },
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use pasion_data::{
    BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, LocalizedClientMetadata, SystemClock,
    oauth2::OAuth2ClientRepository,
};
use pasion_iana::oauth::OAuthClientAuthenticationMethod;
use pasion_keystore::Encrypter;
use pasion_policy::{EvaluationResult, Policy};
use psl::Psl;
use rand::distr::{Alphanumeric, SampleString};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::prelude::*;
use serde::Serialize;
use sha2::Digest as _;
use thiserror::Error;
use tracing::info;
use url::Url;

use crate::handlers::{METER, common::DepotExt};

static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("pasion.oauth2.registration_request")
        .with_description("Number of OAuth2 registration requests")
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error("invalid json body: {0}")]
    InvalidJson(String),

    #[error("invalid client metadata")]
    InvalidClientMetadata(#[from] ClientMetadataVerificationError),

    #[error("{0} is a public suffix, not a valid domain")]
    UrlIsPublicSuffix(&'static str),

    #[error("invalid Matrix redirect URI: {0}")]
    InvalidMatrixRedirectUri(String),

    #[error("client registration denied by the policy: {0}")]
    PolicyDenied(EvaluationResult),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(pasion_policy::LoadError);
impl_from_error_for_route!(pasion_policy::EvaluationError);
impl_from_error_for_route!(pasion_keystore::aead::Error);
impl_from_error_for_route!(serde_json::Error);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "denied")]);

        match self {
            Self::Internal(_) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::InvalidJson(ref e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.clone()),
                ));
            }

            // This error comes from the `ClientMetadata::validate` method. We return an
            // `invalid_redirect_uri` error if the error is related to the redirect URIs, else we
            // return an `invalid_client_metadata` error.
            Self::InvalidClientMetadata(
                ClientMetadataVerificationError::MissingRedirectUris
                | ClientMetadataVerificationError::RedirectUriWithFragment(_),
            ) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRedirectUri)));
            }

            Self::InvalidClientMetadata(ref e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.to_string()),
                ));
            }

            // This error happens if the any of the client's URIs are public suffixes. We return
            // an `invalid_redirect_uri` error if it's a `redirect_uri`, else we return an
            // `invalid_client_metadata` error.
            Self::UrlIsPublicSuffix("redirect_uri") => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidRedirectUri)
                        .with_description("redirect_uri is not using a valid domain".to_owned()),
                ));
            }

            Self::InvalidMatrixRedirectUri(reason) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidRedirectUri).with_description(reason),
                ));
            }

            Self::UrlIsPublicSuffix(field) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(format!("{field} is not using a valid domain")),
                ));
            }

            // For policy violations, we return an `invalid_client_metadata` error with the details
            // of the violations in most cases. If a violation includes `redirect_uri` in the
            // message, we return an `invalid_redirect_uri` error instead.
            Self::PolicyDenied(ref evaluation) => {
                // TODO: detect them better
                let code = if evaluation
                    .violations
                    .iter()
                    .any(|v| v.msg.contains("redirect_uri"))
                {
                    ClientErrorCode::InvalidRedirectUri
                } else {
                    ClientErrorCode::InvalidClientMetadata
                };

                let collected = &evaluation
                    .violations
                    .iter()
                    .map(|v| v.msg.clone())
                    .collect::<Vec<String>>();
                let joined = collected.join("; ");

                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(code).with_description(joined)));
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

#[derive(Serialize)]
struct RouteResponse {
    #[serde(flatten)]
    response: ClientRegistrationResponse,
    #[serde(flatten)]
    metadata: VerifiedClientMetadata,
}

/// Check if the host of the given URL is a public suffix
fn host_is_public_suffix(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().as_bytes();
    let Some(suffix) = psl::List.suffix(host) else {
        // There is no suffix, which is the case for empty hosts, like with custom
        // schemes
        return false;
    };

    if !suffix.is_known() {
        // The suffix is not known, so it's not a public suffix
        return false;
    }

    // We want to cover two cases:
    // - The host is the suffix itself, like `com`
    // - The host is a dot followed by the suffix, like `.com`
    if host.len() <= suffix.as_bytes().len() + 1 {
        // The host only has the suffix in it, so it's a public suffix
        return true;
    }

    false
}

/// Check if any of the URLs in the given `Localized` field is a public suffix
fn localised_url_has_public_suffix(url: &Localized<Url>) -> bool {
    url.iter().any(|(_lang, url)| host_is_public_suffix(url))
}

/// Apply the Matrix Client-Server API redirect rules at dynamic registration.
/// Static OAuth clients are configured by administrators and are unaffected.
fn validate_matrix_redirect_uris(metadata: &VerifiedClientMetadata) -> Result<(), RouteError> {
    let client_uri = metadata
        .client_uri
        .as_ref()
        .map(Localized::non_localized)
        .ok_or_else(|| RouteError::InvalidMatrixRedirectUri("client_uri is required".into()))?;
    if client_uri.scheme() != "https"
        || client_uri.username() != ""
        || client_uri.password().is_some()
    {
        return Err(RouteError::InvalidMatrixRedirectUri(
            "client_uri must be an HTTPS URL without credentials".into(),
        ));
    }
    let base_host = client_uri.host_str().ok_or_else(|| {
        RouteError::InvalidMatrixRedirectUri("client_uri must have a host".into())
    })?;
    let reverse_dns = base_host.split('.').rev().collect::<Vec<_>>().join(".");
    let native = matches!(&metadata.application_type, Some(ApplicationType::Native));

    for uri in metadata.redirect_uris() {
        let https_client_host = uri.scheme() == "https"
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri
                .host_str()
                .is_some_and(|host| host == base_host || host.ends_with(&format!(".{base_host}")));
        let loopback = uri.scheme() == "http"
            && uri.port().is_none()
            && uri.username().is_empty()
            && uri.password().is_none()
            && (matches!(uri.host_str(), Some("localhost" | "127.0.0.1"))
                || matches!(uri.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback()));
        let private_scheme = uri.host().is_none()
            && uri.scheme() != "http"
            && uri.scheme() != "https"
            && (uri.scheme() == reverse_dns
                || uri.scheme().starts_with(&format!("{reverse_dns}.")));

        if !https_client_host && !(native && (loopback || private_scheme)) {
            return Err(RouteError::InvalidMatrixRedirectUri(format!(
                "redirect_uri is not valid for this client: {uri}"
            )));
        }
    }
    Ok(())
}

/// `Url` removes an explicitly written default HTTP port. Inspect the raw
/// registration value so `http://localhost:80` cannot pass as portless.
fn loopback_redirect_has_explicit_port(uri: &str) -> bool {
    let Ok(parsed) = Url::parse(uri) else {
        return false;
    };
    if parsed.scheme() != "http"
        || !(matches!(parsed.host_str(), Some("localhost" | "127.0.0.1"))
            || matches!(parsed.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback()))
    {
        return false;
    }
    let Some((scheme, rest)) = uri.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, tail)| tail);
    if let Some(after_bracket) = host_port.strip_prefix('[') {
        after_bracket
            .split_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':'))
    } else {
        host_port.contains(':')
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.registration.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(response) => {
            res.status_code(StatusCode::CREATED);
            res.render(Json(response));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(req: &mut Request, depot: &Depot) -> Result<RouteResponse, RouteError> {
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng =
        Box::new(ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;
    let mut policy: Policy = depot
        .policy()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let user_agent: Option<String> = req.header("user-agent");

    // Parse the JSON body
    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|e| RouteError::InvalidJson(e.to_string()))?;
    if raw_body
        .get("redirect_uris")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|uris| {
            uris.iter()
                .filter_map(serde_json::Value::as_str)
                .any(loopback_redirect_has_explicit_port)
        })
    {
        return Err(RouteError::InvalidMatrixRedirectUri(
            "native loopback redirect_uri must not specify a port".into(),
        ));
    }
    let body: ClientMetadata =
        serde_json::from_value(raw_body).map_err(|e| RouteError::InvalidJson(e.to_string()))?;

    // Sort the properties to ensure a stable serialisation order for hashing
    let body = body.sorted();

    // We need to serialize the body to compute the hash, and to log it
    let body_json = serde_json::to_string(&body)?;

    info!(body = body_json, "Client registration");

    // Validate the body
    let metadata = body.validate()?;
    validate_matrix_redirect_uris(&metadata)?;

    // Some extra validation that is hard to do in OPA and not done by the
    // `validate` method either
    if let Some(client_uri) = &metadata.client_uri
        && localised_url_has_public_suffix(client_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("client_uri"));
    }

    if let Some(logo_uri) = &metadata.logo_uri
        && localised_url_has_public_suffix(logo_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("logo_uri"));
    }

    if let Some(policy_uri) = &metadata.policy_uri
        && localised_url_has_public_suffix(policy_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("policy_uri"));
    }

    if let Some(tos_uri) = &metadata.tos_uri
        && localised_url_has_public_suffix(tos_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("tos_uri"));
    }

    if let Some(initiate_login_uri) = &metadata.initiate_login_uri
        && host_is_public_suffix(initiate_login_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("initiate_login_uri"));
    }

    for redirect_uri in metadata.redirect_uris() {
        if host_is_public_suffix(redirect_uri) {
            return Err(RouteError::UrlIsPublicSuffix("redirect_uri"));
        }
    }

    let res = policy
        .evaluate_client_registration(pasion_policy::ClientRegistrationInput {
            client_metadata: &metadata,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;
    if !res.valid() {
        return Err(RouteError::PolicyDenied(res));
    }

    let (client_secret, encrypted_client_secret) = match metadata.token_endpoint_auth_method {
        Some(
            OAuthClientAuthenticationMethod::ClientSecretJwt
            | OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretBasic,
        ) => {
            // Let's generate a random client secret
            let client_secret = Alphanumeric.sample_string(&mut rand::rng(), 20);
            let encrypted_client_secret = encrypter.encrypt_to_string(client_secret.as_bytes())?;
            (Some(client_secret), Some(encrypted_client_secret))
        }
        _ => (None, None),
    };

    // If the client doesn't have a secret, we may be able to deduplicate it. To
    // do so, we hash the client metadata, and look for it in the database
    let (digest_hash, existing_client) = if client_secret.is_none() {
        // XXX: One interesting caveat is that we hash *before* saving to the database.
        // It means it takes into account fields that we don't care about *yet*.
        //
        // This means that if later we start supporting a particular field, we
        // will still serve the 'old' client_id, without updating the client in the
        // database
        let hash = sha2::Sha256::digest(&body_json);
        let hash = hex::encode(hash);
        let client = repo.oauth2_client().find_by_metadata_digest(&hash).await?;
        (Some(hash), client)
    } else {
        (None, None)
    };

    let client = if let Some(client) = existing_client {
        tracing::info!(%client.id, "Reusing existing client");
        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "reused")]);
        client
    } else {
        let mut client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                metadata.redirect_uris().to_vec(),
                digest_hash,
                encrypted_client_secret,
                metadata.application_type.clone(),
                //&metadata.response_types(),
                metadata.grant_types().to_vec(),
                metadata
                    .client_name
                    .clone()
                    .map(Localized::to_non_localized),
                metadata.logo_uri.clone().map(Localized::to_non_localized),
                metadata.client_uri.clone().map(Localized::to_non_localized),
                metadata.policy_uri.clone().map(Localized::to_non_localized),
                metadata.tos_uri.clone().map(Localized::to_non_localized),
                metadata.jwks_uri.clone(),
                metadata.jwks.clone(),
                // XXX: those might not be right, should be function calls
                metadata.id_token_signed_response_alg.clone(),
                metadata.userinfo_signed_response_alg.clone(),
                metadata.token_endpoint_auth_method.clone(),
                metadata.token_endpoint_auth_signing_alg.clone(),
                metadata.initiate_login_uri.clone(),
            )
            .await?;

        // Persist any localised metadata variants the registrant supplied
        // (`client_name#ja-Jpan-JP` etc.). The base `add` only stores the
        // non-localised default; the per-locale rows go to a separate
        // table.
        let localized = collect_localized_metadata(&metadata);
        if !localized.is_empty() {
            repo.oauth2_client()
                .replace_localized_metadata(client.id, &localized)
                .await?;
            client.localized_metadata = localized;
        }

        tracing::info!(%client.id, "Registered new client");
        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "created")]);
        client
    };

    let response = ClientRegistrationResponse {
        client_id: client.client_id.clone(),
        client_secret,
        // XXX: we should have a `created_at` field on the clients
        client_id_issued_at: Some(client.id.datetime().into()),
        client_secret_expires_at: None,
    };

    // We round-trip back to the metadata to output it in the response
    // This should never fail, as the client is valid
    let metadata = client.into_metadata().validate()?;

    repo.save().await?;

    Ok(RouteResponse { response, metadata })
}

/// Extract the tagged (locale-specific) variants from `metadata` into a
/// [`LocalizedClientMetadata`] suitable for
/// [`OAuth2ClientRepository::replace_localized_metadata`]. The
/// non-localised default is *not* copied — that already lives on the
/// `oauth2_clients` row itself.
fn collect_localized_metadata(metadata: &VerifiedClientMetadata) -> LocalizedClientMetadata {
    let mut out = LocalizedClientMetadata::default();

    if let Some(name) = metadata.client_name.as_ref() {
        for (tag, value) in name.iter() {
            if let Some(tag) = tag {
                out.client_name
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(logo) = metadata.logo_uri.as_ref() {
        for (tag, value) in logo.iter() {
            if let Some(tag) = tag {
                out.logo_uri.insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.client_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.client_uri
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.policy_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.policy_uri
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.tos_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.tos_uri.insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_suffix_list() {
        fn url_is_public_suffix(url: &str) -> bool {
            host_is_public_suffix(&Url::parse(url).unwrap())
        }

        assert!(url_is_public_suffix("https://.com"));
        assert!(url_is_public_suffix("https://.com."));
        assert!(url_is_public_suffix("https://co.uk"));
        assert!(url_is_public_suffix("https://github.io"));
        assert!(!url_is_public_suffix("https://example.com"));
        assert!(!url_is_public_suffix("https://example.com."));
        assert!(!url_is_public_suffix("https://x.com"));
        assert!(!url_is_public_suffix("https://x.com."));
        assert!(!url_is_public_suffix("https://palpo-im.github.io"));
        assert!(!url_is_public_suffix("http://localhost"));
        assert!(!url_is_public_suffix("org.matrix:/callback"));
        assert!(!url_is_public_suffix("http://somerandominternaldomain"));
    }

    fn metadata(application_type: &str, redirect_uri: &str) -> VerifiedClientMetadata {
        let metadata: ClientMetadata = serde_json::from_value(serde_json::json!({
            "application_type": application_type,
            "client_uri": "https://example.com/",
            "redirect_uris": [redirect_uri],
        }))
        .unwrap();
        metadata.validate().unwrap()
    }

    #[test]
    fn matrix_web_redirects_require_https_and_client_uri_host() {
        assert!(
            validate_matrix_redirect_uris(&metadata("web", "https://app.example.com/callback"))
                .is_ok()
        );
        for uri in [
            "http://app.example.com/callback",
            "https://evil-example.com/callback",
            "https://example.com.evil.test/callback",
            "http://127.0.0.1/callback",
        ] {
            assert!(
                validate_matrix_redirect_uris(&metadata("web", uri)).is_err(),
                "{uri}"
            );
        }
    }

    #[test]
    fn matrix_native_redirects_allow_portless_loopback_and_reverse_dns() {
        for uri in [
            "http://127.0.0.1/callback",
            "http://[::1]/callback",
            "http://localhost/callback",
            "com.example.app:/callback",
            "https://app.example.com/callback",
        ] {
            assert!(
                validate_matrix_redirect_uris(&metadata("native", uri)).is_ok(),
                "{uri}"
            );
        }
        for uri in [
            "http://127.0.0.1:3568/callback",
            "http://127.0.0.2/callback",
            "com.evil.app:/callback",
            "com.example.app://callback",
        ] {
            assert!(
                validate_matrix_redirect_uris(&metadata("native", uri)).is_err(),
                "{uri}"
            );
        }
    }

    #[test]
    fn matrix_native_redirects_reject_even_default_http_port() {
        assert!(loopback_redirect_has_explicit_port(
            "http://localhost:80/callback"
        ));
        assert!(loopback_redirect_has_explicit_port(
            "http://127.0.0.1:80/callback"
        ));
        assert!(loopback_redirect_has_explicit_port(
            "http://[::1]:80/callback"
        ));
        assert!(loopback_redirect_has_explicit_port(
            "HTTP://localhost:80/callback"
        ));
        assert!(!loopback_redirect_has_explicit_port(
            "http://localhost/callback"
        ));
    }

    // Integration tests would need to be updated for Salvo's test utilities
}
