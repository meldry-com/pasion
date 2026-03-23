//! OAuth 2.0 and OpenID Connect protocol endpoint handlers.
//!
//! This module implements the server-side of the OAuth 2.0 / OIDC flows:
//!
//! - [`authorization`] — Authorization endpoint (authorization code grant)
//! - [`token`] — Token endpoint (exchange codes / credentials for tokens)
//! - [`registration`] — Dynamic client registration (RFC 7591)
//! - [`discovery`] — OpenID Connect Discovery
//!   (`/.well-known/openid-configuration`)
//! - [`keys`] — JSON Web Key Set (`/.well-known/jwks.json`)
//! - [`userinfo`] — UserInfo endpoint (returns claims about the authenticated
//!   user)
//! - [`introspection`] — Token introspection (RFC 7662)
//! - [`revoke`] — Token revocation (RFC 7009)
//! - [`device`] — Device authorization grant (RFC 8628)
//! - [`webfinger`] — WebFinger discovery

use std::collections::HashMap;

use chrono::Duration;
use pasion_data_model::{
    AccessToken, Authentication, AuthorizationGrant, BrowserSession, Client, Clock, RefreshToken,
    Session, TokenType,
};
use pasion_iana::jose::JsonWebSignatureAlg;
use pasion_jose::{
    claims::{self, hash_token},
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use pasion_keystore::Keystore;
use pasion_router::UrlBuilder;
use pasion_storage::RepositoryAccess;
use thiserror::Error;

/// Authorization endpoint (user consent and code issuance).
pub mod authorization;
/// Device authorization grant (RFC 8628).
pub mod device;
/// OpenID Connect Discovery metadata.
pub mod discovery;
/// Token introspection (RFC 7662).
pub mod introspection;
/// JWK Set endpoint.
pub mod keys;
/// Dynamic client registration (RFC 7591).
pub mod registration;
/// Token revocation (RFC 7009).
pub mod revoke;
/// Token endpoint (code exchange, client credentials, refresh).
pub mod token;
/// UserInfo endpoint.
pub mod userinfo;
/// WebFinger discovery.
pub mod webfinger;

#[derive(Debug, Error)]
#[error(transparent)]
pub(crate) enum IdTokenSignatureError {
    #[error("The signing key is invalid")]
    InvalidSigningKey,
    Claim(#[from] pasion_jose::claims::ClaimError),
    JwtSignature(#[from] pasion_jose::jwt::JwtSignatureError),
    WrongAlgorithm(#[from] pasion_keystore::WrongAlgorithmError),
    TokenHash(#[from] pasion_jose::claims::TokenHashError),
}

/// Generate a signed OpenID Connect ID Token for the given session.
///
/// The token includes standard claims (`iss`, `sub`, `aud`, `iat`, `exp`)
/// and optional claims (`nonce`, `auth_time`, `at_hash`, `c_hash`) depending
/// on the grant context.
pub(crate) fn generate_id_token(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    clock: &impl Clock,
    url_builder: &UrlBuilder,
    key_store: &Keystore,
    client: &Client,
    grant: Option<&AuthorizationGrant>,
    browser_session: &BrowserSession,
    access_token: Option<&AccessToken>,
    last_authentication: Option<&Authentication>,
) -> Result<String, IdTokenSignatureError> {
    let mut claims = HashMap::new();
    let now = clock.now();
    claims::ISS.insert(&mut claims, url_builder.oidc_issuer().to_string())?;
    claims::SUB.insert(&mut claims, &browser_session.user.sub)?;
    claims::AUD.insert(&mut claims, client.client_id.clone())?;
    claims::IAT.insert(&mut claims, now)?;
    claims::EXP.insert(&mut claims, now + Duration::try_hours(1).unwrap())?;

    if let Some(nonce) = grant.and_then(|grant| grant.nonce.as_ref()) {
        claims::NONCE.insert(&mut claims, nonce)?;
    }

    if let Some(last_authentication) = last_authentication {
        claims::AUTH_TIME.insert(&mut claims, last_authentication.created_at)?;
    }

    let alg = client
        .id_token_signed_response_alg
        .clone()
        .unwrap_or(JsonWebSignatureAlg::Rs256);
    let key = key_store
        .signing_key_for_algorithm(&alg)
        .ok_or(IdTokenSignatureError::InvalidSigningKey)?;

    if let Some(access_token) = access_token {
        claims::AT_HASH.insert(&mut claims, hash_token(&alg, &access_token.access_token)?)?;
    }

    if let Some(code) = grant.and_then(|grant| grant.code.as_ref()) {
        claims::C_HASH.insert(&mut claims, hash_token(&alg, &code.code)?)?;
    }

    let signer = key.params().signing_key_for_alg(&alg)?;
    let header = JsonWebSignatureHeader::new(alg)
        .with_kid(key.kid().ok_or(IdTokenSignatureError::InvalidSigningKey)?);
    let id_token = Jwt::sign_with_rng(rng, header, claims, &signer)?;

    Ok(id_token.into_string())
}

/// Generate a new access-token / refresh-token pair for an OAuth 2.0 session
/// and persist them in the repository.
pub(crate) async fn generate_token_pair<R: RepositoryAccess>(
    rng: &mut (impl rand::RngCore + Send),
    clock: &impl Clock,
    repo: &mut R,
    session: &Session,
    ttl: Duration,
) -> Result<(AccessToken, RefreshToken), R::Error> {
    let access_token_str = TokenType::AccessToken.generate(rng);
    let refresh_token_str = TokenType::RefreshToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, session, access_token_str, Some(ttl))
        .await?;

    let refresh_token = repo
        .oauth2_refresh_token()
        .add(rng, clock, session, &access_token, refresh_token_str)
        .await?;

    Ok((access_token, refresh_token))
}
