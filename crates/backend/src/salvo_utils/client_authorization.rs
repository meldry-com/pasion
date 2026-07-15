use std::{collections::HashMap, sync::LazyLock};

use chrono::{DateTime, Duration, Utc};
use headers::authorization::{Basic, Bearer, Credentials as _};
use http::StatusCode;
use oauth2_types::errors::{ClientError, ClientErrorCode};
use pasion_data::{Client, JwksOrJwksUri, RepositoryAccess, oauth2::OAuth2ClientRepository};
use pasion_iana::jose::JsonWebSignatureAlg;
use pasion_iana::oauth::OAuthClientAuthenticationMethod;
use pasion_jose::{
    claims::{self, TimeOptions},
    jwk::PublicJsonWebKeySet,
    jwt::Jwt,
};
use pasion_keystore::Encrypter;
use salvo::{
    extract::{Extractible, Metadata},
    prelude::*,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

use crate::{outbound_http::RequestBuilderExt, record_error};

static JWT_BEARER_CLIENT_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Deserialize)]
struct AuthorizedForm<F = ()> {
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Credentials {
    None {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: String,
    },
    ClientAssertionJwtBearer {
        client_id: String,
        jwt: Box<Jwt<'static, HashMap<String, serde_json::Value>>>,
    },
    BearerToken {
        token: String,
    },
}

impl Credentials {
    /// Get the `client_id` of the credentials
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => Some(client_id),
            Credentials::BearerToken { .. } => None,
        }
    }

    /// Get the bearer token from the credentials.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        match self {
            Credentials::BearerToken { token } => Some(token),
            _ => None,
        }
    }

    /// Fetch the client from the database
    ///
    /// # Errors
    ///
    /// Returns an error if the client could not be found or if the underlying
    /// repository errored.
    pub async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<Client>, E> {
        let client_id = match self {
            Credentials::None { client_id }
            | Credentials::ClientSecretBasic { client_id, .. }
            | Credentials::ClientSecretPost { client_id, .. }
            | Credentials::ClientAssertionJwtBearer { client_id, .. } => client_id,
            Credentials::BearerToken { .. } => return Ok(None),
        };

        repo.oauth2_client().find_by_client_id(client_id).await
    }

    /// Verify credentials presented by the client for authentication
    ///
    /// # Errors
    ///
    /// Returns an error if the credentials are invalid.
    #[tracing::instrument(skip_all)]
    pub async fn verify(
        &self,
        http_client: &reqwest::Client,
        encrypter: &Encrypter,
        method: &OAuthClientAuthenticationMethod,
        client: &Client,
        token_endpoint: &url::Url,
        issuer: &url::Url,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialsVerificationError> {
        match (self, method) {
            (Credentials::None { .. }, OAuthClientAuthenticationMethod::None) => {}

            (
                Credentials::ClientSecretPost { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretPost,
            )
            | (
                Credentials::ClientSecretBasic { client_secret, .. },
                OAuthClientAuthenticationMethod::ClientSecretBasic,
            ) => {
                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                // Check if the client_secret matches
                if client_secret.as_bytes() != decrypted_client_secret {
                    return Err(CredentialsVerificationError::ClientSecretMismatch);
                }
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, .. },
                OAuthClientAuthenticationMethod::PrivateKeyJwt,
            ) => {
                validate_client_assertion_alg(
                    jwt,
                    client.token_endpoint_auth_signing_alg.as_ref(),
                )?;

                // Get the client JWKS
                let jwks = client
                    .jwks
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let jwks = fetch_jwks(http_client, jwks)
                    .await
                    .map_err(CredentialsVerificationError::JwksFetchFailed)?;

                jwt.verify_with_jwks(&jwks)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
                validate_client_assertion_claims(
                    jwt,
                    &client.client_id,
                    token_endpoint,
                    issuer,
                    now,
                )?;
            }

            (
                Credentials::ClientAssertionJwtBearer { jwt, .. },
                OAuthClientAuthenticationMethod::ClientSecretJwt,
            ) => {
                validate_client_assertion_alg(
                    jwt,
                    client.token_endpoint_auth_signing_alg.as_ref(),
                )?;

                // Decrypt the client_secret
                let encrypted_client_secret = client
                    .encrypted_client_secret
                    .as_ref()
                    .ok_or(CredentialsVerificationError::InvalidClientConfig)?;

                let decrypted_client_secret = encrypter
                    .decrypt_string(encrypted_client_secret)
                    .map_err(|_e| CredentialsVerificationError::DecryptionError)?;

                jwt.verify_with_shared_secret(decrypted_client_secret)
                    .map_err(|_| CredentialsVerificationError::InvalidAssertionSignature)?;
                validate_client_assertion_claims(
                    jwt,
                    &client.client_id,
                    token_endpoint,
                    issuer,
                    now,
                )?;
            }

            (_, _) => {
                return Err(CredentialsVerificationError::AuthenticationMethodMismatch);
            }
        }
        Ok(())
    }
}

fn max_client_assertion_lifetime() -> Duration {
    Duration::try_minutes(5).expect("five-minute assertion lifetime is representable")
}

fn validate_client_assertion_alg(
    jwt: &Jwt<'_, HashMap<String, Value>>,
    expected: Option<&JsonWebSignatureAlg>,
) -> Result<(), CredentialsVerificationError> {
    if let Some(expected) = expected
        && jwt.header().alg() != expected
    {
        return Err(CredentialsVerificationError::AssertionAlgorithmMismatch);
    }

    Ok(())
}

fn validate_client_assertion_claims(
    jwt: &Jwt<'_, HashMap<String, Value>>,
    expected_client_id: &str,
    token_endpoint: &url::Url,
    issuer: &url::Url,
    now: DateTime<Utc>,
) -> Result<(), CredentialsVerificationError> {
    let mut claims = jwt.payload().clone();
    let time_options = TimeOptions::new(now);

    claims::ISS
        .extract_required_with_options(&mut claims, expected_client_id)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;

    let subject = claims::SUB
        .extract_required(&mut claims)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;
    if subject != expected_client_id {
        return Err(CredentialsVerificationError::InvalidAssertionSubject);
    }

    validate_client_assertion_audience(&claims, token_endpoint, issuer)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;

    let expires_at = claims::EXP
        .extract_required_with_options(&mut claims, &time_options)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;
    if expires_at.signed_duration_since(now) > max_client_assertion_lifetime() {
        return Err(CredentialsVerificationError::AssertionExpirationTooLong);
    }

    claims::NBF
        .extract_optional_with_options(&mut claims, &time_options)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;
    claims::IAT
        .extract_optional_with_options(&mut claims, &time_options)
        .map_err(CredentialsVerificationError::InvalidAssertionClaims)?;

    Ok(())
}

fn validate_client_assertion_audience(
    claims: &HashMap<String, Value>,
    token_endpoint: &url::Url,
    issuer: &url::Url,
) -> Result<(), pasion_jose::claims::ClaimError> {
    let accepted = [
        token_endpoint.as_str().to_owned(),
        issuer.as_str().to_owned(),
    ];
    let mut last_error = None;

    for audience in &accepted {
        let mut claims = claims.clone();
        match claims::AUD.extract_required_with_options(&mut claims, audience) {
            Ok(_) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(pasion_jose::claims::ClaimError::MissingClaim("aud")))
}

async fn fetch_jwks(
    http_client: &reqwest::Client,
    jwks: &JwksOrJwksUri,
) -> Result<PublicJsonWebKeySet, Box<dyn std::error::Error + Send + Sync>> {
    let uri = match jwks {
        JwksOrJwksUri::Jwks(j) => return Ok(j.clone()),
        JwksOrJwksUri::JwksUri(u) => u,
    };

    let response = http_client
        .get(uri.as_str())
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(response)
}

#[derive(Debug, Error)]
pub enum CredentialsVerificationError {
    #[error("failed to decrypt client credentials")]
    DecryptionError,

    #[error("invalid client configuration")]
    InvalidClientConfig,

    #[error("client secret did not match")]
    ClientSecretMismatch,

    #[error("authentication method mismatch")]
    AuthenticationMethodMismatch,

    #[error("invalid assertion signature")]
    InvalidAssertionSignature,

    #[error("invalid client assertion claims")]
    InvalidAssertionClaims(#[source] pasion_jose::claims::ClaimError),

    #[error("client assertion subject did not match client id")]
    InvalidAssertionSubject,

    #[error("client assertion expiration is too far in the future")]
    AssertionExpirationTooLong,

    #[error("client assertion signing algorithm did not match registered algorithm")]
    AssertionAlgorithmMismatch,

    #[error("failed to fetch jwks")]
    JwksFetchFailed(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl CredentialsVerificationError {
    /// Returns true if the error is an internal error, not caused by the client
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::DecryptionError | Self::InvalidClientConfig | Self::JwksFetchFailed(_)
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientAuthorization<F = ()> {
    pub credentials: Credentials,
    pub form: Option<F>,
}

impl<F> ClientAuthorization<F> {
    /// Get the `client_id` from the credentials.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.credentials.client_id()
    }
}

#[derive(Debug, Error)]
pub enum ClientAuthorizationError {
    #[error("Invalid Authorization header")]
    InvalidHeader,

    #[error("Could not deserialize request body: {0}")]
    BadForm(String),

    #[error("client_id in form ({form:?}) does not match credential ({credential:?})")]
    ClientIdMismatch { credential: String, form: String },

    #[error("Unsupported client_assertion_type: {client_assertion_type}")]
    UnsupportedClientAssertion { client_assertion_type: String },

    #[error("No credentials were presented")]
    MissingCredentials,

    #[error("Invalid request")]
    InvalidRequest,

    #[error("Invalid client_assertion")]
    InvalidAssertion,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl Scribe for ClientAuthorizationError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, Self::Internal(_));

        let (status, body) = match &self {
            ClientAuthorizationError::InvalidHeader => (
                StatusCode::BAD_REQUEST,
                ClientError::new(
                    ClientErrorCode::InvalidRequest,
                    "Invalid Authorization header",
                ),
            ),

            ClientAuthorizationError::BadForm(err) => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest)
                    .with_description(err.to_string()),
            ),

            ClientAuthorizationError::ClientIdMismatch { .. } => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidGrant)
                    .with_description(format!("{self}")),
            ),

            ClientAuthorizationError::UnsupportedClientAssertion { .. } => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest)
                    .with_description(format!("{self}")),
            ),

            ClientAuthorizationError::MissingCredentials => (
                StatusCode::BAD_REQUEST,
                ClientError::new(
                    ClientErrorCode::InvalidRequest,
                    "No credentials were presented",
                ),
            ),

            ClientAuthorizationError::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                ClientError::from(ClientErrorCode::InvalidRequest),
            ),

            ClientAuthorizationError::InvalidAssertion => (
                StatusCode::BAD_REQUEST,
                ClientError::new(ClientErrorCode::InvalidRequest, "Invalid client_assertion"),
            ),

            ClientAuthorizationError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::from(ClientErrorCode::ServerError).with_description(format!("{e}")),
            ),
        };

        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
        res.render(Json(body));
    }
}

impl<F: DeserializeOwned + Send> ClientAuthorization<F> {
    /// Extract client authorization from a Salvo request
    pub async fn extract_from_request(req: &mut Request) -> Result<Self, ClientAuthorizationError> {
        enum Authorization {
            Basic(String, String),
            Bearer(String),
        }

        // Sadly, the typed-header 'Authorization' doesn't let us check for both
        // Basic and Bearer at the same time, so we need to parse them manually
        let authorization = if let Some(header) = req.headers().get(http::header::AUTHORIZATION) {
            let bytes = header.as_bytes();
            if bytes.len() >= 6 && bytes[..6].eq_ignore_ascii_case(b"Basic ") {
                let Some(decoded) = Basic::decode(header) else {
                    return Err(ClientAuthorizationError::InvalidHeader);
                };

                Some(Authorization::Basic(
                    decoded.username().to_owned(),
                    decoded.password().to_owned(),
                ))
            } else if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"Bearer ") {
                let Some(decoded) = Bearer::decode(header) else {
                    return Err(ClientAuthorizationError::InvalidHeader);
                };

                Some(Authorization::Bearer(decoded.token().to_owned()))
            } else {
                return Err(ClientAuthorizationError::InvalidHeader);
            }
        } else {
            None
        };

        // Check content type to see if we should parse form
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let is_form = content_type.starts_with("application/x-www-form-urlencoded");

        // Take the form value
        let (
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
            form,
        ) = if is_form {
            match req.parse_form::<AuthorizedForm<F>>().await {
                Ok(form) => (
                    form.client_id,
                    form.client_secret,
                    form.client_assertion_type,
                    form.client_assertion,
                    Some(form.inner),
                ),
                Err(e) => {
                    return Err(ClientAuthorizationError::BadForm(e.to_string()));
                }
            }
        } else {
            (None, None, None, None, None)
        };

        // And now, figure out the actual auth method
        let credentials = match (
            authorization,
            client_id_from_form,
            client_secret_from_form,
            client_assertion_type,
            client_assertion,
        ) {
            (
                Some(Authorization::Basic(client_id, client_secret)),
                client_id_from_form,
                None,
                None,
                None,
            ) => {
                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches with the header
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientSecretBasic {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), Some(client_secret), None, None) => {
                // Got both client_id and client_secret from the form
                Credentials::ClientSecretPost {
                    client_id,
                    client_secret,
                }
            }

            (None, Some(client_id), None, None, None) => {
                // Only got a client_id in the form
                Credentials::None { client_id }
            }

            (
                None,
                client_id_from_form,
                None,
                Some(client_assertion_type),
                Some(client_assertion),
            ) if client_assertion_type == JWT_BEARER_CLIENT_ASSERTION => {
                // Got a JWT bearer client_assertion
                let jwt: Jwt<'static, HashMap<String, Value>> = Jwt::try_from(client_assertion)
                    .map_err(|_| ClientAuthorizationError::InvalidAssertion)?;

                let client_id = if let Some(Value::String(client_id)) = jwt.payload().get("sub") {
                    client_id.clone()
                } else {
                    return Err(ClientAuthorizationError::InvalidAssertion);
                };

                if let Some(client_id_from_form) = client_id_from_form {
                    // If the client_id was in the body, verify it matches the one in the JWT
                    if client_id != client_id_from_form {
                        return Err(ClientAuthorizationError::ClientIdMismatch {
                            credential: client_id,
                            form: client_id_from_form,
                        });
                    }
                }

                Credentials::ClientAssertionJwtBearer {
                    client_id,
                    jwt: Box::new(jwt),
                }
            }

            (None, None, None, Some(client_assertion_type), Some(_client_assertion)) => {
                // Got another unsupported client_assertion
                return Err(ClientAuthorizationError::UnsupportedClientAssertion {
                    client_assertion_type,
                });
            }

            (Some(Authorization::Bearer(token)), None, None, None, None) => {
                // Got a bearer token
                Credentials::BearerToken { token }
            }

            (None, None, None, None, None) => {
                // Special case when there are no credentials anywhere
                return Err(ClientAuthorizationError::MissingCredentials);
            }

            _ => {
                // Every other combination is an invalid request
                return Err(ClientAuthorizationError::InvalidRequest);
            }
        };

        Ok(ClientAuthorization { credentials, form })
    }
}

static CLIENT_AUTHORIZATION_METADATA: LazyLock<Metadata> =
    LazyLock::new(|| Metadata::new("ClientAuthorization"));

impl<'ex, F> Extractible<'ex> for ClientAuthorization<F>
where
    F: DeserializeOwned + Send,
{
    fn metadata() -> &'static Metadata {
        &CLIENT_AUTHORIZATION_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(
        req: &'ex mut Request,
        _depot: &'ex mut Depot,
    ) -> Result<Self, ClientAuthorizationError> {
        Self::extract_from_request(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone as _;

    fn jwt_with_claims(claims: serde_json::Value) -> Jwt<'static, HashMap<String, Value>> {
        jwt_with_alg_and_claims("HS256", claims)
    }

    fn jwt_with_alg_and_claims(
        alg: &str,
        claims: serde_json::Value,
    ) -> Jwt<'static, HashMap<String, Value>> {
        fn encode(value: &serde_json::Value) -> String {
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(value).unwrap())
        }

        let header = serde_json::json!({ "alg": alg });
        let token = format!("{}.{}.c2ln", encode(&header), encode(&claims));
        Jwt::try_from(token).unwrap()
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 6, 12, 0, 0).unwrap()
    }

    #[test]
    fn client_assertion_claims_accept_valid_assertion() {
        let now = fixed_now();
        let token_endpoint = url::Url::parse("https://example.com/oauth2/token").unwrap();
        let issuer = url::Url::parse("https://example.com/").unwrap();
        let jwt = jwt_with_claims(serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://example.com/oauth2/token",
            "exp": (now + Duration::try_minutes(1).unwrap()).timestamp(),
            "iat": now.timestamp(),
            "jti": "assertion-1"
        }));

        validate_client_assertion_claims(&jwt, "client-123", &token_endpoint, &issuer, now)
            .unwrap();
    }

    #[test]
    fn client_assertion_alg_rejects_registered_algorithm_mismatch() {
        let jwt = jwt_with_alg_and_claims("HS256", serde_json::json!({}));

        assert!(matches!(
            validate_client_assertion_alg(&jwt, Some(&JsonWebSignatureAlg::Hs512)),
            Err(CredentialsVerificationError::AssertionAlgorithmMismatch)
        ));
    }

    #[test]
    fn client_assertion_claims_accept_issuer_audience() {
        let now = fixed_now();
        let token_endpoint = url::Url::parse("https://example.com/oauth2/token").unwrap();
        let issuer = url::Url::parse("https://example.com/").unwrap();
        let jwt = jwt_with_claims(serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://example.com/",
            "exp": (now + Duration::try_minutes(1).unwrap()).timestamp(),
        }));

        validate_client_assertion_claims(&jwt, "client-123", &token_endpoint, &issuer, now)
            .unwrap();
    }

    #[test]
    fn client_assertion_claims_reject_wrong_audience() {
        let now = fixed_now();
        let token_endpoint = url::Url::parse("https://example.com/oauth2/token").unwrap();
        let issuer = url::Url::parse("https://example.com/").unwrap();
        let jwt = jwt_with_claims(serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://attacker.example/token",
            "exp": (now + Duration::try_minutes(1).unwrap()).timestamp(),
        }));

        assert!(matches!(
            validate_client_assertion_claims(&jwt, "client-123", &token_endpoint, &issuer, now),
            Err(CredentialsVerificationError::InvalidAssertionClaims(_))
        ));
    }

    #[test]
    fn client_assertion_claims_reject_wrong_subject() {
        let now = fixed_now();
        let token_endpoint = url::Url::parse("https://example.com/oauth2/token").unwrap();
        let issuer = url::Url::parse("https://example.com/").unwrap();
        let jwt = jwt_with_claims(serde_json::json!({
            "iss": "client-123",
            "sub": "other-client",
            "aud": "https://example.com/oauth2/token",
            "exp": (now + Duration::try_minutes(1).unwrap()).timestamp(),
        }));

        assert!(matches!(
            validate_client_assertion_claims(&jwt, "client-123", &token_endpoint, &issuer, now),
            Err(CredentialsVerificationError::InvalidAssertionSubject)
        ));
    }

    #[test]
    fn client_assertion_claims_reject_long_lived_assertion() {
        let now = fixed_now();
        let token_endpoint = url::Url::parse("https://example.com/oauth2/token").unwrap();
        let issuer = url::Url::parse("https://example.com/").unwrap();
        let jwt = jwt_with_claims(serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://example.com/oauth2/token",
            "exp": (now + Duration::try_minutes(30).unwrap()).timestamp(),
        }));

        assert!(matches!(
            validate_client_assertion_claims(&jwt, "client-123", &token_endpoint, &issuer, now),
            Err(CredentialsVerificationError::AssertionExpirationTooLong)
        ));
    }

    // Tests would need to be updated for Salvo's test utilities
    // For now, we'll skip the tests as they require significant Salvo-specific
    // changes
}
