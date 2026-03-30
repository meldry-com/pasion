use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::traits::*;

/// `GET /.well-known/openid-configuration`
#[derive(Default, Debug, Clone)]
pub struct OidcConfiguration;

impl SimpleRoute for OidcConfiguration {
    const PATH: &'static str = "/.well-known/openid-configuration";
}

/// `GET /oauth2/keys.json`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Keys;

impl SimpleRoute for OAuth2Keys {
    const PATH: &'static str = "/oauth2/keys.json";
}

/// `GET /oauth2/userinfo`
#[derive(Default, Debug, Clone)]
pub struct OidcUserinfo;

impl SimpleRoute for OidcUserinfo {
    const PATH: &'static str = "/oauth2/userinfo";
}

/// `POST /oauth2/introspect`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Introspection;

impl SimpleRoute for OAuth2Introspection {
    const PATH: &'static str = "/oauth2/introspect";
}

/// `POST /oauth2/revoke`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Revocation;

impl SimpleRoute for OAuth2Revocation {
    const PATH: &'static str = "/oauth2/revoke";
}

/// `POST /oauth2/token`
#[derive(Default, Debug, Clone)]
pub struct OAuth2TokenEndpoint;

impl SimpleRoute for OAuth2TokenEndpoint {
    const PATH: &'static str = "/oauth2/token";
}

/// `POST /oauth2/registration`
#[derive(Default, Debug, Clone)]
pub struct OAuth2RegistrationEndpoint;

impl SimpleRoute for OAuth2RegistrationEndpoint {
    const PATH: &'static str = "/oauth2/registration";
}

/// `GET /authorize`
#[derive(Default, Debug, Clone)]
pub struct OAuth2AuthorizationEndpoint;

impl SimpleRoute for OAuth2AuthorizationEndpoint {
    const PATH: &'static str = "/authorize";
}

/// `GET /consent/{grant_id}`
#[derive(Debug, Clone)]
pub struct Consent(pub Ulid);

impl Route for Consent {
    type Query = ();
    fn route() -> &'static str {
        "/consent/{grant_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/consent/{}", self.0).into()
    }
}

/// `GET|POST /link`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DeviceCodeLink {
    code: Option<String>,
}

impl DeviceCodeLink {
    #[must_use]
    pub fn with_code(code: String) -> Self {
        Self { code: Some(code) }
    }
}

impl Route for DeviceCodeLink {
    type Query = DeviceCodeLink;
    fn route() -> &'static str {
        "/link"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

/// `GET|POST /device/{device_code_id}`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct DeviceCodeConsent {
    id: Ulid,
}

impl Route for DeviceCodeConsent {
    type Query = ();
    fn route() -> &'static str {
        "/device/{device_code_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/device/{}", self.id).into()
    }
}

impl DeviceCodeConsent {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

/// `POST /oauth2/device`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct OAuth2DeviceAuthorizationEndpoint;

impl SimpleRoute for OAuth2DeviceAuthorizationEndpoint {
    const PATH: &'static str = "/oauth2/device";
}
