use crate::traits::*;

/// `GET /`
#[derive(Default, Debug, Clone)]
pub struct Index;

impl SimpleRoute for Index {
    const PATH: &'static str = "/";
}

/// `GET /health`
#[derive(Default, Debug, Clone)]
pub struct Healthcheck;

impl SimpleRoute for Healthcheck {
    const PATH: &'static str = "/health";
}

/// `GET /.well-known/webfinger`
#[derive(Default, Debug, Clone)]
pub struct Webfinger;

impl SimpleRoute for Webfinger {
    const PATH: &'static str = "/.well-known/webfinger";
}

/// `GET /.well-known/change-password`
pub struct ChangePasswordDiscovery;

impl SimpleRoute for ChangePasswordDiscovery {
    const PATH: &'static str = "/.well-known/change-password";
}

/// `GET /assets`
pub struct StaticAsset {
    path: String,
}

impl StaticAsset {
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl Route for StaticAsset {
    type Query = ();
    fn route() -> &'static str {
        "/assets/"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/assets/{}", self.path).into()
    }
}

/// `GET /api/spec.json`
pub struct ApiSpec;

impl SimpleRoute for ApiSpec {
    const PATH: &'static str = "/api/spec.json";
}

/// `GET /api/doc/`
pub struct ApiDoc;

impl SimpleRoute for ApiDoc {
    const PATH: &'static str = "/api/doc/";
}

/// `GET /api/doc/oauth2-callback`
pub struct ApiDocCallback;

impl SimpleRoute for ApiDocCallback {
    const PATH: &'static str = "/api/doc/oauth2-callback";
}
