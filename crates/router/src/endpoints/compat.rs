use crate::traits::*;

/// `GET|POST /_matrix/client/v3/login`
pub struct CompatLogin;

impl SimpleRoute for CompatLogin {
    const PATH: &'static str = "/_matrix/client/{version}/login";
}

/// `POST /_matrix/client/v3/logout`
pub struct CompatLogout;

impl SimpleRoute for CompatLogout {
    const PATH: &'static str = "/_matrix/client/{version}/logout";
}

/// `POST /_matrix/client/v3/logout/all`
pub struct CompatLogoutAll;

impl SimpleRoute for CompatLogoutAll {
    const PATH: &'static str = "/_matrix/client/{version}/logout/all";
}

/// `POST /_matrix/client/v3/refresh`
pub struct CompatRefresh;

impl SimpleRoute for CompatRefresh {
    const PATH: &'static str = "/_matrix/client/{version}/refresh";
}

/// `GET /_matrix/client/v3/login/sso/redirect`
pub struct CompatLoginSsoRedirect;

impl SimpleRoute for CompatLoginSsoRedirect {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect";
}

/// `GET /_matrix/client/v3/login/sso/redirect/`
///
/// This is a workaround for the fact some clients (Element iOS) sends a
/// trailing slash, even though it's not in the spec.
pub struct CompatLoginSsoRedirectSlash;

impl SimpleRoute for CompatLoginSsoRedirectSlash {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect/";
}

/// `GET /_matrix/client/v3/login/sso/redirect/{idp}`
pub struct CompatLoginSsoRedirectIdp;

impl SimpleRoute for CompatLoginSsoRedirectIdp {
    const PATH: &'static str = "/_matrix/client/{version}/login/sso/redirect/{idp}";
}
