//! URL routing definitions for the Pasion authentication service.
//!
//! This crate defines every named route in the application (e.g.
//! [`OAuth2TokenEndpoint`], [`Login`], [`OidcConfiguration`]) along with the
//! [`UrlBuilder`] utility for generating absolute URLs from a base.
//!
//! Each route type implements the [`Route`] trait, which provides:
//! - `route()` — the path template used by the Salvo router
//! - `path_and_query()` — the concrete path (with query parameters if needed)
//!
//! # Example
//!
//! ```ignore
//! use pasion_router::{UrlBuilder, OidcConfiguration, Route};
//!
//! let builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
//! let url = builder.absolute_url_for(&OidcConfiguration);
//! assert_eq!(url.as_str(), "https://auth.example.com/.well-known/openid-configuration");
//! ```

pub(crate) mod endpoints;
pub(crate) mod traits;
mod url_builder;

pub use self::{endpoints::*, traits::Route, url_builder::UrlBuilder};

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ulid::Ulid;
    use url::Url;

    use super::*;

    #[test]
    fn test_relative_urls() {
        assert_eq!(
            OidcConfiguration.path_and_query(),
            Cow::Borrowed("/.well-known/openid-configuration")
        );
        assert_eq!(Index.path_and_query(), Cow::Borrowed("/"));
        assert_eq!(
            Login::and_continue_grant(Ulid::nil()).path_and_query(),
            Cow::Borrowed("/login?kind=continue_authorization_grant&id=00000000000000000000000000")
        );
    }

    #[test]
    fn test_absolute_urls() {
        let base = Url::try_from("https://example.com/").unwrap();
        assert_eq!(Index.absolute_url(&base).as_str(), "https://example.com/");
        assert_eq!(
            OidcConfiguration.absolute_url(&base).as_str(),
            "https://example.com/.well-known/openid-configuration"
        );
    }
}
