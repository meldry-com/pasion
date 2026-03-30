//! Private (encrypted) cookie jar for Salvo

use std::sync::LazyLock;

use cookie::{Cookie, CookieJar as RawCookieJar, Key, SameSite};
use salvo::{
    extract::{Extractible, Metadata},
    prelude::*,
};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
#[error("could not decode cookie")]
pub enum CookieDecodeError {
    Deserialize(#[from] serde_json::Error),
}

/// Manages cookie options and encryption key
///
/// This is meant to be accessible through Salvo's Depot
#[derive(Clone)]
pub struct CookieManager {
    options: CookieOption,
    key: Key,
}

impl CookieManager {
    #[must_use]
    pub fn new(base_url: Url, key: Key) -> Self {
        let options = CookieOption::new(base_url);
        Self { options, key }
    }

    #[must_use]
    pub fn derive_from(base_url: Url, key: &[u8]) -> Self {
        let key = Key::derive_from(key);
        Self::new(base_url, key)
    }

    #[must_use]
    pub fn cookie_jar(&self) -> CookieJar {
        let inner = cookie::CookieJar::new();
        let options = self.options.clone();

        CookieJar {
            inner,
            key: self.key.clone(),
            options,
            pending_cookies: Vec::new(),
        }
    }

    #[must_use]
    pub fn cookie_jar_from_request(&self, request_cookies: &RawCookieJar) -> CookieJar {
        let mut inner = RawCookieJar::new();

        for cookie in request_cookies.iter() {
            inner.add_original(cookie.clone());
        }

        let options = self.options.clone();
        CookieJar {
            inner,
            key: self.key.clone(),
            options,
            pending_cookies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CookieOption {
    base_url: Url,
}

impl CookieOption {
    const fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    fn secure(&self) -> bool {
        self.base_url.scheme() == "https"
    }

    fn path(&self) -> &str {
        self.base_url.path()
    }

    fn apply<'a>(&self, mut cookie: Cookie<'a>) -> Cookie<'a> {
        cookie.set_http_only(true);
        cookie.set_secure(self.secure());
        cookie.set_path(self.path().to_owned());
        cookie.set_same_site(SameSite::Lax);
        cookie
    }
}

/// A cookie jar which encrypts cookies & sets secure options
pub struct CookieJar {
    inner: RawCookieJar,
    key: Key,
    options: CookieOption,
    pending_cookies: Vec<Cookie<'static>>,
}

impl CookieJar {
    /// Save the given payload in a cookie
    ///
    /// If `permanent` is true, the cookie will be valid for 10 years
    ///
    /// # Panics
    ///
    /// Panics if the payload cannot be serialized
    #[must_use]
    pub fn save<T: Serialize>(mut self, key: &str, payload: &T, permanent: bool) -> Self {
        let serialized =
            serde_json::to_string(payload).expect("failed to serialize cookie payload");

        let cookie = Cookie::new(key.to_owned(), serialized);
        let mut cookie = self.options.apply(cookie);

        if permanent {
            // XXX: this should use a clock
            cookie.make_permanent();
        }

        // Add to the private jar (encrypts automatically)
        self.inner.private_mut(&self.key).add(cookie.clone());

        // Get the encrypted cookie for the response
        if let Some(encrypted_cookie) = self.inner.get(key) {
            self.pending_cookies
                .push(encrypted_cookie.clone().into_owned());
        }

        self
    }

    /// Remove a cookie from the jar
    #[must_use]
    pub fn remove(mut self, key: &str) -> Self {
        // Create a removal cookie
        let mut removal = Cookie::new(key.to_owned(), "");
        removal.make_removal();
        removal = self.options.apply(removal);
        self.pending_cookies.push(removal);
        self.inner.private_mut(&self.key).remove(key.to_owned());
        self
    }

    /// Load and deserialize a cookie from the jar
    ///
    /// Returns `None` if the cookie is not present
    ///
    /// # Errors
    ///
    /// Returns an error if the cookie cannot be deserialized
    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CookieDecodeError> {
        let Some(cookie) = self.inner.private(&self.key).get(key) else {
            return Ok(None);
        };

        let decoded: T = serde_json::from_str(cookie.value())?;
        Ok(Some(decoded))
    }

    /// Write pending cookies to the response
    pub fn write_to_response(&self, res: &mut Response) {
        for cookie in &self.pending_cookies {
            res.add_cookie(cookie.clone());
        }
    }

    /// Get the pending cookies for manual response handling
    pub fn pending_cookies(&self) -> &[Cookie<'static>] {
        &self.pending_cookies
    }
}

/// Extract CookieJar from request using Depot
impl CookieJar {
    /// Extract from request and depot
    pub fn extract_from_request(req: &Request, depot: &Depot) -> Result<Self, StatusError> {
        // Try to get CookieManager from depot
        if let Ok(manager) = depot.get::<CookieManager>("cookie_manager") {
            Ok(manager.cookie_jar_from_request(req.cookies()))
        } else {
            Err(StatusError::internal_server_error().brief("CookieManager not found in depot"))
        }
    }
}

static COOKIE_JAR_METADATA: LazyLock<Metadata> = LazyLock::new(|| Metadata::new("CookieJar"));

impl<'ex> Extractible<'ex> for CookieJar {
    fn metadata() -> &'static Metadata {
        &COOKIE_JAR_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(req: &'ex mut Request, depot: &'ex mut Depot) -> Result<Self, StatusError> {
        Self::extract_from_request(req, depot)
    }
}
