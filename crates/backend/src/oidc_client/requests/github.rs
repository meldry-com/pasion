//! GitHub `OAuth2` support (Hagency).
//!
//! GitHub is plain `OAuth2`: there is no `id_token` and no OIDC discovery.
//! The standard token exchange and userinfo fetch (`GET /user`) work as-is;
//! this module adds what GitHub does not return there: the verified primary
//! email (`GET /user/emails`), normalised OIDC-style claims, and a Matrix
//! localpart derived from the GitHub login.
//!
//! A provider is treated as GitHub when its `brand_name` is `github`.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::super::error::UserInfoError;
use crate::outbound_http::RequestBuilderExt;

/// `brand_name` value that switches on the GitHub-specific claim handling.
pub const GITHUB_BRAND_NAME: &str = "github";
/// Claim carrying the GitHub login, kept so Hagency can map members to
/// GitHub users (import it with `account_name.template`).
pub const GITHUB_LOGIN_CLAIM: &str = "github_login";
/// Claim carrying the sanitised, collision-free localpart suggestion.
pub const LOCALPART_CLAIM: &str = "pasion_localpart";
/// Localpart used when a login sanitises to nothing.
const FALLBACK_LOCALPART: &str = "github-user";
/// GitHub logins are at most 39 characters; leave room for a suffix.
const MAX_BASE_LEN: usize = 48;
/// Highest numeric suffix tried before giving up on a localpart.
pub const MAX_LOCALPART_SUFFIX: u32 = 99;
/// GitHub's media type for REST responses.
const GITHUB_JSON: &str = "application/vnd.github+json";

/// One entry of `GET /user/emails`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GitHubEmail {
    /// The address.
    pub email: String,
    /// Whether this is the account's primary address.
    #[serde(default)]
    pub primary: bool,
    /// Whether GitHub verified the address.
    #[serde(default)]
    pub verified: bool,
}

/// Whether a provider's `brand_name` marks it as GitHub.
#[must_use]
pub fn is_github(brand_name: Option<&str>) -> bool {
    brand_name.is_some_and(|b| b.eq_ignore_ascii_case(GITHUB_BRAND_NAME))
}

/// Turn a GitHub login into a valid Matrix localpart
/// (`[a-z0-9._=-]`, lowercase, no leading/trailing separators).
#[must_use]
pub fn sanitize_localpart(login: &str) -> String {
    let mapped: String = login
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || "._=-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(MAX_BASE_LEN)
        .collect();
    let trimmed = mapped.trim_matches(|c| "._=-".contains(c));
    if trimmed.is_empty() {
        FALLBACK_LOCALPART.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Candidate localparts in the order they are tried: `base`, `base-2`, ...
pub fn localpart_candidates(base: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::once(base.to_owned())
        .chain((2..=MAX_LOCALPART_SUFFIX).map(move |n| format!("{base}-{n}")))
}

/// The verified primary address, if GitHub reports one.
#[must_use]
pub fn verified_primary_email(emails: &[GitHubEmail]) -> Option<&str> {
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email.as_str())
}

/// Normalise a `GET /user` payload into the claims Pasion templates use:
/// `sub` (numeric id, stable across renames), `preferred_username`,
/// `github_login`, `name`, `picture`, and `email`/`email_verified` only for
/// the verified primary address (an unverified public email is dropped).
pub fn normalize_claims(user: &mut HashMap<String, Value>, emails: &[GitHubEmail]) {
    if let Some(id) = user.get("id").and_then(value_as_id) {
        user.insert("sub".to_owned(), Value::String(id));
    }
    if let Some(login) = user.get("login").and_then(Value::as_str).map(str::to_owned) {
        user.insert("preferred_username".to_owned(), Value::String(login.clone()));
        user.insert(GITHUB_LOGIN_CLAIM.to_owned(), Value::String(login));
    }
    if let Some(avatar) = user.get("avatar_url").cloned() {
        user.insert("picture".to_owned(), avatar);
    }
    user.remove("email");
    user.remove("email_verified");
    if let Some(email) = verified_primary_email(emails) {
        user.insert("email".to_owned(), Value::String(email.to_owned()));
        user.insert("email_verified".to_owned(), Value::Bool(true));
    }
}

/// The GitHub login of a `GET /user` payload, only when it also carries an
/// account `id`; `None` means the userinfo cannot identify a GitHub user and
/// the callback must fail rather than invent a localpart.
#[must_use]
pub fn identified_login(user: &HashMap<String, Value>) -> Option<&str> {
    user.get("id").and_then(value_as_id)?;
    user.get("login").and_then(Value::as_str).map(str::trim).filter(|l| !l.is_empty())
}

fn value_as_id(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// `{userinfo_endpoint}/emails`, e.g. `https://api.github.com/user/emails`.
#[must_use]
pub fn emails_endpoint(userinfo_endpoint: &Url) -> Url {
    let mut url = userinfo_endpoint.clone();
    let path = format!("{}/emails", url.path().trim_end_matches('/'));
    url.set_path(&path);
    url
}

/// Fetch `GET /user/emails` (needs the `user:email` scope).
#[tracing::instrument(skip_all, fields(%emails_endpoint))]
pub async fn fetch_emails(
    http_client: &reqwest::Client,
    emails_endpoint: &Url,
    access_token: &str,
) -> Result<Vec<GitHubEmail>, UserInfoError> {
    let emails = http_client
        .get(emails_endpoint.as_str())
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, GITHUB_JSON)
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(emails)
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod tests;
