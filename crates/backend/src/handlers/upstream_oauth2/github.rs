//! Callback-side GitHub enrichment (Hagency): adds the verified primary
//! email and a collision-free localpart suggestion to the userinfo claims.
//! Pure mapping lives in [`crate::oidc_client::requests::github`].

use std::collections::HashMap;

use pasion_data::{BoxRepository, RepositoryAccess, RepositoryError};
use serde_json::Value;
use url::Url;

use super::callback::RouteError;
use crate::oidc_client::{
    error::UserInfoError,
    requests::github::{
        LOCALPART_CLAIM, emails_endpoint, fetch_emails, identified_login, localpart_candidates,
        normalize_claims, sanitize_localpart,
    },
};

/// Fetch `/user/emails`, normalise the claims and attach
/// [`LOCALPART_CLAIM`] (the sanitised login, suffixed `-2`, `-3`, ... when
/// a Pasion user already holds it). Missing optional email permission leaves
/// email claims absent; the configured import policy decides if they are
/// needed.
pub(crate) async fn enrich_userinfo(
    client: &reqwest::Client,
    repo: &mut BoxRepository,
    userinfo_endpoint: &Url,
    access_token: &str,
    userinfo: &mut Value,
) -> Result<(), RouteError> {
    let mut claims: HashMap<String, Value> =
        serde_json::from_value(userinfo.take()).map_err(|e| RouteError::Internal(Box::new(e)))?;
    let login = identified_login(&claims)
        .ok_or_else(|| UserInfoError::ProviderError {
            code: 0,
            msg: "GitHub userinfo has no account id or login".to_owned(),
        })?
        .to_owned();
    let emails = fetch_emails(client, &emails_endpoint(userinfo_endpoint), access_token).await?;
    normalize_claims(&mut claims, &emails);
    if let Some(localpart) = first_free_localpart(repo, &sanitize_localpart(&login)).await? {
        claims.insert(LOCALPART_CLAIM.to_owned(), Value::String(localpart));
    }
    *userinfo = serde_json::to_value(claims).map_err(|e| RouteError::Internal(Box::new(e)))?;
    Ok(())
}

/// First candidate not used by an existing Pasion user, or `None` when every
/// suffix up to the limit is taken (the user then picks a username).
async fn first_free_localpart(
    repo: &mut BoxRepository,
    base: &str,
) -> Result<Option<String>, RepositoryError> {
    for candidate in localpart_candidates(base) {
        if !repo.user().exists(&candidate).await? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}
