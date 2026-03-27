//! REST API endpoints for managing linked upstream OAuth accounts.
//!
//! These endpoints allow authenticated users to view and unlink their
//! connected external accounts (GitHub, Google, etc.).

use pasion_storage::{
    RepositoryAccess, Pagination,
    upstream_oauth2::{
        UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
    },
};
use salvo::prelude::*;
use serde::Serialize;
use ulid::Ulid;

use super::{
    RouteError, extract_bound_activity_tracker, extract_session_info, get_repo_factory,
    get_requester, make_clock,
};

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccount>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccount {
    pub id: String,
    pub provider_id: String,
    pub provider_name: Option<String>,
    pub provider_brand: Option<String>,
    pub subject: String,
    pub human_account_name: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkResponse {
    pub status: &'static str,
}

// ── GET /api/v1/linked-accounts ─────────────────────────────────

/// Returns the list of upstream OAuth providers linked to the current user.
#[handler]
pub async fn list_linked_accounts(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<LinkedAccountsResponse>, RouteError> {
    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => {
            return Err(RouteError::Unauthorized);
        }
    };

    let filter = UpstreamOAuthLinkFilter::new().for_user(user);
    let page = repo
        .upstream_oauth_link()
        .list(filter, Pagination::first(100))
        .await?;

    // Fetch all enabled providers to resolve names
    let providers = repo.upstream_oauth_provider().all_enabled().await?;
    let provider_map: std::collections::HashMap<Ulid, _> = providers
        .into_iter()
        .map(|p| (p.id, (p.human_name, p.brand_name)))
        .collect();

    let accounts: Vec<LinkedAccount> = page
        .edges
        .into_iter()
        .map(|edge| {
            let link = edge.node;
            let (provider_name, provider_brand) = provider_map
                .get(&link.provider_id)
                .cloned()
                .unwrap_or((None, None));
            LinkedAccount {
                id: link.id.to_string(),
                provider_id: link.provider_id.to_string(),
                provider_name,
                provider_brand,
                subject: link.subject,
                human_account_name: link.human_account_name,
                created_at: link.created_at.to_rfc3339(),
            }
        })
        .collect();

    repo.cancel().await?;

    Ok(Json(LinkedAccountsResponse { accounts }))
}

// ── DELETE /api/v1/linked-accounts/{id} ─────────────────────────

/// Unlink an upstream OAuth provider from the current user.
#[handler]
pub async fn unlink_account(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<UnlinkResponse>, RouteError> {
    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => session.user.clone(),
        _ => {
            return Err(RouteError::Unauthorized);
        }
    };

    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let link = repo
        .upstream_oauth_link()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Verify the link belongs to the current user
    if link.user_id != Some(user.id) {
        return Err(RouteError::NotFound);
    }

    repo.upstream_oauth_link().remove(&clock, link).await?;
    repo.save().await?;

    Ok(Json(UnlinkResponse { status: "unlinked" }))
}
