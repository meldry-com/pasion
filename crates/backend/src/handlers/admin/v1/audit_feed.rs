//! Admin endpoint for retrieving recent admin audit operations.
//!
//! Returns a feed of admin operations, optionally filtered by admin user or
//! resource type. Since we don't yet have a dedicated `AuditRepository`, this
//! endpoint returns an empty feed as a placeholder.

use chrono::{DateTime, Utc};
use salvo::prelude::*;
use schemars::JsonSchema;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

use crate::handlers::admin::call_context::extract_call_context;
use crate::JsonResult;

/// A single entry in the admin audit feed.
#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// Unique identifier for this audit entry.
    pub id: String,

    /// The admin user who performed the operation, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_user_id: Option<String>,

    /// The operation that was performed, e.g. `"user.lock"`, `"session.finish"`.
    pub operation: String,

    /// The type of resource that was acted upon, e.g. `"user"`, `"session"`.
    pub resource_type: String,

    /// The identifier of the resource that was acted upon.
    pub resource_id: String,

    /// Additional details about the operation (free-form JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// When the operation was performed.
    pub created_at: DateTime<Utc>,
}

/// Response body for the audit feed endpoint.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AuditFeedResponse {
    /// The list of audit entries, ordered by most recent first.
    pub data: Vec<AuditEntry>,
}

/// Query parameters accepted by the audit feed endpoint.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditFeedQuery {
    /// Maximum number of entries to return (default: 50).
    pub limit: Option<usize>,

    /// If provided, only return entries for this admin user.
    pub admin_user_id: Option<String>,

    /// If provided, only return entries matching this resource type.
    pub resource_type: Option<String>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.audit_feed", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AuditFeedResponse> {
    let call_context = extract_call_context(req, depot).await?;

    let _query: AuditFeedQuery = req.parse_queries().unwrap_or_default();

    // TODO: Once an AuditRepository exists, query it here using:
    //   - _query.limit.unwrap_or(50) for the page size
    //   - _query.admin_user_id to filter by acting admin
    //   - _query.resource_type to filter by resource kind
    //
    // For now we return an empty feed.

    call_context.repo.cancel().await?; // read-only, no save needed

    Ok(Json(AuditFeedResponse { data: vec![] }))
}
