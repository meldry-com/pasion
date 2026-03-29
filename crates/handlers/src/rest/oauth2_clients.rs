use salvo::prelude::*;
use serde::Serialize;

use super::{DepotExt, NodeType, RouteError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2ClientResponse {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String> }

/// GET /api/v1/oauth2-clients/:id
#[handler]
pub async fn get_client(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<Oauth2ClientResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Client.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let mut repo = repo_factory.create().await?;

    let client = repo
        .oauth2_client()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    repo.cancel().await?;

    Ok(Json(Oauth2ClientResponse {
        id: NodeType::OAuth2Client.serialize(client.id),
        client_id: client.client_id.to_string(),
        client_name: client.client_name.clone(),
        client_uri: client.client_uri.as_ref().map(|u| u.to_string()),
        tos_uri: client.tos_uri.as_ref().map(|u| u.to_string()),
        policy_uri: client.policy_uri.as_ref().map(|u| u.to_string()),
        logo_uri: client.logo_uri.as_ref().map(|u| u.to_string()) }))
}
