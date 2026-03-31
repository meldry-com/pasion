use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::User,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[derive(Deserialize, JsonSchema)]
pub struct UsernamePathParam {
    /// The username (localpart) of the user to get
    username: String,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.by_username", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let username: String = req
        .param::<String>("username")
        .ok_or_else(|| AppError::not_found(r#"User with username "unknown" not found"#))?;

    let self_path = format!("/api/admin/v1/users/by-username/{username}");
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User with username {username:?} not found")))?;

    Ok(Json(SingleResponse::new(User::from(user), self_path)))
}
