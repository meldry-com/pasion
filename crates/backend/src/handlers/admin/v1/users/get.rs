use salvo::prelude::*;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::User,
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}
