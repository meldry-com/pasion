use salvo::prelude::*;
use salvo::http::StatusCode;
use pasion_salvo_utils::record_error;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::User,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User with username {0:?} not found")]
    NotFound(String),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct UsernamePathParam {
    /// The username (localpart) of the user to get
    username: String,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.users.by_username", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot) -> Result<Json<SingleResponse<User>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, .. } = call_context;
    let username: String = req.param::<String>("username").ok_or_else(|| RouteError::NotFound("unknown".to_owned()))?;

    let self_path = format!("/api/admin/v1/users/by-username/{username}");
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .ok_or(RouteError::NotFound(username))?;

    Ok(Json(SingleResponse::new(User::from(user), self_path)))
}
