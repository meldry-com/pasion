use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};

use crate::{
    admin::{
        call_context::extract_call_context,
        model::{InconsistentPersonalSession, PersonalSession},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Personal session not found")]
    NotFound,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::admin::call_context::Rejection);
impl_from_error_for_route!(InconsistentPersonalSession);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
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

#[handler]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<PersonalSession>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let session_id = id;

    let session = repo
        .personal_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let token = if session.is_revoked() {
        None
    } else {
        repo.personal_access_token()
            .find_active_for_session(&session)
            .await?
    };

    Ok(Json(SingleResponse::new_canonical(
        PersonalSession::try_from((session, token))?,
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data_model::personal::session::PersonalSessionOwner;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(&mut rng, &state.clock, &personal_session, "mpt_hiss", None)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/api/admin/v1/personal-sessions/{}",
            personal_session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["id"], personal_session.id.to_string());
        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "owner_client_id": null,
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test session",
              "scope": "openid",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": null
            },
            "links": {
              "self": "/api/admin/v1/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/api/admin/v1/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let session_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/personal-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
