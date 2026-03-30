pub mod add;
pub mod get;
pub mod list;
pub mod regenerate;
pub mod revoke;

use pasion_data_model::personal::session::PersonalSessionOwner;

use crate::handlers::admin::call_context::CallerSession;

/// Given the [`CallerSession`] of a caller of the Admin API,
/// return the [`PersonalSessionOwner`] that should own created personal
/// sessions.
pub(crate) fn personal_session_owner_from_caller(caller: &CallerSession) -> PersonalSessionOwner {
    match caller {
        CallerSession::OAuth2Session(session) => {
            if let Some(user_id) = session.user_id {
                PersonalSessionOwner::User(user_id)
            } else {
                PersonalSessionOwner::OAuth2Client(session.client_id)
            }
        }
        CallerSession::PersonalSession(session) => {
            PersonalSessionOwner::User(session.actor_user_id)
        }
    }
}
