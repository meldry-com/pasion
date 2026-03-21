mod add;
mod get;
mod list;
mod regenerate;
mod revoke;

use pasion_data_model::personal::session::PersonalSessionOwner;

pub use self::{
    add::{doc as add_doc, handler as add},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
    regenerate::{doc as regenerate_doc, handler as regenerate},
    revoke::{doc as revoke_doc, handler as revoke},
};
use crate::admin::call_context::CallerSession;

/// Given the [`CallerSession`] of a caller of the Admin API,
/// return the [`PersonalSessionOwner`] that should own created personal
/// sessions.
fn personal_session_owner_from_caller(caller: &CallerSession) -> PersonalSessionOwner {
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
