// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

pub mod add;
pub mod get;
pub mod list;
pub mod regenerate;
pub mod revoke;

use pasion_data::personal::session::PersonalSessionOwner;

use crate::handlers::admin::call_context::CallerSession;

/// Derives the [`PersonalSessionOwner`] from the caller's active session,
/// so that newly created personal sessions are attributed correctly.
pub(crate) fn personal_session_owner_from_caller(caller: &CallerSession) -> PersonalSessionOwner {
    match caller {
        CallerSession::OAuth2Session(entry) => {
            if let Some(uid) = entry.user_id {
                PersonalSessionOwner::User(uid)
            } else {
                PersonalSessionOwner::OAuth2Client(entry.client_id)
            }
        }
        CallerSession::PersonalSession(entry) => {
            PersonalSessionOwner::User(entry.actor_user_id)
        }
    }
}
