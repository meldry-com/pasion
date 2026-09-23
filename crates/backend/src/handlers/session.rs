// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Session-limit helpers.

use pasion_data::{
    BoxRepository, RepositoryError, User, oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
};
use pasion_policy::model::SessionCounts;

/// Count all active sessions belonging to the given user, for use in
/// session-limit enforcement.
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let num_oauth2 = repo
        .oauth2_session()
        .count(OAuth2SessionFilter::new().active_only().for_user(user))
        .await? as u64;

    let num_personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .active_only()
                .for_actor_user(user)
                .for_owner_user(user),
        )
        .await? as u64;

    Ok(SessionCounts {
        total: num_oauth2 + num_personal,
        oauth2: num_oauth2,
        personal: num_personal,
    })
}
