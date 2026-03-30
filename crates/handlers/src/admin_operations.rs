//! Admin operations facade.
//!
//! Consolidates admin operational logic so handlers don't directly
//! orchestrate multiple repositories and services.

use pasion_data_model::{Clock, User, audit::AdminOperation};
use pasion_storage::{BoxRepository, RepositoryAccess, RepositoryError};
use rand::RngCore;
use thiserror::Error;

use crate::admin_audit_helper::record_admin_operation;

#[derive(Debug, Error)]
pub enum AdminOperationError {
    #[error("user not found")]
    UserNotFound,
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Lock a user and record an audit log.
pub async fn lock_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin: Option<&User>,
    user_id: ulid::Ulid,
) -> Result<User, AdminOperationError> {
    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AdminOperationError::UserNotFound)?;

    let user = repo.user().lock(clock, user).await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin,
        AdminOperation::UserLocked,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    Ok(user)
}

/// Unlock a user and record an audit log.
pub async fn unlock_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin: Option<&User>,
    user_id: ulid::Ulid,
) -> Result<User, AdminOperationError> {
    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AdminOperationError::UserNotFound)?;

    let user = repo.user().unlock(user).await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin,
        AdminOperation::UserUnlocked,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    Ok(user)
}

/// Deactivate a user and record an audit log.
pub async fn deactivate_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin: Option<&User>,
    user_id: ulid::Ulid,
) -> Result<User, AdminOperationError> {
    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AdminOperationError::UserNotFound)?;

    let user = repo.user().deactivate(clock, user).await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin,
        AdminOperation::UserDeactivated,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    Ok(user)
}

/// Reactivate a user and record an audit log.
pub async fn reactivate_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin: Option<&User>,
    user_id: ulid::Ulid,
) -> Result<User, AdminOperationError> {
    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AdminOperationError::UserNotFound)?;

    let user = repo.user().reactivate(user).await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin,
        AdminOperation::UserReactivated,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    Ok(user)
}
