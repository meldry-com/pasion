use anyhow::{Context as _, Error as AnyhowError};
use pasion_data_model::{Clock, SiteConfig, User, UserEmail};
use pasion_matrix::HomeserverConnection;
use pasion_storage::{
    BoxRepository, RepositoryAccess, RepositoryError,
    queue::{DeactivateUserJob, QueueJobRepositoryExt as _},
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
};
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::{passwords::PasswordManager, rest::Requester};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetDisplayNameOutcome {
    Set,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivateAccountOutcome {
    IncorrectPassword,
    Deactivated,
}

#[derive(Debug, Error)]
pub enum AccountProfileError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("browser session required")]
    BrowserSessionRequired,

    #[error("account deactivation is disabled")]
    DeactivationDisabled,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Homeserver(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn set_display_name(
    mut repo: BoxRepository,
    requester: &Requester,
    homeserver: &dyn HomeserverConnection,
    user_id: Ulid,
    display_name: Option<String>,
) -> Result<SetDisplayNameOutcome, AccountProfileError> {
    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(AccountProfileError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AccountProfileError::NotFound)?;

    let Some(name) = display_name.as_deref() else {
        repo.cancel().await?;
        homeserver
            .unset_displayname(&user.username)
            .await
            .map_err(AccountProfileError::Homeserver)?;
        return Ok(SetDisplayNameOutcome::Set);
    };

    if name.is_empty() || name.len() > 256 {
        repo.cancel().await?;
        return Ok(SetDisplayNameOutcome::Invalid);
    }

    repo.cancel().await?;

    homeserver
        .set_displayname(&user.username, name)
        .await
        .map_err(AccountProfileError::Homeserver)?;

    Ok(SetDisplayNameOutcome::Set)
}

pub async fn allow_cross_signing_reset(
    mut repo: BoxRepository,
    requester: &Requester,
    homeserver: &dyn HomeserverConnection,
    user_id: Ulid,
) -> Result<User, AccountProfileError> {
    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(AccountProfileError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AccountProfileError::NotFound)?;

    repo.cancel().await?;

    homeserver
        .allow_cross_signing_reset(&user.username)
        .await
        .context("failed to allow cross-signing reset")
        .map_err(AccountProfileError::Homeserver)?;

    Ok(user)
}

pub async fn deactivate_current_account(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    hs_erase: bool,
) -> Result<DeactivateAccountOutcome, AccountProfileError> {
    let Some(browser_session) = requester.browser_session() else {
        return Err(AccountProfileError::BrowserSessionRequired);
    };

    if !config.account_deactivation_allowed {
        return Err(AccountProfileError::DeactivationDisabled);
    }

    let password_ok = crate::handlers::account_password::verify_password_if_needed(
        requester.is_admin(),
        config.password_login_enabled,
        password_manager,
        password,
        &browser_session.user,
        &mut repo,
    )
    .await
    .map_err(|error| match error {
        crate::handlers::account_password::VerifyPasswordIfNeededError::Password(error) => {
            AccountProfileError::Password(error)
        }
        crate::handlers::account_password::VerifyPasswordIfNeededError::Repository(error) => {
            AccountProfileError::Repository(error)
        }
    })?;

    if !password_ok {
        repo.cancel().await?;
        return Ok(DeactivateAccountOutcome::IncorrectPassword);
    }

    let user = repo
        .user()
        .deactivate(clock, browser_session.user.clone())
        .await?;

    repo.queue_job()
        .schedule_job(rng, clock, DeactivateUserJob::new(&user, hs_erase))
        .await?;

    repo.save().await?;

    Ok(DeactivateAccountOutcome::Deactivated)
}

/// Profile information for the current viewer, combining data from the
/// repository and the homeserver.
pub struct ViewerProfile {
    pub emails: Vec<UserEmail>,
    pub has_password: bool,
    pub matrix_display_name: Option<String>,
    pub mxid: String,
}

/// Load the viewer profile for a given user.
///
/// This fetches the user's email list, password status, and Matrix profile
/// information in a single service call.
pub async fn load_viewer_profile(
    repo: &mut BoxRepository,
    homeserver: &dyn HomeserverConnection,
    user: &User,
) -> Result<ViewerProfile, AccountProfileError> {
    // Fetch matrix info
    let mxid = homeserver.mxid(&user.username);
    let matrix_display_name = match homeserver.query_user(&user.username).await {
        Ok(info) => info.displayname,
        Err(_) => None,
    };

    // Fetch emails
    let emails = repo.user_email().all(user).await?;

    // Check password
    let has_password = repo.user_password().active(user).await?.is_some();

    Ok(ViewerProfile {
        emails,
        has_password,
        matrix_display_name,
        mxid,
    })
}
