//! Service functions for password management.
//!
//! These functions encapsulate the business logic for changing passwords and
//! resetting passwords via recovery tickets. They are consumed by the REST
//! handlers in [`crate::rest::password`].

use anyhow::{Context as _, Error as AnyhowError};
use pasion_data_model::Clock;
use pasion_storage::{
    BoxRepository, RepositoryAccess, RepositoryError,
    user::{UserEmailRepository, UserPasswordRepository, UserRecoveryRepository, UserRepository},
};
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    Limiter, RequesterFingerprint,
    account_recovery::{ResendAccountRecoveryError, resend_account_recovery},
    passwords::PasswordManager,
};

// ── Change password ───────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ChangePasswordError {
    #[error("password manager is disabled")]
    PasswordDisabled,

    #[error("new password is too weak")]
    PasswordTooWeak,

    #[error("user not found")]
    UserNotFound,

    #[error("password changes are not allowed")]
    PasswordChangesDisabled,

    #[error("no current password set")]
    NoCurrentPassword,

    #[error("current password is required")]
    CurrentPasswordRequired,

    #[error("current password is incorrect")]
    WrongPassword,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Change the password for an existing user.
///
/// When `is_admin` is `false`, the `current_password` must be provided and
/// verified against the stored hash. Admins can set a new password without
/// knowing the current one.
///
/// The caller is responsible for verifying ownership (is_owner_or_admin)
/// before calling this function.
pub async fn change_password(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    user_id: ulid::Ulid,
    current_password: Option<Zeroizing<String>>,
    new_password: Zeroizing<String>,
    is_admin: bool,
    password_change_allowed: bool,
) -> Result<(), ChangePasswordError> {
    if new_password.is_empty() {
        return Err(ChangePasswordError::PasswordTooWeak);
    }

    if !password_manager.is_enabled() {
        return Err(ChangePasswordError::PasswordDisabled);
    }

    if !password_manager
        .is_password_complex_enough(&new_password)
        .map_err(|e| ChangePasswordError::Password(e.into()))?
    {
        return Err(ChangePasswordError::PasswordTooWeak);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(ChangePasswordError::UserNotFound)?;

    if !is_admin {
        if !password_change_allowed {
            return Err(ChangePasswordError::PasswordChangesDisabled);
        }

        let active_password = repo
            .user_password()
            .active(&user)
            .await?
            .ok_or(ChangePasswordError::NoCurrentPassword)?;

        let current = current_password.ok_or(ChangePasswordError::CurrentPasswordRequired)?;

        if !password_manager
            .verify(
                active_password.version,
                current,
                active_password.hashed_password,
            )
            .await
            .map_err(ChangePasswordError::Password)?
            .is_success()
        {
            return Err(ChangePasswordError::WrongPassword);
        }
    }

    let (version, hash) = password_manager
        .hash(make_rng_from(rng), new_password)
        .await
        .map_err(ChangePasswordError::Password)?;

    repo.user_password()
        .add(rng, clock, &user, version, hash, None)
        .await?;

    repo.save().await?;

    Ok(())
}

// ── Reset password by recovery ticket ─────────────────────────

#[derive(Debug, Error)]
pub enum ResetPasswordByRecoveryError {
    #[error("password manager is disabled")]
    PasswordDisabled,

    #[error("new password is too weak")]
    PasswordTooWeak,

    #[error("recovery ticket not found")]
    TicketNotFound,

    #[error("recovery session not found")]
    SessionNotFound,

    #[error("recovery ticket already consumed")]
    AlreadyConsumed,

    #[error("recovery ticket has expired")]
    TicketExpired,

    #[error("user email not found")]
    EmailNotFound,

    #[error("user not found")]
    UserNotFound,

    #[error("user account is locked")]
    AccountLocked,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Reset a user's password using a recovery ticket.
///
/// This validates the ticket, verifies the associated user is active, hashes
/// the new password, saves it, and consumes the ticket so it cannot be reused.
pub async fn reset_password_by_recovery(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    ticket_string: &str,
    new_password: Zeroizing<String>,
    recovery_allowed: bool,
) -> Result<(), ResetPasswordByRecoveryError> {
    if !password_manager.is_enabled() || !recovery_allowed {
        return Err(ResetPasswordByRecoveryError::PasswordDisabled);
    }

    if !password_manager
        .is_password_complex_enough(&new_password)
        .map_err(|e| ResetPasswordByRecoveryError::Password(e.into()))?
    {
        return Err(ResetPasswordByRecoveryError::PasswordTooWeak);
    }

    let ticket = repo
        .user_recovery()
        .find_ticket(ticket_string)
        .await?
        .ok_or(ResetPasswordByRecoveryError::TicketNotFound)?;

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Unknown session")
        .map_err(|_| ResetPasswordByRecoveryError::SessionNotFound)?;

    if session.consumed_at.is_some() {
        return Err(ResetPasswordByRecoveryError::AlreadyConsumed);
    }

    if !ticket.active(clock.now()) {
        return Err(ResetPasswordByRecoveryError::TicketExpired);
    }

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        .context("Unknown email")
        .map_err(|_| ResetPasswordByRecoveryError::EmailNotFound)?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Invalid user")
        .map_err(|_| ResetPasswordByRecoveryError::UserNotFound)?;

    if !user.is_valid() {
        return Err(ResetPasswordByRecoveryError::AccountLocked);
    }

    let (version, hash) = password_manager
        .hash(make_rng_from(rng), new_password)
        .await
        .map_err(ResetPasswordByRecoveryError::Password)?;

    repo.user_password()
        .add(rng, clock, &user, version, hash, None)
        .await?;

    repo.user_recovery()
        .consume_ticket(clock, ticket, session)
        .await?;

    repo.save().await?;

    Ok(())
}

// ── Resend recovery email by ticket ───────────────────────────

#[derive(Debug, Error)]
pub enum ResendRecoveryByTicketError {
    #[error("recovery ticket not found")]
    TicketNotFound,

    #[error("recovery session not found")]
    SessionNotFound,

    #[error("recovery session already consumed")]
    AlreadyConsumed,

    #[error("account recovery resend is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Resend a recovery email, looking up the session from a recovery ticket.
pub async fn resend_recovery_by_ticket(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn rand::RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    ticket_string: &str,
) -> Result<(), ResendRecoveryByTicketError> {
    let ticket = repo
        .user_recovery()
        .find_ticket(ticket_string)
        .await?
        .ok_or(ResendRecoveryByTicketError::TicketNotFound)?;

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Could not load recovery session")
        .map_err(|_| ResendRecoveryByTicketError::SessionNotFound)?;

    let session_id = session.id;

    // Hand off to the recovery service function, which takes ownership of repo
    match resend_account_recovery(repo, limiter, rng, clock, requester, session_id).await {
        Ok(_) => Ok(()),
        Err(ResendAccountRecoveryError::NotFound) => {
            Err(ResendRecoveryByTicketError::SessionNotFound)
        }
        Err(ResendAccountRecoveryError::AlreadyConsumed) => {
            Err(ResendRecoveryByTicketError::AlreadyConsumed)
        }
        Err(ResendAccountRecoveryError::RateLimited) => {
            Err(ResendRecoveryByTicketError::RateLimited)
        }
        Err(ResendAccountRecoveryError::Repository(error)) => {
            Err(ResendRecoveryByTicketError::Repository(error))
        }
    }
}

/// Create a new RNG from the provided one, suitable for `PasswordManager::hash`
/// which requires `CryptoRng + RngCore + Send`.
fn make_rng_from(rng: &mut (dyn CryptoRngCore + Send)) -> rand_chacha::ChaChaRng {
    use rand_chacha::rand_core::SeedableRng;
    rand_chacha::ChaChaRng::from_rng(rng).expect("seeding ChaChaRng should not fail")
}
