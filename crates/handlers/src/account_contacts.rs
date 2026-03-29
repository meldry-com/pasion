//! Service functions for user contact (email/phone) verification and management.
//!
//! These functions encapsulate the business logic for adding, verifying, and
//! removing contact information on an existing user account. They are consumed
//! by the REST handlers in [`crate::rest::emails`].

use pasion_data_model::{BrowserSession, Clock, User, UserEmailAuthentication};
use pasion_storage::{
    BoxRepository, RepositoryAccess, RepositoryError,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailRepository,
};
use rand::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Limiter, RequesterFingerprint,
    notification_dispatch::schedule_email_authentication_code,
};

// ── Start email verification ──────────────────────────────────

#[derive(Debug, Error)]
pub enum StartEmailVerificationError {
    #[error("email verification is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub struct StartedEmailVerification {
    pub authentication: UserEmailAuthentication,
}

/// Begin an email verification flow for an existing user session.
///
/// Creates a [`UserEmailAuthentication`] record and schedules a verification
/// code notification. The caller is responsible for checking config flags
/// (e.g. `email_change_allowed`) and verifying the user's password before
/// calling this function.
pub async fn start_email_verification(
    mut repo: BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    browser_session: &BrowserSession,
    email: String,
    notification_language: String,
) -> Result<StartedEmailVerification, StartEmailVerificationError> {
    if let Err(error) = limiter.check_email_authentication_email(requester, &email) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(StartEmailVerificationError::RateLimited);
    }

    let auth = repo
        .user_email()
        .add_authentication_for_session(rng, clock, email, browser_session)
        .await?;

    schedule_email_authentication_code(&mut repo, rng, clock, &auth, notification_language)
        .await?;

    repo.save().await?;

    Ok(StartedEmailVerification {
        authentication: auth,
    })
}

// ── Complete email verification ───────────────────────────────

#[derive(Debug, Error)]
pub enum CompleteEmailVerificationError {
    #[error("email authentication not found")]
    NotFound,

    #[error("email authentication does not belong to this session")]
    NotOwned,

    #[error("email authentication already completed")]
    AlreadyCompleted,

    #[error("email verification is rate limited")]
    RateLimited,

    #[error("invalid verification code")]
    InvalidCode,

    #[error("verification code has expired")]
    CodeExpired,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Verify an email authentication code and, if successful, add the email to
/// the user's account.
pub async fn complete_email_verification(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    authentication_id: Ulid,
    session_id: Ulid,
    user: &User,
    code: &str,
) -> Result<(), CompleteEmailVerificationError> {
    let auth = repo
        .user_email()
        .lookup_authentication(authentication_id)
        .await?
        .ok_or(CompleteEmailVerificationError::NotFound)?;

    if auth.user_session_id != Some(session_id) {
        return Err(CompleteEmailVerificationError::NotOwned);
    }

    if auth.completed_at.is_some() {
        return Err(CompleteEmailVerificationError::AlreadyCompleted);
    }

    if let Err(error) = limiter.check_email_authentication_attempt(&auth) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(CompleteEmailVerificationError::RateLimited);
    }

    let found_code = repo
        .user_email()
        .find_authentication_code(&auth, code)
        .await?
        .ok_or(CompleteEmailVerificationError::InvalidCode)?;

    if found_code.expires_at < clock.now() {
        return Err(CompleteEmailVerificationError::CodeExpired);
    }

    repo.user_email()
        .complete_authentication_with_code(clock, auth.clone(), &found_code)
        .await?;

    // Add email to user if not already present
    let existing = repo.user_email().find(user, &auth.email).await?;
    if existing.is_none() {
        repo.user_email()
            .add(rng, clock, user, auth.email.clone())
            .await?;
    }

    repo.save().await?;

    Ok(())
}

// ── Resend email verification code ────────────────────────────

#[derive(Debug, Error)]
pub enum ResendEmailVerificationError {
    #[error("email authentication not found")]
    NotFound,

    #[error("email authentication does not belong to this session")]
    NotOwned,

    #[error("email authentication already completed")]
    AlreadyCompleted,

    #[error("email verification resend is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Resend the verification code for an in-progress email authentication.
pub async fn resend_email_verification_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    authentication_id: Ulid,
    session_id: Ulid,
    notification_language: String,
) -> Result<(), ResendEmailVerificationError> {
    let auth = repo
        .user_email()
        .lookup_authentication(authentication_id)
        .await?
        .ok_or(ResendEmailVerificationError::NotFound)?;

    if auth.user_session_id != Some(session_id) {
        return Err(ResendEmailVerificationError::NotOwned);
    }

    if auth.completed_at.is_some() {
        return Err(ResendEmailVerificationError::AlreadyCompleted);
    }

    if let Err(error) = limiter.check_email_authentication_send_code(requester, &auth) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(ResendEmailVerificationError::RateLimited);
    }

    schedule_email_authentication_code(&mut repo, rng, clock, &auth, notification_language)
        .await?;

    repo.save().await?;

    Ok(())
}

// ── Remove user email ─────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RemoveUserEmailError {
    #[error("user email not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Remove an email address from a user's account.
///
/// The caller is responsible for verifying ownership and password before
/// calling this function.
pub async fn remove_user_email(
    mut repo: BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    email_id: Ulid,
    user: &User,
) -> Result<(), RemoveUserEmailError> {
    let email = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or(RemoveUserEmailError::NotFound)?;

    repo.user_email().remove(email).await?;

    repo.queue_job()
        .schedule_job(rng, clock, ProvisionUserJob::new(user))
        .await?;

    repo.save().await?;

    Ok(())
}
