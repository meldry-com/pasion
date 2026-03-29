use std::{net::IpAddr, str::FromStr};

use lettre::Address;
use pasion_data_model::{Clock, UserRecoverySession};
use pasion_storage::{BoxRepository, RepositoryAccess, RepositoryError};
use rand::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::{Limiter, RequesterFingerprint, notification_dispatch::schedule_account_recovery};

#[derive(Debug, Error)]
pub enum StartAccountRecoveryError {
    #[error("invalid email address")]
    InvalidEmail,

    #[error("account recovery is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum LoadAccountRecoverySessionError {
    #[error("account recovery session not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum ResendAccountRecoveryError {
    #[error("account recovery session not found")]
    NotFound,

    #[error("account recovery session already consumed")]
    AlreadyConsumed,

    #[error("account recovery is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn start_account_recovery(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    email: String,
    user_agent: String,
    ip_address: Option<IpAddr>,
    locale: String,
) -> Result<UserRecoverySession, StartAccountRecoveryError> {
    if Address::from_str(&email).is_err() {
        return Err(StartAccountRecoveryError::InvalidEmail);
    }

    if let Err(error) = limiter.check_account_recovery(requester, &email) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(StartAccountRecoveryError::RateLimited);
    }

    let session = repo
        .user_recovery()
        .add_session(rng, clock, email, user_agent, ip_address, locale)
        .await?;

    schedule_account_recovery(&mut repo, rng, clock, &session).await?;
    repo.save().await?;

    Ok(session)
}

pub async fn load_account_recovery_session(
    repo: &mut BoxRepository,
    id: Ulid,
) -> Result<UserRecoverySession, LoadAccountRecoverySessionError> {
    repo.user_recovery()
        .lookup_session(id)
        .await?
        .ok_or(LoadAccountRecoverySessionError::NotFound)
}

pub async fn resend_account_recovery(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    session_id: Ulid,
) -> Result<UserRecoverySession, ResendAccountRecoveryError> {
    let session = load_account_recovery_session(&mut repo, session_id)
        .await
        .map_err(|error| match error {
            LoadAccountRecoverySessionError::NotFound => ResendAccountRecoveryError::NotFound,
            LoadAccountRecoverySessionError::Repository(error) => {
                ResendAccountRecoveryError::Repository(error)
            }
        })?;

    if session.consumed_at.is_some() {
        return Err(ResendAccountRecoveryError::AlreadyConsumed);
    }

    if let Err(error) = limiter.check_account_recovery(requester, &session.email) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(ResendAccountRecoveryError::RateLimited);
    }

    schedule_account_recovery(&mut repo, rng, clock, &session).await?;
    repo.save().await?;

    Ok(session)
}

#[must_use]
pub fn recovery_session_status(session: &UserRecoverySession) -> &'static str {
    if session.consumed_at.is_some() {
        "consumed"
    } else {
        "pending"
    }
}
