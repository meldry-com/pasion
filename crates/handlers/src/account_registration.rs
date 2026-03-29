use std::net::IpAddr;

use anyhow::Error as AnyhowError;
use pasion_data_model::{Clock, UserRegistration};
use pasion_storage::{
    BoxRepository, RepositoryAccess, RepositoryError,
    user::{UserEmailRepository, UserPhoneRepository},
};
use rand_chacha::rand_core::CryptoRngCore;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Limiter, RequesterFingerprint,
    notification_dispatch::{schedule_email_authentication_code, schedule_sms_authentication_code},
    passwords::PasswordManager,
};

pub struct StartPasswordRegistrationRequest {
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub post_auth_action: Option<Value>,
    pub terms_url: Option<Url>,
    pub notification_language: String,
}

pub struct StartedPasswordRegistration {
    pub registration: UserRegistration,
    pub email_verified: bool,
    pub phone_verified: bool,
}

#[derive(Debug, Error)]
pub enum StartPasswordRegistrationError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Password(#[from] AnyhowError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResendRegistrationVerificationStatus {
    RegistrationCompleted,
    Resent,
    AlreadyVerified,
}

#[derive(Debug, Error)]
pub enum ResendRegistrationVerificationError {
    #[error("registration not found")]
    NotFound,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn start_password_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    request: StartPasswordRegistrationRequest,
) -> Result<StartedPasswordRegistration, StartPasswordRegistrationError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            request.username,
            request.ip_address,
            request.user_agent,
            request.post_auth_action,
        )
        .await?;

    if let Some(terms_url) = request.terms_url {
        registration = repo
            .user_registration()
            .set_terms_url(registration, terms_url)
            .await?;
    }

    let email_verified = if let Some(email) = request.email {
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;

        schedule_email_authentication_code(
            &mut repo,
            rng,
            clock,
            &user_email_authentication,
            request.notification_language.clone(),
        )
        .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?;

        false
    } else {
        true
    };

    let phone_verified = if let Some(phone) = request.phone {
        let user_phone_authentication = repo
            .user_phone()
            .add_authentication_for_registration(rng, clock, phone, &registration)
            .await?;

        schedule_sms_authentication_code(
            &mut repo,
            rng,
            clock,
            &user_phone_authentication,
            request.notification_language,
        )
        .await?;

        registration = repo
            .user_registration()
            .set_phone_authentication(registration, &user_phone_authentication)
            .await?;

        false
    } else {
        true
    };

    let (version, hashed_password) = password_manager.hash(rng, request.password).await?;

    registration = repo
        .user_registration()
        .set_password(registration, hashed_password, version)
        .await?;

    repo.save().await?;

    Ok(StartedPasswordRegistration {
        registration,
        email_verified,
        phone_verified,
    })
}

pub async fn resend_pending_registration_verification(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    notification_language: String,
) -> Result<ResendRegistrationVerificationStatus, ResendRegistrationVerificationError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(ResendRegistrationVerificationError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(ResendRegistrationVerificationStatus::RegistrationCompleted);
    }

    if let Some(email_authentication_id) = registration.email_authentication_id {
        let auth = repo
            .user_email()
            .lookup_authentication(email_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter.check_email_authentication_send_code(requester, &auth) {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_email_authentication_code(&mut repo, rng, clock, &auth, notification_language)
                .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    if let Some(phone_authentication_id) = registration.phone_authentication_id {
        let auth = repo
            .user_phone()
            .lookup_authentication(phone_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter.check_phone_authentication_send_code(requester, &auth) {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_sms_authentication_code(&mut repo, rng, clock, &auth, notification_language)
                .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    Ok(ResendRegistrationVerificationStatus::AlreadyVerified)
}
