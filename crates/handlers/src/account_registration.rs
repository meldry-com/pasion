use std::net::IpAddr;

use anyhow::Error as AnyhowError;
use pasion_data_model::{
    BrowserSession, Clock, UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, User,
    UserEmailAuthentication, UserPhoneAuthentication, UserRegistration, UserRegistrationToken,
};
use pasion_storage::{
    BoxRepository, RepositoryAccess, RepositoryError,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository},
    user::{
        BrowserSessionRepository, UserEmailRepository, UserFilter, UserPasswordRepository,
        UserPhoneRepository, UserRegistrationTokenRepository, UserRepository,
        UserTermsRepository,
    },
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

pub struct RegistrationProgress {
    pub registration: UserRegistration,
    pub email_authentication: Option<UserEmailAuthentication>,
    pub phone_authentication: Option<UserPhoneAuthentication>,
}

pub struct CompleteRegistrationRequest {
    pub registration: UserRegistration,
    pub registration_token: Option<UserRegistrationToken>,
    pub email_authentication: Option<UserEmailAuthentication>,
    pub phone_authentication: Option<UserPhoneAuthentication>,
    pub user_agent: Option<String>,
    pub upstream_oauth: Option<(UpstreamOAuthAuthorizationSession, UpstreamOAuthLink)>,
}

pub struct CompletedRegistration {
    pub registration: UserRegistration,
    pub user: User,
    pub user_session: BrowserSession,
    pub password_authenticated: bool,
}

impl RegistrationProgress {
    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.email_authentication.as_ref().map_or(
            self.registration.email_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn phone_verified(&self) -> bool {
        self.phone_authentication.as_ref().map_or(
            self.registration.phone_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn next_step(&self) -> &'static str {
        next_registration_step(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }

    #[must_use]
    pub fn completed_steps(&self) -> Vec<&'static str> {
        completed_registration_steps(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }
}

#[derive(Debug, Error)]
pub enum StartPasswordRegistrationError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Password(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum LoadRegistrationProgressError {
    #[error("registration not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
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

#[derive(Debug, Error)]
pub enum VerifyRegistrationEmailCodeError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("registration has no email authentication")]
    NoEmailAuthentication,

    #[error("registration email authentication not found")]
    EmailAuthenticationMissing,

    #[error("email authentication already completed")]
    EmailAlreadyVerified,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error("invalid email authentication code")]
    InvalidCode,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum VerifyRegistrationPhoneCodeError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("registration has no phone authentication")]
    NoPhoneAuthentication,

    #[error("registration phone authentication not found")]
    PhoneAuthenticationMissing,

    #[error("phone authentication already completed")]
    PhoneAlreadyVerified,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error("invalid phone authentication code")]
    InvalidCode,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum SetRegistrationDisplayNameError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("invalid display name")]
    InvalidDisplayName,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[must_use]
pub fn next_registration_step(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> &'static str {
    if registration.email_authentication_id.is_some() && !email_verified {
        return "verify_email";
    }

    if registration.phone_authentication_id.is_some() && !phone_verified {
        return "verify_phone";
    }

    if registration.display_name.is_none() {
        return "display_name";
    }

    "finish"
}

#[must_use]
pub fn completed_registration_steps(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> Vec<&'static str> {
    let mut steps = Vec::new();
    steps.push("register");

    if registration.email_authentication_id.is_some() && email_verified {
        steps.push("verify_email");
    }

    if registration.phone_authentication_id.is_some() && phone_verified {
        steps.push("verify_phone");
    }

    if registration.display_name.is_some() {
        steps.push("display_name");
    }

    if registration.completed_at.is_some() {
        steps.push("finish");
    }

    steps
}

pub async fn load_registration_progress(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationProgress, LoadRegistrationProgressError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(LoadRegistrationProgressError::NotFound)?;

    let email_authentication =
        if let Some(email_authentication_id) = registration.email_authentication_id {
            repo.user_email()
                .lookup_authentication(email_authentication_id)
                .await?
        } else {
            None
        };

    let phone_authentication =
        if let Some(phone_authentication_id) = registration.phone_authentication_id {
            repo.user_phone()
                .lookup_authentication(phone_authentication_id)
                .await?
        } else {
            None
        };

    Ok(RegistrationProgress {
        registration,
        email_authentication,
        phone_authentication,
    })
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

pub async fn verify_registration_email_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationEmailCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationEmailCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationEmailCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::RegistrationCompleted);
    }

    let email_authentication = if progress.registration.email_authentication_id.is_none() {
        return Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication);
    } else {
        progress
            .email_authentication
            .ok_or(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing)?
    };

    if email_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified);
    }

    if let Err(error) = limiter.check_email_authentication_attempt(&email_authentication) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationEmailCodeError::RateLimited);
    }

    let code = repo
        .user_email()
        .find_authentication_code(&email_authentication, code)
        .await?
        .ok_or(VerifyRegistrationEmailCodeError::InvalidCode)?;

    let email_authentication = repo
        .user_email()
        .complete_authentication_with_code(clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: Some(email_authentication),
        phone_authentication: progress.phone_authentication,
    })
}

pub async fn verify_registration_phone_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationPhoneCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationPhoneCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationPhoneCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted);
    }

    let phone_authentication = if progress.registration.phone_authentication_id.is_none() {
        return Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication);
    } else {
        progress
            .phone_authentication
            .ok_or(VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing)?
    };

    if phone_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified);
    }

    if let Err(error) = limiter.check_phone_authentication_attempt(&phone_authentication) {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationPhoneCodeError::RateLimited);
    }

    let code = repo
        .user_phone()
        .find_authentication_code(&phone_authentication, code)
        .await?
        .ok_or(VerifyRegistrationPhoneCodeError::InvalidCode)?;

    let phone_authentication = repo
        .user_phone()
        .complete_authentication_with_code(clock, phone_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: progress.email_authentication,
        phone_authentication: Some(phone_authentication),
    })
}

pub async fn set_registration_display_name(
    mut repo: BoxRepository,
    registration_id: Ulid,
    display_name: Option<String>,
    skip: bool,
) -> Result<UserRegistration, SetRegistrationDisplayNameError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(SetRegistrationDisplayNameError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(SetRegistrationDisplayNameError::RegistrationCompleted);
    }

    let display_name = if skip {
        registration.username.clone()
    } else {
        let display_name = display_name.as_deref().unwrap_or("").trim().to_owned();

        if display_name.is_empty() || display_name.len() > 255 {
            return Err(SetRegistrationDisplayNameError::InvalidDisplayName);
        }

        display_name
    };

    let registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    Ok(registration)
}

pub async fn complete_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    request: CompleteRegistrationRequest,
) -> Result<CompletedRegistration, RepositoryError> {
    let registration = repo
        .user_registration()
        .complete(clock, request.registration)
        .await?;

    if let Some(registration_token) = request.registration_token {
        repo.user_registration_token()
            .use_token(clock, registration_token)
            .await?;
    }

    let mut user = repo
        .user()
        .add(rng, clock, registration.username.clone())
        .await?;

    let user_count = repo.user().count(UserFilter::new()).await?;
    if user_count == 1 {
        user = repo.user().set_can_request_admin(user, true).await?;
    }

    let user_session = repo
        .browser_session()
        .add(rng, clock, &user, request.user_agent)
        .await?;

    if let Some(email_authentication) = request.email_authentication {
        repo.user_email()
            .add(rng, clock, &user, email_authentication.email)
            .await?;
    }

    if let Some(phone_authentication) = request.phone_authentication {
        repo.user_phone()
            .add(rng, clock, &user, phone_authentication.phone)
            .await?;
    }

    let mut password_authenticated = false;
    if let Some(password) = registration.password.clone() {
        let user_password = repo
            .user_password()
            .add(
                rng,
                clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(rng, clock, &user_session, &user_password)
            .await?;

        password_authenticated = true;
    }

    if let Some((upstream_session, upstream_link)) = request.upstream_oauth {
        let upstream_session = repo
            .upstream_oauth_session()
            .consume(clock, upstream_session, &user_session)
            .await?;

        repo.upstream_oauth_link()
            .associate_to_user(&upstream_link, &user)
            .await?;

        repo.browser_session()
            .authenticate_with_upstream(rng, clock, &user_session, &upstream_session)
            .await?;
    }

    if let Some(terms_url) = registration.terms_url.clone() {
        repo.user_terms()
            .accept_terms(rng, clock, &user, terms_url)
            .await?;
    }

    let mut job = ProvisionUserJob::new(&user);
    if let Some(display_name) = registration.display_name.clone() {
        job = job.set_display_name(display_name);
    }
    repo.queue_job().schedule_job(rng, clock, job).await?;

    repo.save().await?;

    Ok(CompletedRegistration {
        registration,
        user,
        user_session,
        password_authenticated,
    })
}
