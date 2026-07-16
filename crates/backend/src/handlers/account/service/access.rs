use anyhow::Error as AnyhowError;
use pasion_data::{
    BoxRepository, BrowserSession, Clock, Password, RepositoryAccess, RepositoryError, SiteConfig,
    UpstreamOAuthProvider, User,
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
};
use pasion_matrix::HomeserverAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::{
    Limiter, RequesterFingerprint,
    passwords::{PasswordManager, PasswordVerificationResult},
};

#[derive(Debug)]
pub struct PasswordLoginRequest {
    pub username_or_email: String,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub requester: RequesterFingerprint,
    pub skip_requester_limit: bool,
}

#[derive(Debug)]
pub enum PasswordLoginOutcome {
    Disabled,
    InvalidCredentials,
    RateLimited,
    AccountDeactivated,
    AccountLocked,
    Authenticated {
        user: User,
        user_session: BrowserSession,
    },
}

#[derive(Debug)]
pub enum PasswordVerificationOutcome {
    Disabled,
    InvalidCredentials,
    RateLimited,
    AccountDeactivated,
    AccountLocked,
    Authenticated { user: User, user_password: Password },
}

#[derive(Debug, Error)]
pub enum PasswordLoginError {
    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn load_enabled_upstream_providers<R: RepositoryAccess>(
    repo: &mut R,
) -> Result<Vec<UpstreamOAuthProvider>, R::Error> {
    repo.upstream_oauth_provider().all_enabled().await
}

pub async fn login_with_password(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    homeserver: &dyn HomeserverAdmin,
    site_config: &SiteConfig,
    request: PasswordLoginRequest,
) -> Result<PasswordLoginOutcome, PasswordLoginError> {
    let user_agent = request.user_agent.clone();
    match verify_password_login(
        &mut repo,
        rng,
        clock,
        password_manager,
        limiter,
        homeserver,
        site_config,
        request,
    )
    .await?
    {
        PasswordVerificationOutcome::Disabled => Ok(PasswordLoginOutcome::Disabled),
        PasswordVerificationOutcome::InvalidCredentials => {
            Ok(PasswordLoginOutcome::InvalidCredentials)
        }
        PasswordVerificationOutcome::RateLimited => Ok(PasswordLoginOutcome::RateLimited),
        PasswordVerificationOutcome::AccountDeactivated => {
            Ok(PasswordLoginOutcome::AccountDeactivated)
        }
        PasswordVerificationOutcome::AccountLocked => Ok(PasswordLoginOutcome::AccountLocked),
        PasswordVerificationOutcome::Authenticated {
            user,
            user_password,
        } => {
            let user_session = repo
                .browser_session()
                .add(&mut *rng, clock, &user, user_agent)
                .await?;

            repo.browser_session()
                .authenticate_with_password(&mut *rng, clock, &user_session, &user_password)
                .await?;

            repo.save().await?;

            Ok(PasswordLoginOutcome::Authenticated { user, user_session })
        }
    }
}

pub async fn verify_password_login(
    repo: &mut BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    homeserver: &dyn HomeserverAdmin,
    site_config: &SiteConfig,
    request: PasswordLoginRequest,
) -> Result<PasswordVerificationOutcome, PasswordLoginError> {
    if !site_config.password_login_enabled {
        return Ok(PasswordVerificationOutcome::Disabled);
    }

    let username = homeserver
        .localpart(&request.username_or_email)
        .unwrap_or(&request.username_or_email);

    let Some(user) = find_user_by_email_or_by_username(site_config, repo, username).await? else {
        return Ok(PasswordVerificationOutcome::InvalidCredentials);
    };

    if request.skip_requester_limit {
        if limiter.check_password_for_user(&user).await.is_err() {
            return Ok(PasswordVerificationOutcome::RateLimited);
        }
    } else if limiter
        .check_password(request.requester, &user)
        .await
        .is_err()
    {
        return Ok(PasswordVerificationOutcome::RateLimited);
    }

    let Some(user_password) = repo.user_password().active(&user).await? else {
        return Ok(PasswordVerificationOutcome::InvalidCredentials);
    };

    let user_password = match password_manager
        .verify_and_upgrade(
            &mut *rng,
            user_password.version,
            request.password,
            user_password.hashed_password.clone(),
        )
        .await
    {
        Ok(PasswordVerificationResult::Matched(Some((version, new_password_hash)))) => {
            repo.user_password()
                .add(
                    &mut *rng,
                    clock,
                    &user,
                    version,
                    new_password_hash,
                    Some(&user_password),
                )
                .await?
        }
        Ok(PasswordVerificationResult::Matched(None)) => user_password,
        Ok(PasswordVerificationResult::NotMatched) => {
            return Ok(PasswordVerificationOutcome::InvalidCredentials);
        }
        Err(error) => return Err(PasswordLoginError::Password(error)),
    };

    if user.deactivated_at.is_some() {
        return Ok(PasswordVerificationOutcome::AccountDeactivated);
    }

    if user.locked_at.is_some() {
        return Ok(PasswordVerificationOutcome::AccountLocked);
    }

    debug_assert!(user.is_valid());

    Ok(PasswordVerificationOutcome::Authenticated {
        user,
        user_password,
    })
}

pub async fn logout_browser_session(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    session_id: Option<Ulid>,
) -> Result<Option<BrowserSession>, RepositoryError> {
    let maybe_session = if let Some(session_id) = session_id {
        let maybe_session = repo.browser_session().lookup(session_id).await?;

        if let Some(session) = maybe_session {
            if session.finished_at.is_none() {
                repo.browser_session()
                    .finish(clock, session.clone())
                    .await?;
                Some(session)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    repo.save().await?;

    Ok(maybe_session)
}

async fn find_user_by_email_or_by_username(
    site_config: &SiteConfig,
    repo: &mut BoxRepository,
    username_or_email: &str,
) -> Result<Option<User>, RepositoryError> {
    if site_config.login_with_email_allowed && username_or_email.contains('@') {
        let maybe_user_email = repo.user_email().find_by_email(username_or_email).await?;

        if let Some(user_email) = maybe_user_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            if user.is_some() {
                return Ok(user);
            }
        }
    }

    repo.user().find_by_username(username_or_email).await
}
