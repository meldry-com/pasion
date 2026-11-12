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

#[cfg(test)]
mod enumeration_tests {
    use super::*;
    use crate::handlers::{passwords::Hasher, test_utils::test_site_config};
    use pasion_data::{PgRepositoryFactory, RepositoryFactory as _, clock::MockClock};
    use pasion_matrix::MockHomeserverAdmin;
    use rand_core::SeedableRng as _;

    #[tokio::test]
    async fn missing_accounts_spend_the_same_requester_budget_as_existing_accounts() {
        if std::env::var_os("DATABASE_URL").is_none() {
            return;
        }
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(51);
        let manager = PasswordManager::new(0, [(1, Hasher::bcrypt(Some(4), None, false))]).unwrap();
        let mut repo = factory.create().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &clock, "existing".to_owned())
            .await
            .unwrap();
        let (version, hash) = manager
            .hash(&mut rng, Zeroizing::new("correct".to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        let homeserver = MockHomeserverAdmin::new("example.com");
        let config = test_site_config();
        for first in ["missing", "existing"] {
            let limiter = Limiter::new(&pasion_config::RateLimitingConfig::default()).unwrap();
            for attempt in 0..4 {
                let mut repo = factory.create().await.unwrap();
                let outcome = verify_password_login(
                    &mut repo,
                    &mut rng,
                    &clock,
                    &manager,
                    &limiter,
                    &homeserver,
                    &config,
                    PasswordLoginRequest {
                        username_or_email: if attempt < 3 {
                            first.to_owned()
                        } else {
                            "existing".to_owned()
                        },
                        password: Zeroizing::new("wrong".to_owned()),
                        user_agent: None,
                        requester: RequesterFingerprint::new([127, 0, 0, 1].into()),
                        skip_requester_limit: false,
                    },
                )
                .await
                .unwrap();
                if attempt < 3 {
                    assert!(matches!(
                        outcome,
                        PasswordVerificationOutcome::InvalidCredentials
                    ));
                } else {
                    assert!(matches!(outcome, PasswordVerificationOutcome::RateLimited));
                }
                repo.cancel().await.unwrap();
            }
        }
    }
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

    // Charge every attempt, including nonexistent accounts, before any lookup.
    if !request.skip_requester_limit
        && limiter
            .check_password_for_requester(request.requester)
            .await
            .is_err()
    {
        return Ok(PasswordVerificationOutcome::RateLimited);
    }

    let username = homeserver
        .localpart(&request.username_or_email)
        .unwrap_or(&request.username_or_email);

    let Some(user) = find_user_by_email_or_by_username(site_config, repo, username).await? else {
        if !password_manager
            .dummy_verify(request.password)
            .await
            .map_err(PasswordLoginError::Password)?
        {
            return Ok(PasswordVerificationOutcome::RateLimited);
        }
        return Ok(PasswordVerificationOutcome::InvalidCredentials);
    };

    if limiter.check_password_for_user(&user).await.is_err() {
        return Ok(PasswordVerificationOutcome::RateLimited);
    }

    let Some(user_password) = repo.user_password().active(&user).await? else {
        if !password_manager
            .dummy_verify(request.password)
            .await
            .map_err(PasswordLoginError::Password)?
        {
            return Ok(PasswordVerificationOutcome::RateLimited);
        }
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
