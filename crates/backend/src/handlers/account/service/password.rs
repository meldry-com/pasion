//! Service functions for password management.
//!
//! These functions encapsulate the business logic for changing a user's
//! password while already authenticated. Recovery-session orchestration lives
//! in [`crate::handlers::account::service::recovery`].

use anyhow::Error as AnyhowError;
use pasion_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, User,
    user::{UserPasswordRepository, UserRepository},
};
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::handlers::{Limiter, RequesterFingerprint, passwords::PasswordManager};

// ── Change password ───────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ChangePasswordError {
    #[error("password attempt rate limited")]
    RateLimited,
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

#[derive(Debug, Error)]
pub enum VerifyPasswordIfNeededError {
    #[error("password attempt rate limited")]
    RateLimited,
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
    limiter: &Limiter,
    requester: RequesterFingerprint,
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

        limiter
            .check_password(requester, &user)
            .await
            .map_err(|_| ChangePasswordError::RateLimited)?;

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

pub async fn verify_password_if_needed(
    is_admin: bool,
    password_login_enabled: bool,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    password: Option<String>,
    user: &User,
    repo: &mut BoxRepository,
) -> Result<bool, VerifyPasswordIfNeededError> {
    if is_admin {
        return Ok(true);
    }

    if !password_login_enabled {
        return Ok(true);
    }

    let user_password = repo.user_password().active(user).await?;

    let Some(user_password) = user_password else {
        return Ok(true);
    };

    let Some(password) = password else {
        return Ok(false);
    };

    let password = Zeroizing::new(password);

    limiter
        .check_password(requester, user)
        .await
        .map_err(|_| VerifyPasswordIfNeededError::RateLimited)?;

    let res = password_manager
        .verify(
            user_password.version,
            password,
            user_password.hashed_password,
        )
        .await
        .map_err(VerifyPasswordIfNeededError::Password)?;

    Ok(res.is_success())
}

/// Create a new RNG from the provided one, suitable for `PasswordManager::hash`
/// which requires `CryptoRng + RngCore + Send`.
fn make_rng_from(rng: &mut (dyn CryptoRngCore + Send)) -> rand_chacha::ChaChaRng {
    use rand_chacha::rand_core::SeedableRng;
    rand_chacha::ChaChaRng::from_rng(rng).expect("seeding ChaChaRng should not fail")
}

#[cfg(test)]
mod tests {
    use pasion_data::{PgRepositoryFactory, RepositoryFactory as _, clock::MockClock};
    use rand_core::SeedableRng as _;

    use super::*;
    use crate::handlers::passwords::Hasher;

    #[tokio::test]
    async fn sensitive_password_checks_share_login_attempt_budgets() {
        if std::env::var_os("DATABASE_URL").is_none() {
            return;
        }
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(52);
        let manager = PasswordManager::new(0, [(1, Hasher::bcrypt(Some(4), None, false))]).unwrap();
        let mut repo = factory.create().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &clock, "bob".to_owned())
            .await
            .unwrap();
        let (version, hash) = manager
            .hash(&mut rng, Zeroizing::new("correct".to_owned()))
            .await
            .unwrap();
        for user in [&alice, &bob] {
            repo.user_password()
                .add(&mut rng, &clock, user, version, hash.clone(), None)
                .await
                .unwrap();
        }
        let session = repo
            .browser_session()
            .add(&mut rng, &clock, &alice, None)
            .await
            .unwrap();
        let email = repo
            .user_email()
            .add(&mut rng, &clock, &alice, "alice@example.com".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();
        let requester = RequesterFingerprint::new([127, 0, 0, 1].into());
        let fresh_requester = RequesterFingerprint::new([127, 0, 0, 2].into());
        let mut rate_config = pasion_config::RateLimitingConfig::default();
        rate_config.login.per_account.burst = std::num::NonZeroU32::new(5).unwrap();
        rate_config.login.per_account.per_second = 0.01;
        let limiter = Limiter::new(&rate_config).unwrap();
        for _ in 0..3 {
            let mut repo = factory.create().await.unwrap();
            assert!(
                !verify_password_if_needed(
                    false,
                    true,
                    &manager,
                    &limiter,
                    requester,
                    Some("wrong".to_owned()),
                    &alice,
                    &mut repo
                )
                .await
                .unwrap()
            );
            repo.cancel().await.unwrap();
        }
        // Sensitive attempts have consumed the same requester bucket as login.
        assert!(limiter.check_password(requester, &alice).await.is_err());
        let mut repo = factory.create().await.unwrap();
        assert!(matches!(
            verify_password_if_needed(
                false,
                true,
                &manager,
                &limiter,
                requester,
                Some("correct".to_owned()),
                &alice,
                &mut repo
            )
            .await,
            Err(VerifyPasswordIfNeededError::RateLimited)
        ));
        repo.cancel().await.unwrap();
        let repo = factory.create().await.unwrap();
        assert!(matches!(
            change_password(
                repo,
                &mut rng,
                &clock,
                &manager,
                &limiter,
                requester,
                alice.id,
                Some(Zeroizing::new("correct".to_owned())),
                Zeroizing::new("new password".to_owned()),
                false,
                true
            )
            .await,
            Err(ChangePasswordError::RateLimited)
        ));
        use crate::handlers::{
            account::service::{contacts, profile},
            common::{Requester, RequestingEntity},
        };
        let authenticated = Requester {
            entity: RequestingEntity::from(session.clone()),
            ip_address: Some([127, 0, 0, 1].into()),
            user_agent: None,
        };
        assert!(matches!(
            contacts::start_email_verification(
                factory.create().await.unwrap(),
                &mut rng,
                &clock,
                &limiter,
                &manager,
                true,
                true,
                false,
                requester,
                Some(&session),
                "new@example.com".to_owned(),
                Some("correct".to_owned()),
                "en".to_owned(),
            )
            .await,
            Err(contacts::StartEmailVerificationError::RateLimited)
        ));
        assert!(matches!(
            contacts::remove_user_email(
                factory.create().await.unwrap(),
                &mut rng,
                &clock,
                &manager,
                &limiter,
                requester,
                Some(alice.id),
                false,
                true,
                Some("correct".to_owned()),
                email.id,
            )
            .await,
            Err(contacts::RemoveUserEmailError::RateLimited)
        ));
        assert!(matches!(
            profile::deactivate_current_account(
                factory.create().await.unwrap(),
                &authenticated,
                &mut rng,
                &clock,
                &crate::handlers::test_utils::test_site_config(),
                &manager,
                &limiter,
                Some("correct".to_owned()),
                false,
            )
            .await,
            Err(profile::AccountProfileError::RateLimited)
        ));
        // Exhaust the account bucket from distinct requester addresses. A fresh
        // address cannot bypass it, while Bob remains usable from that address.
        for _ in 0..100 {
            if limiter.check_password_for_user(&alice).await.is_err() {
                break;
            }
        }
        let mut repo = factory.create().await.unwrap();
        assert!(matches!(
            verify_password_if_needed(
                false,
                true,
                &manager,
                &limiter,
                fresh_requester,
                Some("correct".to_owned()),
                &alice,
                &mut repo
            )
            .await,
            Err(VerifyPasswordIfNeededError::RateLimited)
        ));
        assert!(
            verify_password_if_needed(
                false,
                true,
                &manager,
                &limiter,
                fresh_requester,
                Some("correct".to_owned()),
                &bob,
                &mut repo
            )
            .await
            .unwrap()
        );
        repo.cancel().await.unwrap();
    }
}
