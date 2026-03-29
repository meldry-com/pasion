use pasion_data_model::{
    Clock, UserEmailAuthentication, UserPhoneAuthentication, UserRecoverySession,
};
use pasion_storage::{
    BoxRepository, RepositoryError,
    queue::{ContactVerificationTarget, DispatchNotificationJob, QueueJobRepositoryExt as _},
};
use rand::RngCore;

/// User-facing notification intent expressed by the business layer.
pub enum NotificationIntent<'a> {
    /// Verify a contact point without binding the caller to a concrete channel.
    ContactVerification {
        /// The verification target.
        target: ContactVerificationIntentTarget<'a>,
        /// The language to use for the notification.
        language: String,
    },
    /// Send account recovery notifications for a recovery session.
    AccountRecovery {
        /// The recovery session for which to notify.
        session: &'a UserRecoverySession,
    },
}

/// Supported contact verification targets.
pub enum ContactVerificationIntentTarget<'a> {
    /// Email verification.
    Email(&'a UserEmailAuthentication),
    /// Phone verification.
    Phone(&'a UserPhoneAuthentication),
}

impl<'a> NotificationIntent<'a> {
    /// Create a contact verification intent for email.
    #[must_use]
    pub fn verify_email(authentication: &'a UserEmailAuthentication, language: String) -> Self {
        Self::ContactVerification {
            target: ContactVerificationIntentTarget::Email(authentication),
            language,
        }
    }

    /// Create a contact verification intent for phone.
    #[must_use]
    pub fn verify_phone(authentication: &'a UserPhoneAuthentication, language: String) -> Self {
        Self::ContactVerification {
            target: ContactVerificationIntentTarget::Phone(authentication),
            language,
        }
    }

    /// Create an account recovery notification intent.
    #[must_use]
    pub fn account_recovery(session: &'a UserRecoverySession) -> Self {
        Self::AccountRecovery { session }
    }
}

/// Schedule a notification intent for background processing.
pub async fn schedule_notification(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    intent: NotificationIntent<'_>,
) -> Result<(), RepositoryError> {
    let job = match intent {
        NotificationIntent::ContactVerification { target, language } => {
            let target = match target {
                ContactVerificationIntentTarget::Email(authentication) => {
                    ContactVerificationTarget::Email {
                        user_email_authentication_id: authentication.id,
                    }
                }
                ContactVerificationIntentTarget::Phone(authentication) => {
                    ContactVerificationTarget::Phone {
                        user_phone_authentication_id: authentication.id,
                    }
                }
            };

            DispatchNotificationJob::contact_verification(target, language)
        }
        NotificationIntent::AccountRecovery { session } => {
            DispatchNotificationJob::account_recovery(session)
        }
    };

    repo.queue_job().schedule_job(rng, clock, job).await
}

/// Schedule an email verification notification.
pub async fn schedule_email_authentication_code(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    authentication: &UserEmailAuthentication,
    language: String,
) -> Result<(), RepositoryError> {
    schedule_notification(
        repo,
        rng,
        clock,
        NotificationIntent::verify_email(authentication, language),
    )
    .await
}

/// Schedule an SMS verification notification.
pub async fn schedule_sms_authentication_code(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    authentication: &UserPhoneAuthentication,
    language: String,
) -> Result<(), RepositoryError> {
    schedule_notification(
        repo,
        rng,
        clock,
        NotificationIntent::verify_phone(authentication, language),
    )
    .await
}

/// Schedule an account recovery notification batch.
pub async fn schedule_account_recovery(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    session: &UserRecoverySession,
) -> Result<(), RepositoryError> {
    schedule_notification(
        repo,
        rng,
        clock,
        NotificationIntent::account_recovery(session),
    )
    .await
}
