use pasion_data_model::{
    Clock, UserEmailAuthentication, UserPhoneAuthentication, UserRecoverySession,
};
use pasion_storage::{
    BoxRepository, RepositoryError,
    queue::{DispatchNotificationJob, QueueJobRepositoryExt as _},
};
use rand::RngCore;

/// Schedule an email verification notification.
pub async fn schedule_email_authentication_code(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    authentication: &UserEmailAuthentication,
    language: String,
) -> Result<(), RepositoryError> {
    repo.queue_job()
        .schedule_job(
            rng,
            clock,
            DispatchNotificationJob::email_authentication_code(authentication, language),
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
    repo.queue_job()
        .schedule_job(
            rng,
            clock,
            DispatchNotificationJob::sms_authentication_code(authentication, language),
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
    repo.queue_job()
        .schedule_job(
            rng,
            clock,
            DispatchNotificationJob::account_recovery(session),
        )
        .await
}
