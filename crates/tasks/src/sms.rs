use async_trait::async_trait;
use chrono::Duration;
use pasion_messaging::NotificationRequest;
use pasion_storage::queue::SendSmsAuthenticationCodeJob;
use rand::{Rng, distributions::Uniform};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for SendSmsAuthenticationCodeJob {
    #[tracing::instrument(
        name = "job.send_sms_authentication_code",
        fields(user_phone_authentication.id = %self.user_phone_authentication_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let notifications = state.notifications();
        let mut rng = state.rng();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user_phone_authentication = repo
            .user_phone()
            .lookup_authentication(self.user_phone_authentication_id())
            .await
            .map_err(JobError::retry)?
            .ok_or(JobError::fail(anyhow::anyhow!(
                "User phone authentication not found"
            )))?;

        if user_phone_authentication.completed_at.is_some() {
            return Err(JobError::fail(anyhow::anyhow!(
                "User phone authentication already completed"
            )));
        }

        // Generate a new 6-digit authentication code.
        let range = Uniform::<u32>::from(0..1_000_000);
        let code = rng.sample(range);
        let code = format!("{code:06}");
        let code = repo
            .user_phone()
            .add_authentication_code(
                &mut rng,
                clock,
                Duration::minutes(5), // TODO: make this configurable
                &user_phone_authentication,
                code,
            )
            .await
            .map_err(JobError::retry)?;

        info!(
            phone = user_phone_authentication.phone,
            "Sending SMS verification code"
        );

        let verification_code = code.code.clone();
        let request = NotificationRequest::SmsVerificationCode {
            to: user_phone_authentication.phone.clone(),
            code: verification_code.clone(),
            language: self.language().to_owned(),
        };
        if let Err(e) = notifications.dispatch(request).await {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "Failed to send SMS verification code. code = {}",
                verification_code,
            );
        }

        repo.save().await.map_err(JobError::fail)?;

        Ok(())
    }
}
