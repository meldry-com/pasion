use anyhow::Context;
use async_trait::async_trait;
use chrono::Duration;
use pasion_i18n::DataLocale;
use pasion_messaging::{Address, Mailbox, NotificationRequest};
use pasion_storage::{
    Pagination, RepositoryAccess,
    queue::DispatchNotificationJob,
    user::{UserEmailFilter, UserRecoveryRepository},
};
use pasion_templates::{EmailRecoveryContext, EmailVerificationContext, TemplateContext as _};
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString, Uniform},
};
use tracing::{error, info};
use ulid::Ulid;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

pub(crate) async fn send_email_authentication_code(
    state: &State,
    user_email_authentication_id: Ulid,
    language: &str,
) -> Result<(), JobError> {
    let clock = state.clock();
    let notifications = state.notifications();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let user_email_authentication = repo
        .user_email()
        .lookup_authentication(user_email_authentication_id)
        .await
        .map_err(JobError::retry)?
        .ok_or(JobError::fail(anyhow::anyhow!(
            "User email authentication not found"
        )))?;

    if user_email_authentication.completed_at.is_some() {
        return Err(JobError::fail(anyhow::anyhow!(
            "User email authentication already completed"
        )));
    }

    let browser_session = if let Some(browser_session) = user_email_authentication.user_session_id {
        Some(
            repo.browser_session()
                .lookup(browser_session)
                .await
                .map_err(JobError::retry)?
                .ok_or(JobError::fail(anyhow::anyhow!(
                    "Failed to load browser session"
                )))?,
        )
    } else {
        None
    };

    let registration = if let Some(registration_id) = user_email_authentication.user_registration_id
    {
        Some(
            repo.user_registration()
                .lookup(registration_id)
                .await
                .map_err(JobError::retry)?
                .ok_or(JobError::fail(anyhow::anyhow!(
                    "Failed to load user registration"
                )))?,
        )
    } else {
        None
    };

    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");
    let code = repo
        .user_email()
        .add_authentication_code(
            &mut rng,
            clock,
            Duration::minutes(5),
            &user_email_authentication,
            code,
        )
        .await
        .map_err(JobError::retry)?;

    let address: Address = user_email_authentication
        .email
        .parse()
        .map_err(JobError::fail)?;
    let username_from_session = browser_session.as_ref().map(|s| s.user.username.clone());
    let username_from_registration = registration.as_ref().map(|r| r.username.clone());
    let username = username_from_registration.or(username_from_session);
    let mailbox = Mailbox::new(username, address);

    info!("Sending email verification code to {}", mailbox);

    let language = language.parse().map_err(JobError::fail)?;

    let context =
        EmailVerificationContext::new(code, browser_session, registration).with_language(language);
    let verification_code = context.code().to_owned();
    let request = NotificationRequest::EmailVerification {
        to: mailbox,
        context,
    };
    if let Err(e) = notifications.dispatch(request).await {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "Failed to send email verification code. code = {}",
            verification_code,
        );
    }

    repo.save().await.map_err(JobError::fail)?;

    Ok(())
}

pub(crate) async fn send_sms_authentication_code(
    state: &State,
    user_phone_authentication_id: Ulid,
    language: &str,
) -> Result<(), JobError> {
    let clock = state.clock();
    let notifications = state.notifications();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let user_phone_authentication = repo
        .user_phone()
        .lookup_authentication(user_phone_authentication_id)
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

    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");
    let code = repo
        .user_phone()
        .add_authentication_code(
            &mut rng,
            clock,
            Duration::minutes(5),
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
        language: language.to_owned(),
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

pub(crate) async fn send_account_recovery(
    state: &State,
    user_recovery_session_id: Ulid,
) -> Result<(), JobError> {
    let clock = state.clock();
    let notifications = state.notifications();
    let url_builder = state.url_builder();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let session = repo
        .user_recovery()
        .lookup_session(user_recovery_session_id)
        .await
        .map_err(JobError::retry)?
        .context("User recovery session not found")
        .map_err(JobError::fail)?;

    tracing::Span::current().record("user_recovery_session.email", &session.email);

    if session.consumed_at.is_some() {
        info!("Recovery session already consumed, not sending email");
        return Ok(());
    }

    let mut cursor = Pagination::first(50);

    let lang: DataLocale = session
        .locale
        .parse()
        .context("Invalid locale in database on recovery session")
        .map_err(JobError::fail)?;

    loop {
        let page = repo
            .user_email()
            .list(UserEmailFilter::new().for_email(&session.email), cursor)
            .await
            .map_err(JobError::retry)?;

        for edge in page.edges {
            let ticket = Alphanumeric.sample_string(&mut rng, 32);

            let ticket = repo
                .user_recovery()
                .add_ticket(&mut rng, clock, &session, &edge.node, ticket)
                .await
                .map_err(JobError::retry)?;

            let user = repo
                .user()
                .lookup(edge.node.user_id)
                .await
                .map_err(JobError::retry)?
                .context("User not found")
                .map_err(JobError::fail)?;

            let url = url_builder.account_recovery_link(ticket.ticket);

            let address: Address = edge.node.email.parse().map_err(JobError::fail)?;
            let mailbox = Mailbox::new(Some(user.username.clone()), address);

            info!("Sending recovery email to {}", mailbox);
            let context =
                EmailRecoveryContext::new(user, session.clone(), url).with_language(lang.clone());
            let request = NotificationRequest::EmailRecovery {
                to: mailbox,
                context,
            };

            if let Err(e) = notifications.dispatch(request).await {
                error!(
                    error = &e as &dyn std::error::Error,
                    "Failed to send recovery email"
                );
            }

            cursor = cursor.after(edge.cursor);
        }

        if !page.has_next_page {
            break;
        }
    }

    repo.save().await.map_err(JobError::fail)?;

    Ok(())
}

#[async_trait]
impl RunnableJob for DispatchNotificationJob {
    #[tracing::instrument(name = "job.dispatch_notification", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        match self {
            Self::EmailAuthenticationCode {
                user_email_authentication_id,
                language,
            } => {
                send_email_authentication_code(state, *user_email_authentication_id, language).await
            }
            Self::SmsAuthenticationCode {
                user_phone_authentication_id,
                language,
            } => send_sms_authentication_code(state, *user_phone_authentication_id, language).await,
            Self::AccountRecovery {
                user_recovery_session_id,
            } => send_account_recovery(state, *user_recovery_session_id).await,
        }
    }
}
