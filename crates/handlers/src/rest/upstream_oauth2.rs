//! REST API endpoints for upstream OAuth 2.0 link flow.
//!
//! These endpoints replace the server-rendered HTML handlers in
//! `upstream_oauth2::link`, providing JSON responses for the Dioxus SPA.

use std::net::IpAddr;
use std::sync::LazyLock;

use minijinja::Environment;
use opentelemetry::{Key, KeyValue, metrics::Counter};
use pasion_data_model::{
    UpstreamOAuthAuthorizationSession, UserRegistration,
};
use pasion_jose::jwt::Jwt;
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::SessionInfoExt;
use pasion_salvo_utils::cookies::CookieJar;
use pasion_storage::{
    RepositoryAccess,
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    user::{BrowserSessionRepository, UserEmailRepository, UserRepository},
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{
    RouteError, extract_bound_activity_tracker, extract_cookie_jar, get_homeserver,
    get_policy_factory, get_repo_factory, get_site_config, get_url_builder, make_clock, make_rng,
};
use crate::{
    METER,
    post_auth::OptionalPostAuthAction,
    upstream_oauth2::{
        UpstreamSessionsCookie,
        template::{AttributeMappingContext, environment},
    },
    user_registration_cookie::UserRegistrationSessions,
};

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.rest.upstream_oauth2.login")
        .with_description("Successful upstream OAuth 2.0 login via REST API")
        .with_unit("{login}")
        .build()
});
static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.rest.upstream_oauth2.registration")
        .with_description("Successful upstream OAuth 2.0 registration via REST API")
        .with_unit("{registration}")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");

const DEFAULT_LOCALPART_TEMPLATE: &str = "{{ user.preferred_username }}";
const DEFAULT_DISPLAYNAME_TEMPLATE: &str = "{{ user.name }}";
const DEFAULT_EMAIL_TEMPLATE: &str = "{{ user.email }}";

// ── Response types ──────────────────────────────────────────────

/// The possible states of an upstream OAuth2 link.
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LinkState {
    /// Redirect: session already linked and matches current user, or auto-login succeeded.
    Redirect {
        redirect_url: String,
    },
    /// User is logged in, upstream not linked: suggest linking.
    SuggestLink {
        provider_name: Option<String>,
        upstream_subject: Option<String>,
    },
    /// User is logged in, but upstream is linked to a different user.
    LinkMismatch {
        existing_username: String,
    },
    /// No session, no link: show registration form.
    Register {
        suggested_username: Option<String>,
        username_forced: bool,
        suggested_display_name: Option<String>,
        display_name_forced: bool,
        suggested_email: Option<String>,
        email_forced: bool,
        provider_name: Option<String>,
        has_tos: bool,
    },
    /// Account is deactivated.
    AccountDeactivated {
        username: String,
    },
    /// Account is locked.
    AccountLocked {
        username: String,
    },
    /// An error occurred.
    Error {
        code: String,
        description: String,
    },
}

#[derive(Serialize)]
pub struct LinkResponse {
    #[serde(flatten)]
    pub state: LinkState,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LinkAction {
    Link,
    Register {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        import_email: Option<bool>,
        #[serde(default)]
        import_display_name: Option<bool>,
        #[serde(default)]
        accept_terms: Option<bool>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkActionResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_errors: Option<serde_json::Value>,
}

// ── Helper: render attribute template ───────────────────────────

fn render_attribute_template(
    environment: &Environment,
    template: &str,
    context: &minijinja::Value,
    required: bool,
) -> Result<Option<String>, RouteError> {
    match environment.render_str(template, context) {
        Ok(value) if value.is_empty() => {
            if required {
                return Err(RouteError::Internal(
                    format!("Template {template:?} rendered to an empty string").into(),
                ));
            }
            Ok(None)
        }
        Ok(value) => Ok(Some(value)),
        Err(source) => {
            if required {
                return Err(RouteError::Internal(Box::new(source)));
            }
            tracing::warn!(error = &source as &dyn std::error::Error, %template, "Error while rendering template");
            Ok(None)
        }
    }
}

// ── GET /api/v1/upstream-oauth2/link/{id} ───────────────────────

/// Return the current state of an upstream OAuth2 link as JSON.
#[handler]
pub async fn get_link(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing link id".into()))?;
    let mut rng = make_rng();
    let clock = make_clock();
    let mut repo = get_repo_factory(depot)?.create().await?;
    let homeserver = get_homeserver(depot)?;
    let cookie_jar = extract_cookie_jar(req, depot)?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let url_builder = get_url_builder(depot)?;
    let policy_factory = get_policy_factory(depot)?;
    let mut policy = policy_factory.instantiate().await.map_err(|e| RouteError::Internal(e.into()))?;
    let site_config = get_site_config(depot)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::BadRequest("missing upstream session cookie".into()))?;
    // Clone to release borrow on sessions_cookie
    let post_auth_action = post_auth_action.cloned();

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::NotFound);
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::BadRequest("session already consumed".into()));
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_active_session(&mut repo).await?;

    let state = match (maybe_user_session, link.user_id) {
        (Some(session), Some(user_id)) if session.user.id == user_id => {
            // Already linked & matches current user — auto-consume
            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            let cookie_jar = cookie_jar.set_session(&session);
            repo.save().await?;

            let action = OptionalPostAuthAction {
                post_auth_action: post_auth_action.clone(),
            };
            let redirect = action.go_next(&url_builder);
            // Get the redirect URL from the Redirect response
            let redirect_url = "/".to_owned(); // fallback

            cookie_jar.write_to_response(res);
            res.render(Json(LinkResponse {
                state: LinkState::Redirect {
                    redirect_url,
                },
            }));
            return Ok(());
        }

        (Some(_session), Some(user_id)) => {
            // Link exists but belongs to different user
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;

            LinkState::LinkMismatch {
                existing_username: user.username.clone(),
            }
        }

        (Some(_session), None) => {
            // User logged in, link not connected
            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;

            LinkState::SuggestLink {
                provider_name: provider.human_name.clone(),
                upstream_subject: Some(link.subject.clone()),
            }
        }

        (None, Some(user_id)) => {
            // Link exists, user not logged in — auto-login
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;

            if user.deactivated_at.is_some() {
                LinkState::AccountDeactivated {
                    username: user.username.clone(),
                }
            } else if user.locked_at.is_some() {
                LinkState::AccountLocked {
                    username: user.username.clone(),
                }
            } else {
                // Auto-login
                let session = repo
                    .browser_session()
                    .add(&mut rng, &clock, &user, user_agent.clone())
                    .await?;

                let upstream_session = repo
                    .upstream_oauth_session()
                    .consume(&clock, upstream_session, &session)
                    .await?;

                repo.browser_session()
                    .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                    .await?;

                let cookie_jar = sessions_cookie
                    .consume_link(link_id)
                    .map_err(|e| RouteError::Internal(e.into()))?
                    .save(cookie_jar, &clock)
                    .set_session(&session);

                repo.save().await?;

                LOGIN_COUNTER.add(
                    1,
                    &[KeyValue::new(
                        PROVIDER,
                        upstream_session.provider_id.to_string(),
                    )],
                );

                let action = OptionalPostAuthAction {
                    post_auth_action: post_auth_action.clone(),
                };

                cookie_jar.write_to_response(res);
                res.render(Json(LinkResponse {
                    state: LinkState::Redirect {
                        redirect_url: "/".to_owned(),
                    },
                }));
                return Ok(());
            }
        }

        (None, None) => {
            // Not linked, not logged in — show registration
            let id_token = upstream_session.id_token().map(Jwt::try_from).transpose()
                .map_err(|e| RouteError::Internal(e.into()))?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;

            let env = environment();

            let mut context = AttributeMappingContext::new();
            if let Some(id_token) = id_token {
                let (_, payload) = id_token.into_parts();
                context = context.with_id_token_claims(payload);
            }
            if let Some(extra_callback_parameters) = upstream_session.extra_callback_parameters() {
                context = context.with_extra_callback_parameters(extra_callback_parameters.clone());
            }
            if let Some(userinfo) = upstream_session.userinfo() {
                context = context.with_userinfo_claims(userinfo.clone());
            }
            let context = context.build();

            let suggested_display_name = if provider.claims_imports.displayname.ignore() {
                None
            } else {
                let template = provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_DISPLAYNAME_TEMPLATE);
                render_attribute_template(&env, template, &context, provider.claims_imports.displayname.is_required())?
            };

            let suggested_email = if provider.claims_imports.email.ignore() {
                None
            } else {
                let template = provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_EMAIL_TEMPLATE);
                render_attribute_template(&env, template, &context, provider.claims_imports.email.is_required())?
            };

            let suggested_username = if provider.claims_imports.localpart.ignore() {
                None
            } else {
                let template = provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_LOCALPART_TEMPLATE);
                render_attribute_template(&env, template, &context, provider.claims_imports.localpart.is_required())?
            };

            // If skip_confirmation is configured, auto-register
            if provider.claims_imports.skip_confirmation {
                let Some(ref localpart) = suggested_username else {
                    return Err(RouteError::Internal(
                        "No localpart available even though the provider is configured to skip confirmation".into()
                    ));
                };

                REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider.id.to_string())]);

                let registration = prepare_user_registration(
                    &mut rng,
                    &clock,
                    &mut repo,
                    upstream_session,
                    localpart.clone(),
                    suggested_display_name.clone(),
                    suggested_email.clone(),
                    activity_tracker.ip(),
                    user_agent,
                    post_auth_action.map(|action| serde_json::json!(action)),
                )
                .await?;

                let registrations = UserRegistrationSessions::load(&cookie_jar);
                let cookie_jar = sessions_cookie
                    .consume_link(link_id)
                    .map_err(|e| RouteError::Internal(e.into()))?
                    .save(cookie_jar, &clock);
                let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

                repo.save().await?;

                let redirect_url = format!("/register/{}/finish", registration.id);
                cookie_jar.write_to_response(res);
                res.render(Json(LinkResponse {
                    state: LinkState::Redirect { redirect_url },
                }));
                return Ok(());
            }

            LinkState::Register {
                suggested_username,
                username_forced: provider.claims_imports.localpart.is_forced_or_required(),
                suggested_display_name,
                display_name_forced: provider.claims_imports.displayname.is_forced_or_required(),
                suggested_email,
                email_forced: provider.claims_imports.email.is_forced_or_required(),
                provider_name: provider.human_name.clone(),
                has_tos: site_config.tos_uri.is_some(),
            }
        }
    };

    cookie_jar.write_to_response(res);
    res.render(Json(LinkResponse { state }));
    Ok(())
}

// ── POST /api/v1/upstream-oauth2/link/{id} ──────────────────────

/// Process a user's choice for an upstream OAuth2 link.
#[handler]
pub async fn post_link(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing link id".into()))?;
    let mut rng = make_rng();
    let clock = make_clock();
    let mut repo = get_repo_factory(depot)?.create().await?;
    let cookie_jar = extract_cookie_jar(req, depot)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let policy_factory = get_policy_factory(depot)?;
    let mut policy = policy_factory.instantiate().await.map_err(|e| RouteError::Internal(e.into()))?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let homeserver = get_homeserver(depot)?;
    let url_builder = get_url_builder(depot)?;
    let site_config = get_site_config(depot)?;

    let input: LinkAction = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| RouteError::BadRequest("missing upstream session cookie".into()))?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if upstream_session.link_id() != Some(link.id) {
        return Err(RouteError::NotFound);
    }

    if upstream_session.is_consumed() {
        return Err(RouteError::BadRequest("session already consumed".into()));
    }

    let (user_session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_user_session = user_session_info.load_active_session(&mut repo).await?;

    match (maybe_user_session, link.user_id, input) {
        (Some(session), None, LinkAction::Link) => {
            // Link the upstream identity to the current user
            repo.upstream_oauth_link()
                .associate_to_user(&link, &session.user)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(&clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_session)
                .await?;

            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, &clock)
                .set_session(&session);

            repo.save().await?;

            cookie_jar.write_to_response(res);
            res.render(Json(LinkActionResponse {
                status: "success",
                redirect_url: Some("/".to_owned()),
                error: None,
                field_errors: None,
            }));
            Ok(())
        }

        (
            None,
            None,
            LinkAction::Register {
                username,
                import_email,
                import_display_name,
                accept_terms,
            },
        ) => {
            let import_email = import_email.unwrap_or(false);
            let import_display_name = import_display_name.unwrap_or(false);
            let accept_terms = accept_terms.unwrap_or(false);

            let id_token = upstream_session
                .id_token()
                .map(Jwt::try_from)
                .transpose()
                .map_err(|e| RouteError::Internal(e.into()))?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;

            let env = environment();
            let mut context = AttributeMappingContext::new();
            if let Some(id_token) = id_token {
                let (_, payload) = id_token.into_parts();
                context = context.with_id_token_claims(payload);
            }
            if let Some(extra_callback_parameters) = upstream_session.extra_callback_parameters() {
                context = context.with_extra_callback_parameters(extra_callback_parameters.clone());
            }
            if let Some(userinfo) = upstream_session.userinfo() {
                context = context.with_userinfo_claims(userinfo.clone());
            }
            let context = context.build();

            let display_name = if provider
                .claims_imports
                .displayname
                .should_import(import_display_name)
            {
                let template = provider
                    .claims_imports
                    .displayname
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_DISPLAYNAME_TEMPLATE);
                render_attribute_template(&env, template, &context, provider.claims_imports.displayname.is_required())?
            } else {
                None
            };

            let email = if provider.claims_imports.email.should_import(import_email) {
                let template = provider
                    .claims_imports
                    .email
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_EMAIL_TEMPLATE);
                render_attribute_template(&env, template, &context, provider.claims_imports.email.is_required())?
            } else {
                None
            };

            let username = if provider.claims_imports.localpart.is_forced_or_required() {
                let template = provider
                    .claims_imports
                    .localpart
                    .template
                    .as_deref()
                    .unwrap_or(DEFAULT_LOCALPART_TEMPLATE);
                render_attribute_template(&env, template, &context, true)?
            } else {
                username
            }
            .unwrap_or_default();

            // Validate
            let mut field_errors = serde_json::Map::new();

            if username.is_empty() {
                field_errors.insert("username".into(), serde_json::json!("required"));
            } else if repo.user().exists(&username).await? {
                field_errors.insert("username".into(), serde_json::json!("exists"));
            } else if !homeserver
                .is_localpart_available(&username)
                .await
                .map_err(|e| RouteError::Internal(e.into()))?
            {
                field_errors.insert("username".into(), serde_json::json!("exists"));
            }

            if site_config.tos_uri.is_some() && !accept_terms {
                field_errors.insert("accept_terms".into(), serde_json::json!("required"));
            }

            // Policy check
            let eval_result = policy
                .evaluate_register(pasion_policy::RegisterInput {
                    registration_method: pasion_policy::RegistrationMethod::UpstreamOAuth2,
                    username: &username,
                    email: email.as_deref(),
                    requester: pasion_policy::Requester {
                        ip_address: activity_tracker.ip(),
                        user_agent: user_agent.clone(),
                    },
                })
                .await
                .map_err(|e| RouteError::Internal(e.into()))?;

            for violation in &eval_result.violations {
                match violation.field.as_deref() {
                    Some("username") => {
                        field_errors.insert(
                            "username".into(),
                            serde_json::json!(if violation.msg.is_empty() { "policy_violation" } else { &violation.msg }),
                        );
                    }
                    _ => {
                        field_errors.insert(
                            "_form".into(),
                            serde_json::json!(if violation.msg.is_empty() { "policy_violation" } else { &violation.msg }),
                        );
                    }
                }
            }

            if !field_errors.is_empty() {
                cookie_jar.write_to_response(res);
                res.render(Json(LinkActionResponse {
                    status: "error",
                    redirect_url: None,
                    error: Some("validation_failed".to_owned()),
                    field_errors: Some(serde_json::Value::Object(field_errors)),
                }));
                return Ok(());
            }

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider.id.to_string())]);

            let mut registration = prepare_user_registration(
                &mut rng,
                &clock,
                &mut repo,
                upstream_session,
                username,
                display_name,
                email,
                activity_tracker.ip(),
                user_agent,
                post_auth_action.map(|action| serde_json::json!(action)),
            )
            .await?;

            if let Some(terms_url) = &site_config.tos_uri {
                registration = repo
                    .user_registration()
                    .set_terms_url(registration, terms_url.clone())
                    .await?;
            }

            let registrations = UserRegistrationSessions::load(&cookie_jar);
            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, &clock);
            let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

            repo.save().await?;

            let redirect_url = format!("/register/{}/finish", registration.id);
            cookie_jar.write_to_response(res);
            res.render(Json(LinkActionResponse {
                status: "success",
                redirect_url: Some(redirect_url),
                error: None,
                field_errors: None,
            }));
            Ok(())
        }

        _ => {
            res.render(Json(LinkActionResponse {
                status: "error",
                redirect_url: None,
                error: Some("invalid_action".to_owned()),
                field_errors: None,
            }));
            Ok(())
        }
    }
}

/// Create a user registration using attributes from the upstream authorization session.
async fn prepare_user_registration(
    rng: &mut pasion_data_model::BoxRng,
    clock: &pasion_data_model::BoxClock,
    repo: &mut pasion_storage::BoxRepository,
    upstream_session: UpstreamOAuthAuthorizationSession,
    localpart: String,
    displayname: Option<String>,
    email: Option<String>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
) -> Result<UserRegistration, RouteError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            localpart,
            ip_address,
            user_agent,
            post_auth_action,
        )
        .await?;

    if let Some(email) = email {
        let authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;
        let authentication = repo
            .user_email()
            .complete_authentication_with_upstream(clock, authentication, &upstream_session)
            .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await?;
    }

    if let Some(name) = displayname {
        registration = repo
            .user_registration()
            .set_display_name(registration, name)
            .await?;
    }

    let registration = repo
        .user_registration()
        .set_upstream_oauth_authorization_session(registration, &upstream_session)
        .await?;

    Ok(registration)
}
