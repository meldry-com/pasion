//! Rendering context types for page and email templates.
//!
//! Every template consumes a dedicated context struct that carries the data it
//! needs.  Context wrappers -- for session, CSRF token, locale and CAPTCHA --
//! can be stacked via [`TemplateContext`] trait methods.

mod branding;
mod captcha;
mod ext;
mod features;

use std::{
    collections::BTreeMap,
    fmt::Formatter,
    net::{IpAddr, Ipv4Addr},
};

use chrono::{DateTime, Duration, Utc};
use http::{Method, Uri, Version};
use oauth2_types::scope::{OPENID, Scope};
use pasion_data::{
    AuthorizationGrant, BrowserSession, Client, DeviceCodeGrant, MatrixUser, PostAuthAction,
    UpstreamOAuthLink, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
    UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod, UrlBuilder, User,
    UserEmailAuthentication, UserEmailAuthenticationCode, UserRecoverySession, UserRegistration,
};
use pasion_i18n::DataLocale;
use pasion_iana::jose::JsonWebSignatureAlg;
// Retained for downstream context types or future additions
#[allow(unused_imports)]
use pasion_policy::{Violation, ViolationCode};
use rand::{
    Rng, SeedableRng,
    distributions::{Alphanumeric, DistString},
};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use ulid::Ulid;
use url::Url;

pub use self::{
    branding::SiteBranding, captcha::WithCaptcha, ext::SiteConfigExt, features::SiteFeatures,
};
use crate::{FieldError, FormField, FormState};

// ===========================================================================
// Core trait & sample helpers
// ===========================================================================

/// Trait implemented by every template context to provide wrapper constructors
/// and deterministic sample data for template validation.
pub trait TemplateContext: Serialize {
    /// Wrap this context with a browser session.
    fn with_session(self, current_session: BrowserSession) -> WithSession<Self>
    where
        Self: Sized,
    {
        WithSession {
            current_session,
            inner: self,
        }
    }

    /// Wrap this context with an optional browser session.
    fn maybe_with_session(
        self,
        current_session: Option<BrowserSession>,
    ) -> WithOptionalSession<Self>
    where
        Self: Sized,
    {
        WithOptionalSession {
            current_session,
            inner: self,
        }
    }

    /// Wrap this context with a CSRF token.
    fn with_csrf<C>(self, csrf_token: C) -> WithCsrf<Self>
    where
        Self: Sized,
        C: ToString,
    {
        // TODO: make this method use a CsrfToken again
        WithCsrf {
            csrf_token: csrf_token.to_string(),
            inner: self,
        }
    }

    /// Wrap this context with a locale tag.
    fn with_language(self, lang: DataLocale) -> WithLanguage<Self>
    where
        Self: Sized,
    {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }

    /// Wrap this context with optional CAPTCHA configuration.
    fn with_captcha(self, captcha: Option<pasion_data::CaptchaConfig>) -> WithCaptcha<Self>
    where
        Self: Sized,
    {
        WithCaptcha::new(captcha, self)
    }

    /// Produce sample values for template validation.
    ///
    /// Used by unit tests and the CLI command (`cargo run -- templates check`).
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized;
}

/// Key that identifies one particular sample rendering variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SampleIdentifier {
    pub components: Vec<(&'static str, String)>,
}

impl SampleIdentifier {
    pub fn from_index(index: usize) -> Self {
        Self {
            components: Vec::default(),
        }
        .with_appended("index", format!("{index}"))
    }

    pub fn with_appended(&self, kind: &'static str, locale: String) -> Self {
        let mut new = self.clone();
        new.components.push((kind, locale));
        new
    }
}

/// Turn a plain list of context values into an indexed sample map.
pub(crate) fn sample_list<T: TemplateContext>(items: Vec<T>) -> BTreeMap<SampleIdentifier, T> {
    items
        .into_iter()
        .enumerate()
        .map(|(idx, ctx)| (SampleIdentifier::from_index(idx), ctx))
        .collect()
}

// ===========================================================================
// TemplateContext for the unit type
// ===========================================================================

impl TemplateContext for () {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BTreeMap::new()
    }
}

// ===========================================================================
// Wrapper: WithLanguage
// ===========================================================================

/// Wraps a context with a locale string.
#[derive(Serialize, Debug)]
pub struct WithLanguage<T> {
    lang: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithLanguage<T> {
    /// Return the language tag carried by this wrapper.
    pub fn language(&self) -> &str {
        &self.lang
    }
}

impl<T> std::ops::Deref for WithLanguage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: TemplateContext> TemplateContext for WithLanguage<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // Create a forked RNG so we make samples deterministic between locales
        let forked_rng = ChaCha8Rng::from_rng(rng).unwrap();
        locales
            .iter()
            .flat_map(|loc| {
                T::sample(now, &mut forked_rng.clone(), locales)
                    .into_iter()
                    .map(|(id, ctx)| {
                        let new_id = id.with_appended("locale", loc.to_string());
                        let wrapped = WithLanguage {
                            lang: loc.to_string(),
                            inner: ctx,
                        };
                        (new_id, wrapped)
                    })
            })
            .collect()
    }
}

// ===========================================================================
// Wrapper: WithCsrf
// ===========================================================================

/// Wraps a context with a CSRF token.
#[derive(Serialize, Debug)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithCsrf<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(id, ctx)| {
                let wrapped = WithCsrf {
                    csrf_token: "fake_csrf_token".into(),
                    inner: ctx,
                };
                (id, wrapped)
            })
            .collect()
    }
}

// ===========================================================================
// Wrapper: WithSession
// ===========================================================================

/// Wraps a context with an authenticated browser session.
#[derive(Serialize)]
pub struct WithSession<T> {
    current_session: BrowserSession,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithSession<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .enumerate()
            .flat_map(|(sess_idx, session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(id, ctx)| {
                        let new_id = id.with_appended("browser-session", sess_idx.to_string());
                        let wrapped = WithSession {
                            current_session: session.clone(),
                            inner: ctx,
                        };
                        (new_id, wrapped)
                    })
            })
            .collect()
    }
}

// ===========================================================================
// Wrapper: WithOptionalSession
// ===========================================================================

/// Wraps a context with an optional browser session.
#[derive(Serialize)]
pub struct WithOptionalSession<T> {
    current_session: Option<BrowserSession>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithOptionalSession<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let session_variants: Vec<Option<BrowserSession>> = BrowserSession::samples(now, rng)
            .into_iter()
            .map(Some)
            .chain(std::iter::once(None))
            .collect();

        session_variants
            .into_iter()
            .enumerate()
            .flat_map(|(sess_idx, maybe_session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(id, ctx)| {
                        let new_id = if maybe_session.is_some() {
                            id.with_appended("browser-session", sess_idx.to_string())
                        } else {
                            id
                        };
                        let wrapped = WithOptionalSession {
                            current_session: maybe_session.clone(),
                            inner: ctx,
                        };
                        (new_id, wrapped)
                    })
            })
            .collect()
    }
}

// ===========================================================================
// EmptyContext
// ===========================================================================

/// Placeholder context that serializes to an empty struct.
pub struct EmptyContext;

impl Serialize for EmptyContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("EmptyContext", 0)?;
        // FIXME: for some reason, serde seems to not like struct flattening with empty
        // stuff
        s.serialize_field("__UNUSED", &())?;
        s.end()
    }
}

impl TemplateContext for EmptyContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![EmptyContext])
    }
}

// ===========================================================================
// Simple page contexts -- Index, App, ApiDoc
// ===========================================================================

/// Data passed to the `index.html` landing page.
#[derive(Serialize)]
pub struct IndexContext {
    discovery_url: Url,
}

impl IndexContext {
    /// Build the context from the OIDC discovery document URL.
    #[must_use]
    pub fn new(discovery_url: Url) -> Self {
        Self { discovery_url }
    }
}

impl TemplateContext for IndexContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            discovery_url: "https://example.com/.well-known/openid-configuration"
                .parse()
                .unwrap(),
        }])
    }
}

// ---------------------------------------------------------------------------

/// An error state injected by the backend so the frontend displays an
/// error page instead of the normal SPA routes.
#[derive(Serialize, Clone, Default)]
pub struct AppErrorState {
    /// One of: `account_deactivated`, `account_locked`, `session_ended`,
    /// `generic`.
    pub kind: String,
    /// The local username (without `@` / `:server`), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Human-readable description, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Frontend application configuration serialized as camelCase JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    root: String,
    api_endpoint: String,
    script_src: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<AppErrorState>,
}

/// Data passed to the `app.html` template.
#[derive(Serialize)]
pub struct AppContext {
    app_config: AppConfig,
}

impl AppContext {
    /// Build the context from a [`UrlBuilder`] and frontend script path
    /// (resolved from the Dioxus build output at startup).
    #[must_use]
    pub fn new(url_builder: &UrlBuilder, script_src: &str) -> Self {
        let root = url_builder.relative_url("/account/");
        let prefix = url_builder.prefix().unwrap_or_default();
        let api_base = format!("{prefix}/api/v1");
        Self {
            app_config: AppConfig {
                root,
                api_endpoint: api_base,
                script_src: script_src.to_owned(),
                error: None,
            },
        }
    }

    /// Attach an error state that the frontend will display instead of
    /// its normal routes.
    #[must_use]
    pub fn with_error(mut self, error: AppErrorState) -> Self {
        self.app_config.error = Some(error);
        self
    }
}

impl TemplateContext for AppContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        sample_list(vec![Self::new(&builder, "/assets/pasion-frontend.js")])
    }
}

// ---------------------------------------------------------------------------

/// Data passed to the `swagger/doc.html` template.
#[derive(Serialize)]
pub struct ApiDocContext {
    openapi_url: Url,
    callback_url: Url,
}

impl ApiDocContext {
    /// Build the context from a [`UrlBuilder`].
    #[must_use]
    pub fn from_url_builder(url_builder: &UrlBuilder) -> Self {
        Self {
            openapi_url: url_builder.absolute_url("/api/spec.json"),
            callback_url: url_builder.absolute_url("/api/doc/oauth2-callback"),
        }
    }
}

impl TemplateContext for ApiDocContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        sample_list(vec![Self::from_url_builder(&builder)])
    }
}

// ===========================================================================
// Login
// ===========================================================================

/// Enumeration of login form fields.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginFormField {
    /// Username field
    Username,

    /// Password field
    Password,
}

impl FormField for LoginFormField {
    fn keep(&self) -> bool {
        matches!(self, Self::Username)
    }
}

/// Discriminated union describing the post-authentication action variant.
/// See [`PostAuthContext`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContextInner {
    /// Resume an in-progress authorization grant.
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: Box<AuthorizationGrant>,
    },

    /// Resume an in-progress device code grant.
    ContinueDeviceCodeGrant {
        /// The device code grant that will be continued after authentication
        grant: Box<DeviceCodeGrant>,
    },

    /// Proceed to password change flow.
    ChangePassword,

    /// Link an upstream OAuth provider account.
    LinkUpstream {
        /// The upstream provider
        provider: Box<UpstreamOAuthProvider>,

        /// The link
        link: Box<UpstreamOAuthLink>,
    },

    /// Navigate to account management.
    ManageAccount,
}

/// Resolved post-authentication action presented on the login screen.
#[derive(Serialize)]
pub struct PostAuthContext {
    /// URL-level action parameters.
    pub params: PostAuthAction,

    /// Loaded context details for the action.
    #[serde(flatten)]
    pub ctx: PostAuthContextInner,
}

/// Data passed to the `login.html` template.
#[derive(Serialize, Default)]
pub struct LoginContext {
    form: FormState<LoginFormField>,
    next: Option<PostAuthContext>,
    providers: Vec<UpstreamOAuthProvider>,
}

impl TemplateContext for LoginContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        sample_list(vec![
            LoginContext {
                form: FormState::default(),
                next: None,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default(),
                next: None,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Required)
                    .with_error_on_field(
                        LoginFormField::Password,
                        FieldError::Policy {
                            code: None,
                            message: "password too short".to_owned(),
                        },
                    ),
                next: None,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Exists),
                next: None,
                providers: Vec::new(),
            },
        ])
    }
}

impl LoginContext {
    /// Replace the current form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Obtain a mutable reference to the form state.
    pub fn form_state_mut(&mut self) -> &mut FormState<LoginFormField> {
        &mut self.form
    }

    /// Attach upstream OAuth 2.0 providers to the context.
    #[must_use]
    pub fn with_upstream_providers(self, providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self { providers, ..self }
    }

    /// Set the post-authentication action.
    #[must_use]
    pub fn with_post_action(self, context: PostAuthContext) -> Self {
        Self {
            next: Some(context),
            ..self
        }
    }
}

// ===========================================================================
// Registration
// ===========================================================================

/// Enumeration of registration form fields.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterFormField {
    /// Username field
    Username,

    /// Email field
    Email,

    /// Password field
    Password,

    /// Confirmation password field
    PasswordConfirm,

    /// Terms-of-service acceptance checkbox
    AcceptTerms,
}

impl FormField for RegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::Email | Self::AcceptTerms => true,
            Self::Password | Self::PasswordConfirm => false,
        }
    }
}

/// Data passed to the `register.html` template.
#[derive(Serialize, Default)]
pub struct RegisterContext {
    providers: Vec<UpstreamOAuthProvider>,
    next: Option<PostAuthContext>,
}

impl TemplateContext for RegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![RegisterContext {
            providers: Vec::new(),
            next: None,
        }])
    }
}

impl RegisterContext {
    /// Build a registration context with the given upstream providers.
    #[must_use]
    pub fn new(providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self {
            providers,
            next: None,
        }
    }

    /// Attach a post-authentication action.
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

/// Data passed to the `password_register.html` template.
#[derive(Serialize, Default)]
pub struct PasswordRegisterContext {
    form: FormState<RegisterFormField>,
    next: Option<PostAuthContext>,
}

impl TemplateContext for PasswordRegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        sample_list(vec![PasswordRegisterContext {
            form: FormState::default(),
            next: None,
        }])
    }
}

impl PasswordRegisterContext {
    /// Replace the form state for the password registration form.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterFormField>) -> Self {
        Self { form, ..self }
    }

    /// Attach a post-authentication action.
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

// ===========================================================================
// Consent
// ===========================================================================

/// Data passed to the `consent.html` template.
#[derive(Serialize)]
pub struct ConsentContext {
    grant: AuthorizationGrant,
    client: Client,
    action: PostAuthAction,
    matrix_user: MatrixUser,
}

impl TemplateContext for ConsentContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    let action = PostAuthAction::continue_grant(grant.id);
                    // XXX
                    grant.client_id = client.id;
                    Self {
                        grant,
                        client,
                        action,
                        matrix_user: MatrixUser {
                            mxid: "@alice:example.com".to_owned(),
                            display_name: Some("Alice".to_owned()),
                        },
                    }
                })
                .collect(),
        )
    }
}

impl ConsentContext {
    /// Build a consent-page context for the given grant, client and Matrix user.
    #[must_use]
    pub fn new(grant: AuthorizationGrant, client: Client, matrix_user: MatrixUser) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant,
            client,
            action,
            matrix_user,
        }
    }
}

// ===========================================================================
// Policy violation
// ===========================================================================

#[derive(Serialize)]
#[serde(tag = "grant_type")]
enum PolicyViolationGrant {
    #[serde(rename = "authorization_code")]
    Authorization(AuthorizationGrant),
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),
}

/// Data passed to the `policy_violation.html` template.
#[derive(Serialize)]
pub struct PolicyViolationContext {
    grant: PolicyViolationGrant,
    client: Client,
    action: PostAuthAction,
}

impl TemplateContext for PolicyViolationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .flat_map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    // XXX
                    grant.client_id = client.id;

                    let auth_ctx =
                        PolicyViolationContext::for_authorization_grant(grant, client.clone());
                    let device_ctx = PolicyViolationContext::for_device_code_grant(
                        DeviceCodeGrant {
                            id: pasion_data::new_id(now, rng),
                            state: pasion_data::DeviceCodeGrantState::Pending,
                            client_id: client.id,
                            scope: [OPENID].into_iter().collect(),
                            user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                            device_code: Alphanumeric.sample_string(rng, 32),
                            created_at: now - Duration::try_minutes(5).unwrap(),
                            expires_at: now + Duration::try_minutes(25).unwrap(),
                            ip_address: None,
                            user_agent: None,
                        },
                        client,
                    );

                    [auth_ctx, device_ctx]
                })
                .collect(),
        )
    }
}

impl PolicyViolationContext {
    /// Build a policy-violation page context for an authorization grant.
    #[must_use]
    pub const fn for_authorization_grant(grant: AuthorizationGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::Authorization(grant),
            client,
            action,
        }
    }

    /// Build a policy-violation page context for a device-code grant.
    #[must_use]
    pub const fn for_device_code_grant(grant: DeviceCodeGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_device_code_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::DeviceCode(grant),
            client,
            action,
        }
    }
}

// ===========================================================================
// Email templates
// ===========================================================================

/// Data passed to the `emails/recovery.{txt,html,subject}` templates.
#[derive(Serialize)]
pub struct EmailRecoveryContext {
    user: User,
    session: UserRecoverySession,
    recovery_link: Url,
}

impl EmailRecoveryContext {
    /// Build the recovery-email context.
    #[must_use]
    pub fn new(user: User, session: UserRecoverySession, recovery_link: Url) -> Self {
        Self {
            user,
            session,
            recovery_link,
        }
    }

    /// The user this recovery email is addressed to.
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// The recovery session associated with this email.
    #[must_use]
    pub fn session(&self) -> &UserRecoverySession {
        &self.session
    }
}

impl TemplateContext for EmailRecoveryContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(User::samples(now, rng).into_iter().map(|user| {
            let session = UserRecoverySession {
                id: pasion_data::new_id(now, rng),
                email: "hello@example.com".to_owned(),
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/536.30.1 (KHTML, like Gecko) Version/6.0.5 Safari/536.30.1".to_owned(),
                ip_address: Some(IpAddr::from([192_u8, 0, 2, 1])),
                locale: "en".to_owned(),
                created_at: now,
                consumed_at: None,
            };

            let link = "https://example.com/recovery/complete?ticket=abcdefghijklmnopqrstuvwxyz0123456789".parse().unwrap();

            Self::new(user, session, link)
        }).collect())
    }
}

// ---------------------------------------------------------------------------

/// Data passed to the `emails/verification.{txt,html,subject}` templates.
#[derive(Serialize)]
pub struct EmailVerificationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    browser_session: Option<BrowserSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_registration: Option<UserRegistration>,
    authentication_code: UserEmailAuthenticationCode,
}

impl EmailVerificationContext {
    /// Build the verification-email context.
    #[must_use]
    pub fn new(
        authentication_code: UserEmailAuthenticationCode,
        browser_session: Option<BrowserSession>,
        user_registration: Option<UserRegistration>,
    ) -> Self {
        Self {
            browser_session,
            user_registration,
            authentication_code,
        }
    }

    /// The user this verification email is addressed to, if available.
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.browser_session.as_ref().map(|s| &s.user)
    }

    /// The verification code carried by this email.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.authentication_code.code
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            BrowserSession::samples(now, rng)
                .into_iter()
                .map(|session| {
                    let code = UserEmailAuthenticationCode {
                        id: pasion_data::new_id(now, rng),
                        user_email_authentication_id: pasion_data::new_id(now, rng),
                        code: "123456".to_owned(),
                        created_at: now - Duration::try_minutes(5).unwrap(),
                        expires_at: now + Duration::try_minutes(25).unwrap(),
                    };

                    Self {
                        browser_session: Some(session),
                        user_registration: None,
                        authentication_code: code,
                    }
                })
                .collect(),
        )
    }
}

// ===========================================================================
// Registration steps
// ===========================================================================

/// Fields on the email-verification step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsVerifyEmailFormField {
    /// Verification code
    Code,
}

impl FormField for RegisterStepsVerifyEmailFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Data for the `pages/register/steps/verify_email.html` template.
#[derive(Serialize)]
pub struct RegisterStepsVerifyEmailContext {
    form: FormState<RegisterStepsVerifyEmailFormField>,
    authentication: UserEmailAuthentication,
}

impl RegisterStepsVerifyEmailContext {
    /// Create a context for the email verification step.
    #[must_use]
    pub fn new(authentication: UserEmailAuthentication) -> Self {
        Self {
            form: FormState::default(),
            authentication,
        }
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterStepsVerifyEmailFormField>) -> Self {
        Self { form, ..self }
    }
}

impl TemplateContext for RegisterStepsVerifyEmailContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let auth = UserEmailAuthentication {
            id: pasion_data::new_id(now, rng),
            user_session_id: None,
            user_registration_id: None,
            email: "foobar@example.com".to_owned(),
            created_at: now,
            completed_at: None,
        };

        sample_list(vec![Self {
            form: FormState::default(),
            authentication: auth,
        }])
    }
}

// ---------------------------------------------------------------------------

/// Data for the `pages/register/steps/email_in_use.html` template.
#[derive(Serialize)]
pub struct RegisterStepsEmailInUseContext {
    email: String,
    action: Option<PostAuthAction>,
}

impl RegisterStepsEmailInUseContext {
    /// Create a context for the email-in-use page.
    #[must_use]
    pub fn new(email: String, action: Option<PostAuthAction>) -> Self {
        Self { email, action }
    }
}

impl TemplateContext for RegisterStepsEmailInUseContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let addr = "hello@example.com".to_owned();
        let action = PostAuthAction::continue_grant(Ulid::nil());
        sample_list(vec![Self::new(addr, Some(action))])
    }
}

// ---------------------------------------------------------------------------

/// Fields on the display-name step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsDisplayNameFormField {
    /// Display name
    DisplayName,
}

impl FormField for RegisterStepsDisplayNameFormField {
    fn keep(&self) -> bool {
        match self {
            Self::DisplayName => true,
        }
    }
}

/// Data for the `display_name.html` template.
#[derive(Serialize, Default)]
pub struct RegisterStepsDisplayNameContext {
    form: FormState<RegisterStepsDisplayNameFormField>,
}

impl RegisterStepsDisplayNameContext {
    /// Build the display-name page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsDisplayNameFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsDisplayNameContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            form: FormState::default(),
        }])
    }
}

// ---------------------------------------------------------------------------

/// Fields on the registration-token step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsRegistrationTokenFormField {
    /// Registration token
    Token,
}

impl FormField for RegisterStepsRegistrationTokenFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Token => true,
        }
    }
}

/// Data for the registration-token step page.
#[derive(Serialize, Default)]
pub struct RegisterStepsRegistrationTokenContext {
    form: FormState<RegisterStepsRegistrationTokenFormField>,
}

impl RegisterStepsRegistrationTokenContext {
    /// Build the registration-token page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsRegistrationTokenFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsRegistrationTokenContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            form: FormState::default(),
        }])
    }
}

// ===========================================================================
// Account recovery
// ===========================================================================

/// Fields on the recovery start form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStartFormField {
    /// Email address
    Email,
}

impl FormField for RecoveryStartFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Email => true,
        }
    }
}

/// Data for the `pages/recovery/start.html` template.
#[derive(Serialize, Default)]
pub struct RecoveryStartContext {
    form: FormState<RecoveryStartFormField>,
}

impl RecoveryStartContext {
    /// Build the recovery-start page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RecoveryStartFormField>) -> Self {
        Self { form }
    }
}

impl TemplateContext for RecoveryStartContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Required),
            ),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------

/// Data for the `pages/recovery/progress.html` template.
#[derive(Serialize)]
pub struct RecoveryProgressContext {
    session: UserRecoverySession,
    /// True when a resend attempt was blocked by the rate limiter.
    resend_failed_due_to_rate_limit: bool,
}

impl RecoveryProgressContext {
    /// Build the recovery-progress page context.
    #[must_use]
    pub fn new(session: UserRecoverySession, resend_failed_due_to_rate_limit: bool) -> Self {
        Self {
            session,
            resend_failed_due_to_rate_limit,
        }
    }
}

impl TemplateContext for RecoveryProgressContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let sess = UserRecoverySession {
            id: pasion_data::new_id(now, rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };

        sample_list(vec![
            Self {
                session: sess.clone(),
                resend_failed_due_to_rate_limit: false,
            },
            Self {
                session: sess,
                resend_failed_due_to_rate_limit: true,
            },
        ])
    }
}

// ---------------------------------------------------------------------------

/// Data for the `pages/recovery/expired.html` template.
#[derive(Serialize)]
pub struct RecoveryExpiredContext {
    session: UserRecoverySession,
}

impl RecoveryExpiredContext {
    /// Build the recovery-expired page context.
    #[must_use]
    pub fn new(session: UserRecoverySession) -> Self {
        Self { session }
    }
}

impl TemplateContext for RecoveryExpiredContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let sess = UserRecoverySession {
            id: pasion_data::new_id(now, rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };

        sample_list(vec![Self { session: sess }])
    }
}

// ---------------------------------------------------------------------------

/// Fields on the recovery-finish form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFinishFormField {
    /// New password
    NewPassword,

    /// New password confirmation
    NewPasswordConfirm,
}

impl FormField for RecoveryFinishFormField {
    fn keep(&self) -> bool {
        false
    }
}

/// Data for the `pages/recovery/finish.html` template.
#[derive(Serialize)]
pub struct RecoveryFinishContext {
    user: User,
    form: FormState<RecoveryFinishFormField>,
}

impl RecoveryFinishContext {
    /// Build the recovery-finish page context.
    #[must_use]
    pub fn new(user: User) -> Self {
        Self {
            user,
            form: FormState::default(),
        }
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(mut self, form: FormState<RecoveryFinishFormField>) -> Self {
        self.form = form;
        self
    }
}

impl TemplateContext for RecoveryFinishContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .flat_map(|u| {
                    vec![
                        Self::new(u.clone()),
                        Self::new(u.clone()).with_form_state(
                            FormState::default().with_error_on_field(
                                RecoveryFinishFormField::NewPassword,
                                FieldError::Invalid,
                            ),
                        ),
                        Self::new(u.clone()).with_form_state(
                            FormState::default().with_error_on_field(
                                RecoveryFinishFormField::NewPasswordConfirm,
                                FieldError::Invalid,
                            ),
                        ),
                    ]
                })
                .collect(),
        )
    }
}

// ===========================================================================
// Upstream OAuth 2.0
// ===========================================================================

/// Data for the `pages/upstream_oauth2/link_mismatch.html` template.
#[derive(Serialize)]
pub struct UpstreamExistingLinkContext {
    linked_user: User,
}

impl UpstreamExistingLinkContext {
    /// Build the context from an already-linked user.
    #[must_use]
    pub fn new(linked_user: User) -> Self {
        Self { linked_user }
    }
}

impl TemplateContext for UpstreamExistingLinkContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|u| Self { linked_user: u })
                .collect(),
        )
    }
}

// ---------------------------------------------------------------------------

/// Data for the `pages/upstream_oauth2/suggest_link.html` template.
#[derive(Serialize)]
pub struct UpstreamSuggestLink {
    post_logout_action: PostAuthAction,
}

impl UpstreamSuggestLink {
    /// Build the context from an upstream OAuth link.
    #[must_use]
    pub fn new(link: &UpstreamOAuthLink) -> Self {
        Self::for_link_id(link.id)
    }

    fn for_link_id(id: Ulid) -> Self {
        let post_logout_action = PostAuthAction::link_upstream(id);
        Self { post_logout_action }
    }
}

impl TemplateContext for UpstreamSuggestLink {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let link_id = pasion_data::new_id(now, rng);
        sample_list(vec![Self::for_link_id(link_id)])
    }
}

// ---------------------------------------------------------------------------

/// User-editable fields on the upstream account registration form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRegisterFormField {
    /// Username field
    Username,

    /// Terms-of-service acceptance
    AcceptTerms,
}

impl FormField for UpstreamRegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::AcceptTerms => true,
        }
    }
}

/// Data for the `pages/upstream_oauth2/do_register.html` template.
#[derive(Serialize)]
pub struct UpstreamRegister {
    upstream_oauth_link: UpstreamOAuthLink,
    upstream_oauth_provider: UpstreamOAuthProvider,
    imported_localpart: Option<String>,
    force_localpart: bool,
    imported_display_name: Option<String>,
    force_display_name: bool,
    imported_email: Option<String>,
    force_email: bool,
    form_state: FormState<UpstreamRegisterFormField>,
}

impl UpstreamRegister {
    /// Build the context for registering via an upstream provider.
    #[must_use]
    pub fn new(
        upstream_oauth_link: UpstreamOAuthLink,
        upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Self {
        Self {
            upstream_oauth_link,
            upstream_oauth_provider,
            imported_localpart: None,
            force_localpart: false,
            imported_display_name: None,
            force_display_name: false,
            imported_email: None,
            force_email: false,
            form_state: FormState::default(),
        }
    }

    /// Set the imported localpart
    pub fn set_localpart(&mut self, localpart: String, force: bool) {
        self.imported_localpart = Some(localpart);
        self.force_localpart = force;
    }

    /// Set the imported localpart
    #[must_use]
    pub fn with_localpart(self, localpart: String, force: bool) -> Self {
        Self {
            imported_localpart: Some(localpart),
            force_localpart: force,
            ..self
        }
    }

    /// Set the imported display name
    pub fn set_display_name(&mut self, display_name: String, force: bool) {
        self.imported_display_name = Some(display_name);
        self.force_display_name = force;
    }

    /// Set the imported display name
    #[must_use]
    pub fn with_display_name(self, display_name: String, force: bool) -> Self {
        Self {
            imported_display_name: Some(display_name),
            force_display_name: force,
            ..self
        }
    }

    /// Set the imported email
    pub fn set_email(&mut self, email: String, force: bool) {
        self.imported_email = Some(email);
        self.force_email = force;
    }

    /// Set the imported email
    #[must_use]
    pub fn with_email(self, email: String, force: bool) -> Self {
        Self {
            imported_email: Some(email),
            force_email: force,
            ..self
        }
    }

    /// Set the form state
    pub fn set_form_state(&mut self, form_state: FormState<UpstreamRegisterFormField>) {
        self.form_state = form_state;
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form_state: FormState<UpstreamRegisterFormField>) -> Self {
        Self { form_state, ..self }
    }
}

impl TemplateContext for UpstreamRegister {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self::new(
            UpstreamOAuthLink {
                id: Ulid::nil(),
                provider_id: Ulid::nil(),
                user_id: None,
                subject: "subject".to_owned(),
                human_account_name: Some("@john".to_owned()),
                created_at: now,
                updated_at: now,
            },
            UpstreamOAuthProvider {
                id: Ulid::nil(),
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client-id".to_owned(),
                encrypted_client_secret: None,
                claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                jwks_uri_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                created_at: now,
                disabled_at: None,
                on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            },
        )])
    }
}

// ===========================================================================
// Device code flow
// ===========================================================================

/// Fields on the device-link page form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkFormField {
    /// Device code
    Code,
}

impl FormField for DeviceLinkFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Data for the `device_link.html` template.
#[derive(Serialize, Default, Debug)]
pub struct DeviceLinkContext {
    form_state: FormState<DeviceLinkFormField>,
}

impl DeviceLinkContext {
    /// Build the device-link page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(mut self, form_state: FormState<DeviceLinkFormField>) -> Self {
        self.form_state = form_state;
        self
    }
}

impl TemplateContext for DeviceLinkContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(DeviceLinkFormField::Code, FieldError::Required),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------

/// Data for the `device_consent.html` template.
#[derive(Serialize, Debug)]
pub struct DeviceConsentContext {
    grant: DeviceCodeGrant,
    client: Client,
    matrix_user: MatrixUser,
}

impl DeviceConsentContext {
    /// Build the device-consent page context.
    #[must_use]
    pub fn new(grant: DeviceCodeGrant, client: Client, matrix_user: MatrixUser) -> Self {
        Self {
            grant,
            client,
            matrix_user,
        }
    }
}

impl TemplateContext for DeviceConsentContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(Client::samples(now, rng)
            .into_iter()
            .map(|client|  {
                let grant = DeviceCodeGrant {
                    id: pasion_data::new_id(now, rng),
                    state: pasion_data::DeviceCodeGrantState::Pending,
                    client_id: client.id,
                    scope: [OPENID].into_iter().collect(),
                    user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                    device_code: Alphanumeric.sample_string(rng, 32),
                    created_at: now - Duration::try_minutes(5).unwrap(),
                    expires_at: now + Duration::try_minutes(25).unwrap(),
                    ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()),
                };
                Self {
                    grant,
                    client,
                    matrix_user: MatrixUser {
                        mxid: "@alice:example.com".to_owned(),
                        display_name: Some("Alice".to_owned()),
                    }
                }
            })
            .collect())
    }
}

// ===========================================================================
// Account state
// ===========================================================================

/// Data for the `account/deactivated.html` and `account/locked.html`
/// templates.
#[derive(Serialize)]
pub struct AccountInactiveContext {
    user: User,
}

impl AccountInactiveContext {
    /// Build the account-inactive page context.
    #[must_use]
    pub fn new(user: User) -> Self {
        Self { user }
    }
}

impl TemplateContext for AccountInactiveContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|u| AccountInactiveContext { user: u })
                .collect(),
        )
    }
}

// ===========================================================================
// Device naming
// ===========================================================================

/// Data for the `device_name.txt` template.
#[derive(Serialize)]
pub struct DeviceNameContext {
    client: Client,
    raw_user_agent: String,
}

impl DeviceNameContext {
    /// Build the context from a client and an optional User-Agent string.
    #[must_use]
    pub fn new(client: Client, user_agent: Option<String>) -> Self {
        Self {
            client,
            raw_user_agent: user_agent.unwrap_or_default(),
        }
    }
}

impl TemplateContext for DeviceNameContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(Client::samples(now, rng)
            .into_iter()
            .map(|client| DeviceNameContext {
                client,
                raw_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned(),
            })
            .collect())
    }
}

// ===========================================================================
// OAuth 2.0 form_post response mode
// ===========================================================================

/// Data for the `form_post.html` template.
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Option<Url>,
    params: T,
}

impl<T: TemplateContext> TemplateContext for FormPostContext<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(id, inner_params)| {
                let ctx = FormPostContext {
                    redirect_uri: "https://example.com/callback".parse().ok(),
                    params: inner_params,
                };
                (id, ctx)
            })
            .collect()
    }
}

impl<T> FormPostContext<T> {
    /// Build a form-post context that redirects to the given URL.
    pub fn new_for_url(redirect_uri: Url, params: T) -> Self {
        Self {
            redirect_uri: Some(redirect_uri),
            params,
        }
    }

    /// Build a form-post context that posts to the current URL.
    pub fn new_for_current_url(params: T) -> Self {
        Self {
            redirect_uri: None,
            params,
        }
    }

    /// Attach a language tag.
    ///
    /// Provided separately from the [`TemplateContext`] trait because the
    /// generic parameter makes blanket implementation awkward.
    pub fn with_language(self, lang: &DataLocale) -> WithLanguage<Self> {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }
}

// ===========================================================================
// Error pages
// ===========================================================================

/// Data for the `error.html` template.
#[derive(Default, Serialize, Debug, Clone)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
    lang: Option<String>,
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = &self.code {
            writeln!(f, "code: {code}")?;
        }
        if let Some(desc) = &self.description {
            writeln!(f, "{desc}")?;
        }
        if let Some(detail) = &self.details {
            writeln!(f, "details: {detail}")?;
        }
        Ok(())
    }
}

impl TemplateContext for ErrorContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new()
                .with_code("sample_error")
                .with_description("A fancy description".into())
                .with_details("Something happened".into()),
            Self::new().with_code("another_error"),
            Self::new(),
        ])
    }
}

impl ErrorContext {
    /// Create a blank error context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the error code.
    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    /// Set the human-readable description.
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set additional detail text.
    #[must_use]
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the language tag for the error page.
    #[must_use]
    pub fn with_language(mut self, lang: &DataLocale) -> Self {
        self.lang = Some(lang.to_string());
        self
    }

    /// Return the error code, if set.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    /// Return the description, if set.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Return the detail text, if set.
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }
}

// ---------------------------------------------------------------------------

/// Data for the `404.html` not-found template.
#[derive(Serialize)]
pub struct NotFoundContext {
    method: String,
    version: String,
    uri: String,
}

impl NotFoundContext {
    /// Build the context from the incoming request metadata.
    #[must_use]
    pub fn new(method: &Method, version: Version, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            version: format!("{version:?}"),
            uri: uri.to_string(),
        }
    }
}

impl TemplateContext for NotFoundContext {
    fn sample<R: Rng>(
        _now: DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(&Method::GET, Version::HTTP_11, &"/".parse().unwrap()),
            Self::new(&Method::POST, Version::HTTP_2, &"/foo/bar".parse().unwrap()),
            Self::new(
                &Method::PUT,
                Version::HTTP_10,
                &"/foo?bar=baz".parse().unwrap(),
            ),
        ])
    }
}
