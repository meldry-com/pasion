use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::UrlBuilder;
use crate::traits::*;

use super::{Index, PostAuthAction};

/// `GET|POST /login`
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,

    login_hint: Option<String>,
}

impl Route for Login {
    type Query = Self;

    fn route() -> &'static str {
        "/login"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

impl Login {
    #[must_use]
    pub const fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
            login_hint: None,
        }
    }

    #[must_use]
    pub const fn and_continue_grant(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(id)),
            login_hint: None,
        }
    }

    #[must_use]
    pub const fn and_continue_device_code_grant(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_device_code_grant(id)),
            login_hint: None,
        }
    }

    #[must_use]
    pub const fn and_link_upstream(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::link_upstream(id)),
            login_hint: None,
        }
    }

    /// Set the login hint to pre-fill the login form.
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: String) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    /// Get a reference to the login's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> salvo::writing::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl From<Option<PostAuthAction>> for Login {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self {
            post_auth_action,
            login_hint: None,
        }
    }
}

/// `POST /logout`
#[derive(Default, Debug, Clone)]
pub struct Logout;

impl SimpleRoute for Logout {
    const PATH: &'static str = "/logout";
}

/// `POST /register`
#[derive(Default, Debug, Clone)]
pub struct Register {
    post_auth_action: Option<PostAuthAction>,
}

impl Register {
    #[must_use]
    pub fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
        }
    }

    #[must_use]
    pub fn and_continue_grant(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(data)),
        }
    }

    /// Get a reference to the reauth's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> salvo::writing::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl Route for Register {
    type Query = PostAuthAction;

    fn route() -> &'static str {
        "/register"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl From<Option<PostAuthAction>> for Register {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

/// `GET|POST /register/password`
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRegister {
    username: Option<String>,

    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

impl PasswordRegister {
    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }

    #[must_use]
    pub fn and_continue_grant(mut self, data: Ulid) -> Self {
        self.post_auth_action = Some(PostAuthAction::continue_grant(data));
        self
    }

    /// Get a reference to the post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    /// Get a reference to the username chosen by the user.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> salvo::writing::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(url_builder),
            None => url_builder.redirect(&Index),
        }
    }
}

impl Route for PasswordRegister {
    type Query = Self;

    fn route() -> &'static str {
        "/register/password"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}

impl From<Option<PostAuthAction>> for PasswordRegister {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self {
            username: None,
            post_auth_action,
        }
    }
}

/// `GET|POST /register/steps/{id}/token`
#[derive(Debug, Clone)]
pub struct RegisterToken {
    id: Ulid,
}

impl RegisterToken {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterToken {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/token"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/token", self.id).into()
    }
}

/// `GET|POST /register/steps/{id}/display-name`
#[derive(Debug, Clone)]
pub struct RegisterDisplayName {
    id: Ulid,
}

impl RegisterDisplayName {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterDisplayName {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/display-name"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/display-name", self.id).into()
    }
}

/// `GET|POST /register/steps/{id}/verify-email`
#[derive(Debug, Clone)]
pub struct RegisterVerifyEmail {
    id: Ulid,
}

impl RegisterVerifyEmail {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterVerifyEmail {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/verify-email"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/verify-email", self.id).into()
    }
}

/// `GET /register/steps/{id}/finish`
#[derive(Debug, Clone)]
pub struct RegisterFinish {
    id: Ulid,
}

impl RegisterFinish {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for RegisterFinish {
    type Query = ();
    fn route() -> &'static str {
        "/register/steps/{id}/finish"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/register/steps/{}/finish", self.id).into()
    }
}

/// `GET|POST /recover`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryStart;

impl SimpleRoute for AccountRecoveryStart {
    const PATH: &'static str = "/recover";
}

/// `GET|POST /recover/progress/{session_id}`
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryProgress {
    session_id: Ulid,
}

impl AccountRecoveryProgress {
    #[must_use]
    pub fn new(session_id: Ulid) -> Self {
        Self { session_id }
    }
}

impl Route for AccountRecoveryProgress {
    type Query = ();
    fn route() -> &'static str {
        "/recover/progress/{session_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/recover/progress/{}", self.session_id).into()
    }
}

/// `GET /account/password/recovery?ticket=:ticket`
/// Rendered by the React frontend
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct AccountRecoveryFinish {
    ticket: String,
}

impl AccountRecoveryFinish {
    #[must_use]
    pub fn new(ticket: String) -> Self {
        Self { ticket }
    }
}

impl Route for AccountRecoveryFinish {
    type Query = AccountRecoveryFinish;

    fn route() -> &'static str {
        "/account/password/recovery"
    }

    fn query(&self) -> Option<&Self::Query> {
        Some(self)
    }
}
