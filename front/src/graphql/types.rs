#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ── Viewer & User ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
pub enum Viewer {
    User(User),
    Anonymous(Anonymous),
}

impl Viewer {
    pub fn as_user(&self) -> Option<&User> {
        match self {
            Viewer::User(u) => Some(u),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Anonymous {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub matrix: Option<MatrixUser>,
    #[serde(default)]
    pub has_password: Option<bool>,
    #[serde(default)]
    pub emails: Option<EmailConnection>,
    #[serde(default)]
    pub browser_sessions: Option<BrowserSessionConnection>,
    #[serde(default)]
    pub app_sessions: Option<AppSessionConnection>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixUser {
    pub mxid: String,
    pub display_name: Option<String>,
}

// ── Session types ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
pub enum ViewerSession {
    BrowserSession(BrowserSession),
    Anonymous(Anonymous),
}

impl ViewerSession {
    pub fn as_browser_session(&self) -> Option<&BrowserSession> {
        match self {
            ViewerSession::BrowserSession(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSession {
    pub id: String,
    #[serde(default)]
    pub user: Option<User>,
    #[serde(default)]
    pub user_agent: Option<UserAgent>,
    #[serde(default)]
    pub last_active_ip: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_authentication: Option<Authentication>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAgent {
    pub name: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub device_type: DeviceType,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceType {
    Pc,
    Mobile,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "__typename")]
pub enum AppSession {
    Oauth2Session(Oauth2Session),
    CompatSession(CompatSession),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2Session {
    pub id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client: Option<Oauth2Client>,
    #[serde(default)]
    pub user_agent: Option<UserAgent>,
    #[serde(default)]
    pub last_active_ip: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2Client {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatSession {
    pub id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub user_agent: Option<UserAgent>,
    #[serde(default)]
    pub last_active_ip: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub sso_login: Option<SsoLogin>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoLogin {
    pub id: String,
    pub redirect_uri: String,
}

// ── Email ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEmail {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub confirmed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailConnection {
    pub total_count: i32,
    #[serde(default)]
    pub edges: Vec<EmailEdge>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EmailEdge {
    pub cursor: String,
    pub node: UserEmail,
}

// ── Session connections / pagination ───────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSessionConnection {
    pub total_count: i32,
    pub edges: Vec<BrowserSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BrowserSessionEdge {
    pub cursor: String,
    pub node: BrowserSession,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionConnection {
    pub total_count: i32,
    pub edges: Vec<AppSessionEdge>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AppSessionEdge {
    pub cursor: String,
    pub node: AppSession,
}

// ── Site Config ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteConfig {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub email_change_allowed: bool,
    #[serde(default)]
    pub password_login_enabled: bool,
    #[serde(default)]
    pub account_deactivation_allowed: bool,
    #[serde(default)]
    pub display_name_change_allowed: bool,
    #[serde(default)]
    pub password_registration_enabled: bool,
    #[serde(default)]
    pub minimum_password_complexity: i32,
    #[serde(default)]
    pub imprint: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub plan_management_iframe_uri: Option<String>,
}

// ── Mutation payloads ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetPasswordPayload {
    pub status: SetPasswordStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetPasswordStatus {
    Allowed,
    WrongPassword,
    InvalidNewPassword,
    NotFound,
    NoCurrentPassword,
    PasswordChangesDisabled,
    AccountLocked,
    ExpiredRecoveryTicket,
    NoSuchRecoveryTicket,
    RecoveryTicketAlreadyUsed,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetDisplayNamePayload {
    pub status: SetDisplayNameStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetDisplayNameStatus {
    Set,
    Invalid,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AddEmailPayload {
    pub status: AddEmailStatus,
    pub email: Option<UserEmail>,
    pub violations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AddEmailStatus {
    Added,
    Exists,
    Invalid,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RemoveEmailPayload {
    pub status: RemoveEmailStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoveEmailStatus {
    Removed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EndSessionPayload {
    pub status: EndSessionStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndSessionStatus {
    Ended,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CompleteEmailAuthPayload {
    pub status: CompleteEmailAuthStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompleteEmailAuthStatus {
    Completed,
    InvalidCode,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeactivateUserPayload {
    pub status: DeactivateUserStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeactivateUserStatus {
    Deactivated,
    NotFound,
    IncorrectPassword,
}

// ── Query response wrappers ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserGreetingData {
    pub viewer: Viewer,
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfileData {
    pub viewer_session: ViewerSession,
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FooterData {
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SessionsOverviewData {
    pub viewer: Viewer,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AppSessionsListData {
    pub viewer: Viewer,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSessionListData {
    pub viewer_session: ViewerSession,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PasswordChangeData {
    pub viewer: Viewer,
    #[serde(rename = "siteConfig")]
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordResult {
    pub set_password: SetPasswordPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisplayNameResult {
    pub set_display_name: SetDisplayNamePayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEmailResult {
    pub add_email: AddEmailPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndBrowserSessionResult {
    pub end_browser_session: EndSessionPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndOauth2SessionResult {
    pub end_oauth2_session: EndSessionPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndCompatSessionResult {
    pub end_compat_session: EndSessionPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanManagementData {
    pub site_config: SiteConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetailData {
    pub node: Option<SessionNode>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum SessionNode {
    BrowserSession(BrowserSession),
    Oauth2Session(Oauth2Session),
    CompatSession(CompatSession),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEmailListData {
    pub viewer_session: ViewerSession,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteEmailAuthResult {
    pub complete_email_authentication: CompleteEmailAuthPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateUserResult {
    pub deactivate_user: DeactivateUserPayload,
}

// ── Client detail ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDetailData {
    pub node: Option<ClientNode>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum ClientNode {
    Oauth2Client(Oauth2ClientDetail),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2ClientDetail {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String>,
}

// ── Device redirect ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DeviceRedirectData {
    pub viewer: Viewer,
}

// ── Password recovery ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordRecoveryData {
    pub site_config: SiteConfig,
}

// ── Cross-signing reset ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentViewerData {
    pub viewer: Viewer,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCrossSigningResetResult {
    pub allow_user_cross_signing_reset: AllowCrossSigningResetPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AllowCrossSigningResetPayload {
    pub user: Option<User>,
}

// ── Resend recovery email ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendRecoveryEmailResult {
    pub resend_recovery_email: ResendRecoveryEmailPayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ResendRecoveryEmailPayload {
    pub status: String,
}

// ── Remove email result ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveEmailResult {
    pub remove_email: RemoveEmailPayload,
}

// ── Session name mutation results ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSessionNamePayload {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetOauth2SessionNameResult {
    pub set_oauth2_session_display_name: SetSessionNamePayload,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCompatSessionNameResult {
    pub set_compat_session_display_name: SetSessionNamePayload,
}

// ── Email verification query/mutation types ───────────────────

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEmailAuthentication {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "__typename")]
pub enum EmailAuthNode {
    UserEmailAuthentication(UserEmailAuthentication),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VerifyEmailData {
    pub node: Option<EmailAuthNode>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendEmailAuthCodePayload {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendEmailAuthCodeResult {
    pub resend_email_authentication_code: ResendEmailAuthCodePayload,
}
