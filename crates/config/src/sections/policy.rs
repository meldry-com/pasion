use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

/// The policy engine backend to use for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEngine {
    /// OPA (Open Policy Agent) WASM backend.
    ///
    /// Uses compiled Rego policies running as WebAssembly modules.
    /// This is the default and most mature backend.
    #[default]
    Opa,

    /// Amazon Cedar policy backend.
    ///
    /// Uses Cedar policies evaluated natively in Rust.
    /// Requires the `cedar` feature to be enabled.
    Cedar,

    /// Remote HTTP policy backend.
    ///
    /// Delegates policy evaluation to an external HTTP service.
    /// Requires the `remote` feature to be enabled.
    Remote,
}

fn is_default_engine(value: &PolicyEngine) -> bool {
    *value == PolicyEngine::default()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_policy_path() -> Utf8PathBuf {
    "./policies/policy.wasm".into()
}

#[cfg(feature = "docker")]
fn default_policy_path() -> Utf8PathBuf {
    "/usr/local/share/pasion/policy.wasm".into()
}

#[cfg(feature = "dist")]
fn default_policy_path() -> Utf8PathBuf {
    "./share/policy.wasm".into()
}

fn is_default_policy_path(value: &Utf8PathBuf) -> bool {
    *value == default_policy_path()
}

fn default_client_registration_entrypoint() -> String {
    "client_registration/violation".to_owned()
}

fn is_default_client_registration_entrypoint(value: &String) -> bool {
    *value == default_client_registration_entrypoint()
}

fn default_register_entrypoint() -> String {
    "register/violation".to_owned()
}

fn is_default_register_entrypoint(value: &String) -> bool {
    *value == default_register_entrypoint()
}

fn default_authorization_grant_entrypoint() -> String {
    "authorization_grant/violation".to_owned()
}

fn is_default_authorization_grant_entrypoint(value: &String) -> bool {
    *value == default_authorization_grant_entrypoint()
}

fn default_password_entrypoint() -> String {
    "password/violation".to_owned()
}

fn is_default_password_entrypoint(value: &String) -> bool {
    *value == default_password_entrypoint()
}

fn default_email_entrypoint() -> String {
    "email/violation".to_owned()
}

fn is_default_email_entrypoint(value: &String) -> bool {
    *value == default_email_entrypoint()
}

fn default_data() -> serde_json::Value {
    serde_json::json!({})
}

fn is_default_data(value: &serde_json::Value) -> bool {
    *value == default_data()
}

/// Policy engine configuration.
///
/// Supports multiple backends: OPA/WASM (default), Cedar, and Remote HTTP.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    /// The policy engine to use.
    ///
    /// Defaults to `opa`. Other options: `cedar`, `remote`.
    #[serde(default, skip_serializing_if = "is_default_engine")]
    pub engine: PolicyEngine,

    // -- OPA-specific configuration --
    /// Path to the OPA WASM module (used when engine is `opa`)
    #[serde(
        default = "default_policy_path",
        skip_serializing_if = "is_default_policy_path"
    )]
    #[schemars(with = "String")]
    pub wasm_module: Utf8PathBuf,

    /// Entrypoint to use when evaluating client registrations
    #[serde(
        default = "default_client_registration_entrypoint",
        skip_serializing_if = "is_default_client_registration_entrypoint"
    )]
    pub client_registration_entrypoint: String,

    /// Entrypoint to use when evaluating user registrations
    #[serde(
        default = "default_register_entrypoint",
        skip_serializing_if = "is_default_register_entrypoint"
    )]
    pub register_entrypoint: String,

    /// Entrypoint to use when evaluating authorization grants
    #[serde(
        default = "default_authorization_grant_entrypoint",
        skip_serializing_if = "is_default_authorization_grant_entrypoint"
    )]
    pub authorization_grant_entrypoint: String,

    /// Entrypoint to use when changing password
    #[serde(
        default = "default_password_entrypoint",
        skip_serializing_if = "is_default_password_entrypoint"
    )]
    pub password_entrypoint: String,

    /// Entrypoint to use when adding an email address
    #[serde(
        default = "default_email_entrypoint",
        skip_serializing_if = "is_default_email_entrypoint"
    )]
    pub email_entrypoint: String,

    /// Arbitrary data to pass to the policy engine
    #[serde(default = "default_data", skip_serializing_if = "is_default_data")]
    pub data: serde_json::Value,

    // -- Cedar-specific configuration --
    /// Path to the Cedar policy file (used when engine is `cedar`).
    ///
    /// The file should contain Cedar policy statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub cedar_policy_file: Option<Utf8PathBuf>,

    // -- Remote-specific configuration --
    /// Base URL of the remote policy service (used when engine is `remote`).
    ///
    /// The service must implement the evaluation HTTP protocol:
    /// `POST {base_url}/evaluate/{policy_type}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_endpoint: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            engine: PolicyEngine::default(),
            wasm_module: default_policy_path(),
            client_registration_entrypoint: default_client_registration_entrypoint(),
            register_entrypoint: default_register_entrypoint(),
            authorization_grant_entrypoint: default_authorization_grant_entrypoint(),
            password_entrypoint: default_password_entrypoint(),
            email_entrypoint: default_email_entrypoint(),
            data: default_data(),
            cedar_policy_file: None,
            remote_endpoint: None,
        }
    }
}

impl PolicyConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_engine(&self.engine)
            && is_default_policy_path(&self.wasm_module)
            && is_default_client_registration_entrypoint(&self.client_registration_entrypoint)
            && is_default_register_entrypoint(&self.register_entrypoint)
            && is_default_authorization_grant_entrypoint(&self.authorization_grant_entrypoint)
            && is_default_password_entrypoint(&self.password_entrypoint)
            && is_default_email_entrypoint(&self.email_entrypoint)
            && is_default_data(&self.data)
            && self.cedar_policy_file.is_none()
            && self.remote_endpoint.is_none()
    }
}

impl ConfigurationSection for PolicyConfig {
    const PATH: Option<&'static str> = Some("policy");
}
