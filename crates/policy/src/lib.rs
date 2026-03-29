//! Policy evaluation abstraction layer.
//!
//! This crate provides a unified interface for policy evaluation that supports
//! multiple backends:
//!
//! - **OPA/WASM** (default): Compiled Open Policy Agent Rego policies running
//!   as WebAssembly modules. This is the original and most mature backend.
//! - **Cedar** (feature `cedar`): Amazon Cedar policies evaluated natively in
//!   Rust, offering a simpler policy language with high performance.
//! - **Remote HTTP** (feature `remote`): Delegates policy evaluation to an
//!   external HTTP service, enabling any language or runtime for policy logic.
//!
//! ## Architecture
//!
//! The abstraction is based on two core traits defined in [`provider`]:
//!
//! - [`PolicyProviderFactory`](provider::PolicyProviderFactory): Creates
//!   evaluator instances and manages dynamic data.
//! - [`PolicyEvaluator`](provider::PolicyEvaluator): Evaluates individual
//!   policy checks (registration, email, authorization, etc.).
//!
//! [`PolicyFactory`] and [`Policy`] are the public-facing types that wrap
//! these traits, preserving backward compatibility with existing handler code.

pub mod audit;
pub mod model;
pub mod opa;
pub mod provider;

#[cfg(feature = "cedar")]
pub mod cedar;
#[cfg(feature = "remote")]
pub mod remote;

use pasion_data_model::SessionLimitConfig;
use serde::Serialize;
use thiserror::Error;
use tokio::io::AsyncRead;

pub use self::model::{
    AuthorizationGrantInput, ClientRegistrationInput, Code as ViolationCode, EmailInput,
    EvaluationResult, GrantType, RegisterInput, RegistrationMethod, Requester, Violation,
};
pub use self::provider::{PolicyEvaluator, PolicyProviderFactory};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read module")]
    Read(#[from] tokio::io::Error),

    #[error("failed to create policy engine")]
    Engine(#[source] anyhow::Error),

    #[error("module compilation task crashed")]
    CompilationTask(#[from] tokio::task::JoinError),

    #[error("failed to compile policy module")]
    Compilation(#[source] anyhow::Error),

    #[error("invalid policy data")]
    InvalidData(#[source] anyhow::Error),

    #[error("failed to instantiate a test instance")]
    Instantiate(#[source] InstantiateError),
}

impl LoadError {
    /// Creates an example of an invalid data error, used for API response
    /// documentation
    #[doc(hidden)]
    #[must_use]
    pub fn invalid_data_example() -> Self {
        Self::InvalidData(anyhow::Error::msg("Failed to merge policy data objects"))
    }
}

#[derive(Debug, Error)]
pub enum InstantiateError {
    #[error("failed to create policy runtime")]
    Runtime(#[source] anyhow::Error),

    #[error("missing entrypoint {entrypoint}")]
    MissingEntrypoint { entrypoint: String },

    #[error("failed to load policy data")]
    LoadData(#[source] anyhow::Error),
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] anyhow::Error),
}

// ---------------------------------------------------------------------------
// OPA-specific types (kept at crate root for backward compatibility)
// ---------------------------------------------------------------------------

/// Holds the entrypoint name for each policy (OPA-specific).
#[derive(Debug, Clone)]
pub struct Entrypoints {
    pub register: String,
    pub client_registration: String,
    pub authorization_grant: String,
    pub email: String,
}

impl Entrypoints {
    pub(crate) fn all(&self) -> [&str; 4] {
        [
            self.register.as_str(),
            self.client_registration.as_str(),
            self.authorization_grant.as_str(),
            self.email.as_str(),
        ]
    }
}

// ---------------------------------------------------------------------------
// Shared data types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Data {
    base: BaseData,
    rest: Option<serde_json::Value>,
}

#[derive(Serialize, Debug)]
struct BaseData {
    server_name: String,
    session_limit: Option<SessionLimitConfig>,
}

impl Data {
    #[must_use]
    pub fn new(server_name: String, session_limit: Option<SessionLimitConfig>) -> Self {
        Self {
            base: BaseData {
                server_name,
                session_limit,
            },
            rest: None,
        }
    }

    #[must_use]
    pub fn with_rest(mut self, rest: serde_json::Value) -> Self {
        self.rest = Some(rest);
        self
    }

    pub(crate) fn to_value(&self) -> Result<serde_json::Value, anyhow::Error> {
        let base = serde_json::to_value(&self.base)?;

        if let Some(rest) = &self.rest {
            merge_data(base, rest.clone())
        } else {
            Ok(base)
        }
    }
}

// ---------------------------------------------------------------------------
// Data merge utilities
// ---------------------------------------------------------------------------

fn value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Object(_) => "object",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Null => "null",
    }
}

pub(crate) fn merge_data(
    mut left: serde_json::Value,
    right: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    merge_data_rec(&mut left, right)?;
    Ok(left)
}

fn merge_data_rec(
    left: &mut serde_json::Value,
    right: serde_json::Value,
) -> Result<(), anyhow::Error> {
    match (left, right) {
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            for (key, value) in right {
                if let Some(left_value) = left.get_mut(&key) {
                    merge_data_rec(left_value, value)?;
                } else {
                    left.insert(key, value);
                }
            }
        }
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            left.extend(right);
        }
        // Other values override
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => {
            *left = right;
        }
        (serde_json::Value::Bool(left), serde_json::Value::Bool(right)) => {
            *left = right;
        }
        (serde_json::Value::String(left), serde_json::Value::String(right)) => {
            *left = right;
        }

        // Null gets overridden by anything
        (left, right) if left.is_null() => *left = right,

        // Null on the right makes the left value null
        (left, right) if right.is_null() => *left = right,

        (left, right) => anyhow::bail!(
            "Cannot merge a {} into a {}",
            value_kind(&right),
            value_kind(left),
        ),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PolicyFactory - the main public-facing factory
// ---------------------------------------------------------------------------

/// Factory for creating [`Policy`] instances.
///
/// Wraps a [`PolicyProviderFactory`] implementation, allowing different
/// backends to be used transparently. The backend is selected at construction
/// time via one of the `load_*` methods.
pub struct PolicyFactory {
    inner: Box<dyn PolicyProviderFactory>,
}

impl PolicyFactory {
    /// Load an OPA WASM policy from the given async reader.
    ///
    /// This is the default constructor, kept for backward compatibility.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy can't be loaded or instantiated.
    #[tracing::instrument(name = "policy.load", skip(source))]
    pub async fn load(
        source: impl AsyncRead + std::marker::Unpin,
        data: Data,
        entrypoints: Entrypoints,
    ) -> Result<Self, LoadError> {
        Self::load_opa(source, data, entrypoints).await
    }

    /// Load an OPA WASM policy from the given async reader.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy can't be loaded or instantiated.
    pub async fn load_opa(
        source: impl AsyncRead + std::marker::Unpin,
        data: Data,
        entrypoints: Entrypoints,
    ) -> Result<Self, LoadError> {
        let factory = opa::OpaProviderFactory::load(source, data, entrypoints).await?;
        Ok(Self {
            inner: Box::new(factory),
        })
    }

    /// Load Cedar policies from a source string.
    ///
    /// Requires the `cedar` feature to be enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if Cedar is not compiled in or policies can't be
    /// parsed.
    #[cfg(feature = "cedar")]
    pub fn load_cedar(policy_src: &str) -> Result<Self, LoadError> {
        let factory = cedar::CedarProviderFactory::new(policy_src)?;
        Ok(Self {
            inner: Box::new(factory),
        })
    }

    /// Load Cedar policies from a file.
    ///
    /// Requires the `cedar` feature to be enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if Cedar is not compiled in, the file can't be read,
    /// or policies can't be parsed.
    #[cfg(feature = "cedar")]
    pub async fn load_cedar_from_file(path: &str) -> Result<Self, LoadError> {
        let factory = cedar::CedarProviderFactory::from_file(path).await?;
        Ok(Self {
            inner: Box::new(factory),
        })
    }

    /// Create a policy factory backed by a remote HTTP service.
    ///
    /// Requires the `remote` feature to be enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the Remote engine is not compiled in.
    #[cfg(feature = "remote")]
    pub fn load_remote(base_url: String, client: reqwest::Client) -> Result<Self, LoadError> {
        let factory = remote::RemoteProviderFactory::new(base_url, client);
        Ok(Self {
            inner: Box::new(factory),
        })
    }

    /// Create a policy factory from an arbitrary [`PolicyProviderFactory`]
    /// implementation.
    ///
    /// This allows users to plug in custom policy backends.
    pub fn from_provider(provider: Box<dyn PolicyProviderFactory>) -> Self {
        Self { inner: provider }
    }

    /// Set the dynamic data for the policy.
    ///
    /// Returns `true` if the data was updated, `false` if the version
    /// was already up-to-date.
    ///
    /// # Errors
    ///
    /// Returns an error if the data can't be applied or the policy can't be
    /// instantiated with the new data.
    pub async fn set_dynamic_data(
        &self,
        dynamic_data: pasion_data_model::PolicyData,
    ) -> Result<bool, LoadError> {
        self.inner.set_dynamic_data(dynamic_data).await
    }

    /// Create a new policy instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy can't be instantiated.
    #[tracing::instrument(name = "policy.instantiate", skip_all)]
    pub async fn instantiate(&self) -> Result<Policy, InstantiateError> {
        let evaluator = self.inner.instantiate().await?;
        Ok(Policy { inner: evaluator })
    }
}

// ---------------------------------------------------------------------------
// Policy - the main public-facing evaluator
// ---------------------------------------------------------------------------

/// An instantiated policy evaluator.
///
/// Created by [`PolicyFactory::instantiate`]. Wraps a [`PolicyEvaluator`]
/// trait object, delegating evaluation calls to the selected backend.
pub struct Policy {
    inner: Box<dyn PolicyEvaluator>,
}

impl Policy {
    /// Evaluate the 'email' policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate_email",
        skip_all,
        fields(
            %input.email,
        ),
    )]
    pub async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_email(input).await
    }

    /// Evaluate the 'register' policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate.register",
        skip_all,
        fields(
            ?input.registration_method,
            input.username = input.username,
            input.email = input.email,
        ),
    )]
    pub async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_register(input).await
    }

    /// Evaluate the `client_registration` policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(skip(self))]
    pub async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_client_registration(input).await
    }

    /// Evaluate the `authorization_grant` policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate.authorization_grant",
        skip_all,
        fields(
            %input.scope,
            %input.client.id,
        ),
    )]
    pub async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_authorization_grant(input).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pasion_data_model::Ulid;

    use super::*;

    fn make_entrypoints() -> Entrypoints {
        Entrypoints {
            register: "register/violation".to_owned(),
            client_registration: "client_registration/violation".to_owned(),
            authorization_grant: "authorization_grant/violation".to_owned(),
            email: "email/violation".to_owned(),
        }
    }

    #[tokio::test]
    async fn test_register() {
        let data = Data::new("example.com".to_owned(), None).with_rest(serde_json::json!({
            "allowed_domains": ["element.io", "*.element.io"],
            "banned_domains": ["staging.element.io"],
        }));

        #[allow(clippy::disallowed_types)]
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("policies")
            .join("policy.wasm");

        let file = tokio::fs::File::open(path).await.unwrap();

        let factory = PolicyFactory::load(file, data, make_entrypoints())
            .await
            .unwrap();

        let mut policy = factory.instantiate().await.unwrap();

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@foo.element.io"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(res.valid());

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@staging.element.io"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());
    }

    #[tokio::test]
    async fn test_dynamic_data() {
        let data = Data::new("example.com".to_owned(), None);

        #[allow(clippy::disallowed_types)]
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("policies")
            .join("policy.wasm");

        let file = tokio::fs::File::open(path).await.unwrap();

        let factory = PolicyFactory::load(file, data, make_entrypoints())
            .await
            .unwrap();

        let mut policy = factory.instantiate().await.unwrap();

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(res.valid());

        // Update the policy data
        factory
            .set_dynamic_data(pasion_data_model::PolicyData {
                id: Ulid::nil(),
                created_at: SystemTime::now().into(),
                data: serde_json::json!({
                    "emails": {
                        "banned_addresses": {
                            "substrings": ["hello"]
                        }
                    }
                }),
            })
            .await
            .unwrap();
        let mut policy = factory.instantiate().await.unwrap();
        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());
    }

    #[tokio::test]
    async fn test_big_dynamic_data() {
        let data = Data::new("example.com".to_owned(), None);

        #[allow(clippy::disallowed_types)]
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("policies")
            .join("policy.wasm");

        let file = tokio::fs::File::open(path).await.unwrap();

        let factory = PolicyFactory::load(file, data, make_entrypoints())
            .await
            .unwrap();

        // That is around 1 MB of JSON data. Each element is a 5-digit string, so 8
        // characters including the quotes and a comma.
        let data: Vec<String> = (0..(1024 * 1024 / 8))
            .map(|i| format!("{:05}", i % 100_000))
            .collect();
        let json = serde_json::json!({ "emails": { "banned_addresses": { "substrings": data } } });
        factory
            .set_dynamic_data(pasion_data_model::PolicyData {
                id: Ulid::nil(),
                created_at: SystemTime::now().into(),
                data: json,
            })
            .await
            .unwrap();

        // Try instantiating the policy, make sure 5-digit numbers are banned from email
        // addresses
        let mut policy = factory.instantiate().await.unwrap();
        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("12345@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                    ..Default::default()
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());
    }

    #[test]
    fn test_merge() {
        use serde_json::json as j;

        // Merging objects
        let res = merge_data(j!({"hello": "world"}), j!({"foo": "bar"})).unwrap();
        assert_eq!(res, j!({"hello": "world", "foo": "bar"}));

        // Override a value of the same type
        let res = merge_data(j!({"hello": "world"}), j!({"hello": "john"})).unwrap();
        assert_eq!(res, j!({"hello": "john"}));

        let res = merge_data(j!({"hello": true}), j!({"hello": false})).unwrap();
        assert_eq!(res, j!({"hello": false}));

        let res = merge_data(j!({"hello": 0}), j!({"hello": 42})).unwrap();
        assert_eq!(res, j!({"hello": 42}));

        // Override a value of a different type
        merge_data(j!({"hello": "world"}), j!({"hello": 123}))
            .expect_err("Can't merge different types");

        // Merge arrays
        let res = merge_data(j!({"hello": ["world"]}), j!({"hello": ["john"]})).unwrap();
        assert_eq!(res, j!({"hello": ["world", "john"]}));

        // Null overrides a value
        let res = merge_data(j!({"hello": "world"}), j!({"hello": null})).unwrap();
        assert_eq!(res, j!({"hello": null}));

        // Null gets overridden by a value
        let res = merge_data(j!({"hello": null}), j!({"hello": "world"})).unwrap();
        assert_eq!(res, j!({"hello": "world"}));

        // Objects get deeply merged
        let res = merge_data(j!({"a": {"b": {"c": "d"}}}), j!({"a": {"b": {"e": "f"}}})).unwrap();
        assert_eq!(res, j!({"a": {"b": {"c": "d", "e": "f"}}}));
    }
}
