//! Remote HTTP policy provider.
//!
//! This module implements policy evaluation by delegating to an external HTTP
//! service. This is the most flexible approach: the remote service can be
//! implemented in any language (Python, Go, Node.js, etc.) and can use any
//! decision logic, including AI models.
//!
//! ## Protocol
//!
//! The remote service must expose the following HTTP endpoints:
//!
//! - `POST {base_url}/evaluate/email` - Email policy evaluation
//! - `POST {base_url}/evaluate/register` - Registration policy evaluation
//! - `POST {base_url}/evaluate/client_registration` - Client registration
//!   evaluation
//! - `POST {base_url}/evaluate/authorization_grant` - Authorization grant
//!   evaluation
//! - `POST {base_url}/data` - Dynamic data update (optional)
//!
//! ### Request Format
//!
//! Each evaluation endpoint receives a JSON body containing the evaluation
//! input (same structure as the Rust input types, serialized via serde).
//!
//! ### Response Format
//!
//! Each evaluation endpoint must return a JSON response:
//!
//! ```json
//! {
//!     "violations": [
//!         {
//!             "msg": "Username too short",
//!             "field": "username",
//!             "code": "username-too-short",
//!             "redirect_uri": null
//!         }
//!     ]
//! }
//! ```
//!
//! An empty `violations` array means the request is allowed.

use async_trait::async_trait;
use pasion_data::PolicyData;
use serde::Deserialize;

use crate::{
    EvaluationError, InstantiateError, LoadError,
    model::{
        AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult,
        RegisterInput, Violation,
    },
    provider::{PolicyEvaluator, PolicyProviderFactory},
};

/// Remote HTTP policy provider factory.
///
/// Delegates all policy evaluation to an external HTTP service.
pub struct RemoteProviderFactory {
    client: reqwest::Client,
    base_url: String,
}

impl RemoteProviderFactory {
    /// Create a new remote provider factory.
    ///
    /// - `base_url`: The base URL of the remote policy service (e.g., `http://localhost:8181`)
    /// - `client`: A shared `reqwest::Client` for making HTTP requests
    #[must_use]
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { client, base_url }
    }
}

#[async_trait]
impl PolicyProviderFactory for RemoteProviderFactory {
    async fn instantiate(&self) -> Result<Box<dyn PolicyEvaluator>, InstantiateError> {
        Ok(Box::new(RemoteEvaluator {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
        }))
    }

    fn supports_dynamic_data(&self) -> bool {
        true
    }

    async fn set_dynamic_data(&self, data: PolicyData) -> Result<bool, LoadError> {
        let response = self
            .client
            .post(format!("{}/data", self.base_url))
            .json(&data.data)
            .send()
            .await
            .map_err(|e| {
                LoadError::InvalidData(anyhow::anyhow!("Remote data update failed: {e}"))
            })?;

        if response.status().is_success() {
            Ok(true)
        } else {
            Err(LoadError::InvalidData(anyhow::anyhow!(
                "Remote data update failed with status: {}",
                response.status()
            )))
        }
    }
}

/// The response format expected from the remote policy service.
#[derive(Deserialize)]
struct RemoteResponse {
    violations: Vec<Violation>,
}

/// Remote HTTP policy evaluator instance.
///
/// Sends evaluation requests to the configured remote HTTP service and
/// parses the response into an [`EvaluationResult`].
pub struct RemoteEvaluator {
    client: reqwest::Client,
    base_url: String,
}

impl RemoteEvaluator {
    /// Send an evaluation request to the remote service.
    async fn evaluate_remote(
        &self,
        path: &str,
        input: &(impl serde::Serialize + Sync),
    ) -> Result<EvaluationResult, EvaluationError> {
        let url = format!("{}/evaluate/{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .json(input)
            .send()
            .await
            .map_err(|e| {
                EvaluationError::Evaluation(anyhow::anyhow!(
                    "Remote policy request to {url} failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(EvaluationError::Evaluation(anyhow::anyhow!(
                "Remote policy service returned status {} for {url}",
                response.status()
            )));
        }

        let remote_response: RemoteResponse = response.json().await.map_err(|e| {
            EvaluationError::Evaluation(anyhow::anyhow!(
                "Failed to parse remote policy response: {e}"
            ))
        })?;

        Ok(EvaluationResult {
            violations: remote_response.violations,
        })
    }
}

#[async_trait]
impl PolicyEvaluator for RemoteEvaluator {
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("email", &input).await
    }

    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("register", &input).await
    }

    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("client_registration", &input).await
    }

    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("authorization_grant", &input).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn client_builder() -> reqwest::ClientBuilder {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        reqwest::Client::builder().no_proxy()
    }

    async fn server(
        status: u16,
        body: &'static str,
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let count = socket.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let body_length: usize = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .unwrap()
                        .1
                        .trim()
                        .parse()
                        .unwrap();
                    if request.len() >= end + 4 + body_length {
                        break;
                    }
                }
            }
            assert!(request.starts_with(b"POST /evaluate/register HTTP/1.1\r\n"));
            tokio::time::sleep(delay).await;
            let response = format!(
                "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            // A timeout test intentionally closes the client first.
            let _ = socket.write_all(response.as_bytes()).await;
        });
        (format!("http://{address}"), task)
    }

    async fn evaluate(
        status: u16,
        body: &'static str,
    ) -> Result<EvaluationResult, EvaluationError> {
        let (base_url, task) = server(status, body, Duration::ZERO).await;
        let evaluator = RemoteEvaluator {
            client: client_builder().build().unwrap(),
            base_url,
        };
        let result = evaluator
            .evaluate_remote("register", &serde_json::json!({}))
            .await;
        task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn allows_empty_violations_and_preserves_denials() {
        assert!(
            evaluate(200, r#"{"violations":[]}"#)
                .await
                .unwrap()
                .violations
                .is_empty()
        );
        let denied = evaluate(200, r#"{"violations":[{"msg":"denied","field":"username","code":"username-banned","redirect_uri":null}]}"#).await.unwrap();
        assert_eq!(denied.violations.len(), 1);
        assert_eq!(denied.violations[0].msg, "denied");
    }

    #[tokio::test]
    async fn rejects_http_errors_and_invalid_responses() {
        assert!(evaluate(503, r#"{"violations":[]}"#).await.is_err());
        assert!(evaluate(200, "invalid JSON").await.is_err());
        assert!(evaluate(200, "{}").await.is_err());
    }

    #[tokio::test]
    async fn timeout_is_an_error_instead_of_an_allow_decision() {
        let (base_url, task) = server(200, r#"{"violations":[]}"#, Duration::from_secs(1)).await;
        let evaluator = RemoteEvaluator {
            client: client_builder()
                .timeout(Duration::from_millis(50))
                .build()
                .unwrap(),
            base_url,
        };
        assert!(
            evaluator
                .evaluate_remote("register", &serde_json::json!({}))
                .await
                .is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn unavailable_service_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let evaluator = RemoteEvaluator {
            client: client_builder().build().unwrap(),
            base_url,
        };
        assert!(
            evaluator
                .evaluate_remote("register", &serde_json::json!({}))
                .await
                .is_err()
        );
    }
}
