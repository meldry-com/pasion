pub mod types;

use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::Value;

use crate::config::api_base_url;

thread_local! {
    /// Shared HTTP client. `reqwest::Client` holds a connection pool, so we
    /// reuse a single instance per thread (WASM is single-threaded) instead of
    /// constructing a new one for every request.
    static CLIENT: Client = Client::new();
}

fn client() -> Client {
    CLIENT.with(|c| c.clone())
}

/// Shared request implementation for all REST verbs.
///
/// `body` is sent as a JSON payload (with the appropriate `Content-Type`)
/// when present; otherwise the request is sent without a body.
async fn request<T: for<'de> Deserialize<'de>>(
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let mut builder = client().request(method, &url);

    if let Some(body) = body {
        builder = builder
            .header("Content-Type", "application/json")
            .json(&body);
    }

    let response = builder
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Try to extract an error message from a non-2xx response body.
async fn extract_error(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<Value>().await {
        Ok(body) => {
            if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
                err.to_owned()
            } else {
                format!("Request failed ({status})")
            }
        }
        Err(_) => format!("Request failed ({status})"),
    }
}

/// Execute a GET request to the REST API.
pub async fn api_get<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    request(Method::GET, path, None).await
}

/// Execute a POST request to the REST API.
pub async fn api_post<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    request(Method::POST, path, Some(body)).await
}

/// Execute a PUT request to the REST API.
pub async fn api_put<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    request(Method::PUT, path, Some(body)).await
}

/// Execute a PATCH request to the REST API.
pub async fn api_patch<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    request(Method::PATCH, path, Some(body)).await
}

/// Execute a DELETE request to the REST API.
pub async fn api_delete<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    request(Method::DELETE, path, None).await
}

/// Execute a DELETE request with a JSON body.
pub async fn api_delete_with_body<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: Value,
) -> Result<T, String> {
    request(Method::DELETE, path, Some(body)).await
}
