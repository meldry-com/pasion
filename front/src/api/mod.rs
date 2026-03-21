pub mod types;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::api_base_url;

/// Execute a GET request to the REST API.
pub async fn api_get<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = Client::new();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("API request failed with status: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a POST request to the REST API.
pub async fn api_post<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: Value,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = Client::new();

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("API request failed with status: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a PUT request to the REST API.
pub async fn api_put<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: Value,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = Client::new();

    let response = client
        .put(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("API request failed with status: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a DELETE request to the REST API.
pub async fn api_delete<T: for<'de> Deserialize<'de>>(
    path: &str,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = Client::new();

    let response = client
        .delete(&url)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("API request failed with status: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a DELETE request with a JSON body.
pub async fn api_delete_with_body<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: Value,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = Client::new();

    let response = client
        .delete(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("API request failed with status: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}
