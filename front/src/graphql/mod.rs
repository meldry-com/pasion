pub mod types;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::graphql_url;

/// GraphQL request body.
#[derive(Serialize)]
struct GraphqlRequestBody {
    query: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    variables: Option<Value>,
}

/// GraphQL response.
#[derive(Deserialize)]
struct GraphqlResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphqlError>>,
}

/// A single GraphQL error.
#[derive(Debug, Deserialize)]
pub struct GraphqlError {
    pub message: String,
}

/// Execute a GraphQL query/mutation.
pub async fn graphql_request<T: for<'de> Deserialize<'de>>(
    query: &'static str,
    variables: Option<Value>,
) -> Result<T, String> {
    let url = graphql_url();
    let client = Client::new();

    let body = GraphqlRequestBody { query, variables };

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("GraphQL request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "GraphQL request failed with status: {}",
            response.status()
        ));
    }

    let result: GraphqlResponse<T> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse GraphQL response: {e}"))?;

    if let Some(errors) = result.errors {
        let msgs: Vec<String> = errors.into_iter().map(|e| e.message).collect();
        return Err(msgs.join(", "));
    }

    result.data.ok_or_else(|| "No data in response".to_string())
}

/// Execute a GraphQL mutation with variables.
pub async fn graphql_mutation<T: for<'de> Deserialize<'de>>(
    query: &'static str,
    variables: Value,
) -> Result<T, String> {
    graphql_request(query, Some(variables)).await
}
