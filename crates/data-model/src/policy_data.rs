use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyData {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub data: serde_json::Value,
}
