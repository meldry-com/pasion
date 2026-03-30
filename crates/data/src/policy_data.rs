use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

pub use crate::pg::policy_data::PgPolicyDataRepository;
pub use crate::storage::policy_data::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyData {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub data: serde_json::Value,
}
