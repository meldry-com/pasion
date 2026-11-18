//! Named projections returned by raw SQL queue, notification and cleanup
//! queries.
#![allow(
    clippy::redundant_field_names,
    reason = "Diesel generates explicit field initializers for QueryableByName"
)]

use diesel::{
    QueryableByName,
    sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid},
};
use uuid::Uuid;

#[derive(Debug, QueryableByName)]
pub(super) struct AbandonedJobResult {
    #[diesel(sql_type = DieselUuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = Text)]
    pub(super) queue_name: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub(super) attempt: i32,
    #[diesel(sql_type = DieselUuid)]
    pub(super) started_by: Uuid,
    #[diesel(sql_type = Timestamptz)]
    pub(super) started_at: jiff_diesel::Timestamp,
    #[diesel(sql_type = Timestamptz)]
    pub(super) worker_shutdown_at: jiff_diesel::Timestamp,
}

#[derive(Debug, QueryableByName)]
pub(super) struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pub(super) count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(super) last_ts: Option<jiff_diesel::Timestamp>,
}

#[derive(Debug, QueryableByName)]
pub(super) struct ReservedDeliveryRow {
    #[diesel(sql_type = DieselUuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    pub(super) notification_request_id: Uuid,
    #[diesel(sql_type = Text)]
    pub(super) channel: String,
    #[diesel(sql_type = Jsonb)]
    pub(super) destination: serde_json::Value,
    #[diesel(sql_type = Nullable<Text>)]
    pub(super) provider_binding_key: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(super) provider_message_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(super) attempt_count: i32,
    #[diesel(sql_type = Text)]
    pub(super) status: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    pub(super) last_failure: Option<serde_json::Value>,
    #[diesel(sql_type = Timestamptz)]
    pub(super) created_at: jiff_diesel::Timestamp,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) reserved_at: Option<jiff_diesel::Timestamp>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) sent_at: Option<jiff_diesel::Timestamp>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) delivered_at: Option<jiff_diesel::Timestamp>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) failed_at: Option<jiff_diesel::Timestamp>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) next_retry_at: Option<jiff_diesel::Timestamp>,
}

#[derive(Debug, QueryableByName)]
pub(super) struct ScheduleLookup {
    #[diesel(sql_type = Text)]
    pub(super) schedule_name: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) last_scheduled_at: Option<jiff_diesel::Timestamp>,
    #[diesel(sql_type = Nullable<Bool>)]
    pub(super) last_scheduled_job_completed: Option<bool>,
}

#[derive(Debug, QueryableByName)]
pub(super) struct ShutdownWorkerRow {
    #[diesel(sql_type = DieselUuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    pub(super) last_seen_at: jiff_diesel::Timestamp,
    #[diesel(sql_type = Timestamptz)]
    pub(super) shutdown_at: jiff_diesel::Timestamp,
}

#[derive(Debug, QueryableByName)]
pub(super) struct WorkerStateRow {
    #[diesel(sql_type = DieselUuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    pub(super) registered_at: jiff_diesel::Timestamp,
    #[diesel(sql_type = Timestamptz)]
    pub(super) last_seen_at: jiff_diesel::Timestamp,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub(super) shutdown_at: Option<jiff_diesel::Timestamp>,
}
