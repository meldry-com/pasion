// Audit repository -- PostgreSQL implementation.
//
// TODO: Implement once the corresponding Diesel schema and migrations are in place.

use async_trait::async_trait;
use pasion_data_model::{Clock, audit::{AccountSecurityEvent, AdminOperationLog}};
use pasion_storage::audit::{AuditRepository, NewAccountSecurityEvent, NewAdminOperationLog};
use rand::RngCore;
use ulid::Ulid;

use crate::DatabaseError;

/// PostgreSQL implementation of [`AuditRepository`].
pub struct PgAuditRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAuditRepository<'c> {
    /// Create a new [`PgAuditRepository`] from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository<'_> {
    type Error = DatabaseError;

    async fn add_admin_operation(
        &mut self,
        _rng: &mut (dyn RngCore + Send),
        _clock: &dyn Clock,
        _params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error> {
        todo!("implement once audit tables exist")
    }

    async fn list_admin_operations(
        &mut self,
        _filter_admin_user_id: Option<Ulid>,
    ) -> Result<Vec<AdminOperationLog>, Self::Error> {
        todo!("implement once audit tables exist")
    }

    async fn add_security_event(
        &mut self,
        _rng: &mut (dyn RngCore + Send),
        _clock: &dyn Clock,
        _params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error> {
        todo!("implement once audit tables exist")
    }

    async fn list_security_events(
        &mut self,
        _user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error> {
        todo!("implement once audit tables exist")
    }
}
