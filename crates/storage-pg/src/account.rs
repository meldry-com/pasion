//! PostgreSQL implementation of [`AccountRepository`].

use async_trait::async_trait;
use pasion_data_model::{AccountContactPoint, AccountIdentityBinding};
use pasion_storage::account::{AccountRepository, AccountSecuritySummary};
use ulid::Ulid;

use crate::DatabaseError;

/// PostgreSQL-backed [`AccountRepository`].
pub struct PgAccountRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAccountRepository<'c> {
    /// Create a new [`PgAccountRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl AccountRepository for PgAccountRepository<'_> {
    type Error = DatabaseError;

    async fn list_contact_points(
        &mut self,
        _user_id: Ulid,
    ) -> Result<Vec<AccountContactPoint>, Self::Error> {
        todo!("PgAccountRepository::list_contact_points")
    }

    async fn list_identity_bindings(
        &mut self,
        _user_id: Ulid,
    ) -> Result<Vec<AccountIdentityBinding>, Self::Error> {
        todo!("PgAccountRepository::list_identity_bindings")
    }

    async fn security_summary(
        &mut self,
        _user_id: Ulid,
    ) -> Result<AccountSecuritySummary, Self::Error> {
        todo!("PgAccountRepository::security_summary")
    }
}
