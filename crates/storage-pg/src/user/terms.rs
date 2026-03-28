use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use pasion_data_model::{Clock, User};
use pasion_storage::user::UserTermsRepository;
use rand::RngCore;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, schema::user_terms};

/// An implementation of [`UserTermsRepository`] for a PostgreSQL connection
pub struct PgUserTermsRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserTermsRepository<'c> {
    /// Create a new [`PgUserTermsRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Insertable row for accepting terms of service
#[derive(Insertable)]
#[diesel(table_name = user_terms)]
struct NewUserTerms {
    user_terms_id: Uuid,
    user_id: Uuid,
    terms_url: String,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserTermsRepository for PgUserTermsRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_terms.accept_terms",
        skip_all,
        fields(
            %user.id,
            user_terms.id,
            %user_terms.url = terms_url.as_str(),
        ),
        err,
    )]
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_terms.id", tracing::field::display(id));

        let new_terms = NewUserTerms {
            user_terms_id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            terms_url: terms_url.to_string(),
            created_at,
        };

        diesel::insert_into(user_terms::table)
            .values(&new_terms)
            .on_conflict((user_terms::user_id, user_terms::terms_url))
            .do_nothing()
            .execute(self.conn)
            .await?;

        Ok(())
    }
}
