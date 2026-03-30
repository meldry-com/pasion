//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use pasion_data_model::{Clock, User, new_id};
use pasion_storage::user::{UserFilter, UserRepository, UserState};
use pasion_storage::{Pagination, pagination::PaginationDirection};
use rand::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, schema::users};

mod email;
mod password;
mod phone;
mod recovery;
mod registration;
mod registration_token;
mod session;
mod terms;

#[cfg(test)]
mod tests;

pub use self::{
    email::PgUserEmailRepository, password::PgUserPasswordRepository, phone::PgUserPhoneRepository,
    recovery::PgUserRecoveryRepository, registration::PgUserRegistrationRepository,
    registration_token::PgUserRegistrationTokenRepository, session::PgBrowserSessionRepository,
    terms::PgUserTermsRepository,
};

/// An implementation of [`UserRepository`] for a PostgreSQL connection
pub struct PgUserRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserRepository<'c> {
    /// Create a new [`PgUserRepository`] from an active PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading users from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = users)]
struct UserRow {
    id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
    locked_at: Option<DateTime<Utc>>,
    deactivated_at: Option<DateTime<Utc>>,
    can_request_admin: bool,
    is_guest: bool,
}

impl pasion_storage::pagination::Node<Ulid> for UserRow {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        let id: Ulid = row.id.into();
        Self {
            id,
            username: row.username,
            sub: id.to_string(),
            created_at: row.created_at,
            locked_at: row.locked_at,
            deactivated_at: row.deactivated_at,
            can_request_admin: row.can_request_admin,
            is_guest: row.is_guest,
        }
    }
}

/// Insertable row for creating a new user
#[derive(Insertable)]
#[diesel(table_name = users)]
struct NewUser {
    id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserRepository for PgUserRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user.lookup",
        skip_all,
        fields(user.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error> {
        let res = users::table
            .find(Uuid::from(id))
            .select(UserRow::as_select())
            .first::<UserRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(User::from))
    }

    #[tracing::instrument(
        name = "db.user.find_by_username",
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error> {
        use crate::lower;

        let res: Vec<UserRow> = users::table
            .filter(lower(users::username).eq(username.to_lowercase()))
            .select(UserRow::as_select())
            .load(self.conn)
            .await?;

        match &res[..] {
            [user] => Ok(Some(user.clone().into())),
            [] => Ok(None),
            list => {
                if let Some(user) = list.iter().find(|u| u.username == username) {
                    Ok(Some(user.clone().into()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[tracing::instrument(
        name = "db.user.add",
        skip_all,
        fields(user.username = username, user.id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user.id", tracing::field::display(id));

        let new_user = NewUser {
            id: Uuid::from(id),
            username: username.clone(),
            created_at,
        };

        let rows_affected = diesel::insert_into(users::table)
            .values(&new_user)
            .on_conflict(users::username)
            .do_nothing()
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(User {
            id,
            username,
            sub: id.to_string(),
            created_at,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
        })
    }

    #[tracing::instrument(
        name = "db.user.exists",
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error> {
        use crate::lower;
        use diesel::dsl::{exists, select};

        let result = select(exists(
            users::table.filter(lower(users::username).eq(username.to_lowercase())),
        ))
        .get_result::<bool>(self.conn)
        .await?;

        Ok(result)
    }

    #[tracing::instrument(
        name = "db.user.lock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn lock(&mut self, clock: &dyn Clock, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_some() {
            return Ok(user);
        }

        let locked_at = clock.now();
        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set(users::locked_at.eq(Some(locked_at)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        user.locked_at = Some(locked_at);
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_none() {
            return Ok(user);
        }

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set(users::locked_at.eq(None::<DateTime<Utc>>))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        user.locked_at = None;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.deactivate",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn deactivate(&mut self, clock: &dyn Clock, mut user: User) -> Result<User, Self::Error> {
        if user.deactivated_at.is_some() {
            return Ok(user);
        }

        let deactivated_at = clock.now();
        let rows_affected = diesel::update(
            users::table
                .find(Uuid::from(user.id))
                .filter(users::deactivated_at.is_null()),
        )
        .set(users::deactivated_at.eq(Some(deactivated_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        user.deactivated_at = Some(deactivated_at);
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.reactivate",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn reactivate(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.deactivated_at.is_none() {
            return Ok(user);
        }

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set(users::deactivated_at.eq(None::<DateTime<Utc>>))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        user.deactivated_at = None;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.set_can_request_admin",
        skip_all,
        fields(%user.id, user.can_request_admin = can_request_admin),
        err,
    )]
    async fn set_can_request_admin(
        &mut self,
        mut user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error> {
        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set(users::can_request_admin.eq(can_request_admin))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        user.can_request_admin = can_request_admin;
        Ok(user)
    }

    #[tracing::instrument(name = "db.user.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<pasion_storage::Page<User>, Self::Error> {
        let mut query = users::table.select(UserRow::as_select()).into_boxed();

        // Apply filters
        if let Some(state) = filter.state() {
            match state {
                UserState::Deactivated => {
                    query = query.filter(users::deactivated_at.is_not_null());
                }
                UserState::Locked => {
                    query = query.filter(users::locked_at.is_not_null());
                }
                UserState::Active => {
                    query = query
                        .filter(users::locked_at.is_null())
                        .filter(users::deactivated_at.is_null());
                }
            }
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(is_guest) = filter.is_guest() {
            query = query.filter(users::is_guest.eq(is_guest));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::username.ilike(pattern));
        }

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(users::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(users::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(users::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(users::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let rows: Vec<UserRow> = query.load(self.conn).await?;
        let page = pagination.process(rows).map(User::from);
        Ok(page)
    }

    #[tracing::instrument(name = "db.user.count", skip_all, err)]
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error> {
        let mut query = users::table.into_boxed();

        if let Some(state) = filter.state() {
            match state {
                UserState::Deactivated => {
                    query = query.filter(users::deactivated_at.is_not_null());
                }
                UserState::Locked => {
                    query = query.filter(users::locked_at.is_not_null());
                }
                UserState::Active => {
                    query = query
                        .filter(users::locked_at.is_null())
                        .filter(users::deactivated_at.is_null());
                }
            }
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(is_guest) = filter.is_guest() {
            query = query.filter(users::is_guest.eq(is_guest));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::username.ilike(pattern));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.user.acquire_lock_for_sync",
        skip_all,
        fields(user.id = %user.id),
        err,
    )]
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error> {
        let lock_id = (u128::from(user.id) & 0xffff_ffff_ffff_ffff) as i64;

        diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
            .bind::<diesel::sql_types::BigInt, _>(lock_id)
            .execute(self.conn)
            .await?;

        Ok(())
    }
}
