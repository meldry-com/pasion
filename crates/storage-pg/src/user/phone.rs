use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pasion_data_model::{
    Clock, User, UserPhone, UserPhoneAuthentication, UserPhoneAuthenticationCode,
    UserRegistration,
};
use pasion_storage::user::UserPhoneRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`UserPhoneRepository`] for a PostgreSQL connection
pub struct PgUserPhoneRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserPhoneRepository<'c> {
    /// Create a new [`PgUserPhoneRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct UserPhoneLookup {
    user_phone_id: Uuid,
    user_id: Uuid,
    phone: String,
    created_at: DateTime<Utc>,
}

impl From<UserPhoneLookup> for UserPhone {
    fn from(e: UserPhoneLookup) -> UserPhone {
        UserPhone {
            id: e.user_phone_id.into(),
            user_id: e.user_id.into(),
            phone: e.phone,
            created_at: e.created_at,
        }
    }
}

struct UserPhoneAuthenticationLookup {
    user_phone_authentication_id: Uuid,
    user_registration_id: Option<Uuid>,
    phone: String,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<UserPhoneAuthenticationLookup> for UserPhoneAuthentication {
    fn from(value: UserPhoneAuthenticationLookup) -> Self {
        UserPhoneAuthentication {
            id: value.user_phone_authentication_id.into(),
            user_registration_id: value.user_registration_id.map(Ulid::from),
            phone: value.phone,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

struct UserPhoneAuthenticationCodeLookup {
    user_phone_authentication_code_id: Uuid,
    user_phone_authentication_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<UserPhoneAuthenticationCodeLookup> for UserPhoneAuthenticationCode {
    fn from(value: UserPhoneAuthenticationCodeLookup) -> Self {
        UserPhoneAuthenticationCode {
            id: value.user_phone_authentication_code_id.into(),
            user_phone_authentication_id: value.user_phone_authentication_id.into(),
            code: value.code,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[async_trait]
impl UserPhoneRepository for PgUserPhoneRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_phone.lookup",
        skip_all,
        fields(
            db.query.text,
            user_phone.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error> {
        let res = sqlx::query_as!(
            UserPhoneLookup,
            r#"
                SELECT user_phone_id
                     , user_id
                     , phone
                     , created_at
                FROM user_phones
                WHERE user_phone_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_phone) = res else {
            return Ok(None);
        };

        Ok(Some(user_phone.into()))
    }

    #[tracing::instrument(
        name = "db.user_phone.find_by_phone",
        skip_all,
        fields(
            db.query.text,
            user_phone.phone = phone,
        ),
        err,
    )]
    async fn find_by_phone(&mut self, phone: &str) -> Result<Option<UserPhone>, Self::Error> {
        let res = sqlx::query_as!(
            UserPhoneLookup,
            r#"
                SELECT user_phone_id
                     , user_id
                     , phone
                     , created_at
                FROM user_phones
                WHERE phone = $1
            "#,
            phone,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        if res.len() != 1 {
            return Ok(None);
        }

        let Some(user_phone) = res.into_iter().next() else {
            return Ok(None);
        };

        Ok(Some(user_phone.into()))
    }

    #[tracing::instrument(
        name = "db.user_phone.all",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error> {
        let res = sqlx::query_as!(
            UserPhoneLookup,
            r#"
                SELECT user_phone_id
                     , user_id
                     , phone
                     , created_at
                FROM user_phones
                WHERE user_id = $1
                ORDER BY phone ASC
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(
        name = "db.user_phone.add",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_phone.id,
            user_phone.phone = phone,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone: String,
    ) -> Result<UserPhone, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_phone.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_phones (user_phone_id, user_id, phone, created_at)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            &phone,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPhone {
            id,
            user_id: user.id,
            phone,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.remove",
        skip_all,
        fields(
            db.query.text,
            user.id = %user_phone.user_id,
            %user_phone.id,
            %user_phone.phone,
        ),
        err,
    )]
    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error> {
        let res = sqlx::query!(
            r#"
                DELETE FROM user_phones
                WHERE user_phone_id = $1
            "#,
            Uuid::from(user_phone.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.user_phone.add_authentication_for_registration",
        skip_all,
        fields(
            db.query.text,
            %user_registration.id,
            user_phone_authentication.id,
            user_phone_authentication.phone = phone,
        ),
        err,
    )]
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        phone: String,
        user_registration: &UserRegistration,
    ) -> Result<UserPhoneAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current()
            .record("user_phone_authentication.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_phone_authentications
                  ( user_phone_authentication_id
                  , user_registration_id
                  , phone
                  , created_at
                  )
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user_registration.id),
            &phone,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPhoneAuthentication {
            id,
            user_registration_id: Some(user_registration.id),
            phone,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.add_authentication_code",
        skip_all,
        fields(
            db.query.text,
            %user_phone_authentication.id,
            %user_phone_authentication.phone,
            user_phone_authentication_code.id,
            user_phone_authentication_code.code = code,
        ),
        err,
    )]
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        user_phone_authentication: &UserPhoneAuthentication,
        code: String,
    ) -> Result<UserPhoneAuthenticationCode, Self::Error> {
        let created_at = clock.now();
        let expires_at = created_at + duration;
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "user_phone_authentication_code.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO user_phone_authentication_codes
                  ( user_phone_authentication_code_id
                  , user_phone_authentication_id
                  , code
                  , created_at
                  , expires_at
                  )
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user_phone_authentication.id),
            &code,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPhoneAuthenticationCode {
            id,
            user_phone_authentication_id: user_phone_authentication.id,
            code,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.lookup_authentication",
        skip_all,
        fields(
            db.query.text,
            user_phone_authentication.id = %id,
        ),
        err,
    )]
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPhoneAuthentication>, Self::Error> {
        let res = sqlx::query_as!(
            UserPhoneAuthenticationLookup,
            r#"
                SELECT user_phone_authentication_id
                     , user_registration_id
                     , phone
                     , created_at
                     , completed_at
                FROM user_phone_authentications
                WHERE user_phone_authentication_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPhoneAuthentication::from))
    }

    #[tracing::instrument(
        name = "db.user_phone.find_authentication_by_code",
        skip_all,
        fields(
            db.query.text,
            %authentication.id,
            user_phone_authentication_code.code = code,
        ),
        err,
    )]
    async fn find_authentication_code(
        &mut self,
        authentication: &UserPhoneAuthentication,
        code: &str,
    ) -> Result<Option<UserPhoneAuthenticationCode>, Self::Error> {
        let res = sqlx::query_as!(
            UserPhoneAuthenticationCodeLookup,
            r#"
                SELECT user_phone_authentication_code_id
                     , user_phone_authentication_id
                     , code
                     , created_at
                     , expires_at
                FROM user_phone_authentication_codes
                WHERE user_phone_authentication_id = $1
                  AND code = $2
            "#,
            Uuid::from(authentication.id),
            code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPhoneAuthenticationCode::from))
    }

    #[tracing::instrument(
        name = "db.user_phone.complete_phone_authentication_with_code",
        skip_all,
        fields(
            db.query.text,
            %user_phone_authentication.id,
            %user_phone_authentication.phone,
            %user_phone_authentication_code.id,
            %user_phone_authentication_code.code,
        ),
        err,
    )]
    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        mut user_phone_authentication: UserPhoneAuthentication,
        user_phone_authentication_code: &UserPhoneAuthenticationCode,
    ) -> Result<UserPhoneAuthentication, Self::Error> {
        // We technically don't use the authentication code here (other than
        // recording it in the span), but this is to make sure the caller has
        // fetched one before calling this
        let completed_at = clock.now();

        // We'll assume the caller has checked that completed_at is None, so in case
        // they haven't, the update will not affect any rows, which will raise
        // an error
        let res = sqlx::query!(
            r#"
                UPDATE user_phone_authentications
                SET completed_at = $2
                WHERE user_phone_authentication_id = $1
                  AND completed_at IS NULL
            "#,
            Uuid::from(user_phone_authentication.id),
            completed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_phone_authentication.completed_at = Some(completed_at);
        Ok(user_phone_authentication)
    }
}
