//! PostgreSQL implementation of the notification template version repository.

use async_trait::async_trait;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use jiff::Timestamp;
use pasion_data::{
    Clock, new_id,
    notification::{NotificationChannel, NotificationTemplateVersion},
};
use rand_core::RngCore;
use uuid::Uuid;

use crate::{
    DatabaseError, schema::notification_template_versions,
    storage::notification_template::NotificationTemplateRepository,
};

/// PostgreSQL-backed notification template version repository.
pub struct PgNotificationTemplateRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgNotificationTemplateRepository<'c> {
    /// Create a new [`PgNotificationTemplateRepository`] from an active
    /// PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = notification_template_versions)]
struct TemplateVersionRow {
    id: Uuid,
    template_key: String,
    version: i32,
    channel: String,
    locale: String,
    subject_template: Option<String>,
    body_template: String,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
    published_at: Option<Timestamp>,
}

fn channel_from_str(s: &str) -> NotificationChannel {
    match s {
        "sms" => NotificationChannel::Sms,
        "webhook" => NotificationChannel::Webhook,
        "in_app" => NotificationChannel::InApp,
        _ => NotificationChannel::Email,
    }
}

impl From<TemplateVersionRow> for NotificationTemplateVersion {
    fn from(row: TemplateVersionRow) -> Self {
        let channel = channel_from_str(&row.channel);
        NotificationTemplateVersion {
            id: row.id.into(),
            template_key: row.template_key,
            version: row.version.cast_unsigned(),
            channel,
            locale: row.locale,
            subject_template: row.subject_template,
            body_template: row.body_template,
            created_at: row.created_at,
            published_at: row.published_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = notification_template_versions)]
struct NewTemplateVersion {
    id: Uuid,
    template_key: String,
    version: i32,
    channel: String,
    locale: String,
    subject_template: Option<String>,
    body_template: String,
    #[diesel(serialize_as = jiff_diesel::Timestamp)]
    created_at: Timestamp,
    published_at: Option<jiff_diesel::Timestamp>,
}

#[async_trait]
impl NotificationTemplateRepository for PgNotificationTemplateRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.notification_template.list", skip_all, err)]
    async fn list(
        &mut self,
        template_key: Option<&str>,
    ) -> Result<Vec<NotificationTemplateVersion>, Self::Error> {
        let mut query = notification_template_versions::table
            .select(TemplateVersionRow::as_select())
            .order(notification_template_versions::created_at.desc())
            .into_boxed();

        if let Some(key) = template_key {
            query = query.filter(notification_template_versions::template_key.eq(key));
        }

        let rows = query.load::<TemplateVersionRow>(self.conn).await?;
        Ok(rows
            .into_iter()
            .map(NotificationTemplateVersion::from)
            .collect())
    }

    #[tracing::instrument(name = "db.notification_template.get_latest", skip_all, err)]
    async fn get_latest(
        &mut self,
        template_key: &str,
        channel: &str,
        locale: &str,
    ) -> Result<Option<NotificationTemplateVersion>, Self::Error> {
        let row = notification_template_versions::table
            .select(TemplateVersionRow::as_select())
            .filter(notification_template_versions::template_key.eq(template_key))
            .filter(notification_template_versions::channel.eq(channel))
            .filter(notification_template_versions::locale.eq(locale))
            .filter(notification_template_versions::published_at.is_not_null())
            .order(notification_template_versions::version.desc())
            .first::<TemplateVersionRow>(self.conn)
            .await
            .optional()?;
        Ok(row.map(NotificationTemplateVersion::from))
    }

    #[tracing::instrument(name = "db.notification_template.publish", skip_all, err)]
    async fn publish(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        template_key: String,
        channel: String,
        locale: String,
        subject_template: Option<String>,
        body_template: String,
    ) -> Result<NotificationTemplateVersion, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);

        // Publishing runs inside the repository transaction. Serialize the
        // read/increment/insert, including concurrent publications of different
        // locales: the existing unique version sequence is per key+channel.
        diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<diesel::sql_types::Text, _>(format!(
                "pasion.notification_template:{template_key}:{channel}"
            ))
            .execute(self.conn)
            .await?;

        // Get the next version number for this key+channel.
        let max_version: Option<i32> = notification_template_versions::table
            .select(diesel::dsl::max(notification_template_versions::version))
            .filter(notification_template_versions::template_key.eq(&template_key))
            .filter(notification_template_versions::channel.eq(&channel))
            .first(self.conn)
            .await?;
        let next_version = max_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(DatabaseError::invalid_operation)?;

        let new_row = NewTemplateVersion {
            id: Uuid::from(id),
            template_key: template_key.clone(),
            version: next_version,
            channel: channel.clone(),
            locale: locale.clone(),
            subject_template: subject_template.clone(),
            body_template: body_template.clone(),
            created_at: now,
            published_at: Some(now.into()),
        };

        diesel::insert_into(notification_template_versions::table)
            .values(new_row)
            .execute(self.conn)
            .await?;

        let ch = channel_from_str(&channel);

        Ok(NotificationTemplateVersion {
            id,
            template_key,
            version: next_version.cast_unsigned(),
            channel: ch,
            locale,
            subject_template,
            body_template,
            created_at: now,
            published_at: Some(now),
        })
    }
}

#[cfg(test)]
mod tests {
    use pasion_data::{PgRepositoryFactory, RepositoryAccess, RepositoryFactory, clock::MockClock};
    use rand_core::SeedableRng as _;

    use super::*;

    async fn publish(
        factory: &PgRepositoryFactory,
        locale: &str,
        channel: &str,
    ) -> NotificationTemplateVersion {
        let mut repo = factory.create().await.unwrap();
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let version = repo
            .notification_template()
            .publish(
                &mut rng,
                &MockClock::default(),
                "verification".to_owned(),
                channel.to_owned(),
                locale.to_owned(),
                None,
                format!("Body {locale}/{channel}"),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        version
    }

    #[tokio::test]
    async fn concurrent_publications_preserve_locale_and_allocate_distinct_versions() {
        let pool = crate::test_utils::setup_test_pool().await;
        let factory = PgRepositoryFactory::new(pool.clone());
        let (english, chinese) = tokio::join!(
            publish(&factory, "en", "email"),
            publish(&factory, "zh-CN", "email")
        );
        assert_ne!(english.version, chinese.version);
        assert_eq!(
            (english.locale.as_str(), chinese.locale.as_str()),
            ("en", "zh-CN")
        );
        // Different channels and missing locales must not accidentally select
        // the newest row for another locale/channel.
        let sms = publish(&factory, "en", "sms").await;
        let mut repo = factory.create().await.unwrap();
        assert_eq!(
            repo.notification_template()
                .get_latest("verification", "email", "en")
                .await
                .unwrap()
                .unwrap(),
            english
        );
        assert_eq!(
            repo.notification_template()
                .get_latest("verification", "email", "zh-CN")
                .await
                .unwrap()
                .unwrap(),
            chinese
        );
        assert_eq!(
            repo.notification_template()
                .get_latest("verification", "sms", "en")
                .await
                .unwrap()
                .unwrap(),
            sms
        );
        assert!(
            repo.notification_template()
                .get_latest("verification", "email", "fr")
                .await
                .unwrap()
                .is_none()
        );
        repo.save().await.unwrap();

        let mut conn = pool.get().await.unwrap();
        diesel::update(
            notification_template_versions::table
                .filter(notification_template_versions::id.eq(Uuid::from(english.id))),
        )
        .set(notification_template_versions::published_at.eq(None::<jiff_diesel::Timestamp>))
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        let mut repo = factory.create().await.unwrap();
        assert!(
            repo.notification_template()
                .get_latest("verification", "email", "en")
                .await
                .unwrap()
                .is_none()
        );
    }
}
