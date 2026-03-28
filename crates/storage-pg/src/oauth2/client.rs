use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use oauth2_types::{oidc::ApplicationType, requests::GrantType};
use pasion_data_model::{Client, Clock, JwksOrJwksUri};
use pasion_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use pasion_jose::jwk::PublicJsonWebKeySet;
use pasion_storage::oauth2::OAuth2ClientRepository;
use rand::RngCore;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{
        oauth2_access_tokens, oauth2_authorization_grants, oauth2_clients, oauth2_refresh_tokens,
        oauth2_sessions, personal_access_tokens, personal_sessions,
    },
};

/// An implementation of [`OAuth2ClientRepository`] for a PostgreSQL connection
pub struct PgOAuth2ClientRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuth2ClientRepository<'c> {
    /// Create a new [`PgOAuth2ClientRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading OAuth2 clients from the database
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = oauth2_clients)]
struct OAuth2ClientRow {
    oauth2_client_id: Uuid,
    metadata_digest: Option<String>,
    encrypted_client_secret: Option<String>,
    application_type: Option<String>,
    redirect_uris: Vec<String>,
    grant_type_authorization_code: bool,
    grant_type_refresh_token: bool,
    grant_type_client_credentials: bool,
    grant_type_device_code: Option<bool>,
    client_name: Option<String>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    id_token_signed_response_alg: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    initiate_login_uri: Option<String>,
}

impl TryFrom<OAuth2ClientRow> for Client {
    type Error = DatabaseInconsistencyError;

    fn try_from(row: OAuth2ClientRow) -> Result<Client, Self::Error> {
        let id = Ulid::from(row.oauth2_client_id);

        let redirect_uris: Result<Vec<Url>, _> =
            row.redirect_uris.iter().map(|s| s.parse()).collect();
        let redirect_uris = redirect_uris.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("redirect_uris")
                .row(id)
                .source(e)
        })?;

        let application_type = row
            .application_type
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("application_type")
                    .row(id)
                    .source(e)
            })?;

        let mut grant_types = Vec::new();
        if row.grant_type_authorization_code {
            grant_types.push(GrantType::AuthorizationCode);
        }
        if row.grant_type_refresh_token {
            grant_types.push(GrantType::RefreshToken);
        }
        if row.grant_type_client_credentials {
            grant_types.push(GrantType::ClientCredentials);
        }
        if row.grant_type_device_code.unwrap_or(false) {
            grant_types.push(GrantType::DeviceCode);
        }

        let logo_uri = row
            .logo_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("logo_uri")
                    .row(id)
                    .source(e)
            })?;

        let client_uri = row
            .client_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("client_uri")
                    .row(id)
                    .source(e)
            })?;

        let policy_uri = row
            .policy_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("policy_uri")
                    .row(id)
                    .source(e)
            })?;

        let tos_uri = row
            .tos_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("tos_uri")
                    .row(id)
                    .source(e)
            })?;

        let id_token_signed_response_alg = row
            .id_token_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = row
            .userinfo_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_method = row
            .token_endpoint_auth_method
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_method")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_signing_alg = row
            .token_endpoint_auth_signing_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_signing_alg")
                    .row(id)
                    .source(e)
            })?;

        let initiate_login_uri = row
            .initiate_login_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("initiate_login_uri")
                    .row(id)
                    .source(e)
            })?;

        let jwks = match (row.jwks, row.jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => {
                let jwks = serde_json::from_value(jwks).map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks")
                        .row(id)
                        .source(e)
                })?;
                Some(JwksOrJwksUri::Jwks(jwks))
            }
            (None, Some(jwks_uri)) => {
                let jwks_uri = jwks_uri.parse().map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks_uri")
                        .row(id)
                        .source(e)
                })?;

                Some(JwksOrJwksUri::JwksUri(jwks_uri))
            }
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth2_clients")
                    .column("jwks(_uri)")
                    .row(id));
            }
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            metadata_digest: row.metadata_digest,
            encrypted_client_secret: row.encrypted_client_secret,
            application_type,
            redirect_uris,
            grant_types,
            client_name: row.client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }
}

/// Insertable row for creating a new OAuth2 client
#[derive(Insertable)]
#[diesel(table_name = oauth2_clients)]
struct NewOAuth2Client {
    oauth2_client_id: Uuid,
    metadata_digest: Option<String>,
    encrypted_client_secret: Option<String>,
    application_type: Option<String>,
    redirect_uris: Vec<String>,
    grant_type_authorization_code: bool,
    grant_type_refresh_token: bool,
    grant_type_client_credentials: bool,
    grant_type_device_code: Option<bool>,
    client_name: Option<String>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    id_token_signed_response_alg: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    initiate_login_uri: Option<String>,
    is_static: Option<bool>,
}

#[async_trait]
impl OAuth2ClientRepository for PgOAuth2ClientRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_client.lookup",
        skip_all,
        fields(
            oauth2_client.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error> {
        let res = oauth2_clients::table
            .find(Uuid::from(id))
            .select(OAuth2ClientRow::as_select())
            .first::<OAuth2ClientRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(Client::try_from(res)?))
    }

    #[tracing::instrument(
        name = "db.oauth2_client.find_by_metadata_digest",
        skip_all,
        err,
    )]
    async fn find_by_metadata_digest(
        &mut self,
        digest: &str,
    ) -> Result<Option<Client>, Self::Error> {
        let res = oauth2_clients::table
            .filter(oauth2_clients::metadata_digest.eq(digest))
            .select(OAuth2ClientRow::as_select())
            .first::<OAuth2ClientRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(Client::try_from(res)?))
    }

    #[tracing::instrument(
        name = "db.oauth2_client.load_batch",
        skip_all,
        err,
    )]
    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error> {
        let ids: Vec<Uuid> = ids.into_iter().map(Uuid::from).collect();

        let res: Vec<OAuth2ClientRow> = oauth2_clients::table
            .filter(oauth2_clients::oauth2_client_id.eq_any(&ids))
            .select(OAuth2ClientRow::as_select())
            .load(self.conn)
            .await?;

        res.into_iter()
            .map(|r| {
                Client::try_from(r)
                    .map(|c| (c.id, c))
                    .map_err(DatabaseError::from)
            })
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.add",
        skip_all,
        fields(
            client.id,
            client.name = client_name
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        metadata_digest: Option<String>,
        encrypted_client_secret: Option<String>,
        application_type: Option<ApplicationType>,
        grant_types: Vec<GrantType>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("client.id", tracing::field::display(id));

        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        let new_client = NewOAuth2Client {
            oauth2_client_id: Uuid::from(id),
            metadata_digest,
            encrypted_client_secret: encrypted_client_secret.clone(),
            application_type: application_type.as_ref().map(ToString::to_string),
            redirect_uris: redirect_uris_array,
            grant_type_authorization_code: grant_types.contains(&GrantType::AuthorizationCode),
            grant_type_refresh_token: grant_types.contains(&GrantType::RefreshToken),
            grant_type_client_credentials: grant_types.contains(&GrantType::ClientCredentials),
            grant_type_device_code: Some(grant_types.contains(&GrantType::DeviceCode)),
            client_name: client_name.clone(),
            logo_uri: logo_uri.as_ref().map(Url::to_string),
            client_uri: client_uri.as_ref().map(Url::to_string),
            policy_uri: policy_uri.as_ref().map(Url::to_string),
            tos_uri: tos_uri.as_ref().map(Url::to_string),
            jwks_uri: jwks_uri.as_ref().map(Url::to_string),
            jwks: jwks_json,
            id_token_signed_response_alg: id_token_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            userinfo_signed_response_alg: userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_method: token_endpoint_auth_method
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_signing_alg: token_endpoint_auth_signing_alg
                .as_ref()
                .map(ToString::to_string),
            initiate_login_uri: initiate_login_uri.as_ref().map(Url::to_string),
            is_static: Some(false),
        };

        diesel::insert_into(oauth2_clients::table)
            .values(&new_client)
            .execute(self.conn)
            .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            metadata_digest: None,
            encrypted_client_secret,
            application_type,
            redirect_uris,
            grant_types,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.upsert_static",
        skip_all,
        fields(
            client.id = %client_id,
        ),
        err,
    )]
    async fn upsert_static(
        &mut self,
        client_id: Ulid,
        client_name: Option<String>,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error> {
        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let client_auth_method_str = client_auth_method.to_string();
        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        let new_client = NewOAuth2Client {
            oauth2_client_id: Uuid::from(client_id),
            metadata_digest: None,
            encrypted_client_secret: encrypted_client_secret.clone(),
            application_type: None,
            redirect_uris: redirect_uris_array.clone(),
            grant_type_authorization_code: true,
            grant_type_refresh_token: true,
            grant_type_client_credentials: true,
            grant_type_device_code: Some(true),
            client_name: client_name.clone(),
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks_uri: jwks_uri.as_ref().map(Url::to_string),
            jwks: jwks_json.clone(),
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            token_endpoint_auth_method: Some(client_auth_method_str.clone()),
            token_endpoint_auth_signing_alg: None,
            initiate_login_uri: None,
            is_static: Some(true),
        };

        diesel::insert_into(oauth2_clients::table)
            .values(&new_client)
            .on_conflict(oauth2_clients::oauth2_client_id)
            .do_update()
            .set((
                oauth2_clients::encrypted_client_secret.eq(encrypted_client_secret.clone()),
                oauth2_clients::redirect_uris.eq(&redirect_uris_array),
                oauth2_clients::grant_type_authorization_code.eq(true),
                oauth2_clients::grant_type_refresh_token.eq(true),
                oauth2_clients::grant_type_client_credentials.eq(true),
                oauth2_clients::grant_type_device_code.eq(Some(true)),
                oauth2_clients::token_endpoint_auth_method.eq(&client_auth_method_str),
                oauth2_clients::jwks.eq(&jwks_json),
                oauth2_clients::client_name.eq(&client_name),
                oauth2_clients::jwks_uri.eq(jwks_uri.as_ref().map(Url::to_string)),
                oauth2_clients::is_static.eq(Some(true)),
            ))
            .execute(self.conn)
            .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id: client_id,
            client_id: client_id.to_string(),
            metadata_digest: None,
            encrypted_client_secret,
            application_type: None,
            redirect_uris,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
            ],
            client_name,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks,
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            initiate_login_uri: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.all_static",
        skip_all,
        err,
    )]
    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error> {
        let res: Vec<OAuth2ClientRow> = oauth2_clients::table
            .filter(oauth2_clients::is_static.eq(Some(true)))
            .select(OAuth2ClientRow::as_select())
            .load(self.conn)
            .await?;

        res.into_iter()
            .map(|r| Client::try_from(r).map_err(DatabaseError::from))
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.delete_by_id",
        skip_all,
        fields(
            client.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        let client_uuid = Uuid::from(id);

        // Delete the authorization grants
        diesel::delete(
            oauth2_authorization_grants::table
                .filter(oauth2_authorization_grants::oauth2_client_id.eq(client_uuid)),
        )
        .execute(self.conn)
        .await?;

        // Delete the OAuth 2 sessions related data: access tokens
        diesel::delete(oauth2_access_tokens::table.filter(
            oauth2_access_tokens::oauth2_session_id.eq_any(
                oauth2_sessions::table
                    .filter(oauth2_sessions::oauth2_client_id.eq(client_uuid))
                    .select(oauth2_sessions::oauth2_session_id),
            ),
        ))
        .execute(self.conn)
        .await?;

        // Delete refresh tokens
        diesel::delete(oauth2_refresh_tokens::table.filter(
            oauth2_refresh_tokens::oauth2_session_id.eq_any(
                oauth2_sessions::table
                    .filter(oauth2_sessions::oauth2_client_id.eq(client_uuid))
                    .select(oauth2_sessions::oauth2_session_id),
            ),
        ))
        .execute(self.conn)
        .await?;

        // Delete sessions
        diesel::delete(
            oauth2_sessions::table
                .filter(oauth2_sessions::oauth2_client_id.eq(client_uuid)),
        )
        .execute(self.conn)
        .await?;

        // Delete personal access tokens owned by the client
        diesel::delete(personal_access_tokens::table.filter(
            personal_access_tokens::personal_session_id.eq_any(
                personal_sessions::table
                    .filter(personal_sessions::owner_oauth2_client_id.eq(client_uuid))
                    .select(personal_sessions::personal_session_id),
            ),
        ))
        .execute(self.conn)
        .await?;

        // Delete personal sessions owned by the client
        diesel::delete(
            personal_sessions::table
                .filter(personal_sessions::owner_oauth2_client_id.eq(client_uuid)),
        )
        .execute(self.conn)
        .await?;

        // Now delete the client itself
        let rows_affected = diesel::delete(
            oauth2_clients::table.find(client_uuid),
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)
    }
}
