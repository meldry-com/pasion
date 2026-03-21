-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_authorization_grants_client_fk
  ON oauth2_authorization_grants (oauth2_client_id);
