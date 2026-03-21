-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_consents_client_fk
  ON oauth2_consents (oauth2_client_id);
