-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_sessions_client_fk
  ON oauth2_sessions (oauth2_client_id);
