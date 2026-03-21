-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_authorization_grants_session_fk
  ON oauth2_authorization_grants (oauth2_session_id);
