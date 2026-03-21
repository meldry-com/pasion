-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_access_tokens_session_fk
  ON oauth2_access_tokens (oauth2_session_id);
