-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_refresh_tokens_session_fk
  ON oauth2_refresh_tokens (oauth2_session_id);
