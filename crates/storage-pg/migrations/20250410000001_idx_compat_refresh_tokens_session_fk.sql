-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_refresh_tokens_session_fk
  ON compat_refresh_tokens (compat_session_id);
