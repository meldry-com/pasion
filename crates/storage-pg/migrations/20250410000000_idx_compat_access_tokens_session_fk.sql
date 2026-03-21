-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_access_tokens_session_fk
  ON compat_access_tokens (compat_session_id);
