-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_refresh_tokens_access_token_fk
  ON compat_refresh_tokens (compat_access_token_id);
