-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_refresh_tokens_access_token_fk
  ON oauth2_refresh_tokens (oauth2_access_token_id);
