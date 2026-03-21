-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_refresh_tokens_next_refresh_token_fk
  ON oauth2_refresh_tokens (next_oauth2_refresh_token_id);
