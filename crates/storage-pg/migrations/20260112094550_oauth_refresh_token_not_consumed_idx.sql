-- no-transaction
-- Adds a partial index on oauth2_refresh_tokens that are consumed
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_token_not_consumed_idx
  ON oauth2_refresh_tokens (oauth2_refresh_token_id)
  WHERE consumed_at IS NOT NULL;
