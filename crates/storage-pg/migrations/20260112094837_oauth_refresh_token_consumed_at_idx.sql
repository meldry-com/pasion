-- no-transaction
-- Adds a partial index on oauth2_refresh_tokens on the consumed_at field
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_token_consumed_at_idx
  ON oauth2_refresh_tokens (consumed_at, next_oauth2_refresh_token_id, oauth2_refresh_token_id)
  WHERE consumed_at IS NOT NULL;
