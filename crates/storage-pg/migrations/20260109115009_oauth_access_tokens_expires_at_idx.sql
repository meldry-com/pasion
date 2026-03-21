-- no-transaction
-- This adds an index on the expires_at field on oauth2_access_tokens to speed up cleaning them up
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_access_tokens_expires_at_idx
  ON oauth2_access_tokens (expires_at) WHERE expires_at IS NOT NULL;
