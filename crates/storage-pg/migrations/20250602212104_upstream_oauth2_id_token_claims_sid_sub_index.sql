-- no-transaction
-- We'll be requesting authorization sessions by provider, sub and sid, so we'll
-- need to index those columns
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    upstream_oauth_authorization_sessions_sid_sub_idx
    ON upstream_oauth_authorization_sessions (
      upstream_oauth_provider_id,
      (id_token_claims->>'sid'),
      (id_token_claims->>'sub')
    );
