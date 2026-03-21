-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_authorization_sessions_provider_fk
  ON upstream_oauth_authorization_sessions (upstream_oauth_provider_id);
