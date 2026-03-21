-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_authorization_sessions_link_fk
  ON upstream_oauth_authorization_sessions (upstream_oauth_link_id);
