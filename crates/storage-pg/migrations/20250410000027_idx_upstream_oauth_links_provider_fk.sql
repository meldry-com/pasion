-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_links_provider_fk
  ON upstream_oauth_links (upstream_oauth_provider_id);
