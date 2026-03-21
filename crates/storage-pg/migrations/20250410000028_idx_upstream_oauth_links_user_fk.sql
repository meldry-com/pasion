-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_links_user_fk
  ON upstream_oauth_links (user_id);
