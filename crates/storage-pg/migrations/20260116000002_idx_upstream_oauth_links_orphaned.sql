-- no-transaction
-- Add partial index for cleanup of orphaned upstream OAuth links
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_upstream_oauth_links_orphaned
    ON upstream_oauth_links (upstream_oauth_link_id)
    WHERE user_id IS NULL;
