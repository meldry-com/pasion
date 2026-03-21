-- no-transaction
-- This adds an index on the username field for ILIKE '%search%' operations,
-- enabling fuzzy searches of usernames
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_username_trgm_idx
  ON users USING gin(username gin_trgm_ops);
