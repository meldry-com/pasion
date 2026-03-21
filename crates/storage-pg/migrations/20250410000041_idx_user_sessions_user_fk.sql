-- no-transaction
-- Including the `last_active_at` column lets us effeciently filter in-memory
-- for those sessions without fetching the rows, and without including it in the
-- index btree
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_sessions_user_fk
  ON user_sessions (user_id)
  INCLUDE (last_active_at);
