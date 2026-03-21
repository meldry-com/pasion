-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_terms_user_fk
  ON user_terms (user_id);
