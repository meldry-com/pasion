-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_passwords_user_fk
  ON user_passwords (user_id);
