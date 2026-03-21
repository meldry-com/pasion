-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_email_authentication_codes_authentication_fk
  ON user_email_authentication_codes (user_email_authentication_id);
