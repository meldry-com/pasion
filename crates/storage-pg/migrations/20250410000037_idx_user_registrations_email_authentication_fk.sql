-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_registrations_email_authentication_fk
  ON user_registrations (email_authentication_id);
