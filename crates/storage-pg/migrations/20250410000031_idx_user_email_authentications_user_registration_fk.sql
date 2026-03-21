-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_email_authentications_user_registration_fk
  ON user_email_authentications (user_registration_id);
