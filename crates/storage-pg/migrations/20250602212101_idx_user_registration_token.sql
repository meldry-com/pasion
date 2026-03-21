-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_registrations_user_registration_token_id_fk
  ON user_registrations (user_registration_token_id);
