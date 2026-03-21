-- We reworked how email verification works but kept some old schema around
-- to allow rolling back. We're safe to drop those now

-- Users don't have a 'primary email' anymore
ALTER TABLE users DROP COLUMN primary_user_email_id;

-- Replaced by user_email_authentications
DROP TABLE user_email_confirmation_codes;

-- User emails are always confirmed when they are in this table now
ALTER TABLE user_emails DROP COLUMN confirmed_at;
