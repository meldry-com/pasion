-- We've removed the idea of conditional consent (just go through the login if
-- we already consented in the past) but didn't do the cleanup

-- In this version we completely stopped writing to this table, so that it's
-- safe to completely drop in the next version
TRUNCATE TABLE oauth2_consents;

-- We stopped reading and writing in those columns a long time ago, so it's fine
-- to drop them now
ALTER TABLE oauth2_authorization_grants
  DROP COLUMN max_age,
  DROP COLUMN requires_consent;
