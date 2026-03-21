-- When we introduced an id_token_claims column on upstream OAuth 2.0 logins, we
-- added a trigger to make sure that when rolling back the new columns gets
-- automatically filled correctly. It's been a while, it's safe to remove them.
DROP TRIGGER IF EXISTS trg_fill_id_token_claims ON upstream_oauth_authorization_sessions;
DROP FUNCTION IF EXISTS fill_id_token_claims();
