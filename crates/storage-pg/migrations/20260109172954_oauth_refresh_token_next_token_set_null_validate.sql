-- Validate the foreign key constraint on the next refresh token
ALTER TABLE oauth2_refresh_tokens
  VALIDATE CONSTRAINT oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey;
