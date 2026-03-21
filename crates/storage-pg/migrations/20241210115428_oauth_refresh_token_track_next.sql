-- Add a reference to the 'next' refresh token when it was consumed and replaced
ALTER TABLE oauth2_refresh_tokens
  ADD COLUMN "next_oauth2_refresh_token_id" UUID
    REFERENCES oauth2_refresh_tokens (oauth2_refresh_token_id);
