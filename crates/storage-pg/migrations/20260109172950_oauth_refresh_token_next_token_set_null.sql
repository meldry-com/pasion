-- Replace the foreign key constraint on the next refresh token to set the field
-- to NULL on delete.
ALTER TABLE oauth2_refresh_tokens
  DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey,
  ADD CONSTRAINT oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey
    FOREIGN KEY (next_oauth2_refresh_token_id)
    REFERENCES oauth2_refresh_tokens (oauth2_refresh_token_id)
    ON DELETE SET NULL
    NOT VALID;
