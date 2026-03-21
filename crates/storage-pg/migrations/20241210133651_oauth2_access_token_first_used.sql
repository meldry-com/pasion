-- Track when the access token was first used. A NULL value means it was never used.
ALTER TABLE oauth2_access_tokens
  ADD COLUMN "first_used_at" TIMESTAMP WITH TIME ZONE;
