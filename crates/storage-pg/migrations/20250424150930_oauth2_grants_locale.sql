-- Track the locale of the user which asked for the authorization grant
ALTER TABLE oauth2_authorization_grants
    ADD COLUMN locale TEXT;
