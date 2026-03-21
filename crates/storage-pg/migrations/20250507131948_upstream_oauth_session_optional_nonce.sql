-- Make the nonce column optional on the upstream oauth sessions
ALTER TABLE "upstream_oauth_authorization_sessions"
    ALTER COLUMN "nonce" DROP NOT NULL;
