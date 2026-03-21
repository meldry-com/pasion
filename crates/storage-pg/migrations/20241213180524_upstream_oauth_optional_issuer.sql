-- Make the issuer field in the upstream_oauth_providers table optional
ALTER TABLE "upstream_oauth_providers"
  ALTER COLUMN "issuer" DROP NOT NULL;
