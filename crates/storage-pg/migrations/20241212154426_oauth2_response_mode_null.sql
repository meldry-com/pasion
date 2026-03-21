-- Drop not null requirement on response mode, so we can ignore this query parameter.
ALTER TABLE "upstream_oauth_providers" ALTER COLUMN "response_mode" DROP NOT NULL;
