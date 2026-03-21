-- This defines the behavior when receiving a backchannel logout notification
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "on_backchannel_logout" TEXT
    NOT NULL
    DEFAULT 'do_nothing';
