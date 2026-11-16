CREATE INDEX notification_template_versions_delivery_lookup_idx
    ON notification_template_versions (template_key, channel, locale, version DESC)
    WHERE published_at IS NOT NULL;
