//! Database-published notification templates. Bodies are plain text (or the
//! provider's parameter JSON for a template-based SMS transport).

use minijinja::{Environment, UndefinedBehavior};
use serde::Serialize;

use crate::TemplateError;

/// A published override selected for one key, channel and locale.
#[derive(Debug, Clone)]
pub struct PublishedNotificationTemplate {
    /// Optional email subject; omission preserves the configured subject.
    pub subject_template: Option<String>,
    /// Plain-text body, or provider parameter JSON for template-based SMS.
    pub body_template: String,
}

/// Rendered content for one delivery.
pub struct RenderedNotificationTemplate {
    /// The override subject, when provided.
    pub subject: Option<String>,
    /// The rendered body.
    pub body: String,
}

impl PublishedNotificationTemplate {
    /// Whether this key/channel pair has an actual delivery consumer.
    #[must_use]
    pub fn supports(key: &str, channel: &str) -> bool {
        matches!(
            (key, channel),
            ("verification", "email" | "sms") | ("recovery", "email")
        )
    }

    /// Compile both fields before publishing, without rendering any secrets.
    ///
    /// # Errors
    /// Returns an error for invalid Minijinja syntax.
    pub fn validate(&self) -> Result<(), TemplateError> {
        let env = Environment::new();
        env.template_from_str(&self.body_template)
            .map_err(TemplateError::Published)?;
        if let Some(subject) = &self.subject_template {
            env.template_from_str(subject)
                .map_err(TemplateError::Published)?;
        }
        Ok(())
    }

    /// Render with strict undefined variables. An invalid published version
    /// fails the delivery rather than silently sending different content.
    ///
    /// # Errors
    /// Returns an error if either template cannot render with this context.
    pub fn render<C: Serialize>(
        &self,
        context: &C,
    ) -> Result<RenderedNotificationTemplate, TemplateError> {
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        let body = env
            .render_str(&self.body_template, context)
            .map_err(TemplateError::Published)?;
        let subject = self
            .subject_template
            .as_ref()
            .map(|subject| {
                env.render_str(subject, context)
                    .map_err(TemplateError::Published)
            })
            .transpose()?;
        Ok(RenderedNotificationTemplate { subject, body })
    }
}

/// Ordered locale lookup: exact locale, successively less specific tags, then
/// English. If no published version exists, the configured templates are used.
#[must_use]
pub fn notification_locale_fallbacks(locale: &str) -> Vec<String> {
    let mut result = vec![locale.to_owned()];
    let mut parent = locale;
    while let Some((prefix, _)) = parent.rsplit_once('-') {
        result.push(prefix.to_owned());
        parent = prefix;
    }
    if !result.iter().any(|entry| entry == "en") {
        result.push("en".to_owned());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_real_context_and_rejects_missing_variables() {
        let template = PublishedNotificationTemplate {
            subject_template: Some("Verify {{ lang }}".to_owned()),
            body_template: "Code {{ authentication_code.code }}".to_owned(),
        };
        template.validate().unwrap();
        let context = serde_json::json!({"lang":"zh-CN", "authentication_code":{"code":"654321"}});
        let rendered = template.render(&context).unwrap();
        assert_eq!(rendered.subject.as_deref(), Some("Verify zh-CN"));
        assert_eq!(rendered.body, "Code 654321");
        assert!(template.render(&serde_json::json!({"lang":"en"})).is_err());
        assert!(
            PublishedNotificationTemplate {
                subject_template: None,
                body_template: "{% if".to_owned()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn resolves_locale_without_crossing_channels_or_unsupported_keys() {
        assert_eq!(
            notification_locale_fallbacks("zh-Hans-CN"),
            ["zh-Hans-CN", "zh-Hans", "zh", "en"]
        );
        assert_eq!(notification_locale_fallbacks("en"), ["en"]);
        assert!(PublishedNotificationTemplate::supports(
            "verification",
            "sms"
        ));
        assert!(!PublishedNotificationTemplate::supports("recovery", "sms"));
        assert!(!PublishedNotificationTemplate::supports(
            "password_reset",
            "email"
        ));
    }
}
