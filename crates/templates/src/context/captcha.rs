use std::{collections::BTreeMap, sync::Arc};

use minijinja::{
    Value,
    value::{Enumerator, Object},
};
use pasion_i18n::DataLocale;
use rand::Rng;
use serde::Serialize;

use crate::{TemplateContext, context::SampleIdentifier};

/// Wraps a [`pasion_data::CaptchaConfig`] so it can be exposed as a minijinja
/// object with named fields.
#[derive(Debug)]
struct CaptchaConfigObject {
    inner: pasion_data::CaptchaConfig,
}

impl CaptchaConfigObject {
    /// Translate the service enum variant into the template-facing string key
    fn service_name(&self) -> &'static str {
        match &self.inner.service {
            pasion_data::CaptchaService::RecaptchaV2 => "recaptcha_v2",
            pasion_data::CaptchaService::CloudflareTurnstile => "cloudflare_turnstile",
            pasion_data::CaptchaService::HCaptcha => "hcaptcha",
        }
    }
}

impl Object for CaptchaConfigObject {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str()? {
            "service" => Some(Value::from(self.service_name())),
            "site_key" => Some(Value::from(self.inner.site_key.clone())),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&["service", "site_key"])
    }
}

/// Context with an optional CAPTCHA configuration in it
#[derive(Serialize)]
pub struct WithCaptcha<T> {
    captcha: Option<Value>,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithCaptcha<T> {
    #[must_use]
    pub(crate) fn new(captcha: Option<pasion_data::CaptchaConfig>, inner: T) -> Self {
        let captcha_value =
            captcha.map(|cfg| Value::from_object(CaptchaConfigObject { inner: cfg }));
        Self {
            captcha: captcha_value,
            inner,
        }
    }
}

impl<T: TemplateContext> TemplateContext for WithCaptcha<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::prelude::Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(identifier, inner_ctx)| (identifier, Self::new(None, inner_ctx)))
            .collect()
    }
}
