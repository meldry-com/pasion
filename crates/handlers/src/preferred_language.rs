use std::sync::Arc;

use headers::HeaderMapExt as _;
use pasion_salvo_utils::language_detection::AcceptLanguage;
use pasion_i18n::{DataLocale, Translator, locale};
use salvo::prelude::*;

use crate::rest::RouteError;

pub fn preferred_language(req: &Request, depot: &Depot) -> DataLocale {
    let translator = depot
        .get::<Arc<Translator>>("translator")
        .cloned()
        .unwrap_or_else(|| Arc::new(Translator::fallback()));

    let accept_language = req.headers().typed_get::<AcceptLanguage>();

    let iter = accept_language
        .iter()
        .flat_map(AcceptLanguage::iter)
        .flat_map(|lang| {
            let lang = DataLocale::from(lang);
            // XXX: this is hacky as we may want to actually maintain proper language
            // aliases at some point, but `zh-CN` doesn't fallback
            // automatically to `zh-Hans`, so we insert it manually here.
            // For some reason, `zh-TW` does fallback to `zh-Hant` correctly.
            if lang == locale!("zh-CN").into() {
                vec![lang, locale!("zh-Hans").into()]
            } else {
                vec![lang]
            }
        });

    translator.choose_locale(iter)
}
