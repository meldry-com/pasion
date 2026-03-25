//! SPA shell handler — serves the Dioxus frontend HTML wrapper.
//!
//! This handler renders the `app.html` template, which loads the Dioxus WASM
//! frontend. The client-side router then handles all page routing.

use pasion_salvo_utils::InternalError;
use pasion_templates::{AppContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};

use crate::rest;

/// Serve the SPA shell for anonymous (public) pages.
///
/// Used for login, registration, recovery, consent, and all other user-facing
/// pages that are handled by the Dioxus frontend.
#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let locale = crate::preferred_language(req, depot);
    let templates = rest::get_templates(depot)?;
    let url_builder = rest::get_url_builder(depot)?;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    res.render(Text::Html(content));
    Ok(())
}
