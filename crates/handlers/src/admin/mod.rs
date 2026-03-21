use salvo::prelude::*;
use pasion_salvo_utils::InternalError;
use pasion_templates::{ApiDocContext, Templates};
use pasion_router::UrlBuilder;

mod call_context;
mod model;
mod params;
mod response;
mod schema;
pub mod v1;

pub use self::call_context::CallContext;

#[handler]
pub async fn swagger(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = crate::rest::get_url_builder(depot)?;
    let templates = crate::rest::get_templates(depot)?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}

#[handler]
pub async fn swagger_callback(depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let url_builder = crate::rest::get_url_builder(depot)?;
    let templates = crate::rest::get_templates(depot)?;
    let ctx = ApiDocContext::from_url_builder(&url_builder);
    let content = templates.render_swagger_callback(&ctx)?;
    res.render(salvo::writing::Text::Html(content));
    Ok(())
}
