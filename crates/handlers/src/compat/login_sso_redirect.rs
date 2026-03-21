use hyper::StatusCode;
use pasion_salvo_utils::{GenericError, InternalError};
use pasion_router::{CompatLoginSsoAction, CompatLoginSsoComplete, UrlBuilder};
use pasion_storage::compat::CompatSsoLoginRepository;
use rand::distributions::{Alphanumeric, DistString};
use salvo::prelude::*;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::impl_from_error_for_route;

#[derive(Debug, Deserialize)]
pub struct Params {
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
    action: Option<CompatLoginSsoAction>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Missing redirectUrl")]
    MissingRedirectUrl,

    #[error("invalid redirectUrl")]
    InvalidRedirectUrl,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::rest::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(e) => InternalError::new(e).render(res),
            Self::MissingRedirectUrl | Self::InvalidRedirectUrl => {
                GenericError::new(StatusCode::BAD_REQUEST, self).render(res);
            }
        }
    }
}

#[handler]
#[tracing::instrument(name = "handlers.compat.login_sso_redirect.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot) -> Result<Redirect, RouteError> {
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let mut repo = crate::rest::get_repo_factory(depot)?.create().await?;
    let url_builder = crate::rest::get_url_builder(depot)?;

    let params: Params = req.parse_queries().unwrap_or(Params {
        redirect_url: None,
        action: None,
    });

    // Check the redirectUrl parameter
    let redirect_url = params.redirect_url.ok_or(RouteError::MissingRedirectUrl)?;
    let redirect_url = Url::parse(&redirect_url).map_err(|_| RouteError::InvalidRedirectUrl)?;

    // Do not allow URLs with username or passwords in them
    if !redirect_url.username().is_empty() || redirect_url.password().is_some() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    // On the http/https scheme, verify the URL has a host
    if matches!(redirect_url.scheme(), "http" | "https") && !redirect_url.has_host() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    let token = Alphanumeric.sample_string(&mut rng, 32);
    let login = repo
        .compat_sso_login()
        .add(&mut rng, &clock, token, redirect_url)
        .await?;

    repo.save().await?;

    Ok(url_builder.absolute_redirect(&CompatLoginSsoComplete::new(login.id, params.action)))
}
