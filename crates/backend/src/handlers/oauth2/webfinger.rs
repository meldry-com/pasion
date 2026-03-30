use oauth2_types::webfinger::WebFingerResponse;
use pasion_data_model::UrlBuilder;
use salvo::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Params {
    resource: String,

    // TODO: handle multiple rel=
    #[serde(default)]
    rel: Option<String>,
}

fn jrd() -> mime::Mime {
    "application/jrd+json".parse().unwrap()
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.webfinger.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");

    let params: Params = match req.parse_queries() {
        Ok(p) => p,
        Err(e) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain(format!("Invalid query parameters: {e}")));
            return;
        }
    };

    // TODO: should we validate the subject?
    let subject = params.resource;

    let wants_issuer = params
        .rel
        .iter()
        .any(|i| i == "http://openid.net/specs/connect/1.0/issuer");

    let webfinger_res = if wants_issuer {
        WebFingerResponse::new(subject).with_issuer(url_builder.oidc_issuer())
    } else {
        WebFingerResponse::new(subject)
    };

    res.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/jrd+json"),
    );
    res.render(Json(webfinger_res));
}
