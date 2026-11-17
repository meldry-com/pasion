//! Embedding Pasion must preserve Matrix identifiers in sibling routes.

use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};

#[handler]
fn capture(req: &mut Request) -> String {
    format!(
        "{}|{}",
        req.param::<String>("id").unwrap(),
        req.uri().path_and_query().unwrap()
    )
}

#[tokio::test]
async fn embedded_router_preserves_encoded_identifiers_and_request_target() {
    let router: salvo_core::Router =
        Router::with_path("_matrix/client/v3/profile/{id}").get(capture);
    let service = Service::new(router);
    for (encoded, decoded) in [
        ("%40a%2Fb%3Aexample.org", "@a/b:example.org"),
        ("@a%2fb:example.org", "@a/b:example.org"),
        ("%40a%252Fb%3Aexample.org", "@a%2Fb:example.org"),
    ] {
        let path = format!("/_matrix/client/v3/profile/{encoded}?probe=%2F");
        let mut response = TestClient::get(format!("http://localhost{path}"))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_string().await.unwrap(),
            format!("{decoded}|{path}")
        );
    }
    for path in [
        "/_matrix/client/v3/profile/@a/b:example.org",
        "/_matrix%2Fclient/v3/profile/@a:example.org",
    ] {
        let response = TestClient::get(format!("http://localhost{path}"))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    }
}
