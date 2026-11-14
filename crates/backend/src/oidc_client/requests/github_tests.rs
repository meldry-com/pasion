//! Tests for the GitHub `OAuth2` helpers, including a run of the token
//! exchange + `/user` + `/user/emails` sequence against a mock GitHub.

use std::collections::HashMap;

use chrono::Utc;
use oauth2_types::requests::{AccessTokenRequest, AuthorizationCodeGrant};
use rand_core::SeedableRng;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};

use super::*;
use crate::oidc_client::types::client_credentials::ClientCredentials;

fn emails() -> Vec<GitHubEmail> {
    serde_json::from_value(json!([
        {"email": "old@example.com", "primary": false, "verified": true},
        {"email": "octo@example.com", "primary": true, "verified": true},
    ]))
    .unwrap()
}

#[test]
fn detects_github_brand_case_insensitively() {
    assert!(is_github(Some("github")));
    assert!(is_github(Some("GitHub")));
    assert!(!is_github(Some("google")));
    assert!(!is_github(None));
}

#[test]
fn sanitizes_logins_into_localparts() {
    assert_eq!(sanitize_localpart("Octo-Cat"), "octo-cat");
    assert_eq!(sanitize_localpart("dev_bot"), "dev_bot");
    assert_eq!(sanitize_localpart("a b+c"), "a-b-c");
    assert_eq!(sanitize_localpart("-x-"), "x");
    assert_eq!(sanitize_localpart("中文"), FALLBACK_LOCALPART);
    assert_eq!(sanitize_localpart(""), FALLBACK_LOCALPART);
    assert!(sanitize_localpart(&"a".repeat(200)).len() <= MAX_BASE_LEN);
}

#[test]
fn collision_candidates_are_suffixed_in_order() {
    let c: Vec<String> = localpart_candidates("octocat").take(3).collect();
    assert_eq!(c, ["octocat", "octocat-2", "octocat-3"]);
    assert_eq!(
        localpart_candidates("x").last().unwrap(),
        format!("x-{MAX_LOCALPART_SUFFIX}")
    );
}

#[test]
fn picks_only_verified_primary_email() {
    assert_eq!(verified_primary_email(&emails()), Some("octo@example.com"));
    let unverified = vec![GitHubEmail {
        email: "a@b.c".into(),
        primary: true,
        verified: false,
    }];
    assert_eq!(verified_primary_email(&unverified), None);
}

#[test]
fn normalizes_user_payload() {
    let mut user: HashMap<String, Value> = serde_json::from_value(json!({
        "id": 583231, "login": "Octocat", "name": "The Octocat",
        "avatar_url": "https://avatars.example/u/583231", "email": "public@unverified.example"
    }))
    .unwrap();
    normalize_claims(&mut user, &emails());
    assert_eq!(user["sub"], json!("583231"));
    assert_eq!(user["preferred_username"], json!("Octocat"));
    assert_eq!(user[GITHUB_LOGIN_CLAIM], json!("Octocat"));
    assert_eq!(user["picture"], json!("https://avatars.example/u/583231"));
    assert_eq!(user["email"], json!("octo@example.com"));
    assert_eq!(user["email_verified"], json!(true));

    let mut no_mail: HashMap<String, Value> =
        serde_json::from_value(json!({"id": 1, "login": "a", "email": "x@y.z"})).unwrap();
    normalize_claims(&mut no_mail, &[]);
    assert!(!no_mail.contains_key("email"));
}

#[test]
fn derives_emails_endpoint() {
    let u: Url = "https://api.github.com/user".parse().unwrap();
    assert_eq!(emails_endpoint(&u).as_str(), "https://api.github.com/user/emails");
    let u: Url = "http://127.0.0.1:9/user/".parse().unwrap();
    assert_eq!(emails_endpoint(&u).as_str(), "http://127.0.0.1:9/user/emails");
}

async fn mount_mock_github(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(header("accept", "application/json"))
        .and(body_string_contains("client_id=test-client"))
        .and(body_string_contains("code=the-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gho_test", "token_type": "bearer", "scope": "read:user,user:email"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer gho_test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42, "login": "Mock_User", "name": "Mock User", "avatar_url": "http://a/42"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .and(header("authorization", "Bearer gho_test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"email": "mock@example.com", "primary": true, "verified": true}
        ])))
        .mount(server)
        .await;
}

#[tokio::test]
async fn full_github_exchange_against_mock_provider() {
    crate::handlers::test_utils::setup();
    let server = MockServer::start().await;
    mount_mock_github(&server).await;
    let client = crate::reqwest_client();
    let base: Url = server.uri().parse().unwrap();
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1);

    let token = super::super::token::request_access_token(
        &client,
        ClientCredentials::ClientSecretPost {
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
        },
        &base.join("/login/oauth/access_token").unwrap(),
        AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: "the-code".into(),
            redirect_uri: Some("http://localhost/cb".into()),
            code_verifier: None,
        }),
        Utc::now(),
        &mut rng,
    )
    .await
    .unwrap();
    assert!(token.id_token.is_none());

    let userinfo_endpoint = base.join("/user").unwrap();
    let mut user = super::super::userinfo::fetch_userinfo(
        &client,
        &userinfo_endpoint,
        &token.access_token,
        None,
    )
    .await
    .unwrap();
    let mails = fetch_emails(&client, &emails_endpoint(&userinfo_endpoint), &token.access_token)
        .await
        .unwrap();
    normalize_claims(&mut user, &mails);

    assert_eq!(user["sub"], json!("42"));
    assert_eq!(user["email"], json!("mock@example.com"));
    assert_eq!(sanitize_localpart(user[GITHUB_LOGIN_CLAIM].as_str().unwrap()), "mock_user");
}

#[test]
fn userinfo_without_id_or_login_identifies_no_github_user() {
    let user = |v: Value| -> HashMap<String, Value> { serde_json::from_value(v).unwrap() };
    assert_eq!(identified_login(&user(json!({"id": 1, "login": "octocat"}))), Some("octocat"));
    assert_eq!(identified_login(&user(json!({"login": "octocat"}))), None);
    assert_eq!(identified_login(&user(json!({"id": 1}))), None);
    assert_eq!(identified_login(&user(json!({"id": 1, "login": "  "}))), None);
    assert_eq!(identified_login(&user(json!({"id": 1, "login": 7}))), None);
}
