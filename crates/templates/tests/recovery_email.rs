//! Hagency: the recovery email must tell the user which username the reset
//! applies to (people forget it more often than the password), and carry the
//! reset link, in every part the mailer sends (subject, text, HTML).

use std::net::{IpAddr, Ipv4Addr};

use camino::Utf8Path;
use pasion_data::{UrlBuilder, User, UserRecoverySession};
use pasion_templates::{
    EmailRecoveryContext, SiteBranding, SiteFeatures, TemplateContext, Templates, WithLanguage,
};
use rand_core::SeedableRng;

const LINK: &str = "https://auth.example.com/recovery/complete?ticket=abc123";

async fn load_templates() -> Templates {
    let root = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let features = SiteFeatures {
        password_login: true,
        password_registration: true,
        password_registration_contact_required: false,
        account_recovery: true,
        login_with_email_allowed: true,
    };
    Templates::load(
        root.join("templates/"),
        UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None),
        root.join("translations"),
        SiteBranding::new("example.com"),
        features,
        true,
    )
    .await
    .unwrap()
}

fn context(lang: &str) -> WithLanguage<EmailRecoveryContext> {
    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([3; 32]);
    let mut user = User::samples(now, &mut rng).remove(0);
    user.username = "octo-cat".to_owned();
    let session = UserRecoverySession {
        id: pasion_data::new_id(now, &mut rng),
        email: "octo@example.com".to_owned(),
        user_agent: "test".to_owned(),
        ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        locale: lang.to_owned(),
        created_at: now,
        consumed_at: None,
    };
    EmailRecoveryContext::new(user, session, LINK.parse().unwrap())
        .with_language(lang.parse().unwrap())
}

#[tokio::test]
async fn recovery_email_states_username_and_link_in_english() {
    let templates = load_templates().await;
    let ctx = context("en");
    let text = templates.render_email_recovery_txt(&ctx).unwrap();
    let html = templates.render_email_recovery_html(&ctx).unwrap();
    let subject = templates.render_email_recovery_subject(&ctx).unwrap();
    assert!(text.contains("Your username is octo-cat."), "{text}");
    assert!(text.contains(LINK), "{text}");
    assert!(html.contains("Your username is octo-cat."), "{html}");
    assert!(html.contains("ticket=abc123"), "{html}");
    assert!(subject.contains("octo-cat"), "{subject}");
}

#[tokio::test]
async fn recovery_email_states_username_in_chinese() {
    let templates = load_templates().await;
    let text = templates.render_email_recovery_txt(&context("zh")).unwrap();
    assert!(text.contains("您的用户名是 octo-cat"), "{text}");
}
