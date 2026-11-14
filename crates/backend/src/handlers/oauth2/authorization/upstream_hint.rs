//! `login_hint=upstream:<provider>` (Hagency): lets a client skip Pasion's
//! login chooser and go straight to one upstream provider, e.g.
//! `upstream:github`. `<provider>` matches the provider's ULID or its
//! `brand_name` (case-insensitive). Unknown or disabled providers, and a
//! brand shared by more than one enabled provider, are ignored and the
//! normal login page is shown: an ambiguous hint never picks one silently.

use pasion_data::{BoxRepository, RepositoryAccess, RepositoryError, UpstreamOAuthProvider};
use ulid::Ulid;

/// Prefix that marks a `login_hint` as an upstream provider hint.
pub const UPSTREAM_HINT_PREFIX: &str = "upstream:";

/// The provider selector inside a `login_hint`, if it is an upstream hint.
#[must_use]
pub fn parse_upstream_hint(login_hint: Option<&str>) -> Option<&str> {
    login_hint
        .and_then(|hint| hint.strip_prefix(UPSTREAM_HINT_PREFIX))
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
}

/// Whether `selector` names this provider by id or brand.
#[must_use]
pub fn selects_provider(selector: &str, provider: &UpstreamOAuthProvider) -> bool {
    provider.id.to_string().eq_ignore_ascii_case(selector)
        || provider
            .brand_name
            .as_deref()
            .is_some_and(|brand| brand.eq_ignore_ascii_case(selector))
}

/// The enabled provider a `login_hint` selects, if any.
pub async fn hinted_provider(
    repo: &mut BoxRepository,
    login_hint: Option<&str>,
) -> Result<Option<Ulid>, RepositoryError> {
    let Some(selector) = parse_upstream_hint(login_hint) else {
        return Ok(None);
    };
    let providers = repo.upstream_oauth_provider().all_enabled().await?;
    Ok(unique_selection(selector, &providers))
}

/// The one provider `selector` names; `None` when none or several match.
#[must_use]
pub fn unique_selection(selector: &str, providers: &[UpstreamOAuthProvider]) -> Option<Ulid> {
    let mut matches = providers.iter().filter(|p| selects_provider(selector, p));
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only.id),
        _ => None,
    }
}

/// Where an unauthenticated (or re-authenticating) user goes next:
/// the hinted provider's authorize URL, else the login page.
#[must_use]
pub fn login_path(hinted: Option<Ulid>, continue_query: &str) -> String {
    let page = hinted.map_or_else(|| "/login".to_owned(), |id| format!("/upstream/authorize/{id}"));
    if continue_query.is_empty() {
        page
    } else {
        format!("{page}?{continue_query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_prefixed_non_empty_hints() {
        assert_eq!(parse_upstream_hint(Some("upstream:github")), Some("github"));
        assert_eq!(parse_upstream_hint(Some("upstream: github ")), Some("github"));
        assert_eq!(parse_upstream_hint(Some("upstream:")), None);
        assert_eq!(parse_upstream_hint(Some("mxid:@a:b")), None);
        assert_eq!(parse_upstream_hint(None), None);
    }

    #[test]
    fn login_path_prefers_the_hinted_provider() {
        let id = Ulid::nil();
        assert_eq!(login_path(None, ""), "/login");
        assert_eq!(login_path(None, "kind=x&id=1"), "/login?kind=x&id=1");
        assert_eq!(
            login_path(Some(id), "kind=x"),
            format!("/upstream/authorize/{id}?kind=x")
        );
    }

    fn provider(id: u128, brand: &str) -> UpstreamOAuthProvider {
        use oauth2_types::scope::{OPENID, Scope};
        use pasion_data::{
            Clock, UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
            UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
            UpstreamOAuthProviderTokenAuthMethod, clock::MockClock,
        };
        UpstreamOAuthProvider {
            id: Ulid(id),
            issuer: None,
            human_name: None,
            brand_name: Some(brand.to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            scope: Scope::from_iter([OPENID]),
            userinfo_endpoint_override: None,
            token_endpoint_override: None,
            client_id: "client".to_owned(),
            encrypted_client_secret: None,
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
            id_token_signed_response_alg: pasion_iana::jose::JsonWebSignatureAlg::Rs256,
            response_mode: None,
            created_at: MockClock::default().now(),
            disabled_at: None,
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 0,
            source: pasion_data::UpstreamOAuthProviderSource::Config,
        }
    }

    #[test]
    fn an_ambiguous_brand_selects_no_provider() {
        let one = [provider(1, "github"), provider(2, "google")];
        assert_eq!(unique_selection("GitHub", &one), Some(Ulid(1)));
        let duplicated = [provider(1, "github"), provider(2, "GITHUB")];
        assert_eq!(unique_selection("github", &duplicated), None);
        // The id stays an unambiguous selector even when brands collide.
        assert_eq!(unique_selection(&Ulid(2).to_string(), &duplicated), Some(Ulid(2)));
        assert_eq!(unique_selection("gitlab", &one), None);
    }
}
