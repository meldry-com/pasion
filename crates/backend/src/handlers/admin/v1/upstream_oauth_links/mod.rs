pub mod add;
pub mod delete;
pub mod get;
pub mod list;
pub mod update;

#[cfg(test)]
mod test_utils {
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data::upstream_oauth2::UpstreamOAuthProviderParams;
    use pasion_data::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use pasion_iana::jose::JsonWebSignatureAlg;

    pub(crate) fn oidc_provider_params(name: &str) -> UpstreamOAuthProviderParams {
        UpstreamOAuthProviderParams {
            issuer: Some(format!("https://{name}.example.com")),
            human_name: Some(name.to_owned()),
            brand_name: Some(name.to_owned()),
            scope: Scope::from_iter([OPENID]),
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
            token_endpoint_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: format!("client_{name}"),
            encrypted_client_secret: Some("secret".to_owned()),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::default(),
            pkce_mode: UpstreamOAuthProviderPkceMode::default(),
            response_mode: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            jwks_uri_override: None,
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            ui_order: 0,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
        }
    }
}
