//! Diagnostic utility to check the health of the deployment
//!
//! The code is quite repetitive for now, but we can refactor later with a
//! better check abstraction

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use hyper::StatusCode;
use pasion_config::{ConfigurationSection, RootConfig};
use pasion_http::RequestBuilderExt;
use tracing::{error, info, info_span, warn};
use url::{Host, Url};

/// Base URL for the human-readable documentation
const DOCS_BASE: &str = "https://palpo-im.github.io/pasion";

#[derive(Parser, Debug)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.doctor").entered();
        info!(
            "💡 Running diagnostics, make sure that both Pasion and Palpo are running, and that Pasion is using the same configuration files as this tool."
        );

        let config = RootConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        // We'll need an HTTP client
        let http_client = pasion_http::reqwest_client();
        let base_url = config.http.public_base.as_str();
        let issuer = config.http.issuer.as_ref().map(url::Url::as_str);
        let issuer = issuer.unwrap_or(base_url);
        let matrix_domain: Host = Host::parse(&config.matrix.homeserver).context(
            r"The homeserver host in the config (`matrix.homeserver`) is not a valid domain.
See {DOCS_BASE}/setup/homeserver.html",
        )?;
        let secret = config.matrix.secret().await?;
        let hs_api = config.matrix.endpoint;

        if !issuer.starts_with("https://") {
            warn!(
                r"⚠️ The issuer in the config (`http.issuer`/`http.public_base`) is not an HTTPS URL.
This means some clients will refuse to use it."
            );
        }

        let well_known_uri = format!("https://{matrix_domain}/.well-known/matrix/client");
        let result = http_client.get(&well_known_uri).send_traced().await;

        let expected_well_known = serde_json::json!({
            "m.homeserver": {
                "base_url": "...",
            },
            "org.matrix.msc2965.authentication": {
                "issuer": issuer,
                "account": format!("{base_url}account/"),
            },
        });

        let discovered_cs_api = match result {
            Ok(response) => {
                // Make sure we got a 2xx response
                let status = response.status();
                if !status.is_success() {
                    warn!(
                        r#"⚠️ Matrix client well-known replied with {status}, expected 2xx.
Make sure the homeserver is reachable and the well-known document is available at "{well_known_uri}""#,
                    );
                }

                let result = response.json::<serde_json::Value>().await;

                match result {
                    Ok(body) => {
                        if let Some(auth) = body.get("org.matrix.msc2965.authentication") {
                            if let Some(wk_issuer) =
                                auth.get("issuer").and_then(|issuer| issuer.as_str())
                            {
                                if issuer == wk_issuer {
                                    info!(
                                        r#"✅ Matrix client well-known at "{well_known_uri}" is valid"#
                                    );
                                } else {
                                    warn!(
                                        r#"⚠️ Matrix client well-known has an "org.matrix.msc2965.authentication" section, but the issuer is not the same as the homeserver.
Check the well-known document at "{well_known_uri}"
This can happen because Pasion parses the URL its config differently from the homeserver.
This means some OIDC-native clients might not work.
Make sure that the Pasion config contains:

  http:
    public_base: {issuer:?}

And in the Palpo config:

  matrix_authentication_service:
    enabled: true
    # This must point to where Pasion is reachable by Palpo
    endpoint: {issuer:?}
    # ...

See {DOCS_BASE}/setup/homeserver.html
"#
                                    );
                                }
                            } else {
                                error!(
                                    r#"❌ Matrix client well-known "org.matrix.msc2965.authentication" does not have a valid "issuer" field.
Check the well-known document at "{well_known_uri}"
"#
                                );
                            }
                        } else {
                            warn!(
                                r#"Matrix client well-known is missing the "org.matrix.msc2965.authentication" section.
Check the well-known document at "{well_known_uri}"
Make sure Palpo has delegated auth enabled:

  matrix_authentication_service:
    enabled: true
    endpoint: {issuer:?}
    # ...

If it is not Palpo handling the well-known document, update it to include the following:

{expected_well_known:#}

See {DOCS_BASE}/setup/homeserver.html
"#
                            );
                        }
                        // Return the discovered homeserver base URL
                        body.get("m.homeserver")
                            .and_then(|hs| hs.get("base_url"))
                            .and_then(|base_url| base_url.as_str())
                            .and_then(|base_url| Url::parse(base_url).ok())
                    }
                    Err(e) => {
                        warn!(
                            r#"⚠️ Invalid JSON for the well-known document at "{well_known_uri}".
Make sure going to {well_known_uri:?} in a web browser returns a valid JSON document, similar to:

{expected_well_known:#}

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    r#"⚠️ Failed to fetch well-known document at "{well_known_uri}".
This means that the homeserver is not reachable, the well-known document is not available, or malformed.
Make sure your homeserver is running.
Make sure going to {well_known_uri:?} in a web browser returns a valid JSON document, similar to:

{expected_well_known:#}

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
                );
                None
            }
        };

        // Now try to reach the homeserver
        let client_versions = hs_api.join("/_matrix/client/versions")?;
        let result = http_client
            .get(client_versions.as_str())
            .send_traced()
            .await;
        let can_reach_cs = match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(r#"✅ Homeserver is reachable at "{client_versions}""#);
                    true
                } else {
                    error!(
                        r#"❌Can't reach the homeserver at "{client_versions}", got {status}.
Make sure your homeserver is running.
This may be due to a misconfiguration in the `matrix` section of the config.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html
"#
                    );
                    false
                }
            }
            Err(e) => {
                error!(
                    r#"❌ Can't reach the homeserver at "{client_versions}".
This may be due to a misconfiguration in the `matrix` section of the config.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
                );
                false
            }
        };

        if can_reach_cs {
            // Try the whoami API. If it replies with `M_UNKNOWN` this is because Palpo
            // couldn't reach Pasion
            let whoami = hs_api.join("/_matrix/client/v3/account/whoami")?;
            let result = http_client
                .get(whoami.as_str())
                .bearer_auth("averyinvalidtokenireallyhopethisisnotvalid")
                .send_traced()
                .await;
            match result {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or("???".into());

                    match status.as_u16() {
                        401 => info!(
                            r#"✅ Homeserver at "{whoami}" is reachable, and it correctly rejected an invalid token."#
                        ),

                        0..=399 => error!(
                            r#"❌ The homeserver at "{whoami}" replied with {status}.
This is *highly* unexpected, as this means that a fake token might have been accepted.
"#
                        ),

                        503 => error!(
                            r#"❌ The homeserver at "{whoami}" replied with {status}.
This means probably means that the homeserver was unable to reach Pasion to validate the token.
Make sure Pasion is running and reachable from Palpo.
Check your homeserver logs.

This is what the homeserver told us about the error:

    {body}

See {DOCS_BASE}/setup/homeserver.html
"#
                        ),

                        _ => warn!(
                            r#"⚠️ The homeserver at "{whoami}" replied with {status}.
Check that the homeserver is running."#
                        ),
                    }
                }
                Err(e) => error!(
                    r#"❌ Can't reach the homeserver at "{whoami}".

Error details: {e}
"#
                ),
            }

            // Try to reach an authenticated Pasion API endpoint
            let mas_api = hs_api.join("/_palpo/mas/is_localpart_available")?;
            let result = http_client
                .get(mas_api.as_str())
                .bearer_auth(&secret)
                .send_traced()
                .await;
            match result {
                Ok(response) => {
                    let status = response.status();
                    // We intentionally omit the required 'localpart' parameter
                    // in this request. If authentication is successful, Palpo
                    // returns a 400 Bad Request because of the missing
                    // parameter. If authentication fails, Palpo will return a
                    // 403 Forbidden. If the Pasion integration isn't enabled,
                    // Palpo will return a 404 Not found.
                    if status == StatusCode::BAD_REQUEST {
                        info!(
                            r#"✅ The Palpo Pasion API is reachable with authentication at "{mas_api}"."#
                        );
                    } else {
                        error!(
                            r#"❌ A Palpo Pasion API endpoint at "{mas_api}" replied with {status}.
Make sure the homeserver is running, and that the Pasion config has the correct `matrix.secret`.
It should match the `secret` set in the Palpo config.

  matrix_authentication_service:
    enabled: true
    endpoint: {issuer:?}
    # This must exactly match the secret in the Pasion config:
    secret: {secret:?}

And in the Pasion config:

  matrix:
    homeserver: "{matrix_domain}"
    endpoint: "{hs_api}"
    secret: {secret:?}
"#
                        );
                    }
                }
                Err(e) => error!(
                    r#"❌ Can't reach the Palpo Pasion API at "{mas_api}".
Make sure the homeserver is running, and that the Pasion config has the correct `matrix.secret`.

Error details: {e}
"#
                ),
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
