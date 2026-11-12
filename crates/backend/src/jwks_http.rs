//! Network boundary for untrusted OAuth client JWKS locations.
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{bail, ensure};
use pasion_jose::jwk::PublicJsonWebKeySet;
use rustls_platform_verifier::ConfigVerifierExt as _;

const MAX_JWKS_BYTES: usize = 256 * 1024;
static FETCH_BUDGET: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

fn validate_url(url: &url::Url) -> anyhow::Result<&str> {
    ensure!(url.scheme() == "https", "JWKS URI must use HTTPS");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "JWKS URI must not contain credentials"
    );
    ensure!(
        url.fragment().is_none(),
        "JWKS URI must not contain a fragment"
    );
    ensure!(
        url.port_or_known_default() == Some(443),
        "JWKS URI must use port 443"
    );
    url.host_str()
        .ok_or_else(|| anyhow::anyhow!("JWKS URI needs a host"))
}

// Conservative public-unicast allowlist, including IPv4-mapped and
// transition-mechanism exclusions. Never follow redirects or use a proxy.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && ((b == 168) || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}

fn validate_addresses(addresses: &[SocketAddr]) -> anyhow::Result<()> {
    ensure!(!addresses.is_empty(), "JWKS host resolved to no addresses");
    ensure!(
        addresses.iter().all(|a| public_ip(a.ip())),
        "JWKS host must resolve only to public addresses"
    );
    Ok(())
}

async fn read_jwks(mut response: reqwest::Response) -> anyhow::Result<PublicJsonWebKeySet> {
    ensure!(
        response.status().is_success(),
        "JWKS endpoint returned a non-success status"
    );
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        bail!("JWKS response exceeds size limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= MAX_JWKS_BYTES - body.len(),
            "JWKS response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn fetch(url: &url::Url) -> anyhow::Result<PublicJsonWebKeySet> {
    let host = validate_url(url)?;
    let _permit = FETCH_BUDGET
        .try_acquire()
        .map_err(|_| anyhow::anyhow!("JWKS fetch capacity exhausted"))?;
    // Pin precisely the validated DNS result into the actual transport to
    // avoid the check/connect DNS rebinding race.
    let addresses = if let Some(ip) = url.host().and_then(|h| match h {
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    }) {
        vec![SocketAddr::new(ip, 443)]
    } else {
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 443)))
            .await??
            .collect()
    };
    validate_addresses(&addresses)?;
    let tls = rustls::ClientConfig::with_platform_verifier()?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()?;
    read_jwks(client.get(url.clone()).send().await?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limits_unknown_length_chunked_bodies() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0, "client disconnected before sending a request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let body = vec![b' '; MAX_JWKS_BYTES + 1];
            stream
                .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        assert!(response.content_length().is_none());
        assert!(
            read_jwks(response)
                .await
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
        server.await.unwrap();
    }

    #[test]
    fn rejects_non_public_destinations_including_mixed_dns_answers() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(validate_addresses(&[]).is_err());
        assert!(
            validate_addresses(&[
                "8.8.8.8:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap()
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_private_ip_literals_before_connecting() {
        for uri in [
            "https://127.0.0.1/jwks",
            "https://[::1]/jwks",
            "https://[::ffff:127.0.0.1]/jwks",
        ] {
            assert!(
                fetch(&uri.parse().unwrap())
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("public")
            );
        }
    }

    #[test]
    fn requires_https_without_credentials_or_custom_ports() {
        for uri in [
            "http://example.com/jwks",
            "https://user:secret@example.com/jwks",
            "https://example.com:8443/jwks",
            "https://example.com/jwks#fragment",
        ] {
            assert!(validate_url(&uri.parse().unwrap()).is_err(), "{uri}");
        }
        assert!(validate_url(&"https://example.com/jwks".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn enforces_streamed_body_limit_and_rejects_redirect_response() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
        let server = MockServer::start().await;
        Mock::given(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_JWKS_BYTES + 1]))
            .mount(&server)
            .await;
        Mock::given(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/target"))
            .mount(&server)
            .await;
        Mock::given(path("/valid"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"keys":[]}"#))
            .mount(&server)
            .await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for route in ["/large", "/redirect"] {
            assert!(
                read_jwks(
                    client
                        .get(format!("{}{route}", server.uri()))
                        .send()
                        .await
                        .unwrap()
                )
                .await
                .is_err()
            );
        }
        assert!(
            read_jwks(
                client
                    .get(format!("{}/valid", server.uri()))
                    .send()
                    .await
                    .unwrap()
            )
            .await
            .is_ok()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}
