// ── Secret and Key Configuration ──
//
// Manages cryptographic keys and encryption secrets used for signing,
// verifying, and encrypting application payloads and cookies.

use std::borrow::Cow;

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use futures_util::future::{try_join, try_join_all};
use pasion_jose::jwk::{JsonWebKey, JsonWebKeySet, Thumbprint};
use pasion_keystore::{Encrypter, Keystore, PrivateKey};
use rand::{Rng, SeedableRng, distributions::Standard, prelude::Distribution as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::task;
use tracing::info;

use super::ConfigurationSection;

// ── Password Config ──

/// Represents a password that can be specified inline or via a file reference
#[derive(Clone, Debug)]
pub enum Password {
    File(Utf8PathBuf),
    Value(String),
}

/// Serialization wrapper for password fields
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct PasswordRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    password_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

impl TryFrom<PasswordRaw> for Option<Password> {
    type Error = anyhow::Error;

    fn try_from(raw: PasswordRaw) -> Result<Self, Self::Error> {
        match (raw.password, raw.password_file) {
            (None, None) => Ok(None),
            (Some(pw), None) => Ok(Some(Password::Value(pw))),
            (None, Some(path)) => Ok(Some(Password::File(path))),
            (Some(_), Some(_)) => bail!("Cannot specify both `password` and `password_file`"),
        }
    }
}

impl From<Option<Password>> for PasswordRaw {
    fn from(opt: Option<Password>) -> Self {
        match opt {
            None => PasswordRaw {
                password: None,
                password_file: None,
            },
            Some(Password::Value(pw)) => PasswordRaw {
                password: Some(pw),
                password_file: None,
            },
            Some(Password::File(path)) => PasswordRaw {
                password: None,
                password_file: Some(path),
            },
        }
    }
}

// ── Key Config ──

/// Represents a cryptographic key that can be specified inline or via a file
#[derive(Clone, Debug)]
pub enum Key {
    File(Utf8PathBuf),
    Value(String),
}

/// Serialization wrapper for key fields
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct KeyRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

impl TryFrom<KeyRaw> for Key {
    type Error = anyhow::Error;

    fn try_from(raw: KeyRaw) -> Result<Key, Self::Error> {
        match (raw.key, raw.key_file) {
            (None, None) => bail!("Missing `key` or `key_file`"),
            (Some(k), None) => Ok(Key::Value(k)),
            (None, Some(path)) => Ok(Key::File(path)),
            (Some(_), Some(_)) => bail!("Cannot specify both `key` and `key_file`"),
        }
    }
}

impl From<Key> for KeyRaw {
    fn from(k: Key) -> Self {
        match k {
            Key::Value(val) => KeyRaw {
                key: Some(val),
                key_file: None,
            },
            Key::File(path) => KeyRaw {
                key: None,
                key_file: Some(path),
            },
        }
    }
}

// ── Single Key Entry ──

/// Configuration for a single signing/encryption key, optionally password-protected
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    /// The key ID `kid` of the key as used by JWKs.
    ///
    /// If not given, `kid` will be the key's RFC 7638 JWK Thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,

    #[schemars(with = "PasswordRaw")]
    #[serde_as(as = "serde_with::TryFromInto<PasswordRaw>")]
    #[serde(flatten)]
    password: Option<Password>,

    #[schemars(with = "KeyRaw")]
    #[serde_as(as = "serde_with::TryFromInto<KeyRaw>")]
    #[serde(flatten)]
    key: Key,
}

impl KeyConfig {
    /// Loads the password bytes, reading from file if necessary
    async fn password(&self) -> anyhow::Result<Option<Cow<'_, [u8]>>> {
        match &self.password {
            None => Ok(None),
            Some(Password::Value(pw)) => Ok(Some(Cow::Borrowed(pw.as_bytes()))),
            Some(Password::File(path)) => {
                let bytes = tokio::fs::read(path).await?;
                Ok(Some(Cow::Owned(bytes)))
            }
        }
    }

    /// Loads the key bytes, reading from file if necessary
    async fn key(&self) -> anyhow::Result<Cow<'_, [u8]>> {
        match &self.key {
            Key::Value(val) => Ok(Cow::Borrowed(val.as_bytes())),
            Key::File(path) => {
                let bytes = tokio::fs::read(path).await?;
                Ok(Cow::Owned(bytes))
            }
        }
    }

    /// Derives a JSON Web Key from this configuration entry
    async fn json_web_key(&self) -> anyhow::Result<JsonWebKey<pasion_keystore::PrivateKey>> {
        let (key_data, password_data) = try_join(self.key(), self.password()).await?;

        let private_key = match password_data {
            Some(pw) => PrivateKey::load_encrypted(&key_data, pw)?,
            None => PrivateKey::load(&key_data)?,
        };

        let kid = self
            .kid
            .clone()
            .unwrap_or_else(|| private_key.thumbprint_sha256_base64());

        Ok(JsonWebKey::new(private_key)
            .with_kid(kid)
            .with_use(pasion_iana::jose::JsonWebKeyUse::Sig))
    }
}

// ── Encryption Config ──

/// Represents the 32-byte encryption key used for secure cookies
#[derive(Debug, Clone)]
pub enum Encryption {
    File(Utf8PathBuf),
    Value([u8; 32]),
}

/// Serialization wrapper for encryption key fields
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Debug, Clone)]
struct EncryptionRaw {
    /// File containing the encryption key for secure cookies.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_file: Option<Utf8PathBuf>,

    /// Encryption key for secure cookies.
    #[schemars(
        with = "Option<String>",
        regex(pattern = r"[0-9a-fA-F]{64}"),
        example = &"0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
    )]
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<[u8; 32]>,
}

impl TryFrom<EncryptionRaw> for Encryption {
    type Error = anyhow::Error;

    fn try_from(raw: EncryptionRaw) -> Result<Encryption, Self::Error> {
        match (raw.encryption, raw.encryption_file) {
            (None, None) => bail!("Missing `encryption` or `encryption_file`"),
            (Some(val), None) => Ok(Encryption::Value(val)),
            (None, Some(path)) => Ok(Encryption::File(path)),
            (Some(_), Some(_)) => bail!("Cannot specify both `encryption` and `encryption_file`"),
        }
    }
}

impl From<Encryption> for EncryptionRaw {
    fn from(enc: Encryption) -> Self {
        match enc {
            Encryption::Value(val) => EncryptionRaw {
                encryption: Some(val),
                encryption_file: None,
            },
            Encryption::File(path) => EncryptionRaw {
                encryption: None,
                encryption_file: Some(path),
            },
        }
    }
}

// ── Directory Key Scanner ──

/// Scans a directory and produces a `KeyConfig` for each regular file found
async fn key_configs_from_path(dir: &Utf8PathBuf) -> anyhow::Result<Vec<KeyConfig>> {
    let mut configs = vec![];
    let mut entries = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        if !entry.path().is_file() {
            continue;
        }
        configs.push(KeyConfig {
            kid: None,
            password: None,
            key: Key::File(entry.path().try_into()?),
        });
    }

    Ok(configs)
}

// ── Secrets Section ──

/// Holds all cryptographic material: signing keys, encryption keys, and
/// optional key directories
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretsConfig {
    /// Encryption key for secure cookies
    #[schemars(with = "EncryptionRaw")]
    #[serde_as(as = "serde_with::TryFromInto<EncryptionRaw>")]
    #[serde(flatten)]
    encryption: Encryption,

    /// List of private keys to use for signing and encrypting payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyConfig>>,

    /// Directory of private keys to use for signing and encrypting payloads.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    keys_dir: Option<Utf8PathBuf>,
}

impl ConfigurationSection for SecretsConfig {
    const PATH: &'static str = "secrets";
}

impl SecretsConfig {
    // ── Public API ──

    /// Builds a signing/verifying keystore from the configured keys
    ///
    /// # Errors
    ///
    /// Returns an error when a key could not be imported
    #[tracing::instrument(name = "secrets.load", skip_all)]
    pub async fn key_store(&self) -> anyhow::Result<Keystore> {
        let all_keys = self.key_configs().await?;
        let jwk_list = try_join_all(all_keys.iter().map(KeyConfig::json_web_key)).await?;
        let jwk_set =
            JsonWebKeySet::try_new(jwk_list).context("invalid JWK metadata in secrets config")?;
        Ok(Keystore::new(jwk_set))
    }

    /// Derive an [`Encrypter`] out of the config
    ///
    /// # Errors
    ///
    /// Returns an error when the Encryptor can not be created.
    pub async fn encrypter(&self) -> anyhow::Result<Encrypter> {
        let key = self.encryption().await?;
        Ok(Encrypter::new(&key))
    }

    /// Returns the encryption secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the encryption secret could not be read from file.
    pub async fn encryption(&self) -> anyhow::Result<[u8; 32]> {
        match self.encryption {
            Encryption::Value(bytes) => Ok(bytes),
            Encryption::File(ref path) => {
                let content = tokio::fs::read(path).await?;
                let mut buf = [0u8; 32];
                hex::decode_to_slice(content, &mut buf).context(
                    "Content of `encryption_file` must contain hex characters \
                    encoding exactly 32 bytes",
                )?;
                Ok(buf)
            }
        }
    }

    // ── Internal helpers ──

    /// Merges directory-based and inline key configs into a single list
    async fn key_configs(&self) -> anyhow::Result<Vec<KeyConfig>> {
        let mut combined = match &self.keys_dir {
            Some(dir) => key_configs_from_path(dir).await?,
            None => vec![],
        };

        let inline_keys = self.keys.as_deref().unwrap_or_default();
        combined.extend(inline_keys.iter().cloned());

        Ok(combined)
    }
}

// ── Key Generation ──

impl SecretsConfig {
    /// Generates a fresh configuration with randomly-created keys for all
    /// supported algorithms
    #[expect(clippy::similar_names, reason = "Key type names are very similar")]
    #[tracing::instrument(skip_all)]
    pub(crate) async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        info!("Generating keys...");

        let span = tracing::info_span!("rsa");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let rsa_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_rsa(key_rng).unwrap();
            info!("Done generating RSA key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let rsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(rsa_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ec_p256");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p256_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p256(key_rng);
            info!("Done generating EC P-256 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p256_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ec_p256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ec_p384");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p384_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p384(key_rng);
            info!("Done generating EC P-384 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p384_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ec_p384_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ec_p521");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p521_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p521(key_rng);
            info!("Done generating EC P-521 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p521_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ec_p521_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ec_k256");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_k256_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_k256(key_rng);
            info!("Done generating EC secp256k1 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_k256_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ec_k256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ed25519");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ed25519_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ed25519(key_rng);
            info!("Done generating Ed25519 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ed25519_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ed25519_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        Ok(Self {
            encryption: Encryption::Value(Standard.sample(&mut rng)),
            keys: Some(vec![
                rsa_key,
                ec_p256_key,
                ec_p384_key,
                ec_p521_key,
                ec_k256_key,
                ed25519_key,
            ]),
            keys_dir: None,
        })
    }

    /// Returns a deterministic test configuration with hardcoded keys
    pub(crate) fn test() -> Self {
        let rsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAymS2RkeIZo7pUeEN
                  QUGCG4GLJru5jzxomO9jiNr5D/oRcerhpQVc9aCpBfAAg4l4a1SmYdBzWqX0X5pU
                  scgTtQIDAQABAkEArNIMlrxUK4bSklkCcXtXdtdKE9vuWfGyOw0GyAB69fkEUBxh
                  3j65u+u3ZmW+bpMWHgp1FtdobE9nGwb2VBTWAQIhAOyU1jiUEkrwKK004+6b5QRE
                  vC9UI2vDWy5vioMNx5Y1AiEA2wGAJ6ETF8FF2Vd+kZlkKK7J0em9cl0gbJDsWIEw
                  N4ECIEyWYkMurD1WQdTQqnk0Po+DMOihdFYOiBYgRdbnPxWBAiEAmtd0xJAd7622
                  tPQniMnrBtiN2NxqFXHCev/8Gpc8gAECIBcaPcF59qVeRmYrfqzKBxFm7LmTwlAl
                  Gh7BNzCeN+D6
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
        };
        let ecdsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                  NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                  OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
        };

        Self {
            encryption: Encryption::Value([0xEA; 32]),
            keys: Some(vec![rsa_key, ecdsa_key]),
            keys_dir: None,
        }
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use pasion_iana::jose::JsonWebSignatureAlg;
    use pasion_jose::constraints::Constrainable;
    use rand::SeedableRng;
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                    "},
                )?;
                jail.create_file(
                    "encryption",
                    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key1",
                    indoc::indoc! {r"
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIJKQIBAAKCAgEA6oR6LXzJOziUxcRryonLTM5Xkfr9cYPCKvnwsWoAHfd2MC6Q
                        OCAWSQnNcNz5RTeQUcLEaA8sxQi64zpCwO9iH8y8COCaO8u9qGkOOuJwWnmPfeLs
                        cEwALEp0LZ67eSUPsMaz533bs4C8p+2UPMd+v7Td8TkkYoqgUrfYuT0bDTMYVsSe
                        wcNB5qsI7hDLf1t5FX6KU79/Asn1K3UYHTdN83mghOlM4zh1l1CJdtgaE1jAg4Ml
                        1X8yG+cT+Ks8gCSGQfIAlVFV4fvvzmpokNKfwAI/b3LS2/ft4ZrK+RCTsWsjUu38
                        Zr8jbQMtDznzBHMw1LoaHpwRNjbJZ7uA6x5ikbwz5NAlfCITTta6xYn8qvaBfiYJ
                        YyUFl0kIHm9Kh9V9p54WPMCFCcQx12deovKV82S6zxTeMflDdosJDB/uG9dT2qPt
                        wkpTD6xAOx5h59IhfiY0j4ScTl725GygVzyK378soP3LQ/vBixQLpheALViotodH
                        fJknsrelaISNkrnapZL3QE5C1SUoaUtMG9ovRz5HDpMx5ooElEklq7shFWDhZXbp
                        2ndU5RPRCZO3Szop/Xhn2mNWQoEontFh79WIf+wS8TkJIRXhjtYBt3+s96z0iqSg
                        gDmE8BcP4lP1+TAUY1d7+QEhGCsTJa9TYtfDtNNfuYI9e3mq6LEpHYKWOvECAwEA
                        AQKCAgAlF60HaCGf50lzT6eePQCAdnEtWrMeyDCRgZTLStvCjEhk7d3LssTeP9mp
                        oe8fPomUv6c3BOds2/5LQFockABHd/y/CV9RA973NclAEQlPlhiBrb793Vd4VJJe
                        6331dveDW0+ggVdFjfVzjhqQfnE9ZcsQ2JvjpiTI0Iv2cy7F01tke0GCSMgx8W1p
                        J2jjDOxwNOKGGoIT8S4roHVJnFy3nM4sbNtyDj+zHimP4uBE8m2zSgQAP60E8sia
                        3+Ki1flnkXJRgQWCHR9cg5dkXfFRz56JmcdgxAHGWX2vD9XRuFi5nitPc6iTw8PV
                        u7GvS3+MC0oO+1pRkTAhOGv3RDK3Uqmy2zrMUuWkEsz6TVId6gPl7+biRJcP+aER
                        plJkeC9J9nSizbQPwErGByzoHGLjADgBs9hwqYkPcN38b6jR5S/VDQ+RncCyI87h
                        s/0pIs/fNlfw4LtpBrolP6g++vo6KUufmE3kRNN9dN4lNOoKjUGkcmX6MGnwxiw6
                        NN/uEqf9+CKQele1XeUhRPNJc9Gv+3Ly5y/wEi6FjfVQmCK4hNrl3tvuZw+qkGbq
                        Au9Jhk7wV81An7fbhBRIXrwOY9AbOKNqUfY+wpKi5vyJFS1yzkFaYSTKTBspkuHW
                        pWbohO+KreREwaR5HOMK8tQMTLEAeE3taXGsQMJSJ15lRrLc7QKCAQEA68TV/R8O
                        C4p+vnGJyhcfDJt6+KBKWlroBy75BG7Dg7/rUXaj+MXcqHi+whRNXMqZchSwzUfS
                        B2WK/HrOBye8JLKDeA3B5TumJaF19vV7EY/nBF2QdRmI1r33Cp+RWUvAcjKa/v2u
                        KksV3btnJKXCu/stdAyTK7nU0on4qBzm5WZxuIJv6VMHLDNPFdCk+4gM8LuJ3ITU
                        l7XuZd4gXccPNj0VTeOYiMjIwxtNmE9RpCkTLm92Z7MI+htciGk1xvV0N4m1BXwA
                        7qhl1nBgVuJyux4dEYFIeQNhLpHozkEz913QK2gDAHL9pAeiUYJntq4p8HNvfHiQ
                        vE3wTzil3aUFnwKCAQEA/qQm1Nx5By6an5UunrOvltbTMjsZSDnWspSQbX//j6mL
                        2atQLe3y/Nr7E5SGZ1kFD9tgAHTuTGVqjvTqp5dBPw4uo146K2RJwuvaYUzNK26c
                        VoGfMfsI+/bfMfjFnEmGRARZdMr8cvhU+2m04hglsSnNGxsvvPdsiIbRaVDx+JvN
                        C5C281WlN0WeVd7zNTZkdyUARNXfCxBHQPuYkP5Mz2roZeYlJMWU04i8Cx0/SEuu
                        bhZQDaNTccSdPDFYcyDDlpqp+mN+U7m+yUPOkVpaxQiSYJZ+NOQsNcAVYfjzyY0E
                        /VP3s2GddjCJs0amf9SeW0LiMAHPgTp8vbMSRPVVbwKCAQEAmZsSd+llsys2TEmY
                        pivONN6PjbCRALE9foCiCLtJcmr1m4uaZRg0HScd0UB87rmoo2TLk9L5CYyksr4n
                        wQ2oTJhpgywjaYAlTVsWiiGBXv3MW1HCLijGuHHno+o2PmFWLpC93ufUMwXcZywT
                        lRLR/rs07+jJcbGO8OSnNpAt9sN5z+Zblz5a6/c5zVK0SpRnKehld2CrSXRkr8W6
                        fJ6WUJYXbTmdRXDbLBJ7yYHUBQolzxkboZBJhvmQnec9/DQq1YxIfhw+Vz8rqjxo
                        5/J9IWALPD5owz7qb/bsIITmoIFkgQMxAXfpvJaksEov3Bs4g8oRlpzOX4C/0j1s
                        Ay3irQKCAQEAwRJ/qufcEFkCvjsj1QsS+MC785shyUSpiE/izlO91xTLx+f/7EM9
                        +QCkXK1B1zyE/Qft24rNYDmJOQl0nkuuGfxL2mzImDv7PYMM2reb3PGKMoEnzoKz
                        xi/h/YbNdnm9BvdxSH/cN+QYs2Pr1X5Pneu+622KnbHQphfq0fqg7Upchwdb4Faw
                        5Z6wthVMvK0YMcppUMgEzOOz0w6xGEbowGAkA5cj1KTG+jjzs02ivNM9V5Utb5nF
                        3D4iphAYK3rNMfTlKsejciIlCX+TMVyb9EdSjU+uM7ZJ2xtgWx+i4NA+10GCT42V
                        EZct4TORbN0ukK2+yH2m8yoAiOks0gJemwKCAQAMGROGt8O4HfhpUdOq01J2qvQL
                        m5oUXX8w1I95XcoAwCqb+dIan8UbCyl/79lbqNpQlHbRy3wlXzWwH9aHKsfPlCvk
                        5dE1qrdMdQhLXwP109bRmTiScuU4zfFgHw3XgQhMFXxNp9pze197amLws0TyuBW3
                        fupS4kM5u6HKCeBYcw2WP5ukxf8jtn29tohLBiA2A7NYtml9xTer6BBP0DTh+QUn
                        IJL6jSpuCNxBPKIK7p6tZZ0nMBEdAWMxglYm0bmHpTSd3pgu3ltCkYtDlDcTIaF0
                        Q4k44lxUTZQYwtKUVQXBe4ZvaT/jIEMS7K5bsAy7URv/toaTaiEh1hguwSmf
                        -----END RSA PRIVATE KEY-----
                    "},
                )?;
                jail.create_file(
                    "keys/key2",
                    indoc::indoc! {r"
                        -----BEGIN EC PRIVATE KEY-----
                        MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                        AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                        h27LAir5RqxByHvua2XsP46rSTChof78uw==
                        -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    assert!(
                        matches!(config.encryption, Encryption::File(ref p) if p == "encryption")
                    );
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let mut key_config = config.key_configs().await.unwrap();
                    key_config.sort_by_key(|a| {
                        if let Key::File(p) = &a.key {
                            Some(p.clone())
                        } else {
                            None
                        }
                    });
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key1"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("xmgGCzGtQFmhEOP0YAqBt-oZyVauSVMXcf4kwcgGZLc")));
                    assert!(key_config[1].kid.is_none());
                    assert!(matches!(&key_config[1].key, Key::File(p) if p == "keys/key2"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_inline_secrets() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption: >-
                            0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                            - key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                                AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                                h27LAir5RqxByHvua2XsP46rSTChof78uw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let key_store = config.key_store().await.unwrap();
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_mixed_key_sources() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key_from_file",
                    indoc::indoc! {r"
                        -----BEGIN EC PRIVATE KEY-----
                        MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                        AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                        h27LAir5RqxByHvua2XsP46rSTChof78uw==
                        -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    let key_config = config.key_configs().await.unwrap();
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key_from_file"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn generate_config_includes_extended_signing_keys() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let config = SecretsConfig::generate(&mut rng).await.unwrap();
        let key_store = config.key_store().await.unwrap();
        let algs = key_store.available_signing_algorithms();

        assert!(algs.contains(&JsonWebSignatureAlg::Es512));
        assert!(algs.contains(&JsonWebSignatureAlg::EdDsa));
    }
}
