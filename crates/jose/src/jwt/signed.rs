// Independent implementation of signed JWT construction and verification.
//
// Provides `Jwt<T>` which can be created by signing a payload with
// `Jwt::sign` / `Jwt::sign_with_rng`, parsed from a compact
// serialisation with `TryFrom<&str>` / `TryFrom<String>`, and
// verified against asymmetric key sets, symmetric secrets, or
// individual keys.

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::thread_rng;
use serde::{Serialize, de::DeserializeOwned};
use signature::{RandomizedSigner, SignatureEncoding, Verifier, rand_core::CryptoRngCore};
use thiserror::Error;

use super::{header::JsonWebSignatureHeader, raw::RawJwt};
use crate::{constraints::ConstraintSet, jwk::PublicJsonWebKeySet};

// ---------------------------------------------------------------------------
// Jwt – the main signed-JWT type
// ---------------------------------------------------------------------------

/// A parsed (and optionally verified) signed JWT.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwt<'a, T> {
    raw: RawJwt<'a>,
    header: JsonWebSignatureHeader,
    payload: T,
    signature: Vec<u8>,
}

impl<T> std::fmt::Display for Jwt<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Jwt<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwt")
            .field("raw", &"...")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &"...")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Decoding errors
// ---------------------------------------------------------------------------

/// Errors that may occur while decoding the compact JWT serialisation.
#[derive(Debug, Error)]
pub enum JwtDecodeError {
    #[error(transparent)]
    RawDecode {
        #[from]
        inner: super::raw::DecodeError,
    },

    #[error("failed to decode JWT header")]
    DecodeHeader {
        #[source]
        inner: base64ct::Error,
    },

    #[error("failed to deserialize JWT header")]
    DeserializeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to decode JWT payload")]
    DecodePayload {
        #[source]
        inner: base64ct::Error,
    },

    #[error("failed to deserialize JWT payload")]
    DeserializePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to decode JWT signature")]
    DecodeSignature {
        #[source]
        inner: base64ct::Error,
    },
}

impl JwtDecodeError {
    fn decode_header(inner: base64ct::Error) -> Self {
        Self::DecodeHeader { inner }
    }

    fn deserialize_header(inner: serde_json::Error) -> Self {
        Self::DeserializeHeader { inner }
    }

    fn decode_payload(inner: base64ct::Error) -> Self {
        Self::DecodePayload { inner }
    }

    fn deserialize_payload(inner: serde_json::Error) -> Self {
        Self::DeserializePayload { inner }
    }

    fn decode_signature(inner: base64ct::Error) -> Self {
        Self::DecodeSignature { inner }
    }
}

// ---------------------------------------------------------------------------
// Decoding – internal helper
// ---------------------------------------------------------------------------

/// Decode a `RawJwt` into its typed components. Factored out so that all
/// three `TryFrom` implementations share one code path.
fn decode_raw_jwt<'a, T: DeserializeOwned>(
    raw: RawJwt<'a>,
) -> Result<Jwt<'a, T>, JwtDecodeError> {
    // Header
    let hdr_decoder = base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.header().as_bytes())
        .map_err(JwtDecodeError::decode_header)?;
    let header: JsonWebSignatureHeader =
        serde_json::from_reader(hdr_decoder).map_err(JwtDecodeError::deserialize_header)?;

    // Payload
    let pay_decoder = base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.payload().as_bytes())
        .map_err(JwtDecodeError::decode_payload)?;
    let payload: T =
        serde_json::from_reader(pay_decoder).map_err(JwtDecodeError::deserialize_payload)?;

    // Signature
    let signature = Base64UrlUnpadded::decode_vec(raw.signature())
        .map_err(JwtDecodeError::decode_signature)?;

    Ok(Jwt {
        raw,
        header,
        payload,
        signature,
    })
}

// -- TryFrom impls ----------------------------------------------------------

impl<'a, T: DeserializeOwned> TryFrom<RawJwt<'a>> for Jwt<'a, T> {
    type Error = JwtDecodeError;

    fn try_from(raw: RawJwt<'a>) -> Result<Self, Self::Error> {
        decode_raw_jwt(raw)
    }
}

impl<'a, T: DeserializeOwned> TryFrom<&'a str> for Jwt<'a, T> {
    type Error = JwtDecodeError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        decode_raw_jwt(RawJwt::try_from(value)?)
    }
}

impl<T: DeserializeOwned> TryFrom<String> for Jwt<'static, T> {
    type Error = JwtDecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        decode_raw_jwt(RawJwt::try_from(value)?)
    }
}

// ---------------------------------------------------------------------------
// Verification errors
// ---------------------------------------------------------------------------

/// Errors that may occur while verifying a JWT signature.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    #[error("failed to parse signature")]
    ParseSignature,

    #[error("signature verification failed")]
    Verify {
        #[source]
        inner: signature::Error,
    },
}

impl JwtVerificationError {
    #[allow(clippy::needless_pass_by_value)]
    fn parse_signature<E>(_inner: E) -> Self {
        Self::ParseSignature
    }

    fn verify(inner: signature::Error) -> Self {
        Self::Verify { inner }
    }
}

/// Returned when none of the candidate keys could verify the signature.
#[derive(Debug, Error, Default)]
#[error("none of the keys worked")]
pub struct NoKeyWorked {
    _inner: (),
}

// ---------------------------------------------------------------------------
// Jwt – accessors and verification
// ---------------------------------------------------------------------------

impl<'a, T> Jwt<'a, T> {
    /// Get the JWT header
    pub fn header(&self) -> &JsonWebSignatureHeader {
        &self.header
    }

    /// Get the JWT payload
    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_owned(self) -> Jwt<'static, T> {
        Jwt {
            raw: self.raw.into_owned(),
            header: self.header,
            payload: self.payload,
            signature: self.signature,
        }
    }

    /// Verify the signature of this JWT using the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify<K, S>(&self, key: &K) -> Result<(), JwtVerificationError>
    where
        K: Verifier<S>,
        S: SignatureEncoding,
    {
        let sig = S::try_from(&self.signature)
            .map_err(JwtVerificationError::parse_signature)?;
        key.verify(self.raw.signed_part().as_bytes(), &sig)
            .map_err(JwtVerificationError::verify)
    }

    /// Verify the signature of this JWT using the given symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or if the algorithm is not
    /// supported.
    pub fn verify_with_shared_secret(&self, secret: Vec<u8>) -> Result<(), NoKeyWorked> {
        let sym_key = crate::jwa::SymmetricKey::new_for_alg(secret, self.header.alg())
            .map_err(|_| NoKeyWorked::default())?;
        self.verify(&sym_key).map_err(|_| NoKeyWorked::default())
    }

    /// Verify the signature of this JWT using the given JWKS.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, if no key matches the
    /// constraints, or if the algorithm is not supported.
    pub fn verify_with_jwks(&self, jwks: &PublicJsonWebKeySet) -> Result<(), NoKeyWorked> {
        let constraint_set = ConstraintSet::from(&self.header);
        let matching_keys = constraint_set.filter(&**jwks);

        for key in matching_keys {
            if let Ok(verifier) = crate::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
                key.params(),
                self.header.alg(),
            ) {
                if self.verify(&verifier).is_ok() {
                    return Ok(());
                }
            }
        }

        Err(NoKeyWorked::default())
    }

    /// Get the raw JWT string as a borrowed [`str`]
    pub fn as_str(&'a self) -> &'a str {
        &self.raw
    }

    /// Get the raw JWT string as an owned [`String`]
    pub fn into_string(self) -> String {
        self.raw.into()
    }

    /// Split the JWT into its parts (header and payload).
    pub fn into_parts(self) -> (JsonWebSignatureHeader, T) {
        (self.header, self.payload)
    }
}

// ---------------------------------------------------------------------------
// Signing errors
// ---------------------------------------------------------------------------

/// Errors that may occur while signing a JWT.
#[derive(Debug, Error)]
pub enum JwtSignatureError {
    #[error("failed to serialize header")]
    EncodeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to serialize payload")]
    EncodePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("failed to sign")]
    Signature {
        #[from]
        inner: signature::Error,
    },
}

impl JwtSignatureError {
    fn encode_header(inner: serde_json::Error) -> Self {
        Self::EncodeHeader { inner }
    }

    fn encode_payload(inner: serde_json::Error) -> Self {
        Self::EncodePayload { inner }
    }
}

// ---------------------------------------------------------------------------
// Jwt – signing (only on 'static lifetime)
// ---------------------------------------------------------------------------

/// Encode a value as JSON then base64url (no padding).
fn json_to_b64url<S: Serialize>(value: &S) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

impl<T> Jwt<'static, T> {
    /// Sign the given payload with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload could not be serialized or if the key
    /// could not sign the payload.
    pub fn sign<K, S>(
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        #[allow(clippy::disallowed_methods)]
        Self::sign_with_rng(&mut thread_rng(), header, payload, key)
    }

    /// Sign the given payload with the given key using the given RNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload could not be serialized or if the key
    /// could not sign the payload.
    pub fn sign_with_rng<R, K, S>(
        rng: &mut R,
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        R: CryptoRngCore,
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        let hdr_b64 = json_to_b64url(&header).map_err(JwtSignatureError::encode_header)?;
        let pay_b64 = json_to_b64url(&payload).map_err(JwtSignatureError::encode_payload)?;

        // Build the signing input: "<header>.<payload>"
        let signing_input = format!("{hdr_b64}.{pay_b64}");
        let first_dot = hdr_b64.len();
        let second_dot = signing_input.len();

        // Produce the cryptographic signature
        let sig_bytes = key.try_sign_with_rng(rng, signing_input.as_bytes())?.to_vec();
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);

        // Assemble the full compact serialisation: "<header>.<payload>.<signature>"
        let mut compact = signing_input;
        compact.reserve_exact(1 + sig_b64.len());
        compact.push('.');
        compact.push_str(&sig_b64);

        let raw = RawJwt::new(compact, first_dot, second_dot);

        Ok(Self {
            raw,
            header,
            payload,
            signature: sig_bytes,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use pasion_iana::jose::JsonWebSignatureAlg;
    use rand::thread_rng;

    use super::*;

    /// A well-known JWT from jwt.io for decode testing.
    const REFERENCE_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn test_jwt_decode() {
        let jwt: Jwt<'_, serde_json::Value> = Jwt::try_from(REFERENCE_JWT).unwrap();

        assert_eq!(jwt.raw.header(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(
            jwt.raw.payload(),
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
        assert_eq!(
            jwt.raw.signature(),
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        assert_eq!(
            jwt.raw.signed_part(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Es256);
        let payload = serde_json::json!({"hello": "world"});

        let signing_key = ecdsa::SigningKey::<p256::NistP256>::random(&mut thread_rng());

        let signed =
            Jwt::sign::<_, ecdsa::Signature<_>>(header, payload, &signing_key).unwrap();

        signed
            .verify::<_, ecdsa::Signature<_>>(signing_key.verifying_key())
            .unwrap();
    }
}
