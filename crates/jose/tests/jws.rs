static HS256_JWT: &str = include_str!("./jwts/hs256.jwt");
static HS384_JWT: &str = include_str!("./jwts/hs384.jwt");
static HS512_JWT: &str = include_str!("./jwts/hs512.jwt");
static RS256_JWT: &str = include_str!("./jwts/rs256.jwt");
static RS384_JWT: &str = include_str!("./jwts/rs384.jwt");
static RS512_JWT: &str = include_str!("./jwts/rs512.jwt");
static PS256_JWT: &str = include_str!("./jwts/ps256.jwt");
static PS384_JWT: &str = include_str!("./jwts/ps384.jwt");
static PS512_JWT: &str = include_str!("./jwts/ps512.jwt");
static ES256_JWT: &str = include_str!("./jwts/es256.jwt");
static ES384_JWT: &str = include_str!("./jwts/es384.jwt");
static ES512_JWT: &str = include_str!("./jwts/es512.jwt");
static ES256K_JWT: &str = include_str!("./jwts/es256k.jwt");
static EDDSA_ED25519_JWT: &str = include_str!("./jwts/eddsa-ed25519.jwt");
static EDDSA_ED448_JWT: &str = include_str!("./jwts/eddsa-ed448.jwt");
static OCT_KEY: &[u8] = include_bytes!("./keys/oct.bin");

fn public_jwks() -> pasion_jose::jwk::PublicJsonWebKeySet {
    serde_json::from_str(include_str!("./keys/jwks.pub.json")).unwrap()
}

fn private_jwks() -> pasion_jose::jwk::PrivateJsonWebKeySet {
    serde_json::from_str(include_str!("./keys/jwks.priv.json")).unwrap()
}

fn oct_key() -> Vec<u8> {
    OCT_KEY.to_vec()
}

#[test]
fn hmac_rejects_incorrect_tags_and_lengths() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use pasion_iana::jose::JsonWebSignatureAlg;
    use pasion_jose::{
        jwa::SymmetricKey,
        jwt::{JsonWebSignatureHeader, Jwt},
    };

    for alg in [
        JsonWebSignatureAlg::Hs256,
        JsonWebSignatureAlg::Hs384,
        JsonWebSignatureAlg::Hs512,
    ] {
        let key = SymmetricKey::new_for_alg(oct_key(), &alg).unwrap();
        let jwt = Jwt::sign(JsonWebSignatureHeader::new(alg), "payload", &key).unwrap();
        jwt.verify(&key).unwrap();
        let (prefix, encoded) = jwt.as_str().rsplit_once('.').unwrap();
        let tag = Base64UrlUnpadded::decode_vec(encoded).unwrap();
        let mut bad = tag.clone();
        bad[0] ^= 1;
        let mut long = tag.clone();
        long.push(0);
        for invalid in [bad, Vec::new(), tag[..tag.len() - 1].to_vec(), long] {
            let token = format!("{prefix}.{}", Base64UrlUnpadded::encode_string(&invalid));
            if let Ok(parsed) = Jwt::<'_, String>::try_from(token.as_str()) {
                assert!(parsed.verify(&key).is_err());
            }
        }
    }
}

#[test]
fn multiprime_private_jwk_keeps_its_existing_support() {
    use pasion_iana::jose::JsonWebSignatureAlg;
    use pasion_jose::{
        jwa::{AsymmetricSigningKey, AsymmetricVerifyingKey},
        jwk::{JsonWebKeyPrivateParameters, JsonWebKeyPublicParameters},
        jwt::{JsonWebSignatureHeader, Jwt},
    };
    let private: JsonWebKeyPrivateParameters =
        serde_json::from_str(include_str!("keys/rsa.multiprime.jwk.json")).unwrap();
    let public = JsonWebKeyPublicParameters::try_from(private.clone()).unwrap();
    for alg in [
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Ps256,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps512,
    ] {
        let signer = AsymmetricSigningKey::from_jwk_and_alg(&private, &alg).unwrap();
        let verifier = AsymmetricVerifyingKey::from_jwk_and_alg(&public, &alg).unwrap();
        let jwt = Jwt::sign(
            JsonWebSignatureHeader::new(alg),
            "legacy multiprime",
            &signer,
        )
        .unwrap();
        jwt.verify(&verifier).unwrap();
    }
}

#[test]
fn legacy_spki_public_keys_keep_their_identity() {
    use elliptic_curve::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
    use pasion_jose::jwk::{JsonWebKeyPublicParameters, Thumbprint};
    macro_rules! roundtrip {
        ($key:ty, $fixture:literal) => {
            let pem = include_str!(concat!("keys/", $fixture, ".pub.pem"));
            let key = <$key>::from_public_key_pem(pem).unwrap();
            let public = JsonWebKeyPublicParameters::from(key.clone());
            let restored =
                <$key>::from_public_key_der(key.to_public_key_der().unwrap().as_bytes()).unwrap();
            assert_eq!(
                public.thumbprint_sha256(),
                JsonWebKeyPublicParameters::from(restored).thumbprint_sha256()
            );
            assert_eq!(&*key.to_public_key_pem(LineEnding::LF).unwrap(), pem);
        };
    }
    roundtrip!(rsa::PublicKey, "rsa");
    roundtrip!(p256::PublicKey, "p256");
    roundtrip!(p384::PublicKey, "p384");
    roundtrip!(p521::PublicKey, "p521");
    roundtrip!(k256::PublicKey, "k256");
    roundtrip!(ed25519_dalek::VerifyingKey, "ed25519");
}

#[test]
fn obsolete_512_bit_rsa_jwks_are_rejected_by_both_key_paths() {
    use pasion_iana::jose::JsonWebSignatureAlg;
    use pasion_jose::{
        jwa::{AsymmetricKeyFromJwkError, AsymmetricSigningKey, AsymmetricVerifyingKey},
        jwk::{JsonWebKeyPrivateParameters, JsonWebKeyPublicParameters},
    };
    let private: JsonWebKeyPrivateParameters =
        serde_json::from_str(include_str!("keys/rsa.legacy512.jwk.json")).unwrap();
    let public = JsonWebKeyPublicParameters::try_from(private.clone()).unwrap();
    for alg in [JsonWebSignatureAlg::Rs256, JsonWebSignatureAlg::Ps256] {
        assert!(matches!(
            AsymmetricSigningKey::from_jwk_and_alg(&private, &alg),
            Err(AsymmetricKeyFromJwkError::Rsa {
                inner: rsa::Error::ModulusTooSmall
            })
        ));
        assert!(matches!(
            AsymmetricVerifyingKey::from_jwk_and_alg(&public, &alg),
            Err(AsymmetricKeyFromJwkError::Rsa {
                inner: rsa::Error::ModulusTooSmall
            })
        ));
    }
}

#[test]
fn signing_propagates_random_generator_failure() {
    use pasion_iana::jose::JsonWebSignatureAlg;
    use pasion_jose::{
        jwa::AsymmetricSigningKey,
        jwt::{JsonWebSignatureHeader, Jwt},
    };
    struct Failing;
    impl rand_chacha::rand_core::RngCore for Failing {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy read")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy read")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible entropy read")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
            Err(rand_chacha::rand_core::Error::new("test entropy failure"))
        }
    }
    impl rand_chacha::rand_core::CryptoRng for Failing {}
    let keys = private_jwks();
    let reference: Jwt<'_, Payload> = Jwt::try_from(PS256_JWT).unwrap();
    let params = keys.find_key(&reference.header().into()).unwrap();
    let signer =
        AsymmetricSigningKey::from_jwk_and_alg(params.params(), &JsonWebSignatureAlg::Ps256)
            .unwrap();
    assert!(
        Jwt::sign_with_rng(
            &mut Failing,
            JsonWebSignatureHeader::new(JsonWebSignatureAlg::Ps256),
            "payload",
            &signer
        )
        .is_err()
    );
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Payload {
    hello: String,
}

macro_rules! conditional {
    { true => $($tt:tt)* } => {
        $($tt)*
    };
    { false => $($tt:tt)* } => {};
}

macro_rules! asymetric_jwt_test {
    ($test_name:ident, $alg:ident, $jwt:ident) => {
        asymetric_jwt_test!($test_name, $alg, $jwt, supported = true);
    };
    ($test_name:ident, $alg:ident, $jwt:ident, supported = $supported:ident) => {
        mod $test_name {
            use std::ops::Deref;

            use pasion_iana::jose::JsonWebSignatureAlg;
            use pasion_jose::{constraints::ConstraintSet, jwt::Jwt};

            use super::*;

            #[test]
            fn validate_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                assert_eq!(jwt.payload().hello, "world");
                assert_eq!(*jwt.header().alg(), JsonWebSignatureAlg::$alg);
            }

            #[test]
            fn find_public_key() {
                let jwks = public_jwks();
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                let constraints = ConstraintSet::from(jwt.header());
                let candidates = constraints.filter(jwks.deref());
                assert_eq!(candidates.len(), 1);
            }

            #[test]
            fn find_private_key() {
                let jwks = private_jwks();
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                let constraints = ConstraintSet::from(jwt.header());
                let candidates = constraints.filter(jwks.deref());
                assert_eq!(candidates.len(), 1);
            }

            conditional! { $supported =>
                use pasion_jose::jwt::JsonWebSignatureHeader;
                use rand_chacha::ChaCha8Rng;
                use rand_chacha::rand_core::SeedableRng;

                #[test]
                fn verify_jwt() {
                    let jwks = public_jwks();
                    let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let key = jwks.find_key(&jwt.header().into()).unwrap();

                    let key = pasion_jose::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
                        key.params(),
                        &JsonWebSignatureAlg::$alg,
                    )
                    .unwrap();

                    jwt.verify(&key).unwrap();
                }

                #[test]
                fn sign_jwt() {
                    let mut rng = ChaCha8Rng::seed_from_u64(42);
                    let alg = JsonWebSignatureAlg::$alg;
                    let payload = Payload {
                        hello: "world".to_owned(),
                    };
                    let header = JsonWebSignatureHeader::new(alg.clone());
                    let template: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let jwks = private_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key = pasion_jose::jwa::AsymmetricSigningKey::from_jwk_and_alg(key.params(), &alg)
                        .unwrap();

                    let jwt: Jwt<'_, Payload> = Jwt::sign_with_rng(&mut rng, header, payload, &key).unwrap();
                    insta::assert_snapshot!(jwt.as_str());
                }

                #[test]
                fn sign_and_verify_jwt() {
                    let alg = JsonWebSignatureAlg::$alg;
                    let payload = Payload {
                        hello: "world".to_owned(),
                    };
                    let header = JsonWebSignatureHeader::new(alg.clone());
                    let template: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let jwks = private_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key = pasion_jose::jwa::AsymmetricSigningKey::from_jwk_and_alg(key.params(), &alg)
                        .unwrap();

                    let jwt: Jwt<'_, Payload> = Jwt::sign(header, payload, &key).unwrap();
                    let jwt: Jwt<'_, Payload> = Jwt::try_from(jwt.as_str()).unwrap();

                    let jwks = public_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key =
                        pasion_jose::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(key.params(), &alg)
                            .unwrap();

                    jwt.verify(&key).unwrap();
                }
            }
        }
    };
}

macro_rules! symetric_jwt_test {
    ($test_name:ident, $alg:ident, $jwt:ident) => {
        mod $test_name {
            use pasion_iana::jose::JsonWebSignatureAlg;
            use pasion_jose::jwt::{JsonWebSignatureHeader, Jwt};

            use super::*;

            #[test]
            fn validate_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                assert_eq!(jwt.payload().hello, "world");
                assert_eq!(*jwt.header().alg(), JsonWebSignatureAlg::$alg);
            }

            #[test]
            fn verify_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                let key = pasion_jose::jwa::SymmetricKey::new_for_alg(
                    oct_key(),
                    &JsonWebSignatureAlg::$alg,
                )
                .unwrap();
                jwt.verify(&key).unwrap();
            }

            #[test]
            fn sign_and_verify_jwt() {
                let alg = JsonWebSignatureAlg::$alg;
                let payload = Payload {
                    hello: "world".to_owned(),
                };
                let header = JsonWebSignatureHeader::new(alg.clone());

                let key = pasion_jose::jwa::SymmetricKey::new_for_alg(oct_key(), &alg).unwrap();

                let jwt: Jwt<'_, Payload> = Jwt::sign(header, payload, &key).unwrap();
                let jwt: Jwt<'_, Payload> = Jwt::try_from(jwt.as_str()).unwrap();

                jwt.verify(&key).unwrap();
            }
        }
    };
}

symetric_jwt_test!(hs256, Hs256, HS256_JWT);
symetric_jwt_test!(hs384, Hs384, HS384_JWT);
symetric_jwt_test!(hs512, Hs512, HS512_JWT);

asymetric_jwt_test!(rs256, Rs256, RS256_JWT);
asymetric_jwt_test!(rs384, Rs384, RS384_JWT);
asymetric_jwt_test!(rs512, Rs512, RS512_JWT);
asymetric_jwt_test!(ps256, Ps256, PS256_JWT);
asymetric_jwt_test!(ps384, Ps384, PS384_JWT);
asymetric_jwt_test!(ps512, Ps512, PS512_JWT);
asymetric_jwt_test!(es256, Es256, ES256_JWT);
asymetric_jwt_test!(es384, Es384, ES384_JWT);
asymetric_jwt_test!(es512, Es512, ES512_JWT);
asymetric_jwt_test!(es256k, Es256K, ES256K_JWT);
asymetric_jwt_test!(eddsa_ed25519, EdDsa, EDDSA_ED25519_JWT);
asymetric_jwt_test!(eddsa_ed448, EdDsa, EDDSA_ED448_JWT, supported = false);

#[test]
fn test_private_to_public_jwks() {
    let priv_jwks = private_jwks();
    let pub_jwks = pasion_jose::jwk::PublicJsonWebKeySet::from(priv_jwks);

    assert_eq!(pub_jwks, public_jwks());
}
