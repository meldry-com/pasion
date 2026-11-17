# RustCrypto security migration

Pasion uses RSA 0.10 and the 0.14 elliptic-curve family, with crypto-bigint
0.7.11. These replace the affected arithmetic described by
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) and
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The coordinated signature, digest, HMAC and key-format dependencies use their
supported current APIs. No vulnerable arithmetic implementation is retained for
compatibility, and these advisories are not waived.

All 14 existing JWT algorithms remain supported: HS256/384/512,
RS256/384/512, PS256/384/512, ES256/384/512/256K and EdDSA/Ed25519.
RSA-PSS retains digest-length salt; ECDSA retains the JWS fixed-width R||S
encoding (ES512 uses 132 bytes) and its existing hash choices.

## Existing keys and tokens

The upgrade does not rewrite, regenerate, rotate or delete configured keys.
Existing strong RSA, NIST EC, secp256k1 and Ed25519 PEM, DER, PKCS#8, SEC1,
SPKI and JWK fixtures retain their identities and remain readable/writable.
Encrypted PKCS#8 files continue to import with their existing passwords.
Regression tests verify tokens issued before this upgrade against their old
stored keys, rather than testing only newly generated key round trips.

RSA imports have an explicit, public modulus-width policy using the supported
`from_components_with_wide_primes` constructor. This preserves valid legacy
unbalanced factors without probing a secret prime's width and selecting a
different implementation. The wider CRT storage can increase private-operation
cost relative to the new library's balanced-factor default; this compatibility
choice makes no throughput claim. PKCS#1 multiprime import remains rejected,
as before. Private JWK `oth` multiprime import remains supported and tested.

RSA keys below 1024 bits now fail with `ModulusTooSmall`. This follows the new
library's public-key minimum and is an intentional compatibility boundary;
affected administrators must review their keys explicitly. Pasion never replaces
them automatically. [RFC 7518 sections 3.3 and 3.5](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
require at least 2048 bits for RS/PS JWT use. New Pasion configuration generation
continues to generate 2048-bit RSA keys. The obsolete 512-bit test-only key was
replaced with a fixed 2048-bit fixture and retained as a rejection test.

The business-facing rand_core 0.6 generator interface remains available through
a narrow adapter into the current RustCrypto traits. It forwards the caller's
entropy without reseeding or deriving a replacement key. Production configuration
generation seeds its CSPRNG from system entropy and persists the resulting PEM;
it does not restore a stable production identity from a public deterministic seed.

## Signature changes and independent validation

P-521 0.13 sampled its signing nonce directly from the RNG. P-521 0.14 uses
ECDSA 0.17's RFC6979 nonce with fresh additional entropy. Consequently a seeded
ES512 signing test produces different valid signature bytes. The hash remains
SHA-512, P-521 does not enable low-S normalization, and previously issued tokens
remain valid. Only the new-signature snapshot changes; the old JWT vectors remain.
See the [old P-521 source](https://docs.rs/crate/p521/0.13.3/source/src/ecdsa.rs)
and [current ECDSA source](https://docs.rs/ecdsa/0.17.0/src/ecdsa/signing.rs.html).

Run `python3 crates/jose/tests/openssl_compat.py` after the Rust tests. OpenSSL 3
independently verifies 14 legacy JWTs and 11 current signing snapshots, checks
ECDSA signature widths, and rejects each corresponding tampered signature.
The same check runs in CI. Rust regressions additionally cover old private-key
snapshots, SPKI/JWK identity, encrypted inputs, unbalanced and multiprime import
boundaries, and incorrect HMAC tags and lengths.

HMAC verification now uses the maintained MAC implementation's `verify_slice`
instead of a general vector equality comparison. This removes the previous
non-constant-time comparison; no claim is made that a remote exploit was proven.

## Maintained dependency paths

YAML configuration and CLI export now use serde-saphyr, including its real
Figment provider. Generated configuration is exported and reloaded through that
provider in a regression test. Tokio SMTP and sendmail functionality remains
enabled; the pinned lettre change removes an accidental inactive async-std
feature path. The Prometheus exporter uses a maintained compact label buffer.
Both temporary upstream pins reference exact tested commits, with upstream
changes tracked in the pull request. Salvo and salvo_core remain pinned to 1.0.1
to preserve encoded Matrix paths.
