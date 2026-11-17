#!/usr/bin/env python3
"""Independently verify old JWT fixtures and current Rust signing snapshots.

Run after `cargo test -p pasion-jose`; requires OpenSSL 3 on PATH. No external
service is contacted. Temporary files contain public signatures/messages only.
"""

import base64
import hmac
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
EC_WIDTH = {"ES256": 64, "ES384": 96, "ES512": 132, "ES256K": 64}
EC_KEYS = {"ES256": "p256", "ES384": "p384", "ES512": "p521", "ES256K": "k256"}
HASH = {"256": "sha256", "384": "sha384", "512": "sha512", "256K": "sha256"}


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def der_length(size):
    if size < 128:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([128 | len(encoded)]) + encoded


def ec_der(raw, alg):
    assert len(raw) == EC_WIDTH[alg], (alg, len(raw))
    half = len(raw) // 2
    parts = []
    for value in (raw[:half], raw[half:]):
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 128:
            value = b"\0" + value
        parts.append(b"\x02" + der_length(len(value)) + value)
    body = b"".join(parts)
    return b"\x30" + der_length(len(body)) + body


def verify(token, directory, tampered=False):
    header, payload, signature = token.strip().split(".")
    alg = json.loads(decode(header))["alg"]
    message = f"{header}.{payload}".encode("ascii")
    raw = decode(signature)
    if tampered:
        raw = bytes([raw[0] ^ 1]) + raw[1:]
    message_path = directory / "message"
    signature_path = directory / "signature"
    message_path.write_bytes(message)
    if alg.startswith("HS"):
        result = subprocess.run(
            ["openssl", "dgst", f"-{HASH[alg[2:]]}", "-mac", "HMAC", "-macopt",
             "hexkey:" + (ROOT / "keys/oct.bin").read_bytes().hex(), "-binary", str(message_path)],
            check=True, capture_output=True,
        )
        accepted = hmac.compare_digest(result.stdout, raw)
    else:
        if alg.startswith("ES"):
            signature_path.write_bytes(ec_der(raw, alg))
            key_name = EC_KEYS[alg]
        else:
            signature_path.write_bytes(raw)
            key_name = "ed25519" if alg == "EdDSA" else "rsa"
        public_key = str(ROOT / f"keys/{key_name}.pub.pem")
        if alg == "EdDSA":
            assert len(raw) == 64
            args = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
                    public_key, "-sigfile", str(signature_path), "-in", str(message_path)]
        else:
            args = ["openssl", "dgst", f"-{HASH[alg[2:]]}", "-verify", public_key,
                    "-signature", str(signature_path)]
            if alg.startswith("PS"):
                args += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest"]
            args.append(str(message_path))
        accepted = subprocess.run(args, capture_output=True).returncode == 0
    assert accepted != tampered, (alg, "tampered" if tampered else "valid")


def main():
    # Ed448 was already unsupported by Pasion and has no implementation here.
    old = [p.read_text() for p in sorted((ROOT / "jwts").glob("*.jwt"))
           if p.name != "eddsa-ed448.jwt"]
    current = [p.read_text().split("\n---\n", 1)[1].strip()
               for p in sorted((ROOT / "snapshots").glob("jws__*__sign_jwt.snap"))]
    assert len(old) == 14 and len(current) == 11, (len(old), len(current))
    with tempfile.TemporaryDirectory(prefix="pasion-jws-openssl-") as tmp:
        for token in old + current:
            verify(token, Path(tmp))
            verify(token, Path(tmp), tampered=True)
    print("OpenSSL compatibility: 14 legacy JWTs + 11 current signatures verified; 25 tampered signatures rejected")


if __name__ == "__main__":
    main()
