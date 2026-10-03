#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
#![allow(dead_code)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::{generate_keypair, sign};
use reallyme_crypto::jwk::{Jwk, JwkOptions};

use reallyme_crypto::jwk::{
    ed25519_public_key_to_jwk, p256_public_key_to_jwk, secp256k1_public_key_to_jwk,
};

#[derive(Debug)]
pub struct TestKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
    pub jwk: Jwk,
}

pub fn gen_ed25519() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();

    let jwk = ed25519_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-ed".into()),
        },
    )
    .unwrap();

    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Okp(jwk.into()),
    }
}

pub fn gen_p256() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();

    let jwk = p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-p256".into()),
        },
    )
    .unwrap();

    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}

pub fn gen_secp256k1() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Secp256k1).unwrap();

    let jwk = secp256k1_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-k1".into()),
        },
    )
    .unwrap();

    TestKey {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}

pub fn base_claims_json() -> serde_json::Value {
    serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "aud": "example",
    })
}

pub fn sign_raw_ed25519_jwt_claims(private_key: &[u8], claims: &serde_json::Value) -> String {
    let header = bytes_to_base64url(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = bytes_to_base64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = sign(Algorithm::Ed25519, private_key, signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}", bytes_to_base64url(&signature))
}
