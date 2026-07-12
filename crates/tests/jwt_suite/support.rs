#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
#![allow(dead_code)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;
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
