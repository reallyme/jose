#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{base_claims_json, gen_p256};
use reallyme_jose::jwt::{decode_verify_jwt_signature_only, encode_signed_jwt, JwtError};

#[test]
fn p256_signed_jwt_roundtrip() {
    let k = gen_p256();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public).unwrap();

    assert_eq!(decoded["sub"], "alice");
}

#[test]
fn p256_rejects_wrong_public_key() {
    let k1 = gen_p256();
    let k2 = gen_p256();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k1.jwk, &k1.private).unwrap();

    let res: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(&jwt, &k2.jwk, &k2.public);

    assert!(res.is_err());
}

#[test]
fn p256_rejects_jwk_public_key_mismatch_before_verification() {
    let k1 = gen_p256();
    let k2 = gen_p256();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k1.jwk, &k1.private).unwrap();

    let err = decode_verify_jwt_signature_only::<serde_json::Value>(&jwt, &k1.jwk, &k2.public)
        .unwrap_err();

    assert!(matches!(err, JwtError::PublicKeyMismatch));
}

#[test]
fn p256_signing_rejects_private_key_that_does_not_match_jwk() {
    let expected = gen_p256();
    let wrong = gen_p256();

    let err = encode_signed_jwt(&base_claims_json(), &expected.jwk, &wrong.private).unwrap_err();

    assert!(matches!(err, JwtError::SigningKeyMismatch));
}
