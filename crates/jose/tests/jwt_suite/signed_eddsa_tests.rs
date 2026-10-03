#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{base_claims_json, gen_ed25519};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jwt::{decode_verify_jwt_signature_only, encode_signed_jwt, JwtError};

#[test]
fn ed25519_signed_jwt_roundtrip() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public).unwrap();

    assert_eq!(decoded["iss"], "did:me:test");
}

#[test]
fn ed25519_identity_jwk_fails_with_typed_public_key_error() {
    let key = gen_ed25519();
    let jwt = encode_signed_jwt(&base_claims_json(), &key.jwk, &key.private).unwrap();
    let mut jwk = key.jwk;
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    if let Jwk::Okp(ref mut value) = jwk {
        value.x = bytes_to_base64url(&identity);
    }

    assert!(matches!(
        decode_verify_jwt_signature_only::<serde_json::Value>(&jwt, &jwk, &key.public),
        Err(JwtError::InvalidPublicKey)
    ));
}
