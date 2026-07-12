#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{base_claims_json, gen_secp256k1};
use reallyme_jose::jwt::{decode_verify_jwt_signature_only, encode_signed_jwt};

#[test]
fn secp256k1_signed_jwt_roundtrip() {
    let k = gen_secp256k1();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public).unwrap();

    assert_eq!(decoded["aud"], "example");
}

#[test]
fn secp256k1_rejects_modified_header() {
    let k = gen_secp256k1();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);

    let bad_header =
        reallyme_codec::base64url::bytes_to_base64url(br#"{"alg":"ES256K","typ":"JWS"}"#);

    let tampered = format!("{}.{}.{}", bad_header, parts[1], parts[2]);

    let res: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(&tampered, &k.jwk, &k.public);

    assert!(res.is_err());
}
