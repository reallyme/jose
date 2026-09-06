#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_jose::jwt::{
    decode_unsigned_jwt, encode_unsigned_jwt, NumericDate, RegisteredClaims, StringOrURI,
};

#[test]
fn unsigned_jwt_roundtrip() {
    let claims = RegisteredClaims {
        iss: Some(StringOrURI("https://issuer.example".into())),
        sub: Some(StringOrURI("did:example:123".into())),
        aud: None,
        exp: Some(NumericDate::new(1_700_000_000)),
        nbf: None,
        iat: None,
        jti: None,
    };

    let jwt = encode_unsigned_jwt(&claims).unwrap();
    let decoded: RegisteredClaims = decode_unsigned_jwt(&jwt).unwrap();

    assert_eq!(claims, decoded);
}

#[test]
fn unsigned_jwt_size_preflight_preserves_boundary() {
    let claims = serde_json::json!({"sub": "a".repeat(786_394)});
    let compact = encode_unsigned_jwt(&claims).unwrap();
    assert_eq!(compact.len(), reallyme_jose::jwt::MAX_COMPACT_JWT_BYTES);
    let decoded: serde_json::Value = decode_unsigned_jwt(&compact).unwrap();
    assert_eq!(decoded, claims);
    let too_large = serde_json::json!({"sub": "a".repeat(786_395)});
    assert!(matches!(
        encode_unsigned_jwt(&too_large),
        Err(reallyme_jose::jwt::JwtError::InputTooLarge)
    ));
}
