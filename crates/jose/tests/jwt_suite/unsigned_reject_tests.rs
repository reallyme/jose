#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::jwt::{
    decode_unsigned_jwt, encode_unsigned_jwt, JwtError, RegisteredClaims, MAX_COMPACT_JWT_BYTES,
};

#[test]
fn reject_two_part_jwt() {
    let jwt = "header.payload";
    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(jwt);
    assert!(res.is_err());
}

#[test]
fn reject_four_part_jwt() {
    let jwt = "a.b.c.d";
    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(jwt);
    assert!(res.is_err());
}

#[test]
fn reject_unsigned_with_alg_not_none() {
    let jwt = format!(
        "{}.{}.",
        bytes_to_base64url(br#"{"alg":"ES256","typ":"JWT"}"#),
        bytes_to_base64url(br#"{}"#),
    );

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);
    assert!(res.is_err());
}

#[test]
fn reject_unsigned_with_typ_not_jwt() {
    let jwt = format!(
        "{}.{}.",
        bytes_to_base64url(br#"{"alg":"none","typ":"JWS"}"#),
        bytes_to_base64url(br#"{}"#),
    );

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);
    assert!(res.is_err());
}

#[test]
fn reject_unsigned_with_duplicate_header_member() {
    let jwt = format!(
        "{}.{}.",
        bytes_to_base64url(br#"{"alg":"ES256","alg":"none","typ":"JWT"}"#),
        bytes_to_base64url(br#"{}"#),
    );

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);

    assert!(matches!(res, Err(JwtError::InvalidJwtFormat)));
}

#[test]
fn reject_unsigned_with_critical_header_parameter() {
    let jwt = format!(
        "{}.{}.",
        bytes_to_base64url(br#"{"alg":"none","typ":"JWT","crit":["exp"]}"#),
        bytes_to_base64url(br#"{}"#),
    );

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);

    assert!(matches!(res, Err(JwtError::InvalidJwtFormat)));
}

#[test]
fn reject_unsigned_with_duplicate_claim_member() {
    let jwt = format!(
        "{}.{}.",
        bytes_to_base64url(br#"{"alg":"none","typ":"JWT"}"#),
        bytes_to_base64url(br#"{"sub":"alice","sub":"bob"}"#),
    );

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);

    assert!(matches!(res, Err(JwtError::InvalidJwtFormat)));
}

#[test]
fn reject_invalid_base64url_segment() {
    let jwt = "!!!.e30.";
    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(jwt);
    assert!(res.is_err());
}

#[test]
fn reject_unsigned_jwt_over_size_limit() {
    let len = MAX_COMPACT_JWT_BYTES.checked_add(1).unwrap();
    let jwt = "a".repeat(len);

    let res: Result<RegisteredClaims, _> = decode_unsigned_jwt(&jwt);

    assert!(matches!(res, Err(JwtError::InputTooLarge)));
}

#[test]
fn reject_unsigned_jwt_encoding_over_size_limit() {
    let claims = serde_json::json!({"data": "a".repeat(800_000)});

    let err = encode_unsigned_jwt(&claims).unwrap_err();

    assert!(matches!(err, JwtError::InputTooLarge));
}
