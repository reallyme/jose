#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{base_claims_json, gen_ed25519};
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only, decode_verify_jwt_signature_only_with_header_validation,
    encode_signed_jwt_with_header_options, JwtError, JwtHeaderEncodeOptions,
    JwtHeaderValidationOptions,
};

#[test]
fn can_encode_and_decode_custom_typ_when_policy_allows_it() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("encode");

    let decoded: serde_json::Value = decode_verify_jwt_signature_only_with_header_validation(
        &jwt,
        &k.jwk,
        &k.public,
        &JwtHeaderValidationOptions::new(false, false, &["dc+sd-jwt"]),
    )
    .expect("decode");

    assert_eq!(decoded["iss"], "did:me:test");
}

#[test]
fn signed_jwt_carries_jwk_key_id() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::jwt(),
    )
    .expect("encode");
    let protected = jwt.split('.').next().expect("protected header");
    let protected_json = base64url_to_bytes(protected).expect("protected header base64url");
    let protected_value: serde_json::Value =
        serde_json::from_slice(&protected_json).expect("protected header json");

    assert_eq!(protected_value["kid"], "k-ed");
}

#[test]
fn standard_policy_rejects_non_jwt_typ() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);
    assert!(decoded.is_err());
}

#[test]
fn can_require_typ_presence() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(None),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only_with_header_validation(
            &jwt,
            &k.jwk,
            &k.public,
            &JwtHeaderValidationOptions::new(false, false, &["JWT"]),
        );

    assert!(decoded.is_err());
}

#[test]
fn empty_accepted_typ_values_rejects_present_typ() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::jwt(),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only_with_header_validation(
            &jwt,
            &k.jwk,
            &k.public,
            &JwtHeaderValidationOptions::new(true, false, &[]),
        );

    assert!(matches!(decoded, Err(JwtError::InvalidHeader)));
}
