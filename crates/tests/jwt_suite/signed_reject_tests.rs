#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{base_claims_json, gen_ed25519, gen_p256, gen_secp256k1};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jws::suites::es256::sign_p256_jose_prehash;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only, encode_signed_jwt, JwtError, MAX_COMPACT_JWT_BYTES,
};

#[test]
fn reject_non_three_part_jwt() {
    let k = gen_ed25519();
    let jwt = "a.b";

    let res: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(jwt, &k.jwk, &k.public);

    assert!(res.is_err());
}

#[test]
fn reject_invalid_base64url_segments() {
    let k = gen_ed25519();
    let jwt = "!!!.!!!.!!!";

    let res: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(jwt, &k.jwk, &k.public);

    assert!(res.is_err());
}

#[test]
fn reject_signed_jwt_over_size_limit() {
    let k = gen_ed25519();
    let len = MAX_COMPACT_JWT_BYTES.checked_add(1).unwrap();
    let jwt = "a".repeat(len);

    let res: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(res, Err(JwtError::InputTooLarge)));
}

#[test]
fn reject_signed_jwt_with_trailing_compact_segment() {
    let k = gen_ed25519();
    let claims = base_claims_json();
    let jwt = format!(
        "{}.extra",
        encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap()
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidJwtFormat)));
}

#[test]
fn reject_signed_jwt_with_padded_base64url_header() {
    let k = gen_ed25519();
    let claims = base_claims_json();
    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();
    let mut parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let padded_header = format!("{}=", parts[0]);
    parts[0] = padded_header.as_str();
    let padded = parts.join(".");

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&padded, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::Base64Url)));
}

#[test]
fn reject_signed_jwt_with_missing_alg_header() {
    let k = gen_p256();
    let jwt = signed_jwt_with_header(
        br#"{"typ":"JWT"}"#,
        br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#,
        &k.private,
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

#[test]
fn reject_signed_jwt_with_alg_none_header() {
    let k = gen_p256();
    let jwt = signed_jwt_with_header(
        br#"{"alg":"none","typ":"JWT"}"#,
        br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#,
        &k.private,
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

#[test]
fn reject_jwt_when_header_alg_differs_from_jwk_alg() {
    let k = gen_p256();
    let expected_key = gen_secp256k1();
    let claims = base_claims_json();
    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &expected_key.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::AlgorithmMismatch)));
}

#[test]
fn reject_jwt_when_jwk_curve_and_alg_disagree() {
    let k = gen_p256();
    let claims = base_claims_json();
    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();
    let mut inconsistent_jwk = k.jwk.clone();

    if let Jwk::Ec(jwk) = &mut inconsistent_jwk {
        jwk.alg = Some("ES256K".to_owned());
    }

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &inconsistent_jwk, &k.public);

    assert!(matches!(result, Err(JwtError::UnsupportedAlgorithm)));
}

#[test]
fn reject_jwt_when_jwk_alg_is_missing() {
    let k = gen_p256();
    let claims = base_claims_json();
    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();
    let mut missing_alg_jwk = k.jwk.clone();

    if let Jwk::Ec(jwk) = &mut missing_alg_jwk {
        jwk.alg = None;
    }

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &missing_alg_jwk, &k.public);

    assert!(matches!(result, Err(JwtError::MissingAlgorithm)));
}

#[test]
fn reject_signed_jwt_with_duplicate_protected_header_members() {
    let k = gen_p256();
    let header = bytes_to_base64url(br#"{"alg":"ES256","alg":"ES256","typ":"JWT"}"#);
    let payload = bytes_to_base64url(br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#);
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&k.private, signing_input.as_bytes()).unwrap();
    let jwt = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

#[test]
fn reject_signed_jwt_with_untrusted_embedded_jwk_header() {
    let k = gen_p256();
    let jwt = signed_jwt_with_header(
        br#"{"alg":"ES256","typ":"JWT","jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}"#,
        br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#,
        &k.private,
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

#[test]
fn reject_signed_jwt_with_untrusted_x5c_header() {
    let k = gen_p256();
    let jwt = signed_jwt_with_header(
        br#"{"alg":"ES256","typ":"JWT","x5c":["AA"]}"#,
        br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#,
        &k.private,
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

#[test]
fn reject_signed_jwt_with_unsupported_crit_header() {
    let k = gen_p256();
    let header = bytes_to_base64url(br#"{"alg":"ES256","typ":"JWT","crit":["exp"]}"#);
    let payload = bytes_to_base64url(br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#);
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&k.private, signing_input.as_bytes()).unwrap();
    let jwt = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}

fn signed_jwt_with_header(header_json: &[u8], payload_json: &[u8], private_key: &[u8]) -> String {
    let header = bytes_to_base64url(header_json);
    let payload = bytes_to_base64url(payload_json);
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(private_key, signing_input.as_bytes()).unwrap();

    format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    )
}

#[test]
fn reject_signed_jwt_with_b64_header_parameter() {
    let k = gen_p256();
    let header = bytes_to_base64url(br#"{"alg":"ES256","typ":"JWT","b64":false}"#);
    let payload = bytes_to_base64url(br#"{"iss":"did:me:test","sub":"alice","aud":"example"}"#);
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&k.private, signing_input.as_bytes()).unwrap();
    let jwt = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let result: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);

    assert!(matches!(result, Err(JwtError::InvalidHeader)));
}
