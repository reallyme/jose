#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used, clippy::panic)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executes the portable `signed-jwt` and `unsigned-jwt` conformance vectors.
//!
//! Positive cases must decode to the expected claims; negative cases must fail
//! closed with the exact `JwtError` variant named in the vector. Regenerate the
//! fixtures with `gen_vectors.rs`.

use serde_json::Value;

use reallyme_jose::jwt::{
    decode_unsigned_jwt, decode_verify_jwt_signature_only,
    decode_verify_jwt_with_temporal_validation, JwtError, JwtTemporalValidationPolicy,
};
use reallyme_jose::Jwk;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn field<'a>(case: &'a Value, key: &str) -> Option<&'a str> {
    case.get(key).and_then(Value::as_str)
}

/// Maps a `JwtError` to the stable string encoding used in the vectors. Temporal
/// variants carry a claim discriminant, encoded as `Variant:Claim`.
fn jwt_error_name(err: &JwtError) -> String {
    match err {
        JwtError::MissingRequiredTemporalClaim(claim) => {
            format!("MissingRequiredTemporalClaim:{claim:?}")
        }
        JwtError::InvalidTemporalClaimValue(claim) => {
            format!("InvalidTemporalClaimValue:{claim:?}")
        }
        other => format!("{other:?}"),
    }
}

fn assert_case(id: &str, result: Result<Value, JwtError>, case: &Value) {
    if let Some(expected) = case.get("expected_claims_json") {
        let decoded = result.unwrap_or_else(|err| panic!("{id}: expected claims, got {err:?}"));
        assert_eq!(&decoded, expected, "{id}: claims mismatch");
    } else if let Some(expected) = field(case, "expected_error") {
        let err = result
            .err()
            .unwrap_or_else(|| panic!("{id}: expected error {expected}, got Ok"));
        assert_eq!(
            jwt_error_name(&err),
            expected,
            "{id}: error variant mismatch"
        );
    } else {
        panic!("{id}: case has neither expected_claims_json nor expected_error");
    }
}

#[test]
fn signed_jwt_vectors_verify_or_fail_closed() {
    let suite: Value =
        serde_json::from_str(include_str!("../../conformance/vectors/signed-jwt.json"))
            .expect("valid signed-jwt vectors");
    let cases = suite["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty());

    for case in cases {
        let id = field(case, "id").expect("id");
        let compact = field(case, "compact").expect("compact");
        let public_key = hex_to_bytes(field(case, "public_key_hex").expect("public_key_hex"));
        let jwk: Jwk =
            serde_json::from_value(case["verification_jwk"].clone()).expect("verification_jwk");

        let result = match case.get("now_unix").and_then(Value::as_u64) {
            Some(now) => {
                let policy = match field(case, "temporal_policy") {
                    Some("strict") | None => JwtTemporalValidationPolicy::strict(),
                    Some(other) => panic!("{id}: unknown temporal_policy {other}"),
                };
                decode_verify_jwt_with_temporal_validation::<Value>(
                    compact,
                    &jwk,
                    &public_key,
                    now,
                    policy,
                )
            }
            None => decode_verify_jwt_signature_only::<Value>(compact, &jwk, &public_key),
        };

        assert_case(id, result, case);
    }
}

#[test]
fn unsigned_jwt_vectors_decode_or_fail_closed() {
    let suite: Value =
        serde_json::from_str(include_str!("../../conformance/vectors/unsigned-jwt.json"))
            .expect("valid unsigned-jwt vectors");
    let cases = suite["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty());

    for case in cases {
        let id = field(case, "id").expect("id");
        let compact = field(case, "compact").expect("compact");
        let result = decode_unsigned_jwt::<Value>(compact);
        assert_case(id, result, case);
    }
}
