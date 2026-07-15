#![allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::panic,
    clippy::unwrap_used
)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executes the portable `jws-compact` conformance vectors.
//!
//! Positive cases must verify; negative cases must fail closed with the exact
//! error variant named in the checked-in fixture. Fixture changes must remain
//! explicit and independently reviewable.

use serde_json::Value;

use reallyme_jose::jws::suites::eddsa::verify_eddsa_jws;
use reallyme_jose::jws::suites::es256::verify_es256_jws;

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

#[test]
fn jws_compact_vectors_verify_or_fail_closed() {
    let suite: Value =
        serde_json::from_str(include_str!("../../conformance/vectors/jws-compact.json"))
            .expect("valid jws-compact vectors");
    let cases = suite["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty());

    for case in cases {
        let id = field(case, "id").expect("id");
        let alg = field(case, "alg").expect("alg");
        let compact = field(case, "compact").expect("compact");
        let public_key = hex_to_bytes(field(case, "public_key_hex").expect("public_key_hex"));

        let (result, actual_error): (Result<(), ()>, Option<String>) = match alg {
            "ES256" => match verify_es256_jws(compact, &public_key) {
                Ok(()) => (Ok(()), None),
                Err(err) => (Err(()), Some(format!("{err:?}"))),
            },
            "EdDSA" => match verify_eddsa_jws(compact, &public_key) {
                Ok(()) => (Ok(()), None),
                Err(err) => (Err(()), Some(format!("{err:?}"))),
            },
            other => panic!("{id}: unexpected alg {other}"),
        };

        if case.get("expected_valid").and_then(Value::as_bool) == Some(true) {
            assert!(result.is_ok(), "{id}: expected valid, got {actual_error:?}");
        } else if let Some(expected) = field(case, "expected_error") {
            assert!(result.is_err(), "{id}: expected error {expected}, got Ok");
            assert_eq!(
                actual_error.as_deref(),
                Some(expected),
                "{id}: error variant mismatch"
            );
        } else {
            panic!("{id}: case has neither expected_valid nor expected_error");
        }
    }
}
