// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Differential coverage for every canonical JWS verification wire entrypoint.

#![cfg(feature = "wire")]
#![allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use buffa::EnumValue;
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_crypto::csprng::SecureRandom;
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_jose::jws::suites::es256::sign_p256_jose_prehash;
use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_error::Error as JoseErrorBranch, jose_jws_verify_response::Outcome,
        jose_operation_request::Operation as JoseOperation, jose_operation_response::Response,
    },
    JoseErrorReason, JoseJwsVerifyRequest, JoseOperationRequest, JoseOperationResponse,
    JoseSignatureAlgorithm,
};
use reallyme_jose::wire::{
    decode_operation_response_v1, encode_json, encode_protobuf, execute_operation_json_v1,
    execute_operation_request, execute_operation_v1, JoseOperationKind,
};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedEnvelope {
    Verified,
    Primitive(JoseErrorReason),
    Provider(JoseErrorReason),
}

#[test]
fn all_wire_routes_match_for_the_complete_jws_corpus() {
    let suite: Value =
        serde_json::from_str(include_str!("../../../vectors/jws-compact.json")).unwrap();
    let cases = suite["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 26);

    for case in cases {
        let algorithm = algorithm_from_str(case["alg"].as_str().unwrap());
        let expected = match case.get("expected_error").and_then(Value::as_str) {
            Some(reason) => ExpectedEnvelope::Primitive(wire_reason_from_str(reason)),
            None => ExpectedEnvelope::Verified,
        };
        assert_all_routes(
            EnumValue::from(algorithm),
            case["compact"].as_str().unwrap(),
            &hex_to_bytes(case["public_key_hex"].as_str().unwrap()),
            expected,
        );
    }
}

#[test]
fn all_wire_routes_match_for_applicable_panva_vectors() {
    let suite: Value =
        serde_json::from_str(include_str!("../../../vectors/panva-jose.json")).unwrap();
    let mut count = 0usize;

    for case in suite["cases"].as_array().unwrap() {
        if case["format"].as_str() != Some("jws-compact") {
            continue;
        }
        count = count.checked_add(1).unwrap();
        assert_all_routes(
            EnumValue::from(algorithm_from_str(case["alg"].as_str().unwrap())),
            case["compact"].as_str().unwrap(),
            &hex_to_bytes(case["public_key_hex"].as_str().unwrap()),
            ExpectedEnvelope::Verified,
        );
    }

    assert_eq!(count, 2);
}

#[test]
fn all_wire_routes_match_for_pilot_specific_failure_reasons() {
    let invalid_utf8_header = bytes_to_base64url(&[0xff]);
    let es256_header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let zero_signature = bytes_to_base64url(&[0u8; 64]);
    let cases = [
        (
            "=.payload.signature".to_owned(),
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        ),
        (
            format!("{invalid_utf8_header}.payload.signature"),
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        ),
        (
            format!("{es256_header}.payload.{zero_signature}"),
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE,
        ),
        (
            format!("{es256_header}.payload.c2hvcnQ"),
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        ),
    ];

    for (compact, reason) in cases {
        assert_all_routes(
            EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
            &compact,
            &[0xff],
            ExpectedEnvelope::Primitive(reason),
        );
    }
}

#[test]
fn all_wire_routes_reject_authenticated_invalid_payload_base64url() {
    let (public_key, private_key) =
        generate_keypair(reallyme_crypto::core::Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let signing_input = format!("{header}.%");
    let signature = sign_p256_jose_prehash(&private_key, signing_input.as_bytes()).unwrap();
    let compact = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    assert_all_routes(
        EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
        &compact,
        &public_key,
        ExpectedEnvelope::Primitive(JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64),
    );
}

#[test]
fn all_wire_routes_match_for_unsupported_algorithm_selection() {
    for algorithm in [
        EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED),
        EnumValue::from(99),
    ] {
        assert_all_routes(
            algorithm,
            "selection.stops.before-compact-validation",
            &[0xff],
            ExpectedEnvelope::Provider(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED),
        );
    }
}

fn assert_all_routes(
    algorithm: EnumValue<JoseSignatureAlgorithm>,
    compact: &str,
    public_key: &[u8],
    expected: ExpectedEnvelope,
) {
    let operation_request = operation(algorithm, compact, public_key);
    let operation_protobuf = encode_protobuf(&operation_request);
    let operation_json = encode_json(&operation_request).unwrap();
    let mut random = RejectRandom;

    let responses = [
        encode_protobuf(&execute_operation_request(
            operation(algorithm, compact, public_key),
            &mut random,
        )),
        execute_operation_v1(&operation_protobuf, &mut random),
        execute_operation_json_v1(&operation_json, &mut random),
    ];

    let canonical = responses[0].as_slice();
    for response in &responses {
        assert_eq!(response.as_slice(), canonical);
        let response =
            decode_operation_response_v1(response, JoseOperationKind::JwsVerify).unwrap();
        assert_response(response, expected);
    }
}

fn request(
    algorithm: EnumValue<JoseSignatureAlgorithm>,
    compact: &str,
    public_key: &[u8],
) -> JoseJwsVerifyRequest {
    JoseJwsVerifyRequest {
        algorithm,
        compact: compact.to_owned(),
        public_key: public_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation(
    algorithm: EnumValue<JoseSignatureAlgorithm>,
    compact: &str,
    public_key: &[u8],
) -> JoseOperationRequest {
    JoseOperationRequest {
        operation: Some(JoseOperation::JwsVerify(Box::new(request(
            algorithm, compact, public_key,
        )))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn assert_response(mut response: JoseOperationResponse, expected: ExpectedEnvelope) {
    let Some(Response::JwsVerify(mut response)) = response.response.take() else {
        panic!("expected JWS verification response");
    };
    let Some(outcome) = response.outcome.take() else {
        panic!("expected JWS verification outcome");
    };
    match (expected, outcome) {
        (ExpectedEnvelope::Verified, Outcome::Result(result)) => {
            assert!(result.__buffa_unknown_fields.is_empty());
        }
        (ExpectedEnvelope::Primitive(reason), Outcome::Error(error)) => match error.error {
            Some(JoseErrorBranch::Primitive(error)) => assert_eq!(error.reason, reason),
            _ => panic!("expected primitive JWS verification error"),
        },
        (ExpectedEnvelope::Provider(reason), Outcome::Error(error)) => match error.error {
            Some(JoseErrorBranch::Provider(error)) => assert_eq!(error.reason, reason),
            _ => panic!("expected provider JWS verification error"),
        },
        _ => panic!("JWS verification response used the wrong outcome"),
    }
}

fn algorithm_from_str(algorithm: &str) -> JoseSignatureAlgorithm {
    match algorithm {
        "ES256" => JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256,
        "EdDSA" => JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA,
        _ => panic!("unsupported differential algorithm"),
    }
}

fn wire_reason_from_str(reason: &str) -> JoseErrorReason {
    match reason {
        "InvalidCompactEncoding" => JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_COMPACT,
        "BadHeaderBase64" => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        "BadHeaderUtf8" => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        "HeaderMismatch" => JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        "BadSignatureBase64" => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64,
        "BadRawSignature" => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE,
        "InvalidSignature" => JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        _ => panic!("unsupported differential error reason"),
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

struct RejectRandom;

impl SecureRandom for RejectRandom {
    fn fill_secure(
        &mut self,
        _output: &mut [u8],
        output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output: output_kind,
            kind: RngFailureKind::InvalidOutputLength,
        })
    }
}
