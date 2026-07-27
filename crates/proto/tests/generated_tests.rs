// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for generated JOSE protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_jose_proto::generated::{
    proto::reallyme::jose::v1::{
        __buffa::oneof::{
            jose_error::Error as JoseErrorBranch,
            jose_operation_request::Operation as JoseOperation,
        },
        JoseBackendError, JoseCompactResult, JoseError, JoseErrorReason,
        JoseJweContentEncryptionAlgorithm, JoseJweEncryptRequest, JoseJweKeyManagementAlgorithm,
        JoseJwePlaintextResult, JoseJwePlaintextResultOwnedView, JoseJwsSignRequest,
        JoseJwsSignRequestOwnedView, JoseJwtTemporalValidationPolicy, JoseOperationRequest,
        JosePrimitiveError, JoseProviderError, JoseSignatureAlgorithm,
    },
    JOSE_PROTO_PACKAGE,
};

fn assert_golden_wire<M>(message: &M, expected: &[u8]) -> Result<(), buffa::DecodeError>
where
    M: Message + Default + PartialEq + core::fmt::Debug,
{
    let encoded = message.encode_to_vec();
    assert_eq!(encoded, expected);

    let decoded = M::decode_from_slice(expected)?;
    assert_eq!(&decoded, message);

    Ok(())
}

fn assert_debug_redacts_bytes(debug: String, field_name: &str) {
    assert!(debug.contains(field_name), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("130"), "{debug}");
    assert!(!debug.contains("[48"), "{debug}");
}

#[test]
fn proto_package_name_is_stable() {
    assert_eq!(JOSE_PROTO_PACKAGE, "reallyme.jose.v1");
}

#[test]
fn generated_private_key_and_payload_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
        private_key: vec![0x30, 0x82, 0x01, 0x0a],
        payload: vec![0x30, 0x82, 0x02, 0x0b],
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{request:?}");
    assert_debug_redacts_bytes(debug.clone(), "private_key");
    assert_debug_redacts_bytes(debug, "payload");

    let view = JoseJwsSignRequestOwnedView::from_owned(&request)?;
    let view_debug = format!("{:?}", view.view());
    assert_debug_redacts_bytes(view_debug.clone(), "private_key");
    assert_debug_redacts_bytes(view_debug, "payload");
    let owned_view_debug = format!("{view:?}");
    assert!(owned_view_debug.contains("<redacted>"));
    assert!(!owned_view_debug.contains("48"));
    assert!(!owned_view_debug.contains("130"));
    Ok(())
}

#[test]
fn generated_plaintext_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let plaintext = JoseJwePlaintextResult {
        plaintext: vec![0x30, 0x82, 0x04, 0x0d],
        __buffa_unknown_fields: Default::default(),
    };

    let plaintext_debug = format!("{plaintext:?}");
    assert_debug_redacts_bytes(plaintext_debug, "plaintext");

    let plaintext_view = JoseJwePlaintextResultOwnedView::from_owned(&plaintext)?;
    let plaintext_view_debug = format!("{:?}", plaintext_view.view());
    assert_debug_redacts_bytes(plaintext_view_debug, "plaintext");
    assert!(format!("{plaintext_view:?}").contains("<redacted>"));
    Ok(())
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn generated_jwt_claim_policy_identifiers_are_redacted_and_cleared() {
    // Drop hardening intentionally prevents struct-update syntax from moving
    // retained unknown fields out of the default owner.
    let mut policy = JoseJwtTemporalValidationPolicy::default();
    policy.expected_audience = "redact-audience-491".to_owned();
    policy.expected_issuer = "redact-issuer-492".to_owned();
    policy.expected_subject = "redact-subject-493".to_owned();

    let debug = format!("{policy:?}");
    assert!(debug.contains("expected_audience"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("redact-audience-491"));
    assert!(!debug.contains("redact-issuer-492"));
    assert!(!debug.contains("redact-subject-493"));

    policy.clear();
    assert!(policy.expected_audience.is_empty());
    assert!(policy.expected_issuer.is_empty());
    assert!(policy.expected_subject.is_empty());
}

#[test]
fn jose_error_reason_values_are_stable() {
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE.to_i32(),
        142
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8.to_i32(),
        103
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64.to_i32(),
        104
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY.to_i32(),
        241
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH.to_i32(),
        327
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY.to_i32(),
        328
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK.to_i32(),
        329
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME.to_i32(),
        385
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY.to_i32(),
        386
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH.to_i32(),
        390
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_SUBJECT_MISMATCH.to_i32(),
        392
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF.to_i32(),
        700
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON.to_i32(),
        701
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MISSING_OPERATION.to_i32(),
        702
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED.to_i32(),
        703
    );
}

#[test]
fn jose_error_reason_values_have_no_stale_placeholders() {
    for value in 1..=73 {
        assert!(JoseErrorReason::from_i32(value).is_none());
    }

    assert!(JoseErrorReason::from_i32(902).is_some());
    assert!(JoseErrorReason::from_i32(903).is_none());
}

#[test]
fn jws_es256k_signature_algorithm_slot_is_reserved() {
    for value in [0, 100, 200] {
        assert!(JoseSignatureAlgorithm::from_i32(value).is_some());
    }

    for value in 1..=3 {
        assert!(JoseSignatureAlgorithm::from_i32(value).is_none());
    }
    assert!(JoseSignatureAlgorithm::from_i32(230).is_none());
}

#[test]
fn algorithm_families_are_sparse() {
    for value in [0, 100, 200, 210, 220] {
        assert!(JoseJweKeyManagementAlgorithm::from_i32(value).is_some());
    }
    for value in 1..=4 {
        assert!(JoseJweKeyManagementAlgorithm::from_i32(value).is_none());
    }

    for value in [0, 100, 110, 120] {
        assert!(JoseJweContentEncryptionAlgorithm::from_i32(value).is_some());
    }
    for value in 1..=3 {
        assert!(JoseJweContentEncryptionAlgorithm::from_i32(value).is_none());
    }
}

#[test]
fn jose_error_oneof_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let primitive = JoseError {
        error: Some(JoseErrorBranch::Primitive(Box::new(JosePrimitiveError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&primitive, &[0x0a, 0x03, 0x08, 0x8e, 0x01])?;

    let provider = JoseError {
        error: Some(JoseErrorBranch::Provider(Box::new(JoseProviderError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&provider, &[0x12, 0x03, 0x08, 0xa1, 0x06])?;

    let backend = JoseError {
        error: Some(JoseErrorBranch::Backend(Box::new(JoseBackendError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&backend, &[0x1a, 0x03, 0x08, 0xbc, 0x05])?;

    Ok(())
}

#[test]
fn jose_compact_result_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let result = JoseCompactResult {
        compact: "a.b.c".to_owned(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&result, &[0x0a, 0x05, b'a', b'.', b'b', b'.', b'c'])?;

    Ok(())
}

#[test]
fn jose_operation_request_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let request = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
            private_key: vec![1, 2],
            payload: vec![3],
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    assert_golden_wire(
        &request,
        &[
            0xc2, 0x3e, 0x0a, 0x08, 0xc8, 0x01, 0x12, 0x02, 0x01, 0x02, 0x1a, 0x01, 0x03,
        ],
    )?;

    Ok(())
}

#[test]
fn jwe_encrypt_request_json_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: vec![7u8; 16],
        plaintext: br#"{"ok":true}"#.to_vec(),
        kid: "kid-1".to_owned(),
        apu: b"wallet".to_vec(),
        apv: b"issuer".to_vec(),
        typ: "JWT".to_owned(),
        cty: "json".to_owned(),
        __buffa_unknown_fields: Default::default(),
    };

    let json = serde_json::to_vec(&request)?;
    let decoded: JoseJweEncryptRequest = serde_json::from_slice(&json)?;
    assert_eq!(decoded, request);

    Ok(())
}
