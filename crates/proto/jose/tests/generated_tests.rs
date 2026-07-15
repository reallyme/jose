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
        JoseJwsSignRequest, JoseOperationRequest, JosePrimitiveError, JoseProtoResultEnvelope,
        JoseProtoResultStatus, JoseProviderError, JoseSignatureAlgorithm,
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

#[test]
fn proto_package_name_is_stable() {
    assert_eq!(JOSE_PROTO_PACKAGE, "reallyme.jose.v1");
}

#[test]
fn jose_error_reason_values_are_stable() {
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE.to_i32(),
        13
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8.to_i32(),
        4
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY.to_i32(),
        29
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH.to_i32(),
        49
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY.to_i32(),
        50
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK.to_i32(),
        51
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME.to_i32(),
        61
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY.to_i32(),
        62
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF.to_i32(),
        68
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_JSON.to_i32(),
        70
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MISSING_OPERATION.to_i32(),
        71
    );
    assert_eq!(
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED.to_i32(),
        72
    );
}

#[test]
fn jose_error_reason_values_have_no_stale_placeholders() {
    for value in [8, 9, 10, 27, 48] {
        assert!(JoseErrorReason::from_i32(value).is_none());
    }

    assert!(JoseErrorReason::from_i32(73).is_some());
    assert!(JoseErrorReason::from_i32(74).is_none());
}

#[test]
fn jws_es256k_signature_algorithm_slot_is_reserved() {
    for value in 0..=2 {
        assert!(
            JoseSignatureAlgorithm::from_i32(value).is_some(),
            "JoseSignatureAlgorithm value {value} must be assigned"
        );
    }

    assert!(JoseSignatureAlgorithm::from_i32(3).is_none());
    assert!(JoseSignatureAlgorithm::from_i32(4).is_none());
}

#[test]
fn operation_enum_values_are_dense() {
    for value in 0..=4 {
        assert!(
            JoseJweKeyManagementAlgorithm::from_i32(value).is_some(),
            "JoseJweKeyManagementAlgorithm value {value} must be assigned"
        );
    }
    assert!(JoseJweKeyManagementAlgorithm::from_i32(5).is_none());

    for value in 0..=3 {
        assert!(
            JoseJweContentEncryptionAlgorithm::from_i32(value).is_some(),
            "JoseJweContentEncryptionAlgorithm value {value} must be assigned"
        );
    }
    assert!(JoseJweContentEncryptionAlgorithm::from_i32(4).is_none());

    for value in 0..=2 {
        assert!(
            JoseProtoResultStatus::from_i32(value).is_some(),
            "JoseProtoResultStatus value {value} must be assigned"
        );
    }
    assert!(JoseProtoResultStatus::from_i32(3).is_none());
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
    assert_golden_wire(&primitive, &[0x0a, 0x02, 0x08, 0x0d])?;

    let provider = JoseError {
        error: Some(JoseErrorBranch::Provider(Box::new(JoseProviderError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&provider, &[0x12, 0x02, 0x08, 0x41])?;

    let backend = JoseError {
        error: Some(JoseErrorBranch::Backend(Box::new(JoseBackendError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&backend, &[0x1a, 0x02, 0x08, 0x44])?;

    Ok(())
}

#[test]
fn jose_result_envelope_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let result = JoseCompactResult {
        compact: "a.b.c".to_owned(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&result, &[0x0a, 0x05, b'a', b'.', b'b', b'.', b'c'])?;

    let envelope = JoseProtoResultEnvelope {
        status: EnumValue::from(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT),
        payload: result.encode_to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(
        &envelope,
        &[
            0x08, 0x01, 0x12, 0x07, 0x0a, 0x05, b'a', b'.', b'b', b'.', b'c',
        ],
    )?;

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
            0x0a, 0x09, 0x08, 0x01, 0x12, 0x02, 0x01, 0x02, 0x1a, 0x01, 0x03,
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
