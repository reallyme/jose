// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for generated JOSE protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::json::{with_json_parse_options, JsonParseOptions};
use buffa::sensitive::{GuardedOwnedView, GuardedViewError};
use buffa::{DecodeOptions, EnumValue, Enumeration, Message};
use reallyme_jose_proto::generated::{
    proto::reallyme::jose::v1::{
        __buffa::oneof::{
            jose_error::Error as JoseErrorBranch,
            jose_operation_request::Operation as JoseOperation,
        },
        JoseBackendError, JoseCompactResult, JoseError, JoseErrorReason, JoseExpectedString,
        JoseJweContentEncryptionAlgorithm, JoseJweEncryptRequest, JoseJweKeyManagementAlgorithm,
        JoseJwePlaintextResult, JoseJwePlaintextResultView, JoseJwsSignRequest,
        JoseJwsSignRequestView, JoseJwtTemporalValidationPolicy, JoseOperationRequest,
        JoseOperationRequestView, JosePrimitiveError, JoseProviderError, JoseSdkErrorCode,
        JoseSignatureAlgorithm, JoseVerifyResult, JoseVerifyResultView,
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
    assert!(debug.contains("[REDACTED]"), "{debug}");
    assert!(!debug.contains("130"), "{debug}");
    assert!(!debug.contains("[48"), "{debug}");
}

#[test]
fn proto_package_name_is_stable() {
    assert_eq!(JOSE_PROTO_PACKAGE, "reallyme.jose.v1");
}

#[test]
fn sdk_error_codes_have_stable_schema_numbers() {
    use JoseSdkErrorCode::{
        JOSE_SDK_ERROR_CODE_INCOMPATIBLE_ABI, JOSE_SDK_ERROR_CODE_INVALID_INPUT,
        JOSE_SDK_ERROR_CODE_JOSE_FAILURE, JOSE_SDK_ERROR_CODE_MALFORMED_PROVIDER_RESPONSE,
        JOSE_SDK_ERROR_CODE_NATIVE_LIBRARY_LOAD_FAILED,
        JOSE_SDK_ERROR_CODE_NATIVE_LIBRARY_NOT_FOUND, JOSE_SDK_ERROR_CODE_NATIVE_SYMBOL_MISSING,
        JOSE_SDK_ERROR_CODE_PROVIDER_FAILURE, JOSE_SDK_ERROR_CODE_PROVIDER_NOT_INSTALLED,
        JOSE_SDK_ERROR_CODE_UNSUPPORTED_PLATFORM,
    };
    for (code, number) in [
        (JOSE_SDK_ERROR_CODE_INVALID_INPUT, 100),
        (JOSE_SDK_ERROR_CODE_PROVIDER_NOT_INSTALLED, 200),
        (JOSE_SDK_ERROR_CODE_PROVIDER_FAILURE, 210),
        (JOSE_SDK_ERROR_CODE_MALFORMED_PROVIDER_RESPONSE, 220),
        (JOSE_SDK_ERROR_CODE_UNSUPPORTED_PLATFORM, 300),
        (JOSE_SDK_ERROR_CODE_NATIVE_LIBRARY_NOT_FOUND, 310),
        (JOSE_SDK_ERROR_CODE_NATIVE_LIBRARY_LOAD_FAILED, 320),
        (JOSE_SDK_ERROR_CODE_NATIVE_SYMBOL_MISSING, 330),
        (JOSE_SDK_ERROR_CODE_INCOMPATIBLE_ABI, 340),
        (JOSE_SDK_ERROR_CODE_JOSE_FAILURE, 400),
    ] {
        assert_eq!(code.to_i32(), number);
        assert_eq!(JoseSdkErrorCode::from_i32(number), Some(code));
    }
    assert_eq!(JoseSdkErrorCode::from_i32(401), None);
}

#[test]
fn generated_private_key_and_payload_debug_output_is_redacted() -> Result<(), GuardedViewError> {
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
        private_key: vec![0x30, 0x82, 0x01, 0x0a].into(),
        payload: vec![0x30, 0x82, 0x02, 0x0b].into(),
    };

    let debug = format!("{request:?}");
    assert_debug_redacts_bytes(debug.clone(), "private_key");
    assert_debug_redacts_bytes(debug, "payload");

    let view = GuardedOwnedView::<JoseJwsSignRequestView<'static>>::from_owned(
        &request,
        &DecodeOptions::new().reject_unknown_fields(),
    )?;
    let view_debug = format!("{:?}", view.view());
    assert_debug_redacts_bytes(view_debug.clone(), "private_key");
    assert_debug_redacts_bytes(view_debug, "payload");
    let owned_view_debug = format!("{view:?}");
    assert!(owned_view_debug.contains("[REDACTED]"));
    assert!(!owned_view_debug.contains("48"));
    assert!(!owned_view_debug.contains("130"));
    Ok(())
}

#[test]
fn generated_plaintext_debug_output_is_redacted() -> Result<(), GuardedViewError> {
    let plaintext = JoseJwePlaintextResult {
        plaintext: vec![0x30, 0x82, 0x04, 0x0d].into(),
    };

    let plaintext_debug = format!("{plaintext:?}");
    assert_debug_redacts_bytes(plaintext_debug, "plaintext");

    let plaintext_view = GuardedOwnedView::<JoseJwePlaintextResultView<'static>>::from_owned(
        &plaintext,
        &DecodeOptions::new().reject_unknown_fields(),
    )?;
    let plaintext_view_debug = format!("{:?}", plaintext_view.view());
    assert_debug_redacts_bytes(plaintext_view_debug, "plaintext");
    assert!(format!("{plaintext_view:?}").contains("[REDACTED]"));
    Ok(())
}

#[test]
fn generated_verified_parts_are_redacted_and_cleared() -> Result<(), GuardedViewError> {
    let mut result = JoseVerifyResult {
        protected_header_json: vec![0x30, 0x82, 0x01, 0x0a].into(),
        payload: vec![0x30, 0x82, 0x02, 0x0b].into(),
    };

    let debug = format!("{result:?}");
    assert_debug_redacts_bytes(debug.clone(), "protected_header_json");
    assert_debug_redacts_bytes(debug, "payload");

    let view = GuardedOwnedView::<JoseVerifyResultView<'static>>::from_owned(
        &result,
        &DecodeOptions::new().reject_unknown_fields(),
    )?;
    let view_debug = format!("{:?}", view.view());
    assert_debug_redacts_bytes(view_debug.clone(), "protected_header_json");
    assert_debug_redacts_bytes(view_debug, "payload");
    assert!(format!("{view:?}").contains("[REDACTED]"));

    result.clear();
    assert!(result.protected_header_json.is_empty());
    assert!(result.payload.is_empty());
    Ok(())
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn generated_jwt_claim_policy_identifiers_are_redacted_and_cleared() {
    // Drop hardening intentionally prevents struct-update syntax from moving
    // guarded fields out of the default owner.
    let mut policy = JoseJwtTemporalValidationPolicy::default();
    policy.expected_audience = "redact-audience-491".to_owned().into();
    policy.expected_issuer_constraint = JoseExpectedString {
        value: "redact-issuer-492".to_owned().into(),
    }
    .into();
    policy.expected_subject_constraint = JoseExpectedString {
        value: "redact-subject-493".to_owned().into(),
    }
    .into();

    let debug = format!("{policy:?}");
    assert!(debug.contains("expected_audience"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("redact-audience-491"));
    assert!(!debug.contains("redact-issuer-492"));
    assert!(!debug.contains("redact-subject-493"));

    policy.clear();
    assert!(policy.expected_audience.is_empty());
    assert!(!policy.expected_issuer_constraint.is_set());
    assert!(!policy.expected_subject_constraint.is_set());
}

#[test]
fn jwt_temporal_policy_proto_json_round_trips_and_accepts_null_defaults(
) -> Result<(), serde_json::Error> {
    let mut policy = JoseJwtTemporalValidationPolicy::default();
    policy.require_exp = true;
    policy.require_nbf = true;
    policy.require_iat = true;
    policy.clock_skew_seconds = 30;
    policy.max_future_iat_skew_seconds = 60;
    policy.now_unix = 1_720_000_000;
    policy.expected_audience = "recipient".to_owned().into();
    policy.expected_issuer_constraint = JoseExpectedString {
        value: "issuer".to_owned().into(),
    }
    .into();
    policy.expected_subject_constraint = JoseExpectedString {
        value: "subject".to_owned().into(),
    }
    .into();

    let encoded = serde_json::to_vec(&policy)?;
    let decoded: JoseJwtTemporalValidationPolicy = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded, policy);

    let numeric: JoseJwtTemporalValidationPolicy = serde_json::from_str(
        r#"{"requireExp":true,"clockSkewSeconds":30,"nowUnix":1720000000,"expectedAudience":"recipient"}"#,
    )?;
    assert_eq!(numeric.now_unix, policy.now_unix);

    let nulls: JoseJwtTemporalValidationPolicy = serde_json::from_str(
        r#"{"requireExp":null,"nowUnix":null,"expectedIssuerConstraint":null,"expectedSubjectConstraint":null}"#,
    )?;
    assert!(!nulls.require_exp);
    assert_eq!(nulls.now_unix, 0);
    assert!(!nulls.expected_issuer_constraint.is_set());
    assert!(!nulls.expected_subject_constraint.is_set());
    Ok(())
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
fn signature_identity_is_shared_and_legacy_values_remain_reserved() {
    for value in [0, 100, 200, 230] {
        assert!(JoseSignatureAlgorithm::from_i32(value).is_some());
    }

    for value in 1..=3 {
        assert!(JoseSignatureAlgorithm::from_i32(value).is_none());
    }
    assert_eq!(
        JoseSignatureAlgorithm::from_i32(230),
        Some(JoseSignatureAlgorithm::Es256k)
    );
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
        }))),
    };
    assert_golden_wire(&primitive, &[0x0a, 0x03, 0x08, 0x8e, 0x01])?;

    let provider = JoseError {
        error: Some(JoseErrorBranch::Provider(Box::new(JoseProviderError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED),
        }))),
    };
    assert_golden_wire(&provider, &[0x12, 0x03, 0x08, 0xa1, 0x06])?;

    let backend = JoseError {
        error: Some(JoseErrorBranch::Backend(Box::new(JoseBackendError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF),
        }))),
    };
    assert_golden_wire(&backend, &[0x1a, 0x03, 0x08, 0xbc, 0x05])?;

    Ok(())
}

#[test]
fn jose_compact_result_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let result = JoseCompactResult {
        compact: "a.b.c".to_owned().into(),
    };
    assert_golden_wire(&result, &[0x0a, 0x05, b'a', b'.', b'b', b'.', b'c'])?;

    Ok(())
}

#[test]
fn jose_verify_result_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let result = JoseVerifyResult {
        protected_header_json: vec![1, 2].into(),
        payload: vec![3, 4].into(),
    };
    assert_golden_wire(&result, &[0x0a, 0x02, 0x01, 0x02, 0x12, 0x02, 0x03, 0x04])?;

    Ok(())
}

#[test]
fn jose_operation_request_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let request = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256),
            private_key: vec![1, 2].into(),
            payload: vec![3].into(),
        }))),
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
        key: vec![7u8; 16].into(),
        plaintext: br#"{"ok":true}"#.to_vec().into(),
        kid: Some("kid-1".to_owned().into()),
        apu: Some(b"wallet".to_vec().into()),
        apv: Some(b"issuer".to_vec().into()),
        typ: Some("JWT".to_owned().into()),
        cty: Some("json".to_owned().into()),
        compression_algorithm: Default::default(),
    };

    let json = serde_json::to_vec(&request)?;
    let decoded: JoseJweEncryptRequest = serde_json::from_slice(&json)?;
    assert_eq!(decoded, request);

    Ok(())
}

#[test]
fn guarded_view_json_and_owned_conversion_preserve_the_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = JoseJwsSignRequest::default()
        .with_private_key(vec![7; 257])
        .with_payload(vec![9; 129]);
    let input = zeroize::Zeroizing::new(request.encode_to_vec());
    let view = GuardedOwnedView::<JoseJwsSignRequestView<'static>>::decode(
        &input,
        &DecodeOptions::new().reject_unknown_fields(),
    )?;
    drop(input);
    assert_eq!(
        serde_json::to_value(view.view())?,
        serde_json::to_value(&request)?
    );
    let owned = view.to_owned_message()?;
    assert_ne!(owned.private_key.as_ptr(), request.private_key.as_ptr());
    drop(view);
    assert_eq!(owned, request);
    Ok(())
}

#[test]
fn nested_operation_views_redact_and_reject_unknown_fields() -> Result<(), GuardedViewError> {
    let marker = "private-marker";
    let request = JoseOperationRequest::default().with_operation(JoseOperation::JwsSign(Box::new(
        JoseJwsSignRequest::default().with_private_key(marker.as_bytes().to_vec()),
    )));
    let options = DecodeOptions::new()
        .reject_unknown_fields()
        .with_max_message_size(1024);
    let wire = zeroize::Zeroizing::new(request.encode_to_vec());
    let eager = options.decode_view::<JoseOperationRequestView<'_>>(&wire)?;
    let guarded =
        GuardedOwnedView::<JoseOperationRequestView<'static>>::from_owned(&request, &options)?;
    for debug in [
        format!("{eager:?}"),
        format!("{:?}", eager.operation),
        format!("{guarded:?}"),
    ] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
        assert!(!debug.contains("[112, 114, 105"));
    }

    // The outer jws_sign field carries a child whose field 4 is unknown.
    let unknown_child = b"\xc2\x3e\x10\x22\x0eprivate-marker";
    assert!(matches!(
        options.decode_view::<JoseOperationRequestView<'_>>(unknown_child),
        Err(buffa::DecodeError::UnknownFieldLimitExceeded)
    ));
    assert!(matches!(
        GuardedOwnedView::<JoseOperationRequestView<'static>>::decode(unknown_child, &options),
        Err(GuardedViewError::Decode(
            buffa::DecodeError::UnknownFieldLimitExceeded
        ))
    ));
    Ok(())
}

#[test]
fn enum_json_errors_omit_rejected_input() {
    let rejected_name = r#""private-rejected-label""#;
    let out_of_range = ["-2147483649", "18446744073709551615"];
    // Standalone enum values are closed. Proto3 fields retain unknown i32s.
    for rejected in [rejected_name, "1234567"].into_iter().chain(out_of_range) {
        assert_redacted_enum_error(
            serde_json::from_str::<JoseSignatureAlgorithm>(rejected),
            rejected,
        );
    }
    for rejected in [rejected_name].into_iter().chain(out_of_range) {
        let request = format!(r#"{{"algorithm":{rejected}}}"#);
        assert_redacted_enum_error(
            serde_json::from_str::<JoseJwsSignRequest>(&request),
            rejected,
        );
    }
}

fn assert_redacted_enum_error<T>(result: serde_json::Result<T>, rejected: &str) {
    assert!(result.err().is_some_and(|error| {
        error.is_data() && !error.to_string().contains(rejected.trim_matches('"'))
    }));
}

#[test]
fn enum_json_preserves_known_open_null_and_lenient_values() -> serde_json::Result<()> {
    use JoseSignatureAlgorithm::{
        JOSE_SIGNATURE_ALGORITHM_ES256, JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED,
    };
    for (token, expected) in [
        (
            r#""JOSE_SIGNATURE_ALGORITHM_ES256""#,
            JOSE_SIGNATURE_ALGORITHM_ES256,
        ),
        ("200", JOSE_SIGNATURE_ALGORITHM_ES256),
        ("null", JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED),
    ] {
        assert_eq!(
            serde_json::from_str::<JoseSignatureAlgorithm>(token)?,
            expected
        );
        let request: JoseJwsSignRequest =
            serde_json::from_str(&format!(r#"{{"algorithm":{token}}}"#))?;
        assert_eq!(request.algorithm, EnumValue::Known(expected));
    }

    let lenient = JsonParseOptions::new().ignore_unknown_enum_values(true);
    for options in [JsonParseOptions::new(), lenient] {
        let request: JoseJwsSignRequest = with_json_parse_options(&options, || {
            serde_json::from_str(r#"{"algorithm":1234567}"#)
        })?;
        assert_eq!(request.algorithm, EnumValue::Unknown(1234567));
    }
    with_json_parse_options(&lenient, || {
        let request: JoseJwsSignRequest =
            serde_json::from_str(r#"{"algorithm":"FUTURE_ALGORITHM"}"#)?;
        assert_eq!(
            request.algorithm,
            EnumValue::Known(JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED)
        );
        assert_redacted_enum_error(
            serde_json::from_str::<JoseSignatureAlgorithm>(r#""FUTURE_ALGORITHM""#),
            "FUTURE_ALGORITHM",
        );
        assert_redacted_enum_error(
            serde_json::from_str::<JoseJwsSignRequest>(r#"{"algorithm":18446744073709551615}"#),
            "18446744073709551615",
        );
        Ok(())
    })
}
