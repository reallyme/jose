// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for the JOSE protobuf boundary layer.

#![cfg(feature = "wire")]
#![allow(missing_docs, clippy::panic)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_crypto::p256::generate_p256_keypair_from_secret_key;
use reallyme_crypto::{
    core::Algorithm,
    csprng::SecureRandom,
    dispatch::generate_keypair,
    jwk::{p256_public_key_to_jwk, JwkOptions},
};
use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_error::Error as JoseErrorBranch, jose_operation_request::Operation as JoseOperation,
    },
    JoseCompactResult, JoseError, JoseErrorReason, JoseExpectedBytes, JoseExpectedString,
    JoseJweContentEncryptionAlgorithm, JoseJweDecryptRequest, JoseJweEncryptRequest,
    JoseJweHeaderValidationPolicy, JoseJweKeyManagementAlgorithm, JoseJwePlaintextResult,
    JoseJwsSignRequest, JoseJwsVerifyRequest, JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest,
    JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest, JoseJwtTemporalValidationPolicy,
    JoseJwtVerifyRequest, JoseOperationRequest, JosePrimitiveError, JoseProtoResultEnvelope,
    JoseProtoResultStatus, JoseSignatureAlgorithm, JoseVerifyResult,
};
use reallyme_jose::wire::{
    encode_json, encode_protobuf, error_envelope_bytes, jose_error_bytes,
    sign_jws_envelope_from_json, sign_jws_envelope_from_protobuf, verify_jws_envelope,
    JoseProtoStatus, JoseWireError, JoseWireErrorBranch, MAX_JOSE_PROTO_JSON_BYTES,
    MAX_JOSE_PROTO_MESSAGE_BYTES,
};
use reallyme_jose::{wire, Jwk};

fn wire_error(branch: JoseWireErrorBranch, reason: JoseErrorReason) -> JoseWireError {
    match JoseWireError::try_new(branch, reason) {
        Ok(error) => error,
        Err(_) => panic!("test reason must belong to its branch"),
    }
}

#[test]
fn malformed_protobuf_returns_backend_error_envelope() -> Result<(), buffa::DecodeError> {
    let envelope = decode_envelope(&sign_jws_envelope_from_protobuf(&[0xff]))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR
    );
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
    )?;
    Ok(())
}

#[test]
fn malformed_json_returns_backend_error_envelope() -> Result<(), buffa::DecodeError> {
    let envelope = decode_envelope(&sign_jws_envelope_from_json(b"{"))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR
    );
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_JSON,
    )?;
    Ok(())
}

#[test]
fn jws_sign_rejects_non_utf8_payload_with_typed_reason() -> Result<(), buffa::DecodeError> {
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        private_key: Vec::new(),
        payload: vec![0xff],
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&sign_jws_envelope_from_protobuf(&encode_protobuf(&request)))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR
    );
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8,
    )?;
    Ok(())
}

#[test]
fn jws_sign_json_and_protobuf_paths_match() -> Result<(), Box<dyn std::error::Error>> {
    let (_public, private) = generate_keypair(Algorithm::Ed25519)?;
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        private_key: private.to_vec(),
        payload: b"cid:example:wire".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let protobuf_envelope = sign_jws_envelope_from_protobuf(&encode_protobuf(&request));
    let json_envelope = sign_jws_envelope_from_json(&encode_json(&request)?);

    let protobuf_result = decode_compact_result(&protobuf_envelope)?;
    let json_result = decode_compact_result(&json_envelope)?;
    assert_eq!(protobuf_result.compact, json_result.compact);

    Ok(())
}

#[test]
fn process_proto_dispatches_every_generated_operation() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = FixedRandom::new([9u8; 12]);

    let (jws_public, jws_private) = generate_keypair(Algorithm::Ed25519)?;
    let jws_sign = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            private_key: jws_private.to_vec(),
            payload: b"cid:example:process-proto".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let signed_jws =
        decode_compact_result(&wire::process_proto(&encode_protobuf(&jws_sign), &mut rng))?;

    let jws_verify = JoseOperationRequest {
        operation: Some(JoseOperation::JwsVerify(Box::new(JoseJwsVerifyRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            compact: signed_jws.compact,
            public_key: jws_public,
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    decode_verify_result(&wire::process_proto(
        &encode_protobuf(&jws_verify),
        &mut rng,
    ))?;

    let unsigned_claims_json = br#"{"sub":"unsigned"}"#.to_vec();
    let jwt_encode_unsigned = JoseOperationRequest {
        operation: Some(JoseOperation::JwtEncodeUnsigned(Box::new(
            JoseJwtEncodeUnsignedRequest {
                claims_json: unsigned_claims_json.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let unsigned_jwt = decode_compact_result(&wire::process_proto(
        &encode_protobuf(&jwt_encode_unsigned),
        &mut rng,
    ))?;

    let jwt_decode_unsigned = JoseOperationRequest {
        operation: Some(JoseOperation::JwtDecodeUnsigned(Box::new(
            JoseJwtDecodeUnsignedRequest {
                compact: unsigned_jwt.compact,
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let unsigned_claims = decode_claims_result(&wire::process_proto(
        &encode_protobuf(&jwt_decode_unsigned),
        &mut rng,
    ))?;
    assert_json_eq(&unsigned_claims.claims_json, &unsigned_claims_json)?;

    let secret = [5u8; 32];
    let (jwt_public, jwt_private) = generate_p256_keypair_from_secret_key(&secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &jwt_public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("kid-1".to_owned()),
        },
    )?);
    let jwk_json = serde_json::to_vec(&jwk)?;
    let signed_claims_json = br#"{"sub":"signed"}"#.to_vec();
    let jwt_sign = JoseOperationRequest {
        operation: Some(JoseOperation::JwtSign(Box::new(JoseJwtSignRequest {
            claims_json: signed_claims_json.clone(),
            jwk_json: jwk_json.clone(),
            private_key: jwt_private.to_vec(),
            typ: String::new(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let signed_jwt =
        decode_compact_result(&wire::process_proto(&encode_protobuf(&jwt_sign), &mut rng))?;

    let jwt_verify = JoseOperationRequest {
        operation: Some(JoseOperation::JwtVerify(Box::new(JoseJwtVerifyRequest {
            compact: signed_jwt.compact,
            jwk_json,
            public_key: jwt_public,
            header_policy: Default::default(),
            temporal_policy: Default::default(),
            signature_only: true,
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let signed_claims = decode_claims_result(&wire::process_proto(
        &encode_protobuf(&jwt_verify),
        &mut rng,
    ))?;
    assert_json_eq(&signed_claims.claims_json, &signed_claims_json)?;

    let jwe_key = vec![7u8; 16];
    let jwe_encrypt = JoseOperationRequest {
        operation: Some(JoseOperation::JweEncrypt(Box::new(JoseJweEncryptRequest {
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: jwe_key.clone(),
            plaintext: b"process-proto plaintext".to_vec(),
            kid: String::new(),
            apu: Vec::new(),
            apv: Vec::new(),
            typ: String::new(),
            cty: String::new(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let encrypted_jwe = decode_compact_result(&wire::process_proto(
        &encode_protobuf(&jwe_encrypt),
        &mut rng,
    ))?;

    let jwe_decrypt = JoseOperationRequest {
        operation: Some(JoseOperation::JweDecrypt(Box::new(JoseJweDecryptRequest {
            compact: encrypted_jwe.compact,
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: jwe_key,
            header_policy: Default::default(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let plaintext = decode_plaintext_result(&wire::process_proto(
        &encode_protobuf(&jwe_decrypt),
        &mut rng,
    ))?;
    assert_eq!(plaintext.plaintext, b"process-proto plaintext");

    Ok(())
}

#[test]
fn process_json_and_process_proto_match_for_generated_dispatcher(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = FixedRandom::new([9u8; 12]);
    let (_public, private) = generate_keypair(Algorithm::Ed25519)?;
    let request = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            private_key: private.to_vec(),
            payload: b"cid:example:process-json".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    let protobuf_result =
        decode_compact_result(&wire::process_proto(&encode_protobuf(&request), &mut rng))?;
    let json_result =
        decode_compact_result(&wire::process_json(&encode_json(&request)?, &mut rng))?;
    assert_eq!(protobuf_result.compact, json_result.compact);

    Ok(())
}

#[test]
fn process_proto_ignores_unknown_fields_on_valid_request() -> Result<(), Box<dyn std::error::Error>>
{
    let mut rng = FixedRandom::new([9u8; 12]);
    let (_public, private) = generate_keypair(Algorithm::Ed25519)?;
    let request = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            private_key: private.to_vec(),
            payload: b"cid:example:unknown-field".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let mut request_bytes = encode_protobuf(&request);
    request_bytes.extend_from_slice(&[0x78, 0x01]);

    let compact = decode_compact_result(&wire::process_proto(&request_bytes, &mut rng))?;
    assert!(!compact.compact.is_empty());

    Ok(())
}

#[test]
fn process_proto_output_and_envelope_bytes_match_cose_style_adapter(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = FixedRandom::new([9u8; 12]);
    let (_public, private) = generate_keypair(Algorithm::Ed25519)?;
    let request = JoseOperationRequest {
        operation: Some(JoseOperation::JwsSign(Box::new(JoseJwsSignRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            private_key: private.to_vec(),
            payload: b"cid:example:output".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let request_bytes = encode_protobuf(&request);

    let output = wire::process_proto_output(&request_bytes, &mut rng);
    assert_eq!(output.status(), JoseProtoStatus::Result);
    let compact = JoseCompactResult::decode_from_slice(output.bytes())?;
    assert!(!compact.compact.is_empty());

    let envelope_bytes = wire::process_proto(&request_bytes, &mut rng);
    let envelope = match wire::decode_proto_result_envelope(envelope_bytes.as_slice()) {
        Ok(envelope) => envelope,
        Err(_) => panic!("envelope decode failed"),
    };
    assert_eq!(envelope.status(), JoseProtoStatus::Result);
    let enveloped_compact = JoseCompactResult::decode_from_slice(envelope.payload())?;
    assert!(!enveloped_compact.compact.is_empty());

    Ok(())
}

#[test]
fn jose_proto_output_json_round_trips_error_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let output = wire::jose_error_output(wire_error(
        JoseWireErrorBranch::Provider,
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNAVAILABLE,
    ));
    let json = match wire::jose_proto_output_to_json(&output) {
        Ok(json) => json,
        Err(_) => panic!("json encode failed"),
    };
    let decoded = match wire::jose_proto_output_from_json(&json) {
        Ok(decoded) => decoded,
        Err(_) => panic!("json decode failed"),
    };

    assert!(json.contains("\"payload\""));
    assert!(!json.contains("\"bytes\""));
    assert_eq!(decoded.status(), JoseProtoStatus::JoseError);
    assert_error(
        decoded.payload(),
        "provider",
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNAVAILABLE,
    )?;

    Ok(())
}

#[test]
fn oversized_process_proto_input_returns_resource_limit() -> Result<(), buffa::DecodeError> {
    let oversized = vec![0u8; MAX_JOSE_PROTO_MESSAGE_BYTES + 1];
    let output = wire::process_proto_output(&oversized, &mut FixedRandom::new([9u8; 12]));
    assert_eq!(output.status(), JoseProtoStatus::JoseError);
    assert_error(
        output.bytes(),
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
    )?;
    Ok(())
}

#[test]
fn maximum_result_payload_round_trips_through_envelope_limit() {
    let payload = vec![7u8; MAX_JOSE_PROTO_MESSAGE_BYTES];
    let encoded = match wire::result_envelope_bytes(payload.clone()) {
        Ok(encoded) => encoded,
        Err(_) => panic!("maximum result payload was rejected during encoding"),
    };
    assert!(encoded.len() > MAX_JOSE_PROTO_MESSAGE_BYTES);

    let decoded = match wire::decode_proto_result_envelope(&encoded) {
        Ok(decoded) => decoded,
        Err(_) => panic!("maximum result envelope was rejected during decoding"),
    };
    assert_eq!(decoded.status(), JoseProtoStatus::Result);
    assert_eq!(decoded.payload(), payload);
}

#[test]
fn json_request_cannot_expand_beyond_binary_message_budget() -> Result<(), buffa::DecodeError> {
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        private_key: Vec::new(),
        payload: vec![b'a'; MAX_JOSE_PROTO_MESSAGE_BYTES],
        __buffa_unknown_fields: Default::default(),
    };
    let json = match encode_json(&request) {
        Ok(json) => json,
        Err(_) => panic!("test request JSON should serialize"),
    };
    assert!(json.len() < MAX_JOSE_PROTO_JSON_BYTES);

    let envelope = decode_envelope(&wire::sign_jws_envelope_from_json(&json))?;
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
    )?;
    Ok(())
}

#[test]
fn oversized_process_json_input_returns_resource_limit() -> Result<(), buffa::DecodeError> {
    let oversized = vec![b' '; MAX_JOSE_PROTO_JSON_BYTES + 1];
    let envelope = decode_envelope(&wire::process_json(
        &oversized,
        &mut FixedRandom::new([9u8; 12]),
    ))?;
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
    )?;
    Ok(())
}

#[test]
fn oversized_jose_proto_output_json_returns_resource_limit() -> Result<(), buffa::DecodeError> {
    let oversized = " ".repeat(MAX_JOSE_PROTO_JSON_BYTES + 1);
    let output = match wire::jose_proto_output_from_json(&oversized) {
        Ok(_) => panic!("oversized JOSE output JSON decoded successfully"),
        Err(output) => output,
    };
    assert_eq!(output.status(), JoseProtoStatus::JoseError);
    assert_error(
        output.bytes(),
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
    )?;
    Ok(())
}

#[test]
fn process_proto_missing_operation_returns_backend_error() -> Result<(), buffa::DecodeError> {
    let request = JoseOperationRequest {
        operation: None,
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::process_proto(
        &encode_protobuf(&request),
        &mut FixedRandom::new([9u8; 12]),
    ))?;
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MISSING_OPERATION,
    )?;
    Ok(())
}

#[test]
fn out_of_range_raw_signature_algorithm_is_provider_unsupported() -> Result<(), buffa::DecodeError>
{
    let mut request_bytes = vec![0x08, 0x63, 0x1a, 0x07];
    request_bytes.extend_from_slice(b"payload");
    let envelope = decode_envelope(&sign_jws_envelope_from_protobuf(&request_bytes))?;
    assert_error(
        &envelope.payload,
        "provider",
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
    )?;
    Ok(())
}

#[test]
fn invalid_jws_signature_preserves_signature_reason() -> Result<(), Box<dyn std::error::Error>> {
    let (public, private) = generate_keypair(Algorithm::Ed25519)?;
    let sign_request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        private_key: private.to_vec(),
        payload: b"cid:example:wire".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let signed = decode_compact_result(&sign_jws_envelope_from_protobuf(&encode_protobuf(
        &sign_request,
    )))?;
    let tampered = tamper_signature_segment(&signed.compact);

    let verify_request = JoseJwsVerifyRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        compact: tampered,
        public_key: public,
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&verify_jws_envelope(verify_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
    )?;

    Ok(())
}

#[test]
fn unsupported_jws_algorithm_preserves_provider_branch() -> Result<(), buffa::DecodeError> {
    let request = JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED),
        private_key: vec![1u8; 32],
        payload: b"payload".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&sign_jws_envelope_from_protobuf(&encode_protobuf(&request)))?;
    assert_error(
        &envelope.payload,
        "provider",
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
    )?;
    Ok(())
}

#[test]
fn jwe_invalid_key_length_is_not_authentication_failure() -> Result<(), buffa::DecodeError> {
    let request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: vec![1u8; 15],
        plaintext: b"plaintext".to_vec(),
        kid: String::new(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: String::new(),
        cty: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut rng = FixedRandom::new([9u8; 12]);
    let envelope = decode_envelope(&wire::encrypt_jwe_envelope(request, &mut rng))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY,
    )?;
    Ok(())
}

#[test]
fn jwe_wire_decrypt_enforces_exact_kid_policy() -> Result<(), Box<dyn std::error::Error>> {
    let key = [7u8; 16];
    let request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: key.to_vec(),
        plaintext: b"plaintext".to_vec(),
        kid: "recipient-a".to_owned(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: String::new(),
        cty: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut rng = FixedRandom::new([9u8; 12]);
    let encrypted = decode_compact_result(&wire::encrypt_jwe_envelope(request, &mut rng))?;
    let policy = JoseJweHeaderValidationPolicy {
        require_kid: false,
        expected_kid: JoseExpectedString {
            value: "recipient-b".to_owned(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        expected_typ: Default::default(),
        expected_cty: Default::default(),
        expected_apu: Default::default(),
        expected_apv: Default::default(),
        __buffa_unknown_fields: Default::default(),
    };
    let decrypt_request = JoseJweDecryptRequest {
        compact: encrypted.compact,
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: key.to_vec(),
        header_policy: policy.into(),
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::decrypt_jwe_envelope(decrypt_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
    )?;
    Ok(())
}

#[test]
fn jwe_wire_decrypt_enforces_presence_and_all_exact_header_values(
) -> Result<(), Box<dyn std::error::Error>> {
    const RECIPIENT_PRIVATE_KEY: [u8; 32] = [5u8; 32];
    const KID: &str = "recipient-a";
    const TYP: &str = "oauth-authz-resp+jwt";
    const CTY: &str = "application/json";
    const APU: &[u8] = b"wallet";
    const APV: &[u8] = b"verifier";

    let (recipient_public_key, recipient_private_key) =
        generate_p256_keypair_from_secret_key(&RECIPIENT_PRIVATE_KEY)?;
    let encrypt_request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: recipient_public_key,
        plaintext: b"plaintext".to_vec(),
        kid: KID.to_owned(),
        apu: APU.to_vec(),
        apv: APV.to_vec(),
        typ: TYP.to_owned(),
        cty: CTY.to_owned(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut rng = FixedRandom::new([9u8; 12]);
    let encrypted = decode_compact_result(&wire::encrypt_jwe_envelope(encrypt_request, &mut rng))?;
    let expected_policy = JoseJweHeaderValidationPolicy {
        require_kid: true,
        expected_kid: JoseExpectedString {
            value: KID.to_owned(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        expected_typ: JoseExpectedString {
            value: TYP.to_owned(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        expected_cty: JoseExpectedString {
            value: CTY.to_owned(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        expected_apu: JoseExpectedBytes {
            value: APU.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        expected_apv: JoseExpectedBytes {
            value: APV.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        __buffa_unknown_fields: Default::default(),
    };
    let decrypt_with_policy = |header_policy: JoseJweHeaderValidationPolicy| {
        wire::decrypt_jwe_envelope(JoseJweDecryptRequest {
            compact: encrypted.compact.clone(),
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: recipient_private_key.to_vec(),
            header_policy: header_policy.into(),
            __buffa_unknown_fields: Default::default(),
        })
    };

    let plaintext = decode_plaintext_result(&decrypt_with_policy(expected_policy.clone()))?;
    assert_eq!(plaintext.plaintext, b"plaintext");

    #[derive(Clone, Copy)]
    enum HeaderMismatch {
        Kid,
        Typ,
        Cty,
        Apu,
        Apv,
    }

    let mismatches = [
        (
            JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
            HeaderMismatch::Kid,
        ),
        (
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
            HeaderMismatch::Typ,
        ),
        (
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
            HeaderMismatch::Cty,
        ),
        (
            JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH,
            HeaderMismatch::Apu,
        ),
        (
            JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH,
            HeaderMismatch::Apv,
        ),
    ];
    for (reason, field) in mismatches {
        let mut policy = expected_policy.clone();
        match field {
            HeaderMismatch::Kid => {
                policy.expected_kid = JoseExpectedString {
                    value: "other-kid".to_owned(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into();
            }
            HeaderMismatch::Typ => {
                policy.expected_typ = JoseExpectedString {
                    value: "other-typ".to_owned(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into();
            }
            HeaderMismatch::Cty => {
                policy.expected_cty = JoseExpectedString {
                    value: "other-cty".to_owned(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into();
            }
            HeaderMismatch::Apu => {
                policy.expected_apu = JoseExpectedBytes {
                    value: b"other-apu".to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into();
            }
            HeaderMismatch::Apv => {
                policy.expected_apv = JoseExpectedBytes {
                    value: b"other-apv".to_vec(),
                    __buffa_unknown_fields: Default::default(),
                }
                .into();
            }
        }
        let envelope = decode_envelope(&decrypt_with_policy(policy))?;
        assert_error(&envelope.payload, "primitive", reason)?;
    }

    Ok(())
}

#[test]
fn jwe_wire_decrypt_enforces_required_kid_presence() -> Result<(), Box<dyn std::error::Error>> {
    let key = [7u8; 16];
    let encrypt_request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: key.to_vec(),
        plaintext: b"plaintext".to_vec(),
        kid: String::new(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: String::new(),
        cty: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut rng = FixedRandom::new([9u8; 12]);
    let encrypted = decode_compact_result(&wire::encrypt_jwe_envelope(encrypt_request, &mut rng))?;
    let decrypt_request = JoseJweDecryptRequest {
        compact: encrypted.compact,
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: key.to_vec(),
        header_policy: JoseJweHeaderValidationPolicy {
            require_kid: true,
            expected_kid: Default::default(),
            expected_typ: Default::default(),
            expected_cty: Default::default(),
            expected_apu: Default::default(),
            expected_apv: Default::default(),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::decrypt_jwe_envelope(decrypt_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWE_MISSING_REQUIRED_HEADER_PARAMETER,
    )?;
    Ok(())
}

#[test]
fn jwe_randomness_failure_preserves_provider_branch() -> Result<(), buffa::DecodeError> {
    let request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: vec![1u8; 16],
        plaintext: b"plaintext".to_vec(),
        kid: String::new(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: String::new(),
        cty: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::encrypt_jwe_envelope(request, &mut FailingRandom))?;
    assert_error(
        &envelope.payload,
        "provider",
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
    )?;
    Ok(())
}

#[test]
fn jwe_authentication_failure_stays_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let key = [7u8; 16];
    let request = JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: key.to_vec(),
        plaintext: b"plaintext".to_vec(),
        kid: String::new(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: String::new(),
        cty: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let mut rng = FixedRandom::new([9u8; 12]);
    let encrypted = decode_compact_result(&wire::encrypt_jwe_envelope(request, &mut rng))?;

    let decrypt_request = JoseJweDecryptRequest {
        compact: encrypted.compact,
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: vec![8u8; 16],
        header_policy: Default::default(),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::decrypt_jwe_envelope(decrypt_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWE_DECRYPT_FAILED,
    )?;
    Ok(())
}

#[test]
fn jwt_invalid_claims_json_preserves_claims_reason() -> Result<(), buffa::DecodeError> {
    let request = JoseJwtEncodeUnsignedRequest {
        claims_json: b"not-json".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::encode_unsigned_jwt_envelope(request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_CLAIMS,
    )?;
    Ok(())
}

#[test]
fn jwt_sign_and_verify_wire_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let secret = [5u8; 32];
    let (public, private) = generate_p256_keypair_from_secret_key(&secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("kid-1".to_owned()),
        },
    )?);
    let jwk_json = serde_json::to_vec(&jwk)?;
    let claims_json = br#"{"sub":"123","iss":"issuer"}"#.to_vec();
    let sign_request = JoseJwtSignRequest {
        claims_json,
        jwk_json: jwk_json.clone(),
        private_key: private.to_vec(),
        typ: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let signed = decode_compact_result(&wire::sign_jwt_envelope(sign_request))?;
    let verify_request = JoseJwtVerifyRequest {
        compact: signed.compact,
        jwk_json,
        public_key: public,
        header_policy: Default::default(),
        temporal_policy: Default::default(),
        signature_only: true,
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT
    );
    Ok(())
}

#[test]
fn jwt_verify_wire_rejects_jwk_key_id_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_jwt_fixture()?;
    let mut jwk: serde_json::Value = serde_json::from_slice(&fixture.jwk_json)?;
    let Some(object) = jwk.as_object_mut() else {
        panic!("fixture JWK is not an object");
    };
    object.insert(
        "kid".to_owned(),
        serde_json::Value::String("kid-2".to_owned()),
    );
    let verify_request = JoseJwtVerifyRequest {
        compact: fixture.compact,
        jwk_json: serde_json::to_vec(&jwk)?,
        public_key: fixture.public_key,
        header_policy: Default::default(),
        temporal_policy: Default::default(),
        signature_only: true,
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR
    );
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_KID_POLICY_MISMATCH,
    )?;
    Ok(())
}

#[test]
fn jwt_verify_wire_rejects_jwk_public_key_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let secret = [5u8; 32];
    let other_secret = [6u8; 32];
    let (public, private) = generate_p256_keypair_from_secret_key(&secret)?;
    let (other_public, _other_private) = generate_p256_keypair_from_secret_key(&other_secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("kid-1".to_owned()),
        },
    )?);
    let jwk_json = serde_json::to_vec(&jwk)?;
    let sign_request = JoseJwtSignRequest {
        claims_json: br#"{"sub":"123","iss":"issuer"}"#.to_vec(),
        jwk_json: jwk_json.clone(),
        private_key: private.to_vec(),
        typ: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let signed = decode_compact_result(&wire::sign_jwt_envelope(sign_request))?;
    let verify_request = JoseJwtVerifyRequest {
        compact: signed.compact,
        jwk_json,
        public_key: other_public,
        header_policy: Default::default(),
        temporal_policy: Default::default(),
        signature_only: true,
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR
    );
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH,
    )?;
    Ok(())
}

#[test]
fn jwt_verify_wire_requires_explicit_signature_only_mode() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = signed_jwt_fixture()?;
    let verify_request = JoseJwtVerifyRequest {
        compact: fixture.compact,
        jwk_json: fixture.jwk_json,
        public_key: fixture.public_key,
        header_policy: Default::default(),
        temporal_policy: Default::default(),
        signature_only: false,
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
    )?;
    Ok(())
}

#[test]
fn jwt_verify_wire_rejects_temporal_policy_without_now_unix(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_jwt_fixture()?;
    let verify_request = JoseJwtVerifyRequest {
        compact: fixture.compact,
        jwk_json: fixture.jwk_json,
        public_key: fixture.public_key,
        header_policy: Default::default(),
        temporal_policy: JoseJwtTemporalValidationPolicy {
            require_exp: true,
            require_nbf: false,
            require_iat: false,
            clock_skew_seconds: 0,
            max_future_iat_skew_seconds: 0,
            now_unix: 0,
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        signature_only: false,
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME,
    )?;
    Ok(())
}

#[test]
fn jwt_verify_wire_rejects_unbounded_temporal_skew() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_jwt_fixture()?;
    let verify_request = JoseJwtVerifyRequest {
        compact: fixture.compact,
        jwk_json: fixture.jwk_json,
        public_key: fixture.public_key,
        header_policy: Default::default(),
        temporal_policy: JoseJwtTemporalValidationPolicy {
            require_exp: true,
            require_nbf: false,
            require_iat: false,
            clock_skew_seconds: u64::MAX,
            max_future_iat_skew_seconds: 60,
            now_unix: 1_720_000_000,
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        signature_only: false,
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
    )?;
    Ok(())
}

#[test]
fn jwt_verify_wire_rejects_malformed_jwk_json() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_jwt_fixture()?;
    let verify_request = JoseJwtVerifyRequest {
        compact: fixture.compact,
        jwk_json: b"not-json".to_vec(),
        public_key: fixture.public_key,
        header_policy: Default::default(),
        temporal_policy: Default::default(),
        signature_only: true,
        __buffa_unknown_fields: Default::default(),
    };

    let envelope = decode_envelope(&wire::verify_jwt_envelope(verify_request))?;
    assert_error(
        &envelope.payload,
        "primitive",
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK,
    )?;
    Ok(())
}

#[test]
fn every_jose_error_reason_passes_through_rust_envelope() -> Result<(), buffa::DecodeError> {
    for value in 1..=73 {
        let Some(reason) = JoseErrorReason::from_i32(value) else {
            continue;
        };
        let (error, branch) = match value {
            1..=63 => (
                wire_error(JoseWireErrorBranch::Primitive, reason),
                "primitive",
            ),
            64..=66 => (
                wire_error(JoseWireErrorBranch::Provider, reason),
                "provider",
            ),
            67..=73 => (wire_error(JoseWireErrorBranch::Backend, reason), "backend"),
            _ => continue,
        };
        let decoded = JoseError::decode_from_slice(&jose_error_bytes(error))?;
        assert_error_branch(decoded, branch, reason);
    }

    Ok(())
}

#[test]
fn rejects_reason_assigned_to_wrong_error_branch() -> Result<(), buffa::DecodeError> {
    assert!(JoseWireError::try_new(
        JoseWireErrorBranch::Provider,
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER,
    )
    .is_err());

    let error = JoseError {
        error: Some(JoseErrorBranch::Provider(Box::new(
            reallyme_jose::wire::proto::proto::reallyme::jose::v1::JoseProviderError {
                reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = JoseProtoResultEnvelope {
        status: EnumValue::from(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR),
        payload: error.encode_to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let output = match wire::decode_proto_result_envelope(&encode_protobuf(&envelope)) {
        Ok(_) => panic!("mismatched JOSE error branch decoded successfully"),
        Err(output) => output,
    };
    assert_error(
        output.payload(),
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
    )?;
    Ok(())
}

#[test]
fn jose_error_envelope_rejects_malformed_error_payload() -> Result<(), buffa::DecodeError> {
    let malformed = JoseProtoResultEnvelope {
        status: EnumValue::from(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR),
        payload: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let output = match wire::decode_proto_result_envelope(&encode_protobuf(&malformed)) {
        Ok(_) => panic!("malformed JOSE error envelope decoded successfully"),
        Err(output) => output,
    };

    assert_eq!(output.status(), JoseProtoStatus::JoseError);
    assert_error(
        output.payload(),
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
    )?;
    Ok(())
}

#[test]
fn jose_error_envelope_rejects_unspecified_error_reason() -> Result<(), buffa::DecodeError> {
    let error = JoseError {
        error: Some(JoseErrorBranch::Primitive(Box::new(JosePrimitiveError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_UNSPECIFIED),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let envelope = JoseProtoResultEnvelope {
        status: EnumValue::from(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR),
        payload: error.encode_to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let output = match wire::decode_proto_result_envelope(&encode_protobuf(&envelope)) {
        Ok(_) => panic!("unspecified JOSE error reason decoded successfully"),
        Err(output) => output,
    };

    assert_eq!(output.status(), JoseProtoStatus::JoseError);
    assert_error(
        output.payload(),
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
    )?;
    Ok(())
}

#[test]
fn serialized_error_passes_through_rust_losslessly() -> Result<(), buffa::DecodeError> {
    let bytes = jose_error_bytes(wire_error(
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER,
    ));
    let decoded = JoseError::decode_from_slice(&bytes)?;
    assert_eq!(decoded.encode_to_vec().as_slice(), bytes.as_slice());

    let provider_envelope = error_envelope_bytes(wire_error(
        JoseWireErrorBranch::Provider,
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNAVAILABLE,
    ));
    let envelope = decode_envelope(&provider_envelope)?;
    assert_error(
        &envelope.payload,
        "provider",
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNAVAILABLE,
    )?;

    let backend_envelope = error_envelope_bytes(wire_error(
        JoseWireErrorBranch::Backend,
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL,
    ));
    let envelope = decode_envelope(&backend_envelope)?;
    assert_error(
        &envelope.payload,
        "backend",
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL,
    )?;

    Ok(())
}

fn assert_error_branch(error: JoseError, expected_branch: &str, expected_reason: JoseErrorReason) {
    match (expected_branch, error.error) {
        ("primitive", Some(JoseErrorBranch::Primitive(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        ("provider", Some(JoseErrorBranch::Provider(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        ("backend", Some(JoseErrorBranch::Backend(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        _ => {
            panic!("unexpected JOSE error branch");
        }
    }
}

fn decode_envelope(bytes: &[u8]) -> Result<JoseProtoResultEnvelope, buffa::DecodeError> {
    JoseProtoResultEnvelope::decode_from_slice(bytes)
}

fn decode_compact_result(bytes: &[u8]) -> Result<JoseCompactResult, buffa::DecodeError> {
    let envelope = decode_envelope(bytes)?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT
    );
    JoseCompactResult::decode_from_slice(&envelope.payload)
}

fn decode_verify_result(bytes: &[u8]) -> Result<JoseVerifyResult, buffa::DecodeError> {
    let envelope = decode_envelope(bytes)?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT
    );
    JoseVerifyResult::decode_from_slice(&envelope.payload)
}

fn decode_claims_result(bytes: &[u8]) -> Result<JoseJwtClaimsResult, buffa::DecodeError> {
    let envelope = decode_envelope(bytes)?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT
    );
    JoseJwtClaimsResult::decode_from_slice(&envelope.payload)
}

fn decode_plaintext_result(bytes: &[u8]) -> Result<JoseJwePlaintextResult, buffa::DecodeError> {
    let envelope = decode_envelope(bytes)?;
    assert_eq!(
        envelope.status,
        JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT
    );
    JoseJwePlaintextResult::decode_from_slice(&envelope.payload)
}

struct SignedJwtFixture {
    compact: String,
    jwk_json: Vec<u8>,
    public_key: Vec<u8>,
}

fn signed_jwt_fixture() -> Result<SignedJwtFixture, Box<dyn std::error::Error>> {
    let secret = [5u8; 32];
    let (public, private) = generate_p256_keypair_from_secret_key(&secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("kid-1".to_owned()),
        },
    )?);
    let jwk_json = serde_json::to_vec(&jwk)?;
    let sign_request = JoseJwtSignRequest {
        claims_json: br#"{"sub":"123","iss":"issuer","exp":2000000000}"#.to_vec(),
        jwk_json: jwk_json.clone(),
        private_key: private.to_vec(),
        typ: String::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let signed = decode_compact_result(&wire::sign_jwt_envelope(sign_request))?;
    Ok(SignedJwtFixture {
        compact: signed.compact,
        jwk_json,
        public_key: public,
    })
}

fn assert_json_eq(left: &[u8], right: &[u8]) -> Result<(), serde_json::Error> {
    let left: serde_json::Value = serde_json::from_slice(left)?;
    let right: serde_json::Value = serde_json::from_slice(right)?;
    assert_eq!(left, right);
    Ok(())
}

fn assert_error(
    bytes: &[u8],
    expected_branch: &str,
    expected_reason: JoseErrorReason,
) -> Result<(), buffa::DecodeError> {
    let error = JoseError::decode_from_slice(bytes)?;
    match (expected_branch, error.error) {
        ("primitive", Some(JoseErrorBranch::Primitive(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        ("provider", Some(JoseErrorBranch::Provider(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        ("backend", Some(JoseErrorBranch::Backend(error))) => {
            assert_eq!(error.reason, expected_reason);
        }
        _ => {
            panic!("unexpected JOSE error branch");
        }
    }
    Ok(())
}

fn tamper_signature_segment(compact: &str) -> String {
    let Some((prefix, signature)) = compact.rsplit_once('.') else {
        return compact.to_owned();
    };

    let mut output = String::with_capacity(compact.len());
    output.push_str(prefix);
    output.push('.');

    let mut changed = false;
    for ch in signature.chars() {
        if changed {
            output.push(ch);
        } else {
            output.push(if ch == 'A' { 'B' } else { 'A' });
            changed = true;
        }
    }

    if changed {
        output
    } else {
        compact.to_owned()
    }
}

struct FixedRandom {
    bytes: [u8; 12],
}

impl FixedRandom {
    const fn new(bytes: [u8; 12]) -> Self {
        Self { bytes }
    }
}

impl SecureRandom for FixedRandom {
    fn fill_secure(
        &mut self,
        output: &mut [u8],
        output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        if output.len() != self.bytes.len() {
            return Err(CryptoError::Rng {
                output: output_kind,
                kind: RngFailureKind::InvalidOutputLength,
            });
        }
        output.copy_from_slice(&self.bytes);
        Ok(())
    }
}

struct FailingRandom;

impl SecureRandom for FailingRandom {
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
