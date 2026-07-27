// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for the versioned, fully discriminated operation response.

#![cfg(feature = "wire")]
#![allow(missing_docs, clippy::panic)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto::core::{Algorithm, CryptoError, RngFailureKind, RngOutputKind};
use reallyme_crypto::p256::generate_p256_keypair_from_secret_key;
use reallyme_crypto::{
    csprng::SecureRandom,
    dispatch::generate_keypair,
    jwk::{p256_public_key_to_jwk, JwkOptions},
};
use reallyme_jose::jwt::encode_signed_jwt;
use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_error::Error as ErrorBranch, jose_jwe_decrypt_response::Outcome as JweDecryptOutcome,
        jose_jwe_encrypt_response::Outcome as JweEncryptOutcome,
        jose_jws_sign_response::Outcome as JwsSignOutcome,
        jose_jws_verify_response::Outcome as JwsVerifyOutcome,
        jose_jwt_decode_unsigned_response::Outcome as JwtDecodeUnsignedOutcome,
        jose_jwt_encode_unsigned_response::Outcome as JwtEncodeUnsignedOutcome,
        jose_jwt_sign_response::Outcome as JwtSignOutcome,
        jose_jwt_verify_response::Outcome as JwtVerifyOutcome,
        jose_operation_request::Operation as RequestOperation, jose_operation_response::Response,
    },
    JoseCompactResult, JoseError, JoseErrorReason, JoseJweContentEncryptionAlgorithm,
    JoseJweDecryptRequest, JoseJweDecryptResponse, JoseJweEncryptRequest,
    JoseJweKeyManagementAlgorithm, JoseJwePlaintextResult, JoseJwsSignRequest,
    JoseJwsVerifyRequest, JoseJwsVerifyResponse, JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest,
    JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest, JoseJwtTemporalValidationPolicy,
    JoseJwtVerifyRequest, JoseOperationContractVersion, JoseOperationRequest,
    JoseOperationResponse, JoseProviderError, JoseSignatureAlgorithm, JoseVerifyResult,
};
use reallyme_jose::wire::{
    decode_operation_response_v1, encode_json, encode_protobuf, execute_operation_json_v1,
    execute_operation_v1, jose_error, JoseOperationKind, JoseWireError, JoseWireErrorBranch,
    MAX_JOSE_PROTO_MESSAGE_BYTES, MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use reallyme_jose::Jwk;

#[test]
fn all_operations_match_binary_and_proto_json_routes() -> Result<(), Box<dyn std::error::Error>> {
    let (jws_public, jws_private) = generate_keypair(Algorithm::Ed25519)?;
    let jws_sign = operation(RequestOperation::JwsSign(Box::new(JoseJwsSignRequest {
        algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
        private_key: jws_private.to_vec(),
        payload: b"stage-11-jws".to_vec(),
        __buffa_unknown_fields: Default::default(),
    })));
    let signed_jws = decode_compact(&assert_route_parity(
        &jws_sign,
        JoseOperationKind::JwsSign,
        [1u8; 12],
    )?)?;

    let jws_verify = operation(RequestOperation::JwsVerify(Box::new(
        JoseJwsVerifyRequest {
            algorithm: EnumValue::from(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA),
            compact: signed_jws,
            public_key: jws_public,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_route_parity(&jws_verify, JoseOperationKind::JwsVerify, [2u8; 12])?;

    let unsigned_claims = br#"{"sub":"unsigned-stage-11"}"#.to_vec();
    let jwt_encode = operation(RequestOperation::JwtEncodeUnsigned(Box::new(
        JoseJwtEncodeUnsignedRequest {
            claims_json: unsigned_claims.clone(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let unsigned_compact = decode_compact(&assert_route_parity(
        &jwt_encode,
        JoseOperationKind::JwtEncodeUnsigned,
        [3u8; 12],
    )?)?;

    let jwt_decode = operation(RequestOperation::JwtDecodeUnsigned(Box::new(
        JoseJwtDecodeUnsignedRequest {
            compact: unsigned_compact,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let decoded_claims = decode_claims(&assert_route_parity(
        &jwt_decode,
        JoseOperationKind::JwtDecodeUnsigned,
        [4u8; 12],
    )?)?;
    assert_eq!(decoded_claims, unsigned_claims);

    let secret = [5u8; 32];
    let (jwt_public, jwt_private) = generate_p256_keypair_from_secret_key(&secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &jwt_public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("stage-11-key".to_owned()),
        },
    )?);
    let jwk_json = serde_json::to_vec(&jwk)?;
    let signed_claims = br#"{"sub":"signed-stage-11"}"#.to_vec();
    let jwt_sign = operation(RequestOperation::JwtSign(Box::new(JoseJwtSignRequest {
        claims_json: signed_claims.clone(),
        jwk_json: jwk_json.clone(),
        private_key: jwt_private.to_vec(),
        typ: String::new(),
        __buffa_unknown_fields: Default::default(),
    })));
    let signed_compact = decode_compact(&assert_route_parity(
        &jwt_sign,
        JoseOperationKind::JwtSign,
        [6u8; 12],
    )?)?;

    let jwt_verify = operation(RequestOperation::JwtVerify(Box::new(
        JoseJwtVerifyRequest {
            compact: signed_compact,
            jwk_json,
            public_key: jwt_public,
            header_policy: Default::default(),
            temporal_policy: Default::default(),
            signature_only: true,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let verified_claims = decode_claims(&assert_route_parity(
        &jwt_verify,
        JoseOperationKind::JwtVerify,
        [7u8; 12],
    )?)?;
    assert_eq!(verified_claims, signed_claims);

    let jwe_key = vec![8u8; 16];
    let plaintext = b"stage-11 plaintext".to_vec();
    let jwe_encrypt = operation(RequestOperation::JweEncrypt(Box::new(
        JoseJweEncryptRequest {
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: jwe_key.clone(),
            plaintext: plaintext.clone(),
            kid: String::new(),
            apu: Vec::new(),
            apv: Vec::new(),
            typ: String::new(),
            cty: String::new(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let encrypted = decode_compact(&assert_route_parity(
        &jwe_encrypt,
        JoseOperationKind::JweEncrypt,
        [9u8; 12],
    )?)?;

    let jwe_decrypt = operation(RequestOperation::JweDecrypt(Box::new(
        JoseJweDecryptRequest {
            compact: encrypted,
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: jwe_key,
            header_policy: Default::default(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let decrypted = decode_plaintext(&assert_route_parity(
        &jwe_decrypt,
        JoseOperationKind::JweDecrypt,
        [10u8; 12],
    )?)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn boundary_and_selected_operation_failures_remain_discriminated(
) -> Result<(), Box<dyn std::error::Error>> {
    let malformed = execute_operation_v1(&[0xff], &mut FixedRandom::new([1u8; 12]));
    let malformed = decode_operation_response_v1(&malformed, JoseOperationKind::JwsSign)?;
    assert_response_error(
        malformed,
        None,
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF,
    );

    let malformed_json = execute_operation_json_v1(b"{", &mut FixedRandom::new([1u8; 12]));
    let malformed_json = decode_operation_response_v1(&malformed_json, JoseOperationKind::JwsSign)?;
    assert_response_error(
        malformed_json,
        None,
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON,
    );

    let unsupported = operation(RequestOperation::JwsSign(Box::new(JoseJwsSignRequest {
        algorithm: EnumValue::from(99),
        private_key: Vec::new(),
        payload: b"payload".to_vec(),
        __buffa_unknown_fields: Default::default(),
    })));
    let unsupported = execute_operation_v1(
        &encode_protobuf(&unsupported),
        &mut FixedRandom::new([1u8; 12]),
    );
    let unsupported = decode_operation_response_v1(&unsupported, JoseOperationKind::JwsSign)?;
    assert_response_error(
        unsupported,
        Some(JoseOperationKind::JwsSign),
        JoseWireErrorBranch::Provider,
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
    );
    Ok(())
}

#[test]
fn protojson_request_rejects_duplicate_and_unknown_members(
) -> Result<(), Box<dyn std::error::Error>> {
    let malformed_requests: &[&[u8]] = &[
        br#"{"jwsSign":null,"jwsSign":null}"#,
        br#"{"jwsSign":{"payload":"","payload":""}}"#,
        br#"{"unknownOperation":{}}"#,
        br#"{"jwsSign":{"unknownField":true}}"#,
    ];

    for request in malformed_requests {
        let response = execute_operation_json_v1(request, &mut FixedRandom::new([1u8; 12]));
        let response = decode_operation_response_v1(&response, JoseOperationKind::JwsSign)?;
        assert_response_error(
            response,
            None,
            JoseWireErrorBranch::Primitive,
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON,
        );
    }
    Ok(())
}

#[test]
fn jwt_wire_temporal_policy_rejects_audience_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    const NOW_UNIX: u64 = 1_720_000_000;

    let secret = [17u8; 32];
    let (public_key, private_key) = generate_p256_keypair_from_secret_key(&secret)?;
    let jwk = Jwk::Ec(p256_public_key_to_jwk(
        &public_key,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("audience-policy-key".to_owned()),
        },
    )?);
    let compact = encode_signed_jwt(
        &serde_json::json!({
            "aud": "service-a",
            "exp": NOW_UNIX + 300,
        }),
        &jwk,
        &private_key,
    )?;
    let request = operation(RequestOperation::JwtVerify(Box::new(
        JoseJwtVerifyRequest {
            compact,
            jwk_json: serde_json::to_vec(&jwk)?,
            public_key,
            header_policy: Default::default(),
            temporal_policy: JoseJwtTemporalValidationPolicy {
                require_exp: true,
                require_nbf: false,
                require_iat: false,
                clock_skew_seconds: 60,
                max_future_iat_skew_seconds: 60,
                now_unix: NOW_UNIX,
                expected_audience: "service-b".to_owned(),
                expected_issuer: String::new(),
                expected_subject: String::new(),
                __buffa_unknown_fields: Default::default(),
            }
            .into(),
            signature_only: false,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let encoded = encode_protobuf(&request);
    let response = execute_operation_v1(&encoded, &mut FixedRandom::new([3u8; 12]));
    let response = decode_operation_response_v1(&response, JoseOperationKind::JwtVerify)?;

    assert_response_error(
        response,
        Some(JoseOperationKind::JwtVerify),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH,
    );
    Ok(())
}

#[test]
fn canonical_decoder_rejects_malformed_versions_oneofs_and_operations() {
    let missing_version = JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_UNSPECIFIED,
        ),
        response: Some(valid_verify_response()),
        __buffa_unknown_fields: Default::default(),
    };
    assert_backend_rejection(
        &encode_protobuf(&missing_version),
        JoseOperationKind::JwsVerify,
    );

    let unknown_version = JoseOperationResponse {
        contract_version: EnumValue::from(99),
        response: Some(valid_verify_response()),
        __buffa_unknown_fields: Default::default(),
    };
    assert_backend_rejection(
        &encode_protobuf(&unknown_version),
        JoseOperationKind::JwsVerify,
    );

    let missing_response = canonical(None);
    assert_backend_rejection(
        &encode_protobuf(&missing_response),
        JoseOperationKind::JwsVerify,
    );

    let missing_outcome = canonical(Some(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: None,
        __buffa_unknown_fields: Default::default(),
    }))));
    assert_backend_rejection(
        &encode_protobuf(&missing_outcome),
        JoseOperationKind::JwsVerify,
    );

    let wrong_operation = canonical(Some(valid_verify_response()));
    assert_backend_rejection(
        &encode_protobuf(&wrong_operation),
        JoseOperationKind::JweDecrypt,
    );

    let wrong_branch = JoseError {
        error: Some(ErrorBranch::Provider(Box::new(JoseProviderError {
            reason: EnumValue::from(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let malformed_error = canonical(Some(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: Some(JwsVerifyOutcome::Error(Box::new(wrong_branch))),
        __buffa_unknown_fields: Default::default(),
    }))));
    assert_backend_rejection(
        &encode_protobuf(&malformed_error),
        JoseOperationKind::JwsVerify,
    );
}

#[test]
fn canonical_decoder_accepts_every_stable_error_branch_and_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    for reason in JoseErrorReason::values() {
        let value = reason.to_i32();
        let branch = if (100..=399).contains(&value) || (700..=703).contains(&value) {
            JoseWireErrorBranch::Primitive
        } else if (800..=802).contains(&value) {
            JoseWireErrorBranch::Provider
        } else if (900..=902).contains(&value) {
            JoseWireErrorBranch::Backend
        } else {
            continue;
        };
        let error = JoseWireError::try_new(branch, *reason)?;
        let response = canonical(Some(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
            outcome: Some(JwsVerifyOutcome::Error(Box::new(jose_error(error)))),
            __buffa_unknown_fields: Default::default(),
        }))));
        let encoded = encode_protobuf(&response);
        let decoded = decode_operation_response_v1(&encoded, JoseOperationKind::JwsVerify)?;
        assert_response_error(decoded, Some(JoseOperationKind::JwsVerify), branch, *reason);
    }
    Ok(())
}

#[test]
fn canonical_decoder_rejects_oversized_provider_output() -> Result<(), Box<dyn std::error::Error>> {
    let length = MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_add(33)
        .ok_or("test response length overflow")?;
    let oversized = vec![0u8; length];
    assert_backend_rejection(&oversized, JoseOperationKind::JwsVerify);
    Ok(())
}

#[test]
fn canonical_maximum_inner_result_fits_frozen_overhead() -> Result<(), Box<dyn std::error::Error>> {
    // A field-1 bytes value at this size uses one tag byte and a three-byte
    // protobuf length prefix, making the nested result exactly the semantic
    // protobuf-message limit.
    let plaintext_length = MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_sub(4)
        .ok_or("test plaintext length underflow")?;
    let result = JoseJwePlaintextResult {
        plaintext: vec![0u8; plaintext_length],
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(result.encode_to_vec().len(), MAX_JOSE_PROTO_MESSAGE_BYTES);
    let response = canonical(Some(Response::JweDecrypt(Box::new(
        JoseJweDecryptResponse {
            outcome: Some(JweDecryptOutcome::Result(Box::new(result))),
            __buffa_unknown_fields: Default::default(),
        },
    ))));
    let encoded = encode_protobuf(&response);
    let maximum_response_length = MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_add(MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES)
        .ok_or("test response length overflow")?;
    assert!(encoded.len() <= maximum_response_length);
    decode_operation_response_v1(&encoded, JoseOperationKind::JweDecrypt)?;
    Ok(())
}

fn assert_route_parity(
    request: &JoseOperationRequest,
    operation_kind: JoseOperationKind,
    rng_bytes: [u8; 12],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let protobuf = encode_protobuf(request);
    let json = encode_json(request)?;
    let binary_response = execute_operation_v1(&protobuf, &mut FixedRandom::new(rng_bytes));
    let json_response = execute_operation_json_v1(&json, &mut FixedRandom::new(rng_bytes));
    assert_eq!(binary_response.as_slice(), json_response.as_slice());

    let canonical = decode_operation_response_v1(&binary_response, operation_kind)?;
    Ok(normalize_response(canonical))
}

fn normalize_response(mut response: JoseOperationResponse) -> Vec<u8> {
    assert_eq!(
        response.contract_version,
        JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1
    );
    let Some(response) = response.response.take() else {
        panic!("canonical response omitted its response oneof");
    };
    match response {
        Response::BoundaryError(error) => normalized_error(&error),
        Response::JwsSign(mut response) => match response.outcome.take() {
            Some(JwsSignOutcome::Result(result)) => normalized_result(&*result),
            Some(JwsSignOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWS sign response omitted its outcome"),
        },
        Response::JwsVerify(mut response) => match response.outcome.take() {
            Some(JwsVerifyOutcome::Result(result)) => normalized_result(&*result),
            Some(JwsVerifyOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWS verify response omitted its outcome"),
        },
        Response::JwtEncodeUnsigned(mut response) => match response.outcome.take() {
            Some(JwtEncodeUnsignedOutcome::Result(result)) => normalized_result(&*result),
            Some(JwtEncodeUnsignedOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWT encode response omitted its outcome"),
        },
        Response::JwtDecodeUnsigned(mut response) => match response.outcome.take() {
            Some(JwtDecodeUnsignedOutcome::Result(result)) => normalized_result(&*result),
            Some(JwtDecodeUnsignedOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWT decode response omitted its outcome"),
        },
        Response::JwtSign(mut response) => match response.outcome.take() {
            Some(JwtSignOutcome::Result(result)) => normalized_result(&*result),
            Some(JwtSignOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWT sign response omitted its outcome"),
        },
        Response::JwtVerify(mut response) => match response.outcome.take() {
            Some(JwtVerifyOutcome::Result(result)) => normalized_result(&*result),
            Some(JwtVerifyOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWT verify response omitted its outcome"),
        },
        Response::JweEncrypt(mut response) => match response.outcome.take() {
            Some(JweEncryptOutcome::Result(result)) => normalized_result(&*result),
            Some(JweEncryptOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWE encrypt response omitted its outcome"),
        },
        Response::JweDecrypt(mut response) => match response.outcome.take() {
            Some(JweDecryptOutcome::Result(result)) => normalized_result(&*result),
            Some(JweDecryptOutcome::Error(error)) => normalized_error(&error),
            None => panic!("JWE decrypt response omitted its outcome"),
        },
    }
}

fn normalized_result<M: Message>(result: &M) -> Vec<u8> {
    result.encode_to_vec()
}

fn normalized_error(error: &JoseError) -> Vec<u8> {
    error.encode_to_vec()
}

fn assert_response_error(
    mut response: JoseOperationResponse,
    expected_operation: Option<JoseOperationKind>,
    branch: JoseWireErrorBranch,
    reason: JoseErrorReason,
) {
    let Some(response) = response.response.take() else {
        panic!("error response omitted its response oneof");
    };
    let error = match (expected_operation, response) {
        (None, Response::BoundaryError(error)) => error,
        (Some(JoseOperationKind::JwsSign), Response::JwsSign(mut response)) => {
            match response.outcome.take() {
                Some(JwsSignOutcome::Error(error)) => error,
                _ => panic!("JWS sign response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JwsVerify), Response::JwsVerify(mut response)) => {
            match response.outcome.take() {
                Some(JwsVerifyOutcome::Error(error)) => error,
                _ => panic!("JWS verify response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JwtVerify), Response::JwtVerify(mut response)) => {
            match response.outcome.take() {
                Some(JwtVerifyOutcome::Error(error)) => error,
                _ => panic!("JWT verify response did not contain an error"),
            }
        }
        _ => panic!("response error used the wrong operation variant"),
    };
    assert_generated_error(&error, branch, reason);
}

fn assert_generated_error(error: &JoseError, branch: JoseWireErrorBranch, reason: JoseErrorReason) {
    match (branch, &error.error) {
        (JoseWireErrorBranch::Primitive, Some(ErrorBranch::Primitive(error))) => {
            assert_eq!(error.reason, reason);
        }
        (JoseWireErrorBranch::Provider, Some(ErrorBranch::Provider(error))) => {
            assert_eq!(error.reason, reason);
        }
        (JoseWireErrorBranch::Backend, Some(ErrorBranch::Backend(error))) => {
            assert_eq!(error.reason, reason);
        }
        _ => panic!("generated error used the wrong branch"),
    }
}

fn assert_backend_rejection(bytes: &[u8], expected_operation: JoseOperationKind) {
    let error = match decode_operation_response_v1(bytes, expected_operation) {
        Ok(_) => panic!("malformed canonical response decoded successfully"),
        Err(error) => error,
    };
    assert_eq!(error.branch(), JoseWireErrorBranch::Backend);
    assert_eq!(
        error.reason(),
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL
    );
}

fn operation(operation: RequestOperation) -> JoseOperationRequest {
    JoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}

fn canonical(response: Option<Response>) -> JoseOperationResponse {
    JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1,
        ),
        response,
        __buffa_unknown_fields: Default::default(),
    }
}

fn valid_verify_response() -> Response {
    Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: Some(JwsVerifyOutcome::Result(Box::new(JoseVerifyResult {
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }))
}

fn decode_compact(bytes: &[u8]) -> Result<String, buffa::DecodeError> {
    let mut result = JoseCompactResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(&mut result.compact))
}

fn decode_claims(bytes: &[u8]) -> Result<Vec<u8>, buffa::DecodeError> {
    let mut result = JoseJwtClaimsResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(&mut result.claims_json))
}

fn decode_plaintext(bytes: &[u8]) -> Result<Vec<u8>, buffa::DecodeError> {
    let mut result = JoseJwePlaintextResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(&mut result.plaintext))
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
