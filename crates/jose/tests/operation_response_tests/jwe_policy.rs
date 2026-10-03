// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn direct_jwe_encrypt_request() -> JoseJweEncryptRequest {
    JoseJweEncryptRequest {
        key_management_algorithm: EnumValue::from(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        ),
        content_encryption_algorithm: EnumValue::from(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        ),
        key: vec![7_u8; 16],
        plaintext: b"wire policy plaintext".to_vec(),
        kid: "recipient".to_owned(),
        apu: Vec::new(),
        apv: Vec::new(),
        typ: "application/JWE".to_owned(),
        cty: "application/json".to_owned(),
        compression_algorithm: Default::default(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn expected_string(value: &str) -> JoseExpectedString {
    JoseExpectedString {
        value: value.to_owned(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn expected_bytes(value: &[u8]) -> JoseExpectedBytes {
    JoseExpectedBytes {
        value: value.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn decrypt_with_policy(
    compact: &str,
    policy: JoseJweHeaderValidationPolicy,
) -> Result<JoseOperationResponse, Box<dyn std::error::Error>> {
    let request = operation(RequestOperation::JweDecrypt(Box::new(
        JoseJweDecryptRequest {
            compact: compact.to_owned(),
            key_management_algorithm: EnumValue::from(
                JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            ),
            content_encryption_algorithm: EnumValue::from(
                JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
            ),
            key: vec![7_u8; 16],
            header_policy: policy.into(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let binary = execute_operation_v1(&encode_protobuf(&request), &mut FixedRandom::new([1; 12]));
    let json = execute_operation_json_v1(&encode_json(&request)?, &mut FixedRandom::new([1; 12]));
    assert_eq!(binary, json);
    Ok(decode_operation_response_v1(
        &binary,
        JoseOperationKind::JweDecrypt,
    )?)
}

#[test]
fn jwe_wire_header_policy_rejects_each_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let encrypt = operation(RequestOperation::JweEncrypt(Box::new(
        direct_jwe_encrypt_request(),
    )));
    let compact = decode_compact(&assert_route_parity(
        &encrypt,
        JoseOperationKind::JweEncrypt,
        [2; 12],
    )?)?;

    let valid = JoseJweHeaderValidationPolicy {
        require_kid: true,
        expected_kid: expected_string("recipient").into(),
        expected_typ: expected_string("JWE").into(),
        expected_cty: expected_string("application/json").into(),
        expected_apu: Default::default(),
        expected_apv: Default::default(),
        allowed_compression_algorithms: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    let accepted = decrypt_with_policy(&compact, valid.clone())?;
    assert!(matches!(
        accepted.response.as_ref(),
        Some(Response::JweDecrypt(response))
            if matches!(response.outcome.as_ref(), Some(JweDecryptOutcome::Result(_)))
    ));

    let mut mismatches = Vec::new();
    let mut kid = valid.clone();
    kid.expected_kid = expected_string("other").into();
    mismatches.push((
        kid,
        JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
    ));
    let mut typ = valid.clone();
    typ.expected_typ = expected_string("JWT").into();
    mismatches.push((
        typ,
        JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
    ));
    let mut cty = valid.clone();
    cty.expected_cty = expected_string("text/plain").into();
    mismatches.push((
        cty,
        JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
    ));
    let mut apu = valid.clone();
    apu.expected_apu = expected_bytes(b"wrong-party").into();
    mismatches.push((
        apu,
        JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH,
    ));
    let mut apv = valid;
    apv.expected_apv = expected_bytes(b"wrong-party").into();
    mismatches.push((
        apv,
        JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH,
    ));
    for (policy, reason) in mismatches {
        assert_response_error(
            decrypt_with_policy(&compact, policy)?,
            Some(JoseOperationKind::JweDecrypt),
            JoseWireErrorBranch::Primitive,
            reason,
        );
    }
    Ok(())
}

struct UnavailableRandom;

impl SecureRandom for UnavailableRandom {
    fn fill_secure(
        &mut self,
        _output: &mut [u8],
        output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output: output_kind,
            kind: RngFailureKind::EntropyUnavailable,
        })
    }
}

#[test]
fn jwe_randomness_failure_preserves_provider_branch() -> Result<(), Box<dyn std::error::Error>> {
    let request = operation(RequestOperation::JweEncrypt(Box::new(
        direct_jwe_encrypt_request(),
    )));
    let binary = execute_operation_v1(&encode_protobuf(&request), &mut UnavailableRandom);
    let json = execute_operation_json_v1(&encode_json(&request)?, &mut UnavailableRandom);
    assert_eq!(binary, json);
    let response = decode_operation_response_v1(&binary, JoseOperationKind::JweEncrypt)?;
    assert_response_error(
        response,
        Some(JoseOperationKind::JweEncrypt),
        JoseWireErrorBranch::Provider,
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
    );
    Ok(())
}
