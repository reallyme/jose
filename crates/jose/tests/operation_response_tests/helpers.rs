// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_jose::api::contract::__buffa::oneof::{
    jose_contract_info_response::Outcome as ContractInfoOutcome,
    jose_jwe_decrypt_with_provider_response::Outcome as JweDecryptWithProviderOutcome,
    jose_jwe_derive_key_response::Outcome as JweDeriveKeyOutcome,
    jose_jwe_encrypt_with_provider_response::Outcome as JweEncryptWithProviderOutcome,
    jose_jws_inspect_response::Outcome as JwsInspectOutcome,
    jose_jwt_claims_parse_response::Outcome as JwtClaimsParseOutcome,
    jose_jwt_sign_with_provider_response::Outcome as JwtSignWithProviderOutcome,
    jose_signature_sign_response::Outcome as SignatureSignOutcome,
    jose_signature_suite_info_response::Outcome as SignatureSuiteInfoOutcome,
    jose_signature_verify_response::Outcome as SignatureVerifyOutcome,
};

fn assert_route_parity(
    request: &JoseOperationRequest,
    operation_kind: JoseOperationKind,
    rng_bytes: [u8; 12],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(normalize_response(assert_canonical_route_parity(
        request,
        operation_kind,
        rng_bytes,
    )?))
}

fn assert_canonical_route_parity(
    request: &JoseOperationRequest,
    operation_kind: JoseOperationKind,
    rng_bytes: [u8; 12],
) -> Result<JoseOperationResponse, Box<dyn std::error::Error>> {
    let protobuf = encode_protobuf(request);
    let json = encode_json(request)?;
    let binary_response = execute_operation_v1(&protobuf, &mut FixedRandom::new(rng_bytes));
    let json_response = execute_operation_json_v1(&json, &mut FixedRandom::new(rng_bytes));
    assert_eq!(binary_response.as_slice(), json_response.as_slice());

    let typed = reallyme_jose::wire::execute_operation_request(
        request.clone(),
        &mut FixedRandom::new(rng_bytes),
    );
    assert_eq!(binary_response.as_slice(), typed.encode_to_vec().as_slice());
    Ok(decode_operation_response_v1(
        &binary_response,
        operation_kind,
    )?)
}

fn normalize_response(response: JoseOperationResponse) -> Vec<u8> {
    assert_eq!(
        response.contract_version,
        JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2
    );
    let Some(response) = response.response.as_ref() else {
        panic!("canonical response omitted its response oneof");
    };
    match response {
        Response::JwsFrameUnauthenticated(response) => {
            use reallyme_jose::api::contract::__buffa::oneof::jose_jws_transport_frame_response::Outcome;
            match response.outcome.as_ref() {
                Some(Outcome::Result(result)) => normalized_result(result.as_ref()),
                Some(Outcome::Error(error)) => normalized_error(error),
                None => panic!("transport framing omitted its outcome"),
            }
        }
        Response::JwsComposeUnauthenticated(response) => {
            use reallyme_jose::api::contract::__buffa::oneof::jose_jws_transport_compose_response::Outcome;
            match response.outcome.as_ref() {
                Some(Outcome::Result(result)) => normalized_result(result.as_ref()),
                Some(Outcome::Error(error)) => normalized_error(error),
                None => panic!("transport composition omitted its outcome"),
            }
        }
        Response::JwkThumbprintSha256(response) => {
            use reallyme_jose::api::contract::__buffa::oneof::jose_jwk_thumbprint_sha256response::Outcome;
            match response.outcome.as_ref() {
                Some(Outcome::Result(result)) => normalized_result(result.as_ref()),
                Some(Outcome::Error(error)) => normalized_error(error),
                None => panic!("JWK thumbprint response omitted its outcome"),
            }
        }
        Response::BoundaryError(error) => normalized_error(error),
        Response::JwsSign(response) | Response::JwsSignWithProvider(response) => match response.outcome.as_ref() {
            Some(JwsSignOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwsSignOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWS sign response omitted its outcome"),
        },
        Response::JwsVerify(response) | Response::JwsVerifyWithProvider(response) => match response.outcome.as_ref() {
            Some(JwsVerifyOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwsVerifyOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWS verify response omitted its outcome"),
        },
        Response::JwsInspect(response) => match response.outcome.as_ref() {
            Some(JwsInspectOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwsInspectOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWS inspect response omitted its outcome"),
        },
        Response::JwtEncodeUnsigned(response) => match response.outcome.as_ref() {
            Some(JwtEncodeUnsignedOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwtEncodeUnsignedOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWT encode response omitted its outcome"),
        },
        Response::JwtDecodeUnsigned(response) => match response.outcome.as_ref() {
            Some(JwtDecodeUnsignedOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwtDecodeUnsignedOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWT decode response omitted its outcome"),
        },
        Response::JwtSign(response) => match response.outcome.as_ref() {
            Some(JwtSignOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwtSignOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWT sign response omitted its outcome"),
        },
        Response::JwtVerify(response) => match response.outcome.as_ref() {
            Some(JwtVerifyOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwtVerifyOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWT verify response omitted its outcome"),
        },
        Response::JweEncrypt(response) => match response.outcome.as_ref() {
            Some(JweEncryptOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JweEncryptOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWE encrypt response omitted its outcome"),
        },
        Response::JweDecrypt(response) => match response.outcome.as_ref() {
            Some(JweDecryptOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JweDecryptOutcome::Error(error)) => normalized_error(error),
            None => panic!("JWE decrypt response omitted its outcome"),
        },
        Response::SignatureSign(value) => match value.outcome.as_ref() {
            Some(SignatureSignOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(SignatureSignOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::SignatureVerify(value) => match value.outcome.as_ref() {
            Some(SignatureVerifyOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(SignatureVerifyOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::SignatureSuiteInfo(value) => match value.outcome.as_ref() {
            Some(SignatureSuiteInfoOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(SignatureSuiteInfoOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::JwtSignWithProvider(value) => match value.outcome.as_ref() {
            Some(JwtSignWithProviderOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JwtSignWithProviderOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::JweDeriveKey(value) => match value.outcome.as_ref() {
            Some(JweDeriveKeyOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(JweDeriveKeyOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::JweEncryptWithProvider(value) => match value.outcome.as_ref() {
            Some(JweEncryptWithProviderOutcome::Result(result)) => {
                normalized_result(result.as_ref())
            }
            Some(JweEncryptWithProviderOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::JweDecryptWithProvider(value) => match value.outcome.as_ref() {
            Some(JweDecryptWithProviderOutcome::Result(result)) => {
                normalized_result(result.as_ref())
            }
            Some(JweDecryptWithProviderOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::ContractInfo(value) => match value.outcome.as_ref() {
            Some(ContractInfoOutcome::Result(result)) => normalized_result(result.as_ref()),
            Some(ContractInfoOutcome::Error(error)) => normalized_error(error),
            None => panic!("response omitted outcome"),
        },

        Response::JwtClaimsParse(value) => match value.outcome.as_ref() {
            Some(JwtClaimsParseOutcome::Result(value)) => normalized_result(value.as_ref()),
            Some(JwtClaimsParseOutcome::Error(error)) => normalized_error(error),
            None => panic!("missing claims parse outcome"),
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
    response: JoseOperationResponse,
    expected_operation: Option<JoseOperationKind>,
    branch: JoseWireErrorBranch,
    reason: JoseErrorReason,
) {
    let Some(response) = response.response.as_ref() else {
        panic!("error response omitted its response oneof");
    };
    let error = match (expected_operation, response) {
        (None, Response::BoundaryError(error)) => error,
        (Some(JoseOperationKind::JwsSign), Response::JwsSign(response)) => {
            match response.outcome.as_ref() {
                Some(JwsSignOutcome::Error(error)) => error,
                _ => panic!("JWS sign response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JwsVerify), Response::JwsVerify(response)) => {
            match response.outcome.as_ref() {
                Some(JwsVerifyOutcome::Error(error)) => error,
                _ => panic!("JWS verify response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JwtVerify), Response::JwtVerify(response)) => {
            match response.outcome.as_ref() {
                Some(JwtVerifyOutcome::Error(error)) => error,
                _ => panic!("JWT verify response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JweEncrypt), Response::JweEncrypt(response)) => {
            match response.outcome.as_ref() {
                Some(JweEncryptOutcome::Error(error)) => error,
                _ => panic!("JWE encrypt response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JweDecrypt), Response::JweDecrypt(response)) => {
            match response.outcome.as_ref() {
                Some(JweDecryptOutcome::Error(error)) => error,
                _ => panic!("JWE decrypt response did not contain an error"),
            }
        }
        (Some(JoseOperationKind::JwtSign), Response::JwtSign(response)) => match response.outcome.as_ref() {
            Some(reallyme_jose_proto::generated::proto::reallyme::jose::v1::__buffa::oneof::jose_jwt_sign_response::Outcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::SignatureSign), Response::SignatureSign(response)) => match response.outcome.as_ref() {
            Some(SignatureSignOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::SignatureVerify), Response::SignatureVerify(response)) => match response.outcome.as_ref() {
            Some(SignatureVerifyOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::SignatureSuiteInfo), Response::SignatureSuiteInfo(response)) => match response.outcome.as_ref() {
            Some(SignatureSuiteInfoOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::JwtSignWithProvider), Response::JwtSignWithProvider(response)) => match response.outcome.as_ref() {
            Some(JwtSignWithProviderOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::JweDeriveKey), Response::JweDeriveKey(response)) => match response.outcome.as_ref() {
            Some(JweDeriveKeyOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::JweEncryptWithProvider), Response::JweEncryptWithProvider(response)) => match response.outcome.as_ref() {
            Some(JweEncryptWithProviderOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::JweDecryptWithProvider), Response::JweDecryptWithProvider(response)) => match response.outcome.as_ref() {
            Some(JweDecryptWithProviderOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::ContractInfo), Response::ContractInfo(response)) => match response.outcome.as_ref() {
            Some(ContractInfoOutcome::Error(error)) => error,
            _ => panic!("response did not contain an error"),
        },
        (Some(JoseOperationKind::JwtClaimsParse), Response::JwtClaimsParse(response)) => match response.outcome.as_ref() {
            Some(JwtClaimsParseOutcome::Error(error)) => error,
            _ => panic!("claims response did not contain an error"),
        },
        _ => panic!("response error used the wrong operation variant"),
    };
    assert_generated_error(error, branch, reason);
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

const fn operation(operation: RequestOperation) -> JoseOperationRequest {
    JoseOperationRequest {
        operation: Some(operation),
    }
}

fn canonical(response: Option<Response>) -> JoseOperationResponse {
    JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2,
        ),
        response,
    }
}

fn valid_verify_response() -> Response {
    Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: Some(JwsVerifyOutcome::Result(Box::new(JoseVerifyResult {
            protected_header_json: Vec::new().into(),
            payload: Vec::new().into(),
        }))),
    }))
}

fn decode_compact(bytes: &[u8]) -> Result<String, buffa::DecodeError> {
    let mut result = JoseCompactResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(
        &mut *core::mem::take(&mut result.compact).into_zeroizing(),
    ))
}

fn decode_claims(bytes: &[u8]) -> Result<Vec<u8>, buffa::DecodeError> {
    let mut result = JoseJwtClaimsResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(
        &mut *core::mem::take(&mut result.claims_json).into_zeroizing(),
    ))
}

fn decode_verify_result(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), buffa::DecodeError> {
    let mut result = JoseVerifyResult::decode_from_slice(bytes)?;
    Ok((
        core::mem::take(&mut *core::mem::take(&mut result.protected_header_json).into_zeroizing()),
        core::mem::take(&mut *core::mem::take(&mut result.payload).into_zeroizing()),
    ))
}

fn decode_plaintext(bytes: &[u8]) -> Result<Vec<u8>, buffa::DecodeError> {
    let mut result = JoseJwePlaintextResult::decode_from_slice(bytes)?;
    Ok(core::mem::take(
        &mut *core::mem::take(&mut result.plaintext).into_zeroizing(),
    ))
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
        _output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        if output.len() != self.bytes.len() {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        output.copy_from_slice(&self.bytes);
        Ok(())
    }
}
