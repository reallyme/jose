// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical versioned protobuf responses for executable JOSE operations.

use crate::operation_contract::protobuf::{capabilities, extended, jwk};
use crate::operation_contract::providers::{BuiltinProviders, OperationProviders};
use buffa::{EnumValue, Message};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_jwe_decrypt_response::Outcome as JweDecryptOutcome,
        jose_jwe_encrypt_response::Outcome as JweEncryptOutcome,
        jose_jws_sign_response::Outcome as JwsSignOutcome,
        jose_jws_verify_response::Outcome as JwsVerifyOutcome,
        jose_jwt_decode_unsigned_response::Outcome as JwtDecodeUnsignedOutcome,
        jose_jwt_encode_unsigned_response::Outcome as JwtEncodeUnsignedOutcome,
        jose_jwt_sign_response::Outcome as JwtSignOutcome,
        jose_jwt_verify_response::Outcome as JwtVerifyOutcome,
        jose_operation_request::Operation as RequestOperation, jose_operation_response::Response,
    },
    JoseErrorReason, JoseOperationContractVersion, JoseOperationRequest, JoseOperationResponse,
};
use zeroize::Zeroizing;

use super::{
    decode_json, decode_protobuf, decode_protobuf_with_limit, encode_protobuf, jose_error,
    JoseWireError, JoseWireResult, MAX_JOSE_PROTO_MESSAGE_BYTES,
    MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use crate::operation_contract::protobuf::{
    decode_unsigned_jwt_request, decrypt_jwe_request, encode_unsigned_jwt_request,
    encrypt_jwe_request, jws_provider, sign_jws_request, sign_jwt_request, verify_jws_request,
    verify_jwt_request,
};
use crate::SecureRandom;

pub use crate::generated_contract::JoseOperationKind;

/// Executes a trusted generated operation request into the canonical V2
/// generated response.
///
/// A missing operation becomes a top-level boundary error. Once an operation
/// is selected, both success and failure stay nested beneath that operation so
/// callers never infer the result type from opaque bytes.
#[must_use]
pub fn execute_operation_request<R: SecureRandom + ?Sized>(
    request: JoseOperationRequest,
    rng: &mut R,
) -> JoseOperationResponse {
    execute_operation_request_with_providers(request, rng, &mut BuiltinProviders)
}

/// Executes the generated contract using explicit caller-scoped capabilities.
#[must_use]
pub fn execute_operation_request_with_providers<R: SecureRandom + ?Sized>(
    mut request: JoseOperationRequest,
    rng: &mut R,
    providers: &mut dyn OperationProviders,
) -> JoseOperationResponse {
    match request
        .try_encoded_len()
        .ok()
        .and_then(|length| usize::try_from(length).ok())
    {
        Some(length) if length <= MAX_JOSE_PROTO_MESSAGE_BYTES => {}
        _ => {
            return boundary_response(JoseWireError::primitive_internal(
                JoseErrorReason::CommonResourceLimitExceeded,
            ))
        }
    }
    // Keep both dropping owners alive while extracting the selected child. The
    // native cleanup profile also wipes the oneof discriminator on return.
    let Some(mut operation) = request.operation.take() else {
        return boundary_response(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_MISSING_OPERATION,
        ));
    };

    match &mut operation {
        RequestOperation::JwkThumbprintSha256(request) => {
            jwk_thumbprint_sha256_response(jwk::thumbprint(request))
        }
        RequestOperation::JwsSign(request) => {
            jws_sign_response(sign_jws_request(core::mem::take(request.as_mut())))
        }
        RequestOperation::JwsVerify(request) => jws_verify_response(verify_jws_request(request)),
        RequestOperation::JwsSignWithProvider(request) => {
            jws_sign_with_provider_response(jws_provider::sign(request, providers))
        }
        RequestOperation::JwsVerifyWithProvider(request) => {
            jws_verify_with_provider_response(jws_provider::verify(request, providers))
        }
        RequestOperation::JwsInspect(request) => {
            jws_inspect_response(crate::jws::inspect_compact_jws(request))
        }
        RequestOperation::JwtEncodeUnsigned(request) => jwt_encode_unsigned_response(
            encode_unsigned_jwt_request(core::mem::take(request.as_mut())),
        ),
        RequestOperation::JwtDecodeUnsigned(request) => jwt_decode_unsigned_response(
            decode_unsigned_jwt_request(core::mem::take(request.as_mut())),
        ),
        RequestOperation::JwtSign(request) => {
            jwt_sign_response(sign_jwt_request(core::mem::take(request.as_mut())))
        }
        RequestOperation::JwtVerify(request) => {
            jwt_verify_response(verify_jwt_request(core::mem::take(request.as_mut())))
        }
        RequestOperation::JweEncrypt(request) => {
            jwe_encrypt_response(encrypt_jwe_request(core::mem::take(request.as_mut()), rng))
        }
        RequestOperation::JweDecrypt(request) => {
            jwe_decrypt_response(decrypt_jwe_request(core::mem::take(request.as_mut())))
        }
        RequestOperation::SignatureSign(request) => {
            signature_sign_response(extended::signature_sign(core::mem::take(request.as_mut())))
        }
        RequestOperation::SignatureVerify(request) => signature_verify_response(
            extended::signature_verify(core::mem::take(request.as_mut())),
        ),
        RequestOperation::SignatureSuiteInfo(request) => signature_suite_info_response(
            extended::signature_suite_info(core::mem::take(request.as_mut())),
        ),
        RequestOperation::JwtSignWithProvider(request) => jwt_sign_with_provider_response(
            capabilities::sign_jwt(core::mem::take(request.as_mut()), providers),
        ),
        RequestOperation::JweDeriveKey(request) => {
            jwe_derive_key_response(extended::derive_key(core::mem::take(request.as_mut())))
        }
        RequestOperation::JweEncryptWithProvider(request) => jwe_encrypt_with_provider_response(
            capabilities::encrypt_jwe(core::mem::take(request.as_mut()), providers, rng),
        ),
        RequestOperation::JweDecryptWithProvider(request) => jwe_decrypt_with_provider_response(
            capabilities::decrypt_with_provider(core::mem::take(request.as_mut()), providers),
        ),
        RequestOperation::ContractInfo(request) => {
            contract_info_response(extended::contract_info(core::mem::take(request.as_mut())))
        }
        RequestOperation::JwtClaimsParse(request) => {
            jwt_claims_parse_response(extended::parse_claims(core::mem::take(request.as_mut())))
        }
    }
}

/// Decodes and executes a binary protobuf request and returns an encoded
/// canonical V2 response.
#[must_use]
pub fn execute_operation_v1<R: SecureRandom + ?Sized>(
    request_bytes: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    let response = match decode_protobuf(request_bytes) {
        Ok(request) => execute_operation_request(request, rng),
        Err(error) => boundary_response(error),
    };
    encode_response_or_error(response)
}

/// Decodes and executes a generated ProtoJSON request and returns an encoded
/// canonical V2 binary protobuf response.
#[must_use]
pub fn execute_operation_json_v1<R: SecureRandom + ?Sized>(
    request_json: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    let response = match decode_json(request_json) {
        Ok(request) => execute_operation_request(request, rng),
        Err(error) => boundary_response(error),
    };
    encode_response_or_error(response)
}

/// Decodes and validates an untrusted canonical V2 response for the operation
/// submitted by the caller.
///
/// # Errors
///
/// Returns a typed backend/internal failure when provider output is oversized,
/// malformed, has an unsupported version, omits either oneof, carries an
/// invalid error branch/reason pair, or selects a different operation.
pub fn decode_operation_response_v1(
    bytes: &[u8],
    expected_operation: JoseOperationKind,
) -> JoseWireResult<JoseOperationResponse> {
    let maximum = max_response_bytes()?;
    if bytes.len() > maximum {
        return Err(backend_output_error());
    }
    let response = decode_protobuf_with_limit::<JoseOperationResponse>(bytes, maximum)
        .map_err(|_| backend_output_error())?;
    validate_response(&response, expected_operation)?;
    Ok(response)
}

fn validate_response(
    response: &JoseOperationResponse,
    expected_operation: JoseOperationKind,
) -> JoseWireResult<()> {
    validate_contract_version(response.contract_version)?;

    let Some(response) = &response.response else {
        return Err(backend_output_error());
    };
    match response {
        Response::JwkThumbprintSha256(response) => {
            require_operation(expected_operation, JoseOperationKind::JwkThumbprintSha256)?;
            match &response.outcome {
                Some(JwkThumbprintSha256Outcome::Result(result))
                    if result.digest.len() == crate::jwk::SHA256_DIGEST_BYTES =>
                {
                    Ok(())
                }
                Some(JwkThumbprintSha256Outcome::Error(error)) => validate_response_error(error),
                Some(JwkThumbprintSha256Outcome::Result(_)) | None => Err(backend_output_error()),
            }
        }
        Response::BoundaryError(error) => validate_response_error(error),
        Response::JwsSign(response) => {
            require_operation(expected_operation, JoseOperationKind::JwsSign)?;
            match &response.outcome {
                Some(JwsSignOutcome::Result(_)) => Ok(()),
                Some(JwsSignOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwsVerify(response) => {
            require_operation(expected_operation, JoseOperationKind::JwsVerify)?;
            match &response.outcome {
                Some(JwsVerifyOutcome::Result(_)) => Ok(()),
                Some(JwsVerifyOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwsSignWithProvider(response) => {
            require_operation(expected_operation, JoseOperationKind::JwsSignWithProvider)?;
            match response.outcome.as_ref() {
                Some(JwsSignOutcome::Result(_)) => Ok(()),
                Some(JwsSignOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwsVerifyWithProvider(response) => {
            require_operation(expected_operation, JoseOperationKind::JwsVerifyWithProvider)?;
            match response.outcome.as_ref() {
                Some(JwsVerifyOutcome::Result(_)) => Ok(()),
                Some(JwsVerifyOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwsInspect(response) => {
            require_operation(expected_operation, JoseOperationKind::JwsInspect)?;
            match response.outcome.as_ref() {
                Some(JwsInspectOutcome::Result(_)) => Ok(()),
                Some(JwsInspectOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwtEncodeUnsigned(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtEncodeUnsigned)?;
            match &response.outcome {
                Some(JwtEncodeUnsignedOutcome::Result(_)) => Ok(()),
                Some(JwtEncodeUnsignedOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwtDecodeUnsigned(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtDecodeUnsigned)?;
            match &response.outcome {
                Some(JwtDecodeUnsignedOutcome::Result(_)) => Ok(()),
                Some(JwtDecodeUnsignedOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwtSign(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtSign)?;
            match &response.outcome {
                Some(JwtSignOutcome::Result(_)) => Ok(()),
                Some(JwtSignOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwtVerify(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtVerify)?;
            match &response.outcome {
                Some(JwtVerifyOutcome::Result(_)) => Ok(()),
                Some(JwtVerifyOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JweEncrypt(response) => {
            require_operation(expected_operation, JoseOperationKind::JweEncrypt)?;
            match &response.outcome {
                Some(JweEncryptOutcome::Result(_)) => Ok(()),
                Some(JweEncryptOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JweDecrypt(response) => {
            require_operation(expected_operation, JoseOperationKind::JweDecrypt)?;
            match &response.outcome {
                Some(JweDecryptOutcome::Result(_)) => Ok(()),
                Some(JweDecryptOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::SignatureSign(response) => {
            require_operation(expected_operation, JoseOperationKind::SignatureSign)?;
            match &response.outcome {
                Some(SignatureSignOutcome::Result(_)) => Ok(()),
                Some(SignatureSignOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::SignatureVerify(response) => {
            require_operation(expected_operation, JoseOperationKind::SignatureVerify)?;
            match &response.outcome {
                Some(SignatureVerifyOutcome::Result(_)) => Ok(()),
                Some(SignatureVerifyOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::SignatureSuiteInfo(response) => {
            require_operation(expected_operation, JoseOperationKind::SignatureSuiteInfo)?;
            match &response.outcome {
                Some(SignatureSuiteInfoOutcome::Result(_)) => Ok(()),
                Some(SignatureSuiteInfoOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::JwtSignWithProvider(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtSignWithProvider)?;
            match &response.outcome {
                Some(JwtSignWithProviderOutcome::Result(_)) => Ok(()),
                Some(JwtSignWithProviderOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::JweDeriveKey(response) => {
            require_operation(expected_operation, JoseOperationKind::JweDeriveKey)?;
            match &response.outcome {
                Some(JweDeriveKeyOutcome::Result(_)) => Ok(()),
                Some(JweDeriveKeyOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::JweEncryptWithProvider(response) => {
            require_operation(
                expected_operation,
                JoseOperationKind::JweEncryptWithProvider,
            )?;
            match &response.outcome {
                Some(JweEncryptWithProviderOutcome::Result(_)) => Ok(()),
                Some(JweEncryptWithProviderOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::JweDecryptWithProvider(response) => {
            require_operation(
                expected_operation,
                JoseOperationKind::JweDecryptWithProvider,
            )?;
            match &response.outcome {
                Some(JweDecryptWithProviderOutcome::Result(_)) => Ok(()),
                Some(JweDecryptWithProviderOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }

        Response::ContractInfo(response) => {
            require_operation(expected_operation, JoseOperationKind::ContractInfo)?;
            match &response.outcome {
                Some(ContractInfoOutcome::Result(_)) => Ok(()),
                Some(ContractInfoOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
        Response::JwtClaimsParse(response) => {
            require_operation(expected_operation, JoseOperationKind::JwtClaimsParse)?;
            match &response.outcome {
                Some(JwtClaimsParseOutcome::Result(_)) => Ok(()),
                Some(JwtClaimsParseOutcome::Error(error)) => validate_response_error(error),
                None => Err(backend_output_error()),
            }
        }
    }
}

#[cfg(kani)]
#[path = "operation_response_proofs.rs"]
mod proofs;

fn max_response_bytes() -> JoseWireResult<usize> {
    MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_add(MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES)
        .ok_or_else(backend_output_error)
}

fn encode_response_or_error(response: JoseOperationResponse) -> Zeroizing<Vec<u8>> {
    let encoded = encode_protobuf(&response);
    match max_response_bytes() {
        Ok(maximum) if encoded.len() <= maximum => encoded,
        Ok(_) | Err(_) => {
            // Preserve a trusted operation identity even when its result could
            // not be represented within the transport cap.
            let fallback = operation_scoped_backend_error(response);
            encode_protobuf(&fallback)
        }
    }
}

fn operation_scoped_backend_error(mut response: JoseOperationResponse) -> JoseOperationResponse {
    let error = backend_output_error();
    match response.response.take() {
        Some(Response::JwkThumbprintSha256(_)) => jwk_thumbprint_sha256_response(Err(error)),
        Some(Response::JwsSign(_)) => jws_sign_response(Err(error)),
        Some(Response::JwsVerify(_)) => jws_verify_response(Err(error)),
        Some(Response::JwsSignWithProvider(_)) => jws_sign_with_provider_response(Err(error)),
        Some(Response::JwsVerifyWithProvider(_)) => jws_verify_with_provider_response(Err(error)),
        Some(Response::JwsInspect(_)) => jws_inspect_response(Err(error)),
        Some(Response::JwtEncodeUnsigned(_)) => jwt_encode_unsigned_response(Err(error)),
        Some(Response::JwtDecodeUnsigned(_)) => jwt_decode_unsigned_response(Err(error)),
        Some(Response::JwtSign(_)) => jwt_sign_response(Err(error)),
        Some(Response::JwtVerify(_)) => jwt_verify_response(Err(error)),
        Some(Response::JweEncrypt(_)) => jwe_encrypt_response(Err(error)),
        Some(Response::JweDecrypt(_)) => jwe_decrypt_response(Err(error)),
        Some(Response::BoundaryError(_)) | None => boundary_response(error),
        Some(Response::SignatureSign(_)) => signature_sign_response(Err(error)),
        Some(Response::SignatureVerify(_)) => signature_verify_response(Err(error)),
        Some(Response::SignatureSuiteInfo(_)) => signature_suite_info_response(Err(error)),
        Some(Response::JwtSignWithProvider(_)) => jwt_sign_with_provider_response(Err(error)),
        Some(Response::JweDeriveKey(_)) => jwe_derive_key_response(Err(error)),
        Some(Response::JweEncryptWithProvider(_)) => jwe_encrypt_with_provider_response(Err(error)),
        Some(Response::JweDecryptWithProvider(_)) => jwe_decrypt_with_provider_response(Err(error)),
        Some(Response::ContractInfo(_)) => contract_info_response(Err(error)),
        Some(Response::JwtClaimsParse(_)) => jwt_claims_parse_response(Err(error)),
    }
}

fn canonical_response(response: Response) -> JoseOperationResponse {
    JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2,
        ),
        response: Some(response),
    }
}

fn boundary_response(error: JoseWireError) -> JoseOperationResponse {
    canonical_response(Response::BoundaryError(Box::new(jose_error(error))))
}

const fn backend_output_error() -> JoseWireError {
    JoseWireError::backend_internal(JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL)
}

use crate::api::contract::__buffa::oneof::{
    jose_contract_info_response::Outcome as ContractInfoOutcome,
    jose_jwe_decrypt_with_provider_response::Outcome as JweDecryptWithProviderOutcome,
    jose_jwe_derive_key_response::Outcome as JweDeriveKeyOutcome,
    jose_jwe_encrypt_with_provider_response::Outcome as JweEncryptWithProviderOutcome,
    jose_jwk_thumbprint_sha256response::Outcome as JwkThumbprintSha256Outcome,
    jose_jws_inspect_response::Outcome as JwsInspectOutcome,
    jose_jwt_claims_parse_response::Outcome as JwtClaimsParseOutcome,
    jose_jwt_sign_with_provider_response::Outcome as JwtSignWithProviderOutcome,
    jose_signature_sign_response::Outcome as SignatureSignOutcome,
    jose_signature_suite_info_response::Outcome as SignatureSuiteInfoOutcome,
    jose_signature_verify_response::Outcome as SignatureVerifyOutcome,
};

mod build_response;
use build_response::{
    contract_info_response, jwe_decrypt_response, jwe_decrypt_with_provider_response,
    jwe_derive_key_response, jwe_encrypt_response, jwe_encrypt_with_provider_response,
    jwk_thumbprint_sha256_response, jws_inspect_response, jws_sign_response,
    jws_sign_with_provider_response, jws_verify_response, jws_verify_with_provider_response,
    jwt_claims_parse_response, jwt_decode_unsigned_response, jwt_encode_unsigned_response,
    jwt_sign_response, jwt_sign_with_provider_response, jwt_verify_response,
    signature_sign_response, signature_suite_info_response, signature_verify_response,
};

#[cfg(kani)]
#[path = "jwe_response_width_proofs.rs"]
mod jwe_response_width_proofs;

mod validate_response_policy;
use validate_response_policy::{
    require_operation, validate_contract_version, validate_response_error,
};
