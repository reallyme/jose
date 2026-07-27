// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical versioned protobuf responses for executable JOSE operations.

use buffa::EnumValue;
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
    JoseCompactResult, JoseError, JoseErrorReason, JoseJweDecryptResponse, JoseJweEncryptResponse,
    JoseJwePlaintextResult, JoseJwsSignResponse, JoseJwsVerifyResponse, JoseJwtClaimsResult,
    JoseJwtDecodeUnsignedResponse, JoseJwtEncodeUnsignedResponse, JoseJwtSignResponse,
    JoseJwtVerifyResponse, JoseOperationContractVersion, JoseOperationRequest,
    JoseOperationResponse, JoseVerifyResult,
};
use zeroize::Zeroizing;

use super::{
    decode_json, decode_protobuf, decode_protobuf_with_limit, encode_protobuf, jose_error,
    validate_jose_error, JoseWireError, JoseWireResult, MAX_JOSE_PROTO_MESSAGE_BYTES,
    MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use crate::operation_contract::protobuf::{
    decode_unsigned_jwt_request, decrypt_jwe_request, encode_unsigned_jwt_request,
    encrypt_jwe_request, sign_jws_request, sign_jwt_request, verify_jws_request,
    verify_jwt_request,
};
use crate::SecureRandom;

/// Operation identity expected by a canonical response consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseOperationKind {
    /// Compact-JWS signing.
    JwsSign,
    /// Compact-JWS verification.
    JwsVerify,
    /// Unsigned-JWT encoding.
    JwtEncodeUnsigned,
    /// Unsigned-JWT decoding.
    JwtDecodeUnsigned,
    /// Signed-JWT encoding.
    JwtSign,
    /// Signed-JWT verification.
    JwtVerify,
    /// Compact-JWE encryption.
    JweEncrypt,
    /// Compact-JWE decryption.
    JweDecrypt,
}

/// Executes a trusted generated operation request into the canonical V1
/// generated response.
///
/// A missing operation becomes a top-level boundary error. Once an operation
/// is selected, both success and failure stay nested beneath that operation so
/// callers never infer the result type from opaque bytes.
#[must_use]
pub fn execute_operation_request<R: SecureRandom + ?Sized>(
    mut request: JoseOperationRequest,
    rng: &mut R,
) -> JoseOperationResponse {
    // Preserve the generated owner until return so its Drop implementation
    // wipes retained unknown fields after the selected child is transferred.
    let Some(operation) = request.operation.take() else {
        return boundary_response(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_MISSING_OPERATION,
        ));
    };

    match operation {
        RequestOperation::JwsSign(request) => jws_sign_response(sign_jws_request(*request)),
        RequestOperation::JwsVerify(request) => jws_verify_response(verify_jws_request(&request)),
        RequestOperation::JwtEncodeUnsigned(request) => {
            jwt_encode_unsigned_response(encode_unsigned_jwt_request(*request))
        }
        RequestOperation::JwtDecodeUnsigned(request) => {
            jwt_decode_unsigned_response(decode_unsigned_jwt_request(*request))
        }
        RequestOperation::JwtSign(request) => jwt_sign_response(sign_jwt_request(*request)),
        RequestOperation::JwtVerify(request) => jwt_verify_response(verify_jwt_request(*request)),
        RequestOperation::JweEncrypt(request) => {
            jwe_encrypt_response(encrypt_jwe_request(*request, rng))
        }
        RequestOperation::JweDecrypt(request) => {
            jwe_decrypt_response(decrypt_jwe_request(*request))
        }
    }
}

/// Decodes and executes a binary protobuf request and returns an encoded
/// canonical V1 response.
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
/// canonical V1 binary protobuf response.
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

/// Decodes and validates an untrusted canonical V1 response for the operation
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
    if response.contract_version.as_known()
        != Some(JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1)
    {
        return Err(backend_output_error());
    }

    let Some(response) = &response.response else {
        return Err(backend_output_error());
    };
    match response {
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
    }
}

fn require_operation(actual: JoseOperationKind, expected: JoseOperationKind) -> JoseWireResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

fn validate_response_error(error: &JoseError) -> JoseWireResult<()> {
    validate_jose_error(error).map_err(|_| backend_output_error())
}

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
        Some(Response::JwsSign(_)) => jws_sign_response(Err(error)),
        Some(Response::JwsVerify(_)) => jws_verify_response(Err(error)),
        Some(Response::JwtEncodeUnsigned(_)) => jwt_encode_unsigned_response(Err(error)),
        Some(Response::JwtDecodeUnsigned(_)) => jwt_decode_unsigned_response(Err(error)),
        Some(Response::JwtSign(_)) => jwt_sign_response(Err(error)),
        Some(Response::JwtVerify(_)) => jwt_verify_response(Err(error)),
        Some(Response::JweEncrypt(_)) => jwe_encrypt_response(Err(error)),
        Some(Response::JweDecrypt(_)) => jwe_decrypt_response(Err(error)),
        Some(Response::BoundaryError(_)) | None => boundary_response(error),
    }
}

fn canonical_response(response: Response) -> JoseOperationResponse {
    JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1,
        ),
        response: Some(response),
        __buffa_unknown_fields: Default::default(),
    }
}

fn boundary_response(error: JoseWireError) -> JoseOperationResponse {
    canonical_response(Response::BoundaryError(Box::new(jose_error(error))))
}

fn jws_sign_response(result: JoseWireResult<JoseCompactResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwsSignOutcome::Result(Box::new(result)),
        Err(error) => JwsSignOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwsSign(Box::new(JoseJwsSignResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

fn jws_verify_response(result: JoseWireResult<JoseVerifyResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwsVerifyOutcome::Result(Box::new(result)),
        Err(error) => JwsVerifyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

fn jwt_encode_unsigned_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtEncodeUnsignedOutcome::Result(Box::new(result)),
        Err(error) => JwtEncodeUnsignedOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtEncodeUnsigned(Box::new(
        JoseJwtEncodeUnsignedResponse {
            outcome: Some(outcome),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

fn jwt_decode_unsigned_response(
    result: JoseWireResult<JoseJwtClaimsResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtDecodeUnsignedOutcome::Result(Box::new(result)),
        Err(error) => JwtDecodeUnsignedOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtDecodeUnsigned(Box::new(
        JoseJwtDecodeUnsignedResponse {
            outcome: Some(outcome),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

fn jwt_sign_response(result: JoseWireResult<JoseCompactResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtSignOutcome::Result(Box::new(result)),
        Err(error) => JwtSignOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtSign(Box::new(JoseJwtSignResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

fn jwt_verify_response(result: JoseWireResult<JoseJwtClaimsResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtVerifyOutcome::Result(Box::new(result)),
        Err(error) => JwtVerifyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtVerify(Box::new(JoseJwtVerifyResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

fn jwe_encrypt_response(result: JoseWireResult<JoseCompactResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweEncryptOutcome::Result(Box::new(result)),
        Err(error) => JweEncryptOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweEncrypt(Box::new(JoseJweEncryptResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

fn jwe_decrypt_response(result: JoseWireResult<JoseJwePlaintextResult>) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweDecryptOutcome::Result(Box::new(result)),
        Err(error) => JweDecryptOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweDecrypt(Box::new(JoseJweDecryptResponse {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    })))
}

const fn backend_output_error() -> JoseWireError {
    JoseWireError::backend_internal(JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL)
}
