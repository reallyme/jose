// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf conversion for compact-JWS verification.

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseErrorReason, JoseJwsVerifyRequest, JoseVerifyResult,
};

use crate::jws::parse_header::JwsAlgorithm;
use crate::operation_contract::jws::{
    verify_jws, JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
};
use crate::wire::{JoseWireError, JoseWireResult};

use super::signature_selector::select_signature_algorithm;

/// Validates and executes a generated compact-JWS verification request.
pub(crate) fn verify_jws_request(
    request: &JoseJwsVerifyRequest,
) -> JoseWireResult<JoseVerifyResult> {
    let algorithm = match select_signature_algorithm(request.algorithm)? {
        JwsAlgorithm::Es256 => JwsVerifyAlgorithm::Es256,
        JwsAlgorithm::Eddsa => JwsVerifyAlgorithm::Eddsa,
    };
    let verified = verify_jws(JwsVerifyInput::new(
        algorithm,
        &request.compact,
        &request.public_key,
    ))
    .map_err(map_verify_error)?;

    let (mut protected_header_json, mut payload) = verified.into_parts();
    Ok(JoseVerifyResult {
        // Transfer both allocations directly into the hardened generated
        // owner. Copying here would leave avoidable duplicate identity and
        // payload bytes in memory until the temporary owners were dropped.
        protected_header_json: core::mem::take(&mut *protected_header_json),
        payload: core::mem::take(&mut *payload),
        __buffa_unknown_fields: Default::default(),
    })
}

const fn map_verify_error(error: JwsVerifyError) -> JoseWireError {
    let reason = match error.reason() {
        JwsVerifyErrorReason::InvalidCompact => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_COMPACT
        }
        JwsVerifyErrorReason::LengthOverflow => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_LENGTH_OVERFLOW
        }
        JwsVerifyErrorReason::BadHeaderBase64 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64
        }
        JwsVerifyErrorReason::BadHeaderUtf8 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8
        }
        JwsVerifyErrorReason::HeaderMismatch => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH
        }
        JwsVerifyErrorReason::BadPayloadBase64 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64
        }
        JwsVerifyErrorReason::BadSignatureBase64 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64
        }
        JwsVerifyErrorReason::BadRawSignature => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE
        }
        JwsVerifyErrorReason::InvalidSignature => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE
        }
    };
    JoseWireError::primitive_internal(reason)
}
