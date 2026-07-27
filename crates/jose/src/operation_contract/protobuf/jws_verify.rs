// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf conversion for compact-JWS verification.

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseErrorReason, JoseJwsVerifyRequest, JoseSignatureAlgorithm, JoseVerifyResult,
};
use thiserror::Error;

use crate::operation_contract::jws::{
    verify_jws, JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
};
use crate::wire::{JoseWireError, JoseWireResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JwsVerifyRequestErrorReason {
    UnsupportedAlgorithm,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("JWS verification request selection failed")]
struct JwsVerifyRequestError {
    reason: JwsVerifyRequestErrorReason,
}

impl JwsVerifyRequestError {
    const fn unsupported_algorithm() -> Self {
        Self {
            reason: JwsVerifyRequestErrorReason::UnsupportedAlgorithm,
        }
    }

    const fn reason(self) -> JwsVerifyRequestErrorReason {
        self.reason
    }
}

/// Validates and executes a generated compact-JWS verification request.
pub(crate) fn verify_jws_request(
    request: &JoseJwsVerifyRequest,
) -> JoseWireResult<JoseVerifyResult> {
    let algorithm = request_algorithm(request.algorithm).map_err(map_request_error)?;
    let verified_payload = verify_jws(JwsVerifyInput::new(
        algorithm,
        &request.compact,
        &request.public_key,
    ))
    .map_err(map_verify_error)?;

    // The wire contract currently exposes only verification status. Dropping
    // this owner here zeroizes the authenticated payload instead of retaining
    // application data beyond the operation boundary.
    drop(verified_payload.into_bytes());
    Ok(JoseVerifyResult {
        __buffa_unknown_fields: Default::default(),
    })
}

fn request_algorithm(
    algorithm: buffa::EnumValue<JoseSignatureAlgorithm>,
) -> Result<JwsVerifyAlgorithm, JwsVerifyRequestError> {
    match algorithm.as_known() {
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256) => {
            Ok(JwsVerifyAlgorithm::Es256)
        }
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA) => {
            Ok(JwsVerifyAlgorithm::Eddsa)
        }
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED) | None => {
            Err(JwsVerifyRequestError::unsupported_algorithm())
        }
    }
}

const fn map_request_error(error: JwsVerifyRequestError) -> JoseWireError {
    match error.reason() {
        JwsVerifyRequestErrorReason::UnsupportedAlgorithm => JoseWireError::provider_internal(
            JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
        ),
    }
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
