// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf conversion for compact-JWS signing.

use core::str;

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseErrorReason, JoseJwsSignRequest, JoseSignatureAlgorithm,
};
use zeroize::Zeroizing;

use crate::operation_contract::jws::{
    sign_jws, JwsSignAlgorithm, JwsSignError, JwsSignErrorReason, JwsSignInput,
};
use crate::wire::{JoseWireError, JoseWireResult};

/// Validates and executes a generated compact-JWS signing request.
pub(crate) fn sign_jws_request(
    mut request: JoseJwsSignRequest,
) -> JoseWireResult<JoseCompactResult> {
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let payload_bytes = Zeroizing::new(core::mem::take(&mut request.payload));
    let payload = str::from_utf8(&payload_bytes).map_err(|_| {
        JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8,
        )
    })?;
    let algorithm = match request.algorithm.as_known() {
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256) => JwsSignAlgorithm::Es256,
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA) => JwsSignAlgorithm::Eddsa,
        Some(JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED) | None => {
            return Err(JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            ));
        }
    };
    let compact = sign_jws(JwsSignInput::new(algorithm, &private_key, payload))
        .map_err(map_sign_error)?
        .into_string();

    Ok(JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })
}

const fn map_sign_error(error: JwsSignError) -> JoseWireError {
    let reason = match error.reason() {
        JwsSignErrorReason::LengthOverflow => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_LENGTH_OVERFLOW
        }
        JwsSignErrorReason::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWS_INPUT_TOO_LARGE,
        JwsSignErrorReason::SignFailed => JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED,
        JwsSignErrorReason::BadDerSignature => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_DER_SIGNATURE
        }
    };
    JoseWireError::primitive_internal(reason)
}
