// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf conversion for compact-JWS signing.

use core::str;

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseErrorReason, JoseJwsSignRequest,
};
use zeroize::Zeroizing;

use crate::operation_contract::jws::{sign_jws, JwsAlgorithm, JwsSignInput};
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
    let algorithm = JwsAlgorithm::try_from(request.algorithm)?;
    let compact = sign_jws(JwsSignInput::new(algorithm, &private_key, payload))
        .map_err(|error| crate::map_failure::jws_sign(&error))?
        .into_string();

    Ok(JoseCompactResult {
        compact: compact.into(),
    })
}
