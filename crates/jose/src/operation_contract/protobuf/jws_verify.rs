// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf conversion for compact-JWS verification.

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseJwsVerifyRequest, JoseVerifyResult,
};

use crate::operation_contract::jws::{verify_jws, JwsAlgorithm, JwsVerifyInput};
use crate::wire::JoseWireResult;

/// Validates and executes a generated compact-JWS verification request.
pub(crate) fn verify_jws_request(
    request: &JoseJwsVerifyRequest,
) -> JoseWireResult<JoseVerifyResult> {
    let algorithm = JwsAlgorithm::try_from(request.algorithm)?;
    let verified = verify_jws(JwsVerifyInput::new(
        algorithm,
        &request.compact,
        &request.public_key,
    ))
    .map_err(|error| crate::map_failure::jws_verify(&error))?;

    let (mut protected_header_json, mut payload) = verified.into_parts();
    Ok(JoseVerifyResult {
        // Transfer both allocations directly into the hardened generated
        // owner. Copying here would leave avoidable duplicate identity and
        // payload bytes in memory until the temporary owners were dropped.
        protected_header_json: core::mem::take(&mut *protected_header_json).into(),
        payload: core::mem::take(&mut *payload).into(),
    })
}
