// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;

use crate::api::contract::{JoseErrorReason, JoseOperationRequest};
use crate::wire::{JoseWireError, JoseWireResult, MAX_JOSE_PROTO_MESSAGE_BYTES};

pub(super) fn validate_request_limit(request: &JoseOperationRequest) -> JoseWireResult<()> {
    // Transport members have explicit caller-owned budgets. Signing,
    // verification and strict inspection retain their existing ceiling;
    // serialized wire entrypoints also keep their independent framing caps.
    if crate::jws::transport::execute::has_member_budgets(request) {
        return Ok(());
    }
    match request
        .try_encoded_len()
        .ok()
        .and_then(|length| usize::try_from(length).ok())
    {
        Some(length) if length <= MAX_JOSE_PROTO_MESSAGE_BYTES => Ok(()),
        _ => Err(JoseWireError::primitive_internal(
            JoseErrorReason::CommonResourceLimitExceeded,
        )),
    }
}
