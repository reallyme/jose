// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    compose_compact_jws_unauthenticated, frame_compact_jws_unauthenticated,
    ComposeCompactJwsRequest, FrameCompactJwsRequest, JwsTransportErrorReason as Error,
};

pub(crate) const fn has_member_budgets(
    request: &crate::api::contract::JoseOperationRequest,
) -> bool {
    use crate::api::contract::__buffa::oneof::jose_operation_request::Operation;
    matches!(
        request.operation.as_ref(),
        Some(Operation::JwsFrameUnauthenticated(_) | Operation::JwsComposeUnauthenticated(_))
    )
}
use crate::api::contract::{
    JoseJwsTransportCompactResult, JoseJwsTransportComposeRequest, JoseJwsTransportFrameRequest,
    JoseJwsTransportFrameResult,
};

pub(crate) fn frame(
    request: &JoseJwsTransportFrameRequest,
) -> Result<JoseJwsTransportFrameResult, Error> {
    let view = frame_compact_jws_unauthenticated(&FrameCompactJwsRequest {
        compact: request.compact.as_str(),
        policy: request.policy.as_option().ok_or(Error::MissingPolicy)?,
        budgets: request.budgets.as_option().ok_or(Error::MissingBudget)?,
    })?;
    let protected_header_end =
        u64::try_from(view.protected_header().len()).map_err(|_| Error::LengthOverflow)?;
    let payload_end =
        u64::try_from(view.signing_input().len()).map_err(|_| Error::LengthOverflow)?;
    let signature_start = payload_end.checked_add(1).ok_or(Error::LengthOverflow)?;
    Ok(JoseJwsTransportFrameResult::default()
        .with_protected_header_end(protected_header_end)
        .with_payload_end(payload_end)
        .with_signature_start(signature_start))
}

pub(crate) fn compose(
    request: &JoseJwsTransportComposeRequest,
) -> Result<JoseJwsTransportCompactResult, Error> {
    let result = compose_compact_jws_unauthenticated(&ComposeCompactJwsRequest {
        protected_header: request
            .protected_header
            .as_deref()
            .ok_or(Error::MissingMember)?,
        payload: request.payload.as_deref().ok_or(Error::MissingMember)?,
        signature: request.signature.as_deref().ok_or(Error::MissingMember)?,
        policy: request.policy.as_option().ok_or(Error::MissingPolicy)?,
        budgets: request.budgets.as_option().ok_or(Error::MissingBudget)?,
    })?;
    let mut compact = result.into_zeroizing();
    Ok(JoseJwsTransportCompactResult::default().with_compact(core::mem::take(&mut *compact)))
}
