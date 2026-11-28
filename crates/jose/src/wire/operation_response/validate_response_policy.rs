// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;

use crate::api::contract::{JoseError, JoseOperationContractVersion};
use crate::wire::{validate_jose_error, JoseWireResult};

use super::{backend_output_error, JoseOperationKind};

pub(super) fn max_response_bytes() -> JoseWireResult<usize> {
    crate::wire::MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_add(crate::wire::MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES)
        .ok_or_else(backend_output_error)
}

pub(super) fn validate_contract_version(
    version: EnumValue<JoseOperationContractVersion>,
) -> JoseWireResult<()> {
    if version.as_known() == Some(JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2)
    {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

pub(super) fn require_operation(
    actual: JoseOperationKind,
    expected: JoseOperationKind,
) -> JoseWireResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

pub(super) fn validate_response_error(error: &JoseError) -> JoseWireResult<()> {
    validate_jose_error(error).map_err(|_| backend_output_error())
}

fn validate_transport_reason(
    reason: EnumValue<crate::api::contract::JoseJwsTransportErrorReason>,
    error: Option<&JoseError>,
) -> JoseWireResult<()> {
    use crate::api::contract::__buffa::oneof::jose_error::Error;
    let known = reason.as_known().ok_or_else(backend_output_error)?;
    let expected = crate::jws::transport::map_reason::stack_reason(known);
    let Some(error) = error else {
        return if expected.is_none() {
            Ok(())
        } else {
            Err(backend_output_error())
        };
    };
    validate_response_error(error)?;
    let actual = match error.error.as_ref() {
        Some(Error::Primitive(value)) => value.reason.as_known(),
        Some(Error::Provider(value)) => value.reason.as_known(),
        Some(Error::Backend(value)) => value.reason.as_known(),
        None => None,
    };
    // An operation-scoped outer serialization failure has no member-admission
    // reason. Every transport admission failure must match its stack mapping.
    if expected == actual
        || expected.is_none()
            && actual == Some(crate::api::contract::JoseErrorReason::BackendInternal)
    {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

pub(super) fn validate_frame_transport_response(
    response: &crate::api::contract::JoseJwsTransportFrameResponse,
    expected: JoseOperationKind,
) -> JoseWireResult<()> {
    use crate::api::contract::__buffa::oneof::jose_jws_transport_frame_response::Outcome;
    require_operation(expected, JoseOperationKind::JwsFrameUnauthenticated)?;
    match &response.outcome {
        Some(Outcome::Result(result))
            if result.protected_header_end < result.payload_end
                && result.payload_end.checked_add(1) == Some(result.signature_start) =>
        {
            validate_transport_reason(response.transport_reason, None)
        }
        Some(Outcome::Error(error)) => {
            validate_transport_reason(response.transport_reason, Some(error))
        }
        _ => Err(backend_output_error()),
    }
}

pub(super) fn validate_compose_transport_response(
    response: &crate::api::contract::JoseJwsTransportComposeResponse,
    expected: JoseOperationKind,
) -> JoseWireResult<()> {
    use crate::api::contract::__buffa::oneof::jose_jws_transport_compose_response::Outcome;
    require_operation(expected, JoseOperationKind::JwsComposeUnauthenticated)?;
    match &response.outcome {
        // Applying compact framing here would reject deliberately opaque dots.
        Some(Outcome::Result(_)) => validate_transport_reason(response.transport_reason, None),
        Some(Outcome::Error(error)) => {
            validate_transport_reason(response.transport_reason, Some(error))
        }
        None => Err(backend_output_error()),
    }
}
