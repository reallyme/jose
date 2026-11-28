// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::JwsTransportErrorReason;
use crate::api::contract::JoseJwsTransportErrorReason;

pub(super) const fn reason(error: &JwsTransportErrorReason) -> JoseJwsTransportErrorReason {
    match error {
        JwsTransportErrorReason::MissingPolicy => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_POLICY
        }
        JwsTransportErrorReason::InvalidCharacterPolicy => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_CHARACTER_POLICY
        }
        JwsTransportErrorReason::MissingBudget => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_BUDGET
        }
        JwsTransportErrorReason::MissingMember => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_MEMBER
        }
        JwsTransportErrorReason::InputTooLarge => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INPUT_TOO_LARGE
        }
        JwsTransportErrorReason::OutputTooLarge => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_OUTPUT_TOO_LARGE
        }
        JwsTransportErrorReason::InvalidFraming => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_FRAMING
        }
        JwsTransportErrorReason::EmptyMember => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_EMPTY_MEMBER
        }
        JwsTransportErrorReason::InvalidCharacters => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_CHARACTERS
        }
        JwsTransportErrorReason::LengthOverflow => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_LENGTH_OVERFLOW
        }
        JwsTransportErrorReason::Allocation => {
            JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_ALLOCATION
        }
    }
}

pub(crate) const fn stack_reason(
    reason: JoseJwsTransportErrorReason,
) -> Option<crate::api::contract::JoseErrorReason> {
    match reason {
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_POLICY => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_POLICY),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_CHARACTER_POLICY => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_CHARACTER_POLICY),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_BUDGET => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_BUDGET),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_MISSING_MEMBER => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_MEMBER),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INPUT_TOO_LARGE => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INPUT_TOO_LARGE),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_OUTPUT_TOO_LARGE => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_OUTPUT_TOO_LARGE),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_FRAMING => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_FRAMING),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_EMPTY_MEMBER => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_EMPTY_MEMBER),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_INVALID_CHARACTERS => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_CHARACTERS),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_LENGTH_OVERFLOW => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_LENGTH_OVERFLOW),
        JoseJwsTransportErrorReason::JOSE_JWS_TRANSPORT_ERROR_REASON_ALLOCATION => Some(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWS_TRANSPORT_ALLOCATION),
        JoseJwsTransportErrorReason::Unspecified => None,
    }
}
