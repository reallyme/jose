// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Fixed, non-identifying failures of unauthenticated transport operations.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwsTransportErrorReason {
    /// A member's admission policy was not supplied.
    #[error("missing JWS transport policy")]
    MissingPolicy,
    /// A character selector is unknown or unspecified.
    #[error("invalid JWS transport character policy")]
    InvalidCharacterPolicy,
    /// A required caller budget was not supplied.
    #[error("missing JWS transport budget")]
    MissingBudget,
    /// A supplied-members operation omitted a member.
    #[error("missing JWS transport member")]
    MissingMember,
    /// The caller's input byte budget was exceeded.
    #[error("JWS transport input budget exceeded")]
    InputTooLarge,
    /// The caller's output byte budget was exceeded.
    #[error("JWS transport output budget exceeded")]
    OutputTooLarge,
    /// Framing requires exactly two separators.
    #[error("invalid JWS transport framing")]
    InvalidFraming,
    /// A member was empty under a policy that forbids it.
    #[error("empty JWS transport member")]
    EmptyMember,
    /// A member violated its selected character policy.
    #[error("invalid JWS transport member characters")]
    InvalidCharacters,
    /// A byte length, offset or platform conversion overflowed.
    #[error("JWS transport length overflow")]
    LengthOverflow,
    /// The output allocation could not be reserved.
    #[error("JWS transport allocation failed")]
    Allocation,
}

impl JwsTransportErrorReason {
    /// Returns the corresponding protobuf transport reason without input data.
    #[must_use]
    pub const fn reason(&self) -> crate::api::contract::JoseJwsTransportErrorReason {
        super::map_reason::reason(self)
    }

    /// Returns the distinct JOSE-domain stack code for this transport failure.
    /// Operation-local transport numbers must not be forwarded as stack codes.
    #[must_use]
    pub const fn stack_reason(&self) -> crate::api::contract::JoseErrorReason {
        crate::map_failure::jws_transport(self).reason()
    }
}
