// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Fixed, non-identifying failures for JWK thumbprint computation.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwkThumbprintErrorReason {
    /// A required member is absent or empty.
    #[error("missing or empty JWK thumbprint member")]
    MissingMember,
    /// A required JSON member is not a string.
    #[error("invalid JWK thumbprint member type")]
    InvalidMemberType,
    /// The JSON key type is not EC, OKP, RSA, or oct.
    #[error("unsupported JWK thumbprint key type")]
    UnsupportedKeyType,
    /// The JSON adapter did not receive an object.
    #[error("JWK thumbprint requires a JSON object")]
    InvalidJsonObject,
    /// A required member exceeds the UTF-8 byte ceiling.
    #[error("JWK thumbprint member too large")]
    MemberTooLarge,
    /// A checked canonical serialization length overflowed.
    #[error("JWK thumbprint length overflow")]
    LengthOverflow,
    /// Canonical JSON storage could not be reserved.
    #[error("JWK thumbprint allocation failed")]
    Allocation,
    /// Canonical JSON serialization failed.
    #[error("JWK thumbprint serialization failed")]
    Serialization,
}

impl JwkThumbprintErrorReason {
    /// Returns the schema-defined reason without exposing caller data.
    #[must_use]
    pub const fn reason(&self) -> crate::api::contract::JoseErrorReason {
        crate::map_failure::jwk_thumbprint(self).reason()
    }
}
