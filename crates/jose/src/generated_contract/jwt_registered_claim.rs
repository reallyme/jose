// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJwtClaim as Contract;

/// Closed native view of the schema's JoseJwtClaim selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JwtRegisteredClaim {
    /// Schema-defined Issuer identity.
    Issuer,
    /// Schema-defined Subject identity.
    Subject,
    /// Schema-defined Audience identity.
    Audience,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJwtClaim>> for JwtRegisteredClaim {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWT_CLAIM_ISSUER) => Ok(Self::Issuer),
            Some(Contract::JOSE_JWT_CLAIM_SUBJECT) => Ok(Self::Subject),
            Some(Contract::JOSE_JWT_CLAIM_AUDIENCE) => Ok(Self::Audience),
            _ => Err(crate::wire::JoseWireError::primitive_internal(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY)),
        }
    }
}

impl From<JwtRegisteredClaim> for Contract {
    fn from(value: JwtRegisteredClaim) -> Self {
        match value {
            JwtRegisteredClaim::Issuer => Self::JOSE_JWT_CLAIM_ISSUER,
            JwtRegisteredClaim::Subject => Self::JOSE_JWT_CLAIM_SUBJECT,
            JwtRegisteredClaim::Audience => Self::JOSE_JWT_CLAIM_AUDIENCE,
        }
    }
}

impl JwtRegisteredClaim {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "iss",
            Self::Subject => "sub",
            Self::Audience => "aud",
        }
    }
}

#[cfg(test)]
#[path = "jwt_registered_claim_tests.rs"]
mod tests;
