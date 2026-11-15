// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJwtClaim as Contract;

/// Closed native view of the schema's JoseJwtClaim selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JwtTemporalClaim {
    /// Schema-defined Exp identity.
    Exp,
    /// Schema-defined Nbf identity.
    Nbf,
    /// Schema-defined Iat identity.
    Iat,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJwtClaim>> for JwtTemporalClaim {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWT_CLAIM_EXP) => Ok(Self::Exp),
            Some(Contract::JOSE_JWT_CLAIM_NBF) => Ok(Self::Nbf),
            Some(Contract::JOSE_JWT_CLAIM_IAT) => Ok(Self::Iat),
            _ => Err(crate::wire::JoseWireError::primitive_internal(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY)),
        }
    }
}

impl From<JwtTemporalClaim> for Contract {
    fn from(value: JwtTemporalClaim) -> Self {
        match value {
            JwtTemporalClaim::Exp => Self::JOSE_JWT_CLAIM_EXP,
            JwtTemporalClaim::Nbf => Self::JOSE_JWT_CLAIM_NBF,
            JwtTemporalClaim::Iat => Self::JOSE_JWT_CLAIM_IAT,
        }
    }
}

impl JwtTemporalClaim {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exp => "exp",
            Self::Nbf => "nbf",
            Self::Iat => "iat",
        }
    }
}

#[cfg(test)]
#[path = "jwt_temporal_claim_tests.rs"]
mod tests;
