// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJweKeyManagementAlgorithm as Contract;

/// Closed native view of the schema's JoseJweKeyManagementAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JweKeyManagementSuite {
    /// Schema-defined Direct identity.
    Direct,
    /// Schema-defined P256 identity.
    P256,
    /// Schema-defined P384 identity.
    P384,
    /// Schema-defined P521 identity.
    P521,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJweKeyManagementAlgorithm>>
    for JweKeyManagementSuite
{
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT) => Ok(Self::Direct),
            Some(Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256) => Ok(Self::P256),
            Some(Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384) => Ok(Self::P384),
            Some(Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521) => Ok(Self::P521),
            _ => Err(crate::wire::JoseWireError::provider_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            )),
        }
    }
}

impl From<JweKeyManagementSuite> for Contract {
    fn from(value: JweKeyManagementSuite) -> Self {
        match value {
            JweKeyManagementSuite::Direct => Self::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            JweKeyManagementSuite::P256 => Self::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256,
            JweKeyManagementSuite::P384 => Self::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384,
            JweKeyManagementSuite::P521 => Self::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521,
        }
    }
}

impl JweKeyManagementSuite {
    /// Returns the schema-defined header algorithm.
    #[must_use]
    pub(crate) const fn header_algorithm(self) -> crate::jwe::JweKeyManagementAlgorithm {
        match self {
            Self::Direct => crate::jwe::JweKeyManagementAlgorithm::Direct,
            Self::P256 => crate::jwe::JweKeyManagementAlgorithm::EcdhEs,
            Self::P384 => crate::jwe::JweKeyManagementAlgorithm::EcdhEs,
            Self::P521 => crate::jwe::JweKeyManagementAlgorithm::EcdhEs,
        }
    }
}

impl JweKeyManagementSuite {
    /// Returns the schema-defined jwk curve.
    #[must_use]
    pub(crate) const fn jwk_curve(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::P256 => Some("P-256"),
            Self::P384 => Some("P-384"),
            Self::P521 => Some("P-521"),
        }
    }
}

#[cfg(test)]
#[path = "jwe_key_management_suite_tests.rs"]
mod tests;
