// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJweHeaderAlgorithm as Contract;

/// Closed native view of the schema's JoseJweHeaderAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JweKeyManagementAlgorithm {
    /// Schema-defined dir identity.
    Direct,
    /// Schema-defined ECDH-ES identity.
    EcdhEs,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJweHeaderAlgorithm>>
    for JweKeyManagementAlgorithm
{
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWE_HEADER_ALGORITHM_DIRECT) => Ok(Self::Direct),
            Some(Contract::JOSE_JWE_HEADER_ALGORITHM_ECDH_ES) => Ok(Self::EcdhEs),
            _ => Err(crate::wire::JoseWireError::provider_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            )),
        }
    }
}

impl From<JweKeyManagementAlgorithm> for Contract {
    fn from(value: JweKeyManagementAlgorithm) -> Self {
        match value {
            JweKeyManagementAlgorithm::Direct => Self::JOSE_JWE_HEADER_ALGORITHM_DIRECT,
            JweKeyManagementAlgorithm::EcdhEs => Self::JOSE_JWE_HEADER_ALGORITHM_ECDH_ES,
        }
    }
}

impl JweKeyManagementAlgorithm {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "dir",
            Self::EcdhEs => "ECDH-ES",
        }
    }
}

impl JweKeyManagementAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "dir" => Some(Self::Direct),
            "ECDH-ES" => Some(Self::EcdhEs),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "jwe_key_management_algorithm_tests.rs"]
mod tests;
