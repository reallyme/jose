// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJweCompressionAlgorithm as Contract;

/// Closed native view of the schema's JoseJweCompressionAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JweCompressionAlgorithm {
    /// Schema-defined DEF identity.
    Deflate,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJweCompressionAlgorithm>>
    for JweCompressionAlgorithm
{
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE) => Ok(Self::Deflate),
            _ => Err(crate::wire::JoseWireError::primitive_internal(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_COMPRESSION_ALGORITHM)),
        }
    }
}

impl From<JweCompressionAlgorithm> for Contract {
    fn from(value: JweCompressionAlgorithm) -> Self {
        match value {
            JweCompressionAlgorithm::Deflate => Self::JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE,
        }
    }
}

impl JweCompressionAlgorithm {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deflate => "DEF",
        }
    }
}

impl JweCompressionAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "DEF" => Some(Self::Deflate),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "jwe_compression_algorithm_tests.rs"]
mod tests;
