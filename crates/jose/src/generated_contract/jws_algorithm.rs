// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseSignatureAlgorithm as Contract;

/// Closed native view of the schema's JoseSignatureAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsAlgorithm {
    /// Schema-defined EdDSA identity.
    Eddsa,
    /// Schema-defined ES256 identity.
    Es256,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseSignatureAlgorithm>> for JwsAlgorithm {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_SIGNATURE_ALGORITHM_EDDSA) => Ok(Self::Eddsa),
            Some(Contract::JOSE_SIGNATURE_ALGORITHM_ES256) => Ok(Self::Es256),
            _ => Err(crate::wire::JoseWireError::provider_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            )),
        }
    }
}

impl From<JwsAlgorithm> for Contract {
    fn from(value: JwsAlgorithm) -> Self {
        match value {
            JwsAlgorithm::Eddsa => Self::JOSE_SIGNATURE_ALGORITHM_EDDSA,
            JwsAlgorithm::Es256 => Self::JOSE_SIGNATURE_ALGORITHM_ES256,
        }
    }
}

impl JwsAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "EdDSA" => Some(Self::Eddsa),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }
}

impl JwsAlgorithm {
    /// Returns the schema-defined protected header json.
    #[must_use]
    pub(crate) const fn protected_header_json(self) -> &'static [u8] {
        match self {
            Self::Eddsa => br#"{"alg":"EdDSA"}"#,
            Self::Es256 => br#"{"alg":"ES256"}"#,
        }
    }
}

#[cfg(test)]
#[path = "jws_algorithm_tests.rs"]
mod tests;
