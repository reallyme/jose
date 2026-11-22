// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseExternalJwsAlgorithm as Contract;

/// Closed native view of the schema's JoseExternalJwsAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExternalJwsAlgorithm {
    /// Schema-defined ES256 identity.
    Es256,
    /// Schema-defined ES384 identity.
    Es384,
    /// Schema-defined ES512 identity.
    Es512,
    /// Schema-defined ES256K identity.
    Es256k,
    /// Schema-defined EdDSA identity.
    EdDsa,
    /// Schema-defined PS256 identity.
    Ps256,
    /// Schema-defined PS384 identity.
    Ps384,
    /// Schema-defined PS512 identity.
    Ps512,
    /// Schema-defined RS256 identity.
    Rs256,
    /// Schema-defined RS384 identity.
    Rs384,
    /// Schema-defined RS512 identity.
    Rs512,
    /// Schema-defined HS256 identity.
    Hs256,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseExternalJwsAlgorithm>>
    for ExternalJwsAlgorithm
{
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES256) => Ok(Self::Es256),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES384) => Ok(Self::Es384),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES512) => Ok(Self::Es512),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES256K) => Ok(Self::Es256k),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_EDDSA) => Ok(Self::EdDsa),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS256) => Ok(Self::Ps256),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS384) => Ok(Self::Ps384),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS512) => Ok(Self::Ps512),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS256) => Ok(Self::Rs256),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS384) => Ok(Self::Rs384),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS512) => Ok(Self::Rs512),
            Some(Contract::JOSE_EXTERNAL_JWS_ALGORITHM_HS256) => Ok(Self::Hs256),
            _ => Err(crate::wire::JoseWireError::primitive_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
            )),
        }
    }
}

impl From<ExternalJwsAlgorithm> for Contract {
    fn from(value: ExternalJwsAlgorithm) -> Self {
        match value {
            ExternalJwsAlgorithm::Es256 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_ES256,
            ExternalJwsAlgorithm::Es384 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_ES384,
            ExternalJwsAlgorithm::Es512 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_ES512,
            ExternalJwsAlgorithm::Es256k => Self::JOSE_EXTERNAL_JWS_ALGORITHM_ES256K,
            ExternalJwsAlgorithm::EdDsa => Self::JOSE_EXTERNAL_JWS_ALGORITHM_EDDSA,
            ExternalJwsAlgorithm::Ps256 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_PS256,
            ExternalJwsAlgorithm::Ps384 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_PS384,
            ExternalJwsAlgorithm::Ps512 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_PS512,
            ExternalJwsAlgorithm::Rs256 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_RS256,
            ExternalJwsAlgorithm::Rs384 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_RS384,
            ExternalJwsAlgorithm::Rs512 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_RS512,
            ExternalJwsAlgorithm::Hs256 => Self::JOSE_EXTERNAL_JWS_ALGORITHM_HS256,
        }
    }
}

impl ExternalJwsAlgorithm {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Es256k => "ES256K",
            Self::EdDsa => "EdDSA",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Hs256 => "HS256",
        }
    }
}

impl ExternalJwsAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            "ES512" => Some(Self::Es512),
            "ES256K" => Some(Self::Es256k),
            "EdDSA" => Some(Self::EdDsa),
            "PS256" => Some(Self::Ps256),
            "PS384" => Some(Self::Ps384),
            "PS512" => Some(Self::Ps512),
            "RS256" => Some(Self::Rs256),
            "RS384" => Some(Self::Rs384),
            "RS512" => Some(Self::Rs512),
            "HS256" => Some(Self::Hs256),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "external_jws_algorithm_tests.rs"]
mod tests;
