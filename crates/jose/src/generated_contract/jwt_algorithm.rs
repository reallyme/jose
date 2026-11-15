// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseSignatureAlgorithm as Contract;

/// Closed native view of the schema's JoseSignatureAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwtAlgorithm {
    /// Schema-defined EdDSA identity.
    Eddsa,
    /// Schema-defined ES256 identity.
    Es256,
    /// Schema-defined ES256K identity.
    Es256k,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseSignatureAlgorithm>> for JwtAlgorithm {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_SIGNATURE_ALGORITHM_EDDSA) => Ok(Self::Eddsa),
            Some(Contract::JOSE_SIGNATURE_ALGORITHM_ES256) => Ok(Self::Es256),
            Some(Contract::JOSE_SIGNATURE_ALGORITHM_ES256K) => Ok(Self::Es256k),
            _ => Err(crate::wire::JoseWireError::provider_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            )),
        }
    }
}

impl From<JwtAlgorithm> for Contract {
    fn from(value: JwtAlgorithm) -> Self {
        match value {
            JwtAlgorithm::Eddsa => Self::JOSE_SIGNATURE_ALGORITHM_EDDSA,
            JwtAlgorithm::Es256 => Self::JOSE_SIGNATURE_ALGORITHM_ES256,
            JwtAlgorithm::Es256k => Self::JOSE_SIGNATURE_ALGORITHM_ES256K,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined as str.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Eddsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es256k => "ES256K",
        }
    }
}

impl JwtAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "EdDSA" => Some(Self::Eddsa),
            "ES256" => Some(Self::Es256),
            "ES256K" => Some(Self::Es256k),
            _ => None,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined backend.
    #[must_use]
    pub(crate) const fn backend(self) -> crate::Algorithm {
        match self {
            Self::Eddsa => crate::Algorithm::Ed25519,
            Self::Es256 => crate::Algorithm::P256,
            Self::Es256k => crate::Algorithm::Secp256k1,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined named curve.
    #[must_use]
    pub(crate) const fn named_curve(self) -> crate::api::contract::JoseNamedCurve {
        match self {
            Self::Eddsa => crate::api::contract::JoseNamedCurve::JOSE_NAMED_CURVE_ED25519,
            Self::Es256 => crate::api::contract::JoseNamedCurve::JOSE_NAMED_CURVE_P256,
            Self::Es256k => crate::api::contract::JoseNamedCurve::JOSE_NAMED_CURVE_SECP256K1,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined signature encoding.
    #[must_use]
    pub(crate) const fn signature_encoding(self) -> crate::api::contract::JoseSignatureEncoding {
        match self {
            Self::Eddsa => {
                crate::api::contract::JoseSignatureEncoding::JOSE_SIGNATURE_ENCODING_FIXED_WIDTH
            }
            Self::Es256 => {
                crate::api::contract::JoseSignatureEncoding::JOSE_SIGNATURE_ENCODING_FIXED_WIDTH
            }
            Self::Es256k => {
                crate::api::contract::JoseSignatureEncoding::JOSE_SIGNATURE_ENCODING_FIXED_WIDTH
            }
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined signature bytes.
    #[must_use]
    pub(crate) const fn signature_bytes(self) -> u32 {
        match self {
            Self::Eddsa => 64,
            Self::Es256 => 64,
            Self::Es256k => 64,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined signature len.
    #[must_use]
    pub(crate) const fn signature_len(self) -> usize {
        match self {
            Self::Eddsa => 64,
            Self::Es256 => 64,
            Self::Es256k => 64,
        }
    }
}

impl JwtAlgorithm {
    /// Returns the schema-defined builtin raw provider.
    #[must_use]
    pub(crate) const fn builtin_raw_provider(self) -> bool {
        match self {
            Self::Eddsa => false,
            Self::Es256 => true,
            Self::Es256k => false,
        }
    }
}

impl JwtAlgorithm {
    pub(crate) fn matches_jwk(self, key: &crate::Jwk) -> bool {
        match (self, key) {
            (Self::Eddsa, crate::Jwk::Okp(key)) => key.crv == "Ed25519",
            (Self::Es256, crate::Jwk::Ec(key)) => key.crv == "P-256",
            (Self::Es256k, crate::Jwk::Ec(key)) => key.crv == "secp256k1",
            _ => false,
        }
    }
}

#[cfg(test)]
#[path = "jwt_algorithm_tests.rs"]
mod tests;
