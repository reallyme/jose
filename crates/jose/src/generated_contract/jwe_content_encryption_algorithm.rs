// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseJweContentEncryptionAlgorithm as Contract;

/// Closed native view of the schema's JoseJweContentEncryptionAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JweContentEncryptionAlgorithm {
    /// Schema-defined A128GCM identity.
    A128Gcm,
    /// Schema-defined A192GCM identity.
    A192Gcm,
    /// Schema-defined A256GCM identity.
    A256Gcm,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseJweContentEncryptionAlgorithm>>
    for JweContentEncryptionAlgorithm
{
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM) => Ok(Self::A128Gcm),
            Some(Contract::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM) => Ok(Self::A192Gcm),
            Some(Contract::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM) => Ok(Self::A256Gcm),
            _ => Err(crate::wire::JoseWireError::provider_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            )),
        }
    }
}

impl From<JweContentEncryptionAlgorithm> for Contract {
    fn from(value: JweContentEncryptionAlgorithm) -> Self {
        match value {
            JweContentEncryptionAlgorithm::A128Gcm => {
                Self::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM
            }
            JweContentEncryptionAlgorithm::A192Gcm => {
                Self::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM
            }
            JweContentEncryptionAlgorithm::A256Gcm => {
                Self::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM
            }
        }
    }
}

impl JweContentEncryptionAlgorithm {
    /// Returns the schema-defined as str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }
}

impl JweContentEncryptionAlgorithm {
    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {
        match value {
            "A128GCM" => Some(Self::A128Gcm),
            "A192GCM" => Some(Self::A192Gcm),
            "A256GCM" => Some(Self::A256Gcm),
            _ => None,
        }
    }
}

impl JweContentEncryptionAlgorithm {
    /// Returns the schema-defined key len.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
            Self::A256Gcm => 32,
        }
    }
}

impl JweContentEncryptionAlgorithm {
    /// Returns the schema-defined nonce len.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::A128Gcm => 12,
            Self::A192Gcm => 12,
            Self::A256Gcm => 12,
        }
    }
}

impl JweContentEncryptionAlgorithm {
    /// Returns the schema-defined tag len.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 16,
            Self::A256Gcm => 16,
        }
    }
}

#[cfg(test)]
#[path = "jwe_content_encryption_algorithm_tests.rs"]
mod tests;
