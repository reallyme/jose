// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize, Serializer};

use crate::jwe::JweError;

/// Supported JWE key-management algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JweKeyManagementAlgorithm {
    /// Direct use of a caller-supplied content-encryption key (`alg = "dir"`).
    Direct,
    /// ECDH-ES direct key agreement (`alg = "ECDH-ES"`).
    EcdhEs,
}

impl JweKeyManagementAlgorithm {
    /// Returns the JOSE `alg` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "dir",
            Self::EcdhEs => "ECDH-ES",
        }
    }

    pub(crate) fn parse(input: &str) -> Result<Self, JweError> {
        match input {
            "dir" => Ok(Self::Direct),
            "ECDH-ES" => Ok(Self::EcdhEs),
            _ => Err(JweError::UnsupportedKeyManagementAlgorithm),
        }
    }
}

impl Serialize for JweKeyManagementAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Supported JWE content-encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JweContentEncryptionAlgorithm {
    /// AES-128-GCM (`enc = "A128GCM"`).
    A128Gcm,
    /// AES-192-GCM (`enc = "A192GCM"`).
    A192Gcm,
    /// AES-256-GCM (`enc = "A256GCM"`).
    A256Gcm,
}

impl JweContentEncryptionAlgorithm {
    /// Returns the JOSE `enc` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// Required content-encryption key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => reallyme_crypto::aes::AES_128_GCM_KEY_LENGTH,
            Self::A192Gcm => reallyme_crypto::aes::AES_192_GCM_KEY_LENGTH,
            Self::A256Gcm => reallyme_crypto::aes::AES_256_GCM_KEY_LENGTH,
        }
    }

    /// Required IV length in bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::A128Gcm => reallyme_crypto::aes::AES_128_GCM_NONCE_LENGTH,
            Self::A192Gcm => reallyme_crypto::aes::AES_192_GCM_NONCE_LENGTH,
            Self::A256Gcm => reallyme_crypto::aes::AES_256_GCM_NONCE_LENGTH,
        }
    }

    /// Required authentication tag length in bytes.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::A128Gcm => reallyme_crypto::aes::AES_128_GCM_TAG_LENGTH,
            Self::A192Gcm => reallyme_crypto::aes::AES_192_GCM_TAG_LENGTH,
            Self::A256Gcm => reallyme_crypto::aes::AES_256_GCM_TAG_LENGTH,
        }
    }

    pub(crate) fn parse(input: &str) -> Result<Self, JweError> {
        match input {
            "A128GCM" => Ok(Self::A128Gcm),
            "A192GCM" => Ok(Self::A192Gcm),
            "A256GCM" => Ok(Self::A256Gcm),
            _ => Err(JweError::UnsupportedContentEncryptionAlgorithm),
        }
    }
}

impl Serialize for JweContentEncryptionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JweKeyManagementAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for JweContentEncryptionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}
