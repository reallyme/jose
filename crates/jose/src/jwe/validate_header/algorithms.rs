// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize, Serializer};

use crate::jwe::JweError;

pub use crate::generated_contract::JweKeyManagementAlgorithm;

impl JweKeyManagementAlgorithm {
    pub(crate) fn parse(input: &str) -> Result<Self, JweError> {
        Self::from_jose_name(input).ok_or(JweError::UnsupportedKeyManagementAlgorithm)
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

pub use crate::generated_contract::JweContentEncryptionAlgorithm;

impl JweContentEncryptionAlgorithm {
    pub(crate) fn parse(input: &str) -> Result<Self, JweError> {
        Self::from_jose_name(input).ok_or(JweError::UnsupportedContentEncryptionAlgorithm)
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

pub use crate::generated_contract::JweCompressionAlgorithm;

impl JweCompressionAlgorithm {
    pub(crate) fn parse(input: &str) -> Result<Self, JweError> {
        Self::from_jose_name(input).ok_or(JweError::UnsupportedCompressionAlgorithm)
    }
}

impl Serialize for JweCompressionAlgorithm {
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

impl<'de> Deserialize<'de> for JweCompressionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}
