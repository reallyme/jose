// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Map;
use zeroize::Zeroize;

use crate::JsonValue;
use reallyme_codec::base64url::bytes_to_base64url;

use super::JweError;

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

/// Decoded compact-JWE protected header.
#[derive(Deserialize)]
pub struct CompactJweProtectedHeader {
    /// Key-management algorithm.
    pub alg: JweKeyManagementAlgorithm,
    /// Content-encryption algorithm.
    pub enc: JweContentEncryptionAlgorithm,
    /// Key identifier, when supplied by the sender.
    pub kid: Option<String>,
    /// Agreement PartyUInfo, still Base64URL-encoded as carried in the header.
    pub apu: Option<String>,
    /// Agreement PartyVInfo, still Base64URL-encoded as carried in the header.
    pub apv: Option<String>,
    /// Ephemeral public key JWK for ECDH-ES.
    pub epk: Option<JsonValue>,
    /// Optional JOSE type.
    pub typ: Option<String>,
    /// Optional JOSE content type.
    pub cty: Option<String>,
}

impl Drop for CompactJweProtectedHeader {
    fn drop(&mut self) {
        self.kid.zeroize();
        self.apu.zeroize();
        self.apv.zeroize();
        if let Some(epk) = self.epk.take() {
            zeroize_json_value(epk);
        }
        self.typ.zeroize();
        self.cty.zeroize();
    }
}

fn zeroize_json_value(value: JsonValue) {
    match value {
        JsonValue::String(mut value) => value.zeroize(),
        JsonValue::Array(values) => values.into_iter().for_each(zeroize_json_value),
        JsonValue::Object(values) => values.into_iter().for_each(|(mut key, value)| {
            key.zeroize();
            zeroize_json_value(value);
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

pub(crate) struct RawCompactJweProtectedHeader {
    alg: String,
    enc: String,
    kid: Option<String>,
    apu: Option<String>,
    apv: Option<String>,
    epk: Option<JsonValue>,
    typ: Option<String>,
    cty: Option<String>,
}

impl<'de> Deserialize<'de> for RawCompactJweProtectedHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RawCompactJweProtectedHeaderVisitor)
    }
}

struct RawCompactJweProtectedHeaderVisitor;

impl<'de> Visitor<'de> for RawCompactJweProtectedHeaderVisitor {
    type Value = RawCompactJweProtectedHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a compact JWE protected header object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut alg = None;
        let mut enc = None;
        let mut kid = None;
        let mut apu = None;
        let mut apv = None;
        let mut epk = None;
        let mut typ = None;
        let mut cty = None;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(JweError::InvalidHeader));
            }
            match key.as_str() {
                "alg" => alg = Some(map.next_value()?),
                "enc" => enc = Some(map.next_value()?),
                "kid" => kid = Some(map.next_value()?),
                "apu" => apu = Some(map.next_value()?),
                "apv" => apv = Some(map.next_value()?),
                "epk" => {
                    let public_epk: PublicEpkJwk = map.next_value()?;
                    epk = Some(public_epk.into_json());
                }
                "typ" => typ = Some(map.next_value()?),
                "cty" => cty = Some(map.next_value()?),
                "b64" | "crit" | "zip" | "jku" | "x5u" | "x5c" | "jwk" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(JweError::InvalidHeader));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(RawCompactJweProtectedHeader {
            alg: alg.ok_or_else(|| serde::de::Error::custom(JweError::InvalidHeader))?,
            enc: enc.ok_or_else(|| serde::de::Error::custom(JweError::InvalidHeader))?,
            kid,
            apu,
            apv,
            epk,
            typ,
            cty,
        })
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

impl TryFrom<RawCompactJweProtectedHeader> for CompactJweProtectedHeader {
    type Error = JweError;

    fn try_from(value: RawCompactJweProtectedHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            alg: JweKeyManagementAlgorithm::parse(&value.alg)?,
            enc: JweContentEncryptionAlgorithm::parse(&value.enc)?,
            kid: value.kid,
            apu: value.apu,
            apv: value.apv,
            epk: value.epk,
            typ: value.typ,
            cty: value.cty,
        })
    }
}

struct PublicEpkJwk {
    fields: Map<String, JsonValue>,
}

impl PublicEpkJwk {
    fn into_json(self) -> JsonValue {
        JsonValue::Object(self.fields)
    }
}

impl<'de> Deserialize<'de> for PublicEpkJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(PublicEpkJwkVisitor)
    }
}

struct PublicEpkJwkVisitor;

impl<'de> Visitor<'de> for PublicEpkJwkVisitor {
    type Value = PublicEpkJwk;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a public ECDH-ES ephemeral public-key JWK")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut fields = Map::new();

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(JweError::InvalidHeader));
            }

            match key.as_str() {
                "kty" | "crv" | "x" | "y" => {
                    fields.insert(key, JsonValue::String(map.next_value()?));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(JweError::InvalidHeader));
                }
            }
        }

        Ok(PublicEpkJwk { fields })
    }
}

/// Header policy for compact JWE decryption.
#[derive(Debug, Clone, Copy)]
pub struct CompactJwePolicy<'a> {
    /// Permitted key-management algorithms.
    allowed_key_management_algorithms: &'a [JweKeyManagementAlgorithm],
    /// Permitted content-encryption algorithms.
    allowed_content_encryption_algorithms: &'a [JweContentEncryptionAlgorithm],
    /// Require a `kid` protected-header parameter.
    require_kid: bool,
    /// Require an exact `kid` value.
    expected_kid: Option<&'a str>,
    /// Require an exact `typ` value when present.
    expected_typ: Option<&'a str>,
    /// Require an exact `cty` value when present.
    expected_cty: Option<&'a str>,
    /// Require exact raw Agreement PartyUInfo bytes when present.
    expected_apu: Option<&'a [u8]>,
    /// Require exact raw Agreement PartyVInfo bytes when present.
    expected_apv: Option<&'a [u8]>,
}

impl<'a> CompactJwePolicy<'a> {
    /// Builds a compact-JWE policy from the permitted algorithm sets.
    #[must_use]
    pub const fn new(
        allowed_key_management_algorithms: &'a [JweKeyManagementAlgorithm],
        allowed_content_encryption_algorithms: &'a [JweContentEncryptionAlgorithm],
    ) -> Self {
        Self {
            allowed_key_management_algorithms,
            allowed_content_encryption_algorithms,
            require_kid: false,
            expected_kid: None,
            expected_typ: None,
            expected_cty: None,
            expected_apu: None,
            expected_apv: None,
        }
    }

    /// Policy for OpenID4VP `direct_post.jwt` response payloads.
    #[must_use]
    pub const fn openid4vp_direct_post_jwt() -> Self {
        Self {
            allowed_key_management_algorithms: &[
                JweKeyManagementAlgorithm::EcdhEs,
                JweKeyManagementAlgorithm::Direct,
            ],
            allowed_content_encryption_algorithms: &[
                JweContentEncryptionAlgorithm::A128Gcm,
                JweContentEncryptionAlgorithm::A192Gcm,
                JweContentEncryptionAlgorithm::A256Gcm,
            ],
            require_kid: false,
            expected_kid: None,
            expected_typ: None,
            expected_cty: None,
            expected_apu: None,
            expected_apv: None,
        }
    }

    /// Requires a `kid` protected-header parameter.
    #[must_use]
    pub const fn require_kid(mut self) -> Self {
        self.require_kid = true;
        self
    }

    /// Requires the protected header to carry this exact `kid` value.
    #[must_use]
    pub const fn with_expected_kid(mut self, expected_kid: &'a str) -> Self {
        self.expected_kid = Some(expected_kid);
        self
    }

    /// Requires the protected header to carry this exact `typ` value.
    #[must_use]
    pub const fn with_expected_typ(mut self, expected_typ: &'a str) -> Self {
        self.expected_typ = Some(expected_typ);
        self
    }

    /// Requires the protected header to carry this exact `cty` value.
    #[must_use]
    pub const fn with_expected_cty(mut self, expected_cty: &'a str) -> Self {
        self.expected_cty = Some(expected_cty);
        self
    }

    /// Requires this exact raw Agreement PartyUInfo value.
    #[must_use]
    pub const fn with_expected_apu(mut self, expected_apu: &'a [u8]) -> Self {
        self.expected_apu = Some(expected_apu);
        self
    }

    /// Requires this exact raw Agreement PartyVInfo value.
    #[must_use]
    pub const fn with_expected_apv(mut self, expected_apv: &'a [u8]) -> Self {
        self.expected_apv = Some(expected_apv);
        self
    }

    pub(crate) fn validate(&self, header: &CompactJweProtectedHeader) -> Result<(), JweError> {
        if !self.allowed_key_management_algorithms.contains(&header.alg) {
            return Err(JweError::UnsupportedKeyManagementAlgorithm);
        }
        if !self
            .allowed_content_encryption_algorithms
            .contains(&header.enc)
        {
            return Err(JweError::UnsupportedContentEncryptionAlgorithm);
        }
        if self.require_kid && header.kid.is_none() {
            return Err(JweError::MissingRequiredHeaderParameter);
        }
        if let Some(expected) = self.expected_kid {
            if header.kid.as_deref() != Some(expected) {
                return Err(JweError::KidPolicyMismatch);
            }
        }
        if let Some(expected) = self.expected_typ {
            if header.typ.as_deref() != Some(expected) {
                return Err(JweError::TypPolicyMismatch);
            }
        }
        if let Some(expected) = self.expected_cty {
            if header.cty.as_deref() != Some(expected) {
                return Err(JweError::CtyPolicyMismatch);
            }
        }
        if let Some(expected) = self.expected_apu {
            let expected = bytes_to_base64url(expected);
            if header.apu.as_deref() != Some(expected.as_str()) {
                return Err(JweError::ApuPolicyMismatch);
            }
        }
        if let Some(expected) = self.expected_apv {
            let expected = bytes_to_base64url(expected);
            if header.apv.as_deref() != Some(expected.as_str()) {
                return Err(JweError::ApvPolicyMismatch);
            }
        }
        validate_jwe_header_structure(
            header.alg,
            header.epk.is_some(),
            header.apu.is_some(),
            header.apv.is_some(),
        )
    }
}

pub(crate) const fn validate_jwe_header_structure(
    alg: JweKeyManagementAlgorithm,
    has_epk: bool,
    has_apu: bool,
    has_apv: bool,
) -> Result<(), JweError> {
    match alg {
        JweKeyManagementAlgorithm::Direct if has_epk || has_apu || has_apv => {
            Err(JweError::InvalidHeader)
        }
        JweKeyManagementAlgorithm::EcdhEs if !has_epk => {
            Err(JweError::MissingRequiredHeaderParameter)
        }
        JweKeyManagementAlgorithm::Direct | JweKeyManagementAlgorithm::EcdhEs => Ok(()),
    }
}
