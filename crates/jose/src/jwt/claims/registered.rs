// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::super::datatype::{NumericDate, StringOrURI};
use super::deserialize_audience::{deserialize_audience, serialize_audience};

/// Registered JWT claims (RFC 7519).
///
/// All fields are optional by spec.
/// Cloning creates another PII owner; each owner clears its string fields on
/// drop. Avoid retaining clones beyond the verification operation.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    /// Issuer claim (`iss`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<StringOrURI>,

    /// Subject claim (`sub`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<StringOrURI>,

    /// Audience claim (`aud`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_audience",
        serialize_with = "serialize_audience"
    )]
    pub aud: Option<Vec<StringOrURI>>,

    /// Expiration time (`exp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<NumericDate>,

    /// Not-before time (`nbf`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<NumericDate>,

    /// Issued-at time (`iat`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<NumericDate>,

    /// JWT identifier (`jti`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl core::fmt::Debug for RegisteredClaims {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RegisteredClaims(<redacted>)")
    }
}

impl Drop for RegisteredClaims {
    fn drop(&mut self) {
        self.jti.zeroize();
        // StringOrURI clears issuer, subject, and each audience on drop.
    }
}
