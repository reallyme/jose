// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::Jwk;

use super::error::JwtError;

#[derive(Debug, Clone, Serialize)]
pub struct JwtHeader {
    /// JOSE `alg` value.
    pub alg: String,

    /// Optional JOSE `typ` value.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Optional JOSE key identifier.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Whether an embedded key header was present in the untrusted input.
    #[serde(skip)]
    pub embedded_key_header: bool,
}

impl<'de> Deserialize<'de> for JwtHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(JwtHeaderVisitor)
    }
}

struct JwtHeaderVisitor;

impl<'de> Visitor<'de> for JwtHeaderVisitor {
    type Value = JwtHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JWT JOSE header object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut alg = None;
        let mut typ = None;
        let mut kid = None;
        let mut embedded_key_header = false;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(JwtError::InvalidHeader));
            }

            match key.as_str() {
                "alg" => alg = Some(map.next_value()?),
                "typ" => typ = Some(map.next_value()?),
                "kid" => kid = Some(map.next_value()?),
                "jwk" | "x5c" => {
                    embedded_key_header = true;
                    let _ = map.next_value::<IgnoredAny>()?;
                }
                "b64" | "crit" | "zip" | "jku" | "x5u" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(JwtError::InvalidHeader));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(JwtHeader {
            alg: alg.ok_or_else(|| serde::de::Error::custom(JwtError::InvalidHeader))?,
            typ,
            kid,
            embedded_key_header,
        })
    }
}

impl JwtHeader {
    /// Validates this header against algorithm, type, and embedded-key policy.
    pub fn validate_with_options(
        &self,
        options: &JwtHeaderValidationOptions<'_>,
    ) -> Result<(), JwtError> {
        match self.alg.as_str() {
            "ES256" | "EdDSA" | "ES256K" => {}
            "none" => return Err(JwtError::InvalidHeader), // unsigned JWTs handled elsewhere
            _ => return Err(JwtError::UnsupportedAlgorithm),
        }

        match self.typ.as_deref() {
            Some(typ) => {
                if options.accepted_typ_values.is_empty()
                    || !options.accepted_typ_values.contains(&typ)
                {
                    return Err(JwtError::InvalidHeader);
                }
            }
            None => {
                if !options.allow_missing_typ {
                    return Err(JwtError::InvalidHeader);
                }
            }
        }

        if self.embedded_key_header && !options.allow_embedded_key_header {
            return Err(JwtError::InvalidHeader);
        }

        Ok(())
    }
}

/// JOSE header options used when encoding signed JWTs.
#[derive(Debug, Clone)]
pub struct JwtHeaderEncodeOptions {
    /// Optional JOSE `typ` value to emit.
    pub(super) typ: Option<String>,
}

impl JwtHeaderEncodeOptions {
    /// Builds signed-JWT header options with an explicit optional `typ` value.
    #[must_use]
    pub const fn new(typ: Option<String>) -> Self {
        Self { typ }
    }

    /// Returns encode options for a conventional `typ = "JWT"` header.
    #[must_use]
    pub fn jwt() -> Self {
        Self::new(Some("JWT".to_owned()))
    }

    /// Returns the configured protected-header `typ` value.
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }
}

/// JOSE header validation policy for signed JWT verification.
#[derive(Debug, Clone, Copy)]
pub struct JwtHeaderValidationOptions<'a> {
    /// Allows signed JWTs that omit `typ`.
    allow_missing_typ: bool,
    /// Allows embedded `jwk` or `x5c` headers.
    allow_embedded_key_header: bool,
    /// Exact accepted `typ` values. Empty means no present `typ` is accepted.
    accepted_typ_values: &'a [&'a str],
}

impl<'a> JwtHeaderValidationOptions<'a> {
    /// Builds a signed-JWT header validation policy.
    #[must_use]
    pub const fn new(
        allow_missing_typ: bool,
        allow_embedded_key_header: bool,
        accepted_typ_values: &'a [&'a str],
    ) -> Self {
        Self {
            allow_missing_typ,
            allow_embedded_key_header,
            accepted_typ_values,
        }
    }

    /// Returns the default signed-JWT policy used by verifier helpers.
    ///
    /// Missing `typ` is accepted for compatibility with deployed JWT issuers,
    /// but embedded sender-controlled key material remains rejected.
    #[must_use]
    pub const fn standard_jwt() -> Self {
        Self::new(true, false, &["JWT"])
    }

    /// Allows signed JWTs that omit `typ`.
    #[must_use]
    pub const fn allow_missing_typ(&self) -> bool {
        self.allow_missing_typ
    }

    /// Allows embedded `jwk` or `x5c` headers.
    #[must_use]
    pub const fn allow_embedded_key_header(&self) -> bool {
        self.allow_embedded_key_header
    }

    /// Returns exact accepted `typ` values.
    #[must_use]
    pub const fn accepted_typ_values(&self) -> &'a [&'a str] {
        self.accepted_typ_values
    }
}

pub(super) fn select_jwk_algorithm(jwk: &Jwk) -> Result<String, JwtError> {
    let use_ = match jwk {
        Jwk::Ec(j) => j.use_.as_deref(),
        Jwk::Okp(j) => j.use_.as_deref(),
        Jwk::Akp(j) => j.use_.as_deref(),
    };
    if use_.is_some_and(|value| value != "sig") {
        return Err(JwtError::AlgorithmMismatch);
    }

    let alg = match jwk {
        Jwk::Ec(j) => j.alg.as_deref(),
        Jwk::Okp(j) => j.alg.as_deref(),
        Jwk::Akp(j) => Some(j.alg.as_str()),
    }
    .ok_or(JwtError::MissingAlgorithm)?;

    match jwk {
        Jwk::Ec(j) if j.crv == "P-256" && alg == "ES256" => Ok(alg.to_string()),
        Jwk::Ec(j) if j.crv == "secp256k1" && alg == "ES256K" => Ok(alg.to_string()),
        Jwk::Okp(j) if j.crv == "Ed25519" && alg == "EdDSA" => Ok(alg.to_string()),

        // No JWT signing algorithm is currently defined for ReallyMe AKP keys.
        Jwk::Akp(_) | Jwk::Ec(_) | Jwk::Okp(_) => Err(JwtError::UnsupportedAlgorithm),
    }
}

pub(super) fn select_jwk_key_id(jwk: &Jwk) -> Option<String> {
    match jwk {
        Jwk::Ec(j) => j.kid.clone(),
        Jwk::Okp(j) => j.kid.clone(),
        Jwk::Akp(j) => j.kid.clone(),
    }
}
