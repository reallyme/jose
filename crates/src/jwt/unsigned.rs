// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use reallyme_codec::base64url::{base64url_bytes_to_bytes, bytes_to_base64url};

use super::{
    parse_compact::{parse_compact_jwt, MAX_COMPACT_JWT_BYTES},
    strict_json::reject_duplicate_object_members,
    JwtError,
};
use crate::Zeroizing;

/// Standard unsigned JWT header.
#[derive(Debug, Clone, Serialize)]
struct UnsignedJwtHeader {
    alg: String,
    typ: Option<String>,
}

impl<'de> Deserialize<'de> for UnsignedJwtHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(UnsignedJwtHeaderVisitor)
    }
}

struct UnsignedJwtHeaderVisitor;

impl<'de> Visitor<'de> for UnsignedJwtHeaderVisitor {
    type Value = UnsignedJwtHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an unsigned JWT JOSE header object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut alg = None;
        let mut typ = None;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(JwtError::InvalidHeader));
            }

            match key.as_str() {
                "alg" => alg = Some(map.next_value()?),
                "typ" => typ = Some(map.next_value()?),
                "b64" | "crit" | "zip" | "jku" | "jwk" | "x5u" | "x5c" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(JwtError::InvalidHeader));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(UnsignedJwtHeader {
            alg: alg.ok_or_else(|| serde::de::Error::custom(JwtError::InvalidHeader))?,
            typ,
        })
    }
}

impl Default for UnsignedJwtHeader {
    fn default() -> Self {
        Self {
            alg: "none".to_string(),
            typ: Some("JWT".to_string()),
        }
    }
}

/// Encode claims into an **unsigned JWT** (alg = "none").
///
/// Output format:
/// base64url(header) "." base64url(payload) "."
///
/// # Errors
///
/// Returns [`JwtError::Serialization`] when claims cannot be serialized and
/// [`JwtError::LengthOverflow`] if compact serialization length arithmetic
/// overflows.
pub fn encode_unsigned_jwt<Claims: Serialize>(claims: &Claims) -> Result<String, JwtError> {
    let claims_json =
        Zeroizing::new(serde_json::to_vec(claims).map_err(|_| JwtError::Serialization)?);
    encode_unsigned_jwt_claims_json(&claims_json)
}

pub(crate) fn encode_unsigned_jwt_claims_json(claims_json: &[u8]) -> Result<String, JwtError> {
    reject_duplicate_object_members(claims_json)?;
    let mut deserializer = serde_json::Deserializer::from_slice(claims_json);
    let _ = IgnoredAny::deserialize(&mut deserializer).map_err(|_| JwtError::InvalidClaims)?;
    deserializer.end().map_err(|_| JwtError::InvalidClaims)?;
    let header = UnsignedJwtHeader::default();

    let header_json =
        Zeroizing::new(serde_json::to_vec(&header).map_err(|_| JwtError::Serialization)?);

    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(claims_json);
    let len = header_b64
        .len()
        .checked_add(1)
        .and_then(|with_separator| with_separator.checked_add(payload_b64.len()))
        .and_then(|with_payload| with_payload.checked_add(1))
        .ok_or(JwtError::LengthOverflow)?;
    if len > MAX_COMPACT_JWT_BYTES {
        return Err(JwtError::InputTooLarge);
    }

    let mut jwt = String::with_capacity(len);
    jwt.push_str(&header_b64);
    jwt.push('.');
    jwt.push_str(&payload_b64);
    jwt.push('.');
    Ok(jwt)
}

/// Decode an **unsigned JWT**.
///
/// This:
/// - enforces `alg = "none"`
/// - enforces empty signature
/// - does NOT verify claims
///
/// # Errors
///
/// Returns [`JwtError::InvalidJwtFormat`] for malformed compact input, invalid
/// Base64URL or JSON, a non-`none` algorithm, a non-empty signature, or claims
/// that cannot be decoded into the requested type.
pub fn decode_unsigned_jwt<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, JwtError> {
    let payload_bytes = decode_unsigned_jwt_claims_json(jwt)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::InvalidJwtFormat)
}

/// Decode an unsigned JWT and return its original claims JSON bytes.
///
/// The returned buffer is zeroized on drop so protobuf and FFI adapters can
/// preserve the caller's JSON representation without keeping a reserialized
/// `serde_json::Value` allocation alive.
///
/// # Errors
///
/// Returns [`JwtError::InvalidJwtFormat`] when compact structure, header
/// policy, payload encoding, or payload JSON validation fails.
pub fn decode_unsigned_jwt_claims_json(jwt: &str) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let parts = parse_compact_jwt(jwt)?;

    let header_bytes = Zeroizing::new(
        base64url_bytes_to_bytes(parts.protected_header.as_bytes())
            .map_err(|_| JwtError::InvalidJwtFormat)?,
    );
    let payload_bytes = Zeroizing::new(
        base64url_bytes_to_bytes(parts.payload.as_bytes())
            .map_err(|_| JwtError::InvalidJwtFormat)?,
    );

    if !parts.signature.is_empty() {
        return Err(JwtError::InvalidJwtFormat);
    }

    let header: UnsignedJwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidJwtFormat)?;

    if header.alg != "none" {
        return Err(JwtError::InvalidJwtFormat);
    }

    if let Some(typ) = header.typ {
        if typ != "JWT" {
            return Err(JwtError::InvalidJwtFormat);
        }
    }

    reject_duplicate_object_members(&payload_bytes).map_err(|_| JwtError::InvalidJwtFormat)?;
    Ok(payload_bytes)
}
