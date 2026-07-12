// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use reallyme_codec::base64url::{base64url_bytes_to_bytes, bytes_to_base64url};

use super::{parse_compact::parse_compact_jwt, JwtError};

/// Standard unsigned JWT header.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct UnsignedJwtHeader {
    alg: String,
    typ: Option<String>,
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
pub fn encode_unsigned_jwt<Claims: Serialize>(claims: &Claims) -> Result<String, JwtError> {
    let header = UnsignedJwtHeader::default();

    let header_json = serde_json::to_vec(&header).map_err(|_| JwtError::Serialization)?;
    let payload_json = serde_json::to_vec(claims).map_err(|_| JwtError::Serialization)?;

    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(&payload_json);

    Ok(format!("{header_b64}.{payload_b64}."))
}

/// Decode an **unsigned JWT**.
///
/// This:
/// - enforces `alg = "none"`
/// - enforces empty signature
/// - does NOT verify claims
pub fn decode_unsigned_jwt<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims, JwtError> {
    let parts = parse_compact_jwt(jwt)?;

    let header_bytes = base64url_bytes_to_bytes(parts.protected_header.as_bytes())
        .map_err(|_| JwtError::InvalidJwtFormat)?;
    let payload_bytes = base64url_bytes_to_bytes(parts.payload.as_bytes())
        .map_err(|_| JwtError::InvalidJwtFormat)?;

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

    serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::InvalidJwtFormat)
}
