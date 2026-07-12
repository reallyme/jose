// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::JwtError;

/// Maximum accepted compact JWT size in bytes.
pub const MAX_COMPACT_JWT_BYTES: usize = 1024 * 1024;

pub(crate) struct CompactJwtParts<'a> {
    pub(crate) protected_header: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

pub(crate) fn parse_compact_jwt(jwt: &str) -> Result<CompactJwtParts<'_>, JwtError> {
    if jwt.len() > MAX_COMPACT_JWT_BYTES {
        return Err(JwtError::InputTooLarge);
    }

    let mut parts = jwt.split('.');
    let Some(protected_header) = parts.next() else {
        return Err(JwtError::InvalidJwtFormat);
    };
    let Some(payload) = parts.next() else {
        return Err(JwtError::InvalidJwtFormat);
    };
    let Some(signature) = parts.next() else {
        return Err(JwtError::InvalidJwtFormat);
    };
    if parts.next().is_some() {
        return Err(JwtError::InvalidJwtFormat);
    }

    Ok(CompactJwtParts {
        protected_header,
        payload,
        signature,
    })
}
