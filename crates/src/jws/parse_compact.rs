// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Maximum accepted compact JWS size in bytes.
pub const MAX_COMPACT_JWS_BYTES: usize = 1024 * 1024;

pub(crate) struct CompactJwsParts<'a> {
    pub(crate) protected_header: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

pub(crate) fn parse_compact_jws<'a, E>(
    jws: &'a str,
    invalid_compact: E,
) -> Result<CompactJwsParts<'a>, E> {
    if jws.len() > MAX_COMPACT_JWS_BYTES {
        return Err(invalid_compact);
    }

    let mut parts = jws.split('.');
    let Some(protected_header) = parts.next() else {
        return Err(invalid_compact);
    };
    let Some(payload) = parts.next() else {
        return Err(invalid_compact);
    };
    let Some(signature) = parts.next() else {
        return Err(invalid_compact);
    };
    if parts.next().is_some() {
        return Err(invalid_compact);
    }

    Ok(CompactJwsParts {
        protected_header,
        payload,
        signature,
    })
}

pub(crate) fn signing_input(protected_header: &str, payload: &str) -> String {
    format!("{protected_header}.{payload}")
}
