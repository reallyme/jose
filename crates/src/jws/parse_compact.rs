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

pub(crate) fn build_sig_structure<E>(
    protected_header: &str,
    payload: &str,
    length_overflow: E,
) -> Result<Vec<u8>, E> {
    let len = protected_header
        .len()
        .checked_add(1)
        .and_then(|with_separator| with_separator.checked_add(payload.len()))
        .ok_or(length_overflow)?;

    let mut structure = Vec::with_capacity(len);
    structure.extend_from_slice(protected_header.as_bytes());
    structure.push(b'.');
    structure.extend_from_slice(payload.as_bytes());
    Ok(structure)
}
