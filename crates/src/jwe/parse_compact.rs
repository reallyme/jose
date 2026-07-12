// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::JweError;

/// Maximum accepted compact JWE size in bytes.
pub const MAX_COMPACT_JWE_BYTES: usize = 1024 * 1024;

pub(crate) struct CompactJweParts<'a> {
    pub(crate) protected_header: &'a str,
    pub(crate) encrypted_key: &'a str,
    pub(crate) iv: &'a str,
    pub(crate) ciphertext: &'a str,
    pub(crate) tag: &'a str,
}

pub(crate) fn parse_compact_jwe(input: &str) -> Result<CompactJweParts<'_>, JweError> {
    if input.len() > MAX_COMPACT_JWE_BYTES {
        return Err(JweError::InputTooLarge);
    }

    let mut parts = input.split('.');
    let Some(protected_header) = parts.next() else {
        return Err(JweError::InvalidCompact);
    };
    let Some(encrypted_key) = parts.next() else {
        return Err(JweError::InvalidCompact);
    };
    let Some(iv) = parts.next() else {
        return Err(JweError::InvalidCompact);
    };
    let Some(ciphertext) = parts.next() else {
        return Err(JweError::InvalidCompact);
    };
    let Some(tag) = parts.next() else {
        return Err(JweError::InvalidCompact);
    };
    if parts.next().is_some() || protected_header.is_empty() || iv.is_empty() || tag.is_empty() {
        return Err(JweError::InvalidCompact);
    }

    Ok(CompactJweParts {
        protected_header,
        encrypted_key,
        iv,
        ciphertext,
        tag,
    })
}

pub(crate) fn format_compact_jwe(
    protected_header: &str,
    encrypted_key: &str,
    iv: &str,
    ciphertext: &str,
    tag: &str,
) -> Result<String, JweError> {
    let encoded_len = protected_header
        .len()
        .checked_add(encrypted_key.len())
        .and_then(|len| len.checked_add(iv.len()))
        .and_then(|len| len.checked_add(ciphertext.len()))
        .and_then(|len| len.checked_add(tag.len()))
        .and_then(|len| len.checked_add(4))
        .ok_or(JweError::LengthOverflow)?;
    if encoded_len > MAX_COMPACT_JWE_BYTES {
        return Err(JweError::InputTooLarge);
    }

    let mut compact = String::with_capacity(encoded_len);
    compact.push_str(protected_header);
    compact.push('.');
    compact.push_str(encrypted_key);
    compact.push('.');
    compact.push_str(iv);
    compact.push('.');
    compact.push_str(ciphertext);
    compact.push('.');
    compact.push_str(tag);
    Ok(compact)
}
