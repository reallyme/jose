// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    JoseJwsTransportCharacterPolicy as Characters, JoseJwsTransportMemberPolicy,
    JoseJwsTransportPolicy,
};

use super::JwsTransportErrorReason as Error;

pub(super) const SEPARATOR_BYTES: usize = 2;

pub(super) fn budget(value: Option<u64>) -> Result<usize, Error> {
    usize::try_from(value.ok_or(Error::MissingBudget)?).map_err(|_| Error::LengthOverflow)
}

pub(super) fn members(
    protected_header: &str,
    payload: &str,
    signature: &str,
    policy: &JoseJwsTransportPolicy,
) -> Result<(), Error> {
    member(protected_header, policy.protected_header.as_option())?;
    member(payload, policy.payload.as_option())?;
    member(signature, policy.signature.as_option())
}

fn member(value: &str, policy: Option<&JoseJwsTransportMemberPolicy>) -> Result<(), Error> {
    let policy = policy.ok_or(Error::MissingPolicy)?;
    // Validate the selector even for an admitted empty member: an empty input
    // must never turn an unspecified or future policy into a successful one.
    let characters = match policy.characters.as_known() {
        Some(Characters::OpaqueUtf8) => Characters::OpaqueUtf8,
        Some(Characters::Ascii) => Characters::Ascii,
        Some(Characters::AsciiWithoutWhitespace) => Characters::AsciiWithoutWhitespace,
        Some(Characters::Base64urlAlphabet) => Characters::Base64urlAlphabet,
        _ => return Err(Error::InvalidCharacterPolicy),
    };
    if value.is_empty() && !policy.allow_empty {
        return Err(Error::EmptyMember);
    }
    let admitted = match characters {
        Characters::OpaqueUtf8 => true,
        Characters::Ascii => value.is_ascii(),
        Characters::AsciiWithoutWhitespace => value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_whitespace()),
        Characters::Base64urlAlphabet => value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        Characters::Unspecified => return Err(Error::InvalidCharacterPolicy),
    };
    if !admitted {
        return Err(Error::InvalidCharacters);
    }
    Ok(())
}

pub(super) fn composed_lengths(
    protected_header: usize,
    payload: usize,
    signature: usize,
) -> Result<(usize, usize), Error> {
    let input = protected_header
        .checked_add(payload)
        .and_then(|length| length.checked_add(signature))
        .ok_or(Error::LengthOverflow)?;
    let output = input
        .checked_add(SEPARATOR_BYTES)
        .ok_or(Error::LengthOverflow)?;
    Ok((input, output))
}
