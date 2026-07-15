// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;

use super::{
    parse_compact::{build_sig_structure, MAX_COMPACT_JWS_BYTES},
    parse_header::JwsAlgorithm,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsSigningInputError {
    LengthOverflow,
    InputTooLarge,
}

pub(crate) struct EncodedJwsSigningInput {
    pub(crate) signing_input: Vec<u8>,
    pub(crate) protected_header: String,
    pub(crate) payload: String,
}

pub(crate) fn encode_jws_signing_input(
    algorithm: JwsAlgorithm,
    payload: &[u8],
) -> Result<EncodedJwsSigningInput, JwsSigningInputError> {
    let protected_header = bytes_to_base64url(algorithm.protected_header_json());
    let payload = bytes_to_base64url(payload);
    let signing_input = build_sig_structure(
        &protected_header,
        &payload,
        JwsSigningInputError::LengthOverflow,
    )?;

    Ok(EncodedJwsSigningInput {
        signing_input,
        protected_header,
        payload,
    })
}

pub(crate) fn encode_compact_jws(
    signing_input: EncodedJwsSigningInput,
    signature: &[u8],
) -> Result<String, JwsSigningInputError> {
    let signature = bytes_to_base64url(signature);
    let len = signing_input
        .protected_header
        .len()
        .checked_add(1)
        .and_then(|with_separator| with_separator.checked_add(signing_input.payload.len()))
        .and_then(|with_payload| with_payload.checked_add(1))
        .and_then(|with_separator| with_separator.checked_add(signature.len()))
        .ok_or(JwsSigningInputError::LengthOverflow)?;
    if len > MAX_COMPACT_JWS_BYTES {
        return Err(JwsSigningInputError::InputTooLarge);
    }

    let mut compact = String::with_capacity(len);
    compact.push_str(&signing_input.protected_header);
    compact.push('.');
    compact.push_str(&signing_input.payload);
    compact.push('.');
    compact.push_str(&signature);
    Ok(compact)
}
