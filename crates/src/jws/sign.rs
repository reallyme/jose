// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;

use super::{parse_compact::signing_input, parse_header::JwsAlgorithm};

pub(crate) struct EncodedJwsSigningInput {
    pub(crate) signing_input: String,
    pub(crate) protected_header: String,
    pub(crate) payload: String,
}

pub(crate) fn encode_jws_signing_input(
    algorithm: JwsAlgorithm,
    payload: &[u8],
) -> EncodedJwsSigningInput {
    let protected_header = bytes_to_base64url(algorithm.protected_header_json());
    let payload = bytes_to_base64url(payload);
    let signing_input = signing_input(&protected_header, &payload);

    EncodedJwsSigningInput {
        signing_input,
        protected_header,
        payload,
    }
}

pub(crate) fn encode_compact_jws(
    signing_input: EncodedJwsSigningInput,
    signature: &[u8],
) -> String {
    let signature = bytes_to_base64url(signature);
    format!(
        "{}.{}.{}",
        signing_input.protected_header, signing_input.payload, signature
    )
}
