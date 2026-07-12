// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::base64url_bytes_to_bytes;

use super::parse_header::{JwsAlgorithm, JwsProtectedHeader};

pub(crate) fn decode_and_validate_header<E: Copy>(
    protected_header: &str,
    algorithm: JwsAlgorithm,
    bad_base64: E,
    bad_utf8: E,
    mismatch: E,
) -> Result<(), E> {
    let header_bytes =
        base64url_bytes_to_bytes(protected_header.as_bytes()).map_err(|_| bad_base64)?;
    let header_text = core::str::from_utf8(&header_bytes).map_err(|_| bad_utf8)?;
    let header: JwsProtectedHeader = serde_json::from_str(header_text).map_err(|_| mismatch)?;
    if header.alg != algorithm {
        return Err(mismatch);
    }

    Ok(())
}

pub(crate) fn decode_signature<E>(signature: &str, bad_base64: E) -> Result<Vec<u8>, E> {
    base64url_bytes_to_bytes(signature.as_bytes()).map_err(|_| bad_base64)
}
