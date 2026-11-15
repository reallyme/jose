// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read bounded fields without ordinary fragmented-input scratch storage.

use buffa::{bytes::Buf, DecodeError, FieldPayload};
use zeroize::Zeroizing;

pub(crate) fn read(
    payload: &mut FieldPayload<impl Buf>,
) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let mut bytes = Zeroizing::new(Vec::new());
    // The runtime validated this exact field length. Reserve before copying
    // any secret so growth cannot free an earlier, unwiped allocation.
    bytes
        .try_reserve_exact(payload.remaining())
        .map_err(|_| DecodeError::MessageTooLarge)?;
    while payload.has_remaining() {
        let chunk = payload.chunk();
        bytes.extend_from_slice(chunk);
        let count = chunk.len();
        payload.advance(count);
    }
    Ok(bytes)
}
