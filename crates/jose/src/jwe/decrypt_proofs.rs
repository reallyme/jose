// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use super::{finish_decryption, JweCompressionAlgorithm, JweError};

#[kani::proof]
fn plaintext_requires_authentication_before_release_or_decompression() {
    let authenticated = kani::any::<bool>();
    let compressed = kani::any::<bool>();
    let decompresses = kani::any::<bool>();
    let plaintext = kani::any::<u8>();
    let decoded = kani::any::<u8>();
    let invoked = Cell::new(false);
    let compression = compressed.then_some(JweCompressionAlgorithm::Deflate);
    // The production function treats plaintext as opaque. Give the cipher and
    // decoder distinct symbolic outputs to check which value reaches the caller.
    let cipher_result = if authenticated {
        Ok(plaintext)
    } else {
        Err(JweError::Decrypt)
    };

    let result = finish_decryption(cipher_result, compression, |input| {
        kani::assert(authenticated, "decompression follows authentication");
        kani::assert(compressed, "decompression requires a compression header");
        kani::assert(
            input == plaintext,
            "the decoder receives the cipher's plaintext",
        );
        invoked.set(true);
        if decompresses {
            Ok(decoded)
        } else {
            Err(JweError::Decompression)
        }
    });

    kani::assert(
        invoked.get() == (authenticated && compressed),
        "decoder invocation matches policy and authentication",
    );
    let returned = result.as_ref().ok().copied();
    match (authenticated, compressed, decompresses) {
        (false, _, _) => kani::assert(
            matches!(result, Err(JweError::Decrypt)),
            "authentication failure is propagated without plaintext",
        ),
        (true, false, _) => kani::assert(
            returned == Some(plaintext),
            "an uncompressed success returns the authenticated bytes",
        ),
        (true, true, true) => kani::assert(
            returned == Some(decoded),
            "a compressed success returns the decompressed bytes",
        ),
        (true, true, false) => kani::assert(
            matches!(result, Err(JweError::Decompression)),
            "a decoder failure is propagated without plaintext",
        ),
    }

    kani::cover!(
        !authenticated && compressed && !invoked.get(),
        "failed authentication skips decompression"
    );
    kani::cover!(
        authenticated && !compressed && result.is_ok(),
        "uncompressed success"
    );
    kani::cover!(
        authenticated && compressed && result.is_ok(),
        "compressed success"
    );
    kani::cover!(
        matches!(result, Err(JweError::Decompression)) && invoked.get(),
        "decoder failure after authentication"
    );
}
