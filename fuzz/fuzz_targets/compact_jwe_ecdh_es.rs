// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz compact JWE ECDH-ES parsing and fail-closed key agreement.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwe::{decrypt_compact_jwe_bytes, CompactJwePolicy, P256EcdhEsJweKeyResolver};

const P256_RECIPIENT_PRIVATE_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
];

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let resolver = P256EcdhEsJweKeyResolver::new(&P256_RECIPIENT_PRIVATE_KEY);
        let _ = decrypt_compact_jwe_bytes(
            input,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &resolver,
        );
    }
});
