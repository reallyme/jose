// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz compact JWE parsing and fail-closed direct-key decryption.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwe::{decrypt_compact_jwe_bytes, CompactJwePolicy, DirectJweKeyResolver};

const A128GCM_KEY: [u8; 16] = [0u8; 16];

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let resolver = DirectJweKeyResolver::new(&A128GCM_KEY);
        let _ = decrypt_compact_jwe_bytes(
            input,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &resolver,
        );
    }
});
