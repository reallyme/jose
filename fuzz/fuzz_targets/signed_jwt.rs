// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz signed JWT parsing, header policy, and ES256 key binding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwt::decode_verify_jwt_signature_only;

mod support;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let jwk = support::p256_jwk();
        let _: Result<serde_json::Value, _> =
            decode_verify_jwt_signature_only(input, &jwk, support::P256_PUBLIC_KEY_SEC1);
    }
});
