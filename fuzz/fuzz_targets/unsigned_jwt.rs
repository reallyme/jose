// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz unsigned JWT parsing and `alg = "none"` policy.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwt::decode_unsigned_jwt;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let _: Result<serde_json::Value, _> = decode_unsigned_jwt(input);
    }
});
