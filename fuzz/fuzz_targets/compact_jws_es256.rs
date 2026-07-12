// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz compact JWS ES256 parsing and protected-header validation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jws::suites::es256::verify_es256_jws;

mod support;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let _ = verify_es256_jws(input, support::P256_PUBLIC_KEY_SEC1);
    }
});
