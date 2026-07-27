// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the public compact-JWE protected-header deserializer directly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwe::CompactJweProtectedHeader;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<CompactJweProtectedHeader>(data);
});
