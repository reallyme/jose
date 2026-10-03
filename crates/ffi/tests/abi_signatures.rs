#![allow(missing_docs)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_jose_ffi::{
    rm_jose_abi_version, rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1,
    rm_jose_max_json_request_bytes, rm_jose_max_request_bytes, rm_jose_max_response_bytes,
    rm_jose_zeroize_buffer,
};

// Keep the Rust signatures paired with the C header smoke test. A declaration
// change on either side must fail its respective compile step.
const _: extern "C" fn() -> u32 = rm_jose_abi_version;
const _: extern "C" fn() -> usize = rm_jose_max_request_bytes;
const _: extern "C" fn() -> usize = rm_jose_max_json_request_bytes;
const _: extern "C" fn() -> usize = rm_jose_max_response_bytes;
const _: unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32 =
    rm_jose_execute_operation_v1;
const _: unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32 =
    rm_jose_execute_operation_json_v1;
const _: unsafe extern "C" fn(u32, *mut u8, usize) -> i32 = rm_jose_zeroize_buffer;
