// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz valid and deliberately rejected C pointer/length arrangements.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose_ffi::status::JoseFfiStatus;
use reallyme_jose_ffi::{
    rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1,
    rm_jose_max_response_bytes, rm_jose_zeroize_buffer, JOSE_ABI_VERSION,
};

const JSON_MASK: u8 = 0x01;
const WRONG_ABI_MASK: u8 = 0x02;
const ALIAS_MASK: u8 = 0x04;
const ZERO_CAPACITY_MASK: u8 = 0x08;
const FUZZ_OUTPUT_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let abi_version = if selector & WRONG_ABI_MASK == 0 {
        JOSE_ABI_VERSION
    } else {
        JOSE_ABI_VERSION.wrapping_add(1)
    };
    let execute = if selector & JSON_MASK == 0 {
        rm_jose_execute_operation_v1
    } else {
        rm_jose_execute_operation_json_v1
    };
    let mut produced = usize::MAX;
    let mut output = [0xa5_u8; FUZZ_OUTPUT_BYTES];

    let status = if selector & ALIAS_MASK != 0 && !body.is_empty() {
        let mut aliased = body.to_vec();
        // SAFETY: Both raw pointers identify the same live allocation on
        // purpose. The boundary must reject overlap before dereference.
        unsafe {
            execute(
                abi_version,
                aliased.as_ptr(),
                aliased.len(),
                aliased.as_mut_ptr(),
                aliased.len(),
                &mut produced,
            )
        }
    } else {
        let (output_ptr, output_capacity) = if selector & ZERO_CAPACITY_MASK == 0 {
            (output.as_mut_ptr(), output.len())
        } else {
            (core::ptr::null_mut(), 0)
        };
        // SAFETY: Input, output, and length storage are valid and disjoint;
        // the null output is paired only with zero capacity.
        unsafe {
            execute(
                abi_version,
                body.as_ptr(),
                body.len(),
                output_ptr,
                output_capacity,
                &mut produced,
            )
        }
    };

    assert!(matches!(
        status,
        value if value == JoseFfiStatus::Success.code()
            || value == JoseFfiStatus::CallerError.code()
            || value == JoseFfiStatus::BackendError.code()
            || value == JoseFfiStatus::PanicCaught.code()
            || value == JoseFfiStatus::OutputCapacityMismatch.code()
            || value == JoseFfiStatus::UnsupportedAbi.code()
    ));
    if status == JoseFfiStatus::Success.code() {
        assert!(produced <= output.len());
    }
    if status == JoseFfiStatus::OutputCapacityMismatch.code() {
        assert!(produced <= rm_jose_max_response_bytes());
    }

    // SAFETY: `output` remains exclusively owned and writable here.
    let cleanup =
        unsafe { rm_jose_zeroize_buffer(JOSE_ABI_VERSION, output.as_mut_ptr(), output.len()) };
    assert_eq!(cleanup, JoseFfiStatus::Success.code());
});
