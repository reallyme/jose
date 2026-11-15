// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references replacement functions through stub attributes.
#![allow(dead_code)]

use core::mem::MaybeUninit;

use super::{response_destination, write_response, JoseFfiStatus, MAX_JOSE_FFI_RESPONSE_BYTES};

struct ExpectedBorrow {
    response_len: usize,
    capacity: usize,
}

unsafe fn observe_output_borrow<'a>(
    ptr: *mut u8,
    len: usize,
) -> Result<&'a mut [MaybeUninit<u8>], JoseFfiStatus> {
    // SAFETY: The full-domain proof passes a pointer to its live observation
    // record. This stub inspects the record without constructing a byte slice.
    let expected = unsafe { &*ptr.cast::<ExpectedBorrow>() };
    kani::assert(
        expected.response_len <= expected.capacity,
        "an undersized output never reaches the borrow",
    );
    kani::assert(
        expected.response_len <= MAX_JOSE_FFI_RESPONSE_BYTES,
        "an oversized response never reaches the borrow",
    );
    kani::assert(
        len == expected.response_len,
        "the borrow includes exactly the reported prefix",
    );
    // Identify the borrow path without allocating a machine-word-sized slice.
    Err(JoseFfiStatus::ProviderError)
}

#[kani::proof]
#[kani::stub(super::write_uninit_slice, observe_output_borrow)]
fn arbitrary_lengths_report_exact_size_and_borrow_only_a_fitting_prefix() {
    let response_len = kani::any::<usize>();
    let capacity = kani::any::<usize>();
    let original = kani::any::<usize>();
    let mut reported = original;
    let mut observation = ExpectedBorrow {
        response_len,
        capacity,
    };

    // SAFETY: The length slot is live and exclusive. The stub observes the
    // output borrow using the record and never treats it as a byte buffer.
    let destination = unsafe {
        response_destination(
            (&raw mut observation).cast(),
            capacity,
            &raw mut reported,
            response_len,
        )
    };

    if response_len > MAX_JOSE_FFI_RESPONSE_BYTES {
        kani::assert(
            matches!(destination, Err(JoseFfiStatus::BackendError)),
            "oversized response is rejected",
        );
        kani::assert(
            reported == original,
            "oversized response leaves the length unchanged",
        );
    } else {
        kani::assert(reported == response_len, "reports the exact encoded length");
        let expected = if capacity < response_len {
            JoseFfiStatus::OutputCapacityMismatch
        } else {
            JoseFfiStatus::ProviderError
        };
        kani::assert(
            matches!(destination, Err(error) if error == expected),
            "only a fitting response reaches the borrow",
        );
    }
    kani::cover!(
        response_len == MAX_JOSE_FFI_RESPONSE_BYTES && capacity == response_len,
        "maximum response fits exactly"
    );
    kani::cover!(
        response_len <= MAX_JOSE_FFI_RESPONSE_BYTES && capacity == 0 && response_len != 0,
        "zero-capacity probe reports the full size"
    );
    kani::cover!(
        response_len <= MAX_JOSE_FFI_RESPONSE_BYTES
            && response_len.checked_sub(1) == Some(capacity)
            && capacity != 0,
        "nonempty output is one byte short"
    );
    kani::cover!(
        response_len < capacity && response_len == 0,
        "empty response selects an empty prefix"
    );
    kani::cover!(
        response_len > MAX_JOSE_FFI_RESPONSE_BYTES,
        "response exceeds the ABI limit"
    );
}

#[kani::proof]
#[kani::unwind(9)]
fn response_copy_preserves_every_byte_outside_the_reported_prefix() {
    // Small live allocations exercise the real slice constructor and copy.
    // The companion harness covers the full size domain without allocations.
    const BYTES: usize = 4;
    let source = kani::any::<[u8; BYTES]>();
    let original = kani::any::<[u8; BYTES]>();
    let response_len = kani::any::<usize>();
    let capacity = kani::any::<usize>();
    kani::assume(response_len <= BYTES && capacity <= BYTES);
    let Some(response) = source.get(..response_len) else {
        kani::assert(false, "source prefix must exist");
        return;
    };
    let mut output = original.map(MaybeUninit::new);
    let mut reported = MaybeUninit::<usize>::uninit();

    // SAFETY: Input, output, and length storage are distinct live allocations.
    // The chosen capacity is within the output allocation.
    let status = unsafe {
        write_response(
            output.as_mut_ptr().cast(),
            capacity,
            reported.as_mut_ptr(),
            response,
        )
    };
    // SAFETY: The modeled response is below the ABI limit and the scalar is
    // valid, so the writer initializes it before either capacity outcome.
    let reported = unsafe { reported.assume_init() };
    kani::assert(
        reported == response_len,
        "actual length storage receives the exact size",
    );

    let fits = capacity >= response_len;
    let expected = if fits {
        JoseFfiStatus::Success
    } else {
        JoseFfiStatus::OutputCapacityMismatch
    };
    kani::assert(
        status == expected,
        "actual writer reports the capacity outcome",
    );
    for (index, (after, before)) in output.iter().zip(original).enumerate() {
        let expected = if fits && index < response_len {
            source.get(index).copied()
        } else {
            Some(before)
        };
        // SAFETY: All four slots were initialized before the call.
        kani::assert(
            Some(unsafe { after.assume_init() }) == expected,
            "each byte matches the response prefix or its original value",
        );
    }
    kani::cover!(
        fits && response_len != 0 && capacity > response_len,
        "successful copy leaves a tail"
    );
    kani::cover!(
        fits && response_len != 0 && capacity == response_len,
        "successful exact-capacity copy"
    );
    kani::cover!(!fits && capacity != 0, "undersized output is preserved");
}
