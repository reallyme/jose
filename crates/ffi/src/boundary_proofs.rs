// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references replacement functions through stub attributes.
#![allow(dead_code)]

use core::mem::{align_of, size_of, MaybeUninit};
use core::ptr::{without_provenance, without_provenance_mut};

use super::{
    rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1, rm_jose_zeroize_buffer,
    JoseFfiStatus, JOSE_ABI_VERSION, MAX_JOSE_PROTO_JSON_BYTES, MAX_JOSE_PROTO_MESSAGE_BYTES,
};
use crate::pointer::validate_operation_ranges;

#[derive(kani::Arbitrary)]
struct CallerRanges {
    request: usize,
    request_len: usize,
    output: usize,
    output_capacity: usize,
    produced: usize,
}

impl CallerRanges {
    fn metadata_is_valid(&self) -> bool {
        let produced_width = size_of::<usize>();
        byte_range_is_valid(self.request, self.request_len)
            && byte_range_is_valid(self.output, self.output_capacity)
            && self.produced != 0
            && self.produced.is_multiple_of(align_of::<usize>())
            && byte_range_is_valid(self.produced, produced_width)
            && !overlap(
                self.request,
                self.request_len,
                self.output,
                self.output_capacity,
            )
            && !overlap(
                self.request,
                self.request_len,
                self.produced,
                produced_width,
            )
            && !overlap(
                self.output,
                self.output_capacity,
                self.produced,
                produced_width,
            )
    }
}

// The specification uses widened math so it never depends on wrapping native
// address arithmetic. Compare intervals by their intersection, including
// adjacent ranges and null/zero pairs.
fn end(start: usize, width: usize) -> u128 {
    let (Ok(start), Ok(width)) = (u128::try_from(start), u128::try_from(width)) else {
        kani::assert(false, "the address model can represent a machine word");
        return u128::MAX;
    };
    let Some(end) = start.checked_add(width) else {
        kani::assert(
            false,
            "the address model can represent the sum of two machine words",
        );
        return u128::MAX;
    };
    end
}

fn byte_range_is_valid(start: usize, width: usize) -> bool {
    width == 0
        || (start != 0 && isize::try_from(width).is_ok() && end(start, width) <= end(usize::MAX, 0))
}

fn overlap(first: usize, first_width: usize, second: usize, second_width: usize) -> bool {
    end(first.max(second), 0) < end(first, first_width).min(end(second, second_width))
}

fn execute_guarded<F: FnOnce() -> JoseFfiStatus>(operation: F) -> JoseFfiStatus {
    operation()
}

unsafe fn unexpected_request_read<'a>(
    _ptr: *const u8,
    _len: usize,
) -> Result<&'a [u8], JoseFfiStatus> {
    kani::assert(
        false,
        "invalid metadata reached the request slice constructor",
    );
    Err(JoseFfiStatus::CallerError)
}

unsafe fn unexpected_length_write(_ptr: *mut usize, _value: usize) -> Result<(), JoseFfiStatus> {
    kani::assert(false, "invalid metadata reached a produced-length write");
    Err(JoseFfiStatus::CallerError)
}

unsafe fn unexpected_output_borrow<'a>(
    _ptr: *mut u8,
    _len: usize,
) -> Result<&'a mut [MaybeUninit<u8>], JoseFfiStatus> {
    kani::assert(
        false,
        "invalid metadata reached the mutable slice constructor",
    );
    Err(JoseFfiStatus::CallerError)
}

fn unexpected_execute(
    _request: &[u8],
    _rng: &mut reallyme_crypto::csprng::OsSecureRandom,
) -> zeroize::Zeroizing<Vec<u8>> {
    kani::assert(false, "invalid metadata reached operation execution");
    zeroize::Zeroizing::new(Vec::new())
}

#[kani::proof]
fn pointer_validator_matches_nonempty_address_intervals() {
    let ranges = kani::any::<CallerRanges>();
    let result = validate_operation_ranges(
        without_provenance(ranges.request),
        ranges.request_len,
        without_provenance_mut(ranges.output),
        ranges.output_capacity,
        without_provenance_mut(ranges.produced),
    );

    kani::assert(
        result
            == if ranges.metadata_is_valid() {
                Ok(())
            } else {
                Err(JoseFfiStatus::CallerError)
            },
        "accept exactly the well-formed, pairwise disjoint ranges",
    );
    kani::cover!(
        result.is_ok() && ranges.request == 0 && ranges.output == 0,
        "null and empty byte ranges are accepted with valid length storage"
    );
    kani::cover!(
        result.is_ok()
            && ranges.request_len == 1
            && end(ranges.request, 1) == end(ranges.output, 0)
            && ranges.output_capacity != 0,
        "adjacent nonempty ranges are accepted"
    );
    kani::cover!(
        result.is_err() && ranges.request_len != 0 && ranges.request == 0,
        "a null nonempty request is rejected"
    );
    kani::cover!(
        result.is_err() && ranges.output_capacity != 0 && ranges.output == 0,
        "a null nonempty output is rejected"
    );
    kani::cover!(
        result.is_err() && ranges.produced == 0,
        "null produced-length storage is rejected"
    );
    kani::cover!(
        result.is_err()
            && ranges.request_len == 0
            && ranges.output_capacity == 0
            && ranges.produced != 0
            && !ranges.produced.is_multiple_of(align_of::<usize>()),
        "misaligned produced-length storage is rejected"
    );
    kani::cover!(
        result.is_err()
            && ranges.request_len == 0
            && ranges.output_capacity == 0
            && ranges.produced.is_multiple_of(align_of::<usize>())
            && end(ranges.produced, size_of::<usize>()) > end(usize::MAX, 0),
        "an aligned produced-length range can still wrap"
    );
    kani::cover!(
        result.is_err()
            && ranges.request != 0
            && isize::try_from(ranges.request_len).is_ok()
            && end(ranges.request, ranges.request_len) > end(usize::MAX, 0),
        "a bounded request length can still wrap its address range"
    );
    kani::cover!(
        result.is_err() && ranges.output != 0 && isize::try_from(ranges.output_capacity).is_err(),
        "output capacity exceeds the maximum slice length"
    );
}

#[kani::proof]
#[kani::stub(super::ffi_guard, execute_guarded)]
#[kani::stub(super::read_slice, unexpected_request_read)]
#[kani::stub(super::write_len, unexpected_length_write)]
#[kani::stub(super::write_uninit_slice, unexpected_output_borrow)]
#[kani::stub(super::execute_binary_operation, unexpected_execute)]
#[kani::stub(super::execute_json_operation, unexpected_execute)]
fn invalid_operation_metadata_reaches_no_caller_memory_access() {
    let ranges = kani::any::<CallerRanges>();
    let json = kani::any::<bool>();
    let request_ceiling = if json {
        MAX_JOSE_PROTO_JSON_BYTES
    } else {
        MAX_JOSE_PROTO_MESSAGE_BYTES
    };
    let too_large = end(ranges.request_len, 0) > end(request_ceiling, 1);
    let ranges_valid = ranges.metadata_is_valid();
    kani::assume(!ranges_valid || too_large);

    // SAFETY: These are address-only pointers. The harness assumes invalid
    // metadata and asserts that every memory-access helper is unreachable.
    let status = unsafe {
        let execute = if json {
            rm_jose_execute_operation_json_v1
        } else {
            rm_jose_execute_operation_v1
        };
        execute(
            kani::any::<u32>(),
            without_provenance(ranges.request),
            ranges.request_len,
            without_provenance_mut(ranges.output),
            ranges.output_capacity,
            without_provenance_mut(ranges.produced),
        )
    };

    kani::assert(
        status == JoseFfiStatus::CallerError.code(),
        "invalid calls fail closed",
    );
    kani::cover!(
        ranges_valid && too_large && !json,
        "binary request ceiling enforced before writes"
    );
    kani::cover!(
        ranges_valid && too_large && json,
        "JSON request ceiling enforced before writes"
    );
    kani::cover!(
        overlap(
            ranges.request,
            ranges.request_len,
            ranges.output,
            ranges.output_capacity
        ),
        "request and output overlap"
    );
    kani::cover!(
        overlap(
            ranges.request,
            ranges.request_len,
            ranges.produced,
            size_of::<usize>()
        ),
        "request and produced length overlap"
    );
    kani::cover!(
        overlap(
            ranges.output,
            ranges.output_capacity,
            ranges.produced,
            size_of::<usize>()
        ),
        "output and produced length overlap"
    );
}

#[kani::proof]
#[kani::stub(super::ffi_guard, execute_guarded)]
#[kani::stub(super::write_uninit_slice, unexpected_output_borrow)]
fn invalid_cleanup_metadata_reaches_no_caller_memory_access() {
    let address = kani::any::<usize>();
    let len = kani::any::<usize>();
    let abi = kani::any::<u32>();
    kani::assume(abi != JOSE_ABI_VERSION || !byte_range_is_valid(address, len));

    // SAFETY: The cleanup must return before borrowing the address as a slice.
    let status = unsafe { rm_jose_zeroize_buffer(abi, without_provenance_mut(address), len) };
    let expected = if abi == JOSE_ABI_VERSION {
        JoseFfiStatus::CallerError
    } else {
        JoseFfiStatus::UnsupportedAbi
    };
    kani::assert(
        status == expected.code(),
        "invalid cleanup fails before borrowing memory",
    );
    kani::cover!(
        abi != JOSE_ABI_VERSION && byte_range_is_valid(address, len),
        "unsupported cleanup ABI"
    );
    kani::cover!(
        abi == JOSE_ABI_VERSION && address == 0 && len != 0,
        "null nonempty cleanup"
    );
    kani::cover!(
        abi == JOSE_ABI_VERSION
            && address != 0
            && isize::try_from(len).is_ok()
            && end(address, len) > end(usize::MAX, 0),
        "wrapping cleanup range"
    );
    kani::cover!(
        abi == JOSE_ABI_VERSION && isize::try_from(len).is_err(),
        "impossible cleanup length"
    );
}
