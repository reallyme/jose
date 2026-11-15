// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::{align_of, MaybeUninit};
use core::ptr::{null, null_mut, without_provenance, without_provenance_mut};

use super::{
    rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1, rm_jose_zeroize_buffer,
    ExecuteOperation, JoseFfiStatus, JOSE_ABI_VERSION,
};

const EXECUTE: [ExecuteOperation; 2] = [
    rm_jose_execute_operation_v1,
    rm_jose_execute_operation_json_v1,
];

#[test]
fn malformed_pointer_and_length_pairs_leave_caller_storage_untouched() {
    for execute in EXECUTE {
        let input = b"{}";
        let mut output = [0xa5_u8; 32];
        let mut produced = usize::MAX;
        let output_ptr = output.as_mut_ptr();
        let len_out = &raw mut produced;
        // A pointer aligned for usize whose one-word interval wraps.
        let wrapping_scalar = usize::MAX ^ (usize::MAX % align_of::<usize>());
        for (request_ptr, request_len, output_ptr, capacity, len_out) in [
            (null(), 1, output_ptr, output.len(), len_out),
            (input.as_ptr(), input.len(), null_mut(), 1, len_out),
            (
                input.as_ptr(),
                input.len(),
                output_ptr,
                output.len(),
                null_mut(),
            ),
            (
                without_provenance(usize::MAX),
                2,
                output_ptr,
                output.len(),
                len_out,
            ),
            (
                input.as_ptr(),
                input.len(),
                without_provenance_mut(usize::MAX),
                2,
                len_out,
            ),
            (
                input.as_ptr(),
                usize::MAX,
                output_ptr,
                output.len(),
                len_out,
            ),
            (input.as_ptr(), input.len(), output_ptr, usize::MAX, len_out),
            (
                input.as_ptr(),
                input.len(),
                output_ptr,
                output.len(),
                len_out.cast::<u8>().wrapping_add(1).cast(),
            ),
            (
                input.as_ptr(),
                input.len(),
                output_ptr,
                output.len(),
                without_provenance_mut(wrapping_scalar),
            ),
        ] {
            // SAFETY: Each row deliberately supplies invalid metadata. The
            // other ranges are live, and the rejected range must stay unused.
            let status = unsafe {
                execute(
                    JOSE_ABI_VERSION,
                    request_ptr,
                    request_len,
                    output_ptr,
                    capacity,
                    len_out,
                )
            };
            assert_eq!(status, JoseFfiStatus::CallerError.code());
            assert_eq!(produced, usize::MAX);
            assert_eq!(output, [0xa5; 32]);
        }
    }
}

#[test]
fn partial_overlap_and_both_length_output_aliases_leave_memory_untouched() {
    for execute in EXECUTE {
        let mut storage = [usize::MAX; 2];
        let aligned = storage.as_mut_ptr();
        let bytes = aligned.cast::<u8>();
        let mut separate_output = [0xa5_u8; 32];
        let mut separate_length = usize::MAX;
        for (request, request_len, output, capacity, len_out) in [
            (
                bytes.cast_const(),
                2,
                bytes.wrapping_add(1),
                2,
                &raw mut separate_length,
            ),
            (
                bytes.wrapping_add(1).cast_const(),
                1,
                separate_output.as_mut_ptr(),
                separate_output.len(),
                aligned,
            ),
            (null(), 0, bytes.wrapping_add(1), 1, aligned),
        ] {
            // SAFETY: Each alias deliberately overlaps one live region, and
            // the boundary rejects it before creating a Rust reference.
            let status = unsafe {
                execute(
                    JOSE_ABI_VERSION,
                    request,
                    request_len,
                    output,
                    capacity,
                    len_out,
                )
            };
            assert_eq!(status, JoseFfiStatus::CallerError.code());
            assert_eq!(storage, [usize::MAX; 2]);
            assert_eq!(separate_output, [0xa5; 32]);
            assert_eq!(separate_length, usize::MAX);
        }
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn accepted_calls_write_only_the_produced_prefix_of_uninitialized_storage() {
    for execute in EXECUTE {
        let mut output = [MaybeUninit::<u8>::uninit(); 64];
        output.last_mut().unwrap().write(0xa5);
        let mut produced = MaybeUninit::<usize>::uninit();
        // SAFETY: Output and produced length are live, exclusive and
        // disjoint. A zero-length request may use a null pointer.
        let status = unsafe {
            execute(
                JOSE_ABI_VERSION,
                null(),
                0,
                output.as_mut_ptr().cast(),
                output.len(),
                produced.as_mut_ptr(),
            )
        };
        assert_eq!(status, JoseFfiStatus::Success.code());
        // SAFETY: A successful call initialized the produced length and
        // exactly that prefix. The trailer was initialized before the call.
        let produced = unsafe { produced.assume_init() };
        assert!(produced > 0 && produced < output.len());
        let response = output.get(..produced).unwrap();
        // SAFETY: Each byte in this prefix was initialized by the export.
        let response = unsafe { response.assume_init_ref() };
        assert!(
            super::decode_operation_response_v1(response, super::JoseOperationKind::JwsSign)
                .is_ok()
        );
        // SAFETY: The trailer was initialized above and lies beyond the
        // reported prefix within the passed buffer.
        assert_eq!(unsafe { output.last().unwrap().assume_init() }, 0xa5);
    }
}

#[test]
fn cleanup_accepts_null_only_for_an_empty_range_and_wipes_uninitialized_bytes() {
    // SAFETY: The null/zero call has no bytes to wipe. The invalid nonempty
    // call must fail before a slice is constructed.
    let empty_status = unsafe { rm_jose_zeroize_buffer(JOSE_ABI_VERSION, null_mut(), 0) };
    let invalid_status = unsafe { rm_jose_zeroize_buffer(JOSE_ABI_VERSION, null_mut(), 1) };
    assert_eq!(empty_status, JoseFfiStatus::Success.code());
    assert_eq!(invalid_status, JoseFfiStatus::CallerError.code());

    let mut storage = [MaybeUninit::<u8>::uninit(); 16];
    // SAFETY: The range is live and exclusively writable.
    let wiped = unsafe {
        rm_jose_zeroize_buffer(JOSE_ABI_VERSION, storage.as_mut_ptr().cast(), storage.len())
    };
    assert_eq!(wiped, JoseFfiStatus::Success.code());
    // SAFETY: Cleanup initialized the entire range to zero.
    assert_eq!(unsafe { storage.assume_init_ref() }, &[0; 16]);
}
