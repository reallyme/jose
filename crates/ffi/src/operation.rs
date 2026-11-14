// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical operation-contract C exports.

// Every exported raw-pointer entry point validates the ABI boundary below.
#![allow(unsafe_code)]

use core::mem::MaybeUninit;

use reallyme_jose::wire::{
    execute_operation_json_v1, execute_operation_v1, MAX_JOSE_PROTO_JSON_BYTES,
    MAX_JOSE_PROTO_MESSAGE_BYTES, MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_mutable_bytes, validate_operation_ranges, write_len, write_uninit_slice,
};
use crate::status::JoseFfiStatus;

/// Exact C ABI version required by every operational call.
pub const JOSE_ABI_VERSION: u32 = 1;

const MAX_JOSE_FFI_RESPONSE_BYTES: usize =
    match MAX_JOSE_PROTO_MESSAGE_BYTES.checked_add(MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES) {
        Some(value) => value,
        None => 0,
    };

type ExecuteRequest = fn(&[u8], &mut reallyme_crypto::csprng::OsSecureRandom) -> Zeroizing<Vec<u8>>;

struct BoundaryCall {
    abi_version: u32,
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
}

/// Returns the exact C ABI signature and ownership version.
#[unsafe(no_mangle)]
pub const extern "C" fn rm_jose_abi_version() -> u32 {
    JOSE_ABI_VERSION
}

/// Returns the authoritative binary protobuf request limit.
#[unsafe(no_mangle)]
pub const extern "C" fn rm_jose_max_request_bytes() -> usize {
    MAX_JOSE_PROTO_MESSAGE_BYTES
}

/// Returns the authoritative generated ProtoJSON request limit.
#[unsafe(no_mangle)]
pub const extern "C" fn rm_jose_max_json_request_bytes() -> usize {
    MAX_JOSE_PROTO_JSON_BYTES
}

/// Returns the authoritative maximum canonical response size.
#[unsafe(no_mangle)]
pub const extern "C" fn rm_jose_max_response_bytes() -> usize {
    MAX_JOSE_FFI_RESPONSE_BYTES
}

/// Executes one binary protobuf request into a canonical V1 response.
///
/// The caller owns every pointer. `len_out` is initialized to zero after all
/// pointer, length, and alias checks pass. On `OutputCapacityMismatch`,
/// it contains the exact required response length and the output is unchanged.
/// On success, only the first `len_out` bytes of the output are initialized
/// with the encoded response.
///
/// A sizing call executes the request independently from the write call. For
/// the same request, successful randomized JWE encryptions have equal encoded
/// response lengths. If an operation outcome changes between calls, the write
/// call reports the actual length and returns `OutputCapacityMismatch` if it
/// needs more space.
///
/// # Safety
///
/// A nonempty input range that passes validation must refer to initialized bytes
/// in one live allocation and remain immutable for the call. Output and
/// `len_out` ranges that pass validation must refer to live storage that is
/// exclusively writable for the call. The output bytes may be uninitialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_execute_operation_v1(
    abi_version: u32,
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
) -> i32 {
    ffi_guard(|| {
        execute_operation_boundary(
            BoundaryCall {
                abi_version,
                request_ptr,
                request_len,
                output_ptr,
                output_capacity,
                len_out,
            },
            MAX_JOSE_PROTO_MESSAGE_BYTES,
            execute_binary_operation,
        )
    })
    .code()
}

/// Executes one generated ProtoJSON request into a canonical binary V1
/// response.
///
/// # Safety
///
/// Pointer, length, aliasing, and ownership requirements are identical to
/// [`rm_jose_execute_operation_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_execute_operation_json_v1(
    abi_version: u32,
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
) -> i32 {
    ffi_guard(|| {
        execute_operation_boundary(
            BoundaryCall {
                abi_version,
                request_ptr,
                request_len,
                output_ptr,
                output_capacity,
                len_out,
            },
            MAX_JOSE_PROTO_JSON_BYTES,
            execute_json_operation,
        )
    })
    .code()
}

/// Best-effort non-elidable cleanup for caller-owned response/request storage.
///
/// # Safety
///
/// For nonzero `len`, `ptr` must reference one exclusively writable allocation
/// containing at least `len` bytes for the duration of the call. The bytes
/// may be uninitialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_zeroize_buffer(abi_version: u32, ptr: *mut u8, len: usize) -> i32 {
    ffi_guard(|| {
        if abi_version != JOSE_ABI_VERSION {
            return JoseFfiStatus::UnsupportedAbi;
        }
        if validate_mutable_bytes(ptr, len).is_err() {
            return JoseFfiStatus::CallerError;
        }
        // SAFETY: The shared validator rejected null or impossible nonempty
        // ranges; the exported contract supplies exclusive writable storage.
        let Ok(bytes) = (unsafe { write_uninit_slice(ptr, len) }) else {
            return JoseFfiStatus::CallerError;
        };
        bytes.zeroize();
        JoseFfiStatus::Success
    })
    .code()
}

fn execute_binary_operation(
    request: &[u8],
    rng: &mut reallyme_crypto::csprng::OsSecureRandom,
) -> Zeroizing<Vec<u8>> {
    execute_operation_v1(request, rng)
}

fn execute_json_operation(
    request: &[u8],
    rng: &mut reallyme_crypto::csprng::OsSecureRandom,
) -> Zeroizing<Vec<u8>> {
    execute_operation_json_v1(request, rng)
}

fn execute_operation_boundary(
    call: BoundaryCall,
    maximum_request_bytes: usize,
    execute_request: ExecuteRequest,
) -> JoseFfiStatus {
    if validate_operation_ranges(
        call.request_ptr,
        call.request_len,
        call.output_ptr,
        call.output_capacity,
        call.len_out,
    )
    .is_err()
    {
        return JoseFfiStatus::CallerError;
    }
    // Leave all caller storage unchanged on invalid metadata. A sentinel one
    // byte above the wire limit still yields a typed resource-limit response.
    let Some(sentinel_maximum) = maximum_request_bytes.checked_add(1) else {
        return JoseFfiStatus::BackendError;
    };
    if call.request_len > sentinel_maximum {
        return JoseFfiStatus::CallerError;
    }

    // SAFETY: The complete range validator established valid, aligned,
    // non-overlapping produced-length storage before initialization.
    if unsafe { write_len(call.len_out, 0) }.is_err() {
        return JoseFfiStatus::CallerError;
    }
    if call.abi_version != JOSE_ABI_VERSION {
        return JoseFfiStatus::UnsupportedAbi;
    }

    // SAFETY: The range validator checked the pointer and length before
    // initialization. The caller supplies a live immutable request allocation.
    let request = match unsafe { read_slice(call.request_ptr, call.request_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut rng = reallyme_crypto::csprng::OsSecureRandom;
    let mut response = execute_request(request, &mut rng);
    // SAFETY: The entrypoint validated the output and length ranges before
    // processing. The caller supplies live exclusive storage for both.
    let status = unsafe {
        write_response(
            call.output_ptr,
            call.output_capacity,
            call.len_out,
            &response,
        )
    };
    response.zeroize();
    status
}

/// # Safety
///
/// Output and length storage must meet the contract of `response_destination`
/// and be disjoint from `response` for the call.
unsafe fn write_response(
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
    response: &[u8],
) -> JoseFfiStatus {
    // SAFETY: The caller supplies independently writable output and length
    // storage for this call. The response is a separate allocation.
    let destination =
        unsafe { response_destination(output_ptr, output_capacity, len_out, response.len()) };
    match destination {
        Ok(prefix) => {
            // The destination and source lengths come from the same slice.
            prefix.write_copy_of_slice(response);
            JoseFfiStatus::Success
        }
        Err(status) => status,
    }
}

/// Reports the exact response length before deciding whether to borrow output.
/// Borrowing just the prefix keeps the rest of the caller allocation outside
/// the mutable slice used to copy the response.
///
/// # Safety
///
/// For nonzero capacity, `output_ptr` must be valid and exclusively writable
/// for that capacity, and `len_out` must be live aligned writable `usize`
/// storage. These ranges must be disjoint for the call. The successful
/// destination borrow must end before the caller accesses the prefix again.
unsafe fn response_destination<'a>(
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
    response_len: usize,
) -> Result<&'a mut [MaybeUninit<u8>], JoseFfiStatus> {
    if MAX_JOSE_FFI_RESPONSE_BYTES == 0 || response_len > MAX_JOSE_FFI_RESPONSE_BYTES {
        return Err(JoseFfiStatus::BackendError);
    }
    // SAFETY: The caller supplies live exclusive storage for the length.
    unsafe { write_len(len_out, response_len) }?;
    if output_capacity < response_len {
        return Err(JoseFfiStatus::OutputCapacityMismatch);
    }
    // SAFETY: The caller supplies a live exclusive allocation. The capacity
    // check establishes that the entire prefix fits within it.
    unsafe { write_uninit_slice(output_ptr, response_len) }
}

#[cfg(kani)]
#[path = "boundary_proofs.rs"]
mod proofs;

#[cfg(kani)]
#[path = "response_write_proofs.rs"]
mod response_write_proofs;
