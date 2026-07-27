// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical operation-contract C exports.

use reallyme_jose::wire::{
    execute_operation_json_v1, execute_operation_v1, MAX_JOSE_PROTO_JSON_BYTES,
    MAX_JOSE_PROTO_MESSAGE_BYTES, MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_mutable_bytes, validate_operation_ranges, write_len, write_slice,
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
/// pointer and alias checks. On `OutputCapacityMismatch`, it contains the exact
/// required response length and the output buffer is unchanged.
///
/// Platform adapters use a zero-capacity sizing call followed by an independent
/// write call. The encoded response length for one request is therefore an ABI
/// invariant: randomized operations may change response bytes, but every
/// randomized field has a fixed encoded width. A future operation with
/// variable-length randomized output requires a different allocation contract.
///
/// # Safety
///
/// Nonempty input and output ranges must each reference one live allocation.
/// The output range must be exclusively writable and disjoint from the input
/// and aligned `len_out` storage for the duration of the call.
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
/// containing at least `len` bytes for the duration of the call.
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
        let Ok(bytes) = (unsafe { write_slice(ptr, len) }) else {
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
    // SAFETY: The complete range validator established valid, aligned,
    // non-overlapping produced-length storage before initialization.
    if unsafe { write_len(call.len_out, 0) }.is_err() {
        return JoseFfiStatus::CallerError;
    }
    if call.abi_version != JOSE_ABI_VERSION {
        return JoseFfiStatus::UnsupportedAbi;
    }
    let Some(sentinel_maximum) = maximum_request_bytes.checked_add(1) else {
        return JoseFfiStatus::BackendError;
    };
    if call.request_len > sentinel_maximum {
        return JoseFfiStatus::CallerError;
    }

    // SAFETY: Range validation preceded initialization and established the
    // caller-owned immutable request allocation for this invocation.
    let request = match unsafe { read_slice(call.request_ptr, call.request_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut rng = reallyme_crypto::csprng::OsSecureRandom;
    let response = execute_request(request, &mut rng);
    write_response(
        call.output_ptr,
        call.output_capacity,
        call.len_out,
        response,
    )
}

fn write_response(
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
    mut response: Zeroizing<Vec<u8>>,
) -> JoseFfiStatus {
    if MAX_JOSE_FFI_RESPONSE_BYTES == 0 {
        response.zeroize();
        return JoseFfiStatus::BackendError;
    }
    if response.len() > MAX_JOSE_FFI_RESPONSE_BYTES {
        response.zeroize();
        return JoseFfiStatus::BackendError;
    }
    let produced_len = response.len();
    // SAFETY: The entrypoint validated and initialized this aligned output
    // before request processing; no aliasing owner has been introduced.
    if unsafe { write_len(len_out, produced_len) }.is_err() {
        response.zeroize();
        return JoseFfiStatus::CallerError;
    }
    if output_capacity < produced_len {
        response.zeroize();
        return JoseFfiStatus::OutputCapacityMismatch;
    }
    // SAFETY: The entrypoint validated the exclusive output allocation and
    // its disjointness from input and length storage before processing.
    let output = match unsafe { write_slice(output_ptr, output_capacity) } {
        Ok(value) => value,
        Err(status) => {
            response.zeroize();
            return status;
        }
    };
    let Some(destination) = output.get_mut(..produced_len) else {
        response.zeroize();
        return JoseFfiStatus::BackendError;
    };
    destination.copy_from_slice(&response);
    response.zeroize();
    JoseFfiStatus::Success
}
