// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared pointer, length, alignment, and alias validation.

use crate::status::JoseFfiStatus;

const MAX_FFI_SLICE_LEN: usize = isize::MAX.unsigned_abs();

fn validate_byte_pair<T>(ptr: *const T, len: usize) -> Result<(), JoseFfiStatus> {
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() || len > MAX_FFI_SLICE_LEN || ptr.addr().checked_add(len).is_none() {
        return Err(JoseFfiStatus::CallerError);
    }
    Ok(())
}

fn validate_scalar_output<T>(ptr: *mut T) -> Result<(), JoseFfiStatus> {
    if ptr.is_null() || !ptr.is_aligned() {
        return Err(JoseFfiStatus::CallerError);
    }
    Ok(())
}

fn validate_disjoint_ranges(
    first_ptr: *const u8,
    first_len: usize,
    second_ptr: *const u8,
    second_len: usize,
) -> Result<(), JoseFfiStatus> {
    validate_byte_pair(first_ptr, first_len)?;
    validate_byte_pair(second_ptr, second_len)?;
    if first_len == 0 || second_len == 0 {
        return Ok(());
    }

    let first_start = first_ptr.addr();
    let second_start = second_ptr.addr();
    let first_end = first_start
        .checked_add(first_len)
        .ok_or(JoseFfiStatus::CallerError)?;
    let second_end = second_start
        .checked_add(second_len)
        .ok_or(JoseFfiStatus::CallerError)?;
    if first_start < second_end && second_start < first_end {
        return Err(JoseFfiStatus::CallerError);
    }
    Ok(())
}

/// Validates all input, output, produced-length, and aliasing relationships for
/// the operation entrypoint before any caller memory is read or written.
pub fn validate_operation_ranges(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    len_out: *mut usize,
) -> Result<(), JoseFfiStatus> {
    validate_byte_pair(request_ptr, request_len)?;
    validate_byte_pair(output_ptr.cast_const(), output_capacity)?;
    validate_scalar_output(len_out)?;

    let len_bytes = core::mem::size_of::<usize>();
    validate_disjoint_ranges(
        output_ptr.cast_const(),
        output_capacity,
        len_out.cast::<u8>().cast_const(),
        len_bytes,
    )?;
    validate_disjoint_ranges(
        request_ptr,
        request_len,
        output_ptr.cast_const(),
        output_capacity,
    )?;
    validate_disjoint_ranges(
        request_ptr,
        request_len,
        len_out.cast::<u8>().cast_const(),
        len_bytes,
    )
}

/// Borrows a caller-owned byte range after validation.
///
/// # Safety
///
/// For nonzero `len`, `ptr` must identify one allocation containing `len`
/// initialized bytes that remain immutable for the returned lifetime.
pub unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], JoseFfiStatus> {
    validate_byte_pair(ptr, len)?;
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: Validation rejects null, impossible lengths, and wrapping
    // address ranges. The exported function's caller contract supplies one
    // live immutable allocation.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Borrows a caller-owned mutable byte range after validation.
///
/// # Safety
///
/// For nonzero `len`, `ptr` must identify one exclusively writable allocation
/// containing at least `len` bytes for the returned lifetime.
pub unsafe fn write_slice<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], JoseFfiStatus> {
    validate_byte_pair(ptr.cast_const(), len)?;
    if len == 0 {
        return Ok(&mut []);
    }
    // SAFETY: Validation rejects null, impossible lengths, and wrapping
    // address ranges. The exported function's caller contract supplies one
    // live exclusive allocation.
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

/// Writes a deterministic produced length after pointer validation.
///
/// # Safety
///
/// `ptr` must identify aligned, writable `usize` storage for the call.
pub unsafe fn write_len(ptr: *mut usize, value: usize) -> Result<(), JoseFfiStatus> {
    validate_scalar_output(ptr)?;
    // SAFETY: The validator established non-null aligned storage; the caller
    // owns it exclusively for this invocation.
    unsafe {
        *ptr = value;
    }
    Ok(())
}

/// Validates a caller-owned mutable byte range used by the cleanup export.
pub fn validate_mutable_bytes(ptr: *mut u8, len: usize) -> Result<(), JoseFfiStatus> {
    validate_byte_pair(ptr.cast_const(), len)
}
