// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-execution C ABI with a Rust-owned response allocation.

// The raw ownership transfer is confined to these C ABI adapters.
#![allow(unsafe_code)]

use core::mem::{size_of, take};
use core::ptr::{self, NonNull};

use reallyme_crypto::csprng::OsSecureRandom;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::guard::ffi_guard;
use crate::operation::{
    execute_binary_operation, execute_json_operation, rm_jose_max_json_request_bytes,
    rm_jose_max_request_bytes, validate_request_len, JOSE_ABI_VERSION, MAX_JOSE_FFI_RESPONSE_BYTES,
};
use crate::pointer::{
    read_slice, validate_operation_ranges, validate_request_and_slot, validate_scalar_output,
};
use crate::status::JoseFfiStatus;

/// Opaque owner for a canonical protobuf response. Release it with
/// [`rm_jose_owned_response_release_v1`].
pub struct JoseOwnedResponse {
    bytes: Vec<u8>,
}

impl JoseOwnedResponse {
    fn new(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, JoseFfiStatus> {
        if bytes.is_empty() || bytes.len() > MAX_JOSE_FFI_RESPONSE_BYTES {
            return Err(JoseFfiStatus::BackendError);
        }
        // Transfer the allocation without copying any plaintext or claims.
        Ok(Self {
            bytes: take(&mut *bytes),
        })
    }

    const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn wipe_bytes(&mut self) {
        // Vec::zeroize clears initialized bytes and spare capacity. The field
        // remains allocated until Rust drops it after this destructor returns.
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for JoseOwnedResponse {}

impl Drop for JoseOwnedResponse {
    fn drop(&mut self) {
        self.wipe_bytes();
    }
}

/// Executes a binary protobuf request exactly once and transfers the response
/// into an initialized null owner slot on transport success.
///
/// # Safety
///
/// A nonempty request range that passes validation must identify live,
/// initialized, immutable storage for the call. A slot that passes validation
/// must be live, aligned, exclusively writable and initialized to null or to
/// an existing owner pointer. A non-null slot is rejected without overwriting it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_execute_owned_operation_v1(
    abi_version: u32,
    request: *const u8,
    request_len: usize,
    owner_out: *mut *mut JoseOwnedResponse,
) -> i32 {
    ffi_guard(|| {
        // SAFETY: The exported contract supplies the request and initialized slot.
        let result = unsafe {
            execute_into_slot(
                abi_version,
                request,
                request_len,
                owner_out,
                rm_jose_max_request_bytes(),
                execute_binary_operation,
            )
        };
        result.err().unwrap_or(JoseFfiStatus::Success)
    })
    .code()
}

/// Executes a ProtoJSON request exactly once and transfers its binary response.
///
/// # Safety
///
/// The request and slot must satisfy [`rm_jose_execute_owned_operation_v1`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_execute_owned_operation_json_v1(
    abi_version: u32,
    request: *const u8,
    request_len: usize,
    owner_out: *mut *mut JoseOwnedResponse,
) -> i32 {
    ffi_guard(|| {
        // SAFETY: The exported contract supplies the request and initialized slot.
        let result = unsafe {
            execute_into_slot(
                abi_version,
                request,
                request_len,
                owner_out,
                rm_jose_max_json_request_bytes(),
                execute_json_operation,
            )
        };
        result.err().unwrap_or(JoseFfiStatus::Success)
    })
    .code()
}

unsafe fn execute_into_slot(
    abi_version: u32,
    request: *const u8,
    request_len: usize,
    owner_out: *mut *mut JoseOwnedResponse,
    maximum_request_bytes: usize,
    execute: impl FnOnce(&[u8], &mut OsSecureRandom) -> Zeroizing<Vec<u8>>,
) -> Result<(), JoseFfiStatus> {
    require_abi(abi_version)?;
    validate_request_len(request_len, maximum_request_bytes)?;
    validate_request_and_slot(request, request_len, owner_out)?;

    // SAFETY: Metadata validation preceded this access. The caller supplies
    // exclusive initialized storage for the slot, disjoint from the request.
    if !unsafe { owner_out.read() }.is_null() {
        return Err(JoseFfiStatus::CallerError);
    }
    // SAFETY: Validation checked the range and the caller holds the immutable
    // request allocation alive across the execution.
    let request = unsafe { read_slice(request, request_len) }?;
    let owner = JoseOwnedResponse::new(execute(request, &mut OsSecureRandom))?;
    // SAFETY: The initialized empty slot is exclusive for the entire call.
    unsafe { owner_out.write(Box::into_raw(Box::new(owner))) };
    Ok(())
}

/// Borrows response bytes without transferring ownership. A successful call
/// publishes a pointer and a positive length. Errors leave both outputs unchanged.
///
/// # Safety
///
/// Non-null `owner` must designate a live owner returned by this image. The
/// caller must prevent release while this function or any view is in use. A
/// pair of output slots that passes validation must be live, aligned, exclusively
/// writable, and disjoint from each other, the owner, and the response bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_owned_response_view_v1(
    abi_version: u32,
    owner: *const JoseOwnedResponse,
    data_out: *mut *const u8,
    len_out: *mut usize,
) -> i32 {
    ffi_guard(|| {
        // SAFETY: The exported contract supplies a live owner and output slots.
        let result = unsafe { view_response(abi_version, owner, data_out, len_out) };
        result.err().unwrap_or(JoseFfiStatus::Success)
    })
    .code()
}

unsafe fn view_response(
    abi_version: u32,
    owner: *const JoseOwnedResponse,
    data_out: *mut *const u8,
    len_out: *mut usize,
) -> Result<(), JoseFfiStatus> {
    require_abi(abi_version)?;
    validate_scalar_output(owner.cast_mut())?;
    validate_scalar_output(data_out)?;
    let data_slot_size = size_of::<*const u8>();
    validate_operation_ranges(
        owner.cast(),
        size_of::<JoseOwnedResponse>(),
        data_out.cast(),
        data_slot_size,
        len_out,
    )?;

    // SAFETY: The caller keeps the owner live and prevents its release. The
    // slot was checked for overlap with the owner, and must be disjoint from
    // the allocation containing the response bytes.
    let response = unsafe { &*owner };
    validate_operation_ranges(
        response.bytes.as_ptr(),
        response.bytes.capacity(),
        data_out.cast(),
        data_slot_size,
        len_out,
    )?;
    // SAFETY: Both overlap checks passed and the caller supplies live writable
    // storage for both values. Writing does not require initialization.
    let bytes = response.as_bytes();
    unsafe {
        data_out.write(bytes.as_ptr());
        len_out.write(bytes.len());
    }
    Ok(())
}

/// Clears an owner slot, zeroizes the response's backing allocation and frees
/// it through the same Rust allocator. Releasing a null owner succeeds.
///
/// # Safety
///
/// A slot that passes validation must be live, aligned, initialized, and
/// exclusively writable. A non-null slot must hold the unique owner returned
/// by this image. All views must be expired and there must be no concurrent
/// access to the owner. An alias in a different slot must never be released.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rm_jose_owned_response_release_v1(
    abi_version: u32,
    owner_slot: *mut *mut JoseOwnedResponse,
) -> i32 {
    ffi_guard(|| {
        // SAFETY: The exported contract requires a unique owner and live slot.
        let result = unsafe { take_owner(abi_version, owner_slot) };
        result.map_or_else(core::convert::identity, |owner| {
            drop(owner);
            JoseFfiStatus::Success
        })
    })
    .code()
}

unsafe fn take_owner(
    abi_version: u32,
    owner_slot: *mut *mut JoseOwnedResponse,
) -> Result<Option<Box<JoseOwnedResponse>>, JoseFfiStatus> {
    require_abi(abi_version)?;
    validate_scalar_output(owner_slot)?;

    // SAFETY: The caller supplies initialized, exclusive pointer storage.
    let Some(owner) = NonNull::new(unsafe { owner_slot.read() }) else {
        return Ok(None);
    };
    validate_scalar_output(owner.as_ptr())?;
    validate_request_and_slot(
        owner.as_ptr().cast(),
        size_of::<JoseOwnedResponse>(),
        owner_slot,
    )?;
    // SAFETY: The original owner is live and the caller has ended all views.
    let response = unsafe { owner.as_ref() };
    validate_request_and_slot(
        response.bytes.as_ptr(),
        response.bytes.capacity(),
        owner_slot,
    )?;

    // SAFETY: The exclusive slot is disjoint from the owner and its response.
    // Clear it before making the original allocation a Rust owner again.
    unsafe { owner_slot.write(ptr::null_mut()) };
    // SAFETY: Only a unique pointer from Box::into_raw in this image is valid
    // here. The slot no longer holds the pointer and no borrowed view is live.
    Ok(Some(unsafe { Box::from_raw(owner.as_ptr()) }))
}

const fn require_abi(version: u32) -> Result<(), JoseFfiStatus> {
    if version == JOSE_ABI_VERSION {
        Ok(())
    } else {
        Err(JoseFfiStatus::UnsupportedAbi)
    }
}

#[cfg(kani)]
#[path = "owned_response_proofs.rs"]
mod proofs;
