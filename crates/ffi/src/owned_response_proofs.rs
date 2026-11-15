// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;
use core::ptr;

use zeroize::Zeroizing;

use super::{execute_into_slot, take_owner, view_response, JoseFfiStatus, JOSE_ABI_VERSION};

const CAPACITY: usize = 4;

#[kani::proof]
#[kani::unwind(7)]
fn the_destructor_wipe_clears_initialized_and_spare_response_bytes() {
    let response = kani::any::<[u8; CAPACITY]>();
    let response_len = kani::any::<usize>();
    kani::assume(response_len > 0 && response_len <= CAPACITY);
    let mut bytes = vec![0; CAPACITY];
    bytes.copy_from_slice(&response);
    bytes.truncate(response_len);
    let original = bytes.as_ptr();

    // Keep the destructor's intermediate state observable after wiping.
    // The lifecycle harness separately runs the full ordinary destruction.
    let mut owner = ManuallyDrop::new(super::JoseOwnedResponse { bytes });
    owner.wipe_bytes();

    kani::assert(
        owner.bytes.as_ptr() == original,
        "wiping uses the original allocation",
    );
    kani::assert(
        owner.bytes.len() == 0 && owner.bytes.capacity() == CAPACITY,
        "the complete allocation is still live after wiping",
    );
    for byte in owner.bytes.spare_capacity_mut() {
        // SAFETY: The harness initialized the full allocation before shortening
        // the vector. Vec::zeroize also initializes every spare byte.
        kani::assert(
            unsafe { *byte.assume_init_ref() } == 0,
            "every initialized and spare byte is zero before deallocation",
        );
    }
    kani::cover!(response_len < CAPACITY, "the response has spare capacity");
    kani::cover!(
        response_len == CAPACITY,
        "the response fills the allocation"
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn single_execution_transfers_one_owner_that_release_consumes() {
    let request = kani::any::<[u8; 1]>();
    let response = kani::any::<[u8; 1]>();
    let executions = Cell::new(false);
    let mut original = ptr::null();
    let mut slot = ptr::null_mut();

    // SAFETY: The request and zero-initialized slot are live and disjoint.
    let result = unsafe {
        execute_into_slot(
            JOSE_ABI_VERSION,
            request.as_ptr(),
            request.len(),
            &mut slot,
            request.len(),
            |input, _| {
                kani::assert(!executions.replace(true), "operation is executed once");
                kani::assert(input == request, "executor receives the original request");
                let buffer = Vec::from(response);
                original = buffer.as_ptr();
                Zeroizing::new(buffer)
            },
        )
    };
    kani::assert(
        result.is_ok() && executions.get() && !slot.is_null(),
        "one owner is published",
    );

    let mut data = ptr::null();
    let mut len = 0;
    // SAFETY: The live owner is kept until after the output view goes out of use.
    let view = unsafe { view_response(JOSE_ABI_VERSION, slot, &mut data, &mut len) };
    kani::assert(
        view.is_ok() && len == response.len(),
        "view reports the exact length",
    );
    kani::assert(data == original, "view borrows the original allocation");
    // SAFETY: The successful view points to the initialized prefix of the live owner.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    kani::assert(bytes == response, "view preserves the response bytes");

    // SAFETY: The view is no longer used. This is the unique initialized slot.
    let owner = unsafe { take_owner(JOSE_ABI_VERSION, &mut slot) };
    kani::assert(
        matches!(owner, Ok(Some(_))),
        "release alone recovers the Rust owner",
    );
    kani::assert(
        slot.is_null(),
        "the caller slot is cleared before destruction",
    );
    let preserved = owner.as_ref().ok().and_then(Option::as_ref);
    kani::assert(
        preserved.is_some_and(|value| value.bytes.as_ptr() == original),
        "release recovers the original allocation",
    );
    drop(owner);

    // SAFETY: The same initialized slot is now empty.
    let repeated = unsafe { take_owner(JOSE_ABI_VERSION, &mut slot) };
    kani::assert(
        matches!(repeated, Ok(None)),
        "a cleared slot cannot recover an allocation again",
    );
    kani::cover!(
        result.is_ok() && view.is_ok() && slot.is_null(),
        "complete transfer lifecycle"
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn a_rejected_execution_never_publishes_or_overwrites_an_owner() {
    let choice = kani::any::<u8>();
    kani::assume(choice <= 5);
    let request = [0x9d];
    let mut occupied = super::JoseOwnedResponse { bytes: Vec::new() };
    let original = if choice == 0 {
        &raw mut occupied
    } else {
        ptr::null_mut()
    };
    let mut slot = original;
    let version = if choice == 1 { 0 } else { JOSE_ABI_VERSION };
    let (input, len) = match choice {
        2 => ((&raw const slot).cast(), 1),
        3 => (ptr::null(), 1),
        _ => (request.as_ptr(), request.len()),
    };
    let output = if choice == 4 {
        ptr::null_mut()
    } else {
        &raw mut slot
    };
    let executed = Cell::new(false);

    // SAFETY: All storage is live. Invalid null and alias cases certify
    // rejection before the overlapping storage can be borrowed or modified.
    let result = unsafe {
        execute_into_slot(version, input, len, output, request.len(), |_, _| {
            executed.set(true);
            Zeroizing::new(Vec::new())
        })
    };
    let expected = match choice {
        1 => JoseFfiStatus::UnsupportedAbi,
        5 => JoseFfiStatus::BackendError,
        _ => JoseFfiStatus::CallerError,
    };
    kani::assert(
        result == Err(expected),
        "failure returns its stable transport status",
    );
    kani::assert(
        slot == original,
        "failure preserves the original slot value",
    );
    kani::assert(
        executed.get() == (choice == 5),
        "only valid metadata reaches the executor",
    );
    kani::cover!(choice == 0, "occupied slot rejected");
    kani::cover!(choice == 1, "unsupported ABI rejected");
    kani::cover!(choice == 2, "overlapping request and owner slot rejected");
    kani::cover!(choice == 3, "null nonempty request rejected");
    kani::cover!(choice == 4, "null output slot rejected");
    kani::cover!(
        choice == 5,
        "empty execution output rejected before transfer"
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn rejected_views_and_releases_preserve_the_outputs_and_live_owner() {
    let choice = kani::any::<u8>();
    kani::assume(choice < 7);
    let mut slot = ptr::null_mut();
    let request = [0x9d];
    // SAFETY: The execution receives a valid request and disjoint owner slot.
    let result = unsafe {
        execute_into_slot(
            JOSE_ABI_VERSION,
            request.as_ptr(),
            request.len(),
            &mut slot,
            request.len(),
            |_, _| Zeroizing::new(vec![0xa5]),
        )
    };
    kani::assert(result.is_ok(), "a response owner is live");
    let owner = slot;
    let mut data = request.as_ptr();
    let mut len = usize::MAX;
    let data_out = &raw mut data;
    let len_out = &raw mut len;
    let version = if choice == 0 || choice == 5 {
        0
    } else {
        JOSE_ABI_VERSION
    };
    let view_status = match choice {
        // SAFETY: Each invalid case uses the real metadata gate. The live
        // outputs may be written only after the gates have all succeeded.
        0..=4 => unsafe {
            view_response(
                version,
                if choice == 1 { ptr::null() } else { owner },
                match choice {
                    2 => ptr::null_mut(),
                    3 => owner.cast(),
                    _ => data_out,
                },
                if choice == 4 {
                    data_out.cast()
                } else {
                    len_out
                },
            )
        },
        _ => Ok(()),
    };
    if choice < 5 {
        let expected = if choice == 0 {
            JoseFfiStatus::UnsupportedAbi
        } else {
            JoseFfiStatus::CallerError
        };
        kani::assert(
            view_status == Err(expected),
            "invalid view returns its transport status",
        );
        kani::assert(
            data == request.as_ptr() && len == usize::MAX,
            "view outputs remain unchanged",
        );
    } else {
        let (release_slot, expected) = if choice == 5 {
            (&raw mut slot, JoseFfiStatus::UnsupportedAbi)
        } else {
            (ptr::null_mut(), JoseFfiStatus::CallerError)
        };
        // SAFETY: The supplied slot is either a live unique slot or null.
        let cleanup = unsafe { take_owner(version, release_slot) };
        kani::assert(
            matches!(cleanup, Err(error) if error == expected),
            "invalid release returns its transport status",
        );
        kani::assert(slot == owner, "rejected release preserves the live owner");
    }
    // SAFETY: The original slot is exclusive and no view was published.
    let cleanup = unsafe { take_owner(JOSE_ABI_VERSION, &mut slot) };
    kani::assert(
        matches!(cleanup, Ok(Some(_))),
        "valid release can still recover the owner",
    );
    drop(cleanup);
    kani::cover!(choice == 0, "view rejects unsupported ABI");
    kani::cover!(choice == 1, "view rejects null owner");
    kani::cover!(choice == 2, "view rejects null output slot");
    kani::cover!(choice == 3, "view rejects overlap with owner");
    kani::cover!(choice == 4, "view rejects overlapping output slots");
    kani::cover!(choice == 5, "release rejects unsupported ABI");
    kani::cover!(choice == 6, "release rejects null slot");
}
