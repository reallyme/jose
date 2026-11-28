// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe initialized live allocations before deallocation, never freed memory.
//! One test owns the observer; allocator callbacks neither allocate nor log.

#![allow(unsafe_code, missing_docs)]

use reallyme_jose::api::contract::{
    JoseJwsTransportCharacterPolicy, JoseJwsTransportComposeBudgets,
    JoseJwsTransportComposeRequest, JoseJwsTransportMemberPolicy, JoseJwsTransportPolicy,
};
use reallyme_jose::jws::transport::{
    compose_compact_jws_unauthenticated as compose, ComposeCompactJwsRequest,
    JwsTransportErrorReason,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

const SLOTS: usize = 64;
const INITIAL_BYTE: u8 = 0xa5;
struct Watch {
    pointer: AtomicPtr<u8>,
    length: AtomicUsize,
}
static WATCHES: [Watch; SLOTS] = [const {
    Watch {
        pointer: AtomicPtr::new(core::ptr::null_mut()),
        length: AtomicUsize::new(0),
    }
}; SLOTS];
static FAIL_SIZE: AtomicUsize = AtomicUsize::new(0);
static SIZE: AtomicUsize = AtomicUsize::new(0);
static SIZE_TWO: AtomicUsize = AtomicUsize::new(0);
static OBSERVED: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);
static OVERFLOW: AtomicBool = AtomicBool::new(false);
thread_local! { static ACTIVE: Cell<bool> = const { Cell::new(false) }; }

fn watch(pointer: *mut u8, length: usize) {
    for slot in &WATCHES {
        if slot.pointer.load(Ordering::SeqCst).is_null() {
            slot.length.store(length, Ordering::SeqCst);
            slot.pointer.store(pointer, Ordering::SeqCst);
            OBSERVED.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }
    OVERFLOW.store(true, Ordering::SeqCst);
}
struct ObservedAllocator;
// SAFETY: each operation delegates to System with the original layout and
// ownership. Observations happen only while the allocation remains live.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.try_with(Cell::get).unwrap_or(false)
            && FAIL_SIZE.load(Ordering::SeqCst) == layout.size()
        {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller supplies GlobalAlloc's valid nonzero layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            // SAFETY: the new allocation owns layout.size() writable bytes.
            // Initializing spare capacity makes later byte observations valid.
            unsafe { pointer.write_bytes(INITIAL_BYTE, layout.size()) };
            if ACTIVE.try_with(Cell::get).unwrap_or(false)
                && (layout.size() == SIZE.load(Ordering::SeqCst)
                    || layout.size() == SIZE_TWO.load(Ordering::SeqCst))
            {
                watch(pointer, layout.size());
            }
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        for slot in &WATCHES {
            if slot.pointer.load(Ordering::SeqCst) == pointer {
                let length = slot.length.load(Ordering::SeqCst);
                if length > layout.size() {
                    OVERFLOW.store(true, Ordering::SeqCst);
                }
                for offset in 0..length.min(layout.size()) {
                    // SAFETY: registered bytes were initialized and the caller
                    // still owns this allocation until System.dealloc below.
                    if unsafe { pointer.add(offset).read_volatile() } != 0 {
                        DIRTY.store(true, Ordering::SeqCst);
                    }
                }
                slot.pointer.store(core::ptr::null_mut(), Ordering::SeqCst);
                RELEASED.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: pointer/layout retain the original allocator contract.
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn begin(first: usize, second: usize) {
    assert!(WATCHES
        .iter()
        .all(|slot| slot.pointer.load(Ordering::SeqCst).is_null()));
    OBSERVED.store(0, Ordering::SeqCst);
    RELEASED.store(0, Ordering::SeqCst);
    DIRTY.store(false, Ordering::SeqCst);
    OVERFLOW.store(false, Ordering::SeqCst);
    SIZE.store(first, Ordering::SeqCst);
    SIZE_TWO.store(second, Ordering::SeqCst);
    ACTIVE.with(|value| value.set(true));
}
fn finish(expected: usize) {
    ACTIVE.with(|value| value.set(false));
    assert!(
        !DIRTY.load(Ordering::SeqCst),
        "secret allocation released without complete wiping"
    );
    assert!(
        !OVERFLOW.load(Ordering::SeqCst),
        "invalid allocation observation"
    );
    assert_eq!(OBSERVED.load(Ordering::SeqCst), expected);
    assert_eq!(RELEASED.load(Ordering::SeqCst), expected);
}
#[test]
fn transport_success_failure_and_partial_json_drop_wipe_owned_storage(
) -> Result<(), JwsTransportErrorReason> {
    let member = JoseJwsTransportMemberPolicy::default()
        .with_characters(JoseJwsTransportCharacterPolicy::OpaqueUtf8);
    let policy = JoseJwsTransportPolicy::default()
        .with_protected_header(member.clone())
        .with_payload(member.clone())
        .with_signature(member);
    let budgets = JoseJwsTransportComposeBudgets::default()
        .with_max_input_bytes(259)
        .with_max_output_bytes(261);
    let header = "h".repeat(257);
    let request = ComposeCompactJwsRequest {
        protected_header: &header,
        payload: "p",
        signature: "s",
        policy: &policy,
        budgets: &budgets,
    };

    begin(261, 0);
    let output = compose(&request)?;
    assert_eq!(output.as_str().len(), 261);
    drop(output);
    finish(1);

    begin(261, 0);
    let output = compose(&request)?.into_zeroizing();
    drop(output);
    finish(1);

    // Admission fails before the first output allocation or copied byte.
    let insufficient = JoseJwsTransportComposeBudgets::default()
        .with_max_input_bytes(258)
        .with_max_output_bytes(261);
    begin(261, 0);
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            budgets: &insufficient,
            ..request
        })
        .err(),
        Some(JwsTransportErrorReason::InputTooLarge)
    );
    finish(0);

    // Inject failure at the fallible output reservation, not at a Rust abort
    // path. The empty guarded owner is dropped and no member has been copied.
    begin(261, 0);
    FAIL_SIZE.store(261, Ordering::SeqCst);
    let failed = compose(&request);
    FAIL_SIZE.store(0, Ordering::SeqCst);
    assert_eq!(failed.err(), Some(JwsTransportErrorReason::Allocation));
    finish(0);

    // A later invalid JSON field must drop the already allocated first member.
    let invalid = format!(r#"{{"protectedHeader":"{}","payload":42}}"#, header);
    begin(257, 0);
    assert!(serde_json::from_str::<JoseJwsTransportComposeRequest>(&invalid).is_err());
    finish(1);

    let owned = JoseJwsTransportComposeRequest::default().with_protected_header(header);
    begin(0, 0);
    if let Some(header) = owned.protected_header.as_ref() {
        watch(header.as_bytes().as_ptr().cast_mut(), header.len());
    }
    drop(owned);
    finish(1);
    Ok(())
}
