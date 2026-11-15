// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe initialized allocations immediately before release, including spare
//! capacity. The observer never reads freed memory or allocates inside hooks.

#![cfg(feature = "generated")]
#![allow(unsafe_code, missing_docs)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use buffa::{
    bytes::Buf,
    sensitive::{GuardedOwnedView, GuardedViewError},
    DecodeOptions, Message,
};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::jose_operation_request::Operation, JoseJweEncryptRequest, JoseJwsSignRequest,
    JoseJwsSignRequestView, JoseJwtAudience, JoseJwtHeaderEncodeOptions, JoseOperationRequest,
};
use reallyme_jose_proto::{SecretBytes, SecretString};
use zeroize::{Zeroize, Zeroizing};

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
fn strict<M: Message>(mut bytes: impl Buf) -> Result<M, buffa::DecodeError> {
    DecodeOptions::new()
        .reject_unknown_fields()
        .with_max_message_size(1_048_576)
        .decode(&mut bytes)
}

#[test]
fn every_native_lifecycle_releases_only_wiped_storage() -> Result<(), Box<dyn std::error::Error>> {
    // Preserve and wipe spare capacity when an existing allocation is adopted.
    let mut raw = vec![INITIAL_BYTE; 4096];
    raw.truncate(17);
    begin(0, 0);
    watch(raw.as_mut_ptr(), raw.capacity());
    let value = SecretBytes::from(raw);
    let cloned = value.clone();
    assert_ne!(value.as_ptr(), cloned.as_ptr());
    watch(cloned.as_ptr().cast_mut(), cloned.len());
    drop(value);
    assert_eq!(cloned.len(), 17);
    drop(cloned);
    finish(2);

    // Serialization output also needs guarded growth before the first byte.
    // This is independent of the generated fields' cleanup ownership.
    let raw = vec![INITIAL_BYTE; 257];
    let mut output = SecretBytes::from(raw);
    begin(0, 0);
    watch(output.as_ptr().cast_mut(), output.len());
    std::io::Write::write_all(&mut output, &[1; 513])?;
    finish(1);
    begin(0, 0);
    watch(output.as_ptr().cast_mut(), output.len());
    drop(output);
    finish(1);

    // Duplicate strings and byte fields replace earlier guarded allocations.
    let first = JoseJwsSignRequest::default().with_private_key(vec![INITIAL_BYTE; 257]);
    let second = JoseJwsSignRequest::default().with_private_key(vec![INITIAL_BYTE; 513]);
    let wire = [first.encode_to_vec(), second.encode_to_vec()].concat();
    begin(257, 513);
    let decoded: JoseJwsSignRequest = strict(wire.as_slice())?;
    assert_eq!(decoded.private_key.len(), 513);
    drop(decoded);
    finish(2);

    // Fragmented bytes need exactly one payload allocation across length
    // prefix boundaries. A default WirePayload scratch copy would fail this.
    for length in [127, 128, 16_383, 16_384] {
        let fixture = JoseJwsSignRequest::default().with_private_key(vec![INITIAL_BYTE; length]);
        let wire = Zeroizing::new(fixture.encode_to_vec());
        let (left, right) = wire
            .split_at_checked(
                wire.len()
                    .checked_sub(17)
                    .ok_or(buffa::DecodeError::MessageTooLarge)?,
            )
            .ok_or(buffa::DecodeError::MessageTooLarge)?;
        begin(length, 0);
        let decoded: JoseJwsSignRequest = strict(left.chain(right))?;
        assert_eq!(decoded.private_key.len(), length);
        drop(decoded);
        finish(1);
    }

    // Noncontiguous valid/invalid UTF-8 must never use an unguarded scratch copy.
    let valid = JoseJwtHeaderEncodeOptions::default().with_typ("x".repeat(257));
    let mut invalid = vec![0x0a, 0x83, 0x02];
    invalid.extend(vec![0xff; 259]);
    let wire = [valid.encode_to_vec(), invalid].concat();
    let split = wire
        .len()
        .checked_sub(129)
        .ok_or(buffa::DecodeError::MessageTooLarge)?;
    begin(257, 259);
    assert!(strict::<JoseJwtHeaderEncodeOptions>(
        wire.get(..split)
            .ok_or(buffa::DecodeError::MessageTooLarge)?
            .chain(
                wire.get(split..)
                    .ok_or(buffa::DecodeError::MessageTooLarge)?
            )
    )
    .is_err());
    finish(2);

    // JSON failure after a decoded field drops both its early message owner
    // and the Base64 policy's partially written destination.
    let json = format!(
        r#"{{"kid":"{}","apu":"{}!!!!"}}"#,
        "k".repeat(257),
        "QUJD".repeat(129)
    );
    begin(257, 520);
    assert!(serde_json::from_str::<JoseJweEncryptRequest>(&json).is_err());
    finish(2);

    // Oneof replacement wipes the departing child, not just its discriminator.
    let request = JoseJwsSignRequest::default().with_payload(vec![INITIAL_BYTE; 257]);
    begin(0, 0);
    watch(request.payload.as_ptr().cast_mut(), request.payload.len());
    let outer =
        JoseOperationRequest::default().with_operation(Operation::JwsSign(Box::new(request)));
    drop(outer.with_operation(Operation::ContractInfo(Box::default())));
    finish(1);

    // Guarded numeric storage wipes both outgrown buffers and spare capacity.
    let mut numbers = buffa::sensitive::List::from(vec![u64::MAX; 4]);
    let bytes = numbers
        .capacity()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(buffa::DecodeError::MessageTooLarge)?;
    begin(0, 0);
    watch(numbers.as_ptr().cast::<u8>().cast_mut(), bytes);
    numbers.push(42);
    finish(1);
    begin(0, 0);
    watch(
        numbers.as_ptr().cast::<u8>().cast_mut(),
        numbers
            .capacity()
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(buffa::DecodeError::MessageTooLarge)?,
    );
    drop(numbers);
    finish(1);

    // Partial repeated JSON elements are inserted directly into wipe owners.
    let json = format!(r#"{{"values":["{}",1]}}"#, "s".repeat(257));
    begin(257, 0);
    assert!(serde_json::from_str::<JoseJwtAudience>(&json).is_err());
    finish(1);

    // Direct encoding uses one private backing allocation, wiped on drop.
    let request = JoseJwsSignRequest::default().with_payload(vec![INITIAL_BYTE; 257]);
    let view_options = DecodeOptions::new()
        .reject_unknown_fields()
        .with_max_message_size(1024);
    let wire = Zeroizing::new(request.encode_to_vec());
    let length = wire.len();
    begin(length, 0);
    let view =
        GuardedOwnedView::<JoseJwsSignRequestView<'static>>::from_owned(&request, &view_options)?;
    assert_eq!(view.view().payload.len(), 257);
    assert_eq!(view.bytes(), wire.as_slice());
    drop(view);
    finish(1);

    // A rejected eager view releases its guarded copy after decoding fails.
    // Field 4 is unknown to JoseJwsSignRequest and follows the valid payload.
    let invalid = Zeroizing::new([wire.as_slice(), &[0x20, 1]].concat());
    begin(invalid.len(), 0);
    assert!(matches!(
        GuardedOwnedView::<JoseJwsSignRequestView<'static>>::decode(&invalid, &view_options),
        Err(GuardedViewError::Decode(
            buffa::DecodeError::UnknownFieldLimitExceeded
        ))
    ));
    finish(1);
    assert!(matches!(
        GuardedOwnedView::<JoseJwsSignRequestView<'static>>::decode(
            &wire,
            &DecodeOptions::new().with_max_message_size(1)
        ),
        Err(GuardedViewError::SizeLimit)
    ));

    // Failed merges wipe both storage already present and fields applied
    // before a later UTF-8 error. The encoded input remains caller-owned.
    let mut destination = JoseJweEncryptRequest::default().with_apu(vec![INITIAL_BYTE; 257]);
    let prefix = JoseJweEncryptRequest::default().with_plaintext(vec![INITIAL_BYTE; 513]);
    let mut invalid_merge = SecretBytes::from(prefix.encode_to_vec());
    std::io::Write::write_all(&mut invalid_merge, &[0x2a, 1, 0xff])?;
    begin(513, 0);
    watch(
        destination
            .apu
            .as_ref()
            .ok_or(buffa::DecodeError::InvalidUtf8)?
            .as_ptr()
            .cast_mut(),
        257,
    );
    let merge_options = DecodeOptions::new()
        .reject_unknown_fields()
        .clear_on_merge_error();
    assert!(matches!(
        merge_options.merge_from_slice(&mut destination, &invalid_merge),
        Err(buffa::DecodeError::InvalidUtf8)
    ));
    assert!(destination.apu.is_none());
    assert!(destination.plaintext.is_empty());
    finish(2);

    // Explicit clearing wipes numeric/optional presence and guarded storage.
    let mut text = SecretString::from("identifying".to_owned());
    text.zeroize();
    assert!(text.is_empty());
    Ok(())
}
