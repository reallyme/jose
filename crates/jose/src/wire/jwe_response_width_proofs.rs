// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references the string sizing replacement through a stub attribute.
#![allow(dead_code)]

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};

use buffa::Message;

use super::{jwe_encrypt_response, max_response_bytes, JoseCompactResult};
use crate::jwe::MAX_COMPACT_JWE_BYTES;

// The stub and harness share one symbolic width for the same string field.
// There are no concurrent operations in this harness.
static COMPACT_WIDTH: AtomicU32 = AtomicU32::new(0);

fn compact_string_wire_size(value: &str) -> usize {
    // This harness gives the generated envelope a one-byte stand-in for
    // the ciphertext. Model only the length-dependent string field and
    // let the real generated code size every enclosing message.
    let length = COMPACT_WIDTH.load(Ordering::Relaxed);
    kani::assert(
        value == "x" || value == "_",
        "only the nonempty compact field is abstracted",
    );
    let Ok(width) = usize::try_from(length) else {
        kani::assert(false, "the selected compact width fits usize");
        return 0;
    };
    let Some(size) = width.checked_add(buffa::encoding::varint_len(u64::from(length))) else {
        kani::assert(false, "the compact and its prefix fit usize");
        return 0;
    };
    size
}

#[kani::proof]
#[kani::unwind(5)]
#[kani::stub(buffa::types::string_encoded_len, compact_string_wire_size)]
fn successful_jwe_response_size_depends_only_on_compact_width() {
    let compact_len = kani::any_where(|len: &u32| {
        *len != 0 && usize::try_from(*len).is_ok_and(|len| len <= MAX_COMPACT_JWE_BYTES)
    });
    COMPACT_WIDTH.store(compact_len, Ordering::Relaxed);
    let compact = JoseCompactResult {
        compact: String::from(if kani::any::<bool>() { "x" } else { "_" }),
        __buffa_unknown_fields: Default::default(),
    };
    let response = ManuallyDrop::new(jwe_encrypt_response(Ok(compact)));
    let size = response.compute_size(&mut buffa::SizeCache::new());
    let Ok(size) = usize::try_from(size) else {
        kani::assert(false, "the generated response size fits usize");
        return;
    };
    let Ok(cap) = max_response_bytes() else {
        kani::assert(false, "the configured response cap is representable");
        return;
    };

    // The contract version uses two bytes, followed by three nested
    // length-delimited fields. Compute an independent size from the schema.
    let expected = length_delimited_size(u64::from(compact_len), 1)
        .and_then(|size| length_delimited_size(size, 1))
        .and_then(|size| length_delimited_size(size, 3))
        .and_then(|size| size.checked_add(2));
    kani::assert(
        u64::try_from(size).ok() == expected,
        "response size is a function of compact width alone",
    );

    kani::assert(
        size <= cap,
        "successful JWE stays below the wire and FFI limits",
    );
    kani::cover!(size < 128, "small compact response");
    kani::cover!(
        (128..16_384).contains(&size),
        "intermediate compact response"
    );
    kani::cover!(
        size > MAX_COMPACT_JWE_BYTES,
        "maximum-sized compact response uses framing overhead"
    );
}

fn length_delimited_size(payload: u64, tag_width: u64) -> Option<u64> {
    let prefix = if payload < 128 {
        1
    } else if payload < 16_384 {
        2
    } else {
        3
    };
    payload.checked_add(prefix)?.checked_add(tag_width)
}
