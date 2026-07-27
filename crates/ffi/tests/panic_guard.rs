// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Panic-firewall tests isolated from production modules.

#![allow(clippy::panic)]

use reallyme_jose_ffi::guard::{ffi_guard, with_redacted_panic_hook};
use reallyme_jose_ffi::status::JoseFfiStatus;

extern "C" fn deliberate_panic_boundary() -> i32 {
    ffi_guard(|| panic!("test-only extern boundary panic")).code()
}

#[test]
fn panic_payload_is_caught_and_mapped_without_escape() {
    let status = ffi_guard(|| panic!("test-only sensitive panic payload"));
    assert_eq!(status, JoseFfiStatus::PanicCaught);
}

#[test]
fn extern_boundary_maps_deliberate_panic_to_stable_status() {
    assert_eq!(
        deliberate_panic_boundary(),
        JoseFfiStatus::PanicCaught.code()
    );
}

#[test]
fn nested_redaction_scope_restores_normal_execution() {
    let status = with_redacted_panic_hook(|| with_redacted_panic_hook(|| JoseFfiStatus::Success));
    assert_eq!(status, JoseFfiStatus::Success);
    assert_eq!(ffi_guard(|| JoseFfiStatus::Success), JoseFfiStatus::Success);
}
