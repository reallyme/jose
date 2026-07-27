// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Panic firewall and thread-scoped panic-output redaction.

use std::cell::Cell;
use std::sync::Once;

use crate::status::JoseFfiStatus;

thread_local! {
    static INSIDE_JOSE_BOUNDARY: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_REDACTING_HOOK: Once = Once::new();

struct NativeBoundaryScope {
    previous: bool,
}

impl NativeBoundaryScope {
    fn enter() -> Self {
        let previous = INSIDE_JOSE_BOUNDARY.replace(true);
        Self { previous }
    }
}

impl Drop for NativeBoundaryScope {
    fn drop(&mut self) {
        INSIDE_JOSE_BOUNDARY.set(self.previous);
    }
}

fn inside_native_boundary() -> bool {
    matches!(INSIDE_JOSE_BOUNDARY.try_with(Cell::get), Ok(true))
}

fn install_redacting_panic_hook() {
    INSTALL_REDACTING_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            if !inside_native_boundary() {
                previous(panic_info);
            }
        }));
    });
}

/// Runs an operation while suppressing panic-hook output only on the current
/// thread and only for the active JOSE boundary scope.
pub fn with_redacted_panic_hook<F, T>(operation: F) -> T
where
    F: FnOnce() -> T,
{
    install_redacting_panic_hook();
    let _scope = NativeBoundaryScope::enter();
    operation()
}

/// Converts an unwind into the stable panic status without exposing its
/// payload, source path, or backend text.
#[inline]
pub fn catch_boundary_unwind<F, T>(operation: F) -> Result<T, JoseFfiStatus>
where
    F: FnOnce() -> T,
{
    // Catch before installing the process hook or entering thread-local scope.
    // Those operations are intentionally simple, but they are still part of
    // the native boundary and must not be allowed to unwind across an extern
    // frame if a future implementation changes their behavior.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_redacted_panic_hook(operation)
    })) {
        Ok(value) => Ok(value),
        Err(_payload) => Err(JoseFfiStatus::PanicCaught),
    }
}

/// Runs a C ABI operation behind the complete panic firewall.
#[inline]
pub fn ffi_guard<F>(operation: F) -> JoseFfiStatus
where
    F: FnOnce() -> JoseFfiStatus,
{
    match catch_boundary_unwind(operation) {
        Ok(status) => status,
        Err(status) => status,
    }
}
