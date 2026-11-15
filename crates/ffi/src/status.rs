// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable transport status values for the JOSE C ABI.

#[path = "generated_contract/jose_ffi_status.rs"]
mod generated;
pub use generated::JoseFfiStatus;

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
