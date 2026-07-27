// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Versioned native C ABI for the canonical JOSE operation contract.
//!
//! The ABI accepts binary protobuf or generated ProtoJSON requests and always
//! returns the canonical binary V1 response. Operation failures remain inside
//! the generated response; C status codes describe only ABI transport state.

#![cfg(not(target_arch = "wasm32"))]
// Raw pointers exist only in the reviewed boundary modules. Each dereference
// is preceded by the shared validation helpers and a local `SAFETY:` proof.
#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

// A panic firewall is ineffective under panic=abort. Native artifact builders
// select the workspace's release-ffi profile, and this check rejects any
// incorrectly configured build.
#[cfg(not(panic = "unwind"))]
compile_error!("reallyme-jose-ffi must be compiled with panic=unwind");

/// Panic containment shared by every non-leaf exported function.
pub mod guard;
/// JNI adapter for the typed Kotlin/JVM facade.
pub mod kotlin;
/// Canonical operation-contract exports.
pub mod operation;
/// Shared raw-pointer and alias validation.
pub mod pointer;
/// Stable C ABI status values.
pub mod status;

pub use operation::{
    rm_jose_abi_version, rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1,
    rm_jose_max_json_request_bytes, rm_jose_max_request_bytes, rm_jose_max_response_bytes,
    rm_jose_zeroize_buffer, JOSE_ABI_VERSION,
};
