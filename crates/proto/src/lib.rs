// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ReallyMe JOSE protobuf boundary messages with generated Buffa bindings.

/// Generated protobuf boundary.
pub mod generated;

#[cfg(feature = "generated")]
mod secret_json_bytes;

#[cfg(feature = "generated")]
mod guarded_decode;
#[cfg(feature = "generated")]
mod secret_bytes;
#[cfg(feature = "generated")]
mod secret_string;
#[cfg(feature = "generated")]
pub use secret_bytes::SecretBytes;
#[cfg(feature = "generated")]
pub use secret_string::SecretString;
