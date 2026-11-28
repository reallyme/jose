// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unauthenticated, byte-preserving JWS transport mechanics.
//!
//! These operations do not decode members, inspect JOSE headers, verify
//! signatures or issue authentication receipts. Application admission remains
//! caller-selected, independently of the strict signing and verification APIs.

mod admit;
mod compose;
mod error;
pub(crate) mod execute;
mod frame;
pub(crate) mod map_reason;

pub use compose::{
    compose_compact_jws_unauthenticated, ComposeCompactJwsRequest, UnauthenticatedCompactJws,
};
pub use error::JwsTransportErrorReason;
pub use frame::{
    frame_compact_jws_unauthenticated, FrameCompactJwsRequest, UnauthenticatedCompactJwsView,
};

#[cfg(test)]
mod tests;
