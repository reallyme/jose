// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON Web Signature support.

pub(crate) mod parse_compact;
pub(crate) mod parse_header;
pub(crate) mod sign;
pub(crate) mod sign_p256;
pub mod suites;
pub(crate) mod verify;
pub(crate) mod verify_p256;

pub use parse_compact::MAX_COMPACT_JWS_BYTES;
