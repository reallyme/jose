// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JSON Web Signature support.

pub(crate) mod parse_compact;
pub(crate) mod parse_header;
pub(crate) mod sign;
pub mod suites;
pub(crate) mod verify;

pub use parse_compact::MAX_COMPACT_JWS_BYTES;
