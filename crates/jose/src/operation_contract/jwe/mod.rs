// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical JWE semantic execution shared by native and wire adapters.

mod execute;

pub(crate) use execute::{decrypt_jwe, encrypt_jwe};
