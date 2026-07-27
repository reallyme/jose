// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical JWE semantic execution shared by native and wire adapters.

mod execute;

pub(crate) use execute::{decrypt_jwe, encrypt_jwe};
