// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Operation-specific semantic execution shared by native and wire adapters.

pub(crate) mod jwe;
pub(crate) mod jws;
pub(crate) mod jwt;
#[cfg(feature = "wire")]
pub(crate) mod protobuf;
