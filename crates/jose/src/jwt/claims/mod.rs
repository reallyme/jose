// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod deserialize_audience;

/// Arbitrary private claim map support.
pub mod any;
/// Registered RFC 7519 claim support.
pub mod registered;

pub use any::AnyClaims;
pub use registered::RegisteredClaims;
