// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// NumericDate as defined by RFC 7519.
///
/// Represents seconds since Unix epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericDate(pub i64);

impl NumericDate {
    /// Creates a NumericDate from seconds since the Unix epoch.
    #[must_use]
    pub const fn new(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn as_i64(&self) -> i64 {
        self.0
    }
}

impl core::fmt::Debug for NumericDate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NumericDate(<redacted>)")
    }
}
