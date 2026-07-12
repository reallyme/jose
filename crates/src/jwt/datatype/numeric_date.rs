// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// NumericDate as defined by RFC 7519.
///
/// Represents seconds since Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericDate(pub i64);

impl NumericDate {
    /// Creates a NumericDate from seconds since the Unix epoch.
    pub fn new(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Returns seconds since the Unix epoch.
    pub fn as_i64(self) -> i64 {
        self.0
    }
}
