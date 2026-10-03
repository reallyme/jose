// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A string that is either a free string or a URI.
///
/// JWT treats these identically.
/// Clones own independent strings, each cleared on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StringOrURI(pub String);

impl core::fmt::Debug for StringOrURI {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StringOrURI(<redacted>)")
    }
}

impl Drop for StringOrURI {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for StringOrURI {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for StringOrURI {
    fn from(s: String) -> Self {
        Self(s)
    }
}
