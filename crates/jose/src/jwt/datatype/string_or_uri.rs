// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// A string that is either a free string or a URI.
///
/// JWT treats these identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StringOrURI(pub String);

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
