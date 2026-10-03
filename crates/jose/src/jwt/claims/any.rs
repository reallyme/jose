// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::jwt::strict_json::zeroize_json_value;
use crate::JsonValue;

/// Arbitrary private JWT claims.
///
/// This is a transparent JSON object.
/// Cloning duplicates claim values. Every owned value is cleared on drop, but
/// callers should keep copies short lived and avoid retaining serialized JSON.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnyClaims(pub BTreeMap<String, JsonValue>);

impl core::fmt::Debug for AnyClaims {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AnyClaims(<redacted>)")
    }
}

impl Drop for AnyClaims {
    fn drop(&mut self) {
        for (mut key, value) in core::mem::take(&mut self.0) {
            key.zeroize();
            zeroize_json_value(value);
        }
    }
}

impl AnyClaims {
    /// Returns a claim value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.0.get(key)
    }

    /// Inserts or replaces a claim value.
    pub fn insert(&mut self, mut key: String, value: JsonValue) {
        if let Some(existing) = self.0.get_mut(&key) {
            key.zeroize();
            zeroize_json_value(core::mem::replace(existing, value));
            return;
        }
        self.0.insert(key, value);
    }
}
