// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::JsonValue;

/// Arbitrary private JWT claims.
///
/// This is a transparent JSON object.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnyClaims(pub BTreeMap<String, JsonValue>);

impl AnyClaims {
    /// Returns a claim value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.0.get(key)
    }

    /// Inserts or replaces a claim value.
    pub fn insert(&mut self, key: String, value: JsonValue) {
        self.0.insert(key, value);
    }
}
