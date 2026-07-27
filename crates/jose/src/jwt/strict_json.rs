// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value as JsonValue;
use zeroize::Zeroize;

use super::JwtError;
use crate::reject_duplicate_json_members::reject_duplicate_json_members as reject_duplicates;

pub(crate) fn reject_duplicate_object_members(bytes: &[u8]) -> Result<(), JwtError> {
    reject_duplicates(bytes).map_err(|_| JwtError::InvalidClaims)
}

pub(crate) struct SensitiveJsonValue(JsonValue);

impl core::ops::Deref for SensitiveJsonValue {
    type Target = JsonValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(self.0.take());
    }
}

pub(crate) fn parse_sensitive_json(bytes: &[u8]) -> Result<SensitiveJsonValue, JwtError> {
    serde_json::from_slice(bytes)
        .map(SensitiveJsonValue)
        .map_err(|_| JwtError::Serialization)
}

fn zeroize_json_value(value: JsonValue) {
    match value {
        JsonValue::String(mut value) => value.zeroize(),
        JsonValue::Array(values) => values.into_iter().for_each(zeroize_json_value),
        JsonValue::Object(values) => values.into_iter().for_each(|(mut key, value)| {
            key.zeroize();
            zeroize_json_value(value);
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}
