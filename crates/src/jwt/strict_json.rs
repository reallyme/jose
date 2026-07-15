// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer as _};
use serde_json::Value as JsonValue;
use zeroize::Zeroize;

use super::JwtError;

pub(crate) fn reject_duplicate_object_members(bytes: &[u8]) -> Result<(), JwtError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer
        .deserialize_any(DuplicateRejectingJson)
        .map_err(|_| JwtError::InvalidClaims)?;
    deserializer.end().map_err(|_| JwtError::InvalidClaims)
}

struct DuplicateRejectingJson;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct SensitiveString(String);

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
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

impl<'de> DeserializeSeed<'de> for DuplicateRejectingJson {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateRejectingJson {
    type Value = ();

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.zeroize();
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJson)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(DuplicateRejectingJson)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<SensitiveString>()? {
            if !seen.insert(key) {
                return Err(serde::de::Error::custom(JwtError::InvalidClaims));
            }
            map.next_value_seed(DuplicateRejectingJson)?;
        }
        Ok(())
    }
}
