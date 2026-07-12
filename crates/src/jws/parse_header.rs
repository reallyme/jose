// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsAlgorithm {
    Es256,
    Eddsa,
}

impl JwsAlgorithm {
    pub(crate) fn protected_header_json(self) -> &'static [u8] {
        match self {
            JwsAlgorithm::Es256 => br#"{"alg":"ES256"}"#,
            JwsAlgorithm::Eddsa => br#"{"alg":"EdDSA"}"#,
        }
    }

    fn parse(input: &str) -> Result<Self, JwsHeaderError> {
        match input {
            "ES256" => Ok(Self::Es256),
            "EdDSA" => Ok(Self::Eddsa),
            _ => Err(JwsHeaderError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JwsProtectedHeader {
    pub(crate) alg: JwsAlgorithm,
}

impl<'de> Deserialize<'de> for JwsProtectedHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(JwsProtectedHeaderVisitor)
    }
}

struct JwsProtectedHeaderVisitor;

impl<'de> Visitor<'de> for JwsProtectedHeaderVisitor {
    type Value = JwsProtectedHeader;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a compact JWS protected header object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        let mut alg = None;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(JwsHeaderError::Invalid));
            }

            match key.as_str() {
                "alg" => alg = Some(map.next_value::<String>()?),
                "typ" | "cty" | "kid" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
                "b64" | "crit" | "zip" | "jku" | "x5u" | "x5c" | "jwk" => {
                    let _ = map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::custom(JwsHeaderError::Invalid));
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let alg = alg.ok_or_else(|| serde::de::Error::custom(JwsHeaderError::Invalid))?;

        Ok(JwsProtectedHeader {
            alg: JwsAlgorithm::parse(&alg).map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JwsHeaderError {
    Invalid,
}

impl Display for JwsHeaderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("invalid JWS protected header"),
        }
    }
}
