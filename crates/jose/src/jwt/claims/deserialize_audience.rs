// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::super::datatype::StringOrURI;

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceWire {
    Single(StringOrURI),
    Multiple(Vec<StringOrURI>),
}

pub(super) fn deserialize_audience<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<StringOrURI>>, D::Error>
where
    D: Deserializer<'de>,
{
    let wire = Option::<AudienceWire>::deserialize(deserializer)?;
    Ok(match wire {
        Some(AudienceWire::Single(audience)) => Some(vec![audience]),
        Some(AudienceWire::Multiple(audiences)) => Some(audiences),
        None => None,
    })
}

pub(super) fn serialize_audience<S>(
    audiences: &Option<Vec<StringOrURI>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match audiences.as_deref() {
        Some([audience]) => audience.serialize(serializer),
        Some(audiences) => audiences.serialize(serializer),
        None => serializer.serialize_none(),
    }
}
