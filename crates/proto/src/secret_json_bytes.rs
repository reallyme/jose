// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keep partially decoded ProtoJSON bytes wipe-owned when Base64 fails.

use crate::generated::proto::reallyme::jose::v1::JoseErrorReason;
use buffa::Enumeration;

// Serde requires Display; retain the generated reason rather than creating a
// second decoder error vocabulary or carrying parser/backend input text.
struct JsonReason(JoseErrorReason);
impl core::fmt::Display for JsonReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0.proto_name())
    }
}
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::de::{Error, Visitor};
use serde::Deserializer;
use zeroize::Zeroizing;

// Match the pinned protobuf runtime's accepted standard and URL-safe spellings.
const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Bytes;
    impl Visitor<'_> for Bytes {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a base64 string or null")
        }

        fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(Vec::new()))
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            let engine = if value.bytes().any(|byte| byte == b'-' || byte == b'_') {
                &URL_SAFE
            } else {
                &STANDARD
            };
            let mut bytes = Zeroizing::new(Vec::new());
            // Decode into one already-owned allocation. decode_vec can grow an
            // ordinary backing buffer after it has received secret bytes.
            bytes
                .try_reserve_exact(value.len())
                .map_err(|_| E::custom(JsonReason(JoseErrorReason::CommonMalformedJson)))?;
            bytes.resize(value.len(), 0);
            let length = engine
                .decode_slice(value, &mut bytes)
                .map_err(|_| E::custom(JsonReason(JoseErrorReason::CommonMalformedJson)))?;
            bytes.truncate(length);
            Ok(bytes)
        }

        fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
            self.visit_str(&Zeroizing::new(value))
        }
    }
    deserializer.deserialize_any(Bytes)
}

pub(crate) fn serialize<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    let length = base64::encoded_len(bytes.len(), true)
        .ok_or_else(|| S::Error::custom(JsonReason(JoseErrorReason::BackendJsonSerialization)))?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .map_err(|_| S::Error::custom(JsonReason(JoseErrorReason::BackendJsonSerialization)))?;
    output.resize(length, 0);
    let written = STANDARD
        .encode_slice(bytes, &mut output)
        .map_err(|_| S::Error::custom(JsonReason(JoseErrorReason::BackendJsonSerialization)))?;
    let text =
        core::str::from_utf8(output.get(..written).ok_or_else(|| {
            S::Error::custom(JsonReason(JoseErrorReason::BackendJsonSerialization))
        })?)
        .map_err(|_| S::Error::custom(JsonReason(JoseErrorReason::BackendJsonSerialization)))?;
    serializer.serialize_str(text)
}
