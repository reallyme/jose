// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Error, ErrorKind, Write};

use serde::ser::{Serialize, SerializeMap, Serializer};
use zeroize::Zeroizing;

use super::{JwkThumbprintErrorReason, JwkThumbprintMembers, MAX_JWK_THUMBPRINT_MEMBER_BYTES};

pub(super) fn encode(
    members: &JwkThumbprintMembers<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwkThumbprintErrorReason> {
    match members {
        JwkThumbprintMembers::Ec { crv, x, y } => {
            encode_fields(&[("crv", crv), ("kty", "EC"), ("x", x), ("y", y)])
        }
        JwkThumbprintMembers::Okp { crv, x } => {
            encode_fields(&[("crv", crv), ("kty", "OKP"), ("x", x)])
        }
        JwkThumbprintMembers::Rsa { e, n } => encode_fields(&[("e", e), ("kty", "RSA"), ("n", n)]),
        JwkThumbprintMembers::Oct { k } => encode_fields(&[("k", k), ("kty", "oct")]),
    }
}

fn encode_fields(fields: &[(&str, &str)]) -> Result<Zeroizing<Vec<u8>>, JwkThumbprintErrorReason> {
    for (_, value) in fields {
        if value.is_empty() {
            return Err(JwkThumbprintErrorReason::MissingMember);
        }
        if value.len() > MAX_JWK_THUMBPRINT_MEMBER_BYTES {
            return Err(JwkThumbprintErrorReason::MemberTooLarge);
        }
    }

    // Measure through the same serializer before allocating. Reserving once
    // avoids leaving copies of symmetric key text in abandoned reallocations,
    // including the worst case where each control byte expands to six bytes.
    let canonical = CanonicalMembers(fields);
    let mut counter = CountBytes::default();
    serde_json::to_writer(&mut counter, &canonical)
        .map_err(|_| JwkThumbprintErrorReason::LengthOverflow)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(counter.0)
        .map_err(|_| JwkThumbprintErrorReason::Allocation)?;
    serde_json::to_writer(&mut *bytes, &canonical)
        .map_err(|_| JwkThumbprintErrorReason::Serialization)?;
    Ok(bytes)
}

struct CanonicalMembers<'a>(&'a [(&'a str, &'a str)]);

impl Serialize for CanonicalMembers<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Default)]
struct CountBytes(usize);

impl Write for CountBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| Error::from(ErrorKind::FileTooLarge))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "encode_required_members_tests.rs"]
mod tests;
