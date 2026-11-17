// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{thumbprint_sha256, JwkThumbprintErrorReason, JwkThumbprintMembers};

/// Borrows required members from a caller-owned JSON value and computes its digest.
///
/// Ignores all extra fields, including private asymmetric material, key IDs,
/// algorithms, and nested metadata. Only required members are inspected, so
/// optional fields cannot affect either the digest or member limits. The caller
/// owns JSON parsing, duplicate-member rejection, input limits, and cleanup of
/// the JSON value; this adapter neither clones nor owns its strings.
///
/// # Errors
///
/// Returns fixed reasons for a non-object, missing/empty or non-string required
/// members, unsupported key types, and failures from [`thumbprint_sha256`].
pub fn thumbprint_sha256_from_json(
    jwk: &Value,
) -> Result<Zeroizing<[u8; 32]>, JwkThumbprintErrorReason> {
    let object = jwk
        .as_object()
        .ok_or(JwkThumbprintErrorReason::InvalidJsonObject)?;
    let members = match member(object, "kty")? {
        "EC" => JwkThumbprintMembers::Ec {
            crv: member(object, "crv")?,
            x: member(object, "x")?,
            y: member(object, "y")?,
        },
        "OKP" => JwkThumbprintMembers::Okp {
            crv: member(object, "crv")?,
            x: member(object, "x")?,
        },
        "RSA" => JwkThumbprintMembers::Rsa {
            e: member(object, "e")?,
            n: member(object, "n")?,
        },
        "oct" => JwkThumbprintMembers::Oct {
            k: member(object, "k")?,
        },
        _ => return Err(JwkThumbprintErrorReason::UnsupportedKeyType),
    };
    thumbprint_sha256(&members)
}

fn member<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, JwkThumbprintErrorReason> {
    let value = object
        .get(name)
        .ok_or(JwkThumbprintErrorReason::MissingMember)?
        .as_str()
        .ok_or(JwkThumbprintErrorReason::InvalidMemberType)?;
    if value.is_empty() {
        return Err(JwkThumbprintErrorReason::MissingMember);
    }
    if value.len() > super::MAX_JWK_THUMBPRINT_MEMBER_BYTES {
        return Err(JwkThumbprintErrorReason::MemberTooLarge);
    }
    Ok(value)
}
