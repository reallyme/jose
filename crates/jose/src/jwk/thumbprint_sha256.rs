// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use super::{encode_required_members::encode, JwkThumbprintErrorReason};

pub(crate) const SHA256_DIGEST_BYTES: usize = reallyme_crypto::sha2::SHA2_256_DIGEST_LENGTH;

/// Maximum UTF-8 byte length of each required JWK thumbprint member.
pub const MAX_JWK_THUMBPRINT_MEMBER_BYTES: usize =
    reallyme_jose_proto::generated::contract_values::JWK_THUMBPRINT_MEMBER_BYTES;

/// Borrowed, already encoded members required by a JWK key type.
///
/// Key type is fixed by the variant. Optional metadata and private asymmetric
/// key members cannot enter the canonical serialization. The caller retains
/// ownership and cleanup responsibility for all borrowed text, including `k`.
/// No key material is copied into this view or exposed through diagnostics.
pub enum JwkThumbprintMembers<'a> {
    /// EC public key members, including both coordinates.
    Ec {
        /// JWK curve name.
        crv: &'a str,
        /// Base64URL-encoded x coordinate.
        x: &'a str,
        /// Base64URL-encoded y coordinate.
        y: &'a str,
    },
    /// Octet key pair public members, such as an Ed25519 key.
    Okp {
        /// JWK curve name.
        crv: &'a str,
        /// Base64URL-encoded public key.
        x: &'a str,
    },
    /// RSA public key members.
    Rsa {
        /// Base64URLUInt-encoded public exponent.
        e: &'a str,
        /// Base64URLUInt-encoded modulus.
        n: &'a str,
    },
    /// Symmetric octet key members. The borrowed key remains caller-owned.
    Oct {
        /// Base64URL-encoded secret key.
        k: &'a str,
    },
}

/// Computes the RFC 7638 SHA-256 digest of the required JWK members.
///
/// Members are serialized in lexicographic order without whitespace. Input is
/// already encoded JWK text: this function does not decode or normalize it,
/// validate curve names, or establish cryptographic key validity. Callers may
/// impose stricter protocol limits before calling this shared primitive.
///
/// JSON quotes, backslashes, and controls are escaped with the JSON serializer;
/// UTF-8 is preserved without Unicode normalization. Escaping is a deterministic
/// extension for values outside RFC 7638 section 3.3's unescaped-value domain.
/// Canonical JSON and the returned digest are zeroizing owners because an oct
/// thumbprint includes secret material and can facilitate key guessing.
///
/// # Errors
///
/// Rejects empty members and members exceeding 8192 UTF-8 bytes. Allocation,
/// checked length, and serialization failures return fixed typed reasons.
pub fn thumbprint_sha256(
    members: &JwkThumbprintMembers<'_>,
) -> Result<Zeroizing<[u8; SHA256_DIGEST_BYTES]>, JwkThumbprintErrorReason> {
    let canonical = encode(members)?;
    let digest = reallyme_crypto::sha2::digest(&canonical);
    Ok(Zeroizing::new(*digest.as_bytes()))
}
