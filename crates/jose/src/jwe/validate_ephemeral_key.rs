// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::JsonValue;

use super::JweError;

pub(super) struct PublicEphemeralJwk<'a> {
    pub(super) key_type: &'a str,
    pub(super) curve: &'a str,
    pub(super) x: &'a str,
    pub(super) y: &'a str,
}

impl<'a> TryFrom<&'a JsonValue> for PublicEphemeralJwk<'a> {
    type Error = JweError;

    fn try_from(jwk: &'a JsonValue) -> Result<Self, Self::Error> {
        let object = jwk.as_object().ok_or(JweError::InvalidKeyAgreementKey)?;
        read_public_members(object.len(), |name| {
            object.get(name).and_then(JsonValue::as_str)
        })
    }
}

fn read_public_members<'a>(
    member_count: usize,
    read: impl Fn(&str) -> Option<&'a str>,
) -> Result<PublicEphemeralJwk<'a>, JweError> {
    const PUBLIC_MEMBER_COUNT: usize = 4;
    // The four named, string-valued members exhaust the map. Any extra
    // member, including a private scalar, must increase its size or replace
    // a required member. Apply this to caller-constructed headers as well.
    if member_count != PUBLIC_MEMBER_COUNT {
        return Err(JweError::InvalidKeyAgreementKey);
    }

    Ok(PublicEphemeralJwk {
        key_type: read("kty").ok_or(JweError::InvalidKeyAgreementKey)?,
        curve: read("crv").ok_or(JweError::InvalidKeyAgreementKey)?,
        x: read("x").ok_or(JweError::InvalidKeyAgreementKey)?,
        y: read("y").ok_or(JweError::InvalidKeyAgreementKey)?,
    })
}

#[derive(Clone, Copy)]
pub(super) enum EphemeralCurve {
    P256,
    #[cfg(feature = "native")]
    P384,
    #[cfg(feature = "native")]
    P521,
}

impl EphemeralCurve {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            #[cfg(feature = "native")]
            Self::P384 => "P-384",
            #[cfg(feature = "native")]
            Self::P521 => "P-521",
        }
    }

    pub(super) const fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            #[cfg(feature = "native")]
            Self::P384 => 48,
            #[cfg(feature = "native")]
            Self::P521 => 66,
        }
    }

    pub(super) fn validate_identity(self, key_type: &[u8], curve: &[u8]) -> Result<(), JweError> {
        if key_type == b"EC" && curve == self.name().as_bytes() {
            Ok(())
        } else {
            Err(JweError::InvalidKeyAgreementKey)
        }
    }

    pub(super) const fn validate_coordinate_lengths(
        self,
        x_len: usize,
        y_len: usize,
    ) -> Result<(), JweError> {
        // Require the full JWA width so that a shortened representation
        // cannot be silently normalized to the same point.
        let width = self.coordinate_len();
        if x_len == width && y_len == width {
            Ok(())
        } else {
            Err(JweError::InvalidKeyAgreementKey)
        }
    }
}

pub(super) fn agree_with_validated_ephemeral_key<Jwk, PublicKey, Output>(
    jwk: Option<&Jwk>,
    decode: impl FnOnce(&Jwk) -> Result<PublicKey, JweError>,
    agree: impl FnOnce(PublicKey) -> Result<Output, JweError>,
) -> Result<Output, JweError> {
    // Only the decoder's validated output reaches the backend with the
    // recipient's private key.
    let jwk = jwk.ok_or(JweError::MissingRequiredHeaderParameter)?;
    let public_key = decode(jwk)?;
    agree(public_key)
}

#[cfg(kani)]
#[path = "validate_ephemeral_key_proofs.rs"]
mod proofs;
