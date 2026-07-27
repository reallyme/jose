// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Map;

use reallyme_codec::base64url::base64url_to_bytes;

use crate::JsonValue;

use super::encode_jwe_base64url;
use crate::jwe::JweError;

pub(super) fn p256_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-256",
        32,
        33,
        65,
        reallyme_crypto::p256::compress_public_key,
        reallyme_crypto::p256::decompress_public_key,
    )
}

pub(super) fn p256_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-256",
        32,
        33,
        reallyme_crypto::p256::decompress_public_key,
        reallyme_crypto::p256::compress_public_key,
    )
}

#[cfg(feature = "native")]
pub(super) fn p384_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-384",
        48,
        49,
        97,
        reallyme_crypto::p384::compress_p384,
        reallyme_crypto::p384::decompress_p384,
    )
}

#[cfg(feature = "native")]
pub(super) fn p384_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-384",
        48,
        49,
        reallyme_crypto::p384::decompress_p384,
        reallyme_crypto::p384::compress_p384,
    )
}

#[cfg(feature = "native")]
pub(super) fn p521_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-521",
        66,
        67,
        133,
        reallyme_crypto::p521::compress_p521,
        reallyme_crypto::p521::decompress_p521,
    )
}

#[cfg(feature = "native")]
pub(super) fn p521_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-521",
        66,
        67,
        reallyme_crypto::p521::decompress_p521,
        reallyme_crypto::p521::compress_p521,
    )
}

fn ec_epk_from_sec1_public_key(
    public_key_sec1: &[u8],
    crv: &'static str,
    coordinate_len: usize,
    compressed_len: usize,
    uncompressed_len: usize,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<JsonValue, JweError> {
    let uncompressed = ec_uncompressed_public_key(
        public_key_sec1,
        compressed_len,
        uncompressed_len,
        compress,
        decompress,
    )?;
    let x_start = 1usize;
    let x_end = x_start
        .checked_add(coordinate_len)
        .ok_or(JweError::LengthOverflow)?;
    let y_end = x_end
        .checked_add(coordinate_len)
        .ok_or(JweError::LengthOverflow)?;
    let x = uncompressed
        .get(x_start..x_end)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let y = uncompressed
        .get(x_end..y_end)
        .ok_or(JweError::InvalidKeyAgreementKey)?;

    let mut epk = Map::new();
    epk.insert("kty".to_owned(), JsonValue::String("EC".to_owned()));
    epk.insert("crv".to_owned(), JsonValue::String(crv.to_owned()));
    epk.insert("x".to_owned(), JsonValue::String(encode_jwe_base64url(x)));
    epk.insert("y".to_owned(), JsonValue::String(encode_jwe_base64url(y)));
    Ok(JsonValue::Object(epk))
}

fn ec_uncompressed_public_key(
    public_key_sec1: &[u8],
    compressed_len: usize,
    uncompressed_len: usize,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<Vec<u8>, JweError> {
    if public_key_sec1.len() == compressed_len {
        return decompress(public_key_sec1).map_err(|_| JweError::InvalidKeyAgreementKey);
    }
    if public_key_sec1.len() == uncompressed_len && public_key_sec1.first().copied() == Some(0x04) {
        compress(public_key_sec1).map_err(|_| JweError::InvalidKeyAgreementKey)?;
        return Ok(public_key_sec1.to_vec());
    }
    Err(JweError::InvalidKeyAgreementKey)
}

fn ec_public_key_from_jwk(
    jwk: &JsonValue,
    crv: &'static str,
    coordinate_len: usize,
    compressed_len: usize,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<Vec<u8>, JweError> {
    let object = jwk.as_object().ok_or(JweError::InvalidKeyAgreementKey)?;
    let kty = object
        .get("kty")
        .and_then(JsonValue::as_str)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let header_crv = object
        .get("crv")
        .and_then(JsonValue::as_str)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    if kty != "EC" || header_crv != crv {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    // The protected-header visitor currently rejects `alg` inside `epk` before
    // this helper runs. Keep the invariant at the JWK-to-SEC1 conversion
    // boundary so a future internal caller cannot bypass that header-layer
    // restriction accidentally.
    if object
        .get("alg")
        .and_then(JsonValue::as_str)
        .is_some_and(|alg| alg != "ECDH-ES")
    {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let x = base64url_to_bytes(
        object
            .get("x")
            .and_then(JsonValue::as_str)
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )
    .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let y = base64url_to_bytes(
        object
            .get("y")
            .and_then(JsonValue::as_str)
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )
    .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    // RFC 7518 requires the full coordinate width. Do not normalize a
    // zero-stripped producer encoding here: accepting two encodings for one
    // point would weaken the strict protected-header profile and obscure
    // interoperability failures at the boundary.
    if x.len() != coordinate_len || y.len() != coordinate_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let uncompressed_coordinate_len = coordinate_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(1))
        .ok_or(JweError::LengthOverflow)?;
    let mut uncompressed = Vec::with_capacity(uncompressed_coordinate_len);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    if uncompressed.len() != uncompressed_coordinate_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let compressed = compress(&uncompressed).map_err(|_| JweError::InvalidKeyAgreementKey)?;
    if compressed.len() != compressed_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let decoded = decompress(&compressed).map_err(|_| JweError::InvalidKeyAgreementKey)?;
    if decoded != uncompressed {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    Ok(compressed)
}
