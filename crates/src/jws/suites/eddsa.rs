// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! EdDSA compact JWS support for Ed25519 keys.

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::{sign as dispatch_sign, verify as dispatch_verify};
use thiserror::Error;

use crate::jws::{
    parse_compact::{build_sig_structure, parse_compact_jws},
    parse_header::JwsAlgorithm,
    sign::{encode_compact_jws, encode_jws_signing_input, JwsSigningInputError},
    verify::{decode_and_validate_header, decode_signature},
};

const ED25519_SIGNATURE_LEN: usize = 64;

/// EdDSA compact JWS signing and verification errors.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum JwsEddsaError {
    /// The Ed25519 signing operation failed.
    #[error("EdDSA JWS signing failed")]
    SignFailed,
    /// The protected header segment was not valid Base64URL.
    #[error("EdDSA JWS header is not valid base64url")]
    BadHeaderBase64,
    /// The decoded protected header was not valid UTF-8.
    #[error("EdDSA JWS header is not valid UTF-8")]
    BadHeaderUtf8,
    /// The signature segment was not valid Base64URL.
    #[error("EdDSA JWS signature is not valid base64url")]
    BadSignatureBase64,
    /// The compact JWS did not contain exactly three segments or exceeded limits.
    #[error("EdDSA JWS compact serialization is invalid")]
    InvalidCompactEncoding,
    /// A checked JWS signing-input length calculation overflowed.
    #[error("EdDSA JWS signing input length overflow")]
    LengthOverflow,
    /// The encoded compact JWS would exceed the parser's public limit.
    #[error("EdDSA JWS compact serialization is too large")]
    InputTooLarge,
    /// The protected header did not validate as supported `alg = "EdDSA"`.
    #[error("EdDSA JWS header does not bind to alg EdDSA")]
    HeaderMismatch,
    /// Signature verification failed.
    #[error("EdDSA JWS signature is invalid")]
    InvalidSignature,
}

/// Sign a compact JWS using the EdDSA JOSE algorithm with Ed25519 keys.
///
/// # Errors
///
/// Returns [`JwsEddsaError`] when signing-input construction overflows,
/// Ed25519 signing fails, or compact serialization fails.
pub fn sign_eddsa_jws(secret_key: &[u8], payload_text: &str) -> Result<String, JwsEddsaError> {
    let signing_input = encode_jws_signing_input(JwsAlgorithm::Eddsa, payload_text.as_bytes())
        .map_err(JwsEddsaError::from)?;
    let signature = dispatch_sign(
        CryptoAlgorithm::Ed25519,
        secret_key,
        &signing_input.signing_input,
    )
    .map_err(|_| JwsEddsaError::SignFailed)?;

    encode_compact_jws(signing_input, &signature).map_err(JwsEddsaError::from)
}

/// Verify a compact JWS using the EdDSA JOSE algorithm with Ed25519 keys.
///
/// # Errors
///
/// Returns [`JwsEddsaError`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, `alg` mismatch, malformed signature bytes, or Ed25519
/// verification failure.
pub fn verify_eddsa_jws(jws: &str, public_key: &[u8]) -> Result<(), JwsEddsaError> {
    let parts = parse_compact_jws(jws, JwsEddsaError::InvalidCompactEncoding)?;
    decode_and_validate_header(
        parts.protected_header,
        JwsAlgorithm::Eddsa,
        JwsEddsaError::BadHeaderBase64,
        JwsEddsaError::BadHeaderUtf8,
        JwsEddsaError::HeaderMismatch,
    )?;

    let signing_input = build_sig_structure(
        parts.protected_header,
        parts.payload,
        JwsEddsaError::LengthOverflow,
    )?;
    let signature = decode_signature(parts.signature, JwsEddsaError::BadSignatureBase64)?;
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(JwsEddsaError::InvalidSignature);
    }

    dispatch_verify(
        CryptoAlgorithm::Ed25519,
        public_key,
        &signing_input,
        &signature,
    )
    .map_err(|_| JwsEddsaError::InvalidSignature)
}

impl From<JwsSigningInputError> for JwsEddsaError {
    fn from(error: JwsSigningInputError) -> Self {
        match error {
            JwsSigningInputError::LengthOverflow => JwsEddsaError::LengthOverflow,
            JwsSigningInputError::InputTooLarge => JwsEddsaError::InputTooLarge,
        }
    }
}
