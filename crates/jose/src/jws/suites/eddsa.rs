// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! EdDSA compact JWS support for Ed25519 keys.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    jws::sign::JwsSigningInputError,
    operation_contract::jws::{
        sign_jws, verify_jws, JwsSignAlgorithm, JwsSignError, JwsSignErrorReason, JwsSignInput,
        JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
    },
};

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
    /// The authenticated payload segment was not valid unpadded Base64URL.
    #[error("EdDSA JWS payload is not valid base64url")]
    BadPayloadBase64,
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
    sign_jws(JwsSignInput::new(
        JwsSignAlgorithm::Eddsa,
        secret_key,
        payload_text,
    ))
    .map(|compact| compact.into_string())
    .map_err(map_jws_sign_error)
}

const fn map_jws_sign_error(error: JwsSignError) -> JwsEddsaError {
    match error.reason() {
        JwsSignErrorReason::LengthOverflow => JwsEddsaError::LengthOverflow,
        JwsSignErrorReason::InputTooLarge => JwsEddsaError::InputTooLarge,
        JwsSignErrorReason::SignFailed | JwsSignErrorReason::BadDerSignature => {
            JwsEddsaError::SignFailed
        }
    }
}

/// Verify a compact JWS using EdDSA and discard its authenticated payload.
///
/// Call [`verify_eddsa_jws_and_decode_payload`] when the authenticated payload
/// is needed; callers must not re-split and decode the compact input separately.
/// The caller-supplied key is authoritative. Protected `kid`, `typ`, and `cty`
/// values are not used for key selection or application policy enforcement.
///
/// # Errors
///
/// Returns [`JwsEddsaError`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, invalid payload Base64URL, `alg` mismatch, malformed
/// signature bytes, or Ed25519 verification failure.
pub fn verify_eddsa_jws(jws: &str, public_key: &[u8]) -> Result<(), JwsEddsaError> {
    let verified_payload = verify_eddsa_jws_and_decode_payload(jws, public_key)?;
    drop(verified_payload);
    Ok(())
}

/// Verify a compact EdDSA JWS and return its authenticated payload bytes.
///
/// The payload segment is decoded with strict unpadded Base64URL only after the
/// signature over the exact encoded segment has been validated. Returned bytes
/// are zeroized when their final owner is dropped.
///
/// The caller-supplied key is authoritative. Protected `kid`, `typ`, and `cty`
/// values are not used for key selection or application policy enforcement.
///
/// # Errors
///
/// Returns [`JwsEddsaError`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, invalid payload Base64URL, `alg` mismatch, malformed
/// signature bytes, or Ed25519 verification failure.
pub fn verify_eddsa_jws_and_decode_payload(
    jws: &str,
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JwsEddsaError> {
    verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Eddsa,
        jws,
        public_key,
    ))
    .map(|verified| verified.into_bytes())
    .map_err(map_jws_verify_error)
}

const fn map_jws_verify_error(error: JwsVerifyError) -> JwsEddsaError {
    match error.reason() {
        JwsVerifyErrorReason::InvalidCompact => JwsEddsaError::InvalidCompactEncoding,
        JwsVerifyErrorReason::LengthOverflow => JwsEddsaError::LengthOverflow,
        JwsVerifyErrorReason::BadHeaderBase64 => JwsEddsaError::BadHeaderBase64,
        JwsVerifyErrorReason::BadHeaderUtf8 => JwsEddsaError::BadHeaderUtf8,
        JwsVerifyErrorReason::HeaderMismatch => JwsEddsaError::HeaderMismatch,
        JwsVerifyErrorReason::BadPayloadBase64 => JwsEddsaError::BadPayloadBase64,
        JwsVerifyErrorReason::BadSignatureBase64 => JwsEddsaError::BadSignatureBase64,
        JwsVerifyErrorReason::BadRawSignature | JwsVerifyErrorReason::InvalidSignature => {
            JwsEddsaError::InvalidSignature
        }
    }
}

impl From<JwsSigningInputError> for JwsEddsaError {
    fn from(error: JwsSigningInputError) -> Self {
        match error {
            JwsSigningInputError::LengthOverflow => JwsEddsaError::LengthOverflow,
            JwsSigningInputError::InputTooLarge => JwsEddsaError::InputTooLarge,
        }
    }
}
