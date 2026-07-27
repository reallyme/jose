// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ES256 compact JWS support.

use reallyme_crypto::p256::P256_ECDSA_JOSE_SIGNATURE_LEN;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    jws::{
        sign::JwsSigningInputError,
        sign_p256::{sign_p256_jose_signature, P256JoseSignError, P256JoseSignErrorReason},
        verify_p256::{verify_p256_jose_signature, P256JoseVerifyError, P256JoseVerifyErrorReason},
    },
    operation_contract::jws::{
        sign_jws, verify_jws, JwsSignAlgorithm, JwsSignError, JwsSignErrorReason, JwsSignInput,
        JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
    },
};

const ES256_JOSE_SIGNATURE_LEN: usize = P256_ECDSA_JOSE_SIGNATURE_LEN;

/// ES256 compact JWS signing, conversion, and verification errors.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum JwsEs256Error {
    /// The P-256 signing operation failed.
    #[error("ES256 JWS signing failed")]
    SignFailed,
    /// The backend returned a DER signature that could not be converted to JOSE form.
    #[error("ES256 JWS signer returned an invalid DER signature")]
    BadDerSignature,
    /// The protected header segment was not valid Base64URL.
    #[error("ES256 JWS header is not valid base64url")]
    BadHeaderBase64,
    /// The decoded protected header was not valid UTF-8.
    #[error("ES256 JWS header is not valid UTF-8")]
    BadHeaderUtf8,
    /// The authenticated payload segment was not valid unpadded Base64URL.
    #[error("ES256 JWS payload is not valid base64url")]
    BadPayloadBase64,
    /// The signature segment was not valid Base64URL.
    #[error("ES256 JWS signature is not valid base64url")]
    BadSignatureBase64,
    /// The raw signature was not valid fixed-width P-256 JOSE form.
    #[error("ES256 JWS signature is not valid raw P-256 JOSE form")]
    BadRawSignature,
    /// The compact JWS did not contain exactly three segments or exceeded limits.
    #[error("ES256 JWS compact serialization is invalid")]
    InvalidCompactEncoding,
    /// A checked JWS signing-input length calculation overflowed.
    #[error("ES256 JWS signing input length overflow")]
    LengthOverflow,
    /// The encoded compact JWS would exceed the parser's public limit.
    #[error("ES256 JWS compact serialization is too large")]
    InputTooLarge,
    /// The protected header did not validate as supported `alg = "ES256"`.
    #[error("ES256 JWS header does not bind to alg ES256")]
    HeaderMismatch,
    /// Signature verification failed.
    #[error("ES256 JWS signature is invalid")]
    InvalidSignature,
    /// Verification failed before a more specific error could be returned.
    #[error("ES256 JWS verification failed")]
    VerifyFailed,
}

/// Sign JOSE/COSE bytes with P-256 and return the fixed-width ES256 signature.
///
/// ReallyMe crypto backends expose P-256 ECDSA signatures in DER form because
/// that is the native representation for X.509 and several platform APIs. JOSE
/// and COSE both carry ES256 signatures as `r || s`, so this helper keeps the
/// DER-to-JOSE conversion at the audit boundary instead of spreading it through
/// callers.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] when signing fails or the backend signature cannot
/// be converted to fixed-width JOSE form.
pub fn sign_p256_jose_prehash(
    secret_key: &[u8],
    signing_input: &[u8],
) -> Result<[u8; ES256_JOSE_SIGNATURE_LEN], JwsEs256Error> {
    sign_p256_jose_signature(secret_key, signing_input).map_err(map_p256_sign_error)
}

const fn map_p256_sign_error(error: P256JoseSignError) -> JwsEs256Error {
    match error.reason() {
        P256JoseSignErrorReason::SignFailed => JwsEs256Error::SignFailed,
        P256JoseSignErrorReason::BadDerSignature => JwsEs256Error::BadDerSignature,
    }
}

/// Verify a fixed-width ES256 JOSE/COSE signature over caller-provided bytes.
///
/// The signature must be the JOSE form (`r || s`). Conversion back to DER is
/// deliberately local to this function because the underlying verifier accepts
/// DER and callers should not need to know that backend detail.
///
/// ES256 permits mathematically equivalent low-S and high-S signatures. This
/// verifier accepts both for JOSE, WebAuthn, and X.509 interoperability. A
/// signature or serialized object containing it must not be used as a unique
/// replay, cache, deduplication, or idempotency identifier.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] when the signature length or encoding is invalid,
/// or when P-256 verification fails.
pub fn verify_p256_jose_prehash(
    signature: &[u8],
    signing_input: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), JwsEs256Error> {
    verify_p256_jose_signature(signature, signing_input, public_key_sec1)
        .map_err(map_p256_verify_error)
}

const fn map_p256_verify_error(error: P256JoseVerifyError) -> JwsEs256Error {
    match error.reason() {
        P256JoseVerifyErrorReason::BadRawSignature => JwsEs256Error::BadRawSignature,
        P256JoseVerifyErrorReason::InvalidSignature => JwsEs256Error::InvalidSignature,
    }
}

/// Sign a compact JWS using ES256.
///
/// Payload is UTF-8 text (CID string).
///
/// Deterministic signing does not make externally supplied ES256 signatures
/// unique: verifiers may accept the equivalent high-S representation. Use an
/// application identifier or a digest of authenticated content for replay,
/// cache, deduplication, and idempotency decisions.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] when signing-input construction overflows, P-256
/// signing fails, signature conversion fails, or compact serialization fails.
pub fn sign_es256_jws(secret_key: &[u8], payload_text: &str) -> Result<String, JwsEs256Error> {
    sign_jws(JwsSignInput::new(
        JwsSignAlgorithm::Es256,
        secret_key,
        payload_text,
    ))
    .map(|compact| compact.into_string())
    .map_err(map_jws_sign_error)
}

const fn map_jws_sign_error(error: JwsSignError) -> JwsEs256Error {
    match error.reason() {
        JwsSignErrorReason::LengthOverflow => JwsEs256Error::LengthOverflow,
        JwsSignErrorReason::InputTooLarge => JwsEs256Error::InputTooLarge,
        JwsSignErrorReason::SignFailed => JwsEs256Error::SignFailed,
        JwsSignErrorReason::BadDerSignature => JwsEs256Error::BadDerSignature,
    }
}

/// Verify a compact JWS ES256 and discard its authenticated payload.
///
/// Verification is fail-closed: malformed input, header mismatch, and invalid
/// signatures are all errors. This shape deliberately avoids `Result<bool>` so
/// callers cannot accidentally continue after `verify_es256_jws(jws, key)?`.
/// Call [`verify_es256_jws_and_decode_payload`] when the authenticated payload
/// is needed; callers must not re-split and decode the compact input separately.
///
/// ES256 signatures are malleable between equivalent low-S and high-S forms,
/// both of which are accepted for interoperability. Neither the compact JWS nor
/// its signature segment is a unique replay, cache, deduplication, or idempotency
/// identifier.
///
/// The caller-supplied key is authoritative. Protected `kid`, `typ`, and `cty`
/// values are not used for key selection or application policy enforcement.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, invalid payload Base64URL, `alg` mismatch, invalid
/// signature encoding, or signature verification failure.
pub fn verify_es256_jws(jws: &str, public_key_sec1: &[u8]) -> Result<(), JwsEs256Error> {
    let verified_payload = verify_es256_jws_and_decode_payload(jws, public_key_sec1)?;
    drop(verified_payload);
    Ok(())
}

/// Verify a compact ES256 JWS and return its authenticated payload bytes.
///
/// The payload segment is decoded with strict unpadded Base64URL only after the
/// signature over the exact encoded segment has been validated. Returned bytes
/// are zeroized when their final owner is dropped.
///
/// ES256 signatures are malleable between equivalent low-S and high-S forms,
/// both of which are accepted for interoperability. Neither the compact JWS nor
/// its signature segment is a unique replay, cache, deduplication, or idempotency
/// identifier.
///
/// The caller-supplied key is authoritative. Protected `kid`, `typ`, and `cty`
/// values are not used for key selection or application policy enforcement.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, invalid payload Base64URL, `alg` mismatch, invalid
/// signature encoding, or signature verification failure.
pub fn verify_es256_jws_and_decode_payload(
    jws: &str,
    public_key_sec1: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JwsEs256Error> {
    verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        jws,
        public_key_sec1,
    ))
    .map(|verified| verified.into_bytes())
    .map_err(map_jws_verify_error)
}

const fn map_jws_verify_error(error: JwsVerifyError) -> JwsEs256Error {
    match error.reason() {
        JwsVerifyErrorReason::InvalidCompact => JwsEs256Error::InvalidCompactEncoding,
        JwsVerifyErrorReason::LengthOverflow => JwsEs256Error::LengthOverflow,
        JwsVerifyErrorReason::BadHeaderBase64 => JwsEs256Error::BadHeaderBase64,
        JwsVerifyErrorReason::BadHeaderUtf8 => JwsEs256Error::BadHeaderUtf8,
        JwsVerifyErrorReason::HeaderMismatch => JwsEs256Error::HeaderMismatch,
        JwsVerifyErrorReason::BadPayloadBase64 => JwsEs256Error::BadPayloadBase64,
        JwsVerifyErrorReason::BadSignatureBase64 => JwsEs256Error::BadSignatureBase64,
        JwsVerifyErrorReason::BadRawSignature => JwsEs256Error::BadRawSignature,
        JwsVerifyErrorReason::InvalidSignature => JwsEs256Error::InvalidSignature,
    }
}

impl From<JwsSigningInputError> for JwsEs256Error {
    fn from(error: JwsSigningInputError) -> Self {
        match error {
            JwsSigningInputError::LengthOverflow => JwsEs256Error::LengthOverflow,
            JwsSigningInputError::InputTooLarge => JwsEs256Error::InputTooLarge,
        }
    }
}
