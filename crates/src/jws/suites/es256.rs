// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ES256 compact JWS support.

use reallyme_crypto::p256::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_jose_signature_to_der, sign_p256_der_prehash,
    verify_p256_der_prehash, P256_ECDSA_JOSE_SIGNATURE_LEN,
};
use thiserror::Error;

use crate::jws::{
    parse_compact::{build_sig_structure, parse_compact_jws},
    parse_header::JwsAlgorithm,
    sign::{encode_compact_jws, encode_jws_signing_input, JwsSigningInputError},
    verify::{decode_and_validate_header, decode_signature},
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
    let der_sig =
        sign_p256_der_prehash(secret_key, signing_input).map_err(|_| JwsEs256Error::SignFailed)?;
    p256_ecdsa_der_to_jose_signature(&der_sig).map_err(|_| JwsEs256Error::BadDerSignature)
}

/// Verify a fixed-width ES256 JOSE/COSE signature over caller-provided bytes.
///
/// The signature must be the JOSE form (`r || s`). Conversion back to DER is
/// deliberately local to this function because the underlying verifier accepts
/// DER and callers should not need to know that backend detail.
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
    if signature.len() != ES256_JOSE_SIGNATURE_LEN {
        return Err(JwsEs256Error::InvalidSignature);
    }

    let der =
        p256_ecdsa_jose_signature_to_der(signature).map_err(|_| JwsEs256Error::BadRawSignature)?;
    verify_p256_der_prehash(&der, signing_input, public_key_sec1)
        .map_err(|_| JwsEs256Error::InvalidSignature)
}

/// Sign a compact JWS using ES256.
///
/// Payload is UTF-8 text (CID string).
///
/// # Errors
///
/// Returns [`JwsEs256Error`] when signing-input construction overflows, P-256
/// signing fails, signature conversion fails, or compact serialization fails.
pub fn sign_es256_jws(secret_key: &[u8], payload_text: &str) -> Result<String, JwsEs256Error> {
    let signing_input = encode_jws_signing_input(JwsAlgorithm::Es256, payload_text.as_bytes())
        .map_err(JwsEs256Error::from)?;
    let raw64 = sign_p256_jose_prehash(secret_key, &signing_input.signing_input)?;

    encode_compact_jws(signing_input, raw64.as_ref()).map_err(JwsEs256Error::from)
}

/// Verify a compact JWS ES256.
///
/// Verification is fail-closed: malformed input, header mismatch, and invalid
/// signatures are all errors. This shape deliberately avoids `Result<bool>` so
/// callers cannot accidentally continue after `verify_es256_jws(jws, key)?`.
///
/// # Errors
///
/// Returns [`JwsEs256Error`] for malformed compact input, invalid Base64URL or
/// UTF-8 header data, `alg` mismatch, invalid signature encoding, or signature
/// verification failure.
pub fn verify_es256_jws(jws: &str, public_key_sec1: &[u8]) -> Result<(), JwsEs256Error> {
    let parts = parse_compact_jws(jws, JwsEs256Error::InvalidCompactEncoding)?;
    decode_and_validate_header(
        parts.protected_header,
        JwsAlgorithm::Es256,
        JwsEs256Error::BadHeaderBase64,
        JwsEs256Error::BadHeaderUtf8,
        JwsEs256Error::HeaderMismatch,
    )?;

    let signing_input = build_sig_structure(
        parts.protected_header,
        parts.payload,
        JwsEs256Error::LengthOverflow,
    )?;
    let raw = decode_signature(parts.signature, JwsEs256Error::BadSignatureBase64)?;
    if raw.len() != ES256_JOSE_SIGNATURE_LEN {
        return Err(JwsEs256Error::InvalidSignature);
    }

    verify_p256_jose_prehash(&raw, &signing_input, public_key_sec1)
}

impl From<JwsSigningInputError> for JwsEs256Error {
    fn from(error: JwsSigningInputError) -> Self {
        match error {
            JwsSigningInputError::LengthOverflow => JwsEs256Error::LengthOverflow,
            JwsSigningInputError::InputTooLarge => JwsEs256Error::InputTooLarge,
        }
    }
}
