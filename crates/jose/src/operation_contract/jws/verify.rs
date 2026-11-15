// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical compact-JWS verification semantics.

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::verify as dispatch_verify;
use thiserror::Error;

use crate::jws::parse_compact::{build_sig_structure, parse_compact_jws};
use crate::jws::parse_header::JwsAlgorithm;
use crate::jws::verify::{decode_and_validate_header, decode_payload, decode_signature};
use crate::jws::verify_p256::{verify_p256_jose_signature, P256JoseVerifyErrorReason};
use crate::jws::AuthenticatedCompactJws;
use crate::verify_signed_payload::verify_signed_payload;

const ED25519_SIGNATURE_LENGTH: usize = 64;
const ES256_SIGNATURE_LENGTH: usize = reallyme_crypto::p256::P256_ECDSA_JOSE_SIGNATURE_LEN;

/// Borrowed input for one compact-JWS verification operation.
///
/// The input deliberately owns no token or key bytes. Native callers retain
/// their buffers, while generated request owners remain alive until the
/// protobuf adapter has completed the semantic call and encoded its result.
pub(crate) struct JwsVerifyInput<'a> {
    algorithm: JwsAlgorithm,
    compact: &'a str,
    public_key: &'a [u8],
}

impl<'a> JwsVerifyInput<'a> {
    /// Builds a borrowed semantic verification request.
    pub(crate) const fn new(
        algorithm: JwsAlgorithm,
        compact: &'a str,
        public_key: &'a [u8],
    ) -> Self {
        Self {
            algorithm,
            compact,
            public_key,
        }
    }
}

/// Stable internal reasons for compact-JWS verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsVerifyErrorReason {
    /// Compact serialization has the wrong shape or exceeds its public limit.
    InvalidCompact,
    /// Checked signing-input length arithmetic overflowed.
    LengthOverflow,
    /// The protected header is not strict unpadded Base64URL.
    BadHeaderBase64,
    /// Decoded protected-header bytes are not UTF-8.
    BadHeaderUtf8,
    /// The protected header is invalid or does not bind the selected algorithm.
    HeaderMismatch,
    /// The authenticated payload segment is not strict unpadded Base64URL.
    BadPayloadBase64,
    /// The signature segment is not strict unpadded Base64URL.
    BadSignatureBase64,
    /// An ES256 signature is not a valid fixed-width pair of P-256 scalars.
    BadRawSignature,
    /// Signature length, key material, or cryptographic verification is invalid.
    InvalidSignature,
}

/// Typed compact-JWS verification error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("JWS verification failed")]
pub(crate) struct JwsVerifyError {
    reason: JwsVerifyErrorReason,
}

impl JwsVerifyError {
    const fn new(reason: JwsVerifyErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the fixed, non-sensitive failure reason.
    pub(crate) const fn reason(&self) -> JwsVerifyErrorReason {
        self.reason
    }
}

/// Verifies one compact JWS with the selected typed algorithm.
///
/// This is the semantic authority for the new operation-contract route. It
/// preserves the existing validation order. Payload decoding occurs only after
/// the signature authenticates the encoded payload segment.
pub(crate) fn verify_jws(
    input: JwsVerifyInput<'_>,
) -> Result<AuthenticatedCompactJws, JwsVerifyError> {
    let parts = parse_compact_jws(
        input.compact,
        JwsVerifyError::new(JwsVerifyErrorReason::InvalidCompact),
    )?;
    verify_signed_payload(
        input.public_key,
        |_| {
            decode_and_validate_header(
                parts.protected_header,
                input.algorithm,
                JwsVerifyError::new(JwsVerifyErrorReason::BadHeaderBase64),
                JwsVerifyError::new(JwsVerifyErrorReason::BadHeaderUtf8),
                JwsVerifyError::new(JwsVerifyErrorReason::HeaderMismatch),
            )
        },
        |caller_key, _| {
            let signing_input = build_sig_structure(
                parts.protected_header,
                parts.payload,
                JwsVerifyError::new(JwsVerifyErrorReason::LengthOverflow),
            )?;
            let signature = decode_signature(
                parts.signature,
                JwsVerifyError::new(JwsVerifyErrorReason::BadSignatureBase64),
            )?;
            match input.algorithm {
                JwsAlgorithm::Es256 => verify_es256(&signature, &signing_input, caller_key),
                JwsAlgorithm::Eddsa => verify_eddsa(&signature, &signing_input, caller_key),
            }
        },
        |protected_header| {
            let payload = decode_payload(
                parts.payload,
                JwsVerifyError::new(JwsVerifyErrorReason::BadPayloadBase64),
            )?;
            Ok(AuthenticatedCompactJws::new(protected_header, payload))
        },
    )
}

fn verify_es256(
    signature: &[u8],
    signing_input: &[u8],
    public_key: &[u8],
) -> Result<(), JwsVerifyError> {
    if signature.len() != ES256_SIGNATURE_LENGTH {
        return Err(JwsVerifyError::new(JwsVerifyErrorReason::InvalidSignature));
    }

    verify_p256_jose_signature(signature, signing_input, public_key).map_err(|error| {
        let reason = match error.reason() {
            P256JoseVerifyErrorReason::BadRawSignature => JwsVerifyErrorReason::BadRawSignature,
            P256JoseVerifyErrorReason::InvalidSignature => JwsVerifyErrorReason::InvalidSignature,
        };
        JwsVerifyError::new(reason)
    })
}

fn verify_eddsa(
    signature: &[u8],
    signing_input: &[u8],
    public_key: &[u8],
) -> Result<(), JwsVerifyError> {
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(JwsVerifyError::new(JwsVerifyErrorReason::InvalidSignature));
    }

    dispatch_verify(
        CryptoAlgorithm::Ed25519,
        public_key,
        signing_input,
        signature,
    )
    .map_err(|_| JwsVerifyError::new(JwsVerifyErrorReason::InvalidSignature))
}
