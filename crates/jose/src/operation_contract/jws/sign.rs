// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical compact-JWS signing semantics.

use reallyme_crypto::core::Algorithm as CryptoAlgorithm;
use reallyme_crypto::dispatch::sign as dispatch_sign;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::jws::parse_header::JwsAlgorithm;
use crate::jws::sign::{encode_compact_jws, encode_jws_signing_input, JwsSigningInputError};
use crate::jws::sign_p256::{sign_p256_jose_signature, P256JoseSignErrorReason};

/// Supported algorithms for the compact-JWS signing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsSignAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    Es256,
    /// EdDSA with Ed25519.
    Eddsa,
}

/// Borrowed input for one compact-JWS signing operation.
pub(crate) struct JwsSignInput<'a> {
    algorithm: JwsSignAlgorithm,
    private_key: &'a [u8],
    payload: &'a str,
}

impl<'a> JwsSignInput<'a> {
    /// Builds a borrowed semantic signing request.
    pub(crate) const fn new(
        algorithm: JwsSignAlgorithm,
        private_key: &'a [u8],
        payload: &'a str,
    ) -> Self {
        Self {
            algorithm,
            private_key,
            payload,
        }
    }
}

/// Owned compact-JWS signing result.
pub(crate) struct SignedCompactJws(String);

impl SignedCompactJws {
    /// Transfers the compact serialization to the caller.
    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// Stable reasons for compact-JWS signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JwsSignErrorReason {
    /// Checked signing-input or compact-output length arithmetic overflowed.
    LengthOverflow,
    /// The encoded compact JWS exceeded its public parser limit.
    InputTooLarge,
    /// The selected signature provider could not sign the input.
    SignFailed,
    /// A P-256 provider signature could not be converted from DER to JOSE form.
    BadDerSignature,
}

/// Typed compact-JWS signing error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("JWS signing failed")]
pub(crate) struct JwsSignError {
    reason: JwsSignErrorReason,
}

impl JwsSignError {
    const fn new(reason: JwsSignErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the fixed, non-sensitive failure reason.
    pub(crate) const fn reason(self) -> JwsSignErrorReason {
        self.reason
    }
}

/// Signs one compact JWS with the selected typed algorithm.
pub(crate) fn sign_jws(input: JwsSignInput<'_>) -> Result<SignedCompactJws, JwsSignError> {
    let header_algorithm = match input.algorithm {
        JwsSignAlgorithm::Es256 => JwsAlgorithm::Es256,
        JwsSignAlgorithm::Eddsa => JwsAlgorithm::Eddsa,
    };
    let signing_input = encode_jws_signing_input(header_algorithm, input.payload.as_bytes())
        .map_err(map_signing_input_error)?;
    let signature = match input.algorithm {
        JwsSignAlgorithm::Es256 => Zeroizing::new(
            sign_p256_jose_signature(input.private_key, &signing_input.signing_input)
                .map_err(|error| match error.reason() {
                    P256JoseSignErrorReason::SignFailed => {
                        JwsSignError::new(JwsSignErrorReason::SignFailed)
                    }
                    P256JoseSignErrorReason::BadDerSignature => {
                        JwsSignError::new(JwsSignErrorReason::BadDerSignature)
                    }
                })?
                .to_vec(),
        ),
        JwsSignAlgorithm::Eddsa => Zeroizing::new(
            dispatch_sign(
                CryptoAlgorithm::Ed25519,
                input.private_key,
                &signing_input.signing_input,
            )
            .map_err(|_| JwsSignError::new(JwsSignErrorReason::SignFailed))?,
        ),
    };
    let compact = encode_compact_jws(signing_input, &signature).map_err(map_signing_input_error)?;
    Ok(SignedCompactJws(compact))
}

const fn map_signing_input_error(error: JwsSigningInputError) -> JwsSignError {
    let reason = match error {
        JwsSigningInputError::LengthOverflow => JwsSignErrorReason::LengthOverflow,
        JwsSigningInputError::InputTooLarge => JwsSignErrorReason::InputTooLarge,
    };
    JwsSignError::new(reason)
}
