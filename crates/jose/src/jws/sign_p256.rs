// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Primitive signing for fixed-width P-256 JOSE signatures.

use reallyme_crypto::p256::{
    p256_ecdsa_der_to_jose_signature, sign_p256_der_prehash, P256_ECDSA_JOSE_SIGNATURE_LEN,
};
use thiserror::Error;

/// Stable reasons for primitive fixed-width P-256 signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum P256JoseSignErrorReason {
    /// The provider could not create a P-256 signature.
    SignFailed,
    /// The provider returned a DER signature that cannot be represented as JOSE.
    BadDerSignature,
}

/// Typed primitive fixed-width P-256 signing error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("P-256 JOSE signature signing failed")]
pub(crate) struct P256JoseSignError {
    reason: P256JoseSignErrorReason,
}

impl P256JoseSignError {
    const fn new(reason: P256JoseSignErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the fixed, non-sensitive failure reason.
    pub(crate) const fn reason(self) -> P256JoseSignErrorReason {
        self.reason
    }
}

/// Signs caller-provided bytes and returns a fixed-width P-256 JOSE signature.
pub(crate) fn sign_p256_jose_signature(
    secret_key: &[u8],
    signing_input: &[u8],
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], P256JoseSignError> {
    let der_signature = sign_p256_der_prehash(secret_key, signing_input)
        .map_err(|_| P256JoseSignError::new(P256JoseSignErrorReason::SignFailed))?;
    p256_ecdsa_der_to_jose_signature(&der_signature)
        .map_err(|_| P256JoseSignError::new(P256JoseSignErrorReason::BadDerSignature))
}
