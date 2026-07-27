// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Primitive verification for fixed-width P-256 JOSE signatures.

use reallyme_crypto::p256::{p256_ecdsa_jose_signature_to_der, verify_p256_der_prehash};
use thiserror::Error;

const ES256_JOSE_SIGNATURE_LENGTH: usize = reallyme_crypto::p256::P256_ECDSA_JOSE_SIGNATURE_LEN;

/// Stable reasons for primitive fixed-width P-256 verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum P256JoseVerifyErrorReason {
    /// The signature is not a valid fixed-width pair of P-256 scalars.
    BadRawSignature,
    /// The signature length, public key, or cryptographic verification failed.
    InvalidSignature,
}

/// Typed primitive fixed-width P-256 verification error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("P-256 JOSE signature verification failed")]
pub(crate) struct P256JoseVerifyError {
    reason: P256JoseVerifyErrorReason,
}

impl P256JoseVerifyError {
    const fn new(reason: P256JoseVerifyErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the fixed, non-sensitive failure reason.
    pub(crate) const fn reason(self) -> P256JoseVerifyErrorReason {
        self.reason
    }
}

/// Verifies a fixed-width P-256 JOSE signature over caller-provided bytes.
pub(crate) fn verify_p256_jose_signature(
    signature: &[u8],
    signing_input: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), P256JoseVerifyError> {
    if signature.len() != ES256_JOSE_SIGNATURE_LENGTH {
        return Err(P256JoseVerifyError::new(
            P256JoseVerifyErrorReason::InvalidSignature,
        ));
    }

    let der = p256_ecdsa_jose_signature_to_der(signature)
        .map_err(|_| P256JoseVerifyError::new(P256JoseVerifyErrorReason::BadRawSignature))?;
    verify_p256_der_prehash(&der, signing_input, public_key_sec1)
        .map_err(|_| P256JoseVerifyError::new(P256JoseVerifyErrorReason::InvalidSignature))
}
