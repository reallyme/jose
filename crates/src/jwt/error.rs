// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

use reallyme_codec::base64url::Base64UrlError;
use reallyme_crypto::dispatch::AlgorithmError;

/// Registered temporal claim identifiers used in typed errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtTemporalClaim {
    /// Expiration time (`exp`).
    Exp,
    /// Not-before time (`nbf`).
    Nbf,
    /// Issued-at time (`iat`).
    Iat,
}

/// JWT parsing, signing, verification, and temporal-validation errors.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Compact serialization is malformed or has the wrong number of parts.
    #[error("invalid JWT format")]
    InvalidJwtFormat,

    /// The JOSE header is malformed or violates header policy.
    #[error("invalid JWT header")]
    InvalidHeader,

    /// Claims are malformed for the requested operation.
    #[error("invalid JWT claims")]
    InvalidClaims,

    /// Signature bytes are malformed or failed verification.
    #[error("invalid JWT signature")]
    InvalidSignature,

    /// Input exceeded the compact JWT parser limit.
    #[error("JWT input too large")]
    InputTooLarge,

    /// The JWT `alg` is not supported by this crate.
    #[error("unsupported JWT algorithm")]
    UnsupportedAlgorithm,

    /// The JOSE header algorithm does not match the supplied key policy.
    #[error("JWT algorithm mismatch")]
    AlgorithmMismatch,

    /// The JWK did not carry an algorithm binding.
    #[error("missing algorithm in JWK")]
    MissingAlgorithm,

    /// The operation required a private key that was not present.
    #[error("missing private key in JWK")]
    MissingPrivateKey,

    /// The operation required a public key that was not present.
    #[error("missing public key in JWK")]
    MissingPublicKey,

    /// JSON serialization or deserialization failed.
    #[error("serialization error")]
    Serialization,

    /// Base64URL decoding failed.
    #[error("base64url decoding error")]
    Base64Url,

    /// The configured crypto backend rejected the operation.
    #[error("cryptographic error")]
    Crypto,

    /// A required temporal claim was absent.
    #[error("missing required temporal claim: {0:?}")]
    MissingRequiredTemporalClaim(JwtTemporalClaim),

    /// A temporal claim was not a valid NumericDate for this policy.
    #[error("invalid temporal claim value: {0:?}")]
    InvalidTemporalClaimValue(JwtTemporalClaim),

    /// The token is expired after applying allowed clock skew.
    #[error("JWT is expired")]
    Expired,

    /// The token is not valid yet after applying allowed clock skew.
    #[error("JWT is not yet valid")]
    NotYetValid,

    /// The issued-at time is too far in the future.
    #[error("JWT issued-at is in the future")]
    IssuedAtInFuture,
}

// ------------------------------------
// Error conversions for `?`
// ------------------------------------

impl From<Base64UrlError> for JwtError {
    fn from(_: Base64UrlError) -> Self {
        JwtError::Base64Url
    }
}

impl From<AlgorithmError> for JwtError {
    fn from(_: AlgorithmError) -> Self {
        JwtError::Crypto
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(_: serde_json::Error) -> Self {
        JwtError::Serialization
    }
}
