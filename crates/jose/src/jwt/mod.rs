// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JSON Web Token (JWT) support.
//!
//! Overview: RFC 7519 / RFC 7515 compatible encoding and verification helpers.
//!
//! Scope:
//! - JWT/JWS serialization and signature verification using the configured crypto backend.
//! - Verifier-grade temporal, audience, issuer, and subject policy enforcement.
//!
//! Non-goals:
//! - Transport, HTTP, or higher-level protocol orchestration.
//!
//! Signature-only APIs deliberately authenticate bytes without validating
//! `exp`, `nbf`, `iat`, `aud`, `iss`, or `sub`. Verifier-grade consumers should
//! use [`decode_verify_jwt_with_claims_validation`].

/// JWT error types.
pub mod error;
pub use error::{JwtError, JwtRegisteredClaim, JwtTemporalClaim};

/// JWT algorithm mapping helpers.
pub mod alg;
pub use alg::algorithm_from_jwt_alg;

mod parse_compact;
mod select_algorithm;
pub(crate) mod sign;
mod strict_json;
pub(crate) mod unsigned;
mod validate_header;
mod validate_registered_claims;
mod validate_temporal_claims;
pub(crate) mod verify;

/// JWT claim container types.
pub mod claims;
pub use claims::{AnyClaims, RegisteredClaims};

/// JWT datatype wrappers.
pub mod datatype;
pub use datatype::{NumericDate, StringOrURI};

pub use parse_compact::MAX_COMPACT_JWT_BYTES;
pub use sign::{
    encode_signed_jwt, encode_signed_jwt_with_header_options, encode_signed_jwt_with_signer,
    encode_signed_jwt_with_signer_and_header_options,
};
#[cfg(feature = "wire")]
pub(crate) use strict_json::reject_duplicate_object_members;
pub use unsigned::{decode_unsigned_jwt, decode_unsigned_jwt_claims_json, encode_unsigned_jwt};
pub use validate_header::{JwtHeaderEncodeOptions, JwtHeaderValidationOptions};
pub use validate_registered_claims::JwtClaimsValidationPolicy;
pub use validate_temporal_claims::JwtTemporalValidationPolicy;
#[allow(deprecated)]
pub use verify::{
    decode_verify_jwt_claims_json_signature_only_with_header_validation,
    decode_verify_jwt_claims_json_with_claims_validation_and_header_validation,
    decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation,
    decode_verify_jwt_signature_only, decode_verify_jwt_signature_only_with_header_validation,
    decode_verify_jwt_with_claims_validation,
    decode_verify_jwt_with_claims_validation_and_header_validation,
    decode_verify_jwt_with_temporal_validation,
    decode_verify_jwt_with_temporal_validation_and_header_validation,
};
