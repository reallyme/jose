// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical JWT execution entrypoints shared by native and boundary facades.

use zeroize::Zeroizing;

use crate::jwt::{
    sign::{encode_signed_jwt_claims_json_core, encode_signed_jwt_claims_json_with_signer_core},
    unsigned::{decode_unsigned_jwt_claims_json_core, encode_unsigned_jwt_claims_json_core},
    verify::{
        decode_verify_jwt_claims_json_signature_only_core,
        decode_verify_jwt_claims_json_with_claims_policy_core,
        decode_verify_jwt_claims_json_with_temporal_policy_core,
    },
    JwtClaimsValidationPolicy, JwtError, JwtHeaderEncodeOptions, JwtHeaderValidationOptions,
    JwtTemporalValidationPolicy,
};
use crate::{Jwk, Signer};

/// Encodes validated claims JSON as an unsigned compact JWT.
pub(crate) fn encode_unsigned_jwt(claims_json: &[u8]) -> Result<String, JwtError> {
    encode_unsigned_jwt_claims_json_core(claims_json)
}

/// Decodes an unsigned compact JWT while preserving its claims bytes.
pub(crate) fn decode_unsigned_jwt(compact: &str) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    decode_unsigned_jwt_claims_json_core(compact)
}

/// Signs validated claims JSON with caller-owned key material.
pub(crate) fn sign_jwt(
    claims_json: &[u8],
    jwk: &Jwk,
    private_key: &[u8],
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    encode_signed_jwt_claims_json_core(claims_json, jwk, private_key, header_options)
}

/// Signs validated claims JSON through an injected signer.
pub(crate) fn sign_jwt_with_signer(
    claims_json: &[u8],
    jwk: &Jwk,
    signer: &dyn Signer,
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    encode_signed_jwt_claims_json_with_signer_core(claims_json, jwk, signer, header_options)
}

/// Verifies a signed JWT without applying temporal policy.
pub(crate) fn verify_jwt_signature_only(
    compact: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    decode_verify_jwt_claims_json_signature_only_core(compact, jwk, public_key, header_validation)
}

/// Verifies a signed JWT and applies the selected temporal policy.
pub(crate) fn verify_jwt_with_temporal_policy(
    compact: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    decode_verify_jwt_claims_json_with_temporal_policy_core(
        compact,
        jwk,
        public_key,
        now_unix,
        temporal_policy,
        header_validation,
    )
}

/// Verifies a signed JWT and applies temporal and registered-claims policy.
pub(crate) fn verify_jwt_with_claims_policy(
    compact: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    claims_policy: JwtClaimsValidationPolicy<'_>,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    decode_verify_jwt_claims_json_with_claims_policy_core(
        compact,
        jwk,
        public_key,
        now_unix,
        claims_policy,
        header_validation,
    )
}
