// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;

use crate::jws::suites::es256::verify_p256_jose_prehash;
use crate::{Algorithm, Jwk};
use reallyme_codec::base64url::base64url_bytes_to_bytes;
use reallyme_crypto::dispatch::verify;

use super::{
    algorithm_from_jwt_alg,
    parse_compact::parse_compact_jwt,
    validate_header::{select_jwk_algorithm, JwtHeader, JwtHeaderValidationOptions},
    validate_temporal_claims::{validate_temporal_claims, JwtTemporalValidationPolicy},
    JwtError,
};

const ECDSA_JOSE_SIGNATURE_LEN: usize = 64;

/// Decode and verify a signed JWT (signature-only).
///
/// - JWK supplies `alg`
/// - Public key bytes are provided explicitly
///
/// This function intentionally does not enforce temporal claims (`exp`/`nbf`/`iat`).
/// Use [`decode_verify_jwt_with_temporal_validation`] in verifier-grade paths.
pub fn decode_verify_jwt_signature_only<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
) -> Result<C, JwtError> {
    decode_verify_jwt_signature_only_with_header_validation(
        jwt,
        jwk,
        public_key,
        &JwtHeaderValidationOptions::standard_jwt(),
    )
}

/// Decode and verify a signed JWT using explicit JOSE header validation.
pub fn decode_verify_jwt_signature_only_with_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = decode_verify_jwt_payload(jwt, jwk, public_key, header_validation)?;
    serde_json::from_value(payload).map_err(|_| JwtError::Serialization)
}

/// Decode and verify a signed JWT with explicit temporal claim validation.
pub fn decode_verify_jwt_with_temporal_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
) -> Result<C, JwtError> {
    decode_verify_jwt_with_temporal_validation_and_header_validation(
        jwt,
        jwk,
        public_key,
        now_unix,
        temporal_policy,
        &JwtHeaderValidationOptions::standard_jwt(),
    )
}

/// Decode and verify a signed JWT with explicit temporal and JOSE header validation.
pub fn decode_verify_jwt_with_temporal_validation_and_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = decode_verify_jwt_payload(jwt, jwk, public_key, header_validation)?;

    validate_temporal_claims(&payload, now_unix, temporal_policy)?;

    serde_json::from_value(payload).map_err(|_| JwtError::Serialization)
}

fn decode_verify_jwt_payload(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<JsonValue, JwtError> {
    let parts = parse_compact_jwt(jwt)?;

    let header: JwtHeader = serde_json::from_slice(&base64url_bytes_to_bytes(
        parts.protected_header.as_bytes(),
    )?)
    .map_err(|_| JwtError::InvalidHeader)?;

    header.validate_with_options(header_validation)?;

    let expected_alg = select_jwk_algorithm(jwk)?;
    if header.alg != expected_alg {
        return Err(JwtError::AlgorithmMismatch);
    }

    let crypto_alg = algorithm_from_jwt_alg(&header.alg)?;
    let signing_input = format!("{}.{}", parts.protected_header, parts.payload);
    let raw = base64url_bytes_to_bytes(parts.signature.as_bytes())?;
    verify_jwt_signature(crypto_alg, public_key, signing_input.as_bytes(), raw)?;

    serde_json::from_slice(&base64url_bytes_to_bytes(parts.payload.as_bytes())?)
        .map_err(|_| JwtError::Serialization)
}

fn signature_for_verifier(alg: Algorithm, raw: Vec<u8>) -> Result<Vec<u8>, JwtError> {
    match alg {
        // ES256K: JWT provides raw fixed-width r||s; dispatch verifies raw.
        Algorithm::Secp256k1 => {
            if raw.len() != ECDSA_JOSE_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(raw)
        }

        // EdDSA: already raw.
        Algorithm::Ed25519 => Ok(raw),

        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

fn verify_jwt_signature(
    alg: Algorithm,
    public_key: &[u8],
    signing_input: &[u8],
    raw: Vec<u8>,
) -> Result<(), JwtError> {
    match alg {
        Algorithm::P256 => verify_p256_jose_prehash(&raw, signing_input, public_key)
            .map_err(|_| JwtError::InvalidSignature),
        Algorithm::Secp256k1 | Algorithm::Ed25519 => {
            let sig = signature_for_verifier(alg, raw)?;
            verify(alg, public_key, signing_input, &sig).map_err(|_| JwtError::InvalidSignature)
        }
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}
