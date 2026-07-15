// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;

use crate::jws::{parse_compact::build_sig_structure, suites::es256::verify_p256_jose_prehash};
use crate::{Algorithm, Jwk, Zeroizing};
use reallyme_codec::base64url::base64url_bytes_to_bytes;
use reallyme_crypto::dispatch::verify;
use reallyme_crypto::jwk::JwtError as CryptoJwkError;

use super::{
    algorithm_from_jwt_alg,
    parse_compact::parse_compact_jwt,
    strict_json::{parse_sensitive_json, reject_duplicate_object_members},
    validate_header::{
        select_jwk_algorithm, select_jwk_key_id, JwtHeader, JwtHeaderValidationOptions,
    },
    validate_temporal_claims::{validate_temporal_claims, JwtTemporalValidationPolicy},
    JwtError,
};

const ECDSA_JOSE_SIGNATURE_LEN: usize = 64;
const ED25519_SIGNATURE_LEN: usize = 64;

/// Decode and verify a signed JWT (signature-only).
///
/// - JWK supplies `alg`
/// - Public key bytes are provided explicitly
///
/// This function intentionally does not enforce temporal claims (`exp`/`nbf`/`iat`).
/// Use [`decode_verify_jwt_with_temporal_validation`] in verifier-grade paths.
///
/// # Errors
///
/// Returns [`JwtError`] for malformed compact input, invalid header policy,
/// unsupported or mismatched algorithms, `kid` mismatch, JWK/public-key byte
/// mismatch, invalid signature, or claims deserialization failure.
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
///
/// # Errors
///
/// Returns [`JwtError`] for compact/JWS parsing failures, header-policy
/// violations, key binding failures, invalid signatures, or claims decoding
/// failures.
pub fn decode_verify_jwt_signature_only_with_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = decode_verify_jwt_claims_json_signature_only_with_header_validation(
        jwt,
        jwk,
        public_key,
        header_validation,
    )?;
    serde_json::from_slice(&payload).map_err(|_| JwtError::Serialization)
}

/// Decode and verify a signed JWT, returning the original claims JSON bytes.
///
/// This variant is intended for protobuf, FFI, and service adapters that need
/// to preserve the input JSON representation and own it in a zeroizing buffer.
///
/// # Errors
///
/// Returns [`JwtError`] when compact parsing, JOSE header validation,
/// JWK/public-key binding, signature verification, or claims JSON validation
/// fails.
pub fn decode_verify_jwt_claims_json_signature_only_with_header_validation(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let payload = decode_verify_jwt_payload_bytes(jwt, jwk, public_key, header_validation)?;
    reject_duplicate_object_members(&payload)?;
    let _payload_value = parse_sensitive_json(&payload)?;
    Ok(payload)
}

/// Decode and verify a signed JWT with explicit temporal claim validation.
///
/// # Errors
///
/// Returns [`JwtError`] for any signature-only verification failure, malformed
/// claims JSON, missing required temporal claims, invalid NumericDate values,
/// expired tokens, not-yet-valid tokens, or future `iat` values.
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
///
/// # Errors
///
/// Returns [`JwtError`] for compact/header/key/signature failures, claims
/// decoding failures, or temporal policy failures.
pub fn decode_verify_jwt_with_temporal_validation_and_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation(
        jwt,
        jwk,
        public_key,
        now_unix,
        temporal_policy,
        header_validation,
    )?;

    serde_json::from_slice(&payload).map_err(|_| JwtError::Serialization)
}

/// Decode and verify a signed JWT with temporal validation, returning original
/// claims JSON bytes in a zeroizing owner.
///
/// # Errors
///
/// Returns [`JwtError`] for compact/header/key/signature failures, invalid
/// claims JSON, or temporal policy failures.
pub fn decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let payload = decode_verify_jwt_payload_bytes(jwt, jwk, public_key, header_validation)?;
    reject_duplicate_object_members(&payload)?;
    let payload_value = parse_sensitive_json(&payload)?;
    validate_temporal_claims(&payload_value, now_unix, temporal_policy)?;
    Ok(payload)
}

fn decode_verify_jwt_payload_bytes(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let parts = parse_compact_jwt(jwt)?;

    let header_bytes = Zeroizing::new(base64url_bytes_to_bytes(parts.protected_header.as_bytes())?);
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;

    header.validate_with_options(header_validation)?;

    let expected_alg = select_jwk_algorithm(jwk)?;
    if header.alg != expected_alg {
        return Err(JwtError::AlgorithmMismatch);
    }
    validate_jwk_key_binding(&header, jwk, public_key)?;

    let crypto_alg = algorithm_from_jwt_alg(&header.alg)?;
    let signing_input = build_sig_structure(
        parts.protected_header,
        parts.payload,
        JwtError::LengthOverflow,
    )?;
    let raw = base64url_bytes_to_bytes(parts.signature.as_bytes())?;
    verify_jwt_signature(crypto_alg, public_key, &signing_input, raw)?;

    Ok(Zeroizing::new(base64url_bytes_to_bytes(
        parts.payload.as_bytes(),
    )?))
}

fn validate_jwk_key_binding(
    header: &JwtHeader,
    jwk: &Jwk,
    public_key: &[u8],
) -> Result<(), JwtError> {
    if let Some(expected_kid) = select_jwk_key_id(jwk) {
        if header.kid.as_deref() != Some(expected_kid.as_str()) {
            return Err(JwtError::KeyIdMismatch);
        }
    }

    let expected_public_key = jwk.public_key_bytes().map_err(map_jwk_public_key_error)?;
    if expected_public_key.as_slice() != public_key {
        return Err(JwtError::PublicKeyMismatch);
    }
    Ok(())
}

const fn map_jwk_public_key_error(error: CryptoJwkError) -> JwtError {
    match error {
        CryptoJwkError::UnsupportedKeyFormat | CryptoJwkError::EncodingError => {
            JwtError::UnsupportedAlgorithm
        }
        CryptoJwkError::InvalidMlDsa44Key
        | CryptoJwkError::InvalidMlDsa65Key
        | CryptoJwkError::InvalidP256Key
        | CryptoJwkError::InvalidSecp256k1Key
        | CryptoJwkError::InvalidEd25519Key
        | CryptoJwkError::InvalidX25519Key
        | CryptoJwkError::InvalidMlDsa87Key
        | CryptoJwkError::InvalidMlKem512Key
        | CryptoJwkError::InvalidMlKem768Key
        | CryptoJwkError::InvalidMlKem1024Key
        | CryptoJwkError::InvalidSlhDsaSha2128sKey
        | CryptoJwkError::InvalidXWing768Key
        | CryptoJwkError::InvalidXWing1024Key => JwtError::InvalidPublicKey,
    }
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

        Algorithm::Ed25519 => {
            if raw.len() != ED25519_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(raw)
        }

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
