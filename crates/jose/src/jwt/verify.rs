// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::de::DeserializeOwned;

use crate::jws::{parse_compact::build_sig_structure, suites::es256::verify_p256_jose_prehash};
use crate::reject_duplicate_json_members::reject_duplicate_json_members;
use crate::verify_signed_payload::verify_signed_payload;
use crate::{Algorithm, Jwk, Zeroizing};
use reallyme_codec::base64url::base64url_bytes_to_bytes;
use reallyme_crypto::core::{CryptoError, CryptoErrorReason};
use reallyme_crypto::dispatch::verify;

use super::{
    algorithm_from_jwt_alg,
    parse_compact::parse_compact_jwt,
    strict_json::{parse_sensitive_json, reject_duplicate_object_members},
    validate_header::{
        select_jwk_algorithm, select_jwk_key_id, validate_signed_header, JwtHeader,
        JwtHeaderValidationOptions,
    },
    validate_registered_claims::{
        validate_claims_set, validate_registered_claims, JwtClaimsValidationPolicy,
    },
    validate_temporal_claims::{validate_temporal_claims, JwtTemporalValidationPolicy},
    JwtError,
};

const ECDSA_JOSE_SIGNATURE_LEN: usize =
    crate::resolve_algorithm::JwtAlgorithm::Es256k.signature_len();
const ED25519_SIGNATURE_LEN: usize = crate::resolve_algorithm::JwtAlgorithm::Eddsa.signature_len();

/// Decode and verify a signed JWT (signature-only).
///
/// - JWK supplies `alg`
/// - Public key bytes are provided explicitly
///
/// This function intentionally does not enforce temporal claims (`exp`/`nbf`/`iat`)
/// or recipient constraints (`aud`/`iss`/`sub`). Use
/// [`decode_verify_jwt_with_claims_validation`] in verifier-grade paths.
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
/// failures. This function does not enforce temporal or registered-claim
/// policy.
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
/// fails. This function does not enforce temporal or registered-claim policy.
pub fn decode_verify_jwt_claims_json_signature_only_with_header_validation(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    crate::operation_contract::jwt::verify_jwt_signature_only(
        jwt,
        jwk,
        public_key,
        header_validation,
    )
}

pub(crate) fn decode_verify_jwt_claims_json_signature_only_core(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let payload = decode_verify_jwt_payload_bytes(jwt, jwk, public_key, header_validation)?;
    reject_duplicate_object_members(&payload)?;
    let payload_value = parse_sensitive_json(&payload)?;
    let _claims = validate_claims_set(&payload_value)?;
    Ok(payload)
}

/// Decode and verify a signed JWT with explicit temporal claim validation.
///
/// # Errors
///
/// Returns [`JwtError`] for any signature-only verification failure, malformed
/// claims JSON, missing required temporal claims, invalid NumericDate values,
/// expired tokens, not-yet-valid tokens, or future `iat` values.
///
/// This compatibility API does not validate `aud`, `iss`, or `sub`. New
/// verifier code must use [`decode_verify_jwt_with_claims_validation`].
#[deprecated(
    since = "0.3.0",
    note = "use decode_verify_jwt_with_claims_validation to enforce audience and identity claims"
)]
pub fn decode_verify_jwt_with_temporal_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
) -> Result<C, JwtError> {
    let payload = crate::operation_contract::jwt::verify_jwt_with_temporal_policy(
        jwt,
        jwk,
        public_key,
        now_unix,
        temporal_policy,
        &JwtHeaderValidationOptions::standard_jwt(),
    )?;
    serde_json::from_slice(&payload).map_err(|_| JwtError::Serialization)
}

/// Decode and verify a signed JWT with explicit temporal and JOSE header validation.
///
/// # Errors
///
/// Returns [`JwtError`] for compact/header/key/signature failures, claims
/// decoding failures, or temporal policy failures.
///
/// This compatibility API does not validate `aud`, `iss`, or `sub`. New
/// verifier code must use
/// [`decode_verify_jwt_with_claims_validation_and_header_validation`].
#[deprecated(
    since = "0.3.0",
    note = "use decode_verify_jwt_with_claims_validation_and_header_validation"
)]
pub fn decode_verify_jwt_with_temporal_validation_and_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = crate::operation_contract::jwt::verify_jwt_with_temporal_policy(
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
///
/// This compatibility API does not validate `aud`, `iss`, or `sub`.
#[deprecated(
    since = "0.3.0",
    note = "use decode_verify_jwt_claims_json_with_claims_validation_and_header_validation"
)]
pub fn decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    crate::operation_contract::jwt::verify_jwt_with_temporal_policy(
        jwt,
        jwk,
        public_key,
        now_unix,
        temporal_policy,
        header_validation,
    )
}

/// Decodes and verifies a signed JWT with audience, optional identity, and
/// temporal validation.
///
/// The claims policy always requires an expected audience. Configured issuer
/// and subject values are also required to match exactly.
///
/// # Errors
///
/// Returns [`JwtError`] for signature/header/key failures, invalid claims,
/// unsafe policy or verification time, temporal failures, missing required
/// registered claims, or audience/issuer/subject mismatches.
pub fn decode_verify_jwt_with_claims_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    claims_policy: JwtClaimsValidationPolicy<'_>,
) -> Result<C, JwtError> {
    decode_verify_jwt_with_claims_validation_and_header_validation(
        jwt,
        jwk,
        public_key,
        now_unix,
        claims_policy,
        &JwtHeaderValidationOptions::standard_jwt(),
    )
}

/// Decodes and verifies a signed JWT with explicit claims and JOSE header
/// validation.
///
/// # Errors
///
/// Returns [`JwtError`] for signature/header/key failures, invalid claims,
/// unsafe policy or verification time, temporal failures, missing required
/// registered claims, or audience/issuer/subject mismatches.
pub fn decode_verify_jwt_with_claims_validation_and_header_validation<C: DeserializeOwned>(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    claims_policy: JwtClaimsValidationPolicy<'_>,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<C, JwtError> {
    let payload = decode_verify_jwt_claims_json_with_claims_validation_and_header_validation(
        jwt,
        jwk,
        public_key,
        now_unix,
        claims_policy,
        header_validation,
    )?;

    serde_json::from_slice(&payload).map_err(|_| JwtError::Serialization)
}

/// Decodes and verifies a signed JWT with explicit claims and JOSE header
/// validation, returning original claims JSON bytes in a zeroizing owner.
///
/// # Errors
///
/// Returns [`JwtError`] for signature/header/key failures, invalid claims,
/// unsafe policy or verification time, temporal failures, missing required
/// registered claims, or audience/issuer/subject mismatches.
pub fn decode_verify_jwt_claims_json_with_claims_validation_and_header_validation(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    claims_policy: JwtClaimsValidationPolicy<'_>,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    crate::operation_contract::jwt::verify_jwt_with_claims_policy(
        jwt,
        jwk,
        public_key,
        now_unix,
        claims_policy,
        header_validation,
    )
}

pub(crate) fn decode_verify_jwt_claims_json_with_temporal_policy_core(
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

pub(crate) fn decode_verify_jwt_claims_json_with_claims_policy_core(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    now_unix: u64,
    claims_policy: JwtClaimsValidationPolicy<'_>,
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let payload = decode_verify_jwt_payload_bytes(jwt, jwk, public_key, header_validation)?;
    reject_duplicate_object_members(&payload)?;
    let payload_value = parse_sensitive_json(&payload)?;
    validate_temporal_claims(&payload_value, now_unix, claims_policy.temporal_policy())?;
    validate_registered_claims(&payload_value, claims_policy)?;
    Ok(payload)
}

fn decode_verify_jwt_payload_bytes(
    jwt: &str,
    jwk: &Jwk,
    public_key: &[u8],
    header_validation: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let parts = parse_compact_jwt(jwt)?;
    verify_signed_payload(
        public_key,
        |caller_key| {
            authorize_jwt_header(parts.protected_header, jwk, caller_key, header_validation)
        },
        |caller_key, algorithm| {
            let signing_input = build_sig_structure(
                parts.protected_header,
                parts.payload,
                JwtError::LengthOverflow,
            )?;
            let raw = Zeroizing::new(base64url_bytes_to_bytes(parts.signature.as_bytes())?);
            verify_jwt_signature(*algorithm, caller_key, &signing_input, raw)
        },
        |_| {
            base64url_bytes_to_bytes(parts.payload.as_bytes())
                .map(Zeroizing::new)
                .map_err(JwtError::from)
        },
    )
}

fn authorize_jwt_header(
    encoded_header: &str,
    jwk: &Jwk,
    public_key: &[u8],
    policy: &JwtHeaderValidationOptions<'_>,
) -> Result<Algorithm, JwtError> {
    let header_bytes = Zeroizing::new(base64url_bytes_to_bytes(encoded_header.as_bytes())?);
    reject_duplicate_json_members(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;

    let crypto_alg = bind_verification_algorithm(
        validate_signed_header(
            &header.alg,
            header.typ.as_deref(),
            header.embedded_key_header,
            policy,
        )?,
        algorithm_from_jwt_alg(&select_jwk_algorithm(jwk)?)?,
    )?;
    validate_jwk_key_binding(header.kid.as_deref(), crypto_alg, jwk, public_key)?;
    Ok(crypto_alg)
}

fn bind_verification_algorithm(
    protected_algorithm: Algorithm,
    key_algorithm: Algorithm,
) -> Result<Algorithm, JwtError> {
    if protected_algorithm != key_algorithm {
        return Err(JwtError::AlgorithmMismatch);
    }

    // Dispatch on the caller's key binding once the protected algorithm agrees.
    Ok(key_algorithm)
}

#[cfg(kani)]
#[path = "verify_proofs.rs"]
mod proofs;

fn validate_jwk_key_binding(
    header_kid: Option<&str>,
    algorithm: Algorithm,
    jwk: &Jwk,
    public_key: &[u8],
) -> Result<(), JwtError> {
    let expected_kid = select_jwk_key_id(jwk);
    validate_key_id(header_kid, expected_kid.as_deref())?;

    let expected_public_key = jwk.public_key_bytes().map_err(map_jwk_public_key_error)?;
    // WebCrypto commonly exports the same P-256 point in uncompressed SEC1.
    // Canonicalize that representation before comparing it with JWK bytes.
    let normalized_public_key = if algorithm == Algorithm::P256 && public_key.len() == 65 {
        std::borrow::Cow::Owned(
            reallyme_crypto::p256::compress_public_key(public_key)
                .map_err(|_| JwtError::InvalidPublicKey)?,
        )
    } else {
        std::borrow::Cow::Borrowed(public_key)
    };
    validate_public_key_bytes(
        expected_public_key.as_slice(),
        normalized_public_key.as_ref(),
    )
}

fn validate_key_id(header: Option<&str>, expected: Option<&str>) -> Result<(), JwtError> {
    if let Some(expected) = expected {
        if header != Some(expected) {
            return Err(JwtError::KeyIdMismatch);
        }
    }
    Ok(())
}

fn validate_public_key_bytes(expected: &[u8], caller: &[u8]) -> Result<(), JwtError> {
    if expected == caller {
        Ok(())
    } else {
        Err(JwtError::PublicKeyMismatch)
    }
}

const fn map_jwk_public_key_error(error: CryptoError) -> JwtError {
    match error.reason() {
        // JWK extraction uses invalidParameter for incompatible key metadata.
        CryptoErrorReason::PrimitiveInvalidParameter
        | CryptoErrorReason::ProviderUnsupportedAlgorithm => JwtError::UnsupportedAlgorithm,
        _ => JwtError::InvalidPublicKey,
    }
}

const fn validate_raw_signature_for_verifier(alg: Algorithm, raw: &[u8]) -> Result<(), JwtError> {
    match alg {
        // ES256K: JWT provides raw fixed-width r||s; dispatch verifies raw.
        Algorithm::Secp256k1 => {
            if raw.len() != ECDSA_JOSE_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(())
        }

        Algorithm::Ed25519 => {
            if raw.len() != ED25519_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(())
        }

        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

fn verify_jwt_signature(
    alg: Algorithm,
    public_key: &[u8],
    signing_input: &[u8],
    raw: Zeroizing<Vec<u8>>,
) -> Result<(), JwtError> {
    match alg {
        Algorithm::P256 => verify_p256_jose_prehash(&raw, signing_input, public_key)
            .map_err(|_| JwtError::InvalidSignature),
        Algorithm::Secp256k1 | Algorithm::Ed25519 => {
            validate_raw_signature_for_verifier(alg, &raw)?;
            verify(alg, public_key, signing_input, &raw).map_err(|_| JwtError::InvalidSignature)
        }
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}
