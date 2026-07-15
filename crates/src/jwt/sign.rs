// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "wire")]
use serde::Deserialize;
use serde::Serialize;

use reallyme_crypto::dispatch::{sign, verify};
use zeroize::Zeroizing;

use reallyme_codec::base64url::bytes_to_base64url;

use crate::jws::parse_compact::build_sig_structure;
use crate::{
    jws::suites::es256::{sign_p256_jose_prehash, verify_p256_jose_prehash},
    Algorithm, Jwk, Signer,
};

#[cfg(feature = "wire")]
use super::strict_json::reject_duplicate_object_members;
use super::{
    algorithm_from_jwt_alg,
    parse_compact::MAX_COMPACT_JWT_BYTES,
    validate_header::{select_jwk_algorithm, select_jwk_key_id, JwtHeader, JwtHeaderEncodeOptions},
    JwtError,
};

const ECDSA_JOSE_SIGNATURE_LEN: usize = 64;
const ED25519_SIGNATURE_LEN: usize = 64;

struct EncodedJwtSigningInput {
    signing_input: Vec<u8>,
    protected_header: String,
    payload: String,
}

/// Encode and sign a JWT.
///
/// - JWK supplies `alg`, `kid`
/// - Private key bytes are provided explicitly
///
/// # Errors
///
/// Returns [`JwtError`] when the JWK lacks a supported algorithm binding, claim
/// serialization fails, length arithmetic overflows, the private key/signature
/// is invalid for the selected algorithm, or the crypto backend fails.
pub fn encode_signed_jwt<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    private_key: &[u8],
) -> Result<String, JwtError> {
    encode_signed_jwt_with_header_options(claims, jwk, private_key, &JwtHeaderEncodeOptions::jwt())
}

/// Encode and sign a JWT with explicit JOSE header options.
///
/// # Errors
///
/// Returns [`JwtError`] for unsupported or mismatched JWK metadata, invalid
/// signing key material, serialization failure, length overflow, or crypto
/// backend failure.
pub fn encode_signed_jwt_with_header_options<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    private_key: &[u8],
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    let alg = select_jwk_algorithm(jwk)?;
    let payload_json =
        Zeroizing::new(serde_json::to_vec(claims).map_err(|_| JwtError::Serialization)?);
    let signing_input =
        encode_signing_input(&payload_json, &alg, select_jwk_key_id(jwk), header_options)?;
    let crypto_alg = algorithm_from_jwt_alg(&alg)?;
    let sig = sign_jwt_signature(crypto_alg, private_key, &signing_input.signing_input)?;
    validate_signature_key_binding(crypto_alg, jwk, &signing_input.signing_input, &sig)?;

    encode_signed_compact_jwt(signing_input, &sig)
}

/// Encode and sign a JWT using an abstract signer (HSM/QSCD/remote-sign friendly).
///
/// - JWK supplies `alg`, `kid`
/// - Signer supplies algorithm + signature bytes
///
/// # Errors
///
/// Returns [`JwtError`] if the signer algorithm does not match the JWK, if the
/// signer fails, if the returned signature is malformed for JOSE, or if compact
/// serialization fails.
pub fn encode_signed_jwt_with_signer<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    signer: &dyn Signer,
) -> Result<String, JwtError> {
    encode_signed_jwt_with_signer_and_header_options(
        claims,
        jwk,
        signer,
        &JwtHeaderEncodeOptions::jwt(),
    )
}

/// Encode and sign a JWT with explicit JOSE header options using an abstract signer.
///
/// # Errors
///
/// Returns [`JwtError`] for unsupported JWK metadata, signer/JWK algorithm
/// mismatch, signer failure, malformed signatures, serialization failure, or
/// length overflow.
pub fn encode_signed_jwt_with_signer_and_header_options<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    signer: &dyn Signer,
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    let alg = select_jwk_algorithm(jwk)?;
    let payload_json =
        Zeroizing::new(serde_json::to_vec(claims).map_err(|_| JwtError::Serialization)?);
    let signing_input =
        encode_signing_input(&payload_json, &alg, select_jwk_key_id(jwk), header_options)?;
    let crypto_alg = algorithm_from_jwt_alg(&alg)?;
    if signer.alg() != crypto_alg {
        return Err(JwtError::AlgorithmMismatch);
    }

    let backend_sig = signer
        .sign(&signing_input.signing_input)
        .map_err(|_| JwtError::Crypto)?;
    let sig = encode_signature_for_jwt(crypto_alg, backend_sig)?;
    validate_signature_key_binding(crypto_alg, jwk, &signing_input.signing_input, &sig)?;

    encode_signed_compact_jwt(signing_input, &sig)
}

#[cfg(feature = "wire")]
pub(crate) fn encode_signed_jwt_claims_json(
    claims_json: &[u8],
    jwk: &Jwk,
    private_key: &[u8],
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    reject_duplicate_object_members(claims_json)?;
    let mut deserializer = serde_json::Deserializer::from_slice(claims_json);
    serde::de::IgnoredAny::deserialize(&mut deserializer).map_err(|_| JwtError::InvalidClaims)?;
    deserializer.end().map_err(|_| JwtError::InvalidClaims)?;

    let alg = select_jwk_algorithm(jwk)?;
    let signing_input =
        encode_signing_input(claims_json, &alg, select_jwk_key_id(jwk), header_options)?;
    let crypto_alg = algorithm_from_jwt_alg(&alg)?;
    let signature = sign_jwt_signature(crypto_alg, private_key, &signing_input.signing_input)?;
    validate_signature_key_binding(crypto_alg, jwk, &signing_input.signing_input, &signature)?;
    encode_signed_compact_jwt(signing_input, &signature)
}

fn encode_signing_input(
    claims_json: &[u8],
    alg: &str,
    kid: Option<String>,
    header_options: &JwtHeaderEncodeOptions,
) -> Result<EncodedJwtSigningInput, JwtError> {
    let header = JwtHeader {
        alg: alg.to_string(),
        typ: header_options.typ.clone(),
        kid,
        embedded_key_header: false,
    };

    let header_json =
        Zeroizing::new(serde_json::to_vec(&header).map_err(|_| JwtError::Serialization)?);
    let protected_header = bytes_to_base64url(&header_json);
    let payload = bytes_to_base64url(claims_json);
    let signing_input = build_sig_structure(&protected_header, &payload, JwtError::LengthOverflow)?;

    Ok(EncodedJwtSigningInput {
        signing_input,
        protected_header,
        payload,
    })
}

fn encode_signed_compact_jwt(
    signing_input: EncodedJwtSigningInput,
    signature: &[u8],
) -> Result<String, JwtError> {
    let signature = bytes_to_base64url(signature);
    let len = signing_input
        .protected_header
        .len()
        .checked_add(1)
        .and_then(|with_separator| with_separator.checked_add(signing_input.payload.len()))
        .and_then(|with_payload| with_payload.checked_add(1))
        .and_then(|with_separator| with_separator.checked_add(signature.len()))
        .ok_or(JwtError::LengthOverflow)?;
    if len > MAX_COMPACT_JWT_BYTES {
        return Err(JwtError::InputTooLarge);
    }

    let mut jwt = String::with_capacity(len);
    jwt.push_str(&signing_input.protected_header);
    jwt.push('.');
    jwt.push_str(&signing_input.payload);
    jwt.push('.');
    jwt.push_str(&signature);
    Ok(jwt)
}

fn validate_signature_key_binding(
    alg: Algorithm,
    jwk: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwtError> {
    let public_key = jwk
        .public_key_bytes()
        .map_err(|_| JwtError::InvalidPublicKey)?;
    match alg {
        Algorithm::P256 => verify_p256_jose_prehash(signature, signing_input, &public_key)
            .map_err(|_| JwtError::SigningKeyMismatch),
        Algorithm::Secp256k1 | Algorithm::Ed25519 => {
            verify(alg, &public_key, signing_input, signature)
                .map_err(|_| JwtError::SigningKeyMismatch)
        }
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

fn encode_signature_for_jwt(alg: Algorithm, backend_sig: Vec<u8>) -> Result<Vec<u8>, JwtError> {
    match alg {
        // ES256: crypto dispatch gives DER, JWT needs raw fixed-width r||s.
        Algorithm::P256 => {
            let sig = reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature(&backend_sig)
                .map_err(|_| JwtError::InvalidSignature)?;
            Ok(sig.to_vec())
        }

        // ES256K: crypto dispatch already gives raw fixed-width r||s.
        Algorithm::Secp256k1 => {
            if backend_sig.len() != ECDSA_JOSE_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(backend_sig)
        }

        // EdDSA: already raw, but still require RFC 8032's fixed width before
        // key-binding verification so malformed signer output stays distinct
        // from a valid signature made by the wrong key.
        Algorithm::Ed25519 => {
            if backend_sig.len() != ED25519_SIGNATURE_LEN {
                return Err(JwtError::InvalidSignature);
            }
            Ok(backend_sig)
        }

        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

fn sign_jwt_signature(
    alg: Algorithm,
    private_key: &[u8],
    signing_input: &[u8],
) -> Result<Vec<u8>, JwtError> {
    match alg {
        Algorithm::P256 => sign_p256_jose_prehash(private_key, signing_input)
            .map(|signature| signature.to_vec())
            .map_err(|_| JwtError::Crypto),
        Algorithm::Secp256k1 | Algorithm::Ed25519 => {
            let signature = sign(alg, private_key, signing_input).map_err(|_| JwtError::Crypto)?;
            encode_signature_for_jwt(alg, signature)
        }
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}
