// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::dispatch::sign;

use crate::{jws::suites::es256::sign_p256_jose_prehash, Algorithm, Jwk, Signer};

use super::{
    algorithm_from_jwt_alg,
    validate_header::{select_jwk_algorithm, select_jwk_key_id, JwtHeader, JwtHeaderEncodeOptions},
    JwtError,
};

const ECDSA_JOSE_SIGNATURE_LEN: usize = 64;

/// Encode and sign a JWT.
///
/// - JWK supplies `alg`, `kid`
/// - Private key bytes are provided explicitly
pub fn encode_signed_jwt<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    private_key: &[u8],
) -> Result<String, JwtError> {
    encode_signed_jwt_with_header_options(claims, jwk, private_key, &JwtHeaderEncodeOptions::jwt())
}

/// Encode and sign a JWT with explicit JOSE header options.
pub fn encode_signed_jwt_with_header_options<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    private_key: &[u8],
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    let alg = select_jwk_algorithm(jwk)?;
    let signing_input = encode_signing_input(claims, &alg, select_jwk_key_id(jwk), header_options)?;
    let crypto_alg = algorithm_from_jwt_alg(&alg)?;
    let sig = sign_jwt_signature(crypto_alg, private_key, signing_input.as_bytes())?;

    Ok(format!("{}.{}", signing_input, bytes_to_base64url(&sig)))
}

/// Encode and sign a JWT using an abstract signer (HSM/QSCD/remote-sign friendly).
///
/// - JWK supplies `alg`, `kid`
/// - Signer supplies algorithm + signature bytes
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
pub fn encode_signed_jwt_with_signer_and_header_options<C: Serialize>(
    claims: &C,
    jwk: &Jwk,
    signer: &dyn Signer,
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    let alg = select_jwk_algorithm(jwk)?;
    let signing_input = encode_signing_input(claims, &alg, select_jwk_key_id(jwk), header_options)?;
    let crypto_alg = algorithm_from_jwt_alg(&alg)?;
    if signer.alg() != crypto_alg {
        return Err(JwtError::AlgorithmMismatch);
    }

    let backend_sig = signer
        .sign(signing_input.as_bytes())
        .map_err(|_| JwtError::Crypto)?;
    let sig = encode_signature_for_jwt(crypto_alg, backend_sig)?;

    Ok(format!("{}.{}", signing_input, bytes_to_base64url(&sig)))
}

fn encode_signing_input<C: Serialize>(
    claims: &C,
    alg: &str,
    kid: Option<String>,
    header_options: &JwtHeaderEncodeOptions,
) -> Result<String, JwtError> {
    let header = JwtHeader {
        alg: alg.to_string(),
        typ: header_options.typ.clone(),
        kid,
        embedded_key_header: false,
    };

    let header_b64 =
        bytes_to_base64url(&serde_json::to_vec(&header).map_err(|_| JwtError::Serialization)?);
    let payload_b64 =
        bytes_to_base64url(&serde_json::to_vec(claims).map_err(|_| JwtError::Serialization)?);

    Ok(format!("{}.{}", header_b64, payload_b64))
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

        // EdDSA: already raw.
        Algorithm::Ed25519 => Ok(backend_sig),

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
