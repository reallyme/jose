// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::JwtError;
use crate::Algorithm;

/// Maps a JWT `alg` header value to the corresponding crypto algorithm.
///
/// RFC 7518 + DID alignment
///
/// # Errors
///
/// Returns [`JwtError::UnsupportedAlgorithm`] for JWT algorithms outside the
/// ReallyMe JOSE profile.
pub fn algorithm_from_jwt_alg(alg: &str) -> Result<Algorithm, JwtError> {
    match alg {
        "ES256" => Ok(Algorithm::P256),
        "ES256K" => Ok(Algorithm::Secp256k1),
        "EdDSA" => Ok(Algorithm::Ed25519),
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}
