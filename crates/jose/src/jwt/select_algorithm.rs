// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    use crate::resolve_algorithm::JwtAlgorithm;
    JwtAlgorithm::from_jose_name(alg)
        .map(JwtAlgorithm::backend)
        .ok_or(JwtError::UnsupportedAlgorithm)
}
