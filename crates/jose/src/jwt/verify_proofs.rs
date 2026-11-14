// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bind_verification_algorithm, validate_signed_header, Algorithm, JwtError,
    JwtHeaderValidationOptions,
};

fn signed_algorithm() -> Algorithm {
    match kani::any::<u8>() {
        0 => Algorithm::Ed25519,
        1 => Algorithm::P256,
        _ => Algorithm::Secp256k1,
    }
}

#[kani::proof]
fn verification_dispatch_requires_matching_algorithms() {
    let protected = signed_algorithm();
    let key = signed_algorithm();
    let result = bind_verification_algorithm(protected, key);
    match (protected, key) {
        (Algorithm::Ed25519, Algorithm::Ed25519) => {
            kani::assert(
                matches!(result, Ok(Algorithm::Ed25519)),
                "EdDSA uses Ed25519",
            );
        }
        (Algorithm::P256, Algorithm::P256) => {
            kani::assert(matches!(result, Ok(Algorithm::P256)), "ES256 uses P-256");
        }
        (Algorithm::Secp256k1, Algorithm::Secp256k1) => {
            kani::assert(
                matches!(result, Ok(Algorithm::Secp256k1)),
                "ES256K uses secp256k1",
            );
        }
        _ => {
            kani::assert(
                matches!(result, Err(JwtError::AlgorithmMismatch)),
                "a different protected algorithm cannot override the caller's key algorithm",
            );
        }
    }

    kani::cover!(
        matches!(&result, Ok(Algorithm::Ed25519)),
        "matching Ed25519"
    );
    kani::cover!(matches!(&result, Ok(Algorithm::P256)), "matching P-256");
    kani::cover!(
        matches!(&result, Ok(Algorithm::Secp256k1)),
        "matching secp256k1"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::AlgorithmMismatch)),
        "algorithm mismatch"
    );
}

#[kani::proof]
fn signed_header_rejects_none_under_all_policy_flags() {
    let allow_missing_type = kani::any::<bool>();
    let allow_embedded = kani::any::<bool>();
    let embedded = kani::any::<bool>();
    let options = JwtHeaderValidationOptions::new(allow_missing_type, allow_embedded, &[]);
    let result = validate_signed_header("none", None, embedded, &options);
    kani::assert(
        matches!(result, Err(JwtError::InvalidHeader)),
        "unsigned tokens are rejected even by permissive signed header policy",
    );
    kani::cover!(
        allow_missing_type && allow_embedded && embedded,
        "unsigned header with embedded metadata under permissive policy"
    );
}
