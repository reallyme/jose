// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bind_verification_algorithm, validate_key_id, validate_public_key_bytes,
    validate_signed_header, Algorithm, JwtError, JwtHeaderValidationOptions,
};
use crate::jwt::validate_header::{forbidden_signed_header_member, validate_header_policy};

#[path = "verify_claims_proofs.rs"]
mod claims;

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

#[kani::proof]
fn signed_jwt_header_requires_each_configured_policy_check() {
    let allow_missing_type = kani::any::<bool>();
    let allow_embedded = kani::any::<bool>();
    let embedded_present = kani::any::<bool>();
    let type_matches = kani::any::<Option<bool>>();
    let options = JwtHeaderValidationOptions::new(allow_missing_type, allow_embedded, &[]);
    let result = validate_header_policy(type_matches, embedded_present, &options);
    let rejected = type_matches == Some(false)
        || (type_matches.is_none() && !allow_missing_type)
        || (embedded_present && !allow_embedded);

    if rejected {
        kani::assert(
            matches!(result, Err(JwtError::InvalidHeader)),
            "one policy failure is sufficient to reject the header",
        );
    } else {
        kani::assert(result.is_ok(), "the header satisfies all configured checks");
    }
    kani::cover!(
        result.is_err() && allow_missing_type && type_matches == Some(false) && !embedded_present,
        "a present mismatched type is rejected even when absence is allowed"
    );
    kani::cover!(
        result.is_err() && type_matches == Some(true) && embedded_present && !allow_embedded,
        "matching type cannot override a forbidden embedded key"
    );
    kani::cover!(
        result.is_ok() && type_matches == Some(true) && embedded_present && allow_embedded,
        "explicitly permitted embedded metadata"
    );
    kani::cover!(
        result.is_ok() && type_matches.is_none() && !embedded_present,
        "explicitly permitted missing type"
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn signed_jwt_rejects_remote_keys_and_critical_extensions_under_all_policy_flags() {
    let member = match kani::any::<u8>() {
        0 => "b64",
        1 => "crit",
        2 => "cty",
        3 => "zip",
        4 => "jku",
        5 => "x5u",
        _ => "kid",
    };
    let rejected = forbidden_signed_header_member(member);
    kani::assert(
        rejected == (member != "kid"),
        "remote key references and unsupported extensions are always forbidden",
    );
    kani::cover!(rejected && member == "jku", "remote JWK rejected");
    kani::cover!(rejected && member == "crit", "critical extension rejected");
    kani::cover!(!rejected, "key identifier goes to the binding check");
}

#[kani::proof]
#[kani::unwind(6)]
fn jwt_key_id_and_public_bytes_must_match_the_callers_binding() {
    let expected_id = kani::any::<Option<bool>>();
    let header_id = kani::any::<Option<bool>>();
    let id_text = |id| if id { "a" } else { "b" };

    let expected_bytes = kani::any::<[u8; 2]>();
    let caller_bytes = kani::any::<[u8; 2]>();
    let shorter = kani::any::<bool>();
    let caller = if shorter {
        &caller_bytes[..1]
    } else {
        caller_bytes.as_slice()
    };
    let id_result = validate_key_id(header_id.map(id_text), expected_id.map(id_text));
    let bytes_result = validate_public_key_bytes(&expected_bytes, caller);
    let requires_matching_id = expected_id.is_some() && header_id != expected_id;
    if requires_matching_id {
        kani::assert(
            matches!(id_result, Err(JwtError::KeyIdMismatch)),
            "the protected key identifier must match the caller JWK",
        );
    } else {
        kani::assert(
            id_result.is_ok(),
            "the caller's key identifier policy is satisfied",
        );
    }
    if shorter || caller_bytes != expected_bytes {
        kani::assert(
            matches!(bytes_result, Err(JwtError::PublicKeyMismatch)),
            "different key bytes fail even when the key identifier matches",
        );
    } else {
        kani::assert(
            bytes_result.is_ok(),
            "the caller's normalized key matches the JWK",
        );
    }

    kani::cover!(
        id_result.is_ok() && bytes_result.is_ok() && expected_id.is_some(),
        "matching key and identifier"
    );
    kani::cover!(
        id_result.is_err() && bytes_result.is_ok() && header_id.is_some(),
        "wrong identifier on the same key"
    );
    kani::cover!(
        id_result.is_ok() && bytes_result.is_err() && !shorter && expected_id.is_some(),
        "matching identifier with a different key"
    );
    kani::cover!(
        id_result.is_ok() && bytes_result.is_err() && shorter,
        "key length differs"
    );
}
