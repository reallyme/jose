// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_protected_algorithm, JwsAlgorithm};
use crate::jws::parse_header::forbidden_protected_member;

#[kani::proof]
#[kani::unwind(8)]
fn jws_rejects_key_indirection_and_critical_extensions() {
    let member = match kani::any::<u8>() {
        0 => "b64",
        1 => "crit",
        2 => "zip",
        3 => "jku",
        4 => "x5u",
        5 => "jwk",
        _ => "kid",
    };
    let rejected = forbidden_protected_member(member);
    kani::assert(
        rejected == (member != "kid"),
        "key references and unsupported critical features are forbidden, while kid is metadata",
    );
    kani::cover!(rejected && member == "jwk", "embedded JWK rejected");
    kani::cover!(rejected && member == "crit", "critical extension rejected");
    kani::cover!(!rejected, "noncritical key identifier allowed");
}

#[kani::proof]
fn compact_jws_requires_the_callers_selected_algorithm() {
    let protected_is_es256 = kani::any::<bool>();
    let caller_is_es256 = kani::any::<bool>();
    let protected = if protected_is_es256 {
        JwsAlgorithm::Es256
    } else {
        JwsAlgorithm::Eddsa
    };
    let caller = if caller_is_es256 {
        JwsAlgorithm::Es256
    } else {
        JwsAlgorithm::Eddsa
    };
    let result = validate_protected_algorithm(protected, caller, false);
    if protected_is_es256 == caller_is_es256 {
        kani::assert(result.is_ok(), "the matching suite is permitted");
    } else {
        kani::assert(
            result == Err(false),
            "a mismatched protected algorithm is rejected",
        );
    }
    kani::cover!(result.is_ok() && caller_is_es256, "matching ES256");
    kani::cover!(result.is_ok() && !caller_is_es256, "matching EdDSA");
    kani::cover!(
        result.is_err() && protected_is_es256,
        "ES256 header with an EdDSA caller"
    );
    kani::cover!(
        result.is_err() && !protected_is_es256,
        "EdDSA header with an ES256 caller"
    );
}
