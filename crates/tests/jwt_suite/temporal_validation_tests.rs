#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::gen_ed25519;
use reallyme_jose::jwt::{
    decode_verify_jwt_with_temporal_validation, encode_signed_jwt, encode_unsigned_jwt, JwtError,
    JwtTemporalClaim, JwtTemporalValidationPolicy,
};

const NOW_UNIX: u64 = 1_720_000_000;

#[test]
fn strict_temporal_rejects_missing_exp() {
    let k = gen_ed25519();
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
    });

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let err = decode_verify_jwt_with_temporal_validation::<serde_json::Value>(
        &jwt,
        &k.jwk,
        &k.public,
        NOW_UNIX,
        JwtTemporalValidationPolicy::strict(),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        JwtError::MissingRequiredTemporalClaim(JwtTemporalClaim::Exp)
    ));
}

#[test]
fn strict_temporal_rejects_expired_token() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX - 61,
    }));

    assert!(matches!(err, JwtError::Expired));
}

#[test]
fn strict_temporal_accepts_expiration_inside_clock_skew() {
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX - 60,
    });

    let decoded = verify_claims(&claims, JwtTemporalValidationPolicy::strict()).unwrap();

    assert_eq!(decoded["iss"], "did:me:test");
}

#[test]
fn temporal_accepts_nbf_and_iat_at_skew_boundaries() {
    let policy = JwtTemporalValidationPolicy::new(true, true, true, 60, 60);
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
        "nbf": NOW_UNIX + 60,
        "iat": NOW_UNIX + 60
    });

    let decoded = verify_claims(&claims, policy).unwrap();

    assert_eq!(decoded["sub"], "alice");
}

#[test]
fn strict_temporal_rejects_future_nbf_outside_clock_skew() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
        "nbf": NOW_UNIX + 61,
    }));

    assert!(matches!(err, JwtError::NotYetValid));
}

#[test]
fn strict_temporal_rejects_future_iat_outside_policy_skew() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
        "iat": NOW_UNIX + 61,
    }));

    assert!(matches!(err, JwtError::IssuedAtInFuture));
}

#[test]
fn strict_temporal_rejects_zero_numeric_date() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": 0,
    }));

    assert!(matches!(
        err,
        JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Exp)
    ));
}

#[test]
fn strict_temporal_rejects_non_integer_numeric_date() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": "1720000300",
    }));

    assert!(matches!(
        err,
        JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Exp)
    ));
}

#[test]
fn strict_temporal_rejects_negative_numeric_date() {
    let err = temporal_error_for_claims(serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": -1,
    }));

    assert!(matches!(
        err,
        JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Exp)
    ));
}

#[test]
fn strict_temporal_rejects_huge_numeric_date() {
    let claims: serde_json::Value =
        serde_json::from_str(r#"{"iss":"did:me:test","sub":"alice","exp":18446744073709551616}"#)
            .unwrap();

    let err = temporal_error_for_claims(claims);

    assert!(matches!(
        err,
        JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Exp)
    ));
}

#[test]
fn temporal_rejects_missing_required_nbf_and_iat() {
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
    });
    let nbf_policy = JwtTemporalValidationPolicy::new(true, true, false, 60, 60);
    let iat_policy = JwtTemporalValidationPolicy::new(true, false, true, 60, 60);

    let nbf_err = verify_claims(&claims, nbf_policy).unwrap_err();
    let iat_err = verify_claims(&claims, iat_policy).unwrap_err();

    assert!(matches!(
        nbf_err,
        JwtError::MissingRequiredTemporalClaim(JwtTemporalClaim::Nbf)
    ));
    assert!(matches!(
        iat_err,
        JwtError::MissingRequiredTemporalClaim(JwtTemporalClaim::Iat)
    ));
}

#[test]
fn temporal_rejects_unbounded_clock_skew_policy() {
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX - 10,
    });
    let policy = JwtTemporalValidationPolicy::new(true, false, false, u64::MAX, 60);

    let err = verify_claims(&claims, policy).unwrap_err();

    assert!(matches!(err, JwtError::InvalidTemporalPolicy));
}

#[test]
fn temporal_rejects_unbounded_future_iat_skew_policy() {
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
        "iat": NOW_UNIX + 10,
    });
    let policy = JwtTemporalValidationPolicy::new(true, false, true, 60, u64::MAX);

    let err = verify_claims(&claims, policy).unwrap_err();

    assert!(matches!(err, JwtError::InvalidTemporalPolicy));
}

#[test]
fn temporal_rejects_checked_time_ceiling_overflow() {
    let k = gen_ed25519();
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": u64::MAX,
        "nbf": u64::MAX,
    });
    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();
    let policy = JwtTemporalValidationPolicy::new(true, true, false, 60, 60);

    let err = decode_verify_jwt_with_temporal_validation::<serde_json::Value>(
        &jwt,
        &k.jwk,
        &k.public,
        u64::MAX - 1,
        policy,
    )
    .unwrap_err();

    assert!(matches!(err, JwtError::InvalidTemporalPolicy));
}

#[test]
fn signed_verifier_rejects_unsigned_jwt() {
    let k = gen_ed25519();
    let claims = serde_json::json!({
        "iss": "did:me:test",
        "sub": "alice",
        "exp": NOW_UNIX + 300,
    });
    let jwt = encode_unsigned_jwt(&claims).unwrap();

    let err = decode_verify_jwt_with_temporal_validation::<serde_json::Value>(
        &jwt,
        &k.jwk,
        &k.public,
        NOW_UNIX,
        JwtTemporalValidationPolicy::strict(),
    )
    .unwrap_err();

    assert!(matches!(err, JwtError::InvalidHeader));
}

fn verify_claims(
    claims: &serde_json::Value,
    policy: JwtTemporalValidationPolicy,
) -> Result<serde_json::Value, JwtError> {
    let k = gen_ed25519();
    let jwt = encode_signed_jwt(claims, &k.jwk, &k.private).unwrap();

    decode_verify_jwt_with_temporal_validation::<serde_json::Value>(
        &jwt, &k.jwk, &k.public, NOW_UNIX, policy,
    )
}

fn temporal_error_for_claims(claims: serde_json::Value) -> JwtError {
    verify_claims(&claims, JwtTemporalValidationPolicy::strict()).unwrap_err()
}
