#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::gen_ed25519;
use reallyme_jose::jwt::{
    decode_verify_jwt_with_claims_validation, encode_signed_jwt, JwtClaimsValidationPolicy,
    JwtError, JwtRegisteredClaim, JwtTemporalValidationPolicy,
};

const NOW_UNIX: u64 = 1_720_000_000;
const EXPECTED_AUDIENCE: &str = "service-b";
const EXPECTED_ISSUER: &str = "did:me:issuer";
const EXPECTED_SUBJECT: &str = "account-7";

#[test]
fn claims_policy_accepts_matching_string_audience() {
    let claims = base_claims(serde_json::json!(EXPECTED_AUDIENCE));

    let decoded = verify_claims(
        &claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap();

    assert_eq!(decoded["aud"], EXPECTED_AUDIENCE);
}

#[test]
fn claims_policy_accepts_expected_member_of_audience_array() {
    let claims = base_claims(serde_json::json!(["service-a", EXPECTED_AUDIENCE]));

    let decoded = verify_claims(
        &claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap();

    assert_eq!(decoded["aud"][1], EXPECTED_AUDIENCE);
}

#[test]
fn claims_policy_rejects_token_for_another_audience() {
    let claims = base_claims(serde_json::json!("service-a"));

    let error = verify_claims(
        &claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap_err();

    assert!(matches!(error, JwtError::AudienceMismatch));
}

#[test]
fn claims_policy_rejects_missing_and_empty_audience() {
    let missing_claims = serde_json::json!({
        "iss": EXPECTED_ISSUER,
        "sub": EXPECTED_SUBJECT,
        "exp": NOW_UNIX + 300,
    });
    let empty_claims = base_claims(serde_json::json!([]));

    let missing_error = verify_claims(
        &missing_claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap_err();
    let empty_error = verify_claims(
        &empty_claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap_err();

    assert!(matches!(
        missing_error,
        JwtError::MissingRequiredRegisteredClaim(JwtRegisteredClaim::Audience)
    ));
    assert!(matches!(
        empty_error,
        JwtError::InvalidRegisteredClaimValue(JwtRegisteredClaim::Audience)
    ));
}

#[test]
fn claims_policy_rejects_malformed_audience_array_even_after_match() {
    let claims = base_claims(serde_json::json!([EXPECTED_AUDIENCE, 7]));

    let error = verify_claims(
        &claims,
        JwtClaimsValidationPolicy::strict(EXPECTED_AUDIENCE),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        JwtError::InvalidRegisteredClaimValue(JwtRegisteredClaim::Audience)
    ));
}

#[test]
fn claims_policy_enforces_exact_issuer_and_subject() {
    let claims = base_claims(serde_json::json!(EXPECTED_AUDIENCE));
    let policy = constrained_policy(EXPECTED_ISSUER, EXPECTED_SUBJECT);

    let decoded = verify_claims(&claims, policy).unwrap();

    assert_eq!(decoded["iss"], EXPECTED_ISSUER);
    assert_eq!(decoded["sub"], EXPECTED_SUBJECT);
}

#[test]
fn claims_policy_rejects_issuer_and_subject_mismatches() {
    let wrong_issuer = serde_json::json!({
        "iss": "did:me:other",
        "sub": EXPECTED_SUBJECT,
        "aud": EXPECTED_AUDIENCE,
        "exp": NOW_UNIX + 300,
    });
    let wrong_subject = serde_json::json!({
        "iss": EXPECTED_ISSUER,
        "sub": "account-8",
        "aud": EXPECTED_AUDIENCE,
        "exp": NOW_UNIX + 300,
    });

    let issuer_error = verify_claims(
        &wrong_issuer,
        constrained_policy(EXPECTED_ISSUER, EXPECTED_SUBJECT),
    )
    .unwrap_err();
    let subject_error = verify_claims(
        &wrong_subject,
        constrained_policy(EXPECTED_ISSUER, EXPECTED_SUBJECT),
    )
    .unwrap_err();

    assert!(matches!(issuer_error, JwtError::IssuerMismatch));
    assert!(matches!(subject_error, JwtError::SubjectMismatch));
}

#[test]
fn claims_policy_rejects_missing_constrained_identity_claim() {
    let claims = serde_json::json!({
        "sub": EXPECTED_SUBJECT,
        "aud": EXPECTED_AUDIENCE,
        "exp": NOW_UNIX + 300,
    });

    let error = verify_claims(
        &claims,
        constrained_policy(EXPECTED_ISSUER, EXPECTED_SUBJECT),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        JwtError::MissingRequiredRegisteredClaim(JwtRegisteredClaim::Issuer)
    ));
}

#[test]
fn claims_policy_rejects_empty_expected_audience() {
    let claims = base_claims(serde_json::json!(EXPECTED_AUDIENCE));
    let policy =
        JwtClaimsValidationPolicy::new(JwtTemporalValidationPolicy::strict(), "", None, None);

    let error = verify_claims(&claims, policy).unwrap_err();

    assert!(matches!(error, JwtError::InvalidClaimsPolicy));
}

fn base_claims(audience: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "iss": EXPECTED_ISSUER,
        "sub": EXPECTED_SUBJECT,
        "aud": audience,
        "exp": NOW_UNIX + 300,
    })
}

fn constrained_policy<'a>(issuer: &'a str, subject: &'a str) -> JwtClaimsValidationPolicy<'a> {
    JwtClaimsValidationPolicy::new(
        JwtTemporalValidationPolicy::strict(),
        EXPECTED_AUDIENCE,
        Some(issuer),
        Some(subject),
    )
}

fn verify_claims(
    claims: &serde_json::Value,
    policy: JwtClaimsValidationPolicy<'_>,
) -> Result<serde_json::Value, JwtError> {
    let key = gen_ed25519();
    let compact = encode_signed_jwt(claims, &key.jwk, &key.private).unwrap();

    decode_verify_jwt_with_claims_validation(&compact, &key.jwk, &key.public, NOW_UNIX, policy)
}
