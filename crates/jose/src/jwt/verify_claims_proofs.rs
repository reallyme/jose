// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references the models through stub attributes.
#![allow(dead_code)]

use core::borrow::Borrow;
use core::hash::Hash;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU8, Ordering};

use reallyme_codec::base64url::Base64UrlError;
use reallyme_crypto::jwk::OkpJwk;
use serde_json::{Map, Value};

use super::super::{
    decode_verify_jwt_claims_json_with_claims_validation_and_header_validation, Algorithm, Jwk,
    JwtClaimsValidationPolicy, JwtError, JwtHeaderValidationOptions, JwtTemporalValidationPolicy,
    Zeroizing,
};
use crate::jwt::{parse_compact::CompactJwtParts, strict_json::SensitiveJsonValue};

static CALLER_PUBLIC_KEY: [u8; 1] = [0xa7];
const CLAIMS_BYTES: &[u8] = &[2];
const NOT_BEFORE: u64 = 2;
const ISSUED_AT: u64 = 3;
const EXPIRATION: u64 = 5;
const AUDIENCE: &str = "a";
const ISSUER: &str = "i";
const SUBJECT: &str = "s";
const OTHER_IDENTITY: &str = "x";

const MALFORMED_COMPACT: u8 = 1;
const REJECTED_HEADER: u8 = 2;
const INVALID_SIGNATURE: u8 = 3;
const INVALID_PAYLOAD_ENCODING: u8 = 4;
const DUPLICATE_CLAIMS: u8 = 5;
const INVALID_CLAIMS_JSON: u8 = 6;

#[derive(Clone, Copy)]
#[repr(u8)]
enum Stage {
    Start,
    HeaderAuthorized,
    SignatureDecoded,
    SignatureVerified,
    ClaimsDecoded,
    ClaimsUnique,
    ClaimsParsed,
    TimeValidated,
    ClaimsValidated,
}

// These observations are local to the sequential harness execution.
static REJECTION: AtomicU8 = AtomicU8::new(0);
static STAGE: AtomicU8 = AtomicU8::new(Stage::Start as u8);

fn require_stage(expected: Stage) {
    kani::assert(
        STAGE.load(Ordering::Relaxed) == expected as u8,
        "an earlier JWT verification stage succeeded before this stage ran",
    );
}

fn advance_to(stage: Stage) {
    STAGE.store(stage as u8, Ordering::Relaxed);
}

fn rejected_at(case: u8) -> bool {
    REJECTION.load(Ordering::Relaxed) == case
}

fn parse_compact(compact: &str) -> Result<CompactJwtParts<'_>, JwtError> {
    require_stage(Stage::Start);
    if compact == "b" {
        return Err(JwtError::InvalidJwtFormat);
    }
    kani::assert(
        compact == "a",
        "the verifier parses the original compact token",
    );
    Ok(CompactJwtParts {
        protected_header: "h",
        payload: "p",
        signature: "s",
    })
}

fn authorize_header(
    header: &str,
    jwk: &Jwk,
    key: &[u8],
    _policy: &JwtHeaderValidationOptions<'_>,
) -> Result<Algorithm, JwtError> {
    require_stage(Stage::Start);
    kani::assert(
        header == "h",
        "authorization receives the compact protected header",
    );
    kani::assert(
        matches!(jwk, Jwk::Okp(_)),
        "authorization receives the caller's JWK",
    );
    kani::assert(
        core::ptr::eq(key, &CALLER_PUBLIC_KEY[..]),
        "authorization receives the caller's key",
    );
    if rejected_at(REJECTED_HEADER) {
        return Err(JwtError::InvalidHeader);
    }
    advance_to(Stage::HeaderAuthorized);
    Ok(Algorithm::Ed25519)
}

fn build_signing_input<E>(header: &str, payload: &str, _: E) -> Result<Zeroizing<Vec<u8>>, E> {
    require_stage(Stage::HeaderAuthorized);
    kani::assert(
        header == "h" && payload == "p",
        "the original compact segments are bound",
    );
    Ok(Zeroizing::new(vec![4]))
}

fn decode_segment(segment: &[u8]) -> Result<Vec<u8>, Base64UrlError> {
    if segment == b"s" {
        require_stage(Stage::HeaderAuthorized);
        advance_to(Stage::SignatureDecoded);
        return Ok(vec![3]);
    }
    kani::assert(
        segment == b"p",
        "the authenticated payload segment is decoded",
    );
    require_stage(Stage::SignatureVerified);
    if rejected_at(INVALID_PAYLOAD_ENCODING) {
        return Err(Base64UrlError::Invalid);
    }
    advance_to(Stage::ClaimsDecoded);
    Ok(CLAIMS_BYTES.to_vec())
}

fn verify_signature(
    algorithm: Algorithm,
    key: &[u8],
    signing_input: &[u8],
    signature: Zeroizing<Vec<u8>>,
) -> Result<(), JwtError> {
    require_stage(Stage::SignatureDecoded);
    kani::assert(
        matches!(algorithm, Algorithm::Ed25519),
        "the authorized algorithm is used",
    );
    kani::assert(
        core::ptr::eq(key, &CALLER_PUBLIC_KEY[..]),
        "verification receives the caller's key",
    );
    kani::assert(
        signing_input == [4],
        "verification binds the header and payload",
    );
    kani::assert(
        signature.as_slice() == [3],
        "the compact signature is checked",
    );
    if rejected_at(INVALID_SIGNATURE) {
        return Err(JwtError::InvalidSignature);
    }
    advance_to(Stage::SignatureVerified);
    Ok(())
}

fn check_unique_claims(bytes: &[u8]) -> Result<(), JwtError> {
    require_stage(Stage::ClaimsDecoded);
    kani::assert(
        bytes == CLAIMS_BYTES,
        "the authenticated bytes reach the duplicate check",
    );
    if rejected_at(DUPLICATE_CLAIMS) {
        return Err(JwtError::InvalidClaims);
    }
    advance_to(Stage::ClaimsUnique);
    Ok(())
}

fn parse_claims(bytes: &[u8]) -> Result<SensitiveJsonValue, JwtError> {
    require_stage(Stage::ClaimsUnique);
    kani::assert(
        bytes == CLAIMS_BYTES,
        "the duplicate-checked bytes reach claims parsing",
    );
    if rejected_at(INVALID_CLAIMS_JSON) {
        return Err(JwtError::Serialization);
    }
    // This object models the successful shape check. The lookup model
    // supplies its fixed fields without expanding the map allocator.
    advance_to(Stage::ClaimsParsed);
    Ok(SensitiveJsonValue::from_parsed_model(Value::Object(
        Map::new(),
    )))
}

#[derive(Clone, Copy)]
enum ClaimValue {
    Date(u64),
    Text(&'static str),
}

const FIXED_CLAIMS: [(&str, ClaimValue); 6] = [
    ("exp", ClaimValue::Date(EXPIRATION)),
    ("nbf", ClaimValue::Date(NOT_BEFORE)),
    ("iat", ClaimValue::Date(ISSUED_AT)),
    ("aud", ClaimValue::Text(AUDIENCE)),
    ("iss", ClaimValue::Text(ISSUER)),
    ("sub", ClaimValue::Text(SUBJECT)),
];

fn lookup_claim<'a, Q>(_: &'a Map<String, Value>, name: &Q) -> Option<&'a Value>
where
    String: Borrow<Q>,
    Q: ?Sized + Ord + Eq + Hash,
{
    require_stage(Stage::ClaimsParsed);
    let (_, value) = FIXED_CLAIMS.iter().find(|(field, _)| {
        let field = String::from(*field);
        <String as Borrow<Q>>::borrow(&field) == name
    })?;
    let decoded = match *value {
        ClaimValue::Date(seconds) => Value::from(seconds),
        ClaimValue::Text(text) => Value::from(text),
    };
    // The proof borrows constant synthetic fields for the rest of the call.
    Some(Box::leak(Box::new(decoded)))
}

fn omit_json_fixture_cleanup(value: Value) {
    // The synthetic lookup values live for this proof. JSON allocator cleanup
    // has no bearing on whether the entry point publishes the raw claims.
    let _value = ManuallyDrop::new(value);
}

fn accept_temporal_policy(
    _: &Value,
    _: u64,
    _: JwtTemporalValidationPolicy,
) -> Result<(), JwtError> {
    require_stage(Stage::ClaimsParsed);
    kani::assert(
        rejected_at(0),
        "policy is reached only after authentication and claims parsing",
    );
    advance_to(Stage::TimeValidated);
    Ok(())
}

fn accept_registered_policy(_: &Value, _: JwtClaimsValidationPolicy<'_>) -> Result<(), JwtError> {
    require_stage(Stage::TimeValidated);
    advance_to(Stage::ClaimsValidated);
    Ok(())
}

fn authenticated_payload(
    compact: &str,
    _: &Jwk,
    key: &[u8],
    _: &JwtHeaderValidationOptions<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    kani::assert(
        compact == "a",
        "the canonical verifier receives the original token",
    );
    kani::assert(
        core::ptr::eq(key, &CALLER_PUBLIC_KEY[..]),
        "the canonical verifier receives the original key",
    );
    advance_to(Stage::ClaimsDecoded);
    Ok(Zeroizing::new(CLAIMS_BYTES.to_vec()))
}

fn verify_with_policy(
    compact: &str,
    now: u64,
    policy: JwtClaimsValidationPolicy<'_>,
) -> Result<Zeroizing<Vec<u8>>, JwtError> {
    let jwk = Jwk::Okp(OkpJwk {
        kty: String::new(),
        crv: String::new(),
        x: String::new(),
        alg: None,
        use_: None,
        kid: None,
    });
    decode_verify_jwt_claims_json_with_claims_validation_and_header_validation(
        compact,
        &jwk,
        &CALLER_PUBLIC_KEY,
        now,
        policy,
        &JwtHeaderValidationOptions::standard_jwt(),
    )
}

fn check_result(result: &Result<Zeroizing<Vec<u8>>, JwtError>, expected: Option<JwtError>) {
    if let Some(error) = expected {
        kani::assert(
            matches!(result, Err(actual) if core::mem::discriminant(actual) == core::mem::discriminant(&error)),
            "a rejected stage returns its typed error without releasing claims",
        );
    } else {
        kani::assert(
            matches!(result, Ok(bytes) if bytes.as_slice() == CLAIMS_BYTES),
            "success releases exactly the authenticated claims bytes",
        );
    }
}

#[kani::proof]
#[kani::unwind(5)]
#[kani::stub(super::super::parse_compact_jwt, parse_compact)]
#[kani::stub(super::super::authorize_jwt_header, authorize_header)]
#[kani::stub(super::super::base64url_bytes_to_bytes, decode_segment)]
#[kani::stub(super::super::verify_jwt_signature, verify_signature)]
#[kani::stub(super::super::build_sig_structure, build_signing_input)]
#[kani::stub(super::super::reject_duplicate_object_members, check_unique_claims)]
#[kani::stub(super::super::parse_sensitive_json, parse_claims)]
#[kani::stub(super::super::validate_temporal_claims, accept_temporal_policy)]
#[kani::stub(super::super::validate_registered_claims, accept_registered_policy)]
#[kani::stub(crate::jwt::strict_json::zeroize_json_value, omit_json_fixture_cleanup)]
fn the_claims_entry_point_requires_authentication_and_decoding_before_policy() {
    let rejection = kani::any::<u8>();
    kani::assume(rejection <= INVALID_CLAIMS_JSON);
    REJECTION.store(rejection, Ordering::Relaxed);
    let compact = if rejection == MALFORMED_COMPACT {
        "b"
    } else {
        "a"
    };
    let result = verify_with_policy(
        compact,
        ISSUED_AT,
        JwtClaimsValidationPolicy::strict(AUDIENCE),
    );

    let (expected_stage, expected) = match rejection {
        MALFORMED_COMPACT => (Stage::Start, Some(JwtError::InvalidJwtFormat)),
        REJECTED_HEADER => (Stage::Start, Some(JwtError::InvalidHeader)),
        INVALID_SIGNATURE => (Stage::SignatureDecoded, Some(JwtError::InvalidSignature)),
        INVALID_PAYLOAD_ENCODING => (Stage::SignatureVerified, Some(JwtError::Base64Url)),
        DUPLICATE_CLAIMS => (Stage::ClaimsDecoded, Some(JwtError::InvalidClaims)),
        INVALID_CLAIMS_JSON => (Stage::ClaimsUnique, Some(JwtError::Serialization)),
        _ => (Stage::ClaimsValidated, None),
    };
    require_stage(expected_stage);
    check_result(&result, expected);

    kani::cover!(
        matches!(&result, Err(JwtError::InvalidJwtFormat)),
        "malformed compact token"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidHeader)),
        "header rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidSignature)),
        "signature rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::Base64Url)),
        "payload decode rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidClaims)),
        "duplicate claims rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::Serialization)),
        "claims parse rejected"
    );
    kani::cover!(
        result.is_ok(),
        "authenticated and parsed claims pass both policy stages"
    );
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(super::super::decode_verify_jwt_payload_bytes, authenticated_payload)]
#[kani::stub(super::super::reject_duplicate_object_members, check_unique_claims)]
#[kani::stub(super::super::parse_sensitive_json, parse_claims)]
#[kani::stub(serde_json::Map::get, lookup_claim)]
#[kani::stub(crate::jwt::strict_json::zeroize_json_value, omit_json_fixture_cleanup)]
fn the_claims_entry_point_rejects_each_failed_claim_check() {
    let now = kani::any::<u64>();
    let audience_matches = kani::any::<bool>();
    let issuer_matches = kani::any::<Option<bool>>();
    let subject_matches = kani::any::<Option<bool>>();
    let policy = JwtClaimsValidationPolicy::new(
        JwtTemporalValidationPolicy::new(true, true, true, 0, 0),
        if audience_matches {
            AUDIENCE
        } else {
            OTHER_IDENTITY
        },
        issuer_matches.map(|matches| if matches { ISSUER } else { OTHER_IDENTITY }),
        subject_matches.map(|matches| if matches { SUBJECT } else { OTHER_IDENTITY }),
    );
    let result = verify_with_policy("a", now, policy);

    let expected = if now == 0 {
        Some(JwtError::InvalidVerificationTime)
    } else if now >= EXPIRATION {
        Some(JwtError::Expired)
    } else if now < NOT_BEFORE {
        Some(JwtError::NotYetValid)
    } else if now < ISSUED_AT {
        Some(JwtError::IssuedAtInFuture)
    } else if !audience_matches {
        Some(JwtError::AudienceMismatch)
    } else if issuer_matches == Some(false) {
        Some(JwtError::IssuerMismatch)
    } else if subject_matches == Some(false) {
        Some(JwtError::SubjectMismatch)
    } else {
        None
    };
    require_stage(Stage::ClaimsParsed);
    check_result(&result, expected);

    kani::cover!(
        matches!(&result, Err(JwtError::InvalidVerificationTime)),
        "invalid verification time"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::Expired)) && now == EXPIRATION,
        "expired at the exact boundary"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::NotYetValid)),
        "not-before claim rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::IssuedAtInFuture)),
        "future issued-at rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::AudienceMismatch)),
        "audience rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::IssuerMismatch)),
        "issuer rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::SubjectMismatch)),
        "subject rejected"
    );
    kani::cover!(
        result.is_ok() && issuer_matches == Some(true) && subject_matches == Some(true),
        "all configured checks pass"
    );
    kani::cover!(
        result.is_ok() && issuer_matches.is_none() && subject_matches.is_none(),
        "both identity constraints omitted"
    );
}
