#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{base_claims_json, gen_ed25519};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;
use reallyme_crypto::jwk::Jwk;
use reallyme_jose::jws::suites::eddsa::sign_eddsa_jws;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only, decode_verify_jwt_signature_only_with_header_validation,
    encode_signed_jwt_with_header_options, JwtError, JwtHeaderEncodeOptions,
    JwtHeaderValidationOptions,
};

#[test]
fn can_encode_and_decode_custom_typ_when_policy_allows_it() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("encode");

    let decoded: serde_json::Value = decode_verify_jwt_signature_only_with_header_validation(
        &jwt,
        &k.jwk,
        &k.public,
        &JwtHeaderValidationOptions::new(false, false, &["dc+sd-jwt"]),
    )
    .expect("decode");

    assert_eq!(decoded["iss"], "did:me:test");
}

#[test]
fn signed_jwt_carries_jwk_key_id() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::jwt(),
    )
    .expect("encode");
    let protected = jwt.split('.').next().expect("protected header");
    let protected_json = base64url_to_bytes(protected).expect("protected header base64url");
    let protected_value: serde_json::Value =
        serde_json::from_slice(&protected_json).expect("protected header json");

    assert_eq!(protected_value["kid"], "k-ed");
}

#[test]
fn standard_policy_rejects_non_jwt_typ() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public);
    assert!(decoded.is_err());
}

#[test]
fn standard_policy_accepts_case_insensitive_application_jwt_typ() {
    let key = gen_ed25519();
    let claims = base_claims_json();
    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &key.jwk,
        &key.private,
        &JwtHeaderEncodeOptions::new(Some("Application/jWt".to_owned())),
    )
    .expect("encode");

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &key.jwk, &key.public).expect("decode");

    assert_eq!(decoded["aud"], "example");
}

#[test]
fn can_require_typ_presence() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::new(None),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, _> =
        decode_verify_jwt_signature_only_with_header_validation(
            &jwt,
            &k.jwk,
            &k.public,
            &JwtHeaderValidationOptions::new(false, false, &["JWT"]),
        );

    assert!(decoded.is_err());
}

#[test]
fn default_jwt_verifier_rejects_generic_jws_signed_with_the_same_key() {
    let key = gen_ed25519();
    let claims = base_claims_json();
    let compact = sign_eddsa_jws(&key.private, &claims.to_string()).expect("sign raw JWS");
    let mut jwk = key.jwk;
    if let Jwk::Okp(ref mut value) = jwk {
        value.kid = None;
    }

    let standard: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only(&compact, &jwk, &key.public);
    assert!(matches!(standard, Err(JwtError::InvalidHeader)));

    let compatible: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only_with_header_validation(
            &compact,
            &jwk,
            &key.public,
            &JwtHeaderValidationOptions::new(true, false, &["JWT"]),
        );
    assert_eq!(compatible.expect("explicit compatibility policy"), claims);
}

#[test]
fn empty_accepted_typ_values_rejects_present_typ() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt_with_header_options(
        &claims,
        &k.jwk,
        &k.private,
        &JwtHeaderEncodeOptions::jwt(),
    )
    .expect("encode");

    let decoded: Result<serde_json::Value, JwtError> =
        decode_verify_jwt_signature_only_with_header_validation(
            &jwt,
            &k.jwk,
            &k.public,
            &JwtHeaderValidationOptions::new(true, false, &[]),
        );

    assert!(matches!(decoded, Err(JwtError::InvalidHeader)));
}

#[test]
fn accepted_type_policy_respects_the_schema_limit() -> Result<(), Box<dyn std::error::Error>> {
    use buffa::Enumeration;
    use reallyme_jose::api::contract::JoseJwtPolicyLimit;
    let key = gen_ed25519();
    let compact = encode_signed_jwt_with_header_options(
        &base_claims_json(),
        &key.jwk,
        &key.private,
        &JwtHeaderEncodeOptions::jwt(),
    )?;
    let limit = usize::try_from(JoseJwtPolicyLimit::AcceptedTypeValues.to_i32())?;
    for count in [limit, limit.checked_add(1).ok_or(JwtError::LengthOverflow)?] {
        let accepted = vec!["JWT"; count];
        let result = decode_verify_jwt_signature_only_with_header_validation::<serde_json::Value>(
            &compact,
            &key.jwk,
            &key.public,
            &JwtHeaderValidationOptions::new(false, false, &accepted),
        );
        if count == limit {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(JwtError::InputTooLarge)));
        }
    }
    Ok(())
}

#[test]
fn owned_header_options_redact_and_wipe_schema_sensitive_metadata() {
    fn assert_wipe_owner<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let mut options = JwtHeaderEncodeOptions::new(Some("private-profile".to_owned()));
    assert_wipe_owner(&options);
    assert_eq!(format!("{options:?}"), "JwtHeaderEncodeOptions(<redacted>)");
    zeroize::Zeroize::zeroize(&mut options);
    assert!(options.typ().is_none());
}

#[test]
fn permitted_embedded_jwk_cannot_authenticate_claims_for_a_different_caller_key() {
    let trusted = gen_ed25519();
    let other = gen_ed25519();
    // Both test JWKs have the same kid, so only the signature distinguishes
    // the caller's key from the untrusted key advertised in the header.
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": "k-ed",
        "jwk": other.jwk,
    });
    let claims = base_claims_json();
    let header = bytes_to_base64url(header.to_string().as_bytes());
    let payload = bytes_to_base64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let trusted_signature = sign(
        Algorithm::Ed25519,
        &trusted.private,
        signing_input.as_bytes(),
    )
    .expect("trusted signature");
    let other_signature = sign(Algorithm::Ed25519, &other.private, signing_input.as_bytes())
        .expect("other signature");
    let trusted_token = format!("{signing_input}.{}", bytes_to_base64url(&trusted_signature));
    let other_token = format!("{signing_input}.{}", bytes_to_base64url(&other_signature));
    let allows_embedded = JwtHeaderValidationOptions::new(false, true, &["JWT"]);

    assert!(matches!(
        decode_verify_jwt_signature_only::<serde_json::Value>(
            &trusted_token,
            &trusted.jwk,
            &trusted.public
        ),
        Err(JwtError::InvalidHeader)
    ));
    assert!(matches!(
        decode_verify_jwt_signature_only_with_header_validation::<serde_json::Value>(
            &other_token,
            &trusted.jwk,
            &trusted.public,
            &allows_embedded
        ),
        Err(JwtError::InvalidSignature)
    ));
    let verified: serde_json::Value = decode_verify_jwt_signature_only_with_header_validation(
        &trusted_token,
        &trusted.jwk,
        &trusted.public,
        &allows_embedded,
    )
    .expect("claims authenticated using the caller's key");
    assert_eq!(verified, claims);
}
