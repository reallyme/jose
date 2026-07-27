// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;

use crate::jws::suites::eddsa::sign_eddsa_jws;
use crate::jws::suites::es256::{sign_es256_jws, sign_p256_jose_prehash};

use super::verify::{
    verify_jws, JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
    VerifiedJwsPayload,
};

const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

#[test]
fn verifies_supported_algorithms() {
    let (es256_public, es256_private) = generate_keypair(Algorithm::P256).unwrap();
    let es256_compact = sign_es256_jws(&es256_private, "stage-5-es256").unwrap();
    let es256_payload = verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        &es256_compact,
        &es256_public,
    ))
    .unwrap()
    .into_bytes();
    assert_eq!(es256_payload.as_slice(), b"stage-5-es256");

    let (eddsa_public, eddsa_private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let eddsa_compact = sign_eddsa_jws(&eddsa_private, "stage-5-eddsa").unwrap();
    let eddsa_payload = verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Eddsa,
        &eddsa_compact,
        &eddsa_public,
    ))
    .unwrap()
    .into_bytes();
    assert_eq!(eddsa_payload.as_slice(), b"stage-5-eddsa");
}

#[test]
fn preserves_validation_order_and_typed_reasons() {
    let (public_key, _private_key) = generate_keypair(Algorithm::P256).unwrap();
    let invalid_utf8_header = bytes_to_base64url(&[0xff]);
    let es256_header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let eddsa_header = bytes_to_base64url(br#"{"alg":"EdDSA"}"#);

    assert_reason(
        "only.two",
        &public_key,
        JwsVerifyErrorReason::InvalidCompact,
    );
    assert_reason(
        "=.payload.signature",
        &public_key,
        JwsVerifyErrorReason::BadHeaderBase64,
    );
    assert_reason(
        &format!("{invalid_utf8_header}.payload.signature"),
        &public_key,
        JwsVerifyErrorReason::BadHeaderUtf8,
    );
    assert_reason(
        &format!("{eddsa_header}.payload.signature"),
        &public_key,
        JwsVerifyErrorReason::HeaderMismatch,
    );
    assert_reason(
        &format!("{es256_header}.payload.%"),
        &public_key,
        JwsVerifyErrorReason::BadSignatureBase64,
    );
    assert_reason(
        &format!("{es256_header}.payload.c2hvcnQ"),
        &public_key,
        JwsVerifyErrorReason::InvalidSignature,
    );

    let oversized = "a".repeat(crate::jws::MAX_COMPACT_JWS_BYTES.checked_add(1).unwrap());
    assert_reason(
        &oversized,
        &public_key,
        JwsVerifyErrorReason::InvalidCompact,
    );
}

#[test]
fn rejects_invalid_es256_scalars_with_the_specific_reason() {
    let (public_key, _private_key) = generate_keypair(Algorithm::P256).unwrap();
    let compact = compact_es256_jws_with_signature(&[0u8; 64]);

    assert_reason(&compact, &public_key, JwsVerifyErrorReason::BadRawSignature);
}

#[test]
fn eddsa_never_reports_the_es256_raw_signature_reason() {
    let (public_key, _private_key) = generate_keypair(Algorithm::Ed25519).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"EdDSA"}"#);
    let signature = bytes_to_base64url(&[0u8; 64]);
    let compact = format!("{header}.payload.{signature}");
    let error = expect_verify_error(verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Eddsa,
        &compact,
        &public_key,
    )));

    assert_eq!(error.reason(), JwsVerifyErrorReason::InvalidSignature);
}

#[test]
fn authenticates_encoded_payload_before_rejecting_invalid_base64url() {
    let (public_key, private_key) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let signing_input = format!("{header}.%");
    let signature = sign_p256_jose_prehash(&private_key, signing_input.as_bytes()).unwrap();
    let compact = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let error = expect_verify_error(verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        &compact,
        &public_key,
    )));
    assert_eq!(error.reason(), JwsVerifyErrorReason::BadPayloadBase64);
}

#[test]
fn checks_signature_before_decoding_payload() {
    let (public_key, private_key) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let signing_input = format!("{header}.%");
    let mut signature = sign_p256_jose_prehash(&private_key, signing_input.as_bytes()).unwrap();
    signature[0] ^= 1;
    let compact = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let error = expect_verify_error(verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        &compact,
        &public_key,
    )));
    assert_eq!(error.reason(), JwsVerifyErrorReason::InvalidSignature);
}

#[test]
fn accepts_valid_high_s_es256_signature() {
    let (public_key, private_key) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let payload = bytes_to_base64url(b"high-s");
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&private_key, signing_input.as_bytes()).unwrap();
    let high_s_signature = high_s_variant(signature);
    let compact = format!(
        "{signing_input}.{}",
        bytes_to_base64url(high_s_signature.as_slice())
    );

    let verified_payload = verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        &compact,
        &public_key,
    ))
    .unwrap()
    .into_bytes();
    assert_eq!(verified_payload.as_slice(), b"high-s");
}

fn assert_reason(compact: &str, public_key: &[u8], expected: JwsVerifyErrorReason) {
    let error = expect_verify_error(verify_jws(JwsVerifyInput::new(
        JwsVerifyAlgorithm::Es256,
        compact,
        public_key,
    )));
    assert_eq!(error.reason(), expected);
}

fn expect_verify_error(result: Result<VerifiedJwsPayload, JwsVerifyError>) -> JwsVerifyError {
    // Converting to `Option` avoids requiring `Debug` on the secret-bearing
    // authenticated payload merely to use `Result::unwrap_err` in tests.
    result.err().unwrap()
}

fn compact_es256_jws_with_signature(signature: &[u8; 64]) -> String {
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let payload = bytes_to_base64url(b"test");
    let signature = bytes_to_base64url(signature);
    format!("{header}.{payload}.{signature}")
}

fn high_s_variant(signature: [u8; 64]) -> [u8; 64] {
    if signature[32..].cmp(P256_HALF_N.as_slice()).is_gt() {
        return signature;
    }

    let mut malleated = signature;
    let mut borrow = 0u16;
    for index in (0usize..32).rev() {
        let signature_index = index.checked_add(32).unwrap();
        let order_byte = u16::from(P256_N[index]);
        let signature_byte = u16::from(signature[signature_index]);
        let subtrahend = signature_byte.checked_add(borrow).unwrap();
        if order_byte >= subtrahend {
            malleated[signature_index] =
                u8::try_from(order_byte.checked_sub(subtrahend).unwrap()).unwrap();
            borrow = 0;
        } else {
            let wrapped = order_byte
                .checked_add(256)
                .and_then(|value| value.checked_sub(subtrahend))
                .unwrap();
            malleated[signature_index] = u8::try_from(wrapped).unwrap();
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0);
    malleated
}
