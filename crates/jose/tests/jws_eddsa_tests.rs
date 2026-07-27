#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::{generate_keypair, sign};
use reallyme_jose::jws::{
    suites::eddsa::{
        sign_eddsa_jws, verify_eddsa_jws, verify_eddsa_jws_and_decode_payload, JwsEddsaError,
    },
    MAX_COMPACT_JWS_BYTES,
};

#[test]
fn jws_eddsa_roundtrip() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let jws = sign_eddsa_jws(&private, "cid:example:eddsa").unwrap();

    verify_eddsa_jws(&jws, &public).unwrap();

    let authenticated = verify_eddsa_jws_and_decode_payload(&jws, &public).unwrap();
    assert_eq!(authenticated.as_slice(), b"cid:example:eddsa");
}

#[test]
fn jws_eddsa_rejects_tampered_payload() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let jws = sign_eddsa_jws(&private, "cid:example:eddsa").unwrap();

    let mut parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);
    parts[1] = "dGFtcGVyZWQ";
    let tampered = parts.join(".");

    let err = verify_eddsa_jws(&tampered, &public).unwrap_err();

    assert_eq!(err, JwsEddsaError::InvalidSignature);
}

#[test]
fn jws_eddsa_rejects_authenticated_invalid_payload_base64url() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"EdDSA"}"#);
    let signing_input = format!("{header}.%");
    let signature = sign(Algorithm::Ed25519, &private, signing_input.as_bytes()).unwrap();
    let jws = format!("{signing_input}.{}", bytes_to_base64url(&signature));

    let error = verify_eddsa_jws_and_decode_payload(&jws, &public).unwrap_err();

    assert_eq!(error, JwsEddsaError::BadPayloadBase64);
}

#[test]
fn jws_eddsa_rejects_es256_header() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let bad_jws = "eyJhbGciOiJFUzI1NiJ9.dGVzdA.c2ln";

    let err = verify_eddsa_jws(bad_jws, &public).unwrap_err();

    assert_eq!(err, JwsEddsaError::HeaderMismatch);
}

#[test]
fn jws_eddsa_rejects_invalid_signature_length() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let bad_jws = "eyJhbGciOiJFZERTQSJ9.dGVzdA.c2hvcnQ";

    let err = verify_eddsa_jws(bad_jws, &public).unwrap_err();

    assert_eq!(err, JwsEddsaError::InvalidSignature);
}

#[test]
fn jws_eddsa_preserves_typed_malformed_input_errors() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).unwrap();

    for (compact, expected) in [
        ("only.two", JwsEddsaError::InvalidCompactEncoding),
        ("=.payload.signature", JwsEddsaError::BadHeaderBase64),
        ("_w.payload.signature", JwsEddsaError::BadHeaderUtf8),
        (
            "eyJhbGciOiJFZERTQSJ9.payload.%",
            JwsEddsaError::BadSignatureBase64,
        ),
    ] {
        let error = verify_eddsa_jws(compact, &public).unwrap_err();
        assert_eq!(error, expected);
    }
}

#[test]
fn jws_eddsa_rejects_compact_input_over_size_limit() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let oversized_length = MAX_COMPACT_JWS_BYTES.checked_add(1).unwrap();
    let oversized = "a".repeat(oversized_length);

    let error = verify_eddsa_jws(&oversized, &public).unwrap_err();

    assert_eq!(error, JwsEddsaError::InvalidCompactEncoding);
}

#[test]
fn jws_eddsa_encoder_rejects_output_over_parser_limit() {
    let (_public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let payload = "a".repeat(800_000);

    let err = sign_eddsa_jws(&private, &payload).unwrap_err();

    assert_eq!(err, JwsEddsaError::InputTooLarge);
}
