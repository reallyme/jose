#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_jose::jws::suites::eddsa::{sign_eddsa_jws, verify_eddsa_jws, JwsEddsaError};

#[test]
fn jws_eddsa_roundtrip() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();
    let jws = sign_eddsa_jws(&private, "cid:example:eddsa").unwrap();

    verify_eddsa_jws(&jws, &public).unwrap();
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
