#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_jose::jws::{
    suites::es256::{
        sign_es256_jws, sign_p256_jose_prehash, verify_es256_jws, verify_p256_jose_prehash,
        JwsEs256Error,
    },
    MAX_COMPACT_JWS_BYTES,
};

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;

const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

#[test]
fn jws_es256_roundtrip() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();

    let payload = "cid:example:12345";

    let jws = sign_es256_jws(&private, payload).unwrap();

    verify_es256_jws(&jws, &public).unwrap();
}

#[test]
fn jws_es256_rejects_tampered_payload() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();

    let payload = "cid:example:12345";

    let jws = sign_es256_jws(&private, payload).unwrap();

    // Tamper with payload segment
    let mut parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);

    parts[1] = "dGFtcGVyZWQ"; // "tampered" base64url
    let tampered = parts.join(".");

    let err = verify_es256_jws(&tampered, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_wrong_public_key() {
    let (_pub1, priv1) = generate_keypair(Algorithm::P256).unwrap();

    let (pub2, _priv2) = generate_keypair(Algorithm::P256).unwrap();

    let payload = "cid:example:12345";

    let jws = sign_es256_jws(&priv1, payload).unwrap();

    let err = verify_es256_jws(&jws, &pub2).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_bad_header() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();

    // alg != ES256
    let bad_jws = "eyJhbGciOiJFUzI1NksifQ.cGF5bG9hZA.c2ln";

    let err = verify_es256_jws(bad_jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn jws_es256_rejects_missing_alg_header() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"typ":"JWT"}"#);
    let bad_jws = format!("{header}.dGVzdA.c2ln");

    let err = verify_es256_jws(&bad_jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn jws_es256_rejects_alg_none_header() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"none"}"#);
    let bad_jws = format!("{header}.dGVzdA.c2ln");

    let err = verify_es256_jws(&bad_jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn jws_es256_rejects_duplicate_protected_header_members() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256","alg":"ES256"}"#);
    let payload = bytes_to_base64url(b"test");
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&private, signing_input.as_bytes()).unwrap();
    let jws = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn jws_es256_rejects_unsupported_crit_header() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256","crit":["exp"]}"#);
    let payload = bytes_to_base64url(b"test");
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&private, signing_input.as_bytes()).unwrap();
    let jws = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn jws_es256_rejects_b64_header_parameter() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256","b64":false}"#);
    let payload = bytes_to_base64url(b"test");
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&private, signing_input.as_bytes()).unwrap();
    let jws = format!(
        "{signing_input}.{}",
        bytes_to_base64url(signature.as_slice())
    );

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::HeaderMismatch);
}

#[test]
fn p256_jose_prehash_helper_signs_and_verifies_raw_signature() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let signing_input = b"protected.payload";

    let signature = sign_p256_jose_prehash(&private, signing_input).unwrap();

    assert_eq!(signature.len(), 64);
    verify_p256_jose_prehash(signature.as_slice(), signing_input, &public).unwrap();
    let err = verify_p256_jose_prehash(signature.as_slice(), b"tampered", &public).unwrap_err();
    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_accepts_high_s_signature_as_valid_ecdsa() {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let payload = bytes_to_base64url(b"test");
    let signing_input = format!("{header}.{payload}");
    let signature = sign_p256_jose_prehash(&private, signing_input.as_bytes()).unwrap();
    let high_s_signature = high_s_variant(signature);

    assert!(signature_has_high_s(&high_s_signature));

    let jws = format!(
        "{signing_input}.{}",
        bytes_to_base64url(high_s_signature.as_slice())
    );

    verify_es256_jws(&jws, &public).unwrap();
}

#[test]
fn jws_es256_rejects_malformed_jws() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();

    let bad = "not.a.jws";

    let res = verify_es256_jws(bad, &public);

    assert_eq!(res.unwrap_err(), JwsEs256Error::BadHeaderBase64);
}

#[test]
fn jws_es256_rejects_wrong_segment_count() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();

    let bad = "only.two";

    let err = verify_es256_jws(bad, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidCompactEncoding);
}

#[test]
fn jws_es256_rejects_trailing_compact_segment() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let bad = "eyJhbGciOiJFUzI1NiJ9.dGVzdA.c2ln.extra";

    let err = verify_es256_jws(bad, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidCompactEncoding);
}

#[test]
fn jws_es256_rejects_padded_base64url_header() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let bad = "eyJhbGciOiJFUzI1NiJ9=.dGVzdA.c2ln";

    let err = verify_es256_jws(bad, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::BadHeaderBase64);
}

#[test]
fn jws_es256_rejects_invalid_utf8_header() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let header = bytes_to_base64url(&[0xff]);
    let bad = format!("{header}.dGVzdA.c2ln");

    let err = verify_es256_jws(&bad, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::BadHeaderUtf8);
}

#[test]
fn jws_es256_rejects_invalid_signature_length() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();

    // header={"alg":"ES256"}, payload="test", sig="short"
    let bad = "eyJhbGciOiJFUzI1NiJ9.dGVzdA.c2hvcnQ";

    let err = verify_es256_jws(bad, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_all_zero_signature_scalars() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let signature = [0u8; 64];
    let jws = compact_es256_jws_with_signature(&signature);

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_r_scalar_at_group_order() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&P256_N);
    signature[63] = 1;
    let jws = compact_es256_jws_with_signature(&signature);

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_s_scalar_at_group_order() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let mut signature = [0u8; 64];
    signature[31] = 1;
    signature[32..].copy_from_slice(&P256_N);
    let jws = compact_es256_jws_with_signature(&signature);

    let err = verify_es256_jws(&jws, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidSignature);
}

#[test]
fn jws_es256_rejects_compact_input_over_size_limit() {
    let (public, _private) = generate_keypair(Algorithm::P256).unwrap();
    let len = MAX_COMPACT_JWS_BYTES.checked_add(1).unwrap();
    let oversized = "a".repeat(len);

    let err = verify_es256_jws(&oversized, &public).unwrap_err();

    assert_eq!(err, JwsEs256Error::InvalidCompactEncoding);
}

fn compact_es256_jws_with_signature(signature: &[u8; 64]) -> String {
    let header = bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let payload = bytes_to_base64url(b"test");
    let signature = bytes_to_base64url(signature);
    format!("{header}.{payload}.{signature}")
}

fn high_s_variant(signature: [u8; 64]) -> [u8; 64] {
    if signature_has_high_s(&signature) {
        return signature;
    }

    malleate_p256_s(signature)
}

fn signature_has_high_s(signature: &[u8; 64]) -> bool {
    signature[32..].cmp(P256_HALF_N.as_slice()).is_gt()
}

fn malleate_p256_s(signature: [u8; 64]) -> [u8; 64] {
    let mut malleated = signature;
    let mut borrow = 0u16;

    for idx in (0usize..32).rev() {
        let sig_idx = idx.checked_add(32).unwrap();
        let order_byte = u16::from(P256_N[idx]);
        let s_byte = u16::from(signature[sig_idx]);
        let subtrahend = s_byte.checked_add(borrow).unwrap();
        if order_byte >= subtrahend {
            malleated[sig_idx] = u8::try_from(order_byte.checked_sub(subtrahend).unwrap()).unwrap();
            borrow = 0;
        } else {
            let wrapped = order_byte
                .checked_add(256)
                .and_then(|value| value.checked_sub(subtrahend))
                .unwrap();
            malleated[sig_idx] = u8::try_from(wrapped).unwrap();
            borrow = 1;
        }
    }

    assert_eq!(borrow, 0);
    malleated
}
